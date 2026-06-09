import json
from fastapi import APIRouter, HTTPException
from database import get_db
from models.schemas import GraphData, GraphNode, GraphEdge

router = APIRouter()


@router.get("/api/pcap/{pcap_id}/sessions")
async def list_sessions(pcap_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, src_ip, dst_ip, src_port, dst_port, protocol,
               app_protocol, packet_count, total_bytes,
               start_time, end_time, duration_ms, state
               FROM sessions WHERE pcap_file_id = ? ORDER BY start_time""",
            (pcap_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, pcap_file_id, src_ip, dst_ip, src_port, dst_port, protocol,
               app_protocol, packet_count, total_bytes,
               start_time, end_time, duration_ms,
               client_payload, server_payload, app_decoded_json, state
               FROM sessions WHERE id = ?""",
            (session_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Session not found")

        result = dict(row)
        client_payload = result.pop('client_payload', None) or b''
        server_payload = result.pop('server_payload', None) or b''
        app_decoded_json = result.pop('app_decoded_json', None)

        result['client_payload_preview'] = client_payload[:1024].decode('utf-8', errors='replace') if client_payload else None
        result['server_payload_preview'] = server_payload[:1024].decode('utf-8', errors='replace') if server_payload else None
        result['app_decoded'] = json.loads(app_decoded_json) if app_decoded_json else None

        return result
    finally:
        await db.close()


@router.get("/api/sessions/{session_id}/timeline")
async def get_session_timeline(session_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT src_ip, src_port FROM sessions WHERE id = ?", (session_id,)
        )
        sess = await cursor.fetchone()
        if not sess:
            raise HTTPException(404, "Session not found")

        cursor = await db.execute(
            """SELECT packet_index, timestamp_sec, timestamp_usec,
               ip_src, src_port, dst_port, tcp_flags, payload_length
               FROM packets WHERE session_id = ?
               ORDER BY packet_index""",
            (session_id,)
        )
        rows = await cursor.fetchall()

        # Fallback: find packets by session's IP/port tuple
        if not rows:
            cursor = await db.execute(
                """SELECT packet_index, timestamp_sec, timestamp_usec,
                   ip_src, src_port, dst_port, tcp_flags, payload_length
                   FROM packets WHERE pcap_file_id = (SELECT pcap_file_id FROM sessions WHERE id = ?)
                   AND ((ip_src = ? AND src_port = ?) OR (ip_dst = ? AND dst_port = ?))
                   ORDER BY packet_index""",
                (session_id, sess['src_ip'], sess['src_port'], sess['src_ip'], sess['src_port'])
            )
            rows = await cursor.fetchall()

        timeline = []
        for r in rows:
            ts = r['timestamp_sec'] + r['timestamp_usec'] / 1_000_000
            direction = "client_to_server" if r['ip_src'] == sess['src_ip'] else "server_to_client"
            flags = _format_flags(r['tcp_flags']) if r['tcp_flags'] is not None else None

            timeline.append({
                "packet_index": r['packet_index'],
                "timestamp": ts,
                "direction": direction,
                "src_port": r['src_port'],
                "dst_port": r['dst_port'],
                "flags": flags,
                "payload_length": r['payload_length'],
            })

        return timeline
    finally:
        await db.close()


@router.get("/api/pcap/{pcap_id}/graph")
async def get_communication_graph(pcap_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, src_ip, dst_ip, src_port, dst_port,
               protocol, app_protocol, packet_count
               FROM sessions WHERE pcap_file_id = ?""",
            (pcap_id,)
        )
        rows = await cursor.fetchall()

        nodes_map = {}
        edges = []

        for r in rows:
            src = r['src_ip']
            dst = r['dst_ip']

            if src not in nodes_map:
                nodes_map[src] = {"id": src, "label": src, "packet_count": 0, "session_count": 0}
            if dst not in nodes_map:
                nodes_map[dst] = {"id": dst, "label": dst, "packet_count": 0, "session_count": 0}

            nodes_map[src]["packet_count"] += r['packet_count']
            nodes_map[src]["session_count"] += 1
            nodes_map[dst]["packet_count"] += r['packet_count']
            nodes_map[dst]["session_count"] += 1

            edges.append({
                "source": src,
                "target": dst,
                "protocol": r['protocol'],
                "app_protocol": r['app_protocol'],
                "packet_count": r['packet_count'],
                "session_id": r['id'],
            })

        return {
            "nodes": list(nodes_map.values()),
            "edges": edges,
        }
    finally:
        await db.close()


def _format_flags(flags: int) -> str:
    parts = []
    if flags & 0x02:
        parts.append("SYN")
    if flags & 0x10:
        parts.append("ACK")
    if flags & 0x01:
        parts.append("FIN")
    if flags & 0x04:
        parts.append("RST")
    if flags & 0x08:
        parts.append("PSH")
    return ",".join(parts)
