import json
from fastapi import APIRouter, HTTPException, Query
from database import get_db

router = APIRouter()


@router.get("/api/pcap/{pcap_id}/packets")
async def list_packets(pcap_id: int, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT COUNT(*) as total FROM packets WHERE pcap_file_id = ?", (pcap_id,)
        )
        row = await cursor.fetchone()
        total = row['total']

        offset = (page - 1) * page_size
        cursor = await db.execute(
            """SELECT id, packet_index, timestamp_sec, timestamp_usec,
               eth_src, eth_dst, ip_src, ip_dst, ip_protocol,
               src_port, dst_port, tcp_flags, payload_length, decoded_json
               FROM packets WHERE pcap_file_id = ?
               ORDER BY packet_index LIMIT ? OFFSET ?""",
            (pcap_id, page_size, offset)
        )
        rows = await cursor.fetchall()

        packets = []
        for r in rows:
            ts = r['timestamp_sec'] + r['timestamp_usec'] / 1_000_000
            flags_str = _format_tcp_flags(r['tcp_flags']) if r['tcp_flags'] is not None else None
            protocol_summary = _get_protocol_summary(r)

            packets.append({
                "id": r['id'],
                "packet_index": r['packet_index'],
                "timestamp": ts,
                "eth_src": r['eth_src'],
                "eth_dst": r['eth_dst'],
                "ip_src": r['ip_src'],
                "ip_dst": r['ip_dst'],
                "ip_protocol": r['ip_protocol'],
                "src_port": r['src_port'],
                "dst_port": r['dst_port'],
                "tcp_flags": flags_str,
                "payload_length": r['payload_length'],
                "protocol_summary": protocol_summary,
            })

        return {"total": total, "page": page, "page_size": page_size, "packets": packets}
    finally:
        await db.close()


@router.get("/api/packets/{packet_id}")
async def get_packet_detail(packet_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, packet_index, timestamp_sec, timestamp_usec,
               raw_length, captured_length, payload, decoded_json
               FROM packets WHERE id = ?""",
            (packet_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Packet not found")

        payload = row['payload'] or b''
        hex_dump = _format_hex_dump(payload)
        decoded = json.loads(row['decoded_json'])
        ts = row['timestamp_sec'] + row['timestamp_usec'] / 1_000_000

        return {
            "id": row['id'],
            "packet_index": row['packet_index'],
            "timestamp": ts,
            "raw_length": row['raw_length'],
            "captured_length": row['captured_length'],
            "decoded": decoded,
            "hex_dump": hex_dump,
        }
    finally:
        await db.close()


def _format_tcp_flags(flags: int) -> str:
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
    return ",".join(parts) if parts else ""


def _get_protocol_summary(row) -> str:
    proto = row['ip_protocol']
    if proto == 6:
        flags = _format_tcp_flags(row['tcp_flags']) if row['tcp_flags'] else ""
        return f"TCP {row['src_port']}→{row['dst_port']} [{flags}]"
    elif proto == 17:
        return f"UDP {row['src_port']}→{row['dst_port']}"
    elif proto == 1:
        return "ICMP"
    return f"Proto({proto})" if proto else "L2"


def _format_hex_dump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width*3}}  {ascii_part}")
    return '\n'.join(lines)
