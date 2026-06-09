import json
import asyncio
from datetime import datetime
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from database import get_db
from models.schemas import ReplayRequest
from replay.engine import ReplayEngine
from replay.timing import TimedSegment

router = APIRouter()
active_replays = {}


@router.post("/api/replay")
async def start_replay(req: ReplayRequest):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, client_payload, server_payload, start_time FROM sessions WHERE id = ?",
            (req.session_id,)
        )
        session = await cursor.fetchone()
        if not session:
            raise HTTPException(404, "Session not found")

        cursor = await db.execute(
            """INSERT INTO replay_jobs (session_id, target_ip, target_port, speed_factor, field_overrides, status, started_at)
               VALUES (?, ?, ?, ?, ?, 'running', ?)""",
            (req.session_id, req.target_ip, req.target_port, req.speed_factor,
             json.dumps(req.field_overrides) if req.field_overrides else None,
             datetime.utcnow().isoformat())
        )
        job_id = cursor.lastrowid
        await db.commit()

        # Build segments from session packets
        cursor = await db.execute(
            """SELECT packet_index, timestamp_sec, timestamp_usec, ip_src, payload
               FROM packets WHERE session_id = ? AND payload_length > 0
               ORDER BY packet_index""",
            (req.session_id,)
        )
        pkt_rows = await cursor.fetchall()

        # Fallback: get packets by matching session IP/port
        if not pkt_rows:
            cursor = await db.execute(
                """SELECT packet_index, timestamp_sec, timestamp_usec, ip_src, payload
                   FROM packets WHERE pcap_file_id = (SELECT pcap_file_id FROM sessions WHERE id = ?)
                   AND ip_src = (SELECT src_ip FROM sessions WHERE id = ?)
                   AND src_port = (SELECT src_port FROM sessions WHERE id = ?)
                   AND payload_length > 0
                   ORDER BY packet_index""",
                (req.session_id, req.session_id, req.session_id)
            )
            pkt_rows = await cursor.fetchall()

        sess_src_ip_cursor = await db.execute("SELECT src_ip FROM sessions WHERE id = ?", (req.session_id,))
        sess_row = await sess_src_ip_cursor.fetchone()
        sess_src_ip = sess_row['src_ip'] if sess_row else None

        client_segments = []
        server_segments = []
        for r in pkt_rows:
            ts = r['timestamp_sec'] + r['timestamp_usec'] / 1_000_000
            seg = TimedSegment(index=r['packet_index'], timestamp=ts, data=r['payload'])
            if r['ip_src'] == sess_src_ip:
                client_segments.append(seg)
            else:
                server_segments.append(seg)

        engine = ReplayEngine(
            target_ip=req.target_ip,
            target_port=req.target_port,
            speed_factor=req.speed_factor,
            field_overrides=req.field_overrides,
            raw_mode=req.raw_mode,
        )
        active_replays[job_id] = engine

        asyncio.create_task(_run_replay(job_id, engine, client_segments, server_segments))

        return {"id": job_id, "status": "running"}
    finally:
        await db.close()


async def _run_replay(job_id: int, engine: ReplayEngine,
                      client_segments, server_segments):
    try:
        result = await engine.replay_session(client_segments, server_segments)

        db = await get_db()
        try:
            await db.execute(
                """UPDATE replay_jobs SET status = ?, completed_at = ?,
                   packets_sent = ?, packets_matched = ?, result_json = ?
                   WHERE id = ?""",
                (result.status, datetime.utcnow().isoformat(),
                 result.packets_sent, result.packets_matched,
                 json.dumps(result.to_dict()), job_id)
            )
            await db.commit()
        finally:
            await db.close()
    except Exception as e:
        db = await get_db()
        try:
            await db.execute(
                "UPDATE replay_jobs SET status = 'error', completed_at = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), job_id)
            )
            await db.commit()
        finally:
            await db.close()
    finally:
        active_replays.pop(job_id, None)


@router.get("/api/replay/{job_id}")
async def get_replay_status(job_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, session_id, target_ip, target_port, speed_factor,
               status, started_at, completed_at, packets_sent, packets_matched, result_json
               FROM replay_jobs WHERE id = ?""",
            (job_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Replay job not found")

        result = dict(row)
        if result['result_json']:
            result['result'] = json.loads(result['result_json'])
        result.pop('result_json', None)
        return result
    finally:
        await db.close()


@router.post("/api/replay/{job_id}/stop")
async def stop_replay(job_id: int):
    engine = active_replays.get(job_id)
    if not engine:
        raise HTTPException(404, "Replay job not active")
    engine.stop()
    return {"status": "stopping"}


@router.websocket("/api/ws/replay/{job_id}")
async def replay_websocket(websocket: WebSocket, job_id: int):
    await websocket.accept()

    engine = active_replays.get(job_id)
    if not engine:
        await websocket.send_json({"error": "Replay job not active"})
        await websocket.close()
        return

    queue = asyncio.Queue()

    async def on_packet_result(result):
        await queue.put(result.to_dict())

    engine.set_callback(on_packet_result)

    try:
        while True:
            try:
                data = await asyncio.wait_for(queue.get(), timeout=30)
                await websocket.send_json(data)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "heartbeat"})
            except WebSocketDisconnect:
                break
    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
