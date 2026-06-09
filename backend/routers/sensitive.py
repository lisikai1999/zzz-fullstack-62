from fastapi import APIRouter, HTTPException
from database import get_db

router = APIRouter()


@router.get("/api/pcap/{pcap_id}/sensitive")
async def get_sensitive_findings(pcap_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, session_id, rule_name, severity, matched_text,
               context, byte_offset, direction, created_at
               FROM sensitive_findings WHERE pcap_file_id = ?
               ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END""",
            (pcap_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/api/sessions/{session_id}/sensitive")
async def get_session_sensitive(session_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, session_id, rule_name, severity, matched_text,
               context, byte_offset, direction
               FROM sensitive_findings WHERE session_id = ?
               ORDER BY byte_offset""",
            (session_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/api/sensitive/stats")
async def get_sensitive_stats():
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) as total FROM sensitive_findings")
        total = (await cursor.fetchone())['total']

        cursor = await db.execute(
            "SELECT severity, COUNT(*) as cnt FROM sensitive_findings GROUP BY severity"
        )
        severity_counts = {row['severity']: row['cnt'] for row in await cursor.fetchall()}

        cursor = await db.execute(
            "SELECT rule_name, COUNT(*) as cnt FROM sensitive_findings GROUP BY rule_name ORDER BY cnt DESC"
        )
        by_rule = {row['rule_name']: row['cnt'] for row in await cursor.fetchall()}

        return {
            "total_findings": total,
            "critical_count": severity_counts.get('critical', 0),
            "high_count": severity_counts.get('high', 0),
            "medium_count": severity_counts.get('medium', 0),
            "by_rule": by_rule,
        }
    finally:
        await db.close()
