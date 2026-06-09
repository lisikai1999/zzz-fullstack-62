import aiosqlite
from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS pcap_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    packet_count INTEGER DEFAULT 0,
    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    parse_status TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_file_id INTEGER NOT NULL REFERENCES pcap_files(id),
    packet_index INTEGER NOT NULL,
    timestamp_sec INTEGER NOT NULL,
    timestamp_usec INTEGER NOT NULL,
    raw_length INTEGER NOT NULL,
    captured_length INTEGER NOT NULL,
    eth_src TEXT,
    eth_dst TEXT,
    eth_type INTEGER,
    ip_src TEXT,
    ip_dst TEXT,
    ip_protocol INTEGER,
    ip_ttl INTEGER,
    src_port INTEGER,
    dst_port INTEGER,
    tcp_seq INTEGER,
    tcp_ack INTEGER,
    tcp_flags INTEGER,
    tcp_window INTEGER,
    payload_length INTEGER DEFAULT 0,
    payload BLOB,
    session_id INTEGER,
    decoded_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_file_id INTEGER NOT NULL REFERENCES pcap_files(id),
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    app_protocol TEXT,
    packet_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    start_time REAL NOT NULL,
    end_time REAL,
    duration_ms REAL,
    client_payload BLOB,
    server_payload BLOB,
    app_decoded_json TEXT,
    state TEXT DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS sensitive_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    pcap_file_id INTEGER NOT NULL REFERENCES pcap_files(id),
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    matched_text TEXT NOT NULL,
    context TEXT,
    byte_offset INTEGER,
    direction TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS replay_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    target_ip TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    speed_factor REAL DEFAULT 1.0,
    field_overrides TEXT,
    status TEXT DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    packets_sent INTEGER DEFAULT 0,
    packets_matched INTEGER DEFAULT 0,
    result_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_packets_pcap ON packets(pcap_file_id);
CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_pcap ON sessions(pcap_file_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON sensitive_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_pcap ON sensitive_findings(pcap_file_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON sensitive_findings(severity);
"""


async def get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def init_db():
    db = await get_db()
    try:
        await db.executescript(SCHEMA)
        await db.commit()
    finally:
        await db.close()
