from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class PcapFileResponse(BaseModel):
    id: int
    filename: str
    file_size: int
    packet_count: int
    upload_time: str
    parse_status: str


class PacketSummary(BaseModel):
    id: int
    packet_index: int
    timestamp: float
    eth_src: Optional[str]
    eth_dst: Optional[str]
    ip_src: Optional[str]
    ip_dst: Optional[str]
    ip_protocol: Optional[int]
    src_port: Optional[int]
    dst_port: Optional[int]
    tcp_flags: Optional[str]
    payload_length: int
    protocol_summary: str


class PacketDetail(BaseModel):
    id: int
    packet_index: int
    timestamp: float
    raw_length: int
    captured_length: int
    decoded: Dict[str, Any]
    hex_dump: str


class SessionResponse(BaseModel):
    id: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    app_protocol: Optional[str]
    packet_count: int
    total_bytes: int
    start_time: float
    end_time: Optional[float]
    duration_ms: Optional[float]
    state: str


class SessionDetail(SessionResponse):
    app_decoded: Optional[Dict[str, Any]]
    client_payload_preview: Optional[str]
    server_payload_preview: Optional[str]


class TimelineEntry(BaseModel):
    packet_index: int
    timestamp: float
    direction: str
    src_port: int
    dst_port: int
    flags: Optional[str]
    payload_length: int


class GraphNode(BaseModel):
    id: str
    label: str
    packet_count: int
    session_count: int


class GraphEdge(BaseModel):
    source: str
    target: str
    protocol: str
    app_protocol: Optional[str]
    packet_count: int
    session_id: int


class GraphData(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class SensitiveFinding(BaseModel):
    id: int
    session_id: int
    rule_name: str
    severity: str
    matched_text: str
    context: Optional[str]
    direction: str
    description: Optional[str] = None


class SensitiveStats(BaseModel):
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    by_rule: Dict[str, int]


class ReplayRequest(BaseModel):
    session_id: int
    target_ip: str
    target_port: int
    speed_factor: float = 1.0
    field_overrides: Optional[Dict[str, Any]] = None
    raw_mode: bool = False


class ReplayJobResponse(BaseModel):
    id: int
    session_id: int
    target_ip: str
    target_port: int
    speed_factor: float
    status: str
    packets_sent: int
    packets_matched: int
    started_at: Optional[str]
    completed_at: Optional[str]
