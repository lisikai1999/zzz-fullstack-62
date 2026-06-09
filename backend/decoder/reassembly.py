from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
import bisect


@dataclass
class StreamSegment:
    seq: int
    data: bytes
    timestamp: float
    is_retransmission: bool = False


@dataclass
class TcpStream:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    segments: List[StreamSegment] = field(default_factory=list)
    isn: Optional[int] = None
    next_expected_seq: int = 0
    fin_seen: bool = False
    rst_seen: bool = False

    @property
    def key(self) -> Tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)

    def reassemble(self) -> bytes:
        if not self.segments:
            return b''

        data_segments = [s for s in self.segments if not s.is_retransmission and s.data]
        data_segments.sort(key=lambda s: s.seq)

        result = bytearray()
        current_pos = data_segments[0].seq if data_segments else 0

        for seg in data_segments:
            if seg.seq >= current_pos:
                gap = seg.seq - current_pos
                if gap > 0:
                    result.extend(b'\x00' * gap)
                result.extend(seg.data)
                current_pos = seg.seq + len(seg.data)
            elif seg.seq + len(seg.data) > current_pos:
                overlap = current_pos - seg.seq
                result.extend(seg.data[overlap:])
                current_pos = seg.seq + len(seg.data)

        return bytes(result)


@dataclass
class ReassembledSession:
    session_key: Tuple
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    client_stream: TcpStream
    server_stream: TcpStream
    start_time: float
    end_time: float
    packet_count: int
    state: str  # "open", "closed", "reset"

    @property
    def client_payload(self) -> bytes:
        return self.client_stream.reassemble()

    @property
    def server_payload(self) -> bytes:
        return self.server_stream.reassemble()


class TcpReassembler:
    def __init__(self):
        self.streams: Dict[Tuple, TcpStream] = {}
        self.sessions: Dict[Tuple, dict] = {}

    def _session_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Tuple:
        pair = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
        return pair

    def _stream_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Tuple:
        return (src_ip, dst_ip, src_port, dst_port)

    def add_segment(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    seq: int, ack: int, flags: int, payload: bytes, timestamp: float):
        stream_key = self._stream_key(src_ip, dst_ip, src_port, dst_port)
        session_key = self._session_key(src_ip, dst_ip, src_port, dst_port)

        if session_key not in self.sessions:
            self.sessions[session_key] = {
                "start_time": timestamp,
                "end_time": timestamp,
                "packet_count": 0,
                "state": "open",
                "initiator": (src_ip, src_port),
            }

        session = self.sessions[session_key]
        session["end_time"] = timestamp
        session["packet_count"] += 1

        if stream_key not in self.streams:
            self.streams[stream_key] = TcpStream(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
            )

        stream = self.streams[stream_key]

        is_syn = bool(flags & 0x02)
        is_fin = bool(flags & 0x01)
        is_rst = bool(flags & 0x04)

        if is_syn:
            stream.isn = seq
            stream.next_expected_seq = seq + 1
            return

        if is_rst:
            stream.rst_seen = True
            session["state"] = "reset"
            return

        if is_fin:
            stream.fin_seen = True
            reverse_key = self._stream_key(dst_ip, src_ip, dst_port, src_port)
            reverse_stream = self.streams.get(reverse_key)
            if reverse_stream and reverse_stream.fin_seen:
                session["state"] = "closed"
            return

        if payload:
            is_retransmission = False
            if stream.next_expected_seq > 0 and seq < stream.next_expected_seq:
                for existing in stream.segments:
                    if existing.seq == seq and existing.data == payload:
                        is_retransmission = True
                        break

            segment = StreamSegment(
                seq=seq, data=payload,
                timestamp=timestamp,
                is_retransmission=is_retransmission,
            )
            stream.segments.append(segment)

            if not is_retransmission:
                expected_end = seq + len(payload)
                if expected_end > stream.next_expected_seq:
                    stream.next_expected_seq = expected_end

    def get_sessions(self) -> List[ReassembledSession]:
        results = []

        for session_key, session_info in self.sessions.items():
            (addr1, addr2) = session_key
            initiator = session_info["initiator"]

            if initiator == addr1:
                client_ip, client_port = addr1
                server_ip, server_port = addr2
            else:
                client_ip, client_port = addr2
                server_ip, server_port = addr1

            client_stream_key = self._stream_key(client_ip, server_ip, client_port, server_port)
            server_stream_key = self._stream_key(server_ip, client_ip, server_port, client_port)

            client_stream = self.streams.get(client_stream_key, TcpStream(
                src_ip=client_ip, dst_ip=server_ip,
                src_port=client_port, dst_port=server_port,
            ))
            server_stream = self.streams.get(server_stream_key, TcpStream(
                src_ip=server_ip, dst_ip=client_ip,
                src_port=server_port, dst_port=client_port,
            ))

            results.append(ReassembledSession(
                session_key=session_key,
                src_ip=client_ip,
                dst_ip=server_ip,
                src_port=client_port,
                dst_port=server_port,
                client_stream=client_stream,
                server_stream=server_stream,
                start_time=session_info["start_time"],
                end_time=session_info["end_time"],
                packet_count=session_info["packet_count"],
                state=session_info["state"],
            ))

        return results
