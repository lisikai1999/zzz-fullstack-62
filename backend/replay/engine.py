import asyncio
import re
import struct
import socket
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Awaitable

from .timing import TimingController, TimedSegment
from .comparator import ResponseComparator, DiffResult


@dataclass
class ReplayPacketResult:
    packet_index: int
    sent_bytes: int
    response_bytes: int
    timing_delta_ms: float
    diff_result: DiffResult
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "packet_index": self.packet_index,
            "sent_bytes": self.sent_bytes,
            "response_bytes": self.response_bytes,
            "timing_delta_ms": round(self.timing_delta_ms, 2),
            "match": self.diff_result.match,
            "diff": self.diff_result.to_dict(),
            "error": self.error,
        }


@dataclass
class ReplayResult:
    total_packets: int
    packets_sent: int
    packets_matched: int
    results: List[ReplayPacketResult]
    status: str  # "completed", "stopped", "error"
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "packets_sent": self.packets_sent,
            "packets_matched": self.packets_matched,
            "status": self.status,
            "error": self.error,
            "results": [r.to_dict() for r in self.results],
        }


class PacketRewriter:
    """Modifies raw IP packets: rewrite destination IP and recalculate checksums."""

    @staticmethod
    def compute_ip_checksum(header: bytes) -> int:
        """Compute IP header checksum per RFC 791."""
        if len(header) % 2 == 1:
            header = header + b'\x00'
        total = 0
        for i in range(0, len(header), 2):
            total += (header[i] << 8) | header[i + 1]
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return ~total & 0xFFFF

    @staticmethod
    def compute_tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_segment: bytes) -> int:
        """Compute TCP checksum with pseudo-header per RFC 793."""
        # Pseudo-header: src_ip(4) + dst_ip(4) + reserved(1) + protocol(1) + tcp_length(2)
        tcp_length = len(tcp_segment)
        pseudo_header = src_ip + dst_ip + struct.pack('!BBH', 0, 6, tcp_length)

        data = pseudo_header + tcp_segment
        if len(data) % 2 == 1:
            data = data + b'\x00'

        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) | data[i + 1]
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return ~total & 0xFFFF

    @staticmethod
    def compute_udp_checksum(src_ip: bytes, dst_ip: bytes, udp_datagram: bytes) -> int:
        """Compute UDP checksum with pseudo-header per RFC 768."""
        udp_length = len(udp_datagram)
        pseudo_header = src_ip + dst_ip + struct.pack('!BBH', 0, 17, udp_length)

        data = pseudo_header + udp_datagram
        if len(data) % 2 == 1:
            data = data + b'\x00'

        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) | data[i + 1]
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        result = ~total & 0xFFFF
        return result if result != 0 else 0xFFFF  # UDP checksum of 0 means "no checksum"

    def rewrite_dst_ip(self, raw_packet: bytes, new_dst_ip: str) -> bytes:
        """Rewrite destination IP in a raw IP packet, recalculating IP + transport checksums.

        Args:
            raw_packet: Raw bytes starting from IP header (no Ethernet)
            new_dst_ip: New destination IP address (dotted quad)

        Returns:
            Modified packet with updated destination and valid checksums
        """
        if len(raw_packet) < 20:
            return raw_packet

        version_ihl = raw_packet[0]
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(raw_packet) < ihl:
            return raw_packet

        protocol = raw_packet[9]
        new_dst_bytes = socket.inet_aton(new_dst_ip)

        # Build modified IP header
        pkt = bytearray(raw_packet)

        # Overwrite destination IP (bytes 16-20)
        pkt[16:20] = new_dst_bytes

        # Zero out IP header checksum and recompute
        pkt[10:12] = b'\x00\x00'
        new_ip_checksum = self.compute_ip_checksum(bytes(pkt[:ihl]))
        pkt[10:12] = struct.pack('!H', new_ip_checksum)

        src_ip_bytes = bytes(pkt[12:16])

        # Recalculate transport layer checksum
        if protocol == 6 and len(pkt) >= ihl + 20:  # TCP
            tcp_data = bytearray(pkt[ihl:])
            # Zero TCP checksum (offset 16-17 within TCP header)
            tcp_data[16:18] = b'\x00\x00'
            new_tcp_checksum = self.compute_tcp_checksum(src_ip_bytes, new_dst_bytes, bytes(tcp_data))
            tcp_data[16:18] = struct.pack('!H', new_tcp_checksum)
            pkt[ihl:] = tcp_data

        elif protocol == 17 and len(pkt) >= ihl + 8:  # UDP
            udp_data = bytearray(pkt[ihl:])
            # Zero UDP checksum (offset 6-7 within UDP header)
            udp_data[6:8] = b'\x00\x00'
            new_udp_checksum = self.compute_udp_checksum(src_ip_bytes, new_dst_bytes, bytes(udp_data))
            udp_data[6:8] = struct.pack('!H', new_udp_checksum)
            pkt[ihl:] = udp_data

        return bytes(pkt)

    def rewrite_src_ip(self, raw_packet: bytes, new_src_ip: str) -> bytes:
        """Rewrite source IP in a raw IP packet, recalculating checksums."""
        if len(raw_packet) < 20:
            return raw_packet

        version_ihl = raw_packet[0]
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(raw_packet) < ihl:
            return raw_packet

        protocol = raw_packet[9]
        new_src_bytes = socket.inet_aton(new_src_ip)

        pkt = bytearray(raw_packet)

        # Overwrite source IP (bytes 12-16)
        pkt[12:16] = new_src_bytes

        # Recompute IP checksum
        pkt[10:12] = b'\x00\x00'
        new_ip_checksum = self.compute_ip_checksum(bytes(pkt[:ihl]))
        pkt[10:12] = struct.pack('!H', new_ip_checksum)

        dst_ip_bytes = bytes(pkt[16:20])

        # Recalculate transport layer checksum
        if protocol == 6 and len(pkt) >= ihl + 20:
            tcp_data = bytearray(pkt[ihl:])
            tcp_data[16:18] = b'\x00\x00'
            new_tcp_checksum = self.compute_tcp_checksum(new_src_bytes, dst_ip_bytes, bytes(tcp_data))
            tcp_data[16:18] = struct.pack('!H', new_tcp_checksum)
            pkt[ihl:] = tcp_data
        elif protocol == 17 and len(pkt) >= ihl + 8:
            udp_data = bytearray(pkt[ihl:])
            udp_data[6:8] = b'\x00\x00'
            new_udp_checksum = self.compute_udp_checksum(new_src_bytes, dst_ip_bytes, bytes(udp_data))
            udp_data[6:8] = struct.pack('!H', new_udp_checksum)
            pkt[ihl:] = udp_data

        return bytes(pkt)

    def rewrite_packet(self, raw_packet: bytes, new_dst_ip: Optional[str] = None,
                       new_src_ip: Optional[str] = None) -> bytes:
        """Apply all address rewrites and recalculate checksums."""
        result = raw_packet
        if new_dst_ip:
            result = self.rewrite_dst_ip(result, new_dst_ip)
        if new_src_ip:
            result = self.rewrite_src_ip(result, new_src_ip)
        return result


class ReplayEngine:
    def __init__(self, target_ip: str, target_port: int,
                 speed_factor: float = 1.0,
                 field_overrides: Optional[Dict] = None,
                 raw_mode: bool = False):
        self.target_ip = target_ip
        self.target_port = target_port
        self.speed_factor = speed_factor
        self.field_overrides = field_overrides or {}
        self.raw_mode = raw_mode
        self.comparator = ResponseComparator()
        self.rewriter = PacketRewriter()
        self._running = False
        self._callback: Optional[Callable[[ReplayPacketResult], Awaitable]] = None

    def set_callback(self, callback: Callable[[ReplayPacketResult], Awaitable]):
        self._callback = callback

    async def replay_session(self, client_segments: List[TimedSegment],
                             server_segments: List[TimedSegment]) -> ReplayResult:
        if not client_segments:
            return ReplayResult(
                total_packets=0, packets_sent=0, packets_matched=0,
                results=[], status="completed",
            )

        if self.raw_mode:
            return await self._replay_raw(client_segments, server_segments)
        return await self._replay_tcp(client_segments, server_segments)

    async def _replay_tcp(self, client_segments: List[TimedSegment],
                          server_segments: List[TimedSegment]) -> ReplayResult:
        """Application-level TCP replay: connect to target and send payload segments."""
        timing = TimingController(client_segments, self.speed_factor)
        self._running = True
        results: List[ReplayPacketResult] = []

        try:
            reader, writer = await asyncio.open_connection(self.target_ip, self.target_port)
        except Exception as e:
            return ReplayResult(
                total_packets=len(client_segments), packets_sent=0,
                packets_matched=0, results=[], status="error",
                error=str(e),
            )

        try:
            for i, segment in enumerate(timing.segments):
                if not self._running:
                    break

                delay = timing.get_delay(i)
                if delay > 0:
                    await asyncio.sleep(delay)

                payload = self._apply_overrides(segment.data)

                send_time = time.monotonic()
                try:
                    writer.write(payload)
                    await writer.drain()

                    response = await self._read_response(reader)
                except Exception as e:
                    result = ReplayPacketResult(
                        packet_index=i,
                        sent_bytes=len(payload),
                        response_bytes=0,
                        timing_delta_ms=0,
                        diff_result=DiffResult(match=False, diff_text=None,
                                               original_length=0, actual_length=0, similarity=0),
                        error=str(e),
                    )
                    results.append(result)
                    if self._callback:
                        await self._callback(result)
                    continue

                elapsed = (time.monotonic() - send_time) * 1000

                original_response = b''
                if i < len(server_segments):
                    original_response = server_segments[i].data

                diff_result = self.comparator.compare(original_response, response)

                result = ReplayPacketResult(
                    packet_index=i,
                    sent_bytes=len(payload),
                    response_bytes=len(response),
                    timing_delta_ms=elapsed,
                    diff_result=diff_result,
                )
                results.append(result)

                if self._callback:
                    await self._callback(result)

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self._running = False

        packets_matched = sum(1 for r in results if r.diff_result.match)
        status = "completed" if len(results) == len(client_segments) else "stopped"

        return ReplayResult(
            total_packets=len(client_segments),
            packets_sent=len(results),
            packets_matched=packets_matched,
            results=results,
            status=status,
        )

    async def _replay_raw(self, client_segments: List[TimedSegment],
                          server_segments: List[TimedSegment]) -> ReplayResult:
        """Raw IP-level replay: send modified packets via raw socket.

        Rewrites destination address and recalculates checksums for gray testing.
        Requires CAP_NET_RAW or root.
        """
        timing = TimingController(client_segments, self.speed_factor)
        self._running = True
        results: List[ReplayPacketResult] = []

        override_dst = self.field_overrides.get('target_ip', self.target_ip)
        override_src = self.field_overrides.get('source_ip')

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            raw_sock.setblocking(False)
        except OSError as e:
            return ReplayResult(
                total_packets=len(client_segments), packets_sent=0,
                packets_matched=0, results=[], status="error",
                error=f"Raw socket creation failed (need root/CAP_NET_RAW): {e}",
            )

        try:
            for i, segment in enumerate(timing.segments):
                if not self._running:
                    break

                delay = timing.get_delay(i)
                if delay > 0:
                    await asyncio.sleep(delay)

                # Rewrite addresses and recalculate checksums
                modified_packet = self.rewriter.rewrite_packet(
                    segment.data,
                    new_dst_ip=override_dst,
                    new_src_ip=override_src,
                )

                send_time = time.monotonic()
                try:
                    raw_sock.sendto(modified_packet, (override_dst, 0))
                except Exception as e:
                    result = ReplayPacketResult(
                        packet_index=i,
                        sent_bytes=len(modified_packet),
                        response_bytes=0,
                        timing_delta_ms=0,
                        diff_result=DiffResult(match=False, diff_text=None,
                                               original_length=0, actual_length=0, similarity=0),
                        error=str(e),
                    )
                    results.append(result)
                    if self._callback:
                        await self._callback(result)
                    continue

                elapsed = (time.monotonic() - send_time) * 1000

                # In raw mode we can't easily capture responses inline;
                # report what was sent and mark as "sent" with no response comparison
                original_response = b''
                if i < len(server_segments):
                    original_response = server_segments[i].data

                result = ReplayPacketResult(
                    packet_index=i,
                    sent_bytes=len(modified_packet),
                    response_bytes=0,
                    timing_delta_ms=elapsed,
                    diff_result=DiffResult(match=False, diff_text="raw mode: no inline response capture",
                                           original_length=len(original_response), actual_length=0, similarity=0),
                )
                results.append(result)

                if self._callback:
                    await self._callback(result)

        finally:
            raw_sock.close()
            self._running = False

        return ReplayResult(
            total_packets=len(client_segments),
            packets_sent=len(results),
            packets_matched=0,
            results=results,
            status="completed" if len(results) == len(client_segments) else "stopped",
        )

    async def _read_response(self, reader: asyncio.StreamReader, timeout: float = 2.0) -> bytes:
        data = bytearray()
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=0.5)
                if not chunk:
                    break
                data.extend(chunk)
        except asyncio.TimeoutError:
            pass
        return bytes(data)

    def _apply_overrides(self, payload: bytes) -> bytes:
        modified = payload
        for field_name, value in self.field_overrides.items():
            if field_name == 'host_header' and b'Host:' in modified:
                modified = re.sub(
                    rb'Host:\s*[^\r\n]+',
                    f'Host: {value}'.encode(),
                    modified,
                )
            elif field_name == 'replace':
                if isinstance(value, dict):
                    for old, new in value.items():
                        modified = modified.replace(
                            old.encode() if isinstance(old, str) else old,
                            new.encode() if isinstance(new, str) else new,
                        )
        return modified

    def stop(self):
        self._running = False
