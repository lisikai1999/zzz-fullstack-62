import struct
import socket
from dataclasses import dataclass


@dataclass
class IPv4Packet:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str
    options: bytes
    payload: bytes
    header_length: int

    def to_dict(self) -> dict:
        return {
            "layer": "IPv4",
            "version": self.version,
            "ihl": self.ihl,
            "header_length": self.header_length,
            "tos": self.tos,
            "total_length": self.total_length,
            "identification": self.identification,
            "flags": {
                "reserved": bool(self.flags & 0x4),
                "dont_fragment": bool(self.flags & 0x2),
                "more_fragments": bool(self.flags & 0x1),
            },
            "fragment_offset": self.fragment_offset,
            "ttl": self.ttl,
            "protocol": self.protocol,
            "protocol_name": self._protocol_name(),
            "checksum": f"0x{self.checksum:04X}",
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
        }

    def _protocol_name(self) -> str:
        names = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return names.get(self.protocol, f"Unknown({self.protocol})")


class IPv4Decoder:
    HEADER_FORMAT = '!BBHHHBBH4s4s'
    MIN_HEADER_SIZE = 20

    def decode(self, data: bytes) -> IPv4Packet:
        if len(data) < self.MIN_HEADER_SIZE:
            raise ValueError(f"IP packet too short: {len(data)} bytes")

        fields = struct.unpack(self.HEADER_FORMAT, data[:self.MIN_HEADER_SIZE])

        version_ihl = fields[0]
        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F
        header_length = ihl * 4

        if version != 4:
            raise ValueError(f"Not IPv4: version={version}")
        if header_length < self.MIN_HEADER_SIZE:
            raise ValueError(f"Invalid IHL: {ihl}")
        if len(data) < header_length:
            raise ValueError(f"Packet shorter than header: {len(data)} < {header_length}")

        flags_frag = fields[4]
        flags = (flags_frag >> 13) & 0x07
        fragment_offset = flags_frag & 0x1FFF

        options = data[self.MIN_HEADER_SIZE:header_length] if header_length > self.MIN_HEADER_SIZE else b''

        total_length = fields[2]
        payload_end = min(total_length, len(data))

        return IPv4Packet(
            version=version,
            ihl=ihl,
            tos=fields[1],
            total_length=total_length,
            identification=fields[3],
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=fields[5],
            protocol=fields[6],
            checksum=fields[7],
            src_ip=socket.inet_ntoa(fields[8]),
            dst_ip=socket.inet_ntoa(fields[9]),
            options=options,
            payload=data[header_length:payload_end],
            header_length=header_length,
        )
