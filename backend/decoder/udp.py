import struct
from dataclasses import dataclass


@dataclass
class UdpDatagram:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes

    def to_dict(self) -> dict:
        return {
            "layer": "UDP",
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "length": self.length,
            "checksum": f"0x{self.checksum:04X}",
            "payload_length": len(self.payload),
        }


class UdpDecoder:
    HEADER_FORMAT = '!HHHH'
    HEADER_SIZE = 8

    def decode(self, data: bytes) -> UdpDatagram:
        if len(data) < self.HEADER_SIZE:
            raise ValueError(f"UDP datagram too short: {len(data)} bytes")

        src_port, dst_port, length, checksum = struct.unpack(
            self.HEADER_FORMAT, data[:self.HEADER_SIZE]
        )

        payload_end = min(length, len(data))
        payload = data[self.HEADER_SIZE:payload_end]

        return UdpDatagram(
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            checksum=checksum,
            payload=payload,
        )
