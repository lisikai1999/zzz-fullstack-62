import struct
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class PcapGlobalHeader:
    magic: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int
    byte_order: str  # '<' or '>'


@dataclass
class RawPacket:
    index: int
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int
    data: bytes

    @property
    def timestamp(self) -> float:
        return self.ts_sec + self.ts_usec / 1_000_000


class PcapParser:
    MAGIC_LE = 0xA1B2C3D4
    MAGIC_BE = 0xD4C3B2A1
    GLOBAL_HEADER_SIZE = 24
    PACKET_HEADER_SIZE = 16

    def __init__(self, data: bytes):
        self.data = data
        self.header: PcapGlobalHeader = None
        self.packets: List[RawPacket] = []

    def parse(self) -> List[RawPacket]:
        if len(self.data) < self.GLOBAL_HEADER_SIZE:
            raise ValueError("File too small for pcap global header")

        self.header = self._parse_global_header()
        self.packets = self._parse_packets()
        return self.packets

    def _parse_global_header(self) -> PcapGlobalHeader:
        magic = struct.unpack('<I', self.data[:4])[0]
        if magic == self.MAGIC_LE:
            byte_order = '<'
        elif magic == self.MAGIC_BE:
            byte_order = '>'
        else:
            raise ValueError(f"Invalid pcap magic number: 0x{magic:08X}")

        fmt = f'{byte_order}IHHiIII'
        fields = struct.unpack(fmt, self.data[:self.GLOBAL_HEADER_SIZE])
        return PcapGlobalHeader(
            magic=fields[0],
            version_major=fields[1],
            version_minor=fields[2],
            thiszone=fields[3],
            sigfigs=fields[4],
            snaplen=fields[5],
            network=fields[6],
            byte_order=byte_order,
        )

    def _parse_packets(self) -> List[RawPacket]:
        packets = []
        offset = self.GLOBAL_HEADER_SIZE
        index = 0
        bo = self.header.byte_order

        while offset + self.PACKET_HEADER_SIZE <= len(self.data):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f'{bo}IIII', self.data[offset:offset + self.PACKET_HEADER_SIZE]
            )
            offset += self.PACKET_HEADER_SIZE

            if offset + incl_len > len(self.data):
                break

            pkt_data = self.data[offset:offset + incl_len]
            offset += incl_len

            packets.append(RawPacket(
                index=index,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                incl_len=incl_len,
                orig_len=orig_len,
                data=pkt_data,
            ))
            index += 1

        return packets
