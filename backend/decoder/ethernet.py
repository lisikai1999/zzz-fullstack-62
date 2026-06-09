import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class EthernetFrame:
    dst_mac: str
    src_mac: str
    ethertype: int
    vlan_id: Optional[int]
    payload: bytes
    header_length: int

    def to_dict(self) -> dict:
        result = {
            "layer": "Ethernet",
            "dst_mac": self.dst_mac,
            "src_mac": self.src_mac,
            "ethertype": f"0x{self.ethertype:04X}",
            "ethertype_name": self._ethertype_name(),
            "header_length": self.header_length,
        }
        if self.vlan_id is not None:
            result["vlan_id"] = self.vlan_id
        return result

    def _ethertype_name(self) -> str:
        names = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "802.1Q",
        }
        return names.get(self.ethertype, "Unknown")


class EthernetDecoder:
    HEADER_FORMAT = '!6s6sH'
    HEADER_SIZE = 14
    VLAN_TAG = 0x8100

    @staticmethod
    def format_mac(raw: bytes) -> str:
        return ':'.join(f'{b:02x}' for b in raw)

    def decode(self, data: bytes) -> EthernetFrame:
        if len(data) < self.HEADER_SIZE:
            raise ValueError(f"Ethernet frame too short: {len(data)} bytes")

        dst_raw, src_raw, ethertype = struct.unpack(
            self.HEADER_FORMAT, data[:self.HEADER_SIZE]
        )

        header_length = self.HEADER_SIZE
        vlan_id = None

        if ethertype == self.VLAN_TAG:
            if len(data) < self.HEADER_SIZE + 4:
                raise ValueError("Truncated VLAN tag")
            tci, ethertype = struct.unpack('!HH', data[self.HEADER_SIZE:self.HEADER_SIZE + 4])
            vlan_id = tci & 0x0FFF
            header_length += 4

        return EthernetFrame(
            dst_mac=self.format_mac(dst_raw),
            src_mac=self.format_mac(src_raw),
            ethertype=ethertype,
            vlan_id=vlan_id,
            payload=data[header_length:],
            header_length=header_length,
        )
