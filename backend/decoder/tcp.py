import struct
from dataclasses import dataclass
from typing import List, Dict


@dataclass
class TcpSegment:
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int
    flags: int
    window: int
    checksum: int
    urgent_ptr: int
    options: List[Dict]
    payload: bytes
    header_length: int

    @property
    def flag_fin(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def flag_syn(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def flag_rst(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def flag_psh(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def flag_ack(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def flag_urg(self) -> bool:
        return bool(self.flags & 0x20)

    def flags_str(self) -> str:
        parts = []
        if self.flag_syn:
            parts.append("SYN")
        if self.flag_ack:
            parts.append("ACK")
        if self.flag_fin:
            parts.append("FIN")
        if self.flag_rst:
            parts.append("RST")
        if self.flag_psh:
            parts.append("PSH")
        if self.flag_urg:
            parts.append("URG")
        return ",".join(parts) if parts else "NONE"

    def to_dict(self) -> dict:
        return {
            "layer": "TCP",
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "seq_num": self.seq_num,
            "ack_num": self.ack_num,
            "data_offset": self.data_offset,
            "header_length": self.header_length,
            "flags": self.flags_str(),
            "flags_raw": self.flags,
            "window": self.window,
            "checksum": f"0x{self.checksum:04X}",
            "urgent_ptr": self.urgent_ptr,
            "options": self.options,
            "payload_length": len(self.payload),
        }


class TcpDecoder:
    HEADER_FORMAT = '!HHIIHHHH'
    MIN_HEADER_SIZE = 20

    def decode(self, data: bytes) -> TcpSegment:
        if len(data) < self.MIN_HEADER_SIZE:
            raise ValueError(f"TCP segment too short: {len(data)} bytes")

        fields = struct.unpack(self.HEADER_FORMAT, data[:self.MIN_HEADER_SIZE])

        data_offset_reserved_flags = fields[4]
        data_offset = (data_offset_reserved_flags >> 12) & 0x0F
        flags = data_offset_reserved_flags & 0x3F
        header_length = data_offset * 4

        if header_length < self.MIN_HEADER_SIZE:
            raise ValueError(f"Invalid TCP data offset: {data_offset}")
        if len(data) < header_length:
            raise ValueError(f"TCP segment shorter than header")

        options = self._parse_options(data[self.MIN_HEADER_SIZE:header_length])

        return TcpSegment(
            src_port=fields[0],
            dst_port=fields[1],
            seq_num=fields[2],
            ack_num=fields[3],
            data_offset=data_offset,
            flags=flags,
            window=fields[5],
            checksum=fields[6],
            urgent_ptr=fields[7],
            options=options,
            payload=data[header_length:],
            header_length=header_length,
        )

    def _parse_options(self, data: bytes) -> List[Dict]:
        options = []
        offset = 0
        while offset < len(data):
            kind = data[offset]
            if kind == 0:  # End of options
                break
            if kind == 1:  # NOP
                options.append({"kind": 1, "name": "NOP"})
                offset += 1
                continue

            if offset + 1 >= len(data):
                break
            length = data[offset + 1]
            if length < 2 or offset + length > len(data):
                break

            opt_data = data[offset + 2:offset + length]
            opt = {"kind": kind, "length": length}

            if kind == 2 and len(opt_data) == 2:  # MSS
                opt["name"] = "MSS"
                opt["value"] = struct.unpack('!H', opt_data)[0]
            elif kind == 3 and len(opt_data) == 1:  # Window Scale
                opt["name"] = "Window Scale"
                opt["value"] = opt_data[0]
            elif kind == 4:  # SACK Permitted
                opt["name"] = "SACK Permitted"
            elif kind == 8 and len(opt_data) == 8:  # Timestamps
                opt["name"] = "Timestamps"
                tsval, tsecr = struct.unpack('!II', opt_data)
                opt["value"] = {"tsval": tsval, "tsecr": tsecr}
            else:
                opt["name"] = f"Option-{kind}"
                opt["data"] = opt_data.hex()

            options.append(opt)
            offset += length

        return options
