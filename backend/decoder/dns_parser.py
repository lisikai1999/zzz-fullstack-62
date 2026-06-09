import struct
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple


@dataclass
class DnsQuestion:
    name: str
    qtype: int
    qclass: int

    def type_name(self) -> str:
        names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
                 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
        return names.get(self.qtype, f"TYPE{self.qtype}")

    def to_dict(self) -> dict:
        return {"name": self.name, "type": self.type_name(), "class": self.qclass}


@dataclass
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: str

    def type_name(self) -> str:
        names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
                 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
        return names.get(self.rtype, f"TYPE{self.rtype}")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type_name(),
            "class": self.rclass,
            "ttl": self.ttl,
            "data": self.rdata,
        }


@dataclass
class DnsMessage:
    transaction_id: int
    is_response: bool
    opcode: int
    flags: int
    rcode: int
    questions: List[DnsQuestion]
    answers: List[DnsRecord]
    authorities: List[DnsRecord]
    additionals: List[DnsRecord]
    timestamp: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""

    def to_dict(self) -> dict:
        return {
            "layer": "DNS",
            "transaction_id": f"0x{self.transaction_id:04X}",
            "type": "response" if self.is_response else "query",
            "opcode": self.opcode,
            "rcode": self._rcode_name(),
            "questions": [q.to_dict() for q in self.questions],
            "answers": [a.to_dict() for a in self.answers],
            "authorities": [a.to_dict() for a in self.authorities],
            "additionals": [a.to_dict() for a in self.additionals],
        }

    def _rcode_name(self) -> str:
        names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                 4: "NOTIMP", 5: "REFUSED"}
        return names.get(self.rcode, f"RCODE({self.rcode})")


@dataclass
class DnsTransaction:
    """A correlated DNS query/response pair identified by transaction ID."""
    transaction_id: int
    query: Optional[DnsMessage] = None
    response: Optional[DnsMessage] = None
    query_time: float = 0.0
    response_time: float = 0.0

    @property
    def latency_ms(self) -> Optional[float]:
        if self.query and self.response:
            return (self.response_time - self.query_time) * 1000
        return None

    @property
    def is_complete(self) -> bool:
        return self.query is not None and self.response is not None

    @property
    def query_name(self) -> str:
        if self.query and self.query.questions:
            return self.query.questions[0].name
        if self.response and self.response.questions:
            return self.response.questions[0].name
        return ""

    @property
    def query_type(self) -> str:
        if self.query and self.query.questions:
            return self.query.questions[0].type_name()
        if self.response and self.response.questions:
            return self.response.questions[0].type_name()
        return ""

    @property
    def resolved_addresses(self) -> List[str]:
        if self.response:
            return [a.rdata for a in self.response.answers]
        return []

    def to_dict(self) -> dict:
        result = {
            "transaction_id": f"0x{self.transaction_id:04X}",
            "query_name": self.query_name,
            "query_type": self.query_type,
            "is_complete": self.is_complete,
            "latency_ms": round(self.latency_ms, 3) if self.latency_ms is not None else None,
            "resolved": self.resolved_addresses,
        }
        if self.query:
            result["query"] = self.query.to_dict()
            result["query_src"] = self.query.src_ip
            result["query_dst"] = self.query.dst_ip
        if self.response:
            result["response"] = self.response.to_dict()
            result["rcode"] = self.response._rcode_name()
        return result


class DnsCorrelator:
    """Correlates DNS queries and responses by transaction ID."""

    def __init__(self):
        self._pending: Dict[int, DnsTransaction] = {}
        self._completed: List[DnsTransaction] = []

    def add_message(self, msg: DnsMessage):
        txn_id = msg.transaction_id

        if txn_id not in self._pending:
            self._pending[txn_id] = DnsTransaction(transaction_id=txn_id)

        txn = self._pending[txn_id]

        if not msg.is_response:
            txn.query = msg
            txn.query_time = msg.timestamp
        else:
            txn.response = msg
            txn.response_time = msg.timestamp

        if txn.is_complete:
            self._completed.append(txn)
            del self._pending[txn_id]

    def get_transactions(self) -> List[DnsTransaction]:
        """Return all transactions: completed pairs + unmatched singles."""
        result = list(self._completed)
        for txn in self._pending.values():
            result.append(txn)
        result.sort(key=lambda t: t.query_time or t.response_time)
        return result

    @property
    def completed_count(self) -> int:
        return len(self._completed)

    @property
    def unmatched_count(self) -> int:
        return len(self._pending)


class DnsParser:
    HEADER_FORMAT = '!HHHHHH'
    HEADER_SIZE = 12

    def parse(self, data: bytes, timestamp: float = 0.0,
              src_ip: str = "", dst_ip: str = "") -> Optional[DnsMessage]:
        if len(data) < self.HEADER_SIZE:
            return None

        txn_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            self.HEADER_FORMAT, data[:self.HEADER_SIZE]
        )

        is_response = bool(flags & 0x8000)
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x000F

        offset = self.HEADER_SIZE
        questions = []
        for _ in range(qdcount):
            name, offset = self._parse_name(data, offset)
            if offset + 4 > len(data):
                break
            qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
            offset += 4
            questions.append(DnsQuestion(name=name, qtype=qtype, qclass=qclass))

        answers = []
        for _ in range(ancount):
            record, offset = self._parse_record(data, offset)
            if record:
                answers.append(record)

        authorities = []
        for _ in range(nscount):
            record, offset = self._parse_record(data, offset)
            if record:
                authorities.append(record)

        additionals = []
        for _ in range(arcount):
            record, offset = self._parse_record(data, offset)
            if record:
                additionals.append(record)

        return DnsMessage(
            transaction_id=txn_id,
            is_response=is_response,
            opcode=opcode,
            flags=flags,
            rcode=rcode,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )

    def _parse_name(self, data: bytes, offset: int) -> tuple:
        labels = []
        visited = set()
        jumped = False
        final_offset = offset

        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)

            length = data[offset]

            if length == 0:
                if not jumped:
                    final_offset = offset + 1
                break

            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    if not jumped:
                        final_offset = offset
                    break
                pointer = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
                if not jumped:
                    final_offset = offset + 2
                jumped = True
                offset = pointer
                continue

            offset += 1
            if offset + length > len(data):
                if not jumped:
                    final_offset = offset
                break
            labels.append(data[offset:offset + length].decode('ascii', errors='replace'))
            offset += length
            if not jumped:
                final_offset = offset

        return '.'.join(labels), final_offset

    def _parse_record(self, data: bytes, offset: int) -> tuple:
        if offset >= len(data):
            return None, offset

        name, offset = self._parse_name(data, offset)
        if offset + 10 > len(data):
            return None, offset

        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10

        if offset + rdlength > len(data):
            return None, len(data)

        rdata_raw = data[offset:offset + rdlength]
        rdata = self._format_rdata(rtype, rdata_raw, data, offset)
        offset += rdlength

        return DnsRecord(name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata), offset

    def _format_rdata(self, rtype: int, rdata: bytes, full_data: bytes, rdata_offset: int) -> str:
        import socket
        if rtype == 1 and len(rdata) == 4:  # A
            return socket.inet_ntoa(rdata)
        elif rtype == 28 and len(rdata) == 16:  # AAAA
            return socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5, 12):  # NS, CNAME, PTR
            name, _ = self._parse_name(full_data, rdata_offset)
            return name
        elif rtype == 15 and len(rdata) >= 2:  # MX
            preference = struct.unpack('!H', rdata[:2])[0]
            name, _ = self._parse_name(full_data, rdata_offset + 2)
            return f"{preference} {name}"
        elif rtype == 16:  # TXT
            texts = []
            pos = 0
            while pos < len(rdata):
                txt_len = rdata[pos]
                pos += 1
                texts.append(rdata[pos:pos + txt_len].decode('utf-8', errors='replace'))
                pos += txt_len
            return ' '.join(texts)
        else:
            return rdata.hex()

    @staticmethod
    def is_dns(src_port: int, dst_port: int) -> bool:
        return src_port == 53 or dst_port == 53
