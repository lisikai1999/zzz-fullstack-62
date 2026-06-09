import struct
from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class TlsRecord:
    content_type: int
    version: tuple
    length: int
    payload: bytes

    def content_type_name(self) -> str:
        names = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
        return names.get(self.content_type, f"Unknown({self.content_type})")


@dataclass
class TlsClientHello:
    version: tuple
    random: bytes
    session_id: bytes
    cipher_suites: List[int]
    compression_methods: List[int]
    extensions: Dict[int, bytes]
    sni: Optional[str]

    def to_dict(self) -> dict:
        result = {
            "layer": "TLS",
            "message_type": "ClientHello",
            "version": f"{self.version[0]}.{self.version[1]}",
            "session_id_length": len(self.session_id),
            "cipher_suites_count": len(self.cipher_suites),
            "cipher_suites": [f"0x{cs:04X}" for cs in self.cipher_suites[:20]],
            "compression_methods": self.compression_methods,
        }
        if self.sni:
            result["sni"] = self.sni
        return result


@dataclass
class TlsServerHello:
    version: tuple
    random: bytes
    session_id: bytes
    cipher_suite: int
    compression_method: int

    def to_dict(self) -> dict:
        return {
            "layer": "TLS",
            "message_type": "ServerHello",
            "version": f"{self.version[0]}.{self.version[1]}",
            "cipher_suite": f"0x{self.cipher_suite:04X}",
            "compression_method": self.compression_method,
            "session_id_length": len(self.session_id),
        }


@dataclass
class TlsCertificateInfo:
    """Extracted plaintext fields from an X.509 certificate in a TLS handshake."""
    subject: Dict[str, str]
    issuer: Dict[str, str]
    not_before: str
    not_after: str
    serial_number: str
    signature_algorithm: str
    subject_alt_names: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "validity": {
                "not_before": self.not_before,
                "not_after": self.not_after,
            },
            "serial_number": self.serial_number,
            "signature_algorithm": self.signature_algorithm,
            "subject_alt_names": self.subject_alt_names,
        }


@dataclass
class TlsHandshakeInfo:
    records: List[dict]
    client_hello: Optional[TlsClientHello] = None
    server_hello: Optional[TlsServerHello] = None
    certificates: List[TlsCertificateInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = {
            "layer": "TLS",
            "records": self.records,
        }
        if self.client_hello:
            result["client_hello"] = self.client_hello.to_dict()
        if self.server_hello:
            result["server_hello"] = self.server_hello.to_dict()
        if self.certificates:
            result["certificates"] = [c.to_dict() for c in self.certificates]
        return result


# OID to human-readable name mapping for common X.509 attributes
OID_NAMES = {
    (2, 5, 4, 3): "CN",
    (2, 5, 4, 6): "C",
    (2, 5, 4, 7): "L",
    (2, 5, 4, 8): "ST",
    (2, 5, 4, 10): "O",
    (2, 5, 4, 11): "OU",
    (1, 2, 840, 113549, 1, 1, 1): "rsaEncryption",
    (1, 2, 840, 113549, 1, 1, 4): "md5WithRSAEncryption",
    (1, 2, 840, 113549, 1, 1, 5): "sha1WithRSAEncryption",
    (1, 2, 840, 113549, 1, 1, 11): "sha256WithRSAEncryption",
    (1, 2, 840, 113549, 1, 1, 12): "sha384WithRSAEncryption",
    (1, 2, 840, 113549, 1, 1, 13): "sha512WithRSAEncryption",
    (1, 2, 840, 10045, 4, 3, 2): "ecdsa-with-SHA256",
    (1, 2, 840, 10045, 4, 3, 3): "ecdsa-with-SHA384",
    (2, 5, 29, 17): "subjectAltName",
}


class Asn1Parser:
    """Minimal DER/ASN.1 parser for X.509 certificate field extraction."""

    @staticmethod
    def parse_tag_length(data: bytes, offset: int) -> tuple:
        """Parse ASN.1 tag and length. Returns (tag, length, header_size)."""
        if offset >= len(data):
            return 0, 0, 0

        tag = data[offset]
        offset += 1

        if offset >= len(data):
            return tag, 0, 1

        length_byte = data[offset]
        offset += 1

        if length_byte < 0x80:
            return tag, length_byte, 2
        elif length_byte == 0x80:
            return tag, 0, 2  # indefinite length (not supported, return 0)
        else:
            num_bytes = length_byte & 0x7F
            if offset + num_bytes > len(data):
                return tag, 0, 2
            length = int.from_bytes(data[offset:offset + num_bytes], 'big')
            return tag, length, 2 + num_bytes

    @staticmethod
    def parse_oid(data: bytes) -> tuple:
        """Parse a DER-encoded OID into a tuple of integers."""
        if not data:
            return ()
        components = [data[0] // 40, data[0] % 40]
        value = 0
        for byte in data[1:]:
            value = (value << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                components.append(value)
                value = 0
        return tuple(components)

    @staticmethod
    def parse_utc_time(data: bytes) -> str:
        """Parse ASN.1 UTCTime (YYMMDDHHMMSSZ)."""
        try:
            text = data.decode('ascii').rstrip('Z')
            if len(text) >= 12:
                year = int(text[:2])
                year = year + 2000 if year < 50 else year + 1900
                return f"{year}-{text[2:4]}-{text[4:6]} {text[6:8]}:{text[8:10]}:{text[10:12]} UTC"
        except (ValueError, UnicodeDecodeError):
            pass
        return data.hex()

    @staticmethod
    def parse_generalized_time(data: bytes) -> str:
        """Parse ASN.1 GeneralizedTime (YYYYMMDDHHMMSSZ)."""
        try:
            text = data.decode('ascii').rstrip('Z')
            if len(text) >= 14:
                return f"{text[:4]}-{text[4:6]}-{text[6:8]} {text[8:10]}:{text[10:12]}:{text[12:14]} UTC"
        except (ValueError, UnicodeDecodeError):
            pass
        return data.hex()

    def parse_name(self, data: bytes, offset: int, end: int) -> Dict[str, str]:
        """Parse an X.509 Name (SEQUENCE of SET of AttributeTypeAndValue)."""
        result = {}
        while offset < end:
            tag, length, hdr_size = self.parse_tag_length(data, offset)
            if tag != 0x31:  # SET
                offset += hdr_size + length
                continue

            set_start = offset + hdr_size
            set_end = set_start + length
            offset = set_end

            # Parse SEQUENCE inside SET
            pos = set_start
            while pos < set_end:
                seq_tag, seq_len, seq_hdr = self.parse_tag_length(data, pos)
                if seq_tag != 0x30:
                    pos += seq_hdr + seq_len
                    continue
                seq_body_start = pos + seq_hdr
                seq_body_end = seq_body_start + seq_len
                pos = seq_body_end

                # OID
                oid_tag, oid_len, oid_hdr = self.parse_tag_length(data, seq_body_start)
                if oid_tag != 0x06:
                    continue
                oid_data = data[seq_body_start + oid_hdr:seq_body_start + oid_hdr + oid_len]
                oid = self.parse_oid(oid_data)
                oid_name = OID_NAMES.get(oid, '.'.join(str(x) for x in oid))

                # Value (usually UTF8String, PrintableString, or IA5String)
                val_offset = seq_body_start + oid_hdr + oid_len
                val_tag, val_len, val_hdr = self.parse_tag_length(data, val_offset)
                val_data = data[val_offset + val_hdr:val_offset + val_hdr + val_len]
                try:
                    value = val_data.decode('utf-8', errors='replace')
                except Exception:
                    value = val_data.hex()

                result[oid_name] = value

        return result

    def parse_validity(self, data: bytes, offset: int, end: int) -> tuple:
        """Parse Validity SEQUENCE containing notBefore and notAfter."""
        not_before = ""
        not_after = ""

        # notBefore
        tag, length, hdr_size = self.parse_tag_length(data, offset)
        time_data = data[offset + hdr_size:offset + hdr_size + length]
        if tag == 0x17:  # UTCTime
            not_before = self.parse_utc_time(time_data)
        elif tag == 0x18:  # GeneralizedTime
            not_before = self.parse_generalized_time(time_data)
        offset += hdr_size + length

        # notAfter
        tag, length, hdr_size = self.parse_tag_length(data, offset)
        time_data = data[offset + hdr_size:offset + hdr_size + length]
        if tag == 0x17:
            not_after = self.parse_utc_time(time_data)
        elif tag == 0x18:
            not_after = self.parse_generalized_time(time_data)

        return not_before, not_after

    def parse_extensions(self, data: bytes, offset: int, end: int) -> List[str]:
        """Extract Subject Alternative Names from extensions."""
        san_list = []
        # Extensions is a SEQUENCE of Extension
        while offset < end:
            ext_tag, ext_len, ext_hdr = self.parse_tag_length(data, offset)
            if ext_tag != 0x30:
                offset += ext_hdr + ext_len
                continue
            ext_body_start = offset + ext_hdr
            ext_body_end = ext_body_start + ext_len
            offset = ext_body_end

            # Extension: OID + optional BOOLEAN + OCTET STRING
            pos = ext_body_start
            oid_tag, oid_len, oid_hdr = self.parse_tag_length(data, pos)
            if oid_tag != 0x06:
                continue
            oid_data = data[pos + oid_hdr:pos + oid_hdr + oid_len]
            oid = self.parse_oid(oid_data)
            pos += oid_hdr + oid_len

            # Skip critical boolean if present
            next_tag = data[pos] if pos < ext_body_end else 0
            if next_tag == 0x01:  # BOOLEAN
                _, b_len, b_hdr = self.parse_tag_length(data, pos)
                pos += b_hdr + b_len

            # subjectAltName OID = 2.5.29.17
            if oid == (2, 5, 29, 17):
                # OCTET STRING wrapping the SAN value
                oct_tag, oct_len, oct_hdr = self.parse_tag_length(data, pos)
                if oct_tag == 0x04:
                    san_data = data[pos + oct_hdr:pos + oct_hdr + oct_len]
                    san_list = self._parse_san(san_data)

        return san_list

    def _parse_san(self, data: bytes) -> List[str]:
        """Parse SubjectAltName SEQUENCE of GeneralName."""
        names = []
        # Outer SEQUENCE
        tag, length, hdr_size = self.parse_tag_length(data, 0)
        if tag != 0x30:
            return names

        offset = hdr_size
        end = hdr_size + length

        while offset < end:
            name_tag, name_len, name_hdr = self.parse_tag_length(data, offset)
            name_data = data[offset + name_hdr:offset + name_hdr + name_len]
            offset += name_hdr + name_len

            # Context-specific tags: [2] = dNSName, [7] = iPAddress
            tag_class = name_tag & 0xC0
            tag_num = name_tag & 0x1F
            if tag_class == 0x80:  # context-specific
                if tag_num == 2:  # dNSName
                    try:
                        names.append(name_data.decode('ascii'))
                    except Exception:
                        names.append(name_data.hex())
                elif tag_num == 7 and name_len == 4:  # iPAddress (IPv4)
                    import socket
                    names.append(socket.inet_ntoa(name_data))

        return names

    def parse_certificate(self, cert_data: bytes) -> Optional[TlsCertificateInfo]:
        """Parse a DER-encoded X.509 certificate and extract key fields."""
        try:
            return self._do_parse_certificate(cert_data)
        except Exception:
            return None

    def _do_parse_certificate(self, data: bytes) -> Optional[TlsCertificateInfo]:
        # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
        tag, length, hdr = self.parse_tag_length(data, 0)
        if tag != 0x30:
            return None

        offset = hdr

        # TBSCertificate ::= SEQUENCE
        tbs_tag, tbs_len, tbs_hdr = self.parse_tag_length(data, offset)
        if tbs_tag != 0x30:
            return None
        tbs_start = offset + tbs_hdr
        tbs_end = tbs_start + tbs_len
        offset = tbs_end  # skip past TBS for signatureAlgorithm

        # Parse signatureAlgorithm (SEQUENCE with OID)
        sig_alg_tag, sig_alg_len, sig_alg_hdr = self.parse_tag_length(data, offset)
        sig_algorithm = ""
        if sig_alg_tag == 0x30:
            # First element is OID
            oid_pos = offset + sig_alg_hdr
            oid_tag, oid_len, oid_hdr = self.parse_tag_length(data, oid_pos)
            if oid_tag == 0x06:
                oid_data = data[oid_pos + oid_hdr:oid_pos + oid_hdr + oid_len]
                oid = self.parse_oid(oid_data)
                sig_algorithm = OID_NAMES.get(oid, '.'.join(str(x) for x in oid))

        # Now parse TBSCertificate fields
        pos = tbs_start

        # version [0] EXPLICIT (optional)
        v_tag = data[pos] if pos < tbs_end else 0
        if v_tag == 0xA0:  # context [0]
            _, v_len, v_hdr = self.parse_tag_length(data, pos)
            pos += v_hdr + v_len

        # serialNumber INTEGER
        serial_tag, serial_len, serial_hdr = self.parse_tag_length(data, pos)
        serial_data = data[pos + serial_hdr:pos + serial_hdr + serial_len]
        serial_number = serial_data.hex()
        pos += serial_hdr + serial_len

        # signature AlgorithmIdentifier (skip)
        sig_tag, sig_len, sig_hdr = self.parse_tag_length(data, pos)
        pos += sig_hdr + sig_len

        # issuer Name
        issuer_tag, issuer_len, issuer_hdr = self.parse_tag_length(data, pos)
        issuer_end = pos + issuer_hdr + issuer_len
        issuer = self.parse_name(data, pos + issuer_hdr, issuer_end)
        pos = issuer_end

        # validity SEQUENCE
        val_tag, val_len, val_hdr = self.parse_tag_length(data, pos)
        val_body_start = pos + val_hdr
        val_body_end = val_body_start + val_len
        not_before, not_after = self.parse_validity(data, val_body_start, val_body_end)
        pos = val_body_end

        # subject Name
        subj_tag, subj_len, subj_hdr = self.parse_tag_length(data, pos)
        subj_end = pos + subj_hdr + subj_len
        subject = self.parse_name(data, pos + subj_hdr, subj_end)
        pos = subj_end

        # subjectPublicKeyInfo (skip)
        spki_tag, spki_len, spki_hdr = self.parse_tag_length(data, pos)
        pos += spki_hdr + spki_len

        # extensions [3] EXPLICIT (optional)
        san_list = []
        if pos < tbs_end:
            ext_wrapper_tag = data[pos] if pos < tbs_end else 0
            if ext_wrapper_tag == 0xA3:  # context [3]
                _, ext_wrapper_len, ext_wrapper_hdr = self.parse_tag_length(data, pos)
                ext_seq_start = pos + ext_wrapper_hdr
                # Inner SEQUENCE of extensions
                ext_seq_tag, ext_seq_len, ext_seq_hdr = self.parse_tag_length(data, ext_seq_start)
                if ext_seq_tag == 0x30:
                    ext_body_start = ext_seq_start + ext_seq_hdr
                    ext_body_end = ext_body_start + ext_seq_len
                    san_list = self.parse_extensions(data, ext_body_start, ext_body_end)

        return TlsCertificateInfo(
            subject=subject,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            serial_number=serial_number,
            signature_algorithm=sig_algorithm,
            subject_alt_names=san_list,
        )


class TlsParser:
    RECORD_HEADER_FORMAT = '!BHH'
    RECORD_HEADER_SIZE = 5
    CONTENT_TYPE_HANDSHAKE = 22

    def __init__(self):
        self._asn1 = Asn1Parser()

    def parse_stream(self, data: bytes) -> Optional[TlsHandshakeInfo]:
        info = TlsHandshakeInfo(records=[])
        offset = 0

        while offset + self.RECORD_HEADER_SIZE <= len(data):
            content_type, version_raw, length = struct.unpack(
                self.RECORD_HEADER_FORMAT, data[offset:offset + self.RECORD_HEADER_SIZE]
            )
            version = (version_raw >> 8, version_raw & 0xFF)

            if content_type not in (20, 21, 22, 23):
                break
            if length > 16384 + 2048:
                break

            payload_start = offset + self.RECORD_HEADER_SIZE
            payload_end = payload_start + length
            if payload_end > len(data):
                break

            payload = data[payload_start:payload_end]

            record_info = {
                "content_type": content_type,
                "content_type_name": TlsRecord(content_type, version, length, payload).content_type_name(),
                "version": f"{version[0]}.{version[1]}",
                "length": length,
            }

            if content_type == self.CONTENT_TYPE_HANDSHAKE:
                self._parse_handshake_messages(payload, info, record_info)

            info.records.append(record_info)
            offset = payload_end

        return info if info.records else None

    def _parse_handshake_messages(self, data: bytes, info: TlsHandshakeInfo, record_info: dict):
        """Parse potentially multiple handshake messages within one record."""
        offset = 0
        while offset + 4 <= len(data):
            handshake_type = data[offset]
            length = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]
            body = data[offset + 4:offset + 4 + length]
            offset += 4 + length

            handshake_names = {1: "ClientHello", 2: "ServerHello", 11: "Certificate",
                              12: "ServerKeyExchange", 13: "CertificateRequest",
                              14: "ServerHelloDone", 16: "ClientKeyExchange"}
            record_info["handshake_type"] = handshake_type
            record_info["handshake_type_name"] = handshake_names.get(handshake_type, f"Unknown({handshake_type})")

            if handshake_type == 1:
                info.client_hello = self._parse_client_hello(body)
            elif handshake_type == 2:
                info.server_hello = self._parse_server_hello(body)
            elif handshake_type == 11:
                certs = self._parse_certificate_message(body)
                info.certificates.extend(certs)

    def _parse_certificate_message(self, data: bytes) -> List[TlsCertificateInfo]:
        """Parse Certificate handshake message: 3-byte total length + certificate chain."""
        results = []
        if len(data) < 3:
            return results

        total_len = (data[0] << 16) | (data[1] << 8) | data[2]
        offset = 3
        end = min(3 + total_len, len(data))

        while offset + 3 <= end:
            cert_len = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
            offset += 3
            if offset + cert_len > end:
                break

            cert_data = data[offset:offset + cert_len]
            offset += cert_len

            cert_info = self._asn1.parse_certificate(cert_data)
            if cert_info:
                results.append(cert_info)

        return results

    def _parse_client_hello(self, data: bytes) -> Optional[TlsClientHello]:
        if len(data) < 38:
            return None

        version = (data[0], data[1])
        random = data[2:34]
        session_id_len = data[34]
        offset = 35 + session_id_len

        if offset + 2 > len(data):
            return None
        session_id = data[35:35 + session_id_len]

        cipher_suites_len = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2
        cipher_suites = []
        cs_end = offset + cipher_suites_len
        while offset + 2 <= cs_end:
            cs = struct.unpack('!H', data[offset:offset + 2])[0]
            cipher_suites.append(cs)
            offset += 2

        offset = cs_end
        if offset >= len(data):
            return TlsClientHello(version=version, random=random, session_id=session_id,
                                  cipher_suites=cipher_suites, compression_methods=[],
                                  extensions={}, sni=None)

        comp_len = data[offset]
        offset += 1
        compression_methods = list(data[offset:offset + comp_len])
        offset += comp_len

        extensions = {}
        sni = None
        if offset + 2 <= len(data):
            ext_total_len = struct.unpack('!H', data[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_total_len

            while offset + 4 <= ext_end:
                ext_type = struct.unpack('!H', data[offset:offset + 2])[0]
                ext_len = struct.unpack('!H', data[offset + 2:offset + 4])[0]
                offset += 4
                ext_data = data[offset:offset + ext_len]
                extensions[ext_type] = ext_data
                offset += ext_len

                if ext_type == 0:  # SNI
                    sni = self._parse_sni(ext_data)

        return TlsClientHello(
            version=version, random=random, session_id=session_id,
            cipher_suites=cipher_suites, compression_methods=compression_methods,
            extensions=extensions, sni=sni,
        )

    def _parse_server_hello(self, data: bytes) -> Optional[TlsServerHello]:
        if len(data) < 38:
            return None

        version = (data[0], data[1])
        random = data[2:34]
        session_id_len = data[34]
        offset = 35 + session_id_len

        if offset + 3 > len(data):
            return None

        session_id = data[35:35 + session_id_len]
        cipher_suite = struct.unpack('!H', data[offset:offset + 2])[0]
        compression_method = data[offset + 2]

        return TlsServerHello(
            version=version, random=random, session_id=session_id,
            cipher_suite=cipher_suite, compression_method=compression_method,
        )

    def _parse_sni(self, data: bytes) -> Optional[str]:
        if len(data) < 5:
            return None
        list_len = struct.unpack('!H', data[:2])[0]
        offset = 2
        while offset + 3 <= len(data):
            name_type = data[offset]
            name_len = struct.unpack('!H', data[offset + 1:offset + 3])[0]
            offset += 3
            if offset + name_len > len(data):
                break
            if name_type == 0:  # host_name
                return data[offset:offset + name_len].decode('ascii', errors='replace')
            offset += name_len
        return None

    @staticmethod
    def is_tls(data: bytes) -> bool:
        if len(data) < 6:
            return False
        content_type = data[0]
        version_major = data[1]
        return content_type == 22 and version_major == 3
