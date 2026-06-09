from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple


@dataclass
class HttpRequest:
    method: str
    uri: str
    version: str
    headers: Dict[str, str]
    body: bytes
    raw_length: int
    stream_offset: int  # byte offset in the client stream where this request starts

    def to_dict(self) -> dict:
        return {
            "type": "request",
            "method": self.method,
            "uri": self.uri,
            "version": self.version,
            "headers": self.headers,
            "body_length": len(self.body),
            "body_preview": self.body[:512].decode('utf-8', errors='replace') if self.body else "",
            "stream_offset": self.stream_offset,
            "raw_length": self.raw_length,
        }


@dataclass
class HttpResponse:
    version: str
    status_code: int
    reason: str
    headers: Dict[str, str]
    body: bytes
    raw_length: int
    stream_offset: int  # byte offset in the server stream where this response starts

    def to_dict(self) -> dict:
        return {
            "type": "response",
            "version": self.version,
            "status_code": self.status_code,
            "reason": self.reason,
            "headers": self.headers,
            "body_length": len(self.body),
            "body_preview": self.body[:512].decode('utf-8', errors='replace') if self.body else "",
            "stream_offset": self.stream_offset,
            "raw_length": self.raw_length,
        }


@dataclass
class HttpTransaction:
    """A paired HTTP request and response on the same connection.

    Pairing is done by sequential consumption order on the TCP stream:
    HTTP/1.x uses strict request-response ordering per connection.
    The Nth request in the client stream is paired with the Nth response
    in the server stream (RFC 7230 Section 5.6: pipelining preserves order).
    """
    sequence: int  # 0-based transaction index on this connection
    request: Optional[HttpRequest]
    response: Optional[HttpResponse]

    @property
    def is_complete(self) -> bool:
        return self.request is not None and self.response is not None

    def to_dict(self) -> dict:
        result = {"sequence": self.sequence, "complete": self.is_complete}
        if self.request:
            result["request"] = self.request.to_dict()
        if self.response:
            result["response"] = self.response.to_dict()
        return result


class HttpParser:
    """HTTP/1.x request/response parser that pairs by stream sequence order.

    This implementation processes the reassembled client and server byte streams
    sequentially, pairing the Nth fully-parsed request with the Nth fully-parsed
    response. This correctly handles HTTP pipelining where the client sends
    multiple requests before receiving any responses.
    """

    def parse_stream(self, client_data: bytes, server_data: bytes) -> List[HttpTransaction]:
        """Parse both directions of a TCP stream and pair requests with responses.

        Pairing logic: HTTP/1.x mandates that responses are sent in the same
        order as requests were received (RFC 7230 Section 5.6). We parse
        requests from client_data and responses from server_data independently,
        then pair them by their sequential position in each stream.
        """
        requests = self._parse_requests(client_data)
        responses = self._parse_responses(server_data)

        transactions = []
        # Pair by sequential stream order: request N maps to response N
        # This is correct because HTTP/1.x requires in-order response delivery
        n_transactions = max(len(requests), len(responses))
        for seq in range(n_transactions):
            req = requests[seq] if seq < len(requests) else None
            resp = responses[seq] if seq < len(responses) else None
            transactions.append(HttpTransaction(sequence=seq, request=req, response=resp))

        return transactions

    def _parse_requests(self, data: bytes) -> List[HttpRequest]:
        """Parse HTTP requests sequentially from the client stream.

        Returns requests in the order they appear in the byte stream.
        Each request's stream_offset records its position for provenance.
        """
        requests = []
        offset = 0

        while offset < len(data):
            # Look for header terminator
            header_end = data.find(b'\r\n\r\n', offset)
            if header_end == -1:
                break

            header_bytes = data[offset:header_end]
            body_start = header_end + 4

            try:
                header_text = header_bytes.decode('utf-8', errors='replace')
            except Exception:
                break

            lines = header_text.split('\r\n')
            if not lines:
                break

            # Validate request line format
            request_line = lines[0].split(' ', 2)
            if len(request_line) < 2:
                break

            method = request_line[0]
            if method not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD',
                              'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'):
                break

            uri = request_line[1]
            version = request_line[2] if len(request_line) > 2 else "HTTP/1.0"
            headers = self._parse_headers(lines[1:])

            body, body_end = self._extract_body(data, body_start, headers, method)

            requests.append(HttpRequest(
                method=method, uri=uri, version=version,
                headers=headers, body=body,
                raw_length=body_end - offset,
                stream_offset=offset,
            ))
            offset = body_end

        return requests

    def _parse_responses(self, data: bytes) -> List[HttpResponse]:
        """Parse HTTP responses sequentially from the server stream.

        Returns responses in stream order. Each response's stream_offset
        records where it begins in the byte stream for provenance tracking.
        """
        responses = []
        offset = 0

        while offset < len(data):
            # Look for header terminator
            header_end = data.find(b'\r\n\r\n', offset)
            if header_end == -1:
                break

            header_bytes = data[offset:header_end]
            body_start = header_end + 4

            try:
                header_text = header_bytes.decode('utf-8', errors='replace')
            except Exception:
                break

            lines = header_text.split('\r\n')
            if not lines:
                break

            # Validate status line
            status_line = lines[0].split(' ', 2)
            if len(status_line) < 2:
                break
            if not status_line[0].startswith('HTTP/'):
                break

            version = status_line[0]
            try:
                status_code = int(status_line[1])
            except ValueError:
                break
            reason = status_line[2] if len(status_line) > 2 else ""

            headers = self._parse_headers(lines[1:])

            # 1xx, 204, 304 responses have no body
            if status_code < 200 or status_code in (204, 304):
                body = b''
                body_end = body_start
            else:
                body, body_end = self._extract_body(data, body_start, headers)

            responses.append(HttpResponse(
                version=version, status_code=status_code,
                reason=reason, headers=headers, body=body,
                raw_length=body_end - offset,
                stream_offset=offset,
            ))
            offset = body_end

        return responses

    def _parse_headers(self, lines: List[str]) -> Dict[str, str]:
        headers = {}
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        return headers

    def _extract_body(self, data: bytes, body_start: int,
                      headers: Dict[str, str], method: str = None) -> Tuple[bytes, int]:
        """Extract message body using Content-Length or Transfer-Encoding.

        For requests: GET/HEAD/DELETE/CONNECT typically have no body
        unless Content-Length or Transfer-Encoding is present.
        """
        # Methods that conventionally have no body
        if method and method in ('GET', 'HEAD', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'):
            if 'content-length' not in headers and 'transfer-encoding' not in headers:
                return b'', body_start

        transfer_encoding = headers.get('transfer-encoding', '').lower()
        content_length = headers.get('content-length', '')

        if 'chunked' in transfer_encoding:
            body, end_pos = self._decode_chunked(data, body_start)
            return body, end_pos

        if content_length:
            try:
                length = int(content_length)
                body_end = min(body_start + length, len(data))
                return data[body_start:body_end], body_end
            except ValueError:
                pass

        # No Content-Length and no chunked: for responses, read until connection close
        # (in a reassembled stream, this means rest of data — but only for last response)
        # For intermediate messages, assume no body
        return b'', body_start

    def _decode_chunked(self, data: bytes, offset: int) -> Tuple[bytes, int]:
        result = bytearray()
        pos = offset

        while pos < len(data):
            line_end = data.find(b'\r\n', pos)
            if line_end == -1:
                break

            chunk_size_str = data[pos:line_end].decode('ascii', errors='replace').strip()
            try:
                chunk_size = int(chunk_size_str.split(';')[0], 16)
            except ValueError:
                break

            if chunk_size == 0:
                # Skip trailers if present: look for empty line after 0-size chunk
                trailer_end = data.find(b'\r\n', line_end + 2)
                if trailer_end == line_end + 2:
                    pos = trailer_end + 2
                else:
                    pos = line_end + 4
                break

            chunk_start = line_end + 2
            chunk_end = chunk_start + chunk_size

            if chunk_end > len(data):
                result.extend(data[chunk_start:])
                pos = len(data)
                break

            result.extend(data[chunk_start:chunk_end])
            pos = chunk_end + 2  # skip \r\n after chunk data

        return bytes(result), pos

    @staticmethod
    def is_http(data: bytes) -> bool:
        methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ',
                   b'OPTIONS ', b'PATCH ', b'CONNECT ']
        for m in methods:
            if data.startswith(m):
                return True
        if data.startswith(b'HTTP/'):
            return True
        return False
