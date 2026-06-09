import os
import json
from fastapi import APIRouter, UploadFile, File, BackgroundTasks, HTTPException
from database import get_db
from config import UPLOAD_DIR
from decoder.pcap_parser import PcapParser
from decoder.ethernet import EthernetDecoder
from decoder.ip import IPv4Decoder
from decoder.tcp import TcpDecoder
from decoder.udp import UdpDecoder
from decoder.reassembly import TcpReassembler
from decoder.http_parser import HttpParser
from decoder.dns_parser import DnsParser, DnsCorrelator
from decoder.tls_parser import TlsParser
from scanner.engine import SensitiveScanner

router = APIRouter()


@router.post("/api/upload")
async def upload_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.endswith(('.pcap', '.cap')):
        raise HTTPException(400, "File must be .pcap or .cap")

    content = await file.read()
    filepath = os.path.join(UPLOAD_DIR, file.filename)

    with open(filepath, 'wb') as f:
        f.write(content)

    db = await get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO pcap_files (filename, filepath, file_size) VALUES (?, ?, ?)",
            (file.filename, filepath, len(content))
        )
        pcap_id = cursor.lastrowid
        await db.commit()
    finally:
        await db.close()

    background_tasks.add_task(parse_pcap_file, pcap_id, content)

    return {"id": pcap_id, "filename": file.filename, "status": "parsing"}


@router.get("/api/pcap")
async def list_pcaps():
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, filename, file_size, packet_count, upload_time, parse_status FROM pcap_files ORDER BY id DESC"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/api/pcap/{pcap_id}/status")
async def get_pcap_status(pcap_id: int):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, filename, file_size, packet_count, parse_status FROM pcap_files WHERE id = ?",
            (pcap_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Pcap file not found")
        return dict(row)
    finally:
        await db.close()


@router.delete("/api/pcap/{pcap_id}")
async def delete_pcap(pcap_id: int):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT filepath FROM pcap_files WHERE id = ?", (pcap_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(404, "Pcap not found")

        await db.execute("DELETE FROM sensitive_findings WHERE pcap_file_id = ?", (pcap_id,))
        await db.execute("DELETE FROM packets WHERE pcap_file_id = ?", (pcap_id,))
        await db.execute("DELETE FROM sessions WHERE pcap_file_id = ?", (pcap_id,))
        await db.execute("DELETE FROM pcap_files WHERE id = ?", (pcap_id,))
        await db.commit()

        filepath = row['filepath']
        if os.path.exists(filepath):
            os.remove(filepath)

        return {"status": "deleted"}
    finally:
        await db.close()


async def parse_pcap_file(pcap_id: int, data: bytes):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE pcap_files SET parse_status = 'parsing' WHERE id = ?", (pcap_id,)
        )
        await db.commit()

        parser = PcapParser(data)
        packets = parser.parse()

        eth_decoder = EthernetDecoder()
        ip_decoder = IPv4Decoder()
        tcp_decoder = TcpDecoder()
        udp_decoder = UdpDecoder()
        reassembler = TcpReassembler()
        dns_parser = DnsParser()
        dns_correlator = DnsCorrelator()

        for pkt in packets:
            decoded_layers = []
            eth_src = eth_dst = None
            eth_type = None
            ip_src = ip_dst = None
            ip_protocol = ip_ttl = None
            src_port = dst_port = None
            tcp_seq = tcp_ack = tcp_flags = tcp_window = None
            payload = b''

            try:
                eth = eth_decoder.decode(pkt.data)
                decoded_layers.append(eth.to_dict())
                eth_src = eth.src_mac
                eth_dst = eth.dst_mac
                eth_type = eth.ethertype

                if eth.ethertype == 0x0800:
                    ip = ip_decoder.decode(eth.payload)
                    decoded_layers.append(ip.to_dict())
                    ip_src = ip.src_ip
                    ip_dst = ip.dst_ip
                    ip_protocol = ip.protocol
                    ip_ttl = ip.ttl

                    if ip.protocol == 6:  # TCP
                        tcp = tcp_decoder.decode(ip.payload)
                        decoded_layers.append(tcp.to_dict())
                        src_port = tcp.src_port
                        dst_port = tcp.dst_port
                        tcp_seq = tcp.seq_num
                        tcp_ack = tcp.ack_num
                        tcp_flags = tcp.flags
                        tcp_window = tcp.window
                        payload = tcp.payload

                        reassembler.add_segment(
                            ip_src, ip_dst, src_port, dst_port,
                            tcp.seq_num, tcp.ack_num, tcp.flags,
                            tcp.payload, pkt.timestamp,
                        )

                    elif ip.protocol == 17:  # UDP
                        udp = udp_decoder.decode(ip.payload)
                        decoded_layers.append(udp.to_dict())
                        src_port = udp.src_port
                        dst_port = udp.dst_port
                        payload = udp.payload

                        if DnsParser.is_dns(src_port, dst_port):
                            dns_msg = dns_parser.parse(
                                udp.payload, timestamp=pkt.timestamp,
                                src_ip=ip_src, dst_ip=ip_dst,
                            )
                            if dns_msg:
                                decoded_layers.append(dns_msg.to_dict())
                                dns_correlator.add_message(dns_msg)

            except (ValueError, Exception):
                pass

            await db.execute(
                """INSERT INTO packets (pcap_file_id, packet_index, timestamp_sec, timestamp_usec,
                   raw_length, captured_length, eth_src, eth_dst, eth_type,
                   ip_src, ip_dst, ip_protocol, ip_ttl,
                   src_port, dst_port, tcp_seq, tcp_ack, tcp_flags, tcp_window,
                   payload_length, payload, decoded_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (pcap_id, pkt.index, pkt.ts_sec, pkt.ts_usec,
                 pkt.orig_len, pkt.incl_len, eth_src, eth_dst, eth_type,
                 ip_src, ip_dst, ip_protocol, ip_ttl,
                 src_port, dst_port, tcp_seq, tcp_ack, tcp_flags, tcp_window,
                 len(payload), payload, json.dumps(decoded_layers))
            )

        await db.commit()

        # Process reassembled sessions
        sessions = reassembler.get_sessions()
        http_parser = HttpParser()
        tls_parser = TlsParser()
        scanner = SensitiveScanner()

        for sess in sessions:
            client_payload = sess.client_payload
            server_payload = sess.server_payload
            total_bytes = len(client_payload) + len(server_payload)

            app_protocol = "unknown"
            app_decoded = None

            if client_payload:
                if HttpParser.is_http(client_payload):
                    app_protocol = "HTTP"
                    transactions = http_parser.parse_stream(client_payload, server_payload)
                    app_decoded = {"transactions": [t.to_dict() for t in transactions]}
                elif TlsParser.is_tls(client_payload):
                    app_protocol = "TLS"
                    tls_info = tls_parser.parse_stream(client_payload)
                    if tls_info:
                        app_decoded = tls_info.to_dict()

            duration_ms = (sess.end_time - sess.start_time) * 1000 if sess.end_time > sess.start_time else 0

            cursor = await db.execute(
                """INSERT INTO sessions (pcap_file_id, src_ip, dst_ip, src_port, dst_port,
                   protocol, app_protocol, packet_count, total_bytes,
                   start_time, end_time, duration_ms,
                   client_payload, server_payload, app_decoded_json, state)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (pcap_id, sess.src_ip, sess.dst_ip, sess.src_port, sess.dst_port,
                 "TCP", app_protocol, sess.packet_count, total_bytes,
                 sess.start_time, sess.end_time, duration_ms,
                 client_payload, server_payload,
                 json.dumps(app_decoded) if app_decoded else None,
                 sess.state)
            )
            session_id = cursor.lastrowid

            # Scan for sensitive info
            scan_result = scanner.scan_session(session_id, client_payload, server_payload)
            for finding in scan_result.findings:
                await db.execute(
                    """INSERT INTO sensitive_findings
                       (session_id, pcap_file_id, rule_name, severity, matched_text, context, byte_offset, direction)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (session_id, pcap_id, finding.rule_name, finding.severity,
                     finding.masked_text, finding.context, finding.offset, finding.direction)
                )

        await db.commit()

        # Store DNS correlated transactions as sessions
        dns_transactions = dns_correlator.get_transactions()
        for txn in dns_transactions:
            src_ip = txn.query.src_ip if txn.query else (txn.response.dst_ip if txn.response else "")
            dst_ip = txn.query.dst_ip if txn.query else (txn.response.src_ip if txn.response else "")
            start_time = txn.query_time or txn.response_time
            end_time = txn.response_time or txn.query_time
            duration = (end_time - start_time) * 1000 if end_time > start_time else 0

            app_decoded = {"dns_transaction": txn.to_dict()}

            await db.execute(
                """INSERT INTO sessions (pcap_file_id, src_ip, dst_ip, src_port, dst_port,
                   protocol, app_protocol, packet_count, total_bytes,
                   start_time, end_time, duration_ms,
                   client_payload, server_payload, app_decoded_json, state)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (pcap_id, src_ip, dst_ip, 0, 53,
                 "UDP", "DNS", 2 if txn.is_complete else 1, 0,
                 start_time, end_time, duration,
                 None, None,
                 json.dumps(app_decoded),
                 "complete" if txn.is_complete else "incomplete")
            )

        await db.commit()

        await db.execute(
            "UPDATE pcap_files SET parse_status = 'completed', packet_count = ? WHERE id = ?",
            (len(packets), pcap_id)
        )
        await db.commit()

    except Exception as e:
        await db.execute(
            "UPDATE pcap_files SET parse_status = 'error' WHERE id = ?", (pcap_id,)
        )
        await db.commit()
        raise
    finally:
        await db.close()
