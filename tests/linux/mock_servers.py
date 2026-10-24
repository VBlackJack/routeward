#!/usr/bin/env python3
# Copyright 2026 Julien Bombled
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import select
import socket
import struct
import sys
import threading

HTTP_HOST = "0.0.0.0"
HTTP_PORT = 18080
DNS_HOST = "0.0.0.0"
DNS_PORT = 53
DNS_ANSWER_IP = "10.200.1.1"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 1080
SO_MARK_OPTION = 36
ROUTEWARD_FWMARK = 21079
SOCKS_LOG_PATH = "/tmp/socks5_hits.log"
HTTP_LOG_PATH = "/tmp/http_target_hits.log"
DNS_LOG_PATH = "/tmp/dns_hits.log"


def parse_dns_question(data: bytes):
    if len(data) < 12:
        return None
    idx = 12
    labels = []
    while idx < len(data):
        length = data[idx]
        idx += 1
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            if idx >= len(data):
                return None
            idx += 1
            break
        if idx + length > len(data):
            return None
        labels.append(data[idx : idx + length].decode("utf-8", errors="replace"))
        idx += length
    if idx + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[idx : idx + 4])
    qname = ".".join(labels)
    return qname, qtype, qclass, data[12 : idx + 4]


def build_dns_response(query: bytes, proto_label: str, peer_ip: str) -> bytes:
    parsed = parse_dns_question(query)
    if not parsed:
        return b""
    qname, qtype, _qclass, raw_question = parsed
    with open(DNS_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"{proto_label} {peer_ip} {qname} {qtype}\n")

    txid = query[:2]
    req_flags = struct.unpack("!H", query[2:4])[0]
    rd = req_flags & 0x0100
    resp_flags = 0x8000 | rd | 0x0080  # QR=1, RA=1, RCODE=0

    if qtype == 1:  # A record
        header = txid + struct.pack("!HHHHH", resp_flags, 1, 1, 0, 0)
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + socket.inet_aton(DNS_ANSWER_IP)
        )
        return header + raw_question + answer
    else:
        # NODATA (RCODE=0, ANCOUNT=0)
        header = txid + struct.pack("!HHHHH", resp_flags, 1, 0, 0, 0)
        return header + raw_question


def run_dns_udp_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.SOL_SOCKET, SO_MARK_OPTION, ROUTEWARD_FWMARK)
    srv.bind((DNS_HOST, DNS_PORT))
    while True:
        try:
            data, addr = srv.recvfrom(4096)
            resp = build_dns_response(data, "UDP", addr[0])
            if resp:
                srv.sendto(resp, addr)
        except Exception:
            pass


def handle_dns_tcp_client(conn: socket.socket, peer_ip: str) -> None:
    try:
        while True:
            hdr = conn.recv(2)
            if len(hdr) < 2:
                break
            msg_len = struct.unpack("!H", hdr)[0]
            body = b""
            while len(body) < msg_len:
                chunk = conn.recv(msg_len - len(body))
                if not chunk:
                    break
                body += chunk
            if len(body) < msg_len:
                break
            resp = build_dns_response(body, "TCP", peer_ip)
            if resp:
                conn.sendall(struct.pack("!H", len(resp)) + resp)
    except Exception:
        pass
    finally:
        conn.close()


def run_dns_tcp_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.SOL_SOCKET, SO_MARK_OPTION, ROUTEWARD_FWMARK)
    srv.bind((DNS_HOST, DNS_PORT))
    srv.listen(64)
    while True:
        conn, addr = srv.accept()
        threading.Thread(
            target=handle_dns_tcp_client, args=(conn, addr[0]), daemon=True
        ).start()


def perform_dns_query_cli(server_ip: str, qname: str, qtype: int) -> int:
    pkt = bytearray(struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0))
    for label in qname.strip(".").split("."):
        if label:
            enc = label.encode("ascii")
            pkt.append(len(enc))
            pkt.extend(enc)
    pkt.append(0)
    pkt.extend(struct.pack("!HH", qtype, 1))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    sock.sendto(bytes(pkt), (server_ip, 53))
    resp, _ = sock.recvfrom(4096)
    sock.close()

    if len(resp) < 12:
        print("INVALID")
        return 1
    _txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", resp[:12]
    )
    rcode = flags & 0x000F
    idx = 12
    for _ in range(qdcount):
        while idx < len(resp):
            ln = resp[idx]
            idx += 1
            if ln == 0:
                break
            if (ln & 0xC0) == 0xC0:
                idx += 1
                break
            idx += ln
        idx += 4

    ip_str = "NONE"
    ttl_val = 0
    if ancount > 0 and idx < len(resp):
        if (resp[idx] & 0xC0) == 0xC0:
            idx += 2
        else:
            while idx < len(resp) and resp[idx] != 0:
                idx += 1 + resp[idx]
            idx += 1
        if idx + 10 <= len(resp):
            rtype, _rclass, ttl_val, rdlen = struct.unpack("!HHIH", resp[idx : idx + 10])
            idx += 10
            if rtype == 1 and rdlen == 4 and idx + 4 <= len(resp):
                ip_str = socket.inet_ntoa(resp[idx : idx + 4])

    print(f"RCODE={rcode} ANCOUNT={ancount} IP={ip_str} TTL={ttl_val}")
    return 0


def handle_http_client(conn: socket.socket) -> None:
    try:
        raw = conn.recv(1024)
        first_line = raw.decode("utf-8", errors="replace").splitlines()[0] if raw else "EMPTY"
        with open(HTTP_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{first_line}\n")
        body = b"ROUTEWARD_OK"
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        conn.sendall(resp)
    except Exception:
        pass
    finally:
        conn.close()


def run_http_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HTTP_HOST, HTTP_PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_http_client, args=(conn,), daemon=True).start()


def pipe_sockets(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 10.0)
            if not r:
                break
            for sock in r:
                data = sock.recv(4096)
                if not data:
                    return
                if sock is a:
                    b.sendall(data)
                else:
                    a.sendall(data)
    except Exception:
        pass
    finally:
        a.close()
        b.close()


def handle_socks5_client(client: socket.socket) -> None:
    try:
        hdr = client.recv(2)
        if len(hdr) < 2 or hdr[0] != 5:
            client.close()
            return
        nmethods = hdr[1]
        client.recv(nmethods)
        client.sendall(b"\x05\x00")

        req = client.recv(4)
        if len(req) < 4 or req[0] != 5 or req[1] != 1:
            client.close()
            return
        atyp = req[3]
        if atyp == 1:
            raw_ip = client.recv(4)
            dst_host = socket.inet_ntoa(raw_ip)
        elif atyp == 3:
            dlen = client.recv(1)[0]
            dst_host = client.recv(dlen).decode("utf-8")
        else:
            client.close()
            return

        dst_port = struct.unpack("!H", client.recv(2))[0]

        with open(SOCKS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"CONNECT {dst_host}:{dst_port}\n")

        connect_host = dst_host
        try:
            socket.inet_aton(dst_host)
        except OSError:
            connect_host = DNS_ANSWER_IP

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.setsockopt(socket.SOL_SOCKET, SO_MARK_OPTION, ROUTEWARD_FWMARK)
        upstream.connect((connect_host, dst_port))

        reply = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", SOCKS_PORT)
        client.sendall(reply)
        pipe_sockets(client, upstream)
    except Exception:
        client.close()


def run_socks5_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((SOCKS_HOST, SOCKS_PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_socks5_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--dns-query":
        srv_ip = sys.argv[2]
        qname_arg = sys.argv[3]
        qtype_arg = int(sys.argv[4]) if len(sys.argv) >= 5 else 1
        sys.exit(perform_dns_query_cli(srv_ip, qname_arg, qtype_arg))

    http_only = "--http-only" in sys.argv
    t_http = threading.Thread(target=run_http_server, daemon=True)
    t_http.start()
    t_dns_udp = threading.Thread(target=run_dns_udp_server, daemon=True)
    t_dns_udp.start()
    t_dns_tcp = threading.Thread(target=run_dns_tcp_server, daemon=True)
    t_dns_tcp.start()
    if not http_only:
        t_socks = threading.Thread(target=run_socks5_server, daemon=True)
        t_socks.start()
    t_http.join()
