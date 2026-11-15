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
import time

HTTP_HOST = "0.0.0.0"
HTTP_PORT = 18080
HTTPS_PORT = 443
LLMNR_PORT = 5355
DNS_HOST = "10.200.1.1"
DNS_PORT = 53
DNS_ANSWER_IP = "10.200.1.1"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 1080
SO_MARK_OPTION = 36
ROUTEWARD_FWMARK = 21079
SOCKS_LOG_PATH = "/tmp/socks5_hits.log"
HTTP_LOG_PATH = "/tmp/http_target_hits.log"
HTTPS_LOG_PATH = "/tmp/https_443_hits.log"
DNS_LOG_PATH = "/tmp/dns_hits.log"
UDP_443_LOG_PATH = "/tmp/udp_443_hits.log"
LLMNR_LOG_PATH = "/tmp/llmnr_5355_hits.log"
UDP_DIRECT_PORT = 19990
UDP_DIRECT_LOG_PATH = "/tmp/udp_direct_hits.log"


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


def run_http_v6_server() -> None:
    try:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        srv.bind(("::", HTTP_PORT))
        srv.listen(64)
    except OSError:
        return
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_http_client, args=(conn,), daemon=True).start()


def handle_https_443_client(conn: socket.socket) -> None:
    try:
        raw = conn.recv(4096)
        with open(HTTPS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"TLS_443 len={len(raw)}\n")
        conn.sendall(b"HTTPS_SNI_OK")
    except Exception:
        pass
    finally:
        conn.close()


def run_https_443_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HTTP_HOST, HTTPS_PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_https_443_client, args=(conn,), daemon=True).start()


def build_tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode("ascii")
    sni_list = struct.pack("!BH", 0x00, len(sni_bytes)) + sni_bytes
    sni_ext_data = struct.pack("!H", len(sni_list)) + sni_list
    ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    ch_body = (
        b"\x03\x03"
        + (b"\x11" * 32)
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(ext))
        + ext
    )
    ch_len = len(ch_body)
    handshake = bytes([0x01, (ch_len >> 16) & 0xFF, (ch_len >> 8) & 0xFF, ch_len & 0xFF]) + ch_body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def perform_tls_sni_probe_cli(target_ip: str, sni: str) -> int:
    hello = build_tls_client_hello(sni)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4.0)
    sock.connect((target_ip, HTTPS_PORT))
    sock.sendall(hello)
    resp = sock.recv(1024)
    sock.close()
    print(resp.decode("utf-8", errors="replace"))
    return 0


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
        elif atyp == 4:
            raw_ip = client.recv(16)
            dst_host = socket.inet_ntop(socket.AF_INET6, raw_ip)
        else:
            client.close()
            return

        dst_port = struct.unpack("!H", client.recv(2))[0]

        with open(SOCKS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"CONNECT {dst_host}:{dst_port}\n")

        connect_host = dst_host
        is_ipv6_target = False
        try:
            socket.inet_aton(dst_host)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, dst_host)
                is_ipv6_target = True
            except OSError:
                connect_host = DNS_ANSWER_IP

        if is_ipv6_target:
            upstream = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            upstream.setsockopt(socket.SOL_SOCKET, SO_MARK_OPTION, ROUTEWARD_FWMARK)
            upstream.connect((connect_host, dst_port))
        else:
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


def run_udp_443_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HTTP_HOST, HTTPS_PORT))
    while True:
        try:
            data, addr = srv.recvfrom(4096)
            with open(UDP_443_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"UDP_443 {addr[0]}:{addr[1]} len={len(data)}\n")
        except Exception:
            pass


def run_llmnr_5355_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HTTP_HOST, LLMNR_PORT))
    while True:
        try:
            data, addr = srv.recvfrom(4096)
            parsed = parse_dns_question(data)
            qname = parsed[0] if parsed else "MALFORMED"
            with open(LLMNR_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"LLMNR_5355 {addr[0]}:{addr[1]} {qname}\n")
        except Exception:
            pass


def perform_socks5_udp_exchange_cli(
    local_socks_port: int, target_ip: str, target_port: int, payload_str: str
) -> int:
    ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl.settimeout(3.0)
    ctrl.connect(("127.0.0.1", local_socks_port))
    ctrl.sendall(b"\x05\x01\x00")
    greeting = ctrl.recv(2)
    if len(greeting) < 2 or greeting[1] != 0:
        print("HANDSHAKE_FAILED")
        ctrl.close()
        return 1

    # Send CMD=0x03 (UDP ASSOCIATE) with 0.0.0.0:0
    ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    rep = ctrl.recv(10)
    if len(rep) < 10 or rep[1] != 0:
        print(f"ASSOCIATE_FAILED REP={rep[1] if len(rep) > 1 else -1}")
        ctrl.close()
        return 1

    bnd_ip = socket.inet_ntoa(rep[4:8])
    bnd_port = struct.unpack("!H", rep[8:10])[0]

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(2.5)
    pkt = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(target_ip)
        + struct.pack("!H", target_port)
        + payload_str.encode("utf-8")
    )
    udp_sock.sendto(pkt, (bnd_ip, bnd_port))
    try:
        resp, _ = udp_sock.recvfrom(4096)
    except socket.timeout:
        print("UDP_TIMEOUT")
        udp_sock.close()
        ctrl.close()
        return 2

    udp_sock.close()
    ctrl.close()
    if len(resp) < 10:
        print("SHORT_REPLY")
        return 1
    atyp = resp[3]
    if atyp == 1:
        hdr_len = 10
    elif atyp == 3:
        hdr_len = 7 + resp[4]
    elif atyp == 4:
        hdr_len = 22
    else:
        print("BAD_ATYP")
        return 1
    body = resp[hdr_len:].decode("utf-8", errors="replace")
    print(f"UDP_OK BODY={body}")
    return 0


def perform_quic_udp_probe_cli(target_ip: str, target_port: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)
    sock.connect((target_ip, target_port))
    t0 = time.perf_counter()
    try:
        sock.send(b"QUIC_INITIAL_PROBE")
        sock.recv(1024)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        print(f"QUIC_UNEXPECTED_RECV DELAY_MS={elapsed_ms:.2f}")
        sock.close()
        return 1
    except ConnectionRefusedError:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        print(f"QUIC_REJECTED ERR=ConnectionRefusedError DELAY_MS={elapsed_ms:.2f}")
        sock.close()
        return 0
    except OSError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        print(f"QUIC_ERROR ERR={type(exc).__name__}:{exc.errno} DELAY_MS={elapsed_ms:.2f}")
        sock.close()
        return 0


def perform_llmnr_query_cli(target_ip: str, qname: str) -> int:
    pkt = bytearray(struct.pack("!HHHHHH", 0x5355, 0x0000, 1, 0, 0, 0))
    for label in qname.strip(".").split("."):
        if label:
            enc = label.encode("ascii")
            pkt.append(len(enc))
            pkt.extend(enc)
    pkt.append(0)
    pkt.extend(struct.pack("!HH", 1, 1))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    local_port = sock.getsockname()[1]
    sock.sendto(bytes(pkt), (target_ip, LLMNR_PORT))
    sock.close()
    print(f"LLMNR_SENT QNAME={qname} SRC_PORT={local_port}")
    return 0


def run_udp_direct_echo_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.SOL_SOCKET, SO_MARK_OPTION, ROUTEWARD_FWMARK)
    srv.bind((HTTP_HOST, UDP_DIRECT_PORT))
    while True:
        try:
            data, addr = srv.recvfrom(4096)
            body = data.decode("utf-8", errors="replace")
            with open(UDP_DIRECT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"UDP_DIRECT {addr[0]}:{addr[1]} {body}\n")
            srv.sendto(("DIRECT_ECHO_OK:" + body).encode("utf-8"), addr)
        except Exception:
            pass


def run_udp_direct_echo_v6_server() -> None:
    try:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        srv.setsockopt(socket.SOL_SOCKET, SO_MARK_OPTION, ROUTEWARD_FWMARK)
        srv.bind(("::", UDP_DIRECT_PORT))
    except OSError:
        return
    while True:
        try:
            data, addr = srv.recvfrom(4096)
            body = data.decode("utf-8", errors="replace")
            with open(UDP_DIRECT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"UDP_DIRECT_V6 [{addr[0]}]:{addr[1]} {body}\n")
            srv.sendto(("DIRECT_ECHO_OK:" + body).encode("utf-8"), addr)
        except Exception:
            pass


def perform_transparent_udp6_send_cli(
    target_ip: str, target_port: int, payload_str: str
) -> int:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(2.5)
    sock.sendto(payload_str.encode("utf-8"), (target_ip, target_port))
    try:
        resp, from_addr = sock.recvfrom(4096)
    except socket.timeout:
        print("TRANSPARENT_UDP6_TIMEOUT")
        sock.close()
        return 2
    except OSError as exc:
        print(f"TRANSPARENT_UDP6_ERR {type(exc).__name__}:{exc.errno}")
        sock.close()
        return 3
    sock.close()
    body = resp.decode("utf-8", errors="replace")
    print(f"TRANSPARENT_UDP6_OK FROM=[{from_addr[0]}]:{from_addr[1]} BODY={body}")
    return 0


def perform_transparent_udp_send_cli(
    target_ip: str, target_port: int, payload_str: str
) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.5)
    sock.sendto(payload_str.encode("utf-8"), (target_ip, target_port))
    try:
        resp, from_addr = sock.recvfrom(4096)
    except socket.timeout:
        print("TRANSPARENT_UDP_TIMEOUT")
        sock.close()
        return 2
    except OSError as exc:
        print(f"TRANSPARENT_UDP_ERR {type(exc).__name__}:{exc.errno}")
        sock.close()
        return 3
    sock.close()
    body = resp.decode("utf-8", errors="replace")
    print(f"TRANSPARENT_UDP_OK FROM={from_addr[0]}:{from_addr[1]} BODY={body}")
    return 0


def perform_transparent_udp_dual_send_cli(
    proxy_ip: str,
    proxy_port: int,
    direct_ip: str,
    direct_port: int,
    payload_str: str,
) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.5)
    sock.bind(("0.0.0.0", 0))
    local_port = sock.getsockname()[1]

    sock.sendto((payload_str + "-via-proxy").encode("utf-8"), (proxy_ip, proxy_port))
    resp1, from1 = sock.recvfrom(4096)

    sock.sendto((payload_str + "-via-direct").encode("utf-8"), (direct_ip, direct_port))
    resp2, from2 = sock.recvfrom(4096)

    sock.close()
    b1 = resp1.decode("utf-8", errors="replace")
    b2 = resp2.decode("utf-8", errors="replace")
    print(
        f"DUAL_OK LOCAL_PORT={local_port} R1={from1[0]}:{from1[1]}:{b1} R2={from2[0]}:{from2[1]}:{b2}"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--dns-query":
        srv_ip = sys.argv[2]
        qname_arg = sys.argv[3]
        qtype_arg = int(sys.argv[4]) if len(sys.argv) >= 5 else 1
        sys.exit(perform_dns_query_cli(srv_ip, qname_arg, qtype_arg))

    if len(sys.argv) >= 4 and sys.argv[1] == "--tls-sni-probe":
        sys.exit(perform_tls_sni_probe_cli(sys.argv[2], sys.argv[3]))

    if len(sys.argv) >= 6 and sys.argv[1] == "--socks5-udp-exchange":
        sys.exit(
            perform_socks5_udp_exchange_cli(
                int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5]
            )
        )

    if len(sys.argv) >= 4 and sys.argv[1] == "--quic-udp-probe":
        sys.exit(perform_quic_udp_probe_cli(sys.argv[2], int(sys.argv[3])))

    if len(sys.argv) >= 4 and sys.argv[1] == "--llmnr-query":
        sys.exit(perform_llmnr_query_cli(sys.argv[2], sys.argv[3]))

    if len(sys.argv) >= 5 and sys.argv[1] == "--transparent-udp-send":
        sys.exit(
            perform_transparent_udp_send_cli(
                sys.argv[2], int(sys.argv[3]), sys.argv[4]
            )
        )

    if len(sys.argv) >= 5 and sys.argv[1] == "--transparent-udp6-send":
        sys.exit(
            perform_transparent_udp6_send_cli(
                sys.argv[2], int(sys.argv[3]), sys.argv[4]
            )
        )

    if len(sys.argv) >= 7 and sys.argv[1] == "--transparent-udp-dual-send":
        sys.exit(
            perform_transparent_udp_dual_send_cli(
                sys.argv[2],
                int(sys.argv[3]),
                sys.argv[4],
                int(sys.argv[5]),
                sys.argv[6],
            )
        )

    http_only = "--http-only" in sys.argv
    t_http = threading.Thread(target=run_http_server, daemon=True)
    t_http.start()
    t_http_v6 = threading.Thread(target=run_http_v6_server, daemon=True)
    t_http_v6.start()
    t_https = threading.Thread(target=run_https_443_server, daemon=True)
    t_https.start()
    t_udp_443 = threading.Thread(target=run_udp_443_server, daemon=True)
    t_udp_443.start()
    t_llmnr = threading.Thread(target=run_llmnr_5355_server, daemon=True)
    t_llmnr.start()
    t_udp_direct = threading.Thread(target=run_udp_direct_echo_server, daemon=True)
    t_udp_direct.start()
    t_udp_direct_v6 = threading.Thread(target=run_udp_direct_echo_v6_server, daemon=True)
    t_udp_direct_v6.start()
    t_dns_udp = threading.Thread(target=run_dns_udp_server, daemon=True)
    t_dns_udp.start()
    t_dns_tcp = threading.Thread(target=run_dns_tcp_server, daemon=True)
    t_dns_tcp.start()
    if not http_only:
        t_socks = threading.Thread(target=run_socks5_server, daemon=True)
        t_socks.start()
    t_http.join()
