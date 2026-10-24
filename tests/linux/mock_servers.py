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
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 1080
SO_MARK_OPTION = 36
ROUTEWARD_FWMARK = 21079
SOCKS_LOG_PATH = "/tmp/socks5_hits.log"
HTTP_LOG_PATH = "/tmp/http_target_hits.log"


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

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.setsockopt(socket.SOL_SOCKET, SO_MARK_OPTION, ROUTEWARD_FWMARK)
        upstream.connect((dst_host, dst_port))

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
    http_only = "--http-only" in sys.argv
    t_http = threading.Thread(target=run_http_server, daemon=True)
    t_http.start()
    if not http_only:
        t_socks = threading.Thread(target=run_socks5_server, daemon=True)
        t_socks.start()
    t_http.join()
