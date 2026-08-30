"""Bundled lab-only target fixtures (stdlib, loopback, threaded).

Three operator-owned fixtures the engine is allowlisted to attack:

1. WebApp - HTTP app with a blind-boolean SQLi oracle (/sqli), a
            command-echo injection (/ping) and a token-gated /admin/exec.
2. Front  - CL-aware smuggling front-end that only permits /proxy* paths.
3. Origin - TE-aware backend. In clte mode Transfer-Encoding wins and a
            smuggled request inside the body gets executed as its own
            next request. In patched mode Content-Length always wins and
            leftovers are rejected (the engine's FP control twin).

Every sink is demo-grade and sandboxed: the RCE sink refuses any command
that is not echo/prompt inside this fixture.
"""
from __future__ import annotations

import http.server
import shlex
import socket
import socketserver
import threading
import time
import urllib.parse
from typing import Callable, Optional

HOST = "127.0.0.1"
FLAG = "RECOIL{lab-demo-extraction-ok}"

ROWS = [
    {"id": 1, "name": "alpha", "v": "a"},
    {"id": 2, "name": "bravo", "v": "b"},
    {"id": 3, "name": "charlie", "v": "c"},
]
EXTRA = [{"id": 9, "name": "secret", "v": FLAG}]


def rows_matching(pred: str) -> int:
    if "fsub(" in pred:
        try:
            body = pred.split("fsub(", 1)[1]
            n_str, rest = body.split(",", 1)
            n = int(n_str.strip())
            rest = rest.split(")", 1)[0].strip()
            for op in (">", "=", "<"):
                if rest.startswith(op):
                    c = rest[len(op):].strip().strip("'\"")
                    break
            else:
                return 0
            ch = FLAG[n - 1]  # SQL substr(flag, n, 1) is 1-based
            if ">" in rest:
                return 1 if ch > c else 0
            if "<" in rest:
                return 1 if ch < c else 0
            return 1 if ch == c else 0
        except Exception:
            return 0
    if any(t in pred for t in ("'1'='1'", "1=1", "'a'='a'")):
        return len(ROWS) + len(EXTRA)
    if any(t in pred for t in ("'1'='2'", "1=2", "'a'='b'")):
        return 0
    if "'" in pred and "AND" in pred.upper():
        return 0
    return len(ROWS) + len(EXTRA)


def _safe_exec(cmdline: str) -> str:
    parts = shlex.split(cmdline)
    if not parts:
        return "denied"
    if parts[0].lower() == "echo":
        return " ".join(parts[1:])
    if parts[0].lower() == "prompt":
        return f"<marker>{' '.join(parts[1:])}</marker>"
    return "denied"


class _HttpHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # type: ignore[no-untyped-def]
        pass

    def _reply(self, code: int, body: str) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        raw = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(raw.query)
        if raw.path == "/sqli":
            self._sqli(qs)
        elif raw.path == "/ping":
            self._ping(qs)
        elif raw.path == "/admin/exec":
            self._admin(qs)
        elif raw.path == "/tick":
            delay = min(int((qs.get("delay") or ["0"])[0]), 800)
            time.sleep(delay / 1000.0)
            self._reply(200, f"tick {delay}")
        else:
            self._reply(404, "not found")

    def do_POST(self) -> None:
        self._reply(405, "no")

    def _sqli(self, qs) -> None:
        ident = (qs.get("id") or [""])[0]
        if not ident:
            self._reply(200, "rows=0")
            return
        if "'" not in ident:
            self._reply(200, "rows=0")
            return
        n = rows_matching(ident)
        if n < 0:
            self._reply(500, "db error")
            return
        picked = [f"{r['id']}:{r['name']}" for r in ROWS + EXTRA][:n]
        if "fsub" in ident:
            # blind boolean oracle: true/false differ ONLY in body length,
            # nothing is leaked - a "static error scanner" misses this.
            body = f"rows={len(picked)}\n" + "row" * len(picked)
            self._reply(200, body)
            return
        self._reply(200, f"rows={len(picked)}\n" + "\n".join(picked))

    def _ping(self, qs) -> None:
        host = (qs.get("host") or [""])[0]
        if "|" in host:
            left, _, right = host.partition("|")
            r = right.strip()
            if r.startswith("ec(") and r.endswith(")"):
                self._reply(200, f"ping {left}\necho:{r[3:-1]}")
                return
            self._reply(200, f"ping {left}")
            return
        self._reply(200, f"ping {host}")

    def _admin(self, qs) -> None:
        if self.headers.get("X-Auth") != "secret":
            self._reply(403, "forbidden")
            return
        cmd = (qs.get("cmd") or ["echo ok"])[0]
        out = _safe_exec(cmd)
        self._reply(200, f"admin-exec:{out}")

class _Handler2(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _reply(self, code: int, body: str) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        raw = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(raw.query)
        if raw.path == "/fsub":
            n = int((qs.get("pos") or ["1"])[0])
            op = (qs.get("op") or [">"])[0]
            c = (qs.get("c") or ["a"])[0]
            hit = 1 if fsub_oracle(n, op, c) else 0
            self._reply(200, f"rows={hit}\n" + "row" * hit)
            return
        if raw.path == "/admin/exec":
            if self.headers.get("X-Auth") != FLAG:
                self._reply(403, "forbidden")
                return
            cmd = (qs.get("cmd") or ["echo ok"])[0]
            out = _safe_exec(cmd)
            self._reply(200, f"admin-exec:{out}")
            return
        if raw.path == "/flag":
            tag = (qs.get("tag") or [""])[0]
            self._reply(200, f"flag:{FLAG}:{tag}")
            return
        self._reply(404, "not found")

    def do_POST(self) -> None:
        self._reply(405, "no")


class AdminHost:
    def __init__(self) -> None:
        self.server = socketserver.ThreadingTCPServer((HOST, 0), _Handler2, bind_and_activate=True)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> "AdminHost":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def fsub_oracle(pos: int, op: str, c: str) -> bool:
    n = rows_matching(f"' AND fsub({pos},{op}'{c}')")
    return n >= 1


class WebApp:
    def __init__(self) -> None:
        self.server = socketserver.ThreadingTCPServer((HOST, 0), _HttpHandler, bind_and_activate=True)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> "WebApp":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# ---------------------------------------------------------------------------
# Desync pair: Front (CL-aware) -> Origin (TE-trusting / patched control twin)
# ---------------------------------------------------------------------------

def spawn_tcp(svc: Callable[[socket.socket], None]) -> socketserver.TCPServer:
    server: socketserver.TCPServer = socketserver.TCPServer((HOST, 0), socketserver.BaseRequestHandler, bind_and_activate=True)
    server.daemon_threads = True

    class Handler(socketserver.BaseRequestHandler):  # type: ignore[misc]
        def handle(self) -> None:  # type: ignore[override]
            try:
                self.request.settimeout(4)
                svc(self.request)
            except Exception:
                pass
            finally:
                try:
                    self.request.close()
                except Exception:
                    pass

    server.RequestHandlerClass = Handler
    server._svc = svc  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def recv_until(sock: socket.socket, needle: bytes, budget: int = 65536) -> bytes:
    buf = b""
    while needle not in buf and len(buf) < budget:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def read_head(sock: socket.socket) -> Optional[dict]:
    data = recv_until(sock, b"\r\n\r\n")
    if b"\r\n\r\n" not in data:
        return None
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    method, path, _ver = lines[0].split(" ", 2)
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    return {"method": method, "path": path, "headers": headers, "rest": rest}


def content_length(headers: dict) -> int:
    try:
        return int(headers.get("content-length", "0"))
    except ValueError:
        return 0


def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def parse_chunked(rest: bytes, sock: socket.socket) -> tuple[bytes, bytes]:
    buf = rest
    chunks = b""
    while True:
        while b"\r\n" not in buf:
            more = sock.recv(4096)
            if not more:
                return chunks, buf
            buf += more
        line, _, buf = buf.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            return chunks, buf
        if size == 0:
            # 0-chunk: framing ends; anything that follows the terminator is
            # the next request on this boundary (empty trailers = single CRLF).
            if buf.startswith(b"\r\n"):
                buf = buf[2:]
            return chunks, buf
        while len(buf) < size + 2:
            more = sock.recv(4096)
            if not more:
                return chunks, buf
            buf += more
        chunks += buf[:size]
        buf = buf[size + 2 :]


def conn_line(rest: bytes, sock: socket.socket) -> Optional[dict]:
    if b"\r\n\r\n" not in rest:
        rest += recv_until(sock, b"\r\n\r\n")
    if b"\r\n\r\n" not in rest:
        return None
    head, _, rest = rest.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    method, path, _ver = lines[0].split(" ", 2)
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    cl = content_length(headers)
    body = b""
    if cl:
        have = rest[:cl]
        rest = rest[cl:]
        body += have
        if len(body) < cl:
            body += read_exact(sock, cl - len(body))
    return {"method": method, "path": path, "headers": headers, "body": body, "rest": rest}


def render_req(method: str, path: str, headers: dict, body: bytes = b"") -> bytes:
    out = f"{method} {path} HTTP/1.1\r\n".encode("iso-8859-1")
    for k, v in headers.items():
        out += f"{k}: {v}\r\n".encode("iso-8859-1")
    out += b"\r\n" + body
    return out


def reply_line(sock: socket.socket, code: int, body: str) -> None:
    data = body.encode()
    sock.sendall(f"HTTP/1.1 {code} OK\r\nContent-Length: {len(data)}\r\n\r\n".encode() + data)


def _route(sock: socket.socket, req: dict, internal_port: int | None = None) -> None:
    if req["path"].startswith("/internal"):
        if internal_port is None:
            reply_line(sock, 400, "no internal target bound")
            return
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(req["path"]).query)
        target = (qs.get("target") or [""])[0]
        if target != "b":
            reply_line(sock, 400, "unknown internal target")
            return
        path = (qs.get("path") or ["/"])[0]
        code, body = pf_fetch(internal_port, path)
        reply_line(sock, code, body)
        return
    if req["path"].startswith("/admin/exec"):
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(req["path"]).query)
        cmd = (qs.get("cmd") or ["echo ok"])[0]
        out = _safe_exec(cmd)
        if out == "denied":
            reply_line(sock, 403, "denied")
        else:
            reply_line(sock, 200, f"admin-exec:{out}")
        return
    if req["path"] == "/basic":
        reply_line(sock, 200, "origin id=ok")
        return
    reply_line(sock, 404, "origin miss")


def pf_fetch(port: int, path: str) -> tuple[int, str]:
    import http.client
    try:
        conn = http.client.HTTPConnection(HOST, port, timeout=4)
        conn.request("GET", path)
        r = conn.getresponse()
        body = r.read().decode("iso-8859-1", "replace")
        return r.status, body
    except Exception as exc:
        return 500, f"err:{type(exc).__name__}"


def origin_svc(mode: str, internal_port: int | None = None) -> Callable[[socket.socket], None]:
    def svc(sock: socket.socket) -> None:
        msg = read_head(sock)
        if not msg:
            return
        hdr = msg["headers"]
        te = hdr.get("transfer-encoding", "").lower()
        cl = content_length(hdr)
        rest = msg["rest"]
        if mode == "clte" and "chunked" in te and cl and msg["path"].startswith("/proxy"):
            _chunks, leftover = parse_chunked(rest, sock)
            if leftover.strip().startswith((b"GET", b"POST", b"HEAD")):
                nxt = conn_line(leftover, sock)
                if nxt:
                    _route(sock, nxt, internal_port)
                    return
                reply_line(sock, 200, "front-flowed id=ok")
                return
            reply_line(sock, 200, "front-flowed id=ok")
            return
        if "chunked" in te and cl:
            parse_chunked(rest, sock)
        elif cl:
            need = cl - len(rest)
            if need > 0:
                read_exact(sock, need)
        if msg["path"].startswith("/proxy"):
            reply_line(sock, 200, "front-flowed id=ok")
            return

    return svc


def patched_svc(sock: socket.socket) -> None:
    msg = read_head(sock)
    if not msg:
        return
    hdr = msg["headers"]
    cl = content_length(hdr)
    rest = msg["rest"]
    if cl:
        need = cl - len(rest)
        if need > 0:
            read_exact(sock, need)
        if rest[:cl].strip().startswith(b"GET"):
            reply_line(sock, 400, "smuggle rejected")
            return
    if msg["path"].startswith("/proxy"):
        reply_line(sock, 200, "front-flowed id=ok")
        return


def front_svc(origin_port: int) -> Callable[[socket.socket], None]:
    def svc(sock: socket.socket) -> None:
        msg = read_head(sock)
        if not msg:
            return
        if not msg["path"].startswith("/proxy"):
            reply_line(sock, 403, "front denied")
            return
        hdr = dict(msg["headers"])
        cl = content_length(hdr)
        body = msg["rest"]
        if cl and len(body) < cl:
            body += read_exact(sock, cl - len(body))
        body = body[:cl]
        forwarded = render_req(msg["method"], msg["path"], hdr, body)
        try:
            with socket.create_connection((HOST, origin_port), timeout=4) as osock:
                osock.settimeout(4)
                osock.sendall(forwarded)
                head = recv_until(osock, b"\r\n\r\n")
                if b"\r\n\r\n" not in head:
                    return
                head_bytes, _, rest = head.partition(b"\r\n\r\n")
                lines = head_bytes.decode("iso-8859-1").split("\r\n")
                out = head_bytes + b"\r\n\r\n"
                for ln in lines[1:]:
                    if ln.lower().startswith("content-length:"):
                        n = int(ln.split(":", 1)[1].strip())
                        have = rest
                        if len(have) < n:
                            have += read_exact(osock, n - len(have))
                        have = have[:n]
                        out += have
                sock.sendall(out)
        except Exception:
            pass

    return svc