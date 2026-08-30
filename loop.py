#!/usr/bin/env python3
"""
RedLoop orchestrator — stateful loop driver for the Brainstormer/Critic pair.

Commands:
  python loop.py status            show iteration count + convergence signal
  python loop.py add -r ROLE -f F  append a JSON artifact (brainstormer|critic|merge)
  python loop.py convergent        exit 0 with champion name if converged
  python loop.py plan -o PLAN.md   write the champion spec into PLAN.md

Everything is persisted under state/ and history.json so the loop componds.
Stdlib only.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE = ROOT / "state"
HISTORY = STATE / "history.json"
CANDIDATES = STATE / "candidates"
CRITIQUES = STATE / "critiques"

CONVERGENCE_SATURATION = 3       # same concept championed >= N times
CONVERGENCE_SCORE = 8.0          # OR overall score >= this
MIN_ITERATIONS_BEFORE_CONVERGE = 6


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_history() -> list:
    if not HISTORY.exists():
        return []
    return json.loads(HISTORY.read_text(encoding="utf-8"))


def save_history(history: list) -> None:
    HISTORY.write_text(json.dumps(history, indent=2), encoding="utf-8")


def add_artifact(role: str, file: Path) -> None:
    data = json.loads(file.read_text(encoding="utf-8"))
    history = load_history()
    entry = {
        "iter": len(history) + 1,
        "role": role,
        "timestamp": utcnow(),
        "data": data,
    }
    history.append(entry)
    save_history(history)
    dest = CANDIDATES if role == "brainstormer" else CRITIQUES if role == "critic" else STATE
    tag = data.get("name") or data.get("target") or role
    (dest / f"iter{entry['iter']:03d}_{tag}.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )
    print(f"[ok] iter={entry['iter']} role={role} tag={tag}")


def status() -> None:
    history = load_history()
    by_role = {}
    for h in history:
        by_role.setdefault(h["role"], 0)
        by_role[h["role"]] += 1
    print(f"total iterations : {len(history)}")
    for role, count in sorted(by_role.items()):
        print(f"  {role:<12} : {count}")
    if not history:
        return
    for winner, n in champion_counts(history):
        if n >= 1:
            print(f"top shortlist/saturation: {winner} x{n}")


def champion_counts(history):
    counts = {}
    for h in history:
        v = h.get("data", {})
        if v.get("verdict") and v["verdict"].startswith(("shortlist", "champion")):
            t = v.get("target", "?")
            counts[t] = counts.get(t, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


def terminal_champion(history):
    for h in reversed(history):
        if h["role"] == "critic" and h.get("data", {}).get("verdict") == "champion_candidate":
            return h["data"].get("target")
    return None


def convergent() -> int:
    history = load_history()
    if len(history) < MIN_ITERATIONS_BEFORE_CONVERGE:
        print(f"not converged: only {len(history)} iterations (< {MIN_ITERATIONS_BEFORE_CONVERGE})")
        return 1
    champ = terminal_champion(history)
    if champ:
        print(f"CONVERGED (terminal verdict) on {champ}")
        return 0
    for winner, n in champion_counts(history):
        if n >= CONVERGENCE_SATURATION:
            print(f"CONVERGED on {winner} (saturation x{n})")
            return 0
        # highest overall score among critiques for this target
    best = 0.0
    best_name = None
    for h in history:
        if h["role"] == "critic":
            sc = h["data"].get("overall", 0)
            if sc > best:
                best = sc
                best_name = h["data"].get("target")
    if best >= CONVERGENCE_SCORE:
        print(f"CONVERGED on {best_name} (overall={best:.1f})")
        return 0
    print(f"not converged: best overall={best:.1f}/{CONVERGENCE_SCORE}")
    return 1


def plan(out: Path) -> None:
    history = load_history()
    champion = terminal_champion(history)
    champion_count = 1 if champion else 0
    if not champion:
        for winner, n in champion_counts(history):
            if n > champion_count:
                champion_count = n
                champion = winner
    if not champion:
        best = 0.0
        for h in history:
            if h["role"] == "critic" and h["data"].get("overall", 0) > best:
                best = h["data"]["overall"]
                champion = h["data"].get("target")
    if not champion:
        print("no champion yet — run more iterations")
        sys.exit(1)

    champ_entry = next(
        (
            h["data"]
            for h in reversed(history)
            if h["role"] == "critic"
            and h["data"].get("target") == champion
            and h["data"].get("verdict") == "champion_candidate"
        ),
        None,
    )
    crit = champ_entry or next(
        (
            h["data"]
            for h in history
            if h["role"] == "critic" and h["data"].get("target") == champion
        ),
        None,
    )
    cand = (champ_entry.get("spec") if champ_entry and champ_entry.get("spec") else champ_entry) or next(
        (
            h["data"]
            for h in history
            if h["role"] in ("brainstormer", "merge") and h["data"].get("name") == champion
        ),
        None,
    )
    out.write_text(
        "# RedLoop — Champion PLAN\n\n"
        f"**Champion:** `{champion}` (shortlisted x{champion_count})\n\n"
        "## Candidate spec\n```json\n"
        + json.dumps(cand, indent=2)
        + "\n```\n\n## Critic verdict\n```json\n"
        + json.dumps(crit, indent=2)
        + "\n```\n\n## Build order\n1. Scaffold `tool/` per candidate spec.\n2. Enforce the scope gate. 3. Network discovery layer. 4. Exploit chain. 5. Smoke-test vs disposable lab target.\n",
        encoding="utf-8",
    )
    print(f"wrote {out}")


def main() -> None:
    p = argparse.ArgumentParser(description="RedLoop orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status")
    s.set_defaults(fn=lambda args, p=p: status())

    a = sub.add_parser("add")
    a.add_argument("-r", "--role", choices=["brainstormer", "critic", "merge"], required=True)
    a.add_argument("-f", "--file", type=Path, required=True)
    a.set_defaults(fn=lambda args, p=p: add_artifact(args.role, args.file))

    c = sub.add_parser("convergent")
    c.set_defaults(fn=lambda args, p=p: (lambda: sys.exit(convergent()))())

    pl = sub.add_parser("plan")
    pl.add_argument("-o", "--out", type=Path, default=ROOT / "PLAN.md")
    pl.set_defaults(fn=lambda args, p=p: plan(args.out))

    args = p.parse_args()
    args.fn(args, p)  # type: ignore[attr-defined]


if __name__ == "__main__":
    main()