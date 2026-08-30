import subprocess

ALLOWLIST = {"echo", "hostname", "ver"}


def canonical(parts: list[str]) -> bool:
    if not parts:
        return False
    return parts[0].lower() in ALLOWLIST


def run(parts: list[str], timeout: float = 6.0) -> dict:
    if not canonical(parts):
        return {"ok": False, "err": "denied-not-in-allowlist", "out": ""}
    try:
        proc = subprocess.run(parts, shell=False, capture_output=True, timeout=timeout, text=True)
        return {
            "ok": proc.returncode == 0,
            "out": (proc.stdout or proc.stderr).strip(),
            "rc": proc.returncode,
        }
    except Exception as exc:
        return {"ok": False, "err": f"{type(exc).__name__}:{exc}", "out": ""}


def double_tap(parts: list[str], reps: int = 3) -> dict:
    outs = set()
    errs = []
    for _ in range(reps):
        r = run(parts)
        if not r.get("ok"):
            errs.append(r)
            break
        outs.add(r["out"])
    return {"ok": len(outs) == 1, "consistent": sorted(outs), "errs": errs, "reps": reps}