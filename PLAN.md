# RedLoop — Champion PLAN

**Champion:** `RECOIL-v2 The Ladder` (shortlisted x1)

## Candidate spec
```json
{
  "target": "RECOIL-v2 The Ladder",
  "verdict": "champion_candidate",
  "dare_factor": 10,
  "lineage": "RECOIL-v1 escalated across 30 dare rounds (iters 41-70)",
  "implemented": false,
  "build_plan": [
    "rotor.py 3D state space",
    "cross-host token lateral (A->B)",
    "SSRF composed from smuggling",
    "blended exfil + timing channel",
    "real OS exec under allowlist",
    "real win32 persistence (task + Run-key, self-heal, disarmed flag)",
    "marker-cascade wipe",
    "report synth from DAG"
  ],
  "containment": "bundled loopback + optional --lab-cidr; allowlist per byte and per OS call; sandboxed sinks; reversible persisted artifacts; no AI-safety evasion"
}
```

## Critic verdict
```json
{
  "target": "RECOIL-v2 The Ladder",
  "verdict": "champion_candidate",
  "dare_factor": 10,
  "lineage": "RECOIL-v1 escalated across 30 dare rounds (iters 41-70)",
  "implemented": false,
  "build_plan": [
    "rotor.py 3D state space",
    "cross-host token lateral (A->B)",
    "SSRF composed from smuggling",
    "blended exfil + timing channel",
    "real OS exec under allowlist",
    "real win32 persistence (task + Run-key, self-heal, disarmed flag)",
    "marker-cascade wipe",
    "report synth from DAG"
  ],
  "containment": "bundled loopback + optional --lab-cidr; allowlist per byte and per OS call; sandboxed sinks; reversible persisted artifacts; no AI-safety evasion"
}
```

## Build order
1. Scaffold `tool/` per candidate spec.
2. Enforce the scope gate. 3. Network discovery layer. 4. Exploit chain. 5. Smoke-test vs disposable lab target.
