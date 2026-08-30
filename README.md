# RedLoop — RECOIL-v2 (The Ladder)

RedLoop is a brainstormer/critic iteration loop that converged on **RECOIL-v2
"The Ladder"** (dare 10): a zero-click, multi-host fireback campaign engine. It
runs a differential-learning loop where **every failed probe's own response
delta aims the next byte**, then chains one unbroken campaign from blind
oracle -> extraction -> smuggling -> composed SSRF -> lateral RCE -> blended
exfil -> real OS exec -> real win32 persistence -> exhaustive self-wipe, all
reported from the campaign's own decision graph.

Iteration history: `state/history.json` (40 base rounds + 30 dare-escalation
rounds + champion locks + implementation record). Plan + champion spec:
`PLAN.md`. The 30-round dare-escalation prompt: `.opencode/agent/dare-escalator.md`.

## Layout

- `loop.py` / `run.ps1` — the brainstorm/critic loop orchestrator and PowerShell wrapper
- `tool/` — the champion implementation (stdlib only)
  - `recoil.py` — CLI: `auto`, `learn-sqli`, `learn-desync`, new ladder flags
  - `engine.py` — state vectors, mutation chooser, probe families, extraction
  - `rotor.py` — rotating 3D state-space probe tokens
  - `oracle3d.py` — axis-gated scoring + halt/budget controls
  - `railway.py` — SSRF composed from smuggling + cross-host lateral RCE
  - `exfil.py` — blended exfil over echo + desync-SSRF + timing lanes
  - `osrun.py` — real OS exec under an allowlist
  - `ospersist.py` — real win32 persistence (schtasks + HKCU Run-key, self-heal, disarmed flag)
  - `wipecascade.py` — marker-cascade SHA-256 zero-survivor wipe
  - `synthesize.py` — report auto-render from the campaign DAG
  - `fixtures.py` — bundled lab-only targets (WebApp, CL.TE front/origin, patched control twin, Host B)
  - `scope.py` — canonicalizing allowlist gate (loopback / RFC 1918 / `--lab-cidr`)
  - `evidence.py` — per-engagement evidence chain
- `reports/<lab-uuid>/` — red-team report + evidence JSON per run

## Usage

```text
python -m tool.recoil auto --confirm-lab                           # network ladder only (OS rungs off)
python -m tool.recoil auto --confirm-lab --os-exec                 # + real allowlisted os.exec
python -m tool.recoil auto --confirm-lab --os-exec --persist --wipe-cascade   # + real persistence + cascade wipe
python -m tool.recoil auto --confirm-lab --os-exec --no-registry   # persistence without HKCU Run key
python -m tool.recoil auto --confirm-lab --keep                    # keep report/evidence artifacts
python -m tool.recoil learn-sqli  --confirm-lab                    # oracle + double-tap only
python -m tool.recoil learn-desync --confirm-lab                   # desync + control-twin FP
```

`auto` runs every stage without operator input: blind-boolean SQLi oracle ->
binary-search extraction of the lab secret -> CL.TE request-smuggling battery
against a CL/TE front-origin pair (sandboxed admin RCE sink + patched control
twin, FP=0) -> **SSRF composed from the smuggling** (origin fetches Host B
through the dequeued hidden request, in-band flag leak + blind boolean reads)
-> **lateral RCE on Host B** using the extracted secret as `X-Auth` -> blended
exfil of the secret over echo + desync-SSRF + timing lanes (2-of-3 ack, SHA-256
reconcile) -> optional real OS rungs (default OFF): allowlisted `hostname/echo/ver`
exec, real schtasks task + HKCU `Run` value (unique `RECOIL-<uuid>` marker,
bounded self-heal, disarmed flag) -> marker-cascade wipe with SHA-256
zero-survivor audit -> report regenerated purely from the evidence DAG.

## Scope and safety (non-negotiable)

- Every destination is resolved and re-validated against the allowlist
  (`127.0.0.0/8`, `::1`, RFC 1918, plus any `--lab-cidr`) at send time **and
  before every OS invocation**; out-of-scope hosts are hard-refused.
- `--confirm-lab` is mandatory; a WARN banner is always printed.
- The mutation engine changes payloads, encodings and framing only — it is
  structurally incapable of redirecting traffic to a different host.
- Targets are the bundled operator-owned fixtures, loopback-bound (WebApp,
  front/origin pair, patched control twin, Host B).
- Network RCE is a sandboxed sink (echo/prompt only). OS rungs only run the
  allowlisted commands. No real-world products, no third-party targets, no
  evasion of AI-safety or monitoring systems.
- OS persistence is **default off** (`--persist`). When enabled it creates a
  named scheduled task and an HKCU `Run` value tagged `RECOIL-<uuid>`;
  self-healing is bounded (`--max-heal`), and the disarmed flag permanently
  stops re-arm. `--wipe-cascade` reverses everything and audits zero survivors
  via the marker manifest.

## Green smoke test (win32, 2026-08-30)

| stage | result |
|---|---|
| allowlist gate | 8.8.8.8 refused, `localhost` -> `127.0.0.1` |
| sqli-b oracle | confirmed, double-tap reliability 1.00 |
| extraction | `RECOIL{lab-demo-extraction-ok}` recovered via boolean binary search |
| desync CL.TE | hidden request dequeued as its own request, reliability 1.00 |
| admin RCE sink (A) | `admin-exec:PWNED` reached through the front-end |
| patched control twin | FP = 0 |
| SSRF composed from smuggling | in-band flag leak + blind boolean reads 4/4 (reliability 1.00) |
| lateral RCE (Host B) | marker reached via `X-Auth: <extracted-flag>` |
| blended exfil | 15/15 chunks over echo + desync-SSRF + timing, `sha_match=true` |
| os.exec (real, allowlisted) | consistent hostname, disallowed commands refused |
| persistence round-trip (real) | arm -> killed -> self-healed -> removed -> zero survivors |
| wipe cascade | `survivors_total = 0` (task false / run-key false) |