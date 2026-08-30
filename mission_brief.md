# RedLoop — Mission Brief (Seed)

**Scope:** Spearhead *one* offensive security tool built from scratch in this
folder, for **lab/CTF/authorized targets only** (your own Docker/virtual lab).

**Mission:** Build an autonomous offensive tool that performs an end-to-end
attack chain against allowlisted lab targets:

1. **Discover** lab targets on the allowlisted lab network
2. **Enumerate** open services and fingerprint them
3. **Triage** candidate vulnerabilities (ranked by likelihood of exploitation)
4. **Exploit** the highest-value target autonomously
5. **Deliver** a payload and achieve execution
6. **Persist** (lab-safe demonstration)
7. **Report** — emit a red-team style report of the engagement

**Hard constraints (every artifact inherits these):**
- Built-in lab-scope allowlist (loopback/private ranges + user-supplied lab CIDR).
- Refuses to touch anything outside the allowlist, with a WARN banner on first run.
- Never facilitates attacking real/third-party targets; never evades AI-safety systems.
- Python-first, stdlib where possible, dependency-light, single-folder tool output.

**Process:** The Brainstormer generates candidate concepts, the Critic reviews
and scores them, the loop merges/evolves until champion convergence, then the
champion is implemented in `tool/` and smoke-tested against a disposable lab target.

Iteration history lives in `state/`. See `state/history.json`.

**Operator directive (updated, binding):** The champion MUST score
`dare_factor >= 9` and exhibit *fireback* novelty — a hot, sharp,
come-back-at-you aggressiveness: maximum autonomy, no operator clicks between
stages, multi-vector chains that feed results back into escalation, and painful
consequences for a lab target (full compromise + persistence + recovery). Novelty
must be novel-in-kind, not re-branded existing tooling. Hard lab-safety lines
(the allowlist gate, WARN banner, no real targets, no AI-safety-system evasion)
remain non-negotiable ABOVE the dare requirement.

**Operator directive (dare-10 escalation, binding):** The champion must reach
`dare_factor = 10`, "for sure". Novelty and fireback are the load-bearing
requirements: the tool must genuinely fire back at the operator (the box talks
back; real contained primitives, real evidence of host execution, recoverable
persistence, forensic-grade cleanup). The operator explicitly accepts handling
that fireback ("I'm ready to handle it"). Dare escalation is driven BY AN AGENT,
~30 iterative rounds, each escalation proving its mechanism, its containment,
and its kill-switch. Containment rails stay: lab-only, allowlist re-validated
per byte, consented OS-level stages, sandboxed-but-real execution sinks,
reversible persistence, SHA-256 zero-survivor wipe, no AI-safety evasion.