import json
import pathlib


def render(dag: dict, report_dir: pathlib.Path) -> pathlib.Path:
    md = report_dir / "report.md"
    out = ["# RECOIL-v2 ladder report", f"**engagement:** {dag.get('engagement','-')}", ""]
    out.append("## Campaign DAG")
    out.append("| node | host | family | primitive | axis signal |")
    out.append("|---|---|---|---|---|")
    for node in dag.get("nodes", []):
        out.append(
            f"| {node.get('phase','')} | {node.get('host','')} | {node.get('family','')} | "
            f"{node.get('primitive','')} | {json.dumps(node.get('axis',{}))} |"
        )
    out.append("")
    out.append("## Verdicts")
    out.extend(f"- `{v.get('what')}` -> **{v.get('outcome','')}**" for v in dag.get("verdicts", []))
    out.append("")
    out.append("## Kill-switch status")
    for k, v in dag.get("kill_switches", {}).items():
        out.append(f"- `{k}` = **{v}**")
    md.write_text("\n".join(out), encoding="utf-8")
    return md