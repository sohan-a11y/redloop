import json
import pathlib
import shutil

from . import ospersist


def cascade(engagement: str, report_dir: pathlib.Path, persister=None) -> dict:
    surv_before = []
    files = list(report_dir.rglob("*.json")) + list(report_dir.rglob("*.k")) + list(report_dir.rglob("manifest.sha256"))
    manifest = {}
    for p in files:
        manifest[str(p)] = __import__("hashlib").sha256(p.read_bytes()).hexdigest()
    for rel in manifest:
        p = pathlib.Path(rel)
        if p.exists():
            surv_before.append(str(p))
    removed_files = 0
    for rel in manifest:
        p = pathlib.Path(rel)
        if p.exists():
            p.unlink(missing_ok=True)
            removed_files += 1
    if persister is not None:
        persister.remove()
        persister.disarm()
    remains_files = [str(pathlib.Path(rel)) for rel in manifest if pathlib.Path(rel).exists()]
    task_here = ospersist.schtasks_available() and ospersist.task_liveness(engagement)
    run_here = False if persister is None or persister.no_registry else ospersist.run_key_liveness(engagement)
    return {
        "audit": "sha256-marker-cascade",
        "manifest_size": len(manifest),
        "removed_files": removed_files,
        "remains_files": remains_files,
        "task_survivor": task_here,
        "run_key_survivor": run_here,
        "survivors_total": len(remains_files) + (1 if task_here else 0) + (1 if run_here else 0),
    }