"""Evidence writer: every probe, delta, verdict and decision is journaled
with the per-engagement lab UUID so the fireback claim (mutations learned
from response deltas) is inspectable, not asserted.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any


class Evidence:
    def __init__(self, engagement: str, root: Path) -> None:
        self.uuid = engagement
        self.root = root
        self.log: list[dict[str, Any]] = []
        self.started = time.time()

    def event(self, kind: str, **fields: Any) -> None:
        fields["kind"] = kind
        fields["t"] = round(time.time() - self.started, 4)
        fields["lab_uuid"] = self.uuid
        self.log.append(fields)

    def dart(self, **fields: Any) -> None:
        self.event("probe", **fields)

    def verdict_ok(self, what: str, **fields: Any) -> None:
        self.event("verdict", outcome="ok", what=what, **fields)

    def verdict_no(self, what: str, **fields: Any) -> None:
        self.event("verdict", outcome="no", what=what, **fields)

    def write(self, name: str = "evidence.json") -> Path:
        out = self.root / name
        out.write_text(json.dumps(self.log, indent=2), encoding="utf-8")
        return out

    def sha(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()