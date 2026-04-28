"""Baseline I/O.

A baseline.json captures the canonical posture for each domain so that the
daily diff has something to compare against. Schema mirrors the snapshot
structure but is intended to be hand-curated / regenerated only on demand.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

from .config import Config
from .snapshot import Snapshot, snapshot_all


def load_baseline(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"created_utc": None, "domains": {}}
    return json.loads(p.read_text())


def write_baseline(snapshot: Snapshot, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "created_utc": snapshot.run_utc,
        "domains": snapshot.domains,
    }
    p.write_text(json.dumps(body, indent=2, default=str, sort_keys=True))
    return p


def regenerate(config: Config, path: str | Path, *, include_crtsh: bool = True) -> Path:
    """Snapshot every domain and write it as the new baseline."""
    snap = snapshot_all(list(config.domain_names), include_crtsh=include_crtsh)
    return write_baseline(snap, path)


def baseline_age_days(baseline: dict[str, Any]) -> int | None:
    created = baseline.get("created_utc")
    if not created:
        return None
    try:
        dt = datetime.datetime.fromisoformat(created.rstrip("Z"))
    except ValueError:
        return None
    return (datetime.datetime.utcnow() - dt).days
