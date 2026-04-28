#!/usr/bin/env python3
"""Re-snapshot all zones and overwrite baseline.json.

Usage:
    python scripts/refresh_baseline.py [--no-crtsh]

Run from the repo root. Use after intentional posture changes (e.g. a new
DNS record, a TXT verification, a new redirect target).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from domain_monitor import baseline as baseline_mod  # noqa: E402
from domain_monitor import config as config_mod  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--config", default=str(ROOT / "domains.yaml"))
    p.add_argument("--out", default=str(ROOT / "baseline.json"))
    p.add_argument("--no-crtsh", action="store_true")
    args = p.parse_args()
    cfg = config_mod.load(args.config)
    out = baseline_mod.regenerate(cfg, args.out, include_crtsh=not args.no_crtsh)
    print(f"refreshed: {out} ({len(cfg.domains)} zones)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
