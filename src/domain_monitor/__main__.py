"""CLI entry point.

Usage:
    domain-monitor run        --config domains.yaml --baseline baseline.json --out runs/
    domain-monitor snapshot   --config domains.yaml --out snapshots/today.json
    domain-monitor diff       --config domains.yaml --baseline baseline.json --snapshot snapshots/today.json
    domain-monitor baseline   --config domains.yaml --out baseline.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from . import config as config_mod
from . import baseline as baseline_mod
from . import diff as diff_mod
from . import report as report_mod
from . import snapshot as snapshot_mod


def _today() -> str:
    return datetime.date.today().isoformat()


def _cmd_snapshot(args: argparse.Namespace) -> int:
    cfg = config_mod.load(args.config)
    snap = snapshot_mod.snapshot_all(list(cfg.domain_names), include_crtsh=not args.no_crtsh)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(snap.to_json())
    print(f"snapshot: wrote {out}", file=sys.stderr)
    return 0


def _cmd_baseline(args: argparse.Namespace) -> int:
    cfg = config_mod.load(args.config)
    out = baseline_mod.regenerate(cfg, args.out, include_crtsh=not args.no_crtsh)
    print(f"baseline: wrote {out}", file=sys.stderr)
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    cfg = config_mod.load(args.config)
    snap = json.loads(Path(args.snapshot).read_text())
    base = baseline_mod.load_baseline(args.baseline) if args.baseline else None
    findings = diff_mod.diff_all(cfg, snap, base)
    md = report_mod.render_markdown(findings, run_utc=snap.get("run_utc"),
                                    domains_total=len(cfg.domains))
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(md)
        print(f"diff: wrote {args.report}", file=sys.stderr)
    else:
        print(md)
    counts = diff_mod.summarise(findings)
    print(f"diff: {counts}", file=sys.stderr)
    if args.fail_on_critical and counts.get(diff_mod.CRITICAL, 0) > 0:
        return 2
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    """Snapshot + diff + report all in one go."""
    cfg = config_mod.load(args.config)
    out_dir = Path(args.out)
    snap_dir = out_dir / "snapshots"
    diff_dir = out_dir / "diffs"
    snap_dir.mkdir(parents=True, exist_ok=True)
    diff_dir.mkdir(parents=True, exist_ok=True)

    snap = snapshot_mod.snapshot_all(list(cfg.domain_names), include_crtsh=not args.no_crtsh)
    snap_path = snap_dir / f"{_today()}.json"
    snap_path.write_text(snap.to_json())

    base = baseline_mod.load_baseline(args.baseline) if args.baseline else None
    snap_dict: dict[str, Any] = {"run_utc": snap.run_utc, "domains": snap.domains}
    findings = diff_mod.diff_all(cfg, snap_dict, base)
    md = report_mod.render_markdown(findings, run_utc=snap.run_utc,
                                    domains_total=len(cfg.domains))
    diff_path = diff_dir / f"{_today()}.md"
    diff_path.write_text(md)
    counts = diff_mod.summarise(findings)
    print(f"run: snapshot={snap_path} diff={diff_path} {counts}", file=sys.stderr)
    if args.fail_on_critical and counts.get(diff_mod.CRITICAL, 0) > 0:
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="domain-monitor")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp_snap = sub.add_parser("snapshot", help="Capture a snapshot")
    sp_snap.add_argument("--config", required=True)
    sp_snap.add_argument("--out", required=True)
    sp_snap.add_argument("--no-crtsh", action="store_true")
    sp_snap.set_defaults(func=_cmd_snapshot)

    sp_base = sub.add_parser("baseline", help="(Re)generate baseline.json")
    sp_base.add_argument("--config", required=True)
    sp_base.add_argument("--out", required=True)
    sp_base.add_argument("--no-crtsh", action="store_true")
    sp_base.set_defaults(func=_cmd_baseline)

    sp_diff = sub.add_parser("diff", help="Diff a snapshot against a baseline")
    sp_diff.add_argument("--config", required=True)
    sp_diff.add_argument("--snapshot", required=True)
    sp_diff.add_argument("--baseline", default=None)
    sp_diff.add_argument("--report", default=None,
                         help="Path to write Markdown report; default stdout")
    sp_diff.add_argument("--fail-on-critical", action="store_true")
    sp_diff.set_defaults(func=_cmd_diff)

    sp_run = sub.add_parser("run", help="Snapshot + diff + report")
    sp_run.add_argument("--config", required=True)
    sp_run.add_argument("--baseline", default=None)
    sp_run.add_argument("--out", required=True)
    sp_run.add_argument("--no-crtsh", action="store_true")
    sp_run.add_argument("--fail-on-critical", action="store_true")
    sp_run.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
