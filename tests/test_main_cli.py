"""End-to-end CLI tests — orchestration, exit codes, file plumbing."""
from __future__ import annotations

import json
from pathlib import Path

from domain_monitor import __main__ as cli
from domain_monitor.snapshot import Snapshot


def _stub_snapshot_all(monkeypatch, healthy_snapshot):
    def fake(domains, *, include_crtsh=True):
        return Snapshot(run_utc=healthy_snapshot["run_utc"],
                        domains={d: healthy_snapshot["domains"][d] for d in domains})
    monkeypatch.setattr(cli.snapshot_mod, "snapshot_all", fake)


def test_diff_subcommand_renders_report(tmp_path: Path, domains_yaml_path,
                                        healthy_snapshot, baseline):
    snap_path = tmp_path / "snap.json"
    base_path = tmp_path / "base.json"
    report_path = tmp_path / "out" / "report.md"
    snap_path.write_text(json.dumps(healthy_snapshot))
    base_path.write_text(json.dumps(baseline))

    rc = cli.main([
        "diff",
        "--config", str(domains_yaml_path),
        "--snapshot", str(snap_path),
        "--baseline", str(base_path),
        "--report", str(report_path),
    ])
    assert rc == 0
    assert report_path.exists()
    md = report_path.read_text()
    assert "Domain Monitor Report" in md


def test_diff_fail_on_critical_returns_2(tmp_path: Path, domains_yaml_path,
                                         degraded_snapshot, baseline):
    snap_path = tmp_path / "snap.json"
    base_path = tmp_path / "base.json"
    snap_path.write_text(json.dumps(degraded_snapshot))
    base_path.write_text(json.dumps(baseline))

    rc = cli.main([
        "diff",
        "--config", str(domains_yaml_path),
        "--snapshot", str(snap_path),
        "--baseline", str(base_path),
        "--report", str(tmp_path / "r.md"),
        "--fail-on-critical",
    ])
    assert rc == 2


def test_run_subcommand_writes_snapshot_and_diff(tmp_path: Path, domains_yaml_path,
                                                 healthy_snapshot, baseline,
                                                 monkeypatch):
    base_path = tmp_path / "base.json"
    base_path.write_text(json.dumps(baseline))
    out_dir = tmp_path / "runs"
    _stub_snapshot_all(monkeypatch, healthy_snapshot)

    rc = cli.main([
        "run",
        "--config", str(domains_yaml_path),
        "--baseline", str(base_path),
        "--out", str(out_dir),
    ])
    assert rc == 0
    assert any((out_dir / "snapshots").iterdir())
    assert any((out_dir / "diffs").iterdir())


def test_baseline_subcommand_writes_file(tmp_path: Path, domains_yaml_path,
                                          healthy_snapshot, monkeypatch):
    out = tmp_path / "b.json"
    _stub_snapshot_all(monkeypatch, healthy_snapshot)
    rc = cli.main([
        "baseline",
        "--config", str(domains_yaml_path),
        "--out", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert "domains" in data and "created_utc" in data


def test_snapshot_subcommand_writes_file(tmp_path: Path, domains_yaml_path,
                                         healthy_snapshot, monkeypatch):
    out = tmp_path / "snap.json"
    _stub_snapshot_all(monkeypatch, healthy_snapshot)
    rc = cli.main([
        "snapshot",
        "--config", str(domains_yaml_path),
        "--out", str(out),
        "--no-crtsh",
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert "run_utc" in data
