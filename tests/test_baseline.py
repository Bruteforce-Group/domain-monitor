"""Baseline I/O tests."""
from __future__ import annotations

import json
from pathlib import Path

from domain_monitor import baseline as baseline_mod
from domain_monitor.snapshot import Snapshot


def test_load_baseline_missing_returns_empty(tmp_path: Path):
    res = baseline_mod.load_baseline(tmp_path / "does-not-exist.json")
    assert res == {"created_utc": None, "domains": {}}


def test_load_baseline_reads_existing(tmp_path: Path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"created_utc": "2026-01-01T00:00:00Z", "domains": {"x.test": {}}}))
    res = baseline_mod.load_baseline(p)
    assert res["created_utc"] == "2026-01-01T00:00:00Z"
    assert "x.test" in res["domains"]


def test_write_baseline_round_trip(tmp_path: Path):
    snap = Snapshot(run_utc="2026-04-28T07:00:00Z",
                    domains={"x.test": {"NS": ["a.ns.cloudflare.com."]}})
    out = baseline_mod.write_baseline(snap, tmp_path / "out" / "b.json")
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["created_utc"] == "2026-04-28T07:00:00Z"
    assert data["domains"]["x.test"]["NS"] == ["a.ns.cloudflare.com."]


def test_baseline_age_days_handles_missing():
    assert baseline_mod.baseline_age_days({}) is None
    assert baseline_mod.baseline_age_days({"created_utc": "garbage"}) is None


def test_baseline_age_days_computes(monkeypatch):
    import datetime
    fake_now = datetime.datetime(2026, 4, 28)

    class FakeDT(datetime.datetime):
        @classmethod
        def utcnow(cls):
            return fake_now

    monkeypatch.setattr(baseline_mod.datetime, "datetime", FakeDT)
    assert baseline_mod.baseline_age_days({"created_utc": "2026-04-21T00:00:00"}) == 7
