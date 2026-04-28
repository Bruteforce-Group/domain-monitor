"""Pytest fixtures shared across the test suite."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from domain_monitor import config as config_mod

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def domains_yaml_path() -> Path:
    return FIXTURES / "domains.yaml"


@pytest.fixture()
def cfg(domains_yaml_path: Path):
    return config_mod.load(domains_yaml_path)


@pytest.fixture()
def healthy_snapshot() -> dict:
    return json.loads((FIXTURES / "snapshot_healthy.json").read_text())


@pytest.fixture()
def degraded_snapshot() -> dict:
    return json.loads((FIXTURES / "snapshot_degraded.json").read_text())


@pytest.fixture()
def baseline() -> dict:
    return json.loads((FIXTURES / "baseline.json").read_text())
