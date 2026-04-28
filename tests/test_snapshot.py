"""Snapshot-module tests — pure-function bits without network."""
from __future__ import annotations

from unittest import mock

from domain_monitor import snapshot as snap_mod


# ---------- _run helper ----------

def test_run_returns_stdout_stderr_returncode():
    out, err, rc = snap_mod._run(["echo", "hello"])
    assert out == "hello"
    assert rc == 0


def test_run_handles_timeout(monkeypatch):
    def boom(*a, **kw):
        raise __import__("subprocess").TimeoutExpired(cmd="x", timeout=1)
    monkeypatch.setattr(snap_mod.subprocess, "run", boom)
    out, err, rc = snap_mod._run(["sleep", "10"], timeout=1)
    assert err == "TIMEOUT"
    assert rc == -1


# ---------- DNS helpers ----------

def test_dig_parses_dig_output(monkeypatch):
    monkeypatch.setattr(snap_mod, "_run", lambda cmd, timeout=15: ("alpha.ns.cloudflare.com.\nbeta.ns.cloudflare.com.\n", "", 0))
    out = snap_mod.dig("example.test", "NS")
    assert out == ["alpha.ns.cloudflare.com.", "beta.ns.cloudflare.com."]


def test_dig_returns_sorted_unique_lines(monkeypatch):
    monkeypatch.setattr(snap_mod, "_run", lambda cmd, timeout=15: ("z\na\nm\n", "", 0))
    assert snap_mod.dig("example.test", "A") == ["a", "m", "z"]


def test_dig_empty_lines_stripped(monkeypatch):
    monkeypatch.setattr(snap_mod, "_run", lambda cmd, timeout=15: ("\n\nfoo\n\n", "", 0))
    assert snap_mod.dig("example.test", "TXT") == ["foo"]


# ---------- HTTP probe ----------

def test_http_probe_parses_curl_output(monkeypatch):
    headers_and_trailer = (
        "HTTP/2 301\n"
        "server: cloudflare\n"
        "location: https://wp.example.test/\n"
        "STATUS=301\n"
        "IP=104.21.1.1\n"
        "CT=text/html\n"
        "FINAL=https://example.test/\n"
    )
    body = "<html>hello</html>"

    calls = []

    def fake_run(cmd, timeout=15):
        calls.append(cmd)
        if "-D" in cmd:  # header probe
            return headers_and_trailer, "", 0
        return body, "", 0

    monkeypatch.setattr(snap_mod, "_run", fake_run)
    res = snap_mod.http_probe("example.test")
    assert res["status"] == 301
    assert res["server"] == "cloudflare"
    assert res["location"] == "https://wp.example.test/"
    assert res["remote_ip"] == "104.21.1.1"
    assert res["content_type"] == "text/html"
    assert res["body_len"] == len(body)
    assert res["body_sha256"]


def test_http_probe_flags_phishing_keywords(monkeypatch):
    headers_and_trailer = ("HTTP/2 200\nSTATUS=200\nIP=1.1.1.1\nCT=text/html\nFINAL=x\n")
    body = "Connect your wallet and enter your seed phrase to verify your account."

    def fake_run(cmd, timeout=15):
        if "-D" in cmd:
            return headers_and_trailer, "", 0
        return body, "", 0

    monkeypatch.setattr(snap_mod, "_run", fake_run)
    res = snap_mod.http_probe("phish.test")
    assert "seed phrase" in res["phishing_flags"]
    assert "connect your wallet" in res["phishing_flags"]
    assert "verify your account" in res["phishing_flags"]


def test_http_probe_curl_failure_sets_error(monkeypatch):
    monkeypatch.setattr(snap_mod, "_run", lambda cmd, timeout=15: ("", "boom", 6))
    res = snap_mod.http_probe("dead.test")
    assert res["error"]


# ---------- crt.sh ----------

def test_crtsh_handles_url_error(monkeypatch):
    import urllib.error

    def fake_open(*a, **kw):
        raise urllib.error.URLError("nope")

    monkeypatch.setattr(snap_mod.urllib.request, "urlopen", fake_open)
    res = snap_mod.crtsh("example.test")
    assert res["count_total"] == 0
    assert res["recent"] == []
    assert "error" in res


def test_crtsh_parses_and_truncates(monkeypatch):
    # Fake response object with .read() returning JSON bytes
    payload = [
        {"id": i, "name_value": f"a{i}.test", "issuer_name": "X", "not_before": "n", "not_after": "n",
         "entry_timestamp": f"2026-04-{i:02d}T00:00:00"}
        for i in range(1, 80)
    ]
    import io
    import json

    class FakeResp:
        def __init__(self, data):
            self._data = data

        def read(self):
            return self._data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(snap_mod.urllib.request, "urlopen",
                        lambda req, timeout=20: FakeResp(json.dumps(payload).encode()))
    res = snap_mod.crtsh("example.test")
    assert res["count_total"] == 79
    assert len(res["recent"]) == 50
    # Sort is descending by entry_timestamp
    assert res["recent"][0]["id"] == 79


# ---------- Snapshot orchestration ----------

def test_snapshot_domain_aggregates_subprobes(monkeypatch):
    monkeypatch.setattr(snap_mod, "dig", lambda d, rt, **kw: [f"{rt}-rec"])
    monkeypatch.setattr(snap_mod, "dig_soa", lambda d, **kw: "soa-rec")
    monkeypatch.setattr(snap_mod, "http_probe", lambda d: {"http": "ok"})
    monkeypatch.setattr(snap_mod, "tls_local", lambda d: {"tls": "ok"})
    monkeypatch.setattr(snap_mod, "crtsh", lambda d: {"crtsh": "ok"})
    s = snap_mod.snapshot_domain("x.test")
    assert s["domain"] == "x.test"
    assert s["NS"] == ["NS-rec"]
    assert s["http"] == {"http": "ok"}
    assert s["tls_local"] == {"tls": "ok"}
    assert s["crtsh"] == {"crtsh": "ok"}


def test_snapshot_domain_skips_crtsh_when_disabled(monkeypatch):
    monkeypatch.setattr(snap_mod, "dig", lambda d, rt, **kw: [])
    monkeypatch.setattr(snap_mod, "dig_soa", lambda d, **kw: "")
    monkeypatch.setattr(snap_mod, "http_probe", lambda d: {})
    monkeypatch.setattr(snap_mod, "tls_local", lambda d: {})
    called = mock.Mock()
    monkeypatch.setattr(snap_mod, "crtsh", called)
    s = snap_mod.snapshot_domain("x.test", include_crtsh=False)
    assert s["crtsh"] == {"skipped": True}
    called.assert_not_called()


def test_snapshot_all_returns_dataclass_with_run_utc(monkeypatch):
    monkeypatch.setattr(snap_mod, "snapshot_domain", lambda d, **kw: {"domain": d})
    s = snap_mod.snapshot_all(["a.test", "b.test"], include_crtsh=False)
    assert "run_utc" in s.to_json()
    assert set(s.domains.keys()) == {"a.test", "b.test"}
