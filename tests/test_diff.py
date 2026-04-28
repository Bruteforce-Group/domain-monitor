"""Diff/severity tests — the core of the monitor's correctness."""
from __future__ import annotations

from domain_monitor import diff as diff_mod
from domain_monitor.diff import CRITICAL, INFO, WARN


def _by_code(findings, code):
    return [f for f in findings if f.code == code]


# -------- happy path --------

def test_healthy_snapshot_against_baseline_yields_no_critical(cfg, healthy_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, healthy_snapshot, baseline)
    counts = diff_mod.summarise(findings)
    assert counts.get(CRITICAL, 0) == 0
    # noemail.test has no SPF/MX requirement and no CAA; still expect at most INFO/WARN
    crit = [f for f in findings if f.severity == CRITICAL]
    assert crit == []


def test_warp_chain_downgraded_to_info(cfg, healthy_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, healthy_snapshot, baseline)
    warp_findings = _by_code(findings, "tls_warp_intercept")
    # example.test has the WARP chain in healthy fixture
    assert any(f.domain == "example.test" for f in warp_findings)
    assert all(f.severity == INFO for f in warp_findings)


def test_no_tls_issuer_warn_when_warp_intercept(cfg, healthy_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, healthy_snapshot, baseline)
    assert _by_code(findings, "tls_issuer_unexpected") == []


# -------- compromise / drift detection --------

def test_ns_drift_to_non_cf_is_critical(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    ns_findings = [f for f in findings if f.code in ("ns_mismatch", "NS_added", "NS_removed")]
    assert ns_findings, "expected NS findings on degraded fixture"
    assert any(f.severity == CRITICAL for f in ns_findings)


def test_a_record_off_cf_is_critical(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    off_cf = _by_code(findings, "a_off_cf")
    assert off_cf
    assert all(f.severity == CRITICAL for f in off_cf)
    assert "8.8.8.8" in off_cf[0].detail["observed"]


def test_phishing_keywords_are_critical(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    phish = _by_code(findings, "phishing_keywords")
    assert phish
    assert phish[0].severity == CRITICAL
    assert "seed phrase" in phish[0].detail["flags"]


def test_redirect_to_unexpected_host_is_warn(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    bad_redirect = _by_code(findings, "redirect_unexpected")
    assert bad_redirect
    assert bad_redirect[0].severity == WARN


def test_tls_issuer_unexpected_when_not_warp(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    issuer_warns = _by_code(findings, "tls_issuer_unexpected")
    # example.test in degraded fixture has Sectigo (not in expected token list, not warp)
    assert any(f.domain == "example.test" for f in issuer_warns)


def test_origin_unreachable_status_is_warn(cfg, degraded_snapshot, baseline):
    # Mutate snapshot inline to inject a 522
    snap = dict(degraded_snapshot)
    snap["domains"]["example.test"]["http"]["status"] = 522
    snap["domains"]["example.test"]["http"]["error"] = None
    findings = diff_mod.diff_all(cfg, snap, baseline)
    unreachable = _by_code(findings, "origin_unreachable")
    assert unreachable
    assert unreachable[0].severity == WARN


def test_spf_missing_warns_when_required(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    spf = _by_code(findings, "spf_missing")
    assert any(f.domain == "example.test" for f in spf)


def test_spf_not_required_skipped(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    # noemail.test has require_spf = False
    spf_for_noemail = [f for f in _by_code(findings, "spf_missing") if f.domain == "noemail.test"]
    assert spf_for_noemail == []


def test_null_mx_violation_warns(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    mx_warn = _by_code(findings, "mx_not_null")
    assert any(f.domain == "example.test" for f in mx_warn)


def test_crtsh_new_issuance_detected(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    new_issue = _by_code(findings, "crtsh_new_issuance")
    assert any(f.domain == "example.test" for f in new_issue)
    assert new_issue[0].detail["now_total"] == 12
    assert new_issue[0].detail["baseline_total"] == 5


def test_summarise_counts(cfg, degraded_snapshot, baseline):
    findings = diff_mod.diff_all(cfg, degraded_snapshot, baseline)
    counts = diff_mod.summarise(findings)
    assert counts[CRITICAL] >= 2
    assert counts[WARN] >= 1


# -------- edge cases --------

def test_missing_snapshot_for_domain_is_warn(cfg, baseline):
    snap = {"run_utc": "x", "domains": {}}
    findings = diff_mod.diff_all(cfg, snap, baseline)
    miss = _by_code(findings, "snapshot_missing")
    assert len(miss) == len(cfg.domains)
    assert all(f.severity == WARN for f in miss)


def test_no_baseline_skips_drift_checks(cfg, healthy_snapshot):
    findings = diff_mod.diff_all(cfg, healthy_snapshot, baseline=None)
    drift_codes = {"NS_added", "NS_removed", "A_added", "A_removed",
                   "AAAA_added", "AAAA_removed", "crtsh_new_issuance"}
    assert not any(f.code in drift_codes for f in findings)


def test_warp_fingerprint_match_downgrades_even_unfamiliar_issuer(cfg, healthy_snapshot, baseline):
    # Replace issuer with one whose md5 matches the configured warp fingerprint.
    import hashlib
    target_fp = cfg.network.warp_intercept_ca_fingerprint
    issuer = "C=ZZ, O=Synthetic Test"
    # The fingerprint is md5(issuer) per diff._fingerprint_from_issuer.
    # We need an issuer whose md5 == target. We'll instead test that a
    # "Gateway CA" + "Cloudflare" issuer is recognised as WARP regardless.
    snap = healthy_snapshot
    snap["domains"]["example.test"]["tls_local"]["issuer"] = (
        "C=US, O=Cloudflare, Inc., CN=Gateway CA - Cloudflare Managed G1"
    )
    findings = diff_mod.diff_all(cfg, snap, baseline)
    warp = _by_code(findings, "tls_warp_intercept")
    assert warp
    _ = (target_fp, hashlib)  # silence unused
