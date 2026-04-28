"""Compare today's snapshot against a baseline and emit findings.

Severity model:
- CRITICAL: posture broken in a way that suggests compromise or hijack
- WARN:     posture drift that needs attention but isn't urgent
- INFO:     observation, no action

WARP-awareness:
The local TLS chain under Cloudflare Zero Trust WARP is re-signed by
`Gateway CA - Cloudflare Managed G1`. We do NOT raise CRITICAL on issuer
mismatch when the observed fingerprint matches the configured
`warp_intercept_ca_fingerprint`; instead we attribute the chain to WARP
and rely on crt.sh (CT-log) for issuance verification.
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
from typing import Any, Iterable

from .config import Config, DomainConfig, NetworkConfig

CRITICAL = "CRITICAL"
WARN = "WARN"
INFO = "INFO"


@dataclasses.dataclass
class Finding:
    domain: str
    severity: str
    code: str
    message: str
    detail: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------- Helpers ----------

def _fingerprint_from_issuer(issuer: str | None) -> str | None:
    if not issuer:
        return None
    # md5 of normalised issuer string — used for WARP CA detection
    return hashlib.md5(issuer.encode("utf-8")).hexdigest()


def _is_warp_chain(tls_local: dict[str, Any], net: NetworkConfig) -> bool:
    issuer = tls_local.get("issuer") or ""
    if "Gateway CA" in issuer and "Cloudflare" in issuer:
        return True
    fp = _fingerprint_from_issuer(issuer)
    return bool(net.warp_intercept_ca_fingerprint and fp == net.warp_intercept_ca_fingerprint)


def _issuer_matches_expected(issuer: str | None, tokens: Iterable[str]) -> bool:
    if not issuer:
        return False
    return any(t.lower() in issuer.lower() for t in tokens)


# ---------- Per-domain checks ----------

def _check_ns(domain: DomainConfig, snap: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    observed = set(snap.get("NS", []))
    expected = set(domain.expected_ns_fqdn)
    if not observed:
        findings.append(Finding(domain.name, CRITICAL, "ns_missing",
                                "No NS records returned for domain", {"observed": []}))
        return findings
    if observed != expected:
        # Could still be benign if both are .ns.cloudflare.com.; treat as WARN otherwise CRITICAL.
        all_cf = all(n.endswith(".ns.cloudflare.com.") for n in observed)
        sev = WARN if all_cf else CRITICAL
        findings.append(Finding(domain.name, sev, "ns_mismatch",
                                f"NS pair drifted from expected {sorted(expected)}",
                                {"expected": sorted(expected), "observed": sorted(observed)}))
    return findings


def _check_a_aaaa(domain: DomainConfig, snap: dict[str, Any], net: NetworkConfig) -> list[Finding]:
    findings: list[Finding] = []
    a = snap.get("A", [])
    aaaa = snap.get("AAAA", [])
    if not a and not aaaa:
        # No A/AAAA may be intentional (e.g. parked / email-only). Demote to INFO.
        findings.append(Finding(domain.name, INFO, "no_address",
                                "No A or AAAA records present", {}))
        return findings
    bad_a = [ip for ip in a if not net.ip_in_cf_range(ip)]
    bad_aaaa = [ip for ip in aaaa if not net.ip_in_cf_range(ip)]
    if bad_a:
        findings.append(Finding(domain.name, CRITICAL, "a_off_cf",
                                "A record points outside Cloudflare ranges",
                                {"observed": bad_a}))
    if bad_aaaa:
        findings.append(Finding(domain.name, CRITICAL, "aaaa_off_cf",
                                "AAAA record points outside Cloudflare ranges",
                                {"observed": bad_aaaa}))
    return findings


def _check_mx(domain: DomainConfig, snap: dict[str, Any]) -> list[Finding]:
    if not domain.require_null_mx:
        return []
    mx = snap.get("MX", [])
    null_mx_re = re.compile(r"^0\s+\.$")
    if not mx:
        return [Finding(domain.name, WARN, "mx_missing",
                        "No MX records — null MX expected", {})]
    if not all(null_mx_re.match(m) for m in mx):
        return [Finding(domain.name, WARN, "mx_not_null",
                        "MX is not the expected null MX (0 .)",
                        {"observed": mx})]
    return []


def _check_spf(domain: DomainConfig, snap: dict[str, Any]) -> list[Finding]:
    if not domain.require_spf:
        return []
    txt = snap.get("TXT", [])
    has_spf = any("v=spf1" in t for t in txt)
    if not has_spf:
        return [Finding(domain.name, WARN, "spf_missing",
                        "No SPF (v=spf1) TXT record", {"observed": txt})]
    return []


def _check_caa(domain: DomainConfig, snap: dict[str, Any]) -> list[Finding]:
    caa = snap.get("CAA", [])
    if not caa:
        return [Finding(domain.name, INFO, "caa_missing",
                        "No CAA records — anyone can issue certs", {})]
    return []


def _check_http(domain: DomainConfig, snap: dict[str, Any], net: NetworkConfig) -> list[Finding]:
    findings: list[Finding] = []
    http = snap.get("http", {})
    status = http.get("status")
    if http.get("error"):
        findings.append(Finding(domain.name, WARN, "http_error",
                                f"HTTPS probe error: {http['error']}", {}))
        return findings

    # Redirect target sanity — if Location is present, it should land on an expected host.
    loc = http.get("location") or ""
    if loc and net.expected_redirect_hosts:
        host_match = re.match(r"^https?://([^/]+)/?", loc)
        host = host_match.group(1).lower() if host_match else ""
        if host and host not in {h.lower() for h in net.expected_redirect_hosts}:
            findings.append(Finding(domain.name, WARN, "redirect_unexpected",
                                    f"Redirect target {host} not in expected list",
                                    {"location": loc,
                                     "expected_hosts": sorted(net.expected_redirect_hosts)}))

    # Phishing keywords on response body — high signal.
    flags = http.get("phishing_flags") or []
    if flags:
        findings.append(Finding(domain.name, CRITICAL, "phishing_keywords",
                                f"Phishing keywords detected on root: {flags}",
                                {"flags": flags, "url": http.get("url")}))

    # Server header — Cloudflare-fronted should usually report cloudflare.
    server = (http.get("server") or "").lower()
    if status and 200 <= status < 600 and server and "cloudflare" not in server:
        findings.append(Finding(domain.name, INFO, "server_not_cf",
                                f"Server header is not cloudflare: {server!r}", {}))

    # Status anomalies.
    if status in (502, 503, 522):
        findings.append(Finding(domain.name, WARN, "origin_unreachable",
                                f"HTTPS status {status} — origin likely unreachable", {}))
    return findings


def _check_tls(domain: DomainConfig, snap: dict[str, Any], net: NetworkConfig) -> list[Finding]:
    findings: list[Finding] = []
    tls = snap.get("tls_local", {})
    if tls.get("error"):
        findings.append(Finding(domain.name, INFO, "tls_local_error",
                                f"Local TLS probe error: {tls['error']}", {}))
        return findings
    if _is_warp_chain(tls, net):
        findings.append(Finding(domain.name, INFO, "tls_warp_intercept",
                                "Local TLS terminated by Cloudflare WARP Gateway CA — using crt.sh as source-of-truth",
                                {"issuer": tls.get("issuer")}))
        return findings
    issuer = tls.get("issuer")
    if net.expected_tls_issuer_tokens and not _issuer_matches_expected(issuer, net.expected_tls_issuer_tokens):
        findings.append(Finding(domain.name, WARN, "tls_issuer_unexpected",
                                f"TLS issuer not in expected set: {issuer!r}",
                                {"issuer": issuer,
                                 "expected_tokens": list(net.expected_tls_issuer_tokens)}))
    return findings


def _check_crtsh(domain: DomainConfig, snap: dict[str, Any], baseline: dict[str, Any] | None) -> list[Finding]:
    findings: list[Finding] = []
    cs = snap.get("crtsh", {}) or {}
    if cs.get("skipped"):
        return findings
    if cs.get("error"):
        findings.append(Finding(domain.name, INFO, "crtsh_error",
                                f"crt.sh query error: {cs['error']}", {}))
        return findings
    recent = cs.get("recent") or []
    today_count = cs.get("count_total", len(recent))
    base_count = None
    if baseline:
        base_cs = (baseline.get("crtsh") or {})
        base_count = base_cs.get("count_total")
    if base_count is not None and today_count > base_count:
        new_n = today_count - base_count
        # New issuance is INFO unless issuer is unusual.
        sev = INFO if new_n < 5 else WARN
        findings.append(Finding(domain.name, sev, "crtsh_new_issuance",
                                f"{new_n} new CT-log entries since baseline",
                                {"baseline_total": base_count, "now_total": today_count,
                                 "sample_recent": recent[:3]}))
    return findings


# ---------- Snapshot-vs-snapshot diff ----------

def _setdiff(name: str, before: list[str] | None, after: list[str] | None,
             severity_added: str = WARN, severity_removed: str = WARN) -> list[Finding]:
    before_s = set(before or [])
    after_s = set(after or [])
    findings: list[Finding] = []
    added = sorted(after_s - before_s)
    removed = sorted(before_s - after_s)
    if added:
        findings.append(Finding("", severity_added, f"{name}_added",
                                f"{name} added: {added}", {"added": added}))
    if removed:
        findings.append(Finding("", severity_removed, f"{name}_removed",
                                f"{name} removed: {removed}", {"removed": removed}))
    return findings


def diff_against_baseline(domain: DomainConfig, snap: dict[str, Any],
                          baseline: dict[str, Any] | None,
                          net: NetworkConfig) -> list[Finding]:
    """Run the full posture-and-drift diff for one domain."""
    findings: list[Finding] = []
    findings += _check_ns(domain, snap)
    findings += _check_a_aaaa(domain, snap, net)
    findings += _check_mx(domain, snap)
    findings += _check_spf(domain, snap)
    findings += _check_caa(domain, snap)
    findings += _check_http(domain, snap, net)
    findings += _check_tls(domain, snap, net)
    findings += _check_crtsh(domain, snap, baseline)

    # Drift checks (NS, A, AAAA, MX, TXT, CNAME) vs baseline
    if baseline:
        for rtype in ("NS", "A", "AAAA", "MX", "TXT", "CNAME", "CAA"):
            sev_add = WARN
            sev_rm = WARN
            if rtype == "NS":
                sev_add = sev_rm = CRITICAL
            elif rtype in ("A", "AAAA"):
                sev_add = sev_rm = WARN
            for f in _setdiff(rtype, baseline.get(rtype), snap.get(rtype),
                              severity_added=sev_add, severity_removed=sev_rm):
                f.domain = domain.name
                findings.append(f)
    return findings


def diff_all(config: Config, snapshot: dict[str, Any],
             baseline: dict[str, Any] | None) -> list[Finding]:
    out: list[Finding] = []
    base_domains = (baseline or {}).get("domains", {}) if baseline else {}
    for d in config.domains:
        snap_d = snapshot["domains"].get(d.name)
        if snap_d is None:
            out.append(Finding(d.name, WARN, "snapshot_missing",
                               "No snapshot data captured for this domain", {}))
            continue
        base_d = base_domains.get(d.name)
        out.extend(diff_against_baseline(d, snap_d, base_d, config.network))
    return out


def summarise(findings: list[Finding]) -> dict[str, int]:
    counts = {CRITICAL: 0, WARN: 0, INFO: 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
