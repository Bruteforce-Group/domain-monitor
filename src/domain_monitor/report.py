"""Render a Markdown report from a list of Findings."""
from __future__ import annotations

import datetime
from collections import defaultdict
from typing import Iterable

from .diff import CRITICAL, Finding, INFO, WARN

SEVERITY_ORDER = (CRITICAL, WARN, INFO)
SEVERITY_BADGE = {CRITICAL: "🚨", WARN: "⚠️ ", INFO: "ℹ️ "}


def render_markdown(findings: Iterable[Finding], *,
                    run_utc: str | None = None,
                    domains_total: int | None = None,
                    title: str = "Domain Monitor Report") -> str:
    findings = list(findings)
    by_sev: dict[str, list[Finding]] = defaultdict(list)
    by_domain: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_sev[f.severity].append(f)
        by_domain[f.domain].append(f)

    lines: list[str] = []
    when = run_utc or (datetime.datetime.utcnow().isoformat() + "Z")
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"_Run: {when}_")
    if domains_total is not None:
        lines.append(f"_Domains monitored: {domains_total}_")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in SEVERITY_ORDER:
        lines.append(f"| {SEVERITY_BADGE[sev].strip()} {sev} | {len(by_sev.get(sev, []))} |")
    lines.append("")

    if not findings:
        lines.append("_No findings._")
        return "\n".join(lines) + "\n"

    # Top section: critical findings (cross-domain)
    crit = by_sev.get(CRITICAL, [])
    if crit:
        lines.append("## 🚨 Critical")
        lines.append("")
        for f in crit:
            lines.append(f"- **{f.domain}** — `{f.code}` — {f.message}")
        lines.append("")

    # Per-domain detail
    lines.append("## Per-domain detail")
    lines.append("")
    for domain in sorted(by_domain):
        domain_findings = by_domain[domain]
        sev_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in domain_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        head_bits = [f"{SEVERITY_BADGE[s].strip()}{sev_counts[s]}" for s in SEVERITY_ORDER if sev_counts[s]]
        head = "  ".join(head_bits) if head_bits else "clean"
        lines.append(f"### {domain or '(global)'} — {head}")
        for f in sorted(domain_findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
            lines.append(f"- {SEVERITY_BADGE[f.severity]}**{f.severity}** `{f.code}` — {f.message}")
        lines.append("")
    return "\n".join(lines) + "\n"
