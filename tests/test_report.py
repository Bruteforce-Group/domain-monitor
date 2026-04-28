"""Markdown report rendering tests."""
from __future__ import annotations

from domain_monitor.diff import CRITICAL, Finding, INFO, WARN
from domain_monitor.report import render_markdown


def test_empty_findings_renders_no_findings():
    md = render_markdown([], domains_total=10)
    assert "Domain Monitor Report" in md
    assert "Domains monitored: 10" in md
    assert "No findings" in md


def test_critical_section_appears_when_critical_present():
    findings = [
        Finding("a.test", CRITICAL, "ns_mismatch", "NS bad"),
        Finding("a.test", WARN, "spf_missing", "no spf"),
    ]
    md = render_markdown(findings)
    assert "## 🚨 Critical" in md
    assert "ns_mismatch" in md
    # WARN finding shouldn't appear in the critical section
    crit_section = md.split("## 🚨 Critical", 1)[1].split("##", 1)[0]
    assert "spf_missing" not in crit_section


def test_per_domain_section_groups_findings():
    findings = [
        Finding("a.test", CRITICAL, "x", "msg"),
        Finding("b.test", WARN, "y", "msg"),
        Finding("a.test", INFO, "z", "msg"),
    ]
    md = render_markdown(findings)
    assert "### a.test" in md
    assert "### b.test" in md


def test_summary_table_counts_severities():
    findings = [
        Finding("a.test", CRITICAL, "x", "msg"),
        Finding("a.test", CRITICAL, "x", "msg"),
        Finding("a.test", WARN, "y", "msg"),
        Finding("a.test", INFO, "z", "msg"),
    ]
    md = render_markdown(findings)
    summary = md.split("## Summary", 1)[1].split("##", 1)[0]
    assert "CRITICAL | 2" in summary
    assert "WARN | 1" in summary
    assert "INFO | 1" in summary


def test_run_utc_in_report():
    md = render_markdown([], run_utc="2026-04-28T07:00:00Z")
    assert "2026-04-28T07:00:00Z" in md
