"""Config loader tests."""
from __future__ import annotations

import ipaddress

from domain_monitor import config as config_mod


def test_load_returns_full_config(domains_yaml_path):
    cfg = config_mod.load(domains_yaml_path)
    assert len(cfg.domains) == 2
    assert cfg.domain_names == ("example.test", "noemail.test")


def test_network_ranges_parsed(cfg):
    assert ipaddress.IPv4Network("104.16.0.0/13") in cfg.network.cf_ipv4_ranges
    assert ipaddress.IPv6Network("2606:4700::/32") in cfg.network.cf_ipv6_ranges


def test_ip_in_cf_range_true_for_known_cf(cfg):
    assert cfg.network.ip_in_cf_range("104.21.1.1") is True
    assert cfg.network.ip_in_cf_range("2606:4700::1") is True


def test_ip_in_cf_range_false_for_external(cfg):
    assert cfg.network.ip_in_cf_range("8.8.8.8") is False
    assert cfg.network.ip_in_cf_range("not-an-ip") is False


def test_expected_ns_fqdn_built_from_pair(cfg):
    d = cfg.domain("example.test")
    assert d is not None
    assert d.expected_ns_fqdn == frozenset(
        {"alpha.ns.cloudflare.com.", "beta.ns.cloudflare.com."}
    )


def test_domain_lookup_unknown_returns_none(cfg):
    assert cfg.domain("does-not-exist.test") is None


def test_per_domain_overrides(cfg):
    d = cfg.domain("noemail.test")
    assert d is not None
    assert d.require_spf is False
    assert d.require_null_mx is False
