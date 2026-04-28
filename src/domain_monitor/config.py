"""domains.yaml loader.

domains.yaml schema:

    network:
      cf_ipv4_ranges: ["104.16.0.0/13", "172.64.0.0/13"]
      cf_ipv6_ranges: ["2606:4700::/32"]
      expected_redirect_hosts: ["wp.bozza.au"]
      expected_tls_issuer_tokens: ["Let's Encrypt", "Google Trust Services"]
      warp_intercept_ca_fingerprint: "dac01715f027bf360c500dce1d805d94"

    domains:
      - name: eflux.com.au
        ns_pair: [jarred, jasmine]
        account: "Bruteforce Group Account"
        require_spf: true
        require_null_mx: true
        notes: "Intermittent 522 from origin"
"""
from __future__ import annotations

import dataclasses
import ipaddress
from pathlib import Path
from typing import Any

import yaml


@dataclasses.dataclass(frozen=True)
class NetworkConfig:
    cf_ipv4_ranges: tuple[ipaddress.IPv4Network, ...]
    cf_ipv6_ranges: tuple[ipaddress.IPv6Network, ...]
    expected_redirect_hosts: frozenset[str]
    expected_tls_issuer_tokens: tuple[str, ...]
    warp_intercept_ca_fingerprint: str | None

    def ip_in_cf_range(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv4Address):
            return any(ip in r for r in self.cf_ipv4_ranges)
        return any(ip in r for r in self.cf_ipv6_ranges)


@dataclasses.dataclass(frozen=True)
class DomainConfig:
    name: str
    ns_pair: tuple[str, ...]
    account: str
    require_spf: bool = True
    require_null_mx: bool = True
    notes: str = ""

    @property
    def expected_ns_fqdn(self) -> frozenset[str]:
        return frozenset(f"{p}.ns.cloudflare.com." for p in self.ns_pair)


@dataclasses.dataclass(frozen=True)
class Config:
    network: NetworkConfig
    domains: tuple[DomainConfig, ...]

    @property
    def domain_names(self) -> tuple[str, ...]:
        return tuple(d.name for d in self.domains)

    def domain(self, name: str) -> DomainConfig | None:
        for d in self.domains:
            if d.name == name:
                return d
        return None


def load(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text())
    return _from_dict(raw)


def _from_dict(raw: dict[str, Any]) -> Config:
    net = raw.get("network", {})
    network = NetworkConfig(
        cf_ipv4_ranges=tuple(ipaddress.ip_network(r) for r in net.get("cf_ipv4_ranges", [])),
        cf_ipv6_ranges=tuple(ipaddress.ip_network(r) for r in net.get("cf_ipv6_ranges", [])),
        expected_redirect_hosts=frozenset(net.get("expected_redirect_hosts", [])),
        expected_tls_issuer_tokens=tuple(net.get("expected_tls_issuer_tokens", [])),
        warp_intercept_ca_fingerprint=net.get("warp_intercept_ca_fingerprint"),
    )
    domains = tuple(
        DomainConfig(
            name=d["name"],
            ns_pair=tuple(d["ns_pair"]),
            account=d.get("account", ""),
            require_spf=d.get("require_spf", True),
            require_null_mx=d.get("require_null_mx", True),
            notes=d.get("notes", ""),
        )
        for d in raw.get("domains", [])
    )
    return Config(network=network, domains=domains)
