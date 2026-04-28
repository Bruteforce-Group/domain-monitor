"""Capture today's DNS / HTTP / TLS / CT-log state for a domain.

WARP-aware design: the local TLS chain is captured for forensic completeness
but not trusted as the issuance source-of-truth, because Cloudflare Zero-Trust
WARP intercepts outbound TLS and re-signs with `Gateway CA - Cloudflare
Managed G1` regardless of the real edge cert. crt.sh (public CT logs) is the
authoritative issuance source.
"""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from typing import Any

PHISHING_TERMS = (
    "verify your account",
    "password reset",
    "wallet connect",
    "metamask",
    "trust wallet",
    "ledger live",
    "seed phrase",
    "private key",
    "connect your wallet",
)


def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:  # pragma: no cover  (defensive)
        return "", str(e), -1


# ---------- DNS ----------

def dig(domain: str, rtype: str, resolver: str = "1.1.1.1") -> list[str]:
    out, _, _ = _run(["dig", "+short", domain, rtype, f"@{resolver}"])
    return sorted(l.strip() for l in out.splitlines() if l.strip())


def dig_soa(domain: str, resolver: str = "1.1.1.1") -> str:
    out, _, _ = _run(["dig", "+short", domain, "SOA", f"@{resolver}"])
    return out.strip()


# ---------- HTTP ----------

def http_probe(domain: str, follow_redirects: bool = False) -> dict[str, Any]:
    """Probe https://<domain>/.

    By default does NOT follow redirects — captures the first response's
    Location header instead. This avoids false-positives in environments where
    the redirect target (e.g. wp.bozza.au) is unreachable due to split-DNS.
    """
    res: dict[str, Any] = {
        "url": f"https://{domain}/",
        "status": None,
        "remote_ip": None,
        "server": None,
        "location": None,
        "content_type": None,
        "body_sha256": None,
        "body_len": 0,
        "phishing_flags": [],
        "error": None,
    }
    flag = "-sSL" if follow_redirects else "-sSi"
    fmt = "STATUS=%{http_code}\nIP=%{remote_ip}\nCT=%{content_type}\nFINAL=%{url_effective}\n"
    out, err, rc = _run(
        [
            "curl",
            flag,
            "-A",
            "domain-monitor/0.1",
            "-o",
            "/dev/null",
            "-w",
            fmt,
            "--max-time",
            "20",
            "-D",
            "-",
            f"https://{domain}/",
        ],
        timeout=25,
    )
    if rc != 0:
        res["error"] = err or f"curl rc={rc}"
        return res

    # The -D - prints headers to stdout; -w trailers to stdout too.
    # Split off the -w trailer block.
    trailer_keys = ("STATUS=", "IP=", "CT=", "FINAL=")
    body_lines: list[str] = []
    trailer: dict[str, str] = {}
    for line in out.splitlines():
        if any(line.startswith(k) for k in trailer_keys):
            k, v = line.split("=", 1)
            trailer[k] = v
        else:
            body_lines.append(line)

    if "STATUS" in trailer:
        try:
            res["status"] = int(trailer["STATUS"])
        except ValueError:
            res["status"] = trailer["STATUS"]
    res["remote_ip"] = trailer.get("IP") or None
    res["content_type"] = trailer.get("CT") or None

    # Parse headers (response chain may have multiple HTTP/X blocks)
    for line in body_lines:
        ll = line.lower()
        if ll.startswith("server:"):
            res["server"] = line.split(":", 1)[1].strip()
        elif ll.startswith("location:") and not res["location"]:
            res["location"] = line.split(":", 1)[1].strip()

    # Body hash (separate fetch so headers don't pollute)
    body, _, _ = _run(
        ["curl", "-sS", "-A", "domain-monitor/0.1", "--max-time", "20", f"https://{domain}/"],
        timeout=25,
    )
    res["body_sha256"] = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    res["body_len"] = len(body)
    low = body.lower()
    res["phishing_flags"] = [t for t in PHISHING_TERMS if t in low]
    return res


# ---------- TLS (local socket — informational only under WARP) ----------

def tls_local(domain: str) -> dict[str, Any]:
    res: dict[str, Any] = {
        "subject": None,
        "issuer": None,
        "san": [],
        "not_before": None,
        "not_after": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(der)
            tmp = tf.name
        out, _, _ = _run(
            ["openssl", "x509", "-inform", "DER", "-in", tmp, "-noout", "-subject", "-issuer", "-dates"],
            timeout=10,
        )
        for line in out.splitlines():
            if line.startswith("subject="):
                res["subject"] = line[len("subject="):].strip()
            elif line.startswith("issuer="):
                res["issuer"] = line[len("issuer="):].strip()
            elif line.startswith("notBefore="):
                res["not_before"] = line[len("notBefore="):].strip()
            elif line.startswith("notAfter="):
                res["not_after"] = line[len("notAfter="):].strip()
        san_out, _, _ = _run(
            ["openssl", "x509", "-inform", "DER", "-in", tmp, "-noout", "-ext", "subjectAltName"],
            timeout=10,
        )
        sans: list[str] = []
        for line in san_out.splitlines():
            if "DNS:" in line:
                for tok in line.split(","):
                    tok = tok.strip()
                    if tok.startswith("DNS:"):
                        sans.append(tok[4:])
        res["san"] = sorted(set(sans))
    except Exception as e:
        res["error"] = str(e)
    return res


# ---------- crt.sh (CT log — issuance source-of-truth) ----------

def crtsh(domain: str, timeout: int = 20) -> dict[str, Any]:
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "domain-monitor/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        return {"error": str(e), "count_total": 0, "recent": []}
    data.sort(key=lambda d: d.get("entry_timestamp") or "", reverse=True)
    slim = [
        {
            "id": d.get("id"),
            "name_value": d.get("name_value"),
            "issuer_name": d.get("issuer_name"),
            "not_before": d.get("not_before"),
            "not_after": d.get("not_after"),
            "entry_timestamp": d.get("entry_timestamp"),
        }
        for d in data[:50]
    ]
    return {"count_total": len(data), "recent": slim}


# ---------- Snapshot orchestration ----------

@dataclasses.dataclass
class Snapshot:
    run_utc: str
    domains: dict[str, dict[str, Any]]

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), indent=2, default=str, sort_keys=True)


def snapshot_domain(domain: str, *, include_crtsh: bool = True) -> dict[str, Any]:
    s: dict[str, Any] = {"domain": domain}
    s["NS"] = dig(domain, "NS")
    s["A"] = dig(domain, "A")
    s["AAAA"] = dig(domain, "AAAA")
    s["MX"] = dig(domain, "MX")
    s["TXT"] = dig(domain, "TXT")
    s["CAA"] = dig(domain, "CAA")
    s["CNAME"] = dig(domain, "CNAME")
    s["SOA"] = dig_soa(domain)
    s["http"] = http_probe(domain)
    s["tls_local"] = tls_local(domain)
    if include_crtsh:
        s["crtsh"] = crtsh(domain)
    else:
        s["crtsh"] = {"skipped": True}
    return s


def snapshot_all(domains: list[str], *, include_crtsh: bool = True) -> Snapshot:
    return Snapshot(
        run_utc=datetime.datetime.utcnow().isoformat() + "Z",
        domains={d: snapshot_domain(d, include_crtsh=include_crtsh) for d in domains},
    )
