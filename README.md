# domain-monitor

Daily defensive monitor for the **30 zones** Bruteforce Group hosts on Cloudflare.
Captures DNS / HTTP / TLS / CT-log state, diffs against a curated baseline, and
emits a Markdown report with severity-classified findings.

Built to run unattended on a Mac or CI host that lives behind Cloudflare
Zero-Trust WARP — see [WARP awareness](#warp-awareness) below.

## What it checks

| Check | Severity if broken |
|---|---|
| NS records match the assigned Cloudflare pair | **CRITICAL** off-CF / **WARN** different CF pair |
| A / AAAA inside Cloudflare published edge ranges | **CRITICAL** |
| MX is null (`0 .`) where required | **WARN** |
| SPF (`v=spf1`) present where required | **WARN** |
| CAA record present | **INFO** |
| HTTPS root reachable, server header is cloudflare | **WARN/INFO** |
| Redirect Location stays within expected hosts | **WARN** |
| Phishing keywords on response body (seed phrase, metamask, etc.) | **CRITICAL** |
| TLS chain (informational under WARP) | **INFO/WARN** |
| crt.sh issuance count vs baseline (issuance source-of-truth) | **INFO/WARN** |

## Layout

```
domain-monitor/
├── domains.yaml             # canonical zone list (30 zones; jarred/jasmine + carter/nadia pairs)
├── baseline.json            # curated baseline (regenerated on demand)
├── pyproject.toml
├── src/domain_monitor/
│   ├── __main__.py          # CLI: snapshot | baseline | diff | run
│   ├── config.py            # YAML loader + frozen dataclasses
│   ├── snapshot.py          # WARP-aware DNS/HTTP/TLS/crt.sh capture
│   ├── diff.py              # severity classification + drift detection
│   ├── baseline.py          # baseline I/O
│   └── report.py            # Markdown rendering
├── tests/                   # pytest, mocked network, 52 tests / 93% cov
└── scripts/run_daily.sh     # cron-ready wrapper
```

## Quickstart

```bash
pip install -e .[dev]

# 1. (Re)generate the baseline once — run this when posture is known-good.
python -m domain_monitor baseline --config domains.yaml --out baseline.json

# 2. Daily run — snapshot + diff + report; exit 2 on any CRITICAL.
python -m domain_monitor run \
    --config domains.yaml \
    --baseline baseline.json \
    --out runs/ \
    --fail-on-critical
```

The `run` subcommand drops two artefacts per day:

- `runs/snapshots/YYYY-MM-DD.json` — full capture for forensic replay
- `runs/diffs/YYYY-MM-DD.md` — human-readable diff report

## WARP awareness

Cloudflare Zero-Trust WARP transparently terminates outbound TLS and re-signs
with `Gateway CA - Cloudflare Managed G1` (md5 fingerprint
`dac01715f027bf360c500dce1d805d94`). That means **the local TLS chain is not
trustworthy** as the issuance source-of-truth — every cert will look like it
came from Cloudflare, even when the real edge cert is Let's Encrypt or GTS.

Two design consequences:

1. **crt.sh (public CT logs) is the issuance source-of-truth.** The diff
   compares CT-log counts against baseline and surfaces new issuance.
2. **HTTP probes don't follow redirects** — they capture the `Location` header
   directly. This avoids false negatives in environments where the redirect
   target (e.g. `wp.bozza.au`) isn't resolvable behind split-DNS.

When the local TLS chain matches the WARP CA, the issuer-mismatch check is
**downgraded to INFO** and explicitly attributed to WARP. If you run this on
a host that's *not* behind WARP, the same check fires at WARN against
unexpected issuers — which is what you want.

## Cron

```cron
0 7 * * * /Users/boz/code/domain-monitor/scripts/run_daily.sh \
    >> /Users/boz/code/domain-monitor/runs/cron.log 2>&1
```

Pair with a Slack/email alert on non-zero exit, or pipe the latest
`runs/diffs/*.md` to whatever pager you prefer.

## Testing

```bash
pytest -m "not network"          # offline tests (default)
pytest                           # everything; some hit dig/curl/crt.sh
pytest --cov=domain_monitor      # with coverage
```

The `network` marker is reserved for tests that touch real DNS / HTTP / crt.sh
— skip them in CI unless you have outbound network and a cooperative
environment.
