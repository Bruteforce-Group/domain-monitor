#!/usr/bin/env bash
# Daily defensive monitor — wired up for cron on Boz's Mac (or any host with python3.10+).
#
# Recommended cron:
#   0 7 * * * /Users/boz/code/domain-monitor/scripts/run_daily.sh
#
# Sends a Slack/email pager only on CRITICAL via --fail-on-critical.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${OUT:-runs}"
CONFIG="${CONFIG:-domains.yaml}"
BASELINE="${BASELINE:-baseline.json}"

python -m domain_monitor run \
    --config "$CONFIG" \
    --baseline "$BASELINE" \
    --out "$OUT" \
    --fail-on-critical
