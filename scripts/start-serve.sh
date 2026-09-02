#!/bin/bash
# Start tanyao.serve against the device agent, detached, logging to /tmp/tanyao-serve.log
#
# Usage:
#   TANYAO_AGENT=<device-ip:port> TANYAO_TOKEN=<token> ./scripts/start-serve.sh
#
# TANYAO_AGENT and TANYAO_TOKEN are required from the environment — never hardcode
# your device address or token here (the token lives on-device at
# /data/local/tmp/.tanyao-token, 0600, and in the operator's env only).
set -e
cd "$(dirname "$0")/.."
: "${TANYAO_AGENT:?set TANYAO_AGENT=<device-ip:port>}"
: "${TANYAO_TOKEN:?set TANYAO_TOKEN=<agent token>}"
AGENT_HOST="${TANYAO_AGENT%%:*}"
AGENT_PORT="${TANYAO_AGENT##*:}"
setsid nohup python3 -m tanyao.serve --host "$AGENT_HOST" --port "$AGENT_PORT" \
  > /tmp/tanyao-serve.log 2>&1 < /dev/null &
echo "started, pid=$! (log: /tmp/tanyao-serve.log)"
