#!/bin/bash
# Start tanyao.serve against the device agent, detached, logging to /tmp/tanyao-serve.log
#
# Usage:
#   TANYAO_AGENT=<device-ip:port> TANYAO_TOKEN=<token> ./scripts/start-serve.sh
#   TANYAO_AGENT=127.0.0.1:52730 ...  → loopback target: adb forward is set up
#                                       automatically (idempotent) and the start
#                                       is gated on an end-to-end health check
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
IPC_PORT="${TANYAO_IPC_PORT:-28101}"

# D12: loopback targets ride an adb forward — pure transport, wire protocol
# untouched. Setting the forward is idempotent; re-running the script repairs
# a lost forward (the field failure mode: agent alive, device online, forward
# gone -> serve lived on reporting agent_unavailable forever).
TRANSPORT="direct-tcp"
case "$AGENT_HOST" in
  127.0.0.1|localhost|::1)
    TRANSPORT="adb-forward"
    if ! command -v adb >/dev/null 2>&1; then
      echo "WARN: TANYAO_AGENT is loopback but adb is not on PATH — assuming the forward already exists" >&2
    elif adb get-state >/dev/null 2>&1; then
      adb forward tcp:"$AGENT_PORT" tcp:"$AGENT_PORT" >/dev/null
      echo "adb forward tcp:$AGENT_PORT -> device:$AGENT_PORT (idempotent)"
    else
      echo "WARN: adb present but no device attached — forward not (re)set" >&2
    fi
    ;;
esac
export TANYAO_TRANSPORT="$TRANSPORT"

setsid nohup python3 -m tanyao.serve --host "$AGENT_HOST" --port "$AGENT_PORT" \
  > /tmp/tanyao-serve.log 2>&1 < /dev/null &
echo "started, pid=$! (log: /tmp/tanyao-serve.log)"

# D12: the start is only "ready" when the FULL chain is up (IPC -> serve ->
# agent), not merely when the process exists.
for _ in $(seq 1 30); do
  sleep 0.5
  body=$(curl -s -m 2 -X POST "http://127.0.0.1:${IPC_PORT}/" \
        -H "Content-Type: application/json" \
        -d '{"method":"get_status","params":{}}' 2>/dev/null || true)
  if printf '%s' "$body" | grep -q '"connected": *true'; then
    echo "ready: chain UP (transport=$TRANSPORT, agent=$TANYAO_AGENT)"
    exit 0
  fi
done

echo "NOT READY after 15s — remediation hints:" >&2
if command -v adb >/dev/null 2>&1 && adb get-state >/dev/null 2>&1; then
  if [ "$TRANSPORT" = "adb-forward" ] && ! adb forward --list 2>/dev/null | grep -q "tcp:${AGENT_PORT}"; then
    echo "  - adb forward missing: re-run this script (it sets 'adb forward tcp:${AGENT_PORT} tcp:${AGENT_PORT}')" >&2
  fi
  if ! timeout 2 bash -c "echo > /dev/tcp/${AGENT_HOST}/${AGENT_PORT}" 2>/dev/null; then
    echo "  - agent not listening on ${AGENT_HOST}:${AGENT_PORT}: start it on the device, e.g." >&2
    echo "    adb shell \"su -M -c 'setsid nohup /data/local/tmp/tanyao-agent --bind <ip> --port ${AGENT_PORT} --token-file /data/local/tmp/.tanyao-token >/dev/null 2>&1 &'\"" >&2
  elif [ "$TRANSPORT" = "adb-forward" ]; then
    echo "  - forward accepts locally but the tunnel dies: the device agent must also" >&2
    echo "    listen on device loopback (adb forward reaches 127.0.0.1 on the DEVICE only)." >&2
    echo "    Either start the agent with a loopback/0.0.0.0 bind, or use TANYAO_AGENT=<device-lan-ip:port> (direct-tcp)." >&2
  fi
else
  echo "  - device offline: check 'adb devices' / USB or network" >&2
fi
if grep -qi "auth" /tmp/tanyao-serve.log 2>/dev/null; then
  echo "  - auth problem in serve log: TANYAO_TOKEN must match the agent token file" >&2
fi
echo "  - full log: /tmp/tanyao-serve.log" >&2
exit 1
