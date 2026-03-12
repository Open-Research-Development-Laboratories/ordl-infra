#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ANCHOR_URL="${DEFEND_ANCHOR_URL:-https://defend.ordl.org}"
NODE_ID="${DEFEND_NODE_ID:-$(hostname 2>/dev/null || echo node-1)}"
ANCHOR_TOKEN="${DEFEND_ANCHOR_TOKEN:-}"
INTERVAL_SEC="${DEFEND_INTERVAL_SEC:-2}"
POLL_SEC="${DEFEND_POLL_SEC:-10}"
NO_OPEN=0

usage() {
  cat <<'USAGE'
Usage: linux-one-click.sh [options]

Options:
  --anchor-url URL      Anchor URL (default: https://defend.ordl.org)
  --node-id ID          Node identifier (default: hostname)
  --anchor-token TOKEN  Anchor node token (default: DEFEND_ANCHOR_TOKEN env)
  --interval-sec N      Monitor interval seconds (default: 2)
  --poll-sec N          Node-agent poll interval seconds (default: 10)
  --no-open             Do not auto-open browser
  -h, --help            Show help
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --anchor-url) shift; ANCHOR_URL="${1:-$ANCHOR_URL}" ;;
    --node-id) shift; NODE_ID="${1:-$NODE_ID}" ;;
    --anchor-token) shift; ANCHOR_TOKEN="${1:-$ANCHOR_TOKEN}" ;;
    --interval-sec) shift; INTERVAL_SEC="${1:-$INTERVAL_SEC}" ;;
    --poll-sec) shift; POLL_SEC="${1:-$POLL_SEC}" ;;
    --no-open) NO_OPEN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

ts="$(date +%Y%m%d-%H%M%S)"
ENDPOINT_OUT="$REPO_ROOT/output/oneclick-endpoint-$ts"
MONITOR_OUT="${DEFEND_MONITOR_OUTPUT_DIR:-${HOME:-/tmp}/.defendmesh/live-dashboard}"
AGENT_OUT="${DEFEND_AGENT_OUTPUT_DIR:-${HOME:-/tmp}/.defendmesh/node-agent}"
IOC_FILE="$REPO_ROOT/iocs/seed-iocs.txt"

mkdir -p "$MONITOR_OUT" "$AGENT_OUT"

echo "[1/4] Running endpoint audit..."
bash "$REPO_ROOT/scripts/linux/defend-host.sh" \
  --mode audit \
  --ioc-file "$IOC_FILE" \
  --output-dir "$ENDPOINT_OUT"

echo "[2/4] Stopping previous one-click monitor/agent if running..."
if [ -f "$MONITOR_OUT/.pid" ]; then
  kill "$(cat "$MONITOR_OUT/.pid")" 2>/dev/null || true
fi
if [ -f "$AGENT_OUT/.pid" ]; then
  kill "$(cat "$AGENT_OUT/.pid")" 2>/dev/null || true
fi

echo "[3/4] Starting live monitor..."
mon_cmd=(bash "$REPO_ROOT/scripts/linux/connection-monitor.sh"
  --interval-sec "$INTERVAL_SEC"
  --output-dir "$MONITOR_OUT"
  --anchor-url "$ANCHOR_URL"
  --node-id "$NODE_ID")
if [ -n "$ANCHOR_TOKEN" ]; then
  mon_cmd+=(--anchor-token "$ANCHOR_TOKEN")
fi
nohup "${mon_cmd[@]}" > "$MONITOR_OUT/oneclick-monitor.log" 2>&1 &
echo $! > "$MONITOR_OUT/.pid"

echo "[4/4] Starting node agent..."
agent_cmd=(bash "$REPO_ROOT/scripts/linux/node-agent.sh"
  --anchor-url "$ANCHOR_URL"
  --node-id "$NODE_ID"
  --poll-sec "$POLL_SEC"
  --output-dir "$AGENT_OUT")
if [ -n "$ANCHOR_TOKEN" ]; then
  agent_cmd+=(--anchor-token "$ANCHOR_TOKEN")
fi
nohup "${agent_cmd[@]}" > "$AGENT_OUT/oneclick-agent.log" 2>&1 &
echo $! > "$AGENT_OUT/.pid"

echo
echo "One-click defense is active."
echo "Anchor route: $ANCHOR_URL"
echo "Node id: $NODE_ID"
echo "Endpoint summary: $ENDPOINT_OUT/summary.json"
echo "Local dashboard: $MONITOR_OUT/dashboard.html"
echo "Monitor PID: $(cat "$MONITOR_OUT/.pid" 2>/dev/null || echo unknown)"
echo "Agent PID: $(cat "$AGENT_OUT/.pid" 2>/dev/null || echo unknown)"
if [ -z "$ANCHOR_TOKEN" ]; then
  echo "WARNING: no anchor token set; heartbeat/task auth may fail on protected anchor."
fi

if [ "$NO_OPEN" -eq 0 ]; then
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$ANCHOR_URL" >/dev/null 2>&1 || true
    xdg-open "$MONITOR_OUT/dashboard.html" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then
    open "$ANCHOR_URL" >/dev/null 2>&1 || true
    open "$MONITOR_OUT/dashboard.html" >/dev/null 2>&1 || true
  fi
fi
