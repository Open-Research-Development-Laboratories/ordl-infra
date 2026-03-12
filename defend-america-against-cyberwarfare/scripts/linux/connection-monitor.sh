#!/usr/bin/env bash
set -u

INTERVAL_SEC=2
HISTORY_POINTS=180
LOOP_COUNT=0
ANCHOR_URL="${DEFEND_ANCHOR_URL:-}"
ANCHOR_URLS="${DEFEND_ANCHOR_URLS:-}"
NODE_ID="${DEFEND_NODE_ID:-}"
ANCHOR_TOKEN="${DEFEND_ANCHOR_TOKEN:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output/live-dashboard"

usage() {
  echo "Usage: connection-monitor.sh [--interval-sec N] [--history-points N] [--loop-count N] [--output-dir DIR] [--anchor-url URL|URL1,URL2] [--node-id ID] [--anchor-token TOKEN]"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --interval-sec) shift; INTERVAL_SEC="${1:-2}" ;;
    --history-points) shift; HISTORY_POINTS="${1:-180}" ;;
    --loop-count) shift; LOOP_COUNT="${1:-0}" ;;
    --output-dir) shift; OUTPUT_DIR="${1:-$OUTPUT_DIR}" ;;
    --anchor-url) shift; ANCHOR_URL="${1:-$ANCHOR_URL}" ;;
    --anchor-urls) shift; ANCHOR_URLS="${1:-$ANCHOR_URLS}" ;;
    --node-id) shift; NODE_ID="${1:-$NODE_ID}" ;;
    --anchor-token) shift; ANCHOR_TOKEN="${1:-$ANCHOR_TOKEN}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

[ "$INTERVAL_SEC" -lt 1 ] 2>/dev/null && INTERVAL_SEC=1
[ "$HISTORY_POINTS" -lt 10 ] 2>/dev/null && HISTORY_POINTS=10
[ -z "$NODE_ID" ] && NODE_ID="$(hostname 2>/dev/null || echo "unknown-node")"
if [ -z "$ANCHOR_URLS" ] && [ -n "$ANCHOR_URL" ]; then
  ANCHOR_URLS="$ANCHOR_URL"
fi

if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
  OUTPUT_DIR="${HOME:-/tmp}/.defendmesh/output/live-dashboard"
  mkdir -p "$OUTPUT_DIR"
fi
DASHBOARD_HTML="$OUTPUT_DIR/dashboard.html"
LIVE_JSON="$OUTPUT_DIR/live.json"
MONITOR_LOG="$OUTPUT_DIR/monitor.log"
HISTORY_CSV="$OUTPUT_DIR/.history.csv"
LOCK_FILE="$OUTPUT_DIR/monitor.lock"
PID_FILE="$OUTPUT_DIR/monitor.pid"
: > "$HISTORY_CSV"

if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] monitor already running; skipping duplicate launch" | tee -a "$MONITOR_LOG"
    exit 0
  fi
else
  if [ -f "$PID_FILE" ]; then
    old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] monitor already running pid=$old_pid; skipping duplicate launch" | tee -a "$MONITOR_LOG"
      exit 0
    fi
  fi
fi

printf '%s\n' "$$" > "$PID_FILE"
cleanup_pid() { rm -f "$PID_FILE"; }
trap cleanup_pid EXIT INT TERM

get_connection_count() {
  if command -v ss >/dev/null 2>&1; then
    ss -nt 2>/dev/null | awk 'NR>1{c++} END{print c+0}'
    return
  fi
  if command -v netstat >/dev/null 2>&1; then
    if netstat -nt >/dev/null 2>&1; then
      netstat -nt 2>/dev/null | awk 'NR>2{c++} END{print c+0}'
      return
    fi
    if netstat -anp tcp >/dev/null 2>&1; then
      netstat -anp tcp 2>/dev/null | awk 'toupper($1)=="TCP"{c++} END{print c+0}'
      return
    fi
    return
  fi
  echo 0
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

anchor_url_items() {
  printf '%s' "$1" | tr ';' ',' | awk -F',' '{for(i=1;i<=NF;i++){gsub(/^[ \t]+|[ \t]+$/, "", $i); if($i!="") print $i}}'
}

send_anchor_heartbeat() {
  local presence="$1"
  local count="$2"
  local trend="$3"
  local updated_at="$4"
  local endpoint
  local node_id_json
  local trend_norm
  local presence_bool
  local payload
  local url
  node_id_json="$(json_escape "$NODE_ID")"
  case "$trend" in
    UP) trend_norm="up" ;;
    DOWN) trend_norm="down" ;;
    *) trend_norm="steady" ;;
  esac
  if [ "$presence" = "YES" ]; then
    presence_bool="true"
  else
    presence_bool="false"
  fi
  payload="$(printf '{"node_id":"%s","platform":"linux","connections_present":%s,"current_count":%s,"trend":"%s","updated_at":"%s"}' "$node_id_json" "$presence_bool" "$count" "$trend_norm" "$updated_at")"

  while IFS= read -r url; do
    [ -z "$url" ] && continue
    endpoint="${url%/}/api/v1/heartbeat"
    if command -v curl >/dev/null 2>&1; then
      if [ -n "$ANCHOR_TOKEN" ]; then
        curl -fsS -m 10 -X POST \
          -H 'Content-Type: application/json' \
          -H "Authorization: Bearer $ANCHOR_TOKEN" \
          -d "$payload" \
          "$endpoint" >/dev/null 2>&1 && return 0
      else
        curl -fsS -m 10 -X POST \
          -H 'Content-Type: application/json' \
          -d "$payload" \
          "$endpoint" >/dev/null 2>&1 && return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if [ -n "$ANCHOR_TOKEN" ]; then
        wget -q -O /dev/null --timeout=10 \
          --header='Content-Type: application/json' \
          --header="Authorization: Bearer $ANCHOR_TOKEN" \
          --post-data="$payload" \
          "$endpoint" >/dev/null 2>&1 && return 0
      else
        wget -q -O /dev/null --timeout=10 \
          --header='Content-Type: application/json' \
          --post-data="$payload" \
          "$endpoint" >/dev/null 2>&1 && return 0
      fi
    fi
  done < <(anchor_url_items "$ANCHOR_URLS")
  return 127
}

write_dashboard() {
  local current_count="$1"
  local trend="$2"
  local presence="$3"
  local trend_class="steady"
  local presence_class="no"
  [ "$trend" = "UP" ] && trend_class="up"
  [ "$trend" = "DOWN" ] && trend_class="down"
  [ "$presence" = "YES" ] && presence_class="yes"

  local rows
  rows="$(tail -n 25 "$HISTORY_CSV" | awk -F',' '{printf "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n",$1,$2,$3}')"

  cat > "$DASHBOARD_HTML" <<EOF_HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="$INTERVAL_SEC">
  <title>Live Connection Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin:20px; background:#0f172a; color:#e2e8f0; }
    .grid { display:grid; grid-template-columns: repeat(3,minmax(180px,1fr)); gap:12px; max-width:900px; }
    .card { background:#111827; border:1px solid #334155; border-radius:10px; padding:14px; }
    .label { color:#94a3b8; font-size:12px; }
    .value { font-size:30px; font-weight:700; margin-top:6px; }
    .yes{color:#22c55e;} .no{color:#f59e0b;} .up{color:#22c55e;} .down{color:#ef4444;} .steady{color:#38bdf8;}
    table { margin-top:18px; border-collapse:collapse; width:100%; max-width:900px; }
    th,td { border:1px solid #334155; padding:8px; font-size:12px; text-align:left; }
    th { color:#94a3b8; font-weight:600; }
  </style>
</head>
<body>
  <h2>Live Connection Dashboard</h2>
  <div class="grid">
    <div class="card"><div class="label">Connections Present</div><div class="value $presence_class">$presence</div></div>
    <div class="card"><div class="label">Current Count</div><div class="value">$current_count</div></div>
    <div class="card"><div class="label">Trend</div><div class="value $trend_class">$trend</div></div>
  </div>
  <table>
    <thead><tr><th>Timestamp</th><th>Count</th><th>Trend</th></tr></thead>
    <tbody>
      $rows
    </tbody>
  </table>
</body>
</html>
EOF_HTML
}

trim_history() {
  local total
  total="$(wc -l < "$HISTORY_CSV" | tr -d ' ')"
  if [ "$total" -gt "$HISTORY_POINTS" ] 2>/dev/null; then
    tail -n "$HISTORY_POINTS" "$HISTORY_CSV" > "$HISTORY_CSV.tmp" && mv "$HISTORY_CSV.tmp" "$HISTORY_CSV"
  fi
}

prev=-1
iter=0
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Live monitor started. Dashboard: $DASHBOARD_HTML"

while true; do
  iter=$((iter+1))
  count="$(get_connection_count)"
  trend="STEADY"
  if [ "$prev" -ge 0 ] 2>/dev/null; then
    if [ "$count" -gt "$prev" ] 2>/dev/null; then trend="UP"; fi
    if [ "$count" -lt "$prev" ] 2>/dev/null; then trend="DOWN"; fi
  fi
  prev="$count"

  presence="NO"
  if [ "$count" -gt 0 ] 2>/dev/null; then presence="YES"; fi

  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  updated_at_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '%s,%s,%s\n' "$ts" "$count" "$trend" >> "$HISTORY_CSV"
  trim_history

  if [ -n "$ANCHOR_URLS" ]; then
    send_anchor_heartbeat "$presence" "$count" "$trend" "$updated_at_utc"
    hb_rc=$?
    if [ "$hb_rc" -ne 0 ]; then
      echo "[$ts] anchor heartbeat failed (exit=$hb_rc)" >> "$MONITOR_LOG"
    fi
  fi

  cat > "$LIVE_JSON" <<EOF_JSON
{
  "updated_at": "$updated_at_utc",
  "interval_sec": $INTERVAL_SEC,
  "connections_present": "$presence",
  "current_count": $count,
  "trend": "$trend"
}
EOF_JSON

  write_dashboard "$count" "$trend" "$presence"

  line="[$ts] count=$count trend=$trend"
  echo "$line" | tee -a "$MONITOR_LOG"

  if [ "$LOOP_COUNT" -gt 0 ] && [ "$iter" -ge "$LOOP_COUNT" ]; then
    break
  fi
  sleep "$INTERVAL_SEC"
done

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Live monitor stopped."
