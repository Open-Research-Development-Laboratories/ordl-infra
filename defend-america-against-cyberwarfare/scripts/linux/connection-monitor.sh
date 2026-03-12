#!/usr/bin/env bash
set -u

INTERVAL_SEC=2
HISTORY_POINTS=180
LOOP_COUNT=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output/live-dashboard"

usage() {
  echo "Usage: connection-monitor.sh [--interval-sec N] [--history-points N] [--loop-count N] [--output-dir DIR]"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --interval-sec) shift; INTERVAL_SEC="${1:-2}" ;;
    --history-points) shift; HISTORY_POINTS="${1:-180}" ;;
    --loop-count) shift; LOOP_COUNT="${1:-0}" ;;
    --output-dir) shift; OUTPUT_DIR="${1:-$OUTPUT_DIR}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

[ "$INTERVAL_SEC" -lt 1 ] 2>/dev/null && INTERVAL_SEC=1
[ "$HISTORY_POINTS" -lt 10 ] 2>/dev/null && HISTORY_POINTS=10

mkdir -p "$OUTPUT_DIR"
DASHBOARD_HTML="$OUTPUT_DIR/dashboard.html"
LIVE_JSON="$OUTPUT_DIR/live.json"
MONITOR_LOG="$OUTPUT_DIR/monitor.log"
HISTORY_CSV="$OUTPUT_DIR/.history.csv"
: > "$HISTORY_CSV"

get_connection_count() {
  if command -v ss >/dev/null 2>&1; then
    ss -nt 2>/dev/null | awk 'NR>1{c++} END{print c+0}'
    return
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -nt 2>/dev/null | awk 'NR>2{c++} END{print c+0}'
    return
  fi
  echo 0
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
  printf '%s,%s,%s\n' "$ts" "$count" "$trend" >> "$HISTORY_CSV"
  trim_history

  cat > "$LIVE_JSON" <<EOF_JSON
{
  "updated_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
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
