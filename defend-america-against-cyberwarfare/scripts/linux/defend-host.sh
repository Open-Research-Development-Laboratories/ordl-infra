#!/usr/bin/env bash
set -u

MODE="audit"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output/defend-host-$(date +%Y%m%d-%H%M%S)"
IOC_FILE="$REPO_ROOT/iocs/seed-iocs.txt"
CONTROL_FILE="$REPO_ROOT/control/mode-control.txt"
EXPECTED_CONTROL_TOKEN="${DEFEND_CONTROL_TOKEN:-}"
BROADCAST_ALERT=0

usage() {
  cat <<'USAGE'
Usage: defend-host.sh [--mode audit|remediate] [--output-dir DIR] [--ioc-file FILE] [--control-file FILE] [--expected-control-token TOKEN] [--broadcast-alert]
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mode)
      shift; MODE="${1:-audit}" ;;
    --output-dir)
      shift; OUTPUT_DIR="${1:-$OUTPUT_DIR}" ;;
    --ioc-file)
      shift; IOC_FILE="${1:-$IOC_FILE}" ;;
    --control-file)
      shift; CONTROL_FILE="${1:-$CONTROL_FILE}" ;;
    --expected-control-token)
      shift; EXPECTED_CONTROL_TOKEN="${1:-}" ;;
    --broadcast-alert)
      BROADCAST_ALERT=1 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

if [ "$MODE" != "audit" ] && [ "$MODE" != "remediate" ]; then
  echo "Invalid mode: $MODE" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR" "$REPO_ROOT/control"
AWARENESS_LOG="$OUTPUT_DIR/awareness.log"
STAGE_LOG="$OUTPUT_DIR/stages.log"
SUMMARY_JSON="$OUTPUT_DIR/summary.json"
REPORT_TXT="$OUTPUT_DIR/report.txt"
DASHBOARD_HTML="$OUTPUT_DIR/dashboard.html"
CONN_RAW="$OUTPUT_DIR/connections.txt"
PROC_RAW="$OUTPUT_DIR/processes.txt"
MATCHED_PIDS="$OUTPUT_DIR/.matched-pids.txt"
MATCHED_PATHS="$OUTPUT_DIR/.matched-paths.txt"
MATCHED_IPS="$OUTPUT_DIR/.matched-ips.txt"
QUARANTINE_DIR="$OUTPUT_DIR/quarantine"
mkdir -p "$QUARANTINE_DIR"
: > "$MATCHED_PIDS"
: > "$MATCHED_PATHS"
: > "$MATCHED_IPS"

stage() {
  local line
  line="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo "$line"
  echo "$line" >> "$STAGE_LOG"
}

awareness() {
  local level="$1"
  shift
  local msg="$*"
  local line
  line="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg"
  echo "$line"
  echo "$line" >> "$AWARENESS_LOG"
  if command -v logger >/dev/null 2>&1; then
    logger -t defend-host "[$level] $msg" || true
  fi
  if [ "$BROADCAST_ALERT" -eq 1 ] && command -v wall >/dev/null 2>&1; then
    printf '%s\n' "$msg" | wall >/dev/null 2>&1 || true
  fi
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g'
}

requested_mode="$MODE"
control_source="cli"
if [ -f "$CONTROL_FILE" ]; then
  stage "Loading control file"
  cf_mode=""
  cf_token=""
  while IFS= read -r line || [ -n "$line" ]; do
    line="$(printf '%s' "$line" | sed 's/^\s*//;s/\s*$//')"
    [ -z "$line" ] && continue
    case "$line" in \#*) continue;; esac
    key="$(printf '%s' "$line" | sed -E 's/[:=].*$//' | tr '[:upper:]' '[:lower:]' | sed 's/\s//g')"
    val="$(printf '%s' "$line" | sed -E 's/^[^:=]+[:=]\s*//')"
    case "$key" in
      mode) cf_mode="$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')" ;;
      token) cf_token="$val" ;;
    esac
  done < "$CONTROL_FILE"

  if [ "$cf_mode" = "audit" ] || [ "$cf_mode" = "remediate" ]; then
    token_ok=1
    if [ -n "$EXPECTED_CONTROL_TOKEN" ] && [ "$cf_token" != "$EXPECTED_CONTROL_TOKEN" ]; then
      token_ok=0
    fi
    if [ "$token_ok" -eq 1 ]; then
      MODE="$cf_mode"
      control_source="control-file"
    else
      MODE="audit"
      control_source="control-file-invalid-token"
      awareness WARN "Control file token invalid; forcing audit mode."
    fi
  fi
fi

awareness INFO "DefendHost run started. requested_mode=$requested_mode effective_mode=$MODE source=$control_source"
if [ "$MODE" = "remediate" ]; then
  awareness ALERT "Remediation mode is ACTIVE on this host."
fi

stage "Collecting connection status"
connection_count=0
if command -v ss >/dev/null 2>&1; then
  ss -nt 2>/dev/null > "$CONN_RAW" || true
  connection_count="$(awk 'NR>1{c++} END{print c+0}' "$CONN_RAW" 2>/dev/null)"
elif command -v netstat >/dev/null 2>&1; then
  netstat -nt 2>/dev/null > "$CONN_RAW" || true
  connection_count="$(awk 'NR>2{c++} END{print c+0}' "$CONN_RAW" 2>/dev/null)"
else
  echo "No ss/netstat available" > "$CONN_RAW"
  connection_count=0
fi
connections_present="NO"
if [ "${connection_count:-0}" -gt 0 ] 2>/dev/null; then
  connections_present="YES"
fi

stage "Collecting process inventory"
if command -v ps >/dev/null 2>&1; then
  ps -eo pid=,comm=,args= > "$PROC_RAW" 2>/dev/null || true
else
  : > "$PROC_RAW"
fi
process_count="$(wc -l < "$PROC_RAW" 2>/dev/null | tr -d ' ' )"
process_count="${process_count:-0}"

stage "Loading IOC file"
ioc_names_file="$OUTPUT_DIR/.ioc-names.txt"
ioc_paths_file="$OUTPUT_DIR/.ioc-paths.txt"
ioc_ips_file="$OUTPUT_DIR/.ioc-ips.txt"
: > "$ioc_names_file"
: > "$ioc_paths_file"
: > "$ioc_ips_file"
if [ -f "$IOC_FILE" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    line="$(printf '%s' "$line" | sed 's/^\s*//;s/\s*$//')"
    [ -z "$line" ] && continue
    case "$line" in \#*) continue;; esac
    key="$(printf '%s' "$line" | sed -E 's/:.*$//' | tr '[:upper:]' '[:lower:]')"
    val="$(printf '%s' "$line" | sed -E 's/^[^:]+:\s*//')"
    [ -z "$val" ] && continue
    case "$key" in
      name) printf '%s\n' "$val" >> "$ioc_names_file" ;;
      path) printf '%s\n' "$val" >> "$ioc_paths_file" ;;
      ip) printf '%s\n' "$val" >> "$ioc_ips_file" ;;
    esac
  done < "$IOC_FILE"
fi

stage "Matching IOC indicators"
while IFS= read -r n || [ -n "$n" ]; do
  [ -z "$n" ] && continue
  awk -v needle="$n" 'BEGIN{IGNORECASE=1} index($0, needle)>0 {print $1}' "$PROC_RAW" 2>/dev/null >> "$MATCHED_PIDS" || true
done < "$ioc_names_file"

while IFS= read -r p || [ -n "$p" ]; do
  [ -z "$p" ] && continue
  if [ -e "$p" ]; then
    printf '%s\n' "$p" >> "$MATCHED_PATHS"
  fi
done < "$ioc_paths_file"

while IFS= read -r ip || [ -n "$ip" ]; do
  [ -z "$ip" ] && continue
  if grep -Fq "$ip" "$CONN_RAW" 2>/dev/null; then
    printf '%s\n' "$ip" >> "$MATCHED_IPS"
  fi
done < "$ioc_ips_file"

sort -u "$MATCHED_PIDS" -o "$MATCHED_PIDS" 2>/dev/null || true
sort -u "$MATCHED_PATHS" -o "$MATCHED_PATHS" 2>/dev/null || true
sort -u "$MATCHED_IPS" -o "$MATCHED_IPS" 2>/dev/null || true

matched_pid_count="$(wc -l < "$MATCHED_PIDS" 2>/dev/null | tr -d ' ')"; matched_pid_count="${matched_pid_count:-0}"
matched_path_count="$(wc -l < "$MATCHED_PATHS" 2>/dev/null | tr -d ' ')"; matched_path_count="${matched_path_count:-0}"
matched_ip_count="$(wc -l < "$MATCHED_IPS" 2>/dev/null | tr -d ' ')"; matched_ip_count="${matched_ip_count:-0}"

remediation_actions=0
if [ "$MODE" = "remediate" ]; then
  stage "Remediation: stopping matched processes"
  while IFS= read -r pid || [ -n "$pid" ]; do
    [ -z "$pid" ] && continue
    if kill -0 "$pid" 2>/dev/null; then
      if kill -TERM "$pid" 2>/dev/null; then remediation_actions=$((remediation_actions+1)); fi
    fi
  done < "$MATCHED_PIDS"

  stage "Remediation: quarantining matched files"
  while IFS= read -r fp || [ -n "$fp" ]; do
    [ -z "$fp" ] && continue
    if [ -f "$fp" ]; then
      qdest="$QUARANTINE_DIR/$(date +%s)_$(basename "$fp")"
      if mv "$fp" "$qdest" 2>/dev/null; then remediation_actions=$((remediation_actions+1)); fi
    fi
  done < "$MATCHED_PATHS"

  stage "Remediation: blocking IOC IPs"
  while IFS= read -r ip || [ -n "$ip" ]; do
    [ -z "$ip" ] && continue
    if command -v nft >/dev/null 2>&1; then
      nft add table inet defend_host >/dev/null 2>&1 || true
      nft list chain inet defend_host output >/dev/null 2>&1 || nft add chain inet defend_host output '{ type filter hook output priority 0; policy accept; }' >/dev/null 2>&1 || true
      if nft add rule inet defend_host output ip daddr "$ip" drop >/dev/null 2>&1; then remediation_actions=$((remediation_actions+1)); fi
    elif command -v iptables >/dev/null 2>&1; then
      if iptables -C OUTPUT -d "$ip" -j DROP >/dev/null 2>&1 || iptables -I OUTPUT -d "$ip" -j DROP >/dev/null 2>&1; then remediation_actions=$((remediation_actions+1)); fi
    fi
  done < "$MATCHED_IPS"
fi

stage "Writing dashboard"
cat > "$DASHBOARD_HTML" <<EOF_HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Defend Host Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background:#0f172a; color:#e2e8f0; }
    .card { max-width: 520px; padding: 20px; border-radius: 12px; background:#111827; border:1px solid #334155; }
    .label { color:#94a3b8; font-size:13px; }
    .value { font-size:40px; font-weight:700; margin:8px 0 4px 0; }
    .yes { color:#22c55e; }
    .no { color:#f59e0b; }
    .meta { margin-top:14px; color:#94a3b8; font-size:12px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="label">Active Connections Present</div>
    <div class="value $( [ "$connections_present" = "YES" ] && echo yes || echo no )">$connections_present</div>
    <div class="meta">Mode: $MODE</div>
    <div class="meta">Updated: $(date '+%Y-%m-%d %H:%M:%S')</div>
  </div>
</body>
</html>
EOF_HTML

stage "Writing summary"
cat > "$SUMMARY_JSON" <<EOF_JSON
{
  "mode": "$(json_escape "$MODE")",
  "requested_mode": "$(json_escape "$requested_mode")",
  "control_source": "$(json_escape "$control_source")",
  "started_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "output_dir": "$(json_escape "$OUTPUT_DIR")",
  "ioc_file": "$(json_escape "$IOC_FILE")",
  "control_file": "$(json_escape "$CONTROL_FILE")",
  "dashboard": "$(json_escape "$DASHBOARD_HTML")",
  "counts": {
    "network_connections": ${connection_count:-0},
    "processes": ${process_count:-0},
    "matched_pids": ${matched_pid_count:-0},
    "matched_paths": ${matched_path_count:-0},
    "matched_ips": ${matched_ip_count:-0},
    "remediation_actions": ${remediation_actions:-0}
  },
  "connections_present": "$(json_escape "$connections_present")"
}
EOF_JSON

cat > "$REPORT_TXT" <<EOF_REPORT
Mode: $MODE
RequestedMode: $requested_mode
ControlSource: $control_source
OutputDir: $OUTPUT_DIR
Dashboard: $DASHBOARD_HTML
Summary: $SUMMARY_JSON
ConnectionsPresent: $connections_present
EOF_REPORT

awareness INFO "DefendHost run completed. mode=$MODE connections_present=$connections_present"
stage "Done. Summary: $SUMMARY_JSON"
