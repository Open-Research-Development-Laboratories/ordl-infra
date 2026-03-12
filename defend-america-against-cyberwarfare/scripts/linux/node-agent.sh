#!/usr/bin/env bash
set -u

ANCHOR_URL="${DEFEND_ANCHOR_URL:-}"
ANCHOR_URLS="${DEFEND_ANCHOR_URLS:-}"
NODE_ID="${DEFEND_NODE_ID:-}"
ANCHOR_TOKEN="${DEFEND_ANCHOR_TOKEN:-}"
POLL_SEC=10
PROFILE_EVERY_SEC="${DEFEND_PROFILE_EVERY_SEC:-600}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${DEFEND_OUTPUT_DIR:-${HOME:-/tmp}/.defendmesh/node-agent}"

usage() {
  echo "Usage: node-agent.sh --anchor-url URL|URL1,URL2 [--node-id ID] [--anchor-token TOKEN] [--poll-sec N] [--profile-every-sec N] [--output-dir DIR]"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --anchor-url) shift; ANCHOR_URL="${1:-$ANCHOR_URL}" ;;
    --anchor-urls) shift; ANCHOR_URLS="${1:-$ANCHOR_URLS}" ;;
    --node-id) shift; NODE_ID="${1:-$NODE_ID}" ;;
    --anchor-token) shift; ANCHOR_TOKEN="${1:-$ANCHOR_TOKEN}" ;;
    --poll-sec) shift; POLL_SEC="${1:-10}" ;;
    --profile-every-sec) shift; PROFILE_EVERY_SEC="${1:-$PROFILE_EVERY_SEC}" ;;
    --output-dir) shift; OUTPUT_DIR="${1:-$OUTPUT_DIR}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

if [ -z "$ANCHOR_URL" ]; then
  ANCHOR_URL="$ANCHOR_URLS"
fi
if [ -z "$ANCHOR_URLS" ] && [ -n "$ANCHOR_URL" ]; then
  ANCHOR_URLS="$ANCHOR_URL"
fi
if [ -z "$ANCHOR_URLS" ]; then
  echo "--anchor-url required" >&2
  exit 1
fi
[ -z "$NODE_ID" ] && NODE_ID="$(hostname 2>/dev/null || echo node-linux)"
[ "$POLL_SEC" -lt 2 ] 2>/dev/null && POLL_SEC=2
[ "$PROFILE_EVERY_SEC" -lt 30 ] 2>/dev/null && PROFILE_EVERY_SEC=30

mkdir -p "$OUTPUT_DIR" "$OUTPUT_DIR/patches"
LOG_FILE="$OUTPUT_DIR/node-agent.log"
LAST_PROFILE_EPOCH=0

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g'
}

anchor_url_items() {
  printf '%s' "$ANCHOR_URLS" | tr ';' ',' | awk -F',' '{for(i=1;i<=NF;i++){gsub(/^[ \t]+|[ \t]+$/, "", $i); if($i!="") print $i}}'
}

anchor_post_json() {
  local path="$1"
  local body="$2"
  local url
  while IFS= read -r base; do
    [ -z "$base" ] && continue
    url="${base%/}${path}"

    if command -v curl >/dev/null 2>&1; then
      if [ -n "$ANCHOR_TOKEN" ]; then
        curl -fsS -m 20 -X POST "$url" -H 'Content-Type: application/json' -H "Authorization: Bearer $ANCHOR_TOKEN" -d "$body" >/dev/null 2>&1 && return 0
      else
        curl -fsS -m 20 -X POST "$url" -H 'Content-Type: application/json' -d "$body" >/dev/null 2>&1 && return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if [ -n "$ANCHOR_TOKEN" ]; then
        wget -q -O /dev/null --timeout=20 --header='Content-Type: application/json' --header="Authorization: Bearer $ANCHOR_TOKEN" --post-data="$body" "$url" >/dev/null 2>&1 && return 0
      else
        wget -q -O /dev/null --timeout=20 --header='Content-Type: application/json' --post-data="$body" "$url" >/dev/null 2>&1 && return 0
      fi
    fi
  done < <(anchor_url_items)

  return 1
}

anchor_get_file() {
  local path="$1"
  local out="$2"
  local url
  while IFS= read -r base; do
    [ -z "$base" ] && continue
    url="${base%/}${path}"

    if command -v curl >/dev/null 2>&1; then
      if [ -n "$ANCHOR_TOKEN" ]; then
        curl -fsS -m 20 "$url" -H "Authorization: Bearer $ANCHOR_TOKEN" -o "$out" && return 0
      else
        curl -fsS -m 20 "$url" -o "$out" && return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if [ -n "$ANCHOR_TOKEN" ]; then
        wget -q -O "$out" --timeout=20 --header="Authorization: Bearer $ANCHOR_TOKEN" "$url" && return 0
      else
        wget -q -O "$out" --timeout=20 "$url" && return 0
      fi
    fi
  done < <(anchor_url_items)

  return 1
}

log_local() {
  local msg="$1"
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts] $msg" | tee -a "$LOG_FILE"
}

send_node_log() {
  local level="$1"
  local msg="$2"
  local payload
  payload="{\"node_id\":\"$(json_escape "$NODE_ID")\",\"level\":\"$(json_escape "$level")\",\"message\":\"$(json_escape "$msg")\"}"
  anchor_post_json "/api/v1/node/log" "$payload" || true
}

send_task_result() {
  local task_id="$1"
  local status="$2"
  local output="$3"
  local payload
  payload="{\"node_id\":\"$(json_escape "$NODE_ID")\",\"task_id\":\"$(json_escape "$task_id")\",\"status\":\"$(json_escape "$status")\",\"output\":\"$(json_escape "$output")\"}"
  anchor_post_json "/api/v1/node/task-result" "$payload" || true
}

send_node_profile() {
  local host user os_name os_build arch kernel updated_at payload
  host="$(hostname 2>/dev/null || echo unknown-host)"
  user="$(id -un 2>/dev/null || echo unknown-user)"
  os_name="$(uname -s 2>/dev/null || echo unknown-os)"
  os_build=""
  if [ -f /etc/os-release ]; then
    os_name="$(awk -F= '/^NAME=/{gsub(/"/, "", $2); print $2; exit}' /etc/os-release 2>/dev/null || echo "$os_name")"
    os_build="$(awk -F= '/^VERSION=/{gsub(/"/, "", $2); print $2; exit}' /etc/os-release 2>/dev/null || echo "")"
  fi
  arch="$(uname -m 2>/dev/null || echo unknown-arch)"
  kernel="$(uname -r 2>/dev/null || echo unknown-kernel)"
  updated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  payload="{\"node_id\":\"$(json_escape "$NODE_ID")\",\"updated_at\":\"$(json_escape "$updated_at")\",\"profile\":{\"client_host\":\"$(json_escape "$host")\",\"client_user\":\"$(json_escape "$user")\",\"client_os\":\"$(json_escape "$os_name")\",\"client_build\":\"$(json_escape "$os_build")\",\"client_arch\":\"$(json_escape "$arch")\",\"client_kernel\":\"$(json_escape "$kernel")\"}}"
  anchor_post_json "/api/v1/node/profile" "$payload" || true
}

maybe_send_node_profile() {
  local now
  now="$(date +%s)"
  if [ "$LAST_PROFILE_EPOCH" -eq 0 ] || [ $((now - LAST_PROFILE_EPOCH)) -ge "$PROFILE_EVERY_SEC" ]; then
    send_node_profile
    LAST_PROFILE_EPOCH="$now"
  fi
}

show_operator_notice() {
  local msg="$1"
  [ -z "$msg" ] && msg="DefendMesh operator notice"
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" >> "$OUTPUT_DIR/operator-notice.log"
  if command -v notify-send >/dev/null 2>&1; then
    notify-send "DefendMesh Notice" "$msg" >/dev/null 2>&1 || true
  fi
  if command -v wall >/dev/null 2>&1; then
    printf '%s\n' "$msg" | wall >/dev/null 2>&1 || true
  fi
  if command -v logger >/dev/null 2>&1; then
    logger -t defendmesh-notice "$msg" >/dev/null 2>&1 || true
  fi
}

fetch_tasks() {
  local out="$1"
  anchor_get_file "/api/v1/node/tasks?node_id=$NODE_ID" "$out"
}

exec_task() {
  local task_id="$1"
  local playbook="$2"
  local args_json="$3"
  local status="ok"
  local output=""
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"

  case "$playbook" in
    endpoint_audit)
      if bash "$SCRIPT_DIR/defend-host.sh" --mode audit --ioc-file "$REPO_ROOT/iocs/seed-iocs.txt" --output-dir "$REPO_ROOT/output/node-endpoint-audit-$ts" >/tmp/node-agent-endpoint.log 2>&1; then
        output="endpoint_audit done"
      else
        status="error"; output="endpoint_audit failed"
      fi
      ;;
    endpoint_remediate)
      if bash "$SCRIPT_DIR/defend-host.sh" --mode remediate --ioc-file "$REPO_ROOT/iocs/seed-iocs.txt" --output-dir "$REPO_ROOT/output/node-endpoint-remediate-$ts" >/tmp/node-agent-endpoint.log 2>&1; then
        output="endpoint_remediate done"
      else
        status="error"; output="endpoint_remediate failed"
      fi
      ;;
    monitor_start)
      interval=$(python3 - <<PY
import json
obj=json.loads('''$args_json''') if '''$args_json'''.strip() else {}
print(int(obj.get('interval_sec',2)))
PY
)
      nohup bash "$SCRIPT_DIR/connection-monitor.sh" --interval-sec "$interval" --output-dir "$REPO_ROOT/output/live-dashboard" --anchor-url "$ANCHOR_URL" --node-id "$NODE_ID" --anchor-token "$ANCHOR_TOKEN" >/tmp/node-monitor.log 2>&1 &
      echo $! > "$REPO_ROOT/output/live-dashboard/.pid"
      output="monitor_start pid=$(cat "$REPO_ROOT/output/live-dashboard/.pid" 2>/dev/null || echo unknown)"
      ;;
    monitor_stop)
      if [ -f "$REPO_ROOT/output/live-dashboard/.pid" ]; then
        kill "$(cat "$REPO_ROOT/output/live-dashboard/.pid")" 2>/dev/null || true
      fi
      pkill -f "connection-monitor.sh --interval-sec" 2>/dev/null || true
      output="monitor_stop done"
      ;;
    monitor_oneshot)
      loops=$(python3 - <<PY
import json
obj=json.loads('''$args_json''') if '''$args_json'''.strip() else {}
print(int(obj.get('loop_count',5)))
PY
)
      interval=$(python3 - <<PY
import json
obj=json.loads('''$args_json''') if '''$args_json'''.strip() else {}
print(int(obj.get('interval_sec',2)))
PY
)
      if bash "$SCRIPT_DIR/connection-monitor.sh" --interval-sec "$interval" --loop-count "$loops" --output-dir "$REPO_ROOT/output/live-dashboard" --anchor-url "$ANCHOR_URL" --node-id "$NODE_ID" --anchor-token "$ANCHOR_TOKEN" >/tmp/node-monitor-oneshot.log 2>&1; then
        output="monitor_oneshot done"
      else
        status="error"; output="monitor_oneshot failed"
      fi
      ;;
    stage_patch)
      patch_id=$(python3 - <<PY
import json
obj=json.loads('''$args_json''') if '''$args_json'''.strip() else {}
print(obj.get('patch_id',''))
PY
)
      if [ -z "$patch_id" ]; then
        status="error"; output="stage_patch missing patch_id"
      else
        tmp_json="$(mktemp)"
        if anchor_get_file "/api/v1/node/patch/$patch_id" "$tmp_json"; then
          pyout=$(python3 - <<PY
import base64,hashlib,json,os,sys
path='$tmp_json'
outdir='$OUTPUT_DIR/patches'
obj=json.load(open(path))
fname=os.path.basename(obj.get('filename','patch.bin')) or 'patch.bin'
raw=base64.b64decode(obj.get('content_b64',''))
sha=obj.get('sha256','')
calc=hashlib.sha256(raw).hexdigest()
os.makedirs(outdir,exist_ok=True)
out=os.path.join(outdir,fname)
open(out,'wb').write(raw)
print(out)
print(calc)
print(sha)
PY
)
          saved_path=$(printf '%s' "$pyout" | sed -n '1p')
          calc_sha=$(printf '%s' "$pyout" | sed -n '2p')
          ref_sha=$(printf '%s' "$pyout" | sed -n '3p')
          if [ -n "$ref_sha" ] && [ "$calc_sha" != "$ref_sha" ]; then
            status="error"; output="patch sha mismatch"
          else
            output="patch staged at $saved_path"
            show_operator_notice "DefendMesh patch staged on $NODE_ID: $saved_path"
          fi
        else
          status="error"; output="failed to fetch patch"
        fi
        rm -f "$tmp_json"
      fi
      ;;
    operator_notice)
      notice_msg=$(python3 - <<PY
import json
obj=json.loads('''$args_json''') if '''$args_json'''.strip() else {}
msg=str(obj.get('message','DefendMesh operator notice')).strip()
print(msg[:300] if msg else 'DefendMesh operator notice')
PY
)
      show_operator_notice "$notice_msg"
      output="operator_notice shown: $notice_msg"
      ;;
    *)
      status="error"; output="unsupported playbook: $playbook"
      ;;
  esac

  send_task_result "$task_id" "$status" "$output"
  send_node_log "info" "task=$task_id playbook=$playbook status=$status"
  log_local "task=$task_id playbook=$playbook status=$status"
}

log_local "node-agent start node_id=$NODE_ID anchors=$ANCHOR_URLS"
send_node_log "info" "node-agent started"
maybe_send_node_profile

while true; do
  maybe_send_node_profile
  tasks_file="$(mktemp)"
  if fetch_tasks "$tasks_file"; then
    python3 - <<PY > "$tasks_file.items"
import base64,json,sys
obj=json.load(open('$tasks_file'))
for t in obj.get('tasks',[]):
  tid=t.get('task_id','')
  pb=t.get('playbook','')
  args=t.get('args',{})
  b=base64.b64encode(json.dumps(args,separators=(',',':')).encode()).decode()
  print(f"{tid}\t{pb}\t{b}")
PY
    while IFS=$'\t' read -r task_id playbook args_b64; do
      [ -z "$task_id" ] && continue
      args_json="$(printf '%s' "$args_b64" | base64 -d 2>/dev/null || echo '{}')"
      exec_task "$task_id" "$playbook" "$args_json"
    done < "$tasks_file.items"
  else
    log_local "task fetch failed"
    send_node_log "warn" "task fetch failed"
  fi

  rm -f "$tasks_file" "$tasks_file.items"
  sleep "$POLL_SEC"
done
