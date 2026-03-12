#!/usr/bin/env bash
set -u

ANCHOR_URL="${DEFEND_ANCHOR_URL:-https://defend.ordl.org}"
NODE_ID="${DEFEND_NODE_ID:-$(hostname 2>/dev/null || echo node-linux)}"
ANCHOR_TOKEN="${DEFEND_ANCHOR_TOKEN:-}"
INTERVAL_SEC=5
LOOP_COUNT=0
ONESHOT=0

usage() {
  cat <<'EOF'
Usage: self-node-monitor.sh [--anchor-url URL] [--node-id ID] [--anchor-token TOKEN] [--interval-sec N] [--loop-count N] [--once]

Checks ONLY your node status from anchor:
- registered (seen by anchor)
- queued_tasks (if node is being tasked)
- token_registered (anchor has token for this node)
- last update / latency / trend / count

If no token is supplied, script attempts self-enroll once.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --anchor-url) shift; ANCHOR_URL="${1:-$ANCHOR_URL}" ;;
    --node-id) shift; NODE_ID="${1:-$NODE_ID}" ;;
    --anchor-token) shift; ANCHOR_TOKEN="${1:-$ANCHOR_TOKEN}" ;;
    --interval-sec) shift; INTERVAL_SEC="${1:-5}" ;;
    --loop-count) shift; LOOP_COUNT="${1:-0}" ;;
    --once) ONESHOT=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

[ "$INTERVAL_SEC" -lt 1 ] 2>/dev/null && INTERVAL_SEC=1
[ "$ONESHOT" -eq 1 ] && LOOP_COUNT=1

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

json_extract() {
  # Minimal JSON scalar extractor: json_extract "$json" "key"
  local json="$1"
  local key="$2"
  local val
  val="$(printf '%s' "$json" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n1)"
  if [ -n "$val" ]; then
    printf '%s' "$val"
    return 0
  fi
  val="$(printf '%s' "$json" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" | head -n1)"
  if [ -n "$val" ]; then
    printf '%s' "$val"
    return 0
  fi
  val="$(printf '%s' "$json" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\(true\\|false\\).*/\\1/p" | head -n1)"
  if [ -n "$val" ]; then
    printf '%s' "$val"
    return 0
  fi
  printf ''
}

enroll_if_needed() {
  [ -n "$ANCHOR_TOKEN" ] && return 0
  local payload resp token
  payload="$(printf '{"node_id":"%s","platform":"linux"}' "$NODE_ID")"
  resp="$(curl -fsS -m 10 -X POST -H 'Content-Type: application/json' -d "$payload" "${ANCHOR_URL%/}/api/v1/node/enroll" 2>/dev/null || true)"
  token="$(json_extract "$resp" "token")"
  if [ -n "$token" ]; then
    ANCHOR_TOKEN="$token"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] token acquired via enroll for node_id=$NODE_ID"
  fi
}

get_status() {
  local url
  url="${ANCHOR_URL%/}/api/v1/node/status?node_id=$NODE_ID"
  if [ -n "$ANCHOR_TOKEN" ]; then
    curl -fsS -m 10 -H "Authorization: Bearer $ANCHOR_TOKEN" "$url"
  else
    curl -fsS -m 10 "$url"
  fi
}

enroll_if_needed

i=0
while true; do
  i=$((i+1))
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  status_json="$(get_status 2>/dev/null || true)"
  if [ -z "$status_json" ]; then
    echo "[$ts] status=unreachable anchor=${ANCHOR_URL%/} node_id=$NODE_ID"
  else
    registered="$(json_extract "$status_json" "registered")"
    queued="$(json_extract "$status_json" "queued_tasks")"
    token_reg="$(json_extract "$status_json" "token_registered")"
    updated="$(json_extract "$status_json" "updated_at")"
    latency="$(json_extract "$status_json" "latency_ms")"
    trend="$(json_extract "$status_json" "trend")"
    count="$(json_extract "$status_json" "current_count")"
    severity="$(json_extract "$status_json" "latest_severity")"
    printf '[%s] node=%s registered=%s token_registered=%s queued=%s count=%s trend=%s latency_ms=%s severity=%s updated_at=%s\n' \
      "$ts" "$NODE_ID" "${registered:-?}" "${token_reg:-?}" "${queued:-?}" "${count:-?}" "${trend:-?}" "${latency:-?}" "${severity:-?}" "${updated:--}"
  fi

  if [ "$LOOP_COUNT" -gt 0 ] && [ "$i" -ge "$LOOP_COUNT" ]; then
    break
  fi
  sleep "$INTERVAL_SEC"
done
