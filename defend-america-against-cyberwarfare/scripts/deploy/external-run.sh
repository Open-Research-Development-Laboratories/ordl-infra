#!/usr/bin/env bash
set -euo pipefail

HOST=""
USER_NAME=""
TARGET_OS=""
MODE="audit"
MONITOR_MODE="start"
INTERVAL_SEC=2
LOOP_COUNT=0
PASSWORD_ENV="DEFEND_SSH_PASSWORD"
ANCHOR_URL=""
ANCHOR_TOKEN_ENV="DEFEND_ANCHOR_TOKEN"
NODE_ID=""
RUN_ENDPOINT=1
RUN_MONITOR=1
SYNC_PACKAGE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SSH_BIN="ssh"
SCP_BIN="scp"
SSH_OPTS=(-T -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)

usage() {
  cat <<'USAGE'
Usage: external-run.sh --host HOST --user USER --os windows|linux [options]

Options:
  --mode audit|remediate          Endpoint mode (default: audit)
  --monitor start|oneshot|stop|off  Monitor action (default: start)
  --interval-sec N                Monitor interval seconds (default: 2)
  --loop-count N                  Loop count for oneshot monitor (default: 0)
  --password-env VAR              Env var holding SSH password (default: DEFEND_SSH_PASSWORD)
  --anchor-url URL                DefendMesh anchor base URL (optional)
  --anchor-token-env VAR          Env var holding anchor node token (default: DEFEND_ANCHOR_TOKEN)
  --node-id ID                    Override node id sent to anchor
  --no-sync                       Skip package upload/sync
  --monitor-only                  Skip endpoint run
  --endpoint-only                 Skip monitor run
  -h, --help                      Show help

Examples:
  DEFEND_SSH_PASSWORD=1234 ./external-run.sh --host 10.0.0.254 --user winsock --os windows --mode audit --monitor start
  DEFEND_SSH_PASSWORD=secret DEFEND_ANCHOR_TOKEN=token ./external-run.sh --host 203.0.113.20 --user ubuntu --os linux --mode audit --monitor start --anchor-url https://defend.ordl.org --node-id laptop-1
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --host) shift; HOST="${1:-}" ;;
    --user) shift; USER_NAME="${1:-}" ;;
    --os) shift; TARGET_OS="${1:-}" ;;
    --mode) shift; MODE="${1:-}" ;;
    --monitor) shift; MONITOR_MODE="${1:-}" ;;
    --interval-sec) shift; INTERVAL_SEC="${1:-2}" ;;
    --loop-count) shift; LOOP_COUNT="${1:-0}" ;;
    --password-env) shift; PASSWORD_ENV="${1:-DEFEND_SSH_PASSWORD}" ;;
    --anchor-url) shift; ANCHOR_URL="${1:-}" ;;
    --anchor-token-env) shift; ANCHOR_TOKEN_ENV="${1:-DEFEND_ANCHOR_TOKEN}" ;;
    --node-id) shift; NODE_ID="${1:-}" ;;
    --no-sync) SYNC_PACKAGE=0 ;;
    --monitor-only) RUN_ENDPOINT=0 ;;
    --endpoint-only) RUN_MONITOR=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

if [ -z "$HOST" ] || [ -z "$USER_NAME" ] || [ -z "$TARGET_OS" ]; then
  echo "Missing required args --host/--user/--os" >&2
  usage >&2
  exit 1
fi

TARGET_OS="$(printf '%s' "$TARGET_OS" | tr '[:upper:]' '[:lower:]')"
if [ "$TARGET_OS" != "windows" ] && [ "$TARGET_OS" != "linux" ]; then
  echo "--os must be windows or linux" >&2
  exit 1
fi
if [ "$MODE" != "audit" ] && [ "$MODE" != "remediate" ]; then
  echo "--mode must be audit or remediate" >&2
  exit 1
fi
case "$MONITOR_MODE" in
  start|oneshot|stop|off) ;;
  *) echo "--monitor must be start|oneshot|stop|off" >&2; exit 1 ;;
esac

SSH_PASSWORD="${!PASSWORD_ENV:-}"
ANCHOR_TOKEN="${!ANCHOR_TOKEN_ENV:-}"

run_ssh() {
  local cmd="$1"
  if [ -n "$SSH_PASSWORD" ]; then
    SSHPASS="$SSH_PASSWORD" sshpass -e "$SSH_BIN" "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "$cmd"
  else
    "$SSH_BIN" "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "$cmd"
  fi
}

run_scp_dir() {
  local src_dir="$1"
  local dst="$2"
  if [ -n "$SSH_PASSWORD" ]; then
    SSHPASS="$SSH_PASSWORD" sshpass -e "$SCP_BIN" -r -o StrictHostKeyChecking=accept-new "$src_dir"/* "$USER_NAME@$HOST:$dst"
  else
    "$SCP_BIN" -r -o StrictHostKeyChecking=accept-new "$src_dir"/* "$USER_NAME@$HOST:$dst"
  fi
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

if [ "$TARGET_OS" = "windows" ]; then
  REMOTE_NATIVE="C:\\Users\\$USER_NAME\\defend-external"
  REMOTE_SCP="/C:/Users/$USER_NAME/defend-external"

  if [ "$SYNC_PACKAGE" -eq 1 ]; then
    log "Syncing package to windows target $HOST"
    run_ssh "cmd /c \"if exist $REMOTE_NATIVE rmdir /s /q $REMOTE_NATIVE & mkdir $REMOTE_NATIVE\""
    run_scp_dir "$PKG_DIR" "$REMOTE_SCP/"
  fi

  if [ "$RUN_ENDPOINT" -eq 1 ]; then
    log "Running windows endpoint script mode=$MODE"
    run_ssh "powershell -NoProfile -ExecutionPolicy Bypass -File $REMOTE_NATIVE\\scripts\\windows\\defend-endpoint.ps1 -Mode $MODE -IocFile $REMOTE_NATIVE\\iocs\\seed-iocs.txt -OutputDir $REMOTE_NATIVE\\output\\external-endpoint-$MODE"
  fi

  if [ "$RUN_MONITOR" -eq 1 ]; then
    WIN_MON_CMD="powershell -NoProfile -ExecutionPolicy Bypass -File $REMOTE_NATIVE\\scripts\\windows\\connection-monitor.ps1 -IntervalSec $INTERVAL_SEC -OutputDir $REMOTE_NATIVE\\output\\live-dashboard-external"
    if [ -n "$ANCHOR_URL" ]; then
      WIN_MON_CMD="$WIN_MON_CMD -AnchorUrl $ANCHOR_URL"
    fi
    if [ -n "$NODE_ID" ]; then
      WIN_MON_CMD="$WIN_MON_CMD -NodeId $NODE_ID"
    fi
    if [ -n "$ANCHOR_TOKEN" ]; then
      WIN_MON_CMD="$WIN_MON_CMD -AnchorToken $ANCHOR_TOKEN"
    fi

    case "$MONITOR_MODE" in
      start)
        log "Starting persistent windows monitor"
        run_ssh "cmd /c \"schtasks /Delete /TN DefendLiveDashboard /F >nul 2>nul & schtasks /Create /TN DefendLiveDashboard /TR \"$WIN_MON_CMD\" /SC ONCE /ST 00:00 /F & schtasks /Run /TN DefendLiveDashboard\""
        ;;
      oneshot)
        log "Running oneshot windows monitor loops=$LOOP_COUNT"
        run_ssh "$WIN_MON_CMD -LoopCount $LOOP_COUNT"
        ;;
      stop)
        log "Stopping windows monitor task"
        run_ssh "cmd /c \"schtasks /End /TN DefendLiveDashboard >nul 2>nul & schtasks /Delete /TN DefendLiveDashboard /F >nul 2>nul\""
        ;;
      off)
        ;;
    esac
  fi

  log "Verifying windows artifacts"
  run_ssh "powershell -NoProfile -Command \"Write-Output ('DASH=' + (Test-Path '$REMOTE_NATIVE\\output\\live-dashboard-external\\dashboard.html')); Write-Output ('LIVE=' + (Test-Path '$REMOTE_NATIVE\\output\\live-dashboard-external\\live.json')); Write-Output ('ENDPOINT=' + (Test-Path '$REMOTE_NATIVE\\output\\external-endpoint-$MODE\\summary.json')); if(Test-Path '$REMOTE_NATIVE\\output\\live-dashboard-external\\live.json'){ \$j=Get-Content -Raw '$REMOTE_NATIVE\\output\\live-dashboard-external\\live.json' | ConvertFrom-Json; Write-Output ('UPDATED=' + \$j.updated_at); Write-Output ('COUNT=' + \$j.current_count); Write-Output ('TREND=' + \$j.trend); }\""

  log "Windows dashboard: $REMOTE_NATIVE\\output\\live-dashboard-external\\dashboard.html"
  exit 0
fi

# linux target
REMOTE_LINUX="~/defend-external"

if [ "$SYNC_PACKAGE" -eq 1 ]; then
  log "Syncing package to linux target $HOST"
  run_ssh "rm -rf $REMOTE_LINUX && mkdir -p $REMOTE_LINUX"
  run_scp_dir "$PKG_DIR" "$REMOTE_LINUX/"
fi

if [ "$RUN_ENDPOINT" -eq 1 ]; then
  log "Running linux endpoint script mode=$MODE"
  run_ssh "bash $REMOTE_LINUX/scripts/linux/defend-host.sh --mode $MODE --ioc-file $REMOTE_LINUX/iocs/seed-iocs.txt --output-dir $REMOTE_LINUX/output/external-endpoint-$MODE"
fi

if [ "$RUN_MONITOR" -eq 1 ]; then
  LIN_MON_CMD="bash $REMOTE_LINUX/scripts/linux/connection-monitor.sh --interval-sec $INTERVAL_SEC --output-dir $REMOTE_LINUX/output/live-dashboard-external"
  if [ -n "$ANCHOR_URL" ]; then
    LIN_MON_CMD="$LIN_MON_CMD --anchor-url $ANCHOR_URL"
  fi
  if [ -n "$NODE_ID" ]; then
    LIN_MON_CMD="$LIN_MON_CMD --node-id $NODE_ID"
  fi
  if [ -n "$ANCHOR_TOKEN" ]; then
    LIN_MON_CMD="$LIN_MON_CMD --anchor-token $ANCHOR_TOKEN"
  fi

  case "$MONITOR_MODE" in
    start)
      log "Starting persistent linux monitor"
      run_ssh "mkdir -p $REMOTE_LINUX/output/live-dashboard-external && nohup $LIN_MON_CMD >/tmp/defend-live-monitor.log 2>&1 & echo \$! > $REMOTE_LINUX/output/live-dashboard-external/.pid"
      ;;
    oneshot)
      log "Running oneshot linux monitor loops=$LOOP_COUNT"
      run_ssh "$LIN_MON_CMD --loop-count $LOOP_COUNT"
      ;;
    stop)
      log "Stopping linux monitor"
      run_ssh "if [ -f $REMOTE_LINUX/output/live-dashboard-external/.pid ]; then kill \$(cat $REMOTE_LINUX/output/live-dashboard-external/.pid) 2>/dev/null || true; fi; pkill -f 'connection-monitor.sh --interval-sec' 2>/dev/null || true"
      ;;
    off)
      ;;
  esac
fi

log "Verifying linux artifacts"
run_ssh "python3 - << 'PY'
import json, pathlib
base=pathlib.Path.home()/'defend-external'/'output'/'live-dashboard-external'
end=pathlib.Path.home()/'defend-external'/'output'/'external-endpoint-$MODE'/'summary.json'
print('DASH='+str((base/'dashboard.html').exists()))
print('LIVE='+str((base/'live.json').exists()))
print('ENDPOINT='+str(end.exists()))
if (base/'live.json').exists():
  d=json.loads((base/'live.json').read_text())
  print('UPDATED='+str(d.get('updated_at')))
  print('COUNT='+str(d.get('current_count')))
  print('TREND='+str(d.get('trend')))
PY"

log "Linux dashboard: ~/defend-external/output/live-dashboard-external/dashboard.html"
