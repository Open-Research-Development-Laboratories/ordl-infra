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
ANCHOR_ADMIN_TOKEN_ENV="DEFEND_ANCHOR_ADMIN_TOKEN"
NODE_ID=""
RUN_ENDPOINT=1
RUN_MONITOR=1
SYNC_PACKAGE=1
TARGETS_FILE=""
REQUIRE_EXTERNAL=1
TOKEN_CACHE_DIR="${HOME:-/tmp}/.defendmesh-node-tokens"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SSH_BIN="ssh"
SCP_BIN="scp"
SSH_OPTS=(-T -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)

usage() {
  cat <<'USAGE'
Usage:
  deploy-all.sh --host HOST --user USER --os windows|linux [options]
  deploy-all.sh --targets FILE.csv [options]
  deploy-all.sh FILE.csv

Options:
  --targets FILE.csv              CSV mode (same format as targets.example.csv)
  --host HOST                     Single-target mode
  --user USER                     Single-target mode
  --os windows|linux              Single-target mode
  --mode audit|remediate          Endpoint mode (default: audit)
  --monitor start|oneshot|stop|off  Monitor action (default: start)
  --interval-sec N                Monitor interval seconds (default: 2)
  --loop-count N                  Loop count for oneshot monitor (default: 0)
  --password-env VAR              Env var holding SSH password (default: DEFEND_SSH_PASSWORD)
  --anchor-url URL                DefendMesh anchor base URL (optional)
  --anchor-token-env VAR          Env var holding anchor node token (default: DEFEND_ANCHOR_TOKEN)
  --anchor-admin-token-env VAR    Env var holding anchor admin token (default: DEFEND_ANCHOR_ADMIN_TOKEN)
  --node-id ID                    Override node id sent to anchor
  --no-sync                       Skip package upload/sync
  --monitor-only                  Skip endpoint run
  --endpoint-only                 Skip monitor run
  --allow-private                 Allow private/local hosts (default is external-only)
  --require-external              Enforce external-only hosts (default)
  -h, --help                      Show help

CSV columns:
  name,host,user,os,mode,monitor,password_env,anchor_url,anchor_token_env,node_id
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --targets) shift; TARGETS_FILE="${1:-}" ;;
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
    --anchor-admin-token-env) shift; ANCHOR_ADMIN_TOKEN_ENV="${1:-DEFEND_ANCHOR_ADMIN_TOKEN}" ;;
    --node-id) shift; NODE_ID="${1:-}" ;;
    --no-sync) SYNC_PACKAGE=0 ;;
    --monitor-only) RUN_ENDPOINT=0 ;;
    --endpoint-only) RUN_MONITOR=0 ;;
    --allow-private) REQUIRE_EXTERNAL=0 ;;
    --require-external) REQUIRE_EXTERNAL=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      if [ -z "$TARGETS_FILE" ] && [ -f "$1" ]; then
        TARGETS_FILE="$1"
      else
        echo "Unknown arg: $1" >&2
        usage >&2
        exit 1
      fi
      ;;
  esac
  shift
done

TARGET_OS="$(printf '%s' "$TARGET_OS" | tr '[:upper:]' '[:lower:]')"
MODE="$(printf '%s' "$MODE" | tr '[:upper:]' '[:lower:]')"

if [ -n "$TARGET_OS" ] && [ "$TARGET_OS" != "windows" ] && [ "$TARGET_OS" != "linux" ]; then
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

run_ssh() {
  local user_name="$1"
  local host="$2"
  local ssh_password="$3"
  local cmd="$4"
  if [ -n "$ssh_password" ]; then
    SSHPASS="$ssh_password" sshpass -e "$SSH_BIN" "${SSH_OPTS[@]}" "$user_name@$host" "$cmd"
  else
    "$SSH_BIN" "${SSH_OPTS[@]}" "$user_name@$host" "$cmd"
  fi
}

run_scp_dir() {
  local user_name="$1"
  local host="$2"
  local ssh_password="$3"
  local src_dir="$4"
  local dst="$5"
  if [ -n "$ssh_password" ]; then
    SSHPASS="$ssh_password" sshpass -e "$SCP_BIN" -r -o StrictHostKeyChecking=accept-new "$src_dir"/* "$user_name@$host:$dst"
  else
    "$SCP_BIN" -r -o StrictHostKeyChecking=accept-new "$src_dir"/* "$user_name@$host:$dst"
  fi
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

is_private_or_local_host() {
  local host="$1"
  case "$host" in
    localhost|localhost.localdomain|127.*|10.*|192.168.*|169.254.*) return 0 ;;
  esac
  if [[ "$host" =~ ^172\.([1][6-9]|2[0-9]|3[0-1])\. ]]; then
    return 0
  fi
  return 1
}

cache_key() {
  printf '%s__%s' "$1" "$2" | sed 's#[^A-Za-z0-9_.-]#_#g'
}

anchor_url_items() {
  printf '%s' "$1" | tr ';' ',' | awk -F',' '{for(i=1;i<=NF;i++){gsub(/^[ \t]+|[ \t]+$/, "", $i); if($i!="") print $i}}'
}

read_local_anchor_admin_token() {
  if [ -f "${HOME:-}/.defendmesh-anchor.env" ]; then
    grep '^ANCHOR_ADMIN_DEV_TOKEN=' "${HOME}/.defendmesh-anchor.env" 2>/dev/null | cut -d= -f2- || true
  fi
}

set_node_token() {
  local anchor_url="$1"
  local admin_token="$2"
  local node_id="$3"
  local token="$4"
  local payload response
  payload="$(printf '{"node_id":"%s","token":"%s","note":"deploy-auto"}' "$node_id" "$token")"
  response="$(curl -fsS -m 20 -X POST \
    -H "Authorization: Bearer $admin_token" \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    "${anchor_url%/}/api/v1/admin/node-token")"
  printf '%s' "$response" | sed -n 's/.*"ok"[[:space:]]*:[[:space:]]*true.*/ok/p' | head -n 1 | grep -q '^ok$'
}

mint_node_token() {
  local anchor_urls="$1"
  local admin_token="$2"
  local node_id="$3"
  local node_token ok url
  node_token="$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 48)"
  [ -z "$node_token" ] && node_token="$(date +%s%N | sha256sum | awk '{print substr($1,1,48)}')"
  ok=0
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    if set_node_token "$url" "$admin_token" "$node_id" "$node_token"; then
      ok=1
    fi
  done < <(anchor_url_items "$anchor_urls")
  if [ "$ok" -eq 1 ]; then
    printf '%s' "$node_token"
  fi
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

kv_get() {
  local input="$1"
  local key="$2"
  printf '%s\n' "$input" | sed -n "s/^${key}=//p" | head -n 1
}

send_node_profile() {
  local anchor_urls="$1"
  local anchor_token="$2"
  local node_id="$3"
  local platform="$4"
  local client_host="$5"
  local client_user="$6"
  local client_os="$7"
  local client_build="$8"
  local client_arch="$9"
  local client_kernel="${10}"
  local payload url
  [ -z "$anchor_urls" ] && return 0
  payload="$(printf '{"node_id":"%s","platform":"%s","profile":{"client_host":"%s","client_user":"%s","client_os":"%s","client_build":"%s","client_arch":"%s","client_kernel":"%s"},"updated_at":"%s"}' \
    "$(json_escape "$node_id")" \
    "$(json_escape "$platform")" \
    "$(json_escape "$client_host")" \
    "$(json_escape "$client_user")" \
    "$(json_escape "$client_os")" \
    "$(json_escape "$client_build")" \
    "$(json_escape "$client_arch")" \
    "$(json_escape "$client_kernel")" \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')")"
  [ -z "$anchor_token" ] && return 0
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    curl -fsS -m 20 -X POST "${url%/}/api/v1/node/profile" \
      -H "Authorization: Bearer $anchor_token" \
      -H 'Content-Type: application/json' \
      -d "$payload" >/dev/null 2>&1 || true
  done < <(anchor_url_items "$anchor_urls")
}

run_target() {
  local host="$1"
  local user_name="$2"
  local target_os="$3"
  local mode="$4"
  local monitor_mode="$5"
  local password_env="$6"
  local anchor_url="$7"
  local anchor_token_env="$8"
  local anchor_admin_token_env="$9"
  local node_id="${10}"

  local ssh_password anchor_token anchor_admin_token token_cache_file
  ssh_password="${!password_env:-}"
  anchor_token="${!anchor_token_env:-}"
  anchor_admin_token="${!anchor_admin_token_env:-}"

  if [ -z "$host" ] || [ -z "$user_name" ] || [ -z "$target_os" ]; then
    echo "Missing required target fields (host/user/os)" >&2
    return 1
  fi
  if [ "$REQUIRE_EXTERNAL" -eq 1 ] && is_private_or_local_host "$host"; then
    echo "Refusing private/local host in external-only mode: $host" >&2
    return 1
  fi

  target_os="$(printf '%s' "$target_os" | tr '[:upper:]' '[:lower:]')"
  if [ "$target_os" != "windows" ] && [ "$target_os" != "linux" ]; then
    echo "target os must be windows or linux (got: $target_os)" >&2
    return 1
  fi
  if [ -z "$node_id" ]; then
    node_id="${target_os}-${host}"
  fi
  if [ -n "$anchor_url" ] && [ -z "$anchor_token" ]; then
    mkdir -p "$TOKEN_CACHE_DIR"
    token_cache_file="$TOKEN_CACHE_DIR/$(cache_key "$anchor_url" "$node_id").token"
    if [ -f "$token_cache_file" ]; then
      anchor_token="$(cat "$token_cache_file" 2>/dev/null || true)"
    fi
    if [ -z "$anchor_admin_token" ]; then
      anchor_admin_token="$(read_local_anchor_admin_token)"
    fi
    if [ -z "$anchor_token" ] && [ -n "$anchor_admin_token" ]; then
      log "Auto-provisioning node token for node_id=$node_id"
      anchor_token="$(mint_node_token "$anchor_url" "$anchor_admin_token" "$node_id" || true)"
      if [ -n "$anchor_token" ]; then
        printf '%s\n' "$anchor_token" > "$token_cache_file"
        chmod 600 "$token_cache_file" 2>/dev/null || true
      fi
    fi
    if [ -z "$anchor_token" ]; then
      echo "Anchor token missing and auto-provision failed. Set $anchor_admin_token_env or $anchor_token_env." >&2
      return 1
    fi
  fi

  if [ "$target_os" = "windows" ]; then
    local remote_native remote_scp win_mon_cmd win_inventory
    remote_native="C:\\Users\\$user_name\\defend-external"
    remote_scp="/C:/Users/$user_name/defend-external"

    if [ "$SYNC_PACKAGE" -eq 1 ]; then
      log "Syncing package to windows target $host"
      run_ssh "$user_name" "$host" "$ssh_password" "cmd /c \"if exist $remote_native rmdir /s /q $remote_native & mkdir $remote_native\""
      run_scp_dir "$user_name" "$host" "$ssh_password" "$PKG_DIR" "$remote_scp/"
    fi

    if [ "$RUN_ENDPOINT" -eq 1 ]; then
      log "Running windows endpoint script mode=$mode"
      run_ssh "$user_name" "$host" "$ssh_password" "powershell -NoProfile -ExecutionPolicy Bypass -File $remote_native\\scripts\\windows\\defend-endpoint.ps1 -Mode $mode -IocFile $remote_native\\iocs\\seed-iocs.txt -OutputDir $remote_native\\output\\external-endpoint-$mode"
    fi

    log "Collecting windows client inventory"
    win_inventory="$(run_ssh "$user_name" "$host" "$ssh_password" "powershell -NoProfile -Command \"\$os=Get-CimInstance Win32_OperatingSystem; Write-Output ('CLIENT_HOST=' + \$env:COMPUTERNAME); Write-Output ('CLIENT_USER=' + \$env:USERNAME); Write-Output ('CLIENT_OS=' + \$os.Caption); Write-Output ('CLIENT_BUILD=' + \$os.BuildNumber); Write-Output ('CLIENT_ARCH=' + \$os.OSArchitecture);\"")"
    printf '%s\n' "$win_inventory"
    send_node_profile "$anchor_url" "$anchor_token" "$node_id" "windows" \
      "$(kv_get "$win_inventory" "CLIENT_HOST")" \
      "$(kv_get "$win_inventory" "CLIENT_USER")" \
      "$(kv_get "$win_inventory" "CLIENT_OS")" \
      "$(kv_get "$win_inventory" "CLIENT_BUILD")" \
      "$(kv_get "$win_inventory" "CLIENT_ARCH")" \
      ""

    if [ "$RUN_MONITOR" -eq 1 ]; then
      win_mon_cmd="powershell -NoProfile -ExecutionPolicy Bypass -File $remote_native\\scripts\\windows\\connection-monitor.ps1 -IntervalSec $INTERVAL_SEC -OutputDir $remote_native\\output\\live-dashboard-external"
      if [ -n "$anchor_url" ]; then
        win_mon_cmd="$win_mon_cmd -AnchorUrl $anchor_url"
      fi
      if [ -n "$node_id" ]; then
        win_mon_cmd="$win_mon_cmd -NodeId $node_id"
      fi
      if [ -n "$anchor_token" ]; then
        win_mon_cmd="$win_mon_cmd -AnchorToken $anchor_token"
      fi

      case "$monitor_mode" in
        start)
          log "Starting persistent windows monitor"
          run_ssh "$user_name" "$host" "$ssh_password" "powershell -NoProfile -Command \"Get-CimInstance Win32_Process | Where-Object { \$_.CommandLine -like '*connection-monitor.ps1*' } | ForEach-Object { try { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }; Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','$remote_native\\scripts\\windows\\connection-monitor.ps1','-IntervalSec','$INTERVAL_SEC','-OutputDir','$remote_native\\output\\live-dashboard-external'$( [ -n \"$anchor_url\" ] && printf \",'-AnchorUrl','%s'\" \"$anchor_url\" )$( [ -n \"$node_id\" ] && printf \",'-NodeId','%s'\" \"$node_id\" )$( [ -n \"$anchor_token\" ] && printf \",'-AnchorToken','%s'\" \"$anchor_token\" ) -WindowStyle Hidden\""
          ;;
        oneshot)
          log "Running oneshot windows monitor loops=$LOOP_COUNT"
          run_ssh "$user_name" "$host" "$ssh_password" "$win_mon_cmd -LoopCount $LOOP_COUNT"
          ;;
        stop)
          log "Stopping windows monitor task"
          run_ssh "$user_name" "$host" "$ssh_password" "powershell -NoProfile -Command \"Get-CimInstance Win32_Process | Where-Object { \$_.CommandLine -like '*connection-monitor.ps1*' } | ForEach-Object { try { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }\""
          ;;
        off) ;;
      esac
    fi

    log "Verifying windows artifacts"
    run_ssh "$user_name" "$host" "$ssh_password" "powershell -NoProfile -Command \"Write-Output ('DASH=' + (Test-Path '$remote_native\\output\\live-dashboard-external\\dashboard.html')); Write-Output ('LIVE=' + (Test-Path '$remote_native\\output\\live-dashboard-external\\live.json')); Write-Output ('ENDPOINT=' + (Test-Path '$remote_native\\output\\external-endpoint-$mode\\summary.json')); if(Test-Path '$remote_native\\output\\live-dashboard-external\\live.json'){ \$j=Get-Content -Raw '$remote_native\\output\\live-dashboard-external\\live.json' | ConvertFrom-Json; Write-Output ('UPDATED=' + \$j.updated_at); Write-Output ('COUNT=' + \$j.current_count); Write-Output ('TREND=' + \$j.trend); }\""
    log "Windows dashboard: $remote_native\\output\\live-dashboard-external\\dashboard.html"
    return 0
  fi

  local remote_linux lin_mon_cmd lin_inventory
  remote_linux="~/defend-external"
  if [ "$SYNC_PACKAGE" -eq 1 ]; then
    log "Syncing package to linux target $host"
    run_ssh "$user_name" "$host" "$ssh_password" "rm -rf $remote_linux && mkdir -p $remote_linux"
    run_scp_dir "$user_name" "$host" "$ssh_password" "$PKG_DIR" "$remote_linux/"
  fi

  if [ "$RUN_ENDPOINT" -eq 1 ]; then
    log "Running linux endpoint script mode=$mode"
    run_ssh "$user_name" "$host" "$ssh_password" "bash $remote_linux/scripts/linux/defend-host.sh --mode $mode --ioc-file $remote_linux/iocs/seed-iocs.txt --output-dir $remote_linux/output/external-endpoint-$mode"
  fi

  log "Collecting linux client inventory"
  lin_inventory="$(run_ssh "$user_name" "$host" "$ssh_password" "bash -lc 'echo CLIENT_HOST=\$(hostname 2>/dev/null || echo unknown); echo CLIENT_USER=\$(id -un 2>/dev/null || echo unknown); echo CLIENT_OS=\$(uname -s 2>/dev/null || echo unknown); echo CLIENT_KERNEL=\$(uname -r 2>/dev/null || echo unknown); echo CLIENT_ARCH=\$(uname -m 2>/dev/null || echo unknown)'")"
  printf '%s\n' "$lin_inventory"
  send_node_profile "$anchor_url" "$anchor_token" "$node_id" "linux" \
    "$(kv_get "$lin_inventory" "CLIENT_HOST")" \
    "$(kv_get "$lin_inventory" "CLIENT_USER")" \
    "$(kv_get "$lin_inventory" "CLIENT_OS")" \
    "" \
    "$(kv_get "$lin_inventory" "CLIENT_ARCH")" \
    "$(kv_get "$lin_inventory" "CLIENT_KERNEL")"

  if [ "$RUN_MONITOR" -eq 1 ]; then
    lin_mon_cmd="bash $remote_linux/scripts/linux/connection-monitor.sh --interval-sec $INTERVAL_SEC --output-dir $remote_linux/output/live-dashboard-external"
    if [ -n "$anchor_url" ]; then
      lin_mon_cmd="$lin_mon_cmd --anchor-url $anchor_url"
    fi
    if [ -n "$node_id" ]; then
      lin_mon_cmd="$lin_mon_cmd --node-id $node_id"
    fi
    if [ -n "$anchor_token" ]; then
      lin_mon_cmd="$lin_mon_cmd --anchor-token $anchor_token"
    fi

    case "$monitor_mode" in
      start)
        log "Starting persistent linux monitor"
        run_ssh "$user_name" "$host" "$ssh_password" "mkdir -p $remote_linux/output/live-dashboard-external && nohup $lin_mon_cmd >/tmp/defend-live-monitor.log 2>&1 & echo \$! > $remote_linux/output/live-dashboard-external/.pid"
        ;;
      oneshot)
        log "Running oneshot linux monitor loops=$LOOP_COUNT"
        run_ssh "$user_name" "$host" "$ssh_password" "$lin_mon_cmd --loop-count $LOOP_COUNT"
        ;;
      stop)
        log "Stopping linux monitor"
        run_ssh "$user_name" "$host" "$ssh_password" "if [ -f $remote_linux/output/live-dashboard-external/.pid ]; then kill \$(cat $remote_linux/output/live-dashboard-external/.pid) 2>/dev/null || true; fi; pkill -f 'connection-monitor.sh --interval-sec' 2>/dev/null || true"
        ;;
      off) ;;
    esac
  fi

  log "Verifying linux artifacts"
  run_ssh "$user_name" "$host" "$ssh_password" "python3 - << 'PY'
import json, pathlib
base=pathlib.Path.home()/'defend-external'/'output'/'live-dashboard-external'
end=pathlib.Path.home()/'defend-external'/'output'/'external-endpoint-$mode'/'summary.json'
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
}

if [ -n "$TARGETS_FILE" ]; then
  if [ ! -f "$TARGETS_FILE" ]; then
    echo "Targets file not found: $TARGETS_FILE" >&2
    exit 1
  fi

  while IFS=',' read -r name host user_name target_os mode_csv monitor_csv password_env_csv anchor_url_csv anchor_token_env_csv node_id_csv; do
    name="${name//[$'\r\n']/}"
    host="${host//[$'\r\n']/}"
    user_name="${user_name//[$'\r\n']/}"
    target_os="${target_os//[$'\r\n']/}"
    mode_csv="${mode_csv//[$'\r\n']/}"
    monitor_csv="${monitor_csv//[$'\r\n']/}"
    password_env_csv="${password_env_csv//[$'\r\n']/}"
    anchor_url_csv="${anchor_url_csv//[$'\r\n']/}"
    anchor_token_env_csv="${anchor_token_env_csv//[$'\r\n']/}"
    node_id_csv="${node_id_csv//[$'\r\n']/}"

    [ -z "$name" ] && continue
    case "$name" in \#*) continue ;; esac
    if [ "$name" = "name" ] && [ "$host" = "host" ]; then
      continue
    fi

    echo "=== target: $name ($host/$target_os) ==="
    run_target \
      "$host" \
      "$user_name" \
      "$target_os" \
      "${mode_csv:-$MODE}" \
      "${monitor_csv:-$MONITOR_MODE}" \
      "${password_env_csv:-$PASSWORD_ENV}" \
      "${anchor_url_csv:-$ANCHOR_URL}" \
      "${anchor_token_env_csv:-$ANCHOR_TOKEN_ENV}" \
      "$ANCHOR_ADMIN_TOKEN_ENV" \
      "${node_id_csv:-$NODE_ID}"
  done < "$TARGETS_FILE"
  exit 0
fi

if [ -z "$HOST" ] || [ -z "$USER_NAME" ] || [ -z "$TARGET_OS" ]; then
  echo "Missing required args. Use --host/--user/--os or --targets FILE.csv" >&2
  usage >&2
  exit 1
fi

run_target "$HOST" "$USER_NAME" "$TARGET_OS" "$MODE" "$MONITOR_MODE" "$PASSWORD_ENV" "$ANCHOR_URL" "$ANCHOR_TOKEN_ENV" "$ANCHOR_ADMIN_TOKEN_ENV" "$NODE_ID"
