#!/usr/bin/env bash
set -euo pipefail

HOME_BASE="${HOME:-/tmp}"
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ] && command -v dscl >/dev/null 2>&1; then
  SUDO_HOME="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || true)"
  if [ -n "$SUDO_HOME" ]; then
    HOME_BASE="$SUDO_HOME"
  fi
fi
DEFAULT_ROOT="${DEFEND_ROOT_DIR:-$HOME_BASE/.defendmesh}"
WORK_DIR="${DEFEND_WORK_DIR:-${TMPDIR:-/tmp}/defendmesh-bootstrap}"
CWD_ROOT="$(pwd)"

run_maybe_sudo() {
  "$@" 2>/dev/null || true
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    sudo -n "$@" >/dev/null 2>&1 || true
  fi
}

kill_pid() {
  local pid="$1"
  [ -z "$pid" ] && return 0
  run_maybe_sudo kill "$pid"
  sleep 0.2
  if kill -0 "$pid" 2>/dev/null; then
    run_maybe_sudo kill -9 "$pid"
  elif [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n kill -0 "$pid" >/dev/null 2>&1; then
    run_maybe_sudo kill -9 "$pid"
  fi
}

kill_from_pid_file() {
  local pid_file="$1"
  [ -f "$pid_file" ] || return 0
  local pid
  pid="$(cat "$pid_file" 2>/dev/null | tr -dc '0-9' | head -c 16 || true)"
  if [ -n "$pid" ]; then
    kill_pid "$pid"
  fi
  rm -f "$pid_file" 2>/dev/null || true
}

pkill_pattern() {
  local signal="$1"
  local pattern="$2"
  pkill "-$signal" -f "$pattern" 2>/dev/null || true
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    sudo -n pkill "-$signal" -f "$pattern" >/dev/null 2>&1 || true
  fi
}

echo "[1/5] Stopping DefendMesh monitor/agent processes..."
for pid_file in \
  "$DEFAULT_ROOT/live-dashboard/monitor.pid" \
  "$DEFAULT_ROOT/live-dashboard/.pid" \
  "$DEFAULT_ROOT/node-agent/node-agent.pid" \
  "$DEFAULT_ROOT/node-agent/.pid" \
  "$CWD_ROOT/output/live-dashboard/monitor.pid" \
  "$CWD_ROOT/output/live-dashboard/.pid" \
  "$CWD_ROOT/output/node-agent/node-agent.pid" \
  "$CWD_ROOT/output/node-agent/.pid" \
  "$CWD_ROOT/output/oneclick-live-dashboard/.pid" \
  "$CWD_ROOT/output/oneclick-node-agent/.pid"
do
  kill_from_pid_file "$pid_file"
done

for pattern in \
  'defendmesh-bootstrap/connection-monitor.sh' \
  'defendmesh-bootstrap/node-agent.sh' \
  '/scripts/linux/connection-monitor.sh' \
  '/scripts/linux/node-agent.sh' \
  'connection-monitor.sh --' \
  'node-agent.sh --'
do
  pkill_pattern TERM "$pattern"
done
sleep 1
for pattern in \
  'defendmesh-bootstrap/connection-monitor.sh' \
  'defendmesh-bootstrap/node-agent.sh' \
  '/scripts/linux/connection-monitor.sh' \
  '/scripts/linux/node-agent.sh' \
  'connection-monitor.sh --' \
  'node-agent.sh --'
do
  pkill_pattern KILL "$pattern"
done

echo "[2/5] Removing bootstrap workspace..."
for target in "$WORK_DIR" "${TMPDIR:-/tmp}/defendmesh-bootstrap"; do
  [ -n "$target" ] || continue
  run_maybe_sudo rm -rf "$target"
done

echo "[3/5] Removing DefendMesh output directories..."
for target in \
  "$DEFAULT_ROOT" \
  "${HOME:-/tmp}/.defendmesh" \
  "/var/root/.defendmesh" \
  "$CWD_ROOT/output/live-dashboard" \
  "$CWD_ROOT/output/node-agent" \
  "$CWD_ROOT/output/oneclick-live-dashboard" \
  "$CWD_ROOT/output/oneclick-node-agent"
do
  [ -n "$target" ] || continue
  run_maybe_sudo rm -rf "$target"
done

echo "[4/5] Checking for lingering DefendMesh processes..."
remaining="$(ps -axo pid=,command= | grep -E '(connection-monitor\.sh|node-agent\.sh)' | grep -v grep || true)"
if [ -n "$remaining" ]; then
  echo "warning: lingering monitor/agent processes detected (may require elevated privileges):"
  printf '%s\n' "$remaining"
else
  echo "No lingering monitor/agent processes found."
fi

echo "[5/5] Removal complete."
