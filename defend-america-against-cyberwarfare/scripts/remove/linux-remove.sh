#!/usr/bin/env bash
set -euo pipefail

HOME_BASE="${HOME:-/tmp}"
DEFAULT_ROOT="${DEFEND_ROOT_DIR:-$HOME_BASE/.defendmesh}"
WORK_DIR="${DEFEND_WORK_DIR:-${TMPDIR:-/tmp}/defendmesh-bootstrap}"

echo "[1/4] Stopping DefendMesh monitor/agent processes..."
pkill -f 'connection-monitor.sh' 2>/dev/null || true
pkill -f 'node-agent.sh' 2>/dev/null || true

echo "[2/4] Removing bootstrap workspace..."
rm -rf "$WORK_DIR" 2>/dev/null || true

echo "[3/4] Removing DefendMesh output directories..."
rm -rf "$DEFAULT_ROOT" 2>/dev/null || true
rm -rf "./output/live-dashboard" "./output/node-agent" "./output/oneclick-live-dashboard" "./output/oneclick-node-agent" 2>/dev/null || true

echo "[4/4] Removal complete."
