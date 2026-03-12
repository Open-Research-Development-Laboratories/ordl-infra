#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ $# -gt 0 ] && [[ "${1:-}" == -* ]]; then
  exec bash "$SCRIPT_DIR/deploy-all.sh" "$@"
fi
TARGETS_FILE="${1:-$SCRIPT_DIR/targets.example.csv}"
shift || true

exec bash "$SCRIPT_DIR/deploy-all.sh" --targets "$TARGETS_FILE" "$@"
