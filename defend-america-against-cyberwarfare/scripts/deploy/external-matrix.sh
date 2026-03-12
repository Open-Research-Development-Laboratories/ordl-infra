#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/external-run.sh"
TARGETS_FILE="${1:-$SCRIPT_DIR/targets.example.csv}"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "Targets file not found: $TARGETS_FILE" >&2
  exit 1
fi

# CSV columns:
# name,host,user,os,mode,monitor,password_env,anchor_url,anchor_token_env,node_id
while IFS=',' read -r name host user os mode monitor password_env anchor_url anchor_token_env node_id; do
  name="${name//[$'\r\n']/}"
  host="${host//[$'\r\n']/}"
  user="${user//[$'\r\n']/}"
  os="${os//[$'\r\n']/}"
  mode="${mode//[$'\r\n']/}"
  monitor="${monitor//[$'\r\n']/}"
  password_env="${password_env//[$'\r\n']/}"
  anchor_url="${anchor_url//[$'\r\n']/}"
  anchor_token_env="${anchor_token_env//[$'\r\n']/}"
  node_id="${node_id//[$'\r\n']/}"

  [ -z "$name" ] && continue
  case "$name" in \#*) continue ;; esac
  if [ "$name" = "name" ] && [ "$host" = "host" ]; then
    continue
  fi

  echo "=== target: $name ($host/$os) ==="
  "$RUNNER" \
    --host "$host" \
    --user "$user" \
    --os "$os" \
    --mode "${mode:-audit}" \
    --monitor "${monitor:-start}" \
    --password-env "${password_env:-DEFEND_SSH_PASSWORD}" \
    --anchor-url "${anchor_url:-}" \
    --anchor-token-env "${anchor_token_env:-DEFEND_ANCHOR_TOKEN}" \
    --node-id "${node_id:-}"
done < "$TARGETS_FILE"
