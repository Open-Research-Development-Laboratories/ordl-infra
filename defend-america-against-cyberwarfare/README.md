# Defend America Against Cyberwarfare

Defensive-only host triage and containment scripts for Windows, Linux, and macOS.

## DefendMesh Anchor (Zero Trust Node System)

Use `anchor/` as the central control plane exposed on `defend.ordl.org` via tunnel.

- Operators authenticate with Zero Trust email login (for example `.gov` / `.mil` / org domains).
- Nodes send heartbeat/logs over outbound HTTPS.
- Anchor auto-queues defensive baseline playbooks (audit + monitor) and can auto-remediate on configured severity.
- Triage events can be enriched by an OpenAI-compatible model for defensive assistance.
- Operators queue approved defensive playbooks and stage signed patch bundles through anchor APIs (arbitrary remote script execution is intentionally disabled).

See [`anchor/README.md`](./anchor/README.md).

## Anchor Download + Removal

Connect node (one-line):
- Linux: `curl -fsSL https://defend.ordl.org/download/linux | bash`
- macOS: `curl -fsSL https://defend.ordl.org/download/macos | bash`
- Windows: `powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://defend.ordl.org/download/windows -OutFile $env:TEMP\defendmesh.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\defendmesh.ps1"`

Remove node tooling (one-line):
- Linux: `curl -fsSL https://defend.ordl.org/download/remove/linux | bash`
- macOS: `curl -fsSL https://defend.ordl.org/download/remove/macos | bash`
- Windows: `powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://defend.ordl.org/download/remove/windows -OutFile $env:TEMP\defendmesh-remove.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\defendmesh-remove.ps1"`

## Point-and-Click (Windows)

Run:

`scripts\\windows\\defend-launcher.bat`

It shows a menu:
- `1` Audit mode (safe default)
- `2` Remediation mode
- `3` Realtime connection dashboard monitor

## One-Click Launchers (Windows/Linux/macOS)

These wrappers are defensive-only startup wrappers that run endpoint audit, start live monitor, and start node-agent.

Run:

- Windows (Batch):
  `scripts\one-click\windows-one-click.bat`
- Windows (PowerShell):
  `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\one-click\windows-one-click.ps1`
- Linux:
  `bash ./scripts/one-click/linux-one-click.sh`
- macOS:
  `bash ./scripts/one-click/macos-one-click.command`

Env vars:
- `DEFEND_ANCHOR_TOKEN`: required for authenticated/protected anchor tasking and heartbeat.
- `DEFEND_ANCHOR_URL` (optional): defaults to `https://defend.ordl.org`.
- `DEFEND_NODE_ID` (optional): defaults to `%COMPUTERNAME%` on Windows, `hostname` on Linux/macOS (fallback `node-1`).

## Unified External Deploy (Single Script)

Use one script for both single-target and matrix deployment:

- Single target:
  `bash ./scripts/deploy/deploy-all.sh --host 10.0.0.254 --user winsock --os windows --mode audit --monitor start --anchor-url https://defend.ordl.org --node-id edge-windows-1`
- CSV matrix:
  `bash ./scripts/deploy/deploy-all.sh --targets ./scripts/deploy/targets.example.csv`

Default behavior is external-only host targeting (private/local hosts are refused).
Use `--allow-private` only for lab testing.

Token provisioning:
- If node token is missing, deploy auto-mints one via anchor admin API and caches it locally.
- Set `DEFEND_ANCHOR_ADMIN_TOKEN` once for auto-provisioning, or set `DEFEND_ANCHOR_TOKEN` directly.

Client inventory:
- Deploy prints lawful host inventory it can read from authorized endpoints (hostname, user, OS/build, architecture).

Compatibility wrappers still work:
- `bash ./scripts/deploy/external-run.sh ...`
- `bash ./scripts/deploy/external-matrix.sh ./scripts/deploy/targets.example.csv`

## Windows CLI

Audit:

`powershell -ExecutionPolicy Bypass -File .\\scripts\\windows\\defend-endpoint.ps1 -Mode audit -IocFile .\\iocs\\seed-iocs.txt -BroadcastAlert`

Remediate:

`powershell -ExecutionPolicy Bypass -File .\\scripts\\windows\\defend-endpoint.ps1 -Mode remediate -IocFile .\\iocs\\seed-iocs.txt -BroadcastAlert`

Realtime dashboard monitor:

`powershell -ExecutionPolicy Bypass -File .\\scripts\\windows\\connection-monitor.ps1 -IntervalSec 2`

With anchor heartbeat:

`powershell -ExecutionPolicy Bypass -File .\\scripts\\windows\\connection-monitor.ps1 -IntervalSec 2 -AnchorUrl https://defend.ordl.org -NodeId edge-1 -AnchorToken $env:DEFEND_ANCHOR_TOKEN`

## Linux CLI

Audit:

`bash ./scripts/linux/defend-host.sh --mode audit --ioc-file ./iocs/seed-iocs.txt --broadcast-alert`

Remediate:

`sudo bash ./scripts/linux/defend-host.sh --mode remediate --ioc-file ./iocs/seed-iocs.txt --broadcast-alert`

Realtime dashboard monitor:

`bash ./scripts/linux/connection-monitor.sh --interval-sec 2`

With anchor heartbeat:

`bash ./scripts/linux/connection-monitor.sh --interval-sec 2 --anchor-url https://defend.ordl.org --node-id laptop-1 --anchor-token \"$DEFEND_ANCHOR_TOKEN\"`

## Control File Mode Switching (No Listening Port)

Default control file path:

- Windows: `control\\mode-control.txt`
- Linux: `control/mode-control.txt`

Format:

`mode:audit`
or
`mode:remediate`

Optional token control:

`token:YOUR_SECRET`

Set env var `DEFEND_CONTROL_TOKEN` on the host to require a matching token.

## Dashboard

Each run writes `dashboard.html` in its output folder.

Realtime monitors also write a live dashboard in:

- `output/live-dashboard/dashboard.html`

Realtime dashboard displays:
- `Connections Present: YES/NO`
- active sockets (live socket count sampled from `ss`/`netstat`)
- trend (`UP`, `DOWN`, `STEADY`)
- recent timestamped count history

No IP/port/process endpoint details are shown in the dashboard.

## Safety

- Defensive use only.
- Start in audit mode first.
- Keep IOC file sanitized for public repositories.

## Acceptable Use

- Use this project only for authorized defensive security operations.
- Do not use this project for offensive operations, disruption, denial-of-service, unauthorized access, or retaliation.
- Run only on systems you own or are explicitly authorized to administer.
- Follow local laws, organizational policy, and platform terms of service.

See [`SECURITY.md`](./SECURITY.md) for reporting and security policy details.
