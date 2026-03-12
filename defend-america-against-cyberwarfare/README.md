# Defend America Against Cyberwarfare

Defensive-only host triage and containment scripts for Windows and Linux.

## Point-and-Click (Windows)

Run:

`scripts\\windows\\defend-launcher.bat`

It shows a menu:
- `1` Audit mode (safe default)
- `2` Remediation mode
- `3` Realtime connection dashboard monitor

## Windows CLI

Audit:

`powershell -ExecutionPolicy Bypass -File .\\scripts\\windows\\defend-endpoint.ps1 -Mode audit -IocFile .\\iocs\\seed-iocs.txt -BroadcastAlert`

Remediate:

`powershell -ExecutionPolicy Bypass -File .\\scripts\\windows\\defend-endpoint.ps1 -Mode remediate -IocFile .\\iocs\\seed-iocs.txt -BroadcastAlert`

Realtime dashboard monitor:

`powershell -ExecutionPolicy Bypass -File .\\scripts\\windows\\connection-monitor.ps1 -IntervalSec 2`

## Linux CLI

Audit:

`bash ./scripts/linux/defend-host.sh --mode audit --ioc-file ./iocs/seed-iocs.txt --broadcast-alert`

Remediate:

`sudo bash ./scripts/linux/defend-host.sh --mode remediate --ioc-file ./iocs/seed-iocs.txt --broadcast-alert`

Realtime dashboard monitor:

`bash ./scripts/linux/connection-monitor.sh --interval-sec 2`

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
- current count
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
