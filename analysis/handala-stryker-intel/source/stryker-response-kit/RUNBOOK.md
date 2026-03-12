# Stryker Local Response Kit

This kit does not patch Stryker devices or vendor systems. It is for your facility side only.

## Files

- `detect-stryker-local.ps1`
  Read-only Windows triage collection. No external modules or downloads.
- `defend-stryker-local.ps1`
  Optional local containment. Nothing changes unless you pass switches.
- `reverse-stryker-defense.ps1`
  Reverses the containment changes on the facility side.
- `build-federal-package.ps1`
  Builds a reporting package with imported triage, raw snapshots, EVTX exports, hashes, and a federal report draft.
- `federal-triage-template.txt`
  Fill-in template for CISA, FBI, HHS HC3, and FDA reporting.

## What the detector collects

- Local administrators and Remote Desktop Users membership
- Remote support software footprint
- Public established TCP connections
- Recent Windows security, Defender, PowerShell, service install, task scheduler, and RDP events
- Firewall profile state, SMB shares, DNS servers, and RDP settings

## Detector usage

Run from an elevated PowerShell prompt if possible:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\\detect-stryker-local.ps1 -HoursBack 72
```

Artifacts are written to a timestamped folder in the current directory. The main outputs are `summary.txt` and `triage.json`.

## Recommended sequence

Use this order on a Windows host you are assessing:

1. Run the detector and preserve the output folder.
2. Review the defense script with `-WhatIf`.
3. Apply only the containment switches you actually need.
4. Build the federal package from the detector and containment output folders.
5. Report to `CISA / DHS` first and `FBI` in parallel if you have local indicators or patient-care impact.

## Containment usage

Snapshot only:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\\defend-stryker-local.ps1
```

Disable inbound RDP and Remote Assistance:

```powershell
.\\defend-stryker-local.ps1 -BlockInboundRdp -DisableRemoteAssistance
```

Also block common remote support tools if present under `Program Files` or `ProgramData`:

```powershell
.\\defend-stryker-local.ps1 -BlockInboundRdp -DisableRemoteAssistance -BlockCommonRemoteSupportTools
```

Disable specific local vendor accounts listed one per line in a file:

```powershell
.\\defend-stryker-local.ps1 -VendorAccountsFile .\\vendor-accounts.txt
```

Review first without making changes:

```powershell
.\\defend-stryker-local.ps1 -BlockInboundRdp -DisableRemoteAssistance -WhatIf
```

## Reversal

Full rollback of the facility-side containment changes:

```powershell
.\\reverse-stryker-defense.ps1 -RestoreInboundRdp -RestoreRemoteAssistance -RemoveTemporaryFirewallRules
```

If you used `-VendorAccountsFile` during containment, pass the same file to re-enable those local accounts:

```powershell
.\\reverse-stryker-defense.ps1 -VendorAccountsFile .\\vendor-accounts.txt
```

If you point the reversal script at the original defense output directory, it will use `pre-change-state.json` to avoid re-enabling rules that were already disabled before the defense run:

```powershell
.\\reverse-stryker-defense.ps1 -ResponseDir .\\stryker-defend-20260312-130000 -RestoreInboundRdp -RestoreRemoteAssistance -RemoveTemporaryFirewallRules
```

Review first without making changes:

```powershell
.\\reverse-stryker-defense.ps1 -RestoreInboundRdp -RestoreRemoteAssistance -RemoveTemporaryFirewallRules -WhatIf
```

## Federal package

Build a case folder after you run the detector, and after containment if you applied it:

```powershell
.\\build-federal-package.ps1 -DetectionDir .\\stryker-detect-20260312-130000 -ContainmentDir .\\stryker-defend-20260312-131500 -HoursBack 72 -CreateZip
```

If you want the report draft to be prefilled with your site information:

```powershell
.\\build-federal-package.ps1 `
  -DetectionDir .\\stryker-detect-20260312-130000 `
  -ContainmentDir .\\stryker-defend-20260312-131500 `
  -FacilityName "Example Surgery Center" `
  -FacilityAddress "123 Main St, City, ST" `
  -PrimaryContact "Jane Doe" `
  -PrimaryRole "Administrator" `
  -PrimaryPhone "555-555-5555" `
  -PrimaryEmail "jane@example.org" `
  -CreateZip
```

This package includes:

- Imported detector and containment artifacts if you provide their folders
- Live snapshots of services, local users, scheduled tasks, firewall focus areas, public TCP connections, and Defender status
- Raw command output for `ipconfig`, `route`, `arp`, `netstat`, `quser`, `net user`, `schtasks`, and firewall profiles
- EVTX exports for Security, System, PowerShell, Defender, Task Scheduler, and RDP where export succeeds
- SHA256 hashes for remote-support binaries and processes with public TCP sessions where paths are available
- `federal-report-draft.txt` and `package-manifest.json`

## Reporting order

Use this order unless counsel or law enforcement directs otherwise:

1. `CISA / DHS` first for coordination and technical help.
2. `FBI` in parallel through the local field office and `IC3`.
3. `NSA` only as a secondary path for cybersecurity collaboration, or if you have DoD / DIB ties or are specifically asked to coordinate with them.

## Operational notes

- Run the detector first and preserve the output folder.
- Use `-WhatIf` on the containment script before applying changes on a live clinical workstation or server.
- Do not use this kit to alter medical device software or vendor-managed device configurations.
- If you see local compromise indicators, move to internal incident response and notify CISA and FBI.
