# Repository-Derived Handala / Stryker Operational Profile

## Scope

- Source repository: `Open-Research-Development-Laboratories/ordl-infra`
- Commit analyzed: `6948df93106066cc01b0f469a6d1b9551d49d1f8`
- Query basis: `Handala OR Stryker`
- Matched files: 12
- Matched lines: 58
- Important limit: this report is constrained to the repository search corpus, not external reporting or historical attribution.

## Executive Summary

The repository splits into two distinct defensive tracks.

`Handala` is represented as a cloud and administrative-plane wiper defense package focused on Microsoft Intune, Azure AD / Entra, OAuth consent abuse, EMR access anomalies, and clinical device availability. The strongest repo-backed behaviors are mass device wipe detection, suspicious privileged sign-in detection, admin hardening, and emergency reduction of destructive device actions.

`Stryker` is represented as a facility-side Windows triage and containment kit focused on remote support software, public established TCP connections, RDP / Remote Assistance exposure, local vendor accounts, scheduled-task visibility, and evidence packaging for federal reporting. The strongest repo-backed behaviors are remote-support footprinting, local containment, and evidence collection rather than actor attribution.

## Repo-Derived Handala Profile

### Confirmed detection and response surfaces

- Mass Intune destructive actions are explicitly monitored with a 5-minute window and a default threshold greater than 5 wipe-like actions. Evidence: `handala-security/Detect-HandalaThreats.ps1:22-27`, `handala-security/Detect-HandalaThreats.ps1:81-137`.
- Suspicious Azure AD administrative sign-ins are detected based on admin-like usernames, high or medium risk state, risky geographies, and conditional access failures. Evidence: `handala-security/Detect-HandalaThreats.ps1:139-199`.
- OAuth application consent abuse is treated as suspicious when app metadata or targets look high risk or outside an allowlist. Evidence: `handala-security/Detect-HandalaThreats.ps1:202-258`.
- EMR access anomalies are monitored for bulk access, after-hours access, and non-clinical workstation usage. Evidence: `handala-security/Detect-HandalaThreats.ps1:262-324`.
- Clinical device network disconnects are treated as patient-safety critical alerts. Evidence: `handala-security/Detect-HandalaThreats.ps1:326-383`.

### Confirmed hardening and containment patterns

- Intune hardening disables automatic wipe behavior and, in emergency mode, restricts destructive device actions such as `wipe`, `retire`, and `delete`. Evidence: `handala-security/Protect-SurgicalCenter.ps1:65-107`.
- Azure AD hardening enforces MFA for admin roles, checks break-glass coverage, and creates an admin geo-restriction conditional access policy. Evidence: `handala-security/Protect-SurgicalCenter.ps1:109-179`.
- Network segmentation is modeled as a clinical VLAN isolation template, especially between clinical, internet, and admin segments. Evidence: `handala-security/Protect-SurgicalCenter.ps1:181-217`.
- Backup verification covers EMR, AD system-state, and Intune configuration backups. Evidence: `handala-security/Protect-SurgicalCenter.ps1:220-265`.
- Continuous monitoring can be scheduled every 5 minutes as `SYSTEM` under the `SC-HandalaDetection` task. Evidence: `handala-security/Protect-SurgicalCenter.ps1:267-321`.
- Restoration logic exists for Intune, Azure AD, firewall, scheduled task, backup, and segmentation rollback after eviction. Evidence: `handala-security/Restore-Hardening.ps1:130-379`.

### What the repo supports only weakly

- `HANDALA-RESPONSE.md` mentions suspicious PowerShell from `SYSTEM`, unexpected lateral movement, and credential harvesting patterns, but the search corpus does not implement dedicated detection logic for those three behaviors. Evidence: `HANDALA-RESPONSE.md:3-10`.
- The corpus is strongly defensive. It does not, by itself, prove initial access, actor provenance, or live command-and-control infrastructure.

## Repo-Derived Stryker Profile

### Confirmed triage surfaces

- The local detector inventories installed programs, services, and processes for common remote support tooling including AnyDesk, TeamViewer, ScreenConnect, Bomgar, BeyondTrust, Splashtop, RustDesk, LogMeIn, Atera, Kaseya, MeshCentral, and multiple VNC variants. Evidence: `stryker-response-kit/detect-stryker-local.ps1:84-140`.
- The detector records established TCP sessions whose remote addresses are not loopback or RFC1918 private space. Evidence: `stryker-response-kit/detect-stryker-local.ps1:142-176`.
- The detector snapshots local administrators, Remote Desktop Users, logged-on users, firewall profiles, SMB shares, DNS servers, and RDP / Remote Assistance state. Evidence: `stryker-response-kit/detect-stryker-local.ps1:216-317`.
- Event collection covers Security, service install, Task Scheduler, PowerShell operational, Defender operational, and Remote Desktop logs. Evidence: `stryker-response-kit/detect-stryker-local.ps1:178-185`, `stryker-response-kit/detect-stryker-local.ps1:246-317`.

### Confirmed containment and rollback patterns

- Local containment can disable inbound Remote Desktop rules or create a fallback TCP/3389 block rule. Evidence: `stryker-response-kit/defend-stryker-local.ps1:197-221`.
- Local containment can disable Remote Assistance both in the registry and in the firewall rule group. Evidence: `stryker-response-kit/defend-stryker-local.ps1:223-237`.
- Local containment can create per-program inbound and outbound block rules for discovered remote support executables. Evidence: `stryker-response-kit/defend-stryker-local.ps1:70-145`, `stryker-response-kit/defend-stryker-local.ps1:239-247`.
- Local containment can disable listed local vendor accounts from a supplied file. Evidence: `stryker-response-kit/defend-stryker-local.ps1:147-175`, `stryker-response-kit/defend-stryker-local.ps1:250-257`.
- Rollback can re-enable Remote Desktop and Remote Assistance according to pre-change state, remove temporary Stryker firewall rules, and re-enable listed local accounts. Evidence: `stryker-response-kit/reverse-stryker-defense.ps1:70-176`, `stryker-response-kit/reverse-stryker-defense.ps1:222-252`.

### Confirmed evidence packaging and reporting

- The runbook positions the Stryker kit as facility-side only and explicitly says it does not patch vendor systems or devices. Evidence: `stryker-response-kit/RUNBOOK.md:1-16`.
- The federal package builder can import detection and containment artifacts, export EVTX windows, hash remote-support binaries and public-connection processes, and draft a reporting package. Evidence: `stryker-response-kit/build-federal-package.ps1:154-252`, `stryker-response-kit/build-federal-package.ps1:254-410`.
- The federal report draft emphasizes downstream exposure through Stryker-connected trust paths or vendor-linked disruption, not direct proof of actor control. Evidence: `stryker-response-kit/build-federal-package.ps1:274-329`.
- The reporting guidance prioritizes CISA / DHS first, FBI in parallel, and NSA only secondarily. Evidence: `stryker-response-kit/RUNBOOK.md:138-151`, `stryker-response-kit/federal-triage-template.txt`.

## Support Matrix For The Supplied Claims

| Claim | Status | Notes |
| --- | --- | --- |
| Handala mass Intune wipe activity | Supported | Exact detection logic exists. |
| Handala suspicious Azure AD admin sign-ins | Supported | Exact detection logic exists. |
| Handala OAuth abuse / suspicious app consent | Supported | Exact detection logic exists. |
| Handala EMR anomaly / possible bulk access | Supported | Exact detection logic exists. |
| Handala continuous SYSTEM-scheduled monitoring | Supported | `SC-HandalaDetection` runs every 5 minutes as `SYSTEM`. |
| Handala suspicious PowerShell from SYSTEM | Partial | Mentioned in `HANDALA-RESPONSE.md`, not implemented as dedicated logic in the matched corpus. |
| Handala lateral movement detection | Partial | Mentioned in docs only. |
| Handala credential harvesting detection | Partial | Mentioned in docs only. |
| Handala conditional access removal or policy tampering detection | Not found | Hardening creates policy; the corpus does not detect policy removal in the search-hit files. |
| Handala audit log deletion detection | Not found | No explicit logic found in the search-hit corpus. |
| Handala cloud-to-on-prem trust path exploitation | Not found | No explicit detection or modeling found. |
| `Test-SuspiciousAdminLogin -RiskyCountries ...` | Not found as written | The function hardcodes risky countries and does not expose a `-RiskyCountries` parameter in the search-hit corpus. |
| Stryker remote support tools as central hunt surface | Supported | Exact tooling lists and triage logic exist. |
| Stryker public external TCP connections | Supported | Exact collection logic exists. |
| Stryker RDP / Remote Assistance exposure | Supported | Exact triage, containment, and reversal logic exist. |
| Stryker vendor/local account handling | Supported | Disable and re-enable flows exist via `VendorAccountsFile`. |
| Stryker scheduled-task persistence hunting | Partial | Task Scheduler events are collected, but actor-specific persistence attribution is not hardcoded. |
| Stryker process chain analysis | Partial | Processes include `ParentProcessId`, but the search-hit corpus does not implement the exact `4688` process tree query you supplied. |
| Stryker HTTPS to public IPs | Partial | The detector captures public TCP connections generally, not HTTPS-specific flows. |
| Stryker vendor -> MSP -> facility trust chain | Partial | The package narrative references vendor-linked disruption and downstream exposure, but there is no explicit trust-chain graph or provenance logic. |
| Stryker Defender-disabling or EDR-bypass behavior | Not found | Defender logs are collected, but no actor-evolution claim is encoded in the corpus. |
| Historical-vs-current Stryker differential analysis | Not found | No historical comparison model exists in the search-hit corpus. |
| Negative claims such as what the actors do not do | Not found | The repository does not substantiate those exclusions. |

## Intelligence Gaps That Remain After Repo Analysis

- Initial access methods are not established by this corpus.
- The corpus does not prove whether `Handala` and `Stryker` are operationally linked.
- There is no live infrastructure, malware family, or packet-level C2 detail.
- There is no direct evidence of data staging destinations, exfiltration endpoints, or specific victim datasets.
- The Stryker content is intentionally local and facility-side; it does not claim visibility into vendor infrastructure.
- The Handala content is strongly healthcare and surgical-center oriented, which may not generalize beyond that environment.

## Dataset Artifacts Produced

- `manifest.json`: inventory, hashes, commit, and corpus counts.
- `documents.jsonl`: one JSON document per matched file with metadata, hit lines, full text, and Base64 copy of raw bytes.
- `match_lines.csv`: line-level hit export.
- `search_results.txt`: grep-style search output for the current commit.
- `full_corpus.txt`: concatenated full text of all 12 matched files.
- `source/`: exact copies of each matched file preserving relative paths.
- `operational_profile.json`: structured machine-readable summary of confirmed and unsupported claims.

## Recommended AI Ingestion Order

1. `operational_profile.json` for structured priors and support levels.
2. `documents.jsonl` for file-level retrieval and reasoning.
3. `match_lines.csv` or `search_results.txt` for quick filtering.
4. `full_corpus.txt` or `source/` when full-text grounding is required.
