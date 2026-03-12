[CmdletBinding()]
param(
    [int]$HoursBack = 72,
    [string]$DetectionDir,
    [string]$ContainmentDir,
    [string]$FacilityName = "",
    [string]$FacilityAddress = "",
    [string]$PrimaryContact = "",
    [string]$PrimaryRole = "",
    [string]$PrimaryPhone = "",
    [string]$PrimaryEmail = "",
    [switch]$CreateZip,
    [string]$OutputDir = (Join-Path -Path $PWD -ChildPath ("stryker-federal-" + (Get-Date -Format "yyyyMMdd-HHmmss")))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-Note {
    param([Parameter(Mandatory = $true)][string]$Message)
    $script:Notes.Add(("{0} {1}" -f (Get-Date -Format "o"), $Message))
}

function Save-Notes {
    $script:Notes | Set-Content -LiteralPath (Join-Path $OutputDir "collection-notes.log") -Encoding UTF8
}

function Export-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$InputObject
    )
    $InputObject | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Save-TextOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )

    try {
        & $Script | Out-String -Width 4096 | Set-Content -LiteralPath $Path -Encoding UTF8
        Write-Note "Wrote text output: $Path"
    }
    catch {
        Write-Note "Failed to write text output $Path: $($_.Exception.Message)"
    }
}

function Save-CsvOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )

    try {
        & $Script | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
        Write-Note "Wrote CSV output: $Path"
    }
    catch {
        Write-Note "Failed to write CSV output $Path: $($_.Exception.Message)"
    }
}

function Save-JsonOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )

    try {
        $result = & $Script
        Export-JsonFile -Path $Path -InputObject $result
        Write-Note "Wrote JSON output: $Path"
    }
    catch {
        Write-Note "Failed to write JSON output $Path: $($_.Exception.Message)"
    }
}

function Copy-IfPresent {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationDir
    )

    if (-not (Test-Path -LiteralPath $SourcePath)) {
        Write-Note "Source not found for copy: $SourcePath"
        return
    }

    Copy-Item -LiteralPath $SourcePath -Destination $DestinationDir -Force
    Write-Note "Copied artifact: $SourcePath"
}

function Resolve-ExecutablePath {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $trimmed = $Text.Trim()
    if ($trimmed.StartsWith('"')) {
        $quoted = [regex]::Match($trimmed, '^"([^"]+\.exe)"', 'IgnoreCase')
        if ($quoted.Success) {
            return $quoted.Groups[1].Value
        }
    }

    $unquoted = [regex]::Match($trimmed, '^([^ ]+\.exe)', 'IgnoreCase')
    if ($unquoted.Success) {
        return $unquoted.Groups[1].Value
    }

    return $null
}

function Get-TriageArtifact {
    if (-not $DetectionDir) {
        return $null
    }

    $path = Join-Path $DetectionDir "triage.json"
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Note "Triage artifact not found: $path"
        return $null
    }

    try {
        Write-Note "Loaded triage artifact: $path"
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Note "Failed to parse triage artifact $path: $($_.Exception.Message)"
        return $null
    }
}

function Export-EventLogWindow {
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][int]$Hours
    )

    $milliseconds = [int64]$Hours * 60 * 60 * 1000
    $query = "*[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"

    try {
        & wevtutil.exe epl $LogName $DestinationPath "/ow:true" "/q:$query" | Out-Null
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $DestinationPath)) {
            Write-Note "Exported EVTX log $LogName to $DestinationPath"
        }
        else {
            Write-Note "wevtutil returned exit code $LASTEXITCODE while exporting $LogName"
        }
    }
    catch {
        Write-Note "Failed to export EVTX log $LogName: $($_.Exception.Message)"
    }
}

function Get-RemoteSupportHashes {
    param($Triage)

    $paths = New-Object System.Collections.Generic.HashSet[string]

    if ($Triage) {
        foreach ($svc in @($Triage.RemoteSupportFootprint.Services)) {
            $path = Resolve-ExecutablePath -Text $svc.PathName
            if ($path -and (Test-Path -LiteralPath $path)) {
                [void]$paths.Add($path)
            }
        }

        foreach ($proc in @($Triage.RemoteSupportFootprint.Processes)) {
            if ($proc.ExecutablePath -and (Test-Path -LiteralPath $proc.ExecutablePath)) {
                [void]$paths.Add($proc.ExecutablePath)
            }
        }
    }

    foreach ($path in $paths) {
        try {
            $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop
            [pscustomobject]@{
                Path = $hash.Path
                Algorithm = $hash.Algorithm
                Hash = $hash.Hash
            }
        }
        catch {
            Write-Note "Failed to hash $path: $($_.Exception.Message)"
        }
    }
}

function Get-PublicConnectionProcessHashes {
    $connections = @()
    try {
        $connections = @(Get-NetTCPConnection -State Established -ErrorAction Stop |
            Where-Object {
                $_.RemoteAddress -notmatch "^(127\.|0\.0\.0\.0|::1|fe80:)" -and
                $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)"
            })
    }
    catch {
        Write-Note "Failed to enumerate public established TCP connections: $($_.Exception.Message)"
    }

    $paths = New-Object System.Collections.Generic.HashSet[string]
    foreach ($conn in $connections) {
        try {
            $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($conn.OwningProcess)" -ErrorAction Stop
            if ($process.ExecutablePath -and (Test-Path -LiteralPath $process.ExecutablePath)) {
                [void]$paths.Add($process.ExecutablePath)
            }
        }
        catch {
            Write-Note "Failed to resolve executable for PID $($conn.OwningProcess): $($_.Exception.Message)"
        }
    }

    foreach ($path in $paths) {
        try {
            $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop
            [pscustomobject]@{
                Path = $hash.Path
                Algorithm = $hash.Algorithm
                Hash = $hash.Hash
            }
        }
        catch {
            Write-Note "Failed to hash public-connection process $path: $($_.Exception.Message)"
        }
    }
}

function Write-FederalReportDraft {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Triage
    )

    $remoteSupport = @()
    if ($Triage) {
        $remoteSupport += @($Triage.RemoteSupportFootprint.InstalledPrograms | ForEach-Object { $_.DisplayName })
        $remoteSupport += @($Triage.RemoteSupportFootprint.Services | ForEach-Object { $_.DisplayName })
        $remoteSupport += @($Triage.RemoteSupportFootprint.Processes | ForEach-Object { $_.Name })
    }
    $remoteSupport = @($remoteSupport | Where-Object { $_ } | Sort-Object -Unique)
    $publicConnectionCount = if ($Triage) { @($Triage.Network.PublicTcpConnections).Count } else { 0 }
    $securityEventCount = if ($Triage) { @($Triage.Events.Security).Count } else { 0 }
    $serviceEventCount = if ($Triage) { @($Triage.Events.Services).Count } else { 0 }
    $powerShellEventCount = if ($Triage) { @($Triage.Events.PowerShell).Count } else { 0 }
    $defenderEventCount = if ($Triage) { @($Triage.Events.Defender).Count } else { 0 }
    $rdpEventCount = if ($Triage) { @($Triage.Events.RemoteDesktop).Count } else { 0 }

    $lines = @(
        "Incident title: Potential downstream impact from Stryker network disruption"
        "Facility name: $FacilityName"
        "Facility address: $FacilityAddress"
        "Primary contact: $PrimaryContact"
        "Primary contact role: $PrimaryRole"
        "Primary contact phone: $PrimaryPhone"
        "Primary contact email: $PrimaryEmail"
        ""
        "Package generated at: $(Get-Date -Format o)"
        "Hours covered: $HoursBack"
        "Collector elevated: $(Test-IsAdministrator)"
        ""
        "Reason for report:"
        "- Possible downstream exposure from Stryker-connected trust paths or vendor-linked disruption."
        ""
        "Local observations summary:"
        "- Public established TCP connections at collection time: $publicConnectionCount"
        "- Remote support programs or services seen: $(if ($remoteSupport) { $remoteSupport -join ', ' } else { 'none identified from triage artifact' })"
        "- Recent Security events captured: $securityEventCount"
        "- Recent service install events (7045): $serviceEventCount"
        "- Recent PowerShell operational events: $powerShellEventCount"
        "- Recent Defender operational events: $defenderEventCount"
        "- Recent RDP connection events: $rdpEventCount"
        ""
        "Patient care impact:"
        "- Fill in exact case delays, cancellations, backup workflows, and any safety concerns."
        ""
        "Containment actions already available in this package:"
        "- Review defend-stryker-local.ps1 output and actions.log if containment has been run."
        ""
        "Attachments prepared in this package:"
        "- triage.json and summary.txt from local detector, if supplied"
        "- EVTX exports for Security, System, PowerShell, Defender, Task Scheduler, and RDP where export succeeded"
        "- Current network, user, service, scheduled task, and firewall snapshots"
        "- SHA256 hashes for remote-support binaries and processes with public TCP sessions, where available"
        ""
        "Recommended reporting order:"
        "1. CISA / DHS first for coordination and technical assistance"
        "2. FBI in parallel via local field office or IC3"
        "3. NSA only as a secondary coordination path or if specifically requested / DOD-linked"
        ""
        "CISA / DHS:"
        "- Services Portal / incident reporting"
        "- 1-844-Say-CISA (1-844-729-2472)"
        "- report@cisa.gov"
        ""
        "FBI:"
        "- Local FBI field office"
        "- IC3 at ic3.gov"
        "- CyWatch 24/7 phone: 1-855-292-3937"
        ""
        "NSA:"
        "- NSA Cybersecurity Contact Us form"
        "- Use for cybersecurity collaboration or if referred; not the primary victim intake path for most healthcare providers"
    )

    $lines | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Note "Wrote federal report draft: $Path"
}

New-Directory -Path $OutputDir
New-Directory -Path (Join-Path $OutputDir "raw")
New-Directory -Path (Join-Path $OutputDir "logs")
New-Directory -Path (Join-Path $OutputDir "hashes")
New-Directory -Path (Join-Path $OutputDir "imports")

$script:Notes = New-Object System.Collections.Generic.List[string]
Write-Note "Starting federal package build"
if (-not (Test-IsAdministrator)) {
    Write-Note "Collector is not elevated; some data sources and EVTX exports may be incomplete"
}

$triage = Get-TriageArtifact

if ($DetectionDir) {
    Copy-IfPresent -SourcePath (Join-Path $DetectionDir "triage.json") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $DetectionDir "summary.txt") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $DetectionDir "public-tcp-connections.csv") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $DetectionDir "security-events.csv") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $DetectionDir "service-install-events.csv") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $DetectionDir "powershell-events.csv") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $DetectionDir "defender-events.csv") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $DetectionDir "rdp-events.csv") -DestinationDir (Join-Path $OutputDir "imports")
}

if ($ContainmentDir) {
    Copy-IfPresent -SourcePath (Join-Path $ContainmentDir "actions.log") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $ContainmentDir "pre-change-state.json") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $ContainmentDir "post-change-state.json") -DestinationDir (Join-Path $OutputDir "imports")
    Copy-IfPresent -SourcePath (Join-Path $ContainmentDir "state-snapshot.json") -DestinationDir (Join-Path $OutputDir "imports")
}

Save-JsonOutput -Path (Join-Path $OutputDir "raw\host-snapshot.json") -Script {
    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString("o")
        RunningAsAdministrator = Test-IsAdministrator
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        Domain = $env:USERDOMAIN
        PSVersion = $PSVersionTable.PSVersion.ToString()
        OperatingSystem = try { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | Select-Object Caption, Version, BuildNumber, LastBootUpTime } catch { $null }
        ComputerSystem = try { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop | Select-Object Manufacturer, Model, Domain, PartOfDomain } catch { $null }
    }
}

Save-CsvOutput -Path (Join-Path $OutputDir "raw\services.csv") -Script {
    Get-CimInstance Win32_Service -ErrorAction Stop |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName
}

Save-CsvOutput -Path (Join-Path $OutputDir "raw\scheduled-tasks.csv") -Script {
    Get-ScheduledTask -ErrorAction Stop |
        Select-Object TaskPath, TaskName, State, Author, Description
}

Save-CsvOutput -Path (Join-Path $OutputDir "raw\local-users.csv") -Script {
    Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop |
        Select-Object Name, Disabled, Lockout, PasswordRequired, SID
}

Save-CsvOutput -Path (Join-Path $OutputDir "raw\firewall-rules-focus.csv") -Script {
    Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object {
            $_.DisplayGroup -in @("Remote Desktop", "Remote Assistance", "Stryker Response Temporary") -or
            $_.DisplayName -like "Stryker Response Block *"
        } |
        Select-Object Name, DisplayName, Enabled, Direction, Action, Profile, DisplayGroup
}

Save-CsvOutput -Path (Join-Path $OutputDir "raw\public-tcp-connections-live.csv") -Script {
    Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object {
            $_.RemoteAddress -notmatch "^(127\.|0\.0\.0\.0|::1|fe80:)" -and
            $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)"
        } |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
}

Save-JsonOutput -Path (Join-Path $OutputDir "raw\defender-status.json") -Script {
    try {
        Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        [pscustomobject]@{
            Error = $_.Exception.Message
        }
    }
}

Save-TextOutput -Path (Join-Path $OutputDir "raw\ipconfig-all.txt") -Script { & ipconfig.exe /all }
Save-TextOutput -Path (Join-Path $OutputDir "raw\route-print.txt") -Script { & route.exe print }
Save-TextOutput -Path (Join-Path $OutputDir "raw\arp-a.txt") -Script { & arp.exe -a }
Save-TextOutput -Path (Join-Path $OutputDir "raw\netstat-ano.txt") -Script { & netstat.exe -ano }
Save-TextOutput -Path (Join-Path $OutputDir "raw\quser.txt") -Script { & quser.exe }
Save-TextOutput -Path (Join-Path $OutputDir "raw\net-user.txt") -Script { & net.exe user }
Save-TextOutput -Path (Join-Path $OutputDir "raw\firewall-profiles.txt") -Script { & netsh.exe advfirewall show allprofiles }
Save-TextOutput -Path (Join-Path $OutputDir "raw\schtasks-query.txt") -Script { & schtasks.exe /query /fo LIST /v }

$remoteHashes = @(Get-RemoteSupportHashes -Triage $triage)
if ($remoteHashes) {
    $remoteHashes | Export-Csv -LiteralPath (Join-Path $OutputDir "hashes\remote-support-sha256.csv") -NoTypeInformation -Encoding UTF8
    Write-Note "Wrote remote support hashes"
}
else {
    Write-Note "No remote support executable hashes were available"
}

$publicProcessHashes = @(Get-PublicConnectionProcessHashes)
if ($publicProcessHashes) {
    $publicProcessHashes | Export-Csv -LiteralPath (Join-Path $OutputDir "hashes\public-connection-process-sha256.csv") -NoTypeInformation -Encoding UTF8
    Write-Note "Wrote public connection process hashes"
}
else {
    Write-Note "No process hashes were generated for public TCP connections"
}

Export-EventLogWindow -LogName "Security" -DestinationPath (Join-Path $OutputDir "logs\Security.evtx") -Hours $HoursBack
Export-EventLogWindow -LogName "System" -DestinationPath (Join-Path $OutputDir "logs\System.evtx") -Hours $HoursBack
Export-EventLogWindow -LogName "Microsoft-Windows-PowerShell/Operational" -DestinationPath (Join-Path $OutputDir "logs\PowerShell-Operational.evtx") -Hours $HoursBack
Export-EventLogWindow -LogName "Microsoft-Windows-Windows Defender/Operational" -DestinationPath (Join-Path $OutputDir "logs\Defender-Operational.evtx") -Hours $HoursBack
Export-EventLogWindow -LogName "Microsoft-Windows-TaskScheduler/Operational" -DestinationPath (Join-Path $OutputDir "logs\TaskScheduler-Operational.evtx") -Hours $HoursBack
Export-EventLogWindow -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -DestinationPath (Join-Path $OutputDir "logs\RDP-Operational.evtx") -Hours $HoursBack

Write-FederalReportDraft -Path (Join-Path $OutputDir "federal-report-draft.txt") -Triage $triage

$manifest = [ordered]@{
    GeneratedAt = (Get-Date).ToString("o")
    HoursBack = $HoursBack
    RunningAsAdministrator = Test-IsAdministrator
    DetectionDir = $DetectionDir
    ContainmentDir = $ContainmentDir
    FacilityName = $FacilityName
    FacilityAddress = $FacilityAddress
    PrimaryContact = $PrimaryContact
    PrimaryRole = $PrimaryRole
    PrimaryPhone = $PrimaryPhone
    PrimaryEmail = $PrimaryEmail
    OutputDir = $OutputDir
}
Export-JsonFile -Path (Join-Path $OutputDir "package-manifest.json") -InputObject $manifest

if ($CreateZip) {
    try {
        $zipPath = "$OutputDir.zip"
        Compress-Archive -Path (Join-Path $OutputDir "*") -DestinationPath $zipPath -Force
        Write-Note "Created zip archive: $zipPath"
    }
    catch {
        Write-Note "Failed to create zip archive: $($_.Exception.Message)"
    }
}

Save-Notes
Write-Host "Federal package written to $OutputDir"
