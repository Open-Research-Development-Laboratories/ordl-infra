[CmdletBinding()]
param(
    [ValidateSet('audit','remediate')]
    [string]$Mode = 'audit',
    [string]$OutputDir,
    [string]$IocFile,
    [string]$ControlFile,
    [string]$ExpectedControlToken = $env:DEFEND_CONTROL_TOKEN,
    [switch]$BroadcastAlert
)

$ErrorActionPreference = 'Continue'
$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot ("output\\defend-endpoint-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
if ([string]::IsNullOrWhiteSpace($IocFile)) {
    $IocFile = Join-Path $repoRoot 'iocs\seed-iocs.txt'
}
if ([string]::IsNullOrWhiteSpace($ControlFile)) {
    $ControlFile = Join-Path $repoRoot 'control\mode-control.txt'
}

$summaryPath = Join-Path $OutputDir 'summary.json'
$reportPath = Join-Path $OutputDir 'report.txt'
$dashboardPath = Join-Path $OutputDir 'dashboard.html'
$alertPath = Join-Path $OutputDir 'awareness.log'
$quarantineDir = Join-Path $OutputDir 'quarantine'
$stageLog = New-Object System.Collections.Generic.List[string]

function Write-Stage {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $stageLog.Add($line) | Out-Null
    Write-Host $line
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-Awareness {
    param(
        [ValidateSet('INFO','WARN','ALERT')]
        [string]$Level = 'INFO',
        [string]$Message
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ALERT' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line -ForegroundColor Cyan }
    }
    try { Add-Content -LiteralPath $alertPath -Value $line -Encoding UTF8 } catch {}
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('DefendEndpoint')) {
            New-EventLog -LogName Application -Source 'DefendEndpoint' | Out-Null
        }
        $etype = if ($Level -eq 'ALERT') { 'Warning' } elseif ($Level -eq 'WARN') { 'Information' } else { 'Information' }
        Write-EventLog -LogName Application -Source 'DefendEndpoint' -EventId 4100 -EntryType $etype -Message $Message
    } catch {}
    if ($BroadcastAlert) {
        try {
            $msg = ($Message -replace '[\r\n]+',' ').Trim()
            & msg.exe * $msg | Out-Null
        } catch {}
    }
}

function Normalize-Path {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $s = $Value.Trim().Trim('"').Trim("'")
    if ($s -match '^%') { $s = [Environment]::ExpandEnvironmentVariables($s) }
    try {
        if ([IO.Path]::IsPathRooted($s)) {
            $s = [IO.Path]::GetFullPath($s)
        }
    } catch {}
    return $s
}

function Extract-ExeFromCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $t = $Command.Trim()
    if ($t.StartsWith('"')) {
        $m = [regex]::Match($t, '^"([^"]+)"')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    return ($t -split '\s+',2)[0]
}

function Read-Iocs {
    param([string]$Path)
    $r = [ordered]@{ path=@{}; sha256=@{}; name=@{}; ip=@{} }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [pscustomobject]$r }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $l = $line.Trim()
        if (-not $l -or $l.StartsWith('#')) { continue }
        $parts = $l.Split(':',2)
        if ($parts.Count -ne 2) { continue }
        $k = $parts[0].Trim().ToLowerInvariant()
        $v = $parts[1].Trim()
        if (-not $v) { continue }
        switch ($k) {
            'path'   { $r.path[(Normalize-Path $v).ToLowerInvariant()] = $true }
            'sha256' { $r.sha256[$v.ToLowerInvariant()] = $true }
            'name'   { $r.name[$v.ToLowerInvariant()] = $true }
            'ip'     { $r.ip[$v.ToLowerInvariant()] = $true }
        }
    }
    return [pscustomobject]$r
}

function Get-Sha256 {
    param([string]$Path)
    try {
        if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } catch {}
    return $null
}

Ensure-Dir $OutputDir
Ensure-Dir (Split-Path -Parent $ControlFile)

$requestedMode = $Mode
$controlSource = 'cli'
if (Test-Path -LiteralPath $ControlFile -PathType Leaf) {
    Write-Stage 'Loading control file'
    $rawControl = @{}
    foreach ($line in (Get-Content -LiteralPath $ControlFile -ErrorAction SilentlyContinue)) {
        $l = $line.Trim()
        if (-not $l -or $l.StartsWith('#')) { continue }
        $parts = $l -split '[:=]', 2
        if ($parts.Count -eq 2) {
            $rawControl[$parts[0].Trim().ToLowerInvariant()] = $parts[1].Trim()
        }
    }
    $candidateMode = $null
    if ($rawControl.ContainsKey('mode')) { $candidateMode = $rawControl['mode'].ToLowerInvariant() }
    if ($candidateMode -in @('audit','remediate')) {
        $tokenOK = $true
        if (-not [string]::IsNullOrWhiteSpace($ExpectedControlToken)) {
            $tokenOK = ($rawControl.ContainsKey('token') -and ($rawControl['token'] -eq $ExpectedControlToken))
        }
        if ($tokenOK) {
            $Mode = $candidateMode
            $controlSource = 'control-file'
        } else {
            $Mode = 'audit'
            $controlSource = 'control-file-invalid-token'
            Write-Awareness -Level 'WARN' -Message 'Control file token invalid; forcing audit mode.'
        }
    }
}
if ($Mode -eq 'remediate') { Ensure-Dir $quarantineDir }

Write-Stage "Starting defend-endpoint ($Mode)"
Write-Awareness -Level 'INFO' -Message ("DefendEndpoint run started. requested_mode={0} effective_mode={1} source={2}" -f $requestedMode, $Mode, $controlSource)
if ($Mode -eq 'remediate') {
    Write-Awareness -Level 'ALERT' -Message 'Remediation mode is ACTIVE on this endpoint.'
}
Write-Stage 'Loading IOC file'
$iocs = Read-Iocs $IocFile

$summary = [ordered]@{
    mode = $Mode
    requested_mode = $requestedMode
    control_source = $controlSource
    started_at = (Get-Date).ToString('o')
    output_dir = $OutputDir
    dashboard = $dashboardPath
    ioc_file = $IocFile
    control_file = $ControlFile
    host = [ordered]@{}
    counts = [ordered]@{}
    findings = [ordered]@{
        runkey_hits = @()
        process_hits = @()
        service_hits = @()
        task_hits = @()
        network_ip_hits = @()
        file_hits = @()
    }
    remediation = @()
    stages = @()
}

Write-Stage 'Collecting host metadata'
$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem } catch {}
$summary.host = [ordered]@{
    computer = $env:COMPUTERNAME
    user = $env:USERNAME
    os = $os.Caption
    version = $os.Version
    build = $os.BuildNumber
}

Write-Stage 'Collecting startup run keys'
$runEntries = New-Object System.Collections.Generic.List[object]
$runPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runPaths) {
    try {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $item = Get-ItemProperty -LiteralPath $k
        foreach ($p in $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            $exe = Normalize-Path (Extract-ExeFromCommand ([string]$p.Value))
            $runEntries.Add([pscustomobject]@{ key=$k; value_name=$p.Name; command=[string]$p.Value; exe=$exe }) | Out-Null
        }
    } catch {}
}

Write-Stage 'Collecting process inventory'
$procEntries = New-Object System.Collections.Generic.List[object]
try {
    foreach ($p in Get-CimInstance Win32_Process) {
        $exe = Normalize-Path $p.ExecutablePath
        $sha = Get-Sha256 $exe
        $procEntries.Add([pscustomobject]@{
            pid=[int]$p.ProcessId
            ppid=[int]$p.ParentProcessId
            name=[string]$p.Name
            exe=$exe
            sha256=$sha
            command=[string]$p.CommandLine
        }) | Out-Null
    }
} catch {}

Write-Stage 'Collecting service inventory'
$svcEntries = New-Object System.Collections.Generic.List[object]
try {
    foreach ($s in Get-CimInstance Win32_Service) {
        $exe = Normalize-Path (Extract-ExeFromCommand ([string]$s.PathName))
        $sha = Get-Sha256 $exe
        $svcEntries.Add([pscustomobject]@{
            name=[string]$s.Name
            display=[string]$s.DisplayName
            state=[string]$s.State
            start_mode=[string]$s.StartMode
            pid=[int]$s.ProcessId
            exe=$exe
            sha256=$sha
        }) | Out-Null
    }
} catch {}

Write-Stage 'Collecting scheduled tasks'
$taskEntries = New-Object System.Collections.Generic.List[object]
try {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        foreach ($t in Get-ScheduledTask) {
            $paths = @()
            foreach ($a in $t.Actions) {
                $ep = Normalize-Path $a.Execute
                if ($ep) { $paths += $ep }
            }
            $taskEntries.Add([pscustomobject]@{
                task=($t.TaskPath + $t.TaskName)
                state=[string]$t.State
                action_paths=@($paths | Select-Object -Unique)
            }) | Out-Null
        }
    }
} catch {}

Write-Stage 'Collecting network connections'
$netEntries = New-Object System.Collections.Generic.List[object]
try {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        foreach ($n in Get-NetTCPConnection) {
            $netEntries.Add([pscustomobject]@{
                local=("{0}:{1}" -f $n.LocalAddress,$n.LocalPort)
                remote=("{0}:{1}" -f $n.RemoteAddress,$n.RemotePort)
                state=[string]$n.State
                pid=[int]$n.OwningProcess
                remote_ip=[string]$n.RemoteAddress
            }) | Out-Null
        }
    }
} catch {}

Write-Stage 'Matching IOC indicators'
$hitPaths = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($r in $runEntries) {
    $reasons = @()
    if ($r.exe) {
        $lp = $r.exe.ToLowerInvariant()
        if ($iocs.path.ContainsKey($lp)) { $reasons += 'path' }
        $name = [IO.Path]::GetFileName($r.exe).ToLowerInvariant()
        if ($iocs.name.ContainsKey($name)) { $reasons += 'name' }
        $sha = Get-Sha256 $r.exe
        if ($sha -and $iocs.sha256.ContainsKey($sha)) { $reasons += 'sha256' }
        if ($reasons.Count -gt 0) {
            $summary.findings.runkey_hits += [pscustomobject]@{ key=$r.key; value_name=$r.value_name; exe=$r.exe; reasons=@($reasons|Select-Object -Unique) }
            $null = $hitPaths.Add($r.exe)
        }
    }
}

foreach ($p in $procEntries) {
    $reasons = @()
    if ($p.exe) {
        $lp = $p.exe.ToLowerInvariant()
        if ($iocs.path.ContainsKey($lp)) { $reasons += 'path' }
        $name = [string]$p.name
        if ($name -and $iocs.name.ContainsKey($name.ToLowerInvariant())) { $reasons += 'name' }
        if ($p.sha256 -and $iocs.sha256.ContainsKey($p.sha256)) { $reasons += 'sha256' }
        if ($reasons.Count -gt 0) {
            $summary.findings.process_hits += [pscustomobject]@{ pid=$p.pid; name=$p.name; exe=$p.exe; reasons=@($reasons|Select-Object -Unique) }
            $null = $hitPaths.Add($p.exe)
        }
    }
}

foreach ($s in $svcEntries) {
    $reasons = @()
    if ($s.exe) {
        $lp = $s.exe.ToLowerInvariant()
        if ($iocs.path.ContainsKey($lp)) { $reasons += 'path' }
        if ($iocs.name.ContainsKey($s.name.ToLowerInvariant())) { $reasons += 'name' }
        if ($s.sha256 -and $iocs.sha256.ContainsKey($s.sha256)) { $reasons += 'sha256' }
        if ($reasons.Count -gt 0) {
            $summary.findings.service_hits += [pscustomobject]@{ name=$s.name; exe=$s.exe; pid=$s.pid; reasons=@($reasons|Select-Object -Unique) }
            $null = $hitPaths.Add($s.exe)
        }
    }
}

foreach ($t in $taskEntries) {
    $taskReasons = @()
    foreach ($ap in $t.action_paths) {
        $lap = $ap.ToLowerInvariant()
        $sha = Get-Sha256 $ap
        $nm = [IO.Path]::GetFileName($ap).ToLowerInvariant()
        if ($iocs.path.ContainsKey($lap) -or ($sha -and $iocs.sha256.ContainsKey($sha)) -or $iocs.name.ContainsKey($nm)) {
            $taskReasons += $ap
            $null = $hitPaths.Add($ap)
        }
    }
    if ($taskReasons.Count -gt 0) {
        $summary.findings.task_hits += [pscustomobject]@{ task=$t.task; action_paths=@($taskReasons|Select-Object -Unique) }
    }
}

foreach ($n in $netEntries) {
    if ($n.remote_ip -and $iocs.ip.ContainsKey($n.remote_ip.ToLowerInvariant())) {
        $summary.findings.network_ip_hits += $n
    }
}

foreach ($hp in $hitPaths) {
    $summary.findings.file_hits += [pscustomobject]@{ path=$hp; sha256=(Get-Sha256 $hp) }
}

$summary.counts = [ordered]@{
    run_entries = $runEntries.Count
    processes = $procEntries.Count
    services = $svcEntries.Count
    tasks = $taskEntries.Count
    network_connections = $netEntries.Count
    runkey_hits = $summary.findings.runkey_hits.Count
    process_hits = $summary.findings.process_hits.Count
    service_hits = $summary.findings.service_hits.Count
    task_hits = $summary.findings.task_hits.Count
    network_ip_hits = $summary.findings.network_ip_hits.Count
    file_hits = $summary.findings.file_hits.Count
}

if ($Mode -eq 'remediate') {
    Write-Stage 'Remediation: stopping matched processes'
    $stopPids = @($summary.findings.process_hits | Select-Object -ExpandProperty pid -Unique)
    foreach ($pid in $stopPids) {
        try {
            Stop-Process -Id $pid -Force -ErrorAction Stop
            $summary.remediation += "stopped_process:$pid"
        } catch {
            $summary.remediation += "failed_stop_process:$pid"
        }
    }

    Write-Stage 'Remediation: removing matched run keys'
    foreach ($rk in $summary.findings.runkey_hits) {
        try {
            Remove-ItemProperty -LiteralPath $rk.key -Name $rk.value_name -ErrorAction Stop
            $summary.remediation += "removed_runkey:$($rk.key):$($rk.value_name)"
        } catch {
            $summary.remediation += "failed_remove_runkey:$($rk.key):$($rk.value_name)"
        }
    }

    Write-Stage 'Remediation: quarantining matched files'
    foreach ($f in $summary.findings.file_hits) {
        try {
            if (Test-Path -LiteralPath $f.path -PathType Leaf) {
                $dest = Join-Path $quarantineDir ((Get-Date -Format 'yyyyMMddHHmmssfff') + '_' + [IO.Path]::GetFileName($f.path))
                Move-Item -LiteralPath $f.path -Destination $dest -Force -ErrorAction Stop
                $summary.remediation += "quarantined:$($f.path)"
            }
        } catch {
            $summary.remediation += "failed_quarantine:$($f.path)"
        }
    }

    Write-Stage 'Remediation: blocking IOC IPs in firewall'
    foreach ($ip in $iocs.ip.Keys) {
        try {
            $rule = "DefendEndpoint-Block-" + ($ip -replace '[^A-Za-z0-9]','_')
            if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null
            }
            $summary.remediation += "blocked_ip:$ip"
        } catch {
            $summary.remediation += "failed_block_ip:$ip"
        }
    }
}

$summary.ended_at = (Get-Date).ToString('o')
$summary.stages = @($stageLog)

Write-Stage 'Writing report files'
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Stage 'Writing dashboard'
$connectionsPresent = $false
if ($summary.counts.network_connections -gt 0) { $connectionsPresent = $true }
$dashboardHtml = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Defend Endpoint Dashboard</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background:#0f172a; color:#e2e8f0; }
    .card { max-width: 520px; padding: 20px; border-radius: 12px; background:#111827; border:1px solid #334155; }
    .label { color:#94a3b8; font-size:13px; }
    .value { font-size:40px; font-weight:700; margin:8px 0 4px 0; }
    .yes { color:#22c55e; }
    .no { color:#f59e0b; }
    .meta { margin-top:14px; color:#94a3b8; font-size:12px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="label">Active Connections Present</div>
    <div class="value $(if ($connectionsPresent) { 'yes' } else { 'no' })">$(if ($connectionsPresent) { 'YES' } else { 'NO' })</div>
    <div class="meta">Mode: $Mode</div>
    <div class="meta">Updated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))</div>
  </div>
</body>
</html>
"@
$dashboardHtml | Set-Content -LiteralPath $dashboardPath -Encoding UTF8
@(
    "Mode: $Mode",
    "Started: $($summary.started_at)",
    "Ended: $($summary.ended_at)",
    "OutputDir: $OutputDir",
    "Dashboard: $dashboardPath",
    "IocFile: $IocFile",
    '',
    'Counts:',
    ($summary.counts.GetEnumerator() | ForEach-Object { "  $($_.Key): $($_.Value)" }),
    '',
    "Summary JSON: $summaryPath"
) | Set-Content -LiteralPath $reportPath -Encoding UTF8

Write-Stage "Done. Summary: $summaryPath"
Write-Awareness -Level 'INFO' -Message ("DefendEndpoint run completed. mode={0} hits={1}" -f $Mode, $summary.counts.file_hits)
