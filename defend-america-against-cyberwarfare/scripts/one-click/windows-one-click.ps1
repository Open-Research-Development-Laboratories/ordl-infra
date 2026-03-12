[CmdletBinding()]
param(
    [string]$AnchorUrl = $(if ([string]::IsNullOrWhiteSpace($env:DEFEND_ANCHOR_URL)) { 'https://defend.ordl.org' } else { $env:DEFEND_ANCHOR_URL }),
    [string]$NodeId = $(if ([string]::IsNullOrWhiteSpace($env:DEFEND_NODE_ID)) { $env:COMPUTERNAME } else { $env:DEFEND_NODE_ID }),
    [string]$AnchorToken = $env:DEFEND_ANCHOR_TOKEN,
    [int]$IntervalSec = 2,
    [int]$PollSec = 10,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
$winScripts = Join-Path $repoRoot 'scripts\windows'
$iocFile = Join-Path $repoRoot 'iocs\seed-iocs.txt'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$endpointOut = Join-Path $repoRoot ("output\oneclick-endpoint-$timestamp")
$monitorOut = if ([string]::IsNullOrWhiteSpace($env:DEFEND_MONITOR_OUTPUT_DIR)) { Join-Path $env:USERPROFILE '.defendmesh\live-dashboard' } else { $env:DEFEND_MONITOR_OUTPUT_DIR }
$agentOut = if ([string]::IsNullOrWhiteSpace($env:DEFEND_AGENT_OUTPUT_DIR)) { Join-Path $env:USERPROFILE '.defendmesh\node-agent' } else { $env:DEFEND_AGENT_OUTPUT_DIR }

function Stop-ScriptProcess {
    param([string]$ScriptName)
    try {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine -like "*$ScriptName*" } |
            ForEach-Object {
                try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
            }
    } catch {}
}

New-Item -ItemType Directory -Path $monitorOut -Force | Out-Null
New-Item -ItemType Directory -Path $agentOut -Force | Out-Null

Write-Host "[1/4] Running endpoint audit..."
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $winScripts 'defend-endpoint.ps1') -Mode audit -IocFile $iocFile -OutputDir $endpointOut

Write-Host "[2/4] Stopping previous one-click monitor/agent if running..."
Stop-ScriptProcess -ScriptName 'connection-monitor.ps1'
Stop-ScriptProcess -ScriptName 'node-agent.ps1'

Write-Host "[3/4] Starting live monitor..."
$monitorArgs = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $winScripts 'connection-monitor.ps1'),
    '-IntervalSec', "$IntervalSec",
    '-OutputDir', $monitorOut,
    '-AnchorUrl', $AnchorUrl,
    '-NodeId', $NodeId
)
if (-not [string]::IsNullOrWhiteSpace($AnchorToken)) {
    $monitorArgs += @('-AnchorToken', $AnchorToken)
}
$monProc = Start-Process -FilePath 'powershell.exe' -ArgumentList $monitorArgs -WindowStyle Hidden -PassThru
($monProc.Id | Out-String).Trim() | Set-Content -LiteralPath (Join-Path $monitorOut '.pid') -Encoding ASCII

Write-Host "[4/4] Starting node agent..."
$agentArgs = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $winScripts 'node-agent.ps1'),
    '-AnchorUrl', $AnchorUrl,
    '-NodeId', $NodeId,
    '-PollSec', "$PollSec",
    '-OutputDir', $agentOut
)
if (-not [string]::IsNullOrWhiteSpace($AnchorToken)) {
    $agentArgs += @('-AnchorToken', $AnchorToken)
}
$agentProc = Start-Process -FilePath 'powershell.exe' -ArgumentList $agentArgs -WindowStyle Hidden -PassThru
($agentProc.Id | Out-String).Trim() | Set-Content -LiteralPath (Join-Path $agentOut '.pid') -Encoding ASCII

$dashboardPath = Join-Path $monitorOut 'dashboard.html'

Write-Host ""
Write-Host "One-click defense is active."
Write-Host "Anchor route: $AnchorUrl"
Write-Host "Node id: $NodeId"
Write-Host "Endpoint summary: $endpointOut\\summary.json"
Write-Host "Local dashboard: $dashboardPath"
Write-Host "Monitor PID: $($monProc.Id)"
Write-Host "Agent PID: $($agentProc.Id)"
if ([string]::IsNullOrWhiteSpace($AnchorToken)) {
    Write-Host "WARNING: no anchor token set; heartbeat/task auth may fail on protected anchor."
}

if (-not $NoOpen) {
    try { Start-Process $AnchorUrl | Out-Null } catch {}
    try { if (Test-Path -LiteralPath $dashboardPath) { Start-Process $dashboardPath | Out-Null } } catch {}
}
