[CmdletBinding()]
param(
    [int]$IntervalSec = 2,
    [int]$HistoryPoints = 180,
    [int]$LoopCount = 0,
    [string]$OutputDir,
    [string]$AnchorUrl,
    [string]$NodeId = $env:DEFEND_NODE_ID,
    [string]$AnchorToken = $env:DEFEND_ANCHOR_TOKEN
)

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot 'output\live-dashboard'
}
if ($IntervalSec -lt 1) { $IntervalSec = 1 }
if ($HistoryPoints -lt 10) { $HistoryPoints = 10 }

if (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$dashboardPath = Join-Path $OutputDir 'dashboard.html'
$jsonPath = Join-Path $OutputDir 'live.json'
$logPath = Join-Path $OutputDir 'monitor.log'
$samples = New-Object System.Collections.Generic.List[object]
$prev = -1
$iter = 0
$heartbeatUrls = New-Object System.Collections.Generic.List[string]
$seenHeartbeatAnchors = @{}
function Add-HeartbeatAnchors {
    param([string]$Source)
    if ([string]::IsNullOrWhiteSpace($Source)) { return }
    foreach ($anchor in ($Source -split '[,;]')) {
        $trimmedAnchor = $anchor.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmedAnchor)) { continue }
        $normalizedAnchor = $trimmedAnchor.TrimEnd('/')
        if ($seenHeartbeatAnchors.ContainsKey($normalizedAnchor)) { continue }
        $seenHeartbeatAnchors[$normalizedAnchor] = $true
        $heartbeatUrls.Add(('{0}/api/v1/heartbeat' -f $normalizedAnchor)) | Out-Null
    }
}
Add-HeartbeatAnchors -Source $AnchorUrl
Add-HeartbeatAnchors -Source $env:DEFEND_ANCHOR_URLS
Add-HeartbeatAnchors -Source $env:DEFEND_ANCHOR_URL
$heartbeatNodeId = if ([string]::IsNullOrWhiteSpace($NodeId)) { $env:COMPUTERNAME } else { $NodeId }
$heartbeatHeaders = @{}
if (-not [string]::IsNullOrWhiteSpace($AnchorToken)) {
    $heartbeatHeaders['Authorization'] = "Bearer $AnchorToken"
}

function Get-ConnectionCount {
    try {
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            return (Get-NetTCPConnection -ErrorAction SilentlyContinue | Measure-Object).Count
        }
    } catch {}
    try {
        $lines = netstat -an -p tcp 2>$null
        if ($lines) {
            return (($lines | Where-Object { $_ -match '^\s*TCP\s+' }) | Measure-Object).Count
        }
    } catch {}
    return 0
}

function Write-Dashboard {
    param(
        [int]$CurrentCount,
        [string]$Trend,
        [string]$Presence,
        [object[]]$Recent
    )

    $rows = @($Recent | Select-Object -Last 25)
    $rowsHtml = foreach ($r in $rows) {
        "<tr><td>$($r.ts)</td><td>$($r.count)</td><td>$($r.trend)</td></tr>"
    }

    $trendClass = if ($Trend -eq 'UP') { 'up' } elseif ($Trend -eq 'DOWN') { 'down' } else { 'steady' }
    $presenceClass = if ($Presence -eq 'YES') { 'yes' } else { 'no' }

    $html = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="$IntervalSec">
  <title>Live Connection Dashboard</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background:#0f172a; color:#e2e8f0; }
    .grid { display:grid; grid-template-columns: repeat(3,minmax(180px,1fr)); gap:12px; max-width:900px; }
    .card { background:#111827; border:1px solid #334155; border-radius:10px; padding:14px; }
    .label { color:#94a3b8; font-size:12px; }
    .value { font-size:30px; font-weight:700; margin-top:6px; }
    .yes{color:#22c55e;} .no{color:#f59e0b;} .up{color:#22c55e;} .down{color:#ef4444;} .steady{color:#38bdf8;}
    table { margin-top:18px; border-collapse:collapse; width:100%; max-width:900px; }
    th,td { border:1px solid #334155; padding:8px; font-size:12px; text-align:left; }
    th { color:#94a3b8; font-weight:600; }
  </style>
</head>
<body>
  <h2>Live Connection Dashboard</h2>
  <div class="grid">
    <div class="card"><div class="label">Connections Present</div><div class="value $presenceClass">$Presence</div></div>
    <div class="card"><div class="label">Current Count</div><div class="value">$CurrentCount</div></div>
    <div class="card"><div class="label">Trend</div><div class="value $trendClass">$Trend</div></div>
  </div>
  <table>
    <thead><tr><th>Timestamp</th><th>Count</th><th>Trend</th></tr></thead>
    <tbody>
      $($rowsHtml -join "`n")
    </tbody>
  </table>
</body>
</html>
"@

    $html | Set-Content -LiteralPath $dashboardPath -Encoding UTF8
}

Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Live monitor started. Dashboard: $dashboardPath"
while ($true) {
    $iter++
    $count = [int](Get-ConnectionCount)
    $trend = 'STEADY'
    if ($prev -ge 0) {
        if ($count -gt $prev) { $trend = 'UP' }
        elseif ($count -lt $prev) { $trend = 'DOWN' }
    }
    $prev = $count
    $presence = if ($count -gt 0) { 'YES' } else { 'NO' }
    $presenceBool = ($count -gt 0)
    $heartbeatTrend = switch ($trend) {
        'UP' { 'up' }
        'DOWN' { 'down' }
        default { 'steady' }
    }

    $sample = [ordered]@{
        ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        count = $count
        trend = $trend
    }

    if ($heartbeatUrls.Count -gt 0) {
        $heartbeatPayload = [ordered]@{
            node_id = $heartbeatNodeId
            platform = 'windows'
            connections_present = $presenceBool
            current_count = $count
            trend = $heartbeatTrend
            updated_at = (Get-Date).ToString('o')
        }
        $invokeParams = @{
            Method = 'Post'
            ContentType = 'application/json'
            Body = ($heartbeatPayload | ConvertTo-Json -Depth 4 -Compress)
            ErrorAction = 'Stop'
        }
        if ($heartbeatHeaders.Count -gt 0) {
            $invokeParams['Headers'] = $heartbeatHeaders
        }

        $heartbeatSucceeded = $false
        $heartbeatErrors = New-Object System.Collections.Generic.List[string]
        foreach ($heartbeatUrl in $heartbeatUrls) {
            try {
                $invokeParams['Uri'] = $heartbeatUrl
                Invoke-RestMethod @invokeParams | Out-Null
                $heartbeatSucceeded = $true
                break
            } catch {
                $errMsg = $_.Exception.Message -replace '\s+', ' '
                $heartbeatErrors.Add(("uri={0} msg={1}" -f $heartbeatUrl, $errMsg)) | Out-Null
            }
        }

        if (-not $heartbeatSucceeded -and $heartbeatErrors.Count -gt 0) {
            $hbLine = "[{0}] heartbeat_error attempts={1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), ($heartbeatErrors -join '; ')
            $hbLine | Add-Content -LiteralPath $logPath -Encoding UTF8
        }
    }

    $samples.Add([pscustomobject]$sample) | Out-Null
    while ($samples.Count -gt $HistoryPoints) { $samples.RemoveAt(0) }

    $payload = [ordered]@{
        updated_at = (Get-Date).ToString('o')
        interval_sec = $IntervalSec
        connections_present = $presence
        current_count = $count
        trend = $trend
        history = @($samples.ToArray())
    }
    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Write-Dashboard -CurrentCount $count -Trend $trend -Presence $presence -Recent @($samples.ToArray())

    $line = "[{0}] count={1} trend={2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $count, $trend
    $line | Add-Content -LiteralPath $logPath -Encoding UTF8
    Write-Host $line

    if ($LoopCount -gt 0 -and $iter -ge $LoopCount) { break }
    Start-Sleep -Seconds $IntervalSec
}

Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Live monitor stopped."
