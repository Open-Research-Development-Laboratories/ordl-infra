$ErrorActionPreference = 'SilentlyContinue'

$homeBase = $env:USERPROFILE
if ([string]::IsNullOrWhiteSpace($homeBase)) {
    if ($env:HOMEDRIVE -and $env:HOMEPATH) {
        $homeBase = ('{0}{1}' -f $env:HOMEDRIVE, $env:HOMEPATH)
    } else {
        $homeBase = $env:TEMP
    }
}
$root = if ($env:DEFEND_ROOT_DIR) { $env:DEFEND_ROOT_DIR } else { Join-Path $homeBase '.defendmesh' }
$work = if ($env:DEFEND_WORK_DIR) { $env:DEFEND_WORK_DIR } else { Join-Path $env:TEMP 'defendmesh-bootstrap' }

function Stop-PidFileProcess {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        $pidValue = (Get-Content -LiteralPath $Path -ErrorAction Stop | Select-Object -First 1).Trim()
        if ($pidValue -match '^\d+$') {
            $pidInt = [int]$pidValue
            try { Stop-Process -Id $pidInt -Force -ErrorAction SilentlyContinue } catch {}
            Start-Sleep -Milliseconds 200
            if (Get-Process -Id $pidInt -ErrorAction SilentlyContinue) {
                try { taskkill /PID $pidInt /F | Out-Null } catch {}
            }
        }
    } catch {}
    try { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Output '[1/5] Stopping DefendMesh monitor/agent processes...'
$pidFiles = @(
    (Join-Path $root 'live-dashboard\monitor.pid'),
    (Join-Path $root 'live-dashboard\.pid'),
    (Join-Path $root 'node-agent\node-agent.pid'),
    (Join-Path $root 'node-agent\.pid'),
    '.\output\live-dashboard\monitor.pid',
    '.\output\live-dashboard\.pid',
    '.\output\node-agent\node-agent.pid',
    '.\output\node-agent\.pid',
    '.\output\oneclick-live-dashboard\.pid',
    '.\output\oneclick-node-agent\.pid'
)
foreach ($pidFile in $pidFiles) {
    Stop-PidFileProcess -Path $pidFile
}

Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -and (
        $_.CommandLine -like '*connection-monitor.ps1*' -or
        $_.CommandLine -like '*node-agent.ps1*' -or
        $_.CommandLine -like '*defendmesh-bootstrap*connection-monitor*' -or
        $_.CommandLine -like '*defendmesh-bootstrap*node-agent*'
    )
} | ForEach-Object {
    try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
    try { taskkill /PID $_.ProcessId /F | Out-Null } catch {}
}

Write-Output '[2/5] Removing bootstrap workspace...'
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:TEMP 'defendmesh-bootstrap') -Recurse -Force -ErrorAction SilentlyContinue

Write-Output '[3/5] Removing DefendMesh output directories...'
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:USERPROFILE '.defendmesh') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\output\live-dashboard' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\output\node-agent' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\output\oneclick-live-dashboard' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\output\oneclick-node-agent' -Recurse -Force -ErrorAction SilentlyContinue

Write-Output '[4/5] Checking for lingering DefendMesh processes...'
$remaining = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -and (
        $_.CommandLine -like '*connection-monitor.ps1*' -or
        $_.CommandLine -like '*node-agent.ps1*'
    )
}
if ($remaining) {
    Write-Output 'warning: lingering monitor/agent processes detected:'
    $remaining | Select-Object ProcessId, Name, CommandLine | Format-Table -AutoSize
} else {
    Write-Output 'No lingering monitor/agent processes found.'
}

Write-Output '[5/5] Removal complete.'
