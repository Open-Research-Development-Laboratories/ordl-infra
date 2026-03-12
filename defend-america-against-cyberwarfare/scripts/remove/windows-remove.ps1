$ErrorActionPreference = 'SilentlyContinue'

$root = if ($env:DEFEND_ROOT_DIR) { $env:DEFEND_ROOT_DIR } else { Join-Path $env:USERPROFILE '.defendmesh' }
$work = if ($env:DEFEND_WORK_DIR) { $env:DEFEND_WORK_DIR } else { Join-Path $env:TEMP 'defendmesh-bootstrap' }

Write-Output '[1/4] Stopping DefendMesh monitor/agent processes...'
Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -and (
        $_.CommandLine -like '*connection-monitor.ps1*' -or
        $_.CommandLine -like '*node-agent.ps1*'
    )
} | ForEach-Object {
    try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Output '[2/4] Removing bootstrap workspace...'
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue

Write-Output '[3/4] Removing DefendMesh output directories...'
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\output\live-dashboard' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\output\node-agent' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\output\oneclick-live-dashboard' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\output\oneclick-node-agent' -Recurse -Force -ErrorAction SilentlyContinue

Write-Output '[4/4] Removal complete.'
