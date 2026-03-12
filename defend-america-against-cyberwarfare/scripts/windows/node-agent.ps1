[CmdletBinding()]
param(
    [string]$AnchorUrl = $null,
    [string]$NodeId = $env:DEFEND_NODE_ID,
    [string]$AnchorToken = $env:DEFEND_ANCHOR_TOKEN,
    [int]$PollSec = 10,
    [string]$OutputDir
)

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot 'output\node-agent'
}
if ([string]::IsNullOrWhiteSpace($NodeId)) {
    $NodeId = $env:COMPUTERNAME
}

function Split-AnchorUrls {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return @(
        $Value -split '[,;]' |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

$resolvedAnchorUrls = @()
if ($PSBoundParameters.ContainsKey('AnchorUrl')) {
    $resolvedAnchorUrls = Split-AnchorUrls -Value $AnchorUrl
}
if ($resolvedAnchorUrls.Count -eq 0) {
    $resolvedAnchorUrls = Split-AnchorUrls -Value $env:DEFEND_ANCHOR_URLS
}
if ($resolvedAnchorUrls.Count -eq 0) {
    $resolvedAnchorUrls = Split-AnchorUrls -Value $env:DEFEND_ANCHOR_URL
}
if ($resolvedAnchorUrls.Count -eq 0) {
    throw 'AnchorUrl is required (param AnchorUrl, DEFEND_ANCHOR_URLS, or DEFEND_ANCHOR_URL)'
}
$anchorUrls = @($resolvedAnchorUrls)
$anchorUrlList = ($anchorUrls -join ',')
if ($PollSec -lt 2) { $PollSec = 2 }

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $OutputDir 'patches') -Force | Out-Null
$logPath = Join-Path $OutputDir 'node-agent.log'

$headers = @{}
if (-not [string]::IsNullOrWhiteSpace($AnchorToken)) {
    $headers['Authorization'] = "Bearer $AnchorToken"
}

function Write-AgentLog {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $line | Tee-Object -FilePath $logPath -Append
}

function Invoke-Anchor {
    param(
        [string]$Method,
        [string]$Path,
        [object]$Body = $null
    )
    $params = @{ Method = $Method; ErrorAction = 'Stop' }
    if ($headers.Count -gt 0) { $params['Headers'] = $headers }
    if ($null -ne $Body) {
        $params['ContentType'] = 'application/json'
        $params['Body'] = ($Body | ConvertTo-Json -Depth 8 -Compress)
    }
    $errors = @()
    foreach ($anchor in $anchorUrls) {
        $params['Uri'] = ('{0}{1}' -f $anchor.TrimEnd('/'), $Path)
        try {
            return Invoke-RestMethod @params
        } catch {
            $errors += ("{0}: {1}" -f $anchor, $_.Exception.Message)
        }
    }
    throw ("anchor request failed method={0} path={1} errors={2}" -f $Method, $Path, ($errors -join ' | '))
}

function Send-NodeLog {
    param([string]$Level,[string]$Message)
    try {
        Invoke-Anchor -Method 'Post' -Path '/api/v1/node/log' -Body @{
            node_id = $NodeId
            level = $Level
            message = $Message
        } | Out-Null
    } catch {}
}

function Send-TaskResult {
    param([string]$TaskId,[string]$Status,[string]$Output)
    try {
        Invoke-Anchor -Method 'Post' -Path '/api/v1/node/task-result' -Body @{
            node_id = $NodeId
            task_id = $TaskId
            status = $Status
            output = $Output
        } | Out-Null
    } catch {}
}

function Run-Task {
    param([object]$Task)

    $taskId = [string]$Task.task_id
    $playbook = [string]$Task.playbook
    $args = $Task.args
    $status = 'ok'
    $output = ''
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'

    try {
        switch ($playbook) {
            'endpoint_audit' {
                & powershell -ExecutionPolicy Bypass -File (Join-Path $scriptRoot 'defend-endpoint.ps1') -Mode audit -IocFile (Join-Path $repoRoot 'iocs\seed-iocs.txt') -OutputDir (Join-Path $repoRoot "output\node-endpoint-audit-$ts")
                $output = 'endpoint_audit done'
            }
            'endpoint_remediate' {
                & powershell -ExecutionPolicy Bypass -File (Join-Path $scriptRoot 'defend-endpoint.ps1') -Mode remediate -IocFile (Join-Path $repoRoot 'iocs\seed-iocs.txt') -OutputDir (Join-Path $repoRoot "output\node-endpoint-remediate-$ts")
                $output = 'endpoint_remediate done'
            }
            'monitor_start' {
                $interval = 2
                if ($null -ne $args -and $args.PSObject.Properties.Name -contains 'interval_sec') { $interval = [int]$args.interval_sec }
                $monitorArgs = "-NoProfile -ExecutionPolicy Bypass -File \"$(Join-Path $scriptRoot 'connection-monitor.ps1')\" -IntervalSec $interval -OutputDir \"$(Join-Path $repoRoot 'output\live-dashboard')\" -AnchorUrl \"$anchorUrlList\" -NodeId \"$NodeId\""
                if (-not [string]::IsNullOrWhiteSpace($AnchorToken)) {
                    $monitorArgs += " -AnchorToken \"$AnchorToken\""
                }
                Start-Process -FilePath 'powershell.exe' -ArgumentList $monitorArgs -WindowStyle Hidden | Out-Null
                $output = 'monitor_start done'
            }
            'monitor_stop' {
                Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*connection-monitor.ps1*' } | ForEach-Object {
                    try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
                }
                $output = 'monitor_stop done'
            }
            'monitor_oneshot' {
                $interval = 2
                $loops = 5
                if ($null -ne $args -and $args.PSObject.Properties.Name -contains 'interval_sec') { $interval = [int]$args.interval_sec }
                if ($null -ne $args -and $args.PSObject.Properties.Name -contains 'loop_count') { $loops = [int]$args.loop_count }
                & powershell -ExecutionPolicy Bypass -File (Join-Path $scriptRoot 'connection-monitor.ps1') -IntervalSec $interval -LoopCount $loops -OutputDir (Join-Path $repoRoot 'output\live-dashboard') -AnchorUrl $anchorUrlList -NodeId $NodeId -AnchorToken $AnchorToken
                $output = 'monitor_oneshot done'
            }
            'stage_patch' {
                if ($null -eq $args -or -not ($args.PSObject.Properties.Name -contains 'patch_id')) {
                    throw 'stage_patch missing patch_id'
                }
                $patchId = [string]$args.patch_id
                $patch = Invoke-Anchor -Method 'Get' -Path ("/api/v1/node/patch/{0}" -f $patchId)
                $raw = [Convert]::FromBase64String([string]$patch.content_b64)
                $patchFile = Join-Path (Join-Path $OutputDir 'patches') ([string]$patch.filename)
                [IO.File]::WriteAllBytes($patchFile, $raw)
                $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $patchFile).Hash.ToLowerInvariant()
                if ($patch.sha256 -and $sha -ne [string]$patch.sha256) {
                    throw 'patch sha mismatch'
                }
                $output = "patch staged at $patchFile"
            }
            default {
                throw "unsupported playbook: $playbook"
            }
        }
    } catch {
        $status = 'error'
        $output = $_.Exception.Message
    }

    Send-TaskResult -TaskId $taskId -Status $status -Output $output
    Send-NodeLog -Level 'info' -Message ("task={0} playbook={1} status={2}" -f $taskId, $playbook, $status)
    Write-AgentLog ("task={0} playbook={1} status={2}" -f $taskId, $playbook, $status)
}

Write-AgentLog "node-agent start node_id=$NodeId anchors=$anchorUrlList"
Send-NodeLog -Level 'info' -Message 'node-agent started'

while ($true) {
    try {
        $resp = Invoke-Anchor -Method 'Get' -Path ("/api/v1/node/tasks?node_id={0}" -f [Uri]::EscapeDataString($NodeId))
        if ($resp.tasks) {
            foreach ($task in $resp.tasks) {
                Run-Task -Task $task
            }
        }
    } catch {
        Write-AgentLog ("task fetch failed: {0}" -f $_.Exception.Message)
        Send-NodeLog -Level 'warn' -Message 'task fetch failed'
    }

    Start-Sleep -Seconds $PollSec
}
