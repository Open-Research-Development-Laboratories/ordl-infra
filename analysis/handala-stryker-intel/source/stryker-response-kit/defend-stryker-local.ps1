[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [switch]$BlockInboundRdp,
    [switch]$DisableRemoteAssistance,
    [switch]$BlockCommonRemoteSupportTools,
    [string]$VendorAccountsFile,
    [string]$OutputDir = (Join-Path -Path $PWD -ChildPath ("stryker-defend-" + (Get-Date -Format "yyyyMMdd-HHmmss")))
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

function Write-Action {
    param([Parameter(Mandatory = $true)][string]$Message)
    $script:ActionLog.Add(("{0} {1}" -f (Get-Date -Format "o"), $Message))
}

function Save-ActionLog {
    $script:ActionLog | Set-Content -LiteralPath (Join-Path $OutputDir "actions.log") -Encoding UTF8
}

function Write-StateSnapshot {
    param([Parameter(Mandatory = $true)][string]$FileName)

    $snapshot = [ordered]@{
        GeneratedAt = (Get-Date).ToString("o")
        FirewallProfiles = try {
            Get-NetFirewallProfile -ErrorAction Stop |
                Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
        } catch { @() }
        RemoteDesktopRules = try {
            Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop |
                Select-Object DisplayName, Enabled, Direction, Action, Profile
        } catch { @() }
        RemoteAssistanceRules = try {
            Get-NetFirewallRule -DisplayGroup "Remote Assistance" -ErrorAction Stop |
                Select-Object DisplayName, Enabled, Direction, Action, Profile
        } catch { @() }
        RdpRegistry = [pscustomobject]@{
            DenyRdpConnections = try { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop).fDenyTSConnections } catch { $null }
            RemoteAssistance   = try { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction Stop).fAllowToGetHelp } catch { $null }
        }
        LocalUsers = try {
            Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop |
                Select-Object Name, Disabled, Lockout, PasswordRequired, SID
        } catch { @() }
        TemporaryRules = try {
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.DisplayGroup -eq "Stryker Response Temporary" } |
                Select-Object DisplayName, Enabled, Direction, Action, DisplayGroup
        } catch { @() }
    }

    $snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDir $FileName) -Encoding UTF8
}

function Resolve-RemoteSupportExecutables {
    $patterns = @(
        "AnyDesk.exe",
        "TeamViewer.exe",
        "ScreenConnect.WindowsClient.exe",
        "ScreenConnect.Service.exe",
        "Bomgar-scc.exe",
        "bomgar-scc.exe",
        "BeyondTrustRemoteSupport.exe",
        "GoToAssist.exe",
        "g2ax_host_service.exe",
        "SRService.exe",
        "rustdesk.exe",
        "splashtop-streamer.exe",
        "LMIGuardianSvc.exe",
        "AteraAgent.exe",
        "AgentMon.exe",
        "KaseyaAgent.exe",
        "MeshAgent.exe",
        "UltraVNC.exe",
        "winvnc.exe",
        "tv_x64.exe"
    )

    $roots = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:ProgramData"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $found = New-Object System.Collections.Generic.HashSet[string]
    foreach ($root in $roots) {
        try {
            Get-ChildItem -Path $root -Recurse -File -Include $patterns -ErrorAction SilentlyContinue |
                ForEach-Object { [void]$found.Add($_.FullName) }
        }
        catch {
        }
    }

    $found.ToArray() | Sort-Object
}

function Ensure-BlockRuleForProgram {
    param([Parameter(Mandatory = $true)][string]$ProgramPath)

    $safeName = ($ProgramPath -replace "[^A-Za-z0-9]", "_")
    $rules = @(
        @{
            DisplayName = "Stryker Response Block OUT $safeName"
            Direction = "Outbound"
        },
        @{
            DisplayName = "Stryker Response Block IN $safeName"
            Direction = "Inbound"
        }
    )

    foreach ($rule in $rules) {
        $existing = Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Action "Firewall rule already present: $($rule.DisplayName)"
            continue
        }

        if ($PSCmdlet.ShouldProcess($ProgramPath, "Create firewall block rule $($rule.DisplayName)")) {
            New-NetFirewallRule -DisplayName $rule.DisplayName `
                -DisplayGroup "Stryker Response Temporary" `
                -Direction $rule.Direction `
                -Action Block `
                -Program $ProgramPath `
                -Profile Any | Out-Null
            Write-Action "Created $($rule.Direction) block rule for $ProgramPath"
        }
    }
}

function Disable-ListedLocalAccounts {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "VendorAccountsFile not found: $Path"
    }

    $accounts = Get-Content -LiteralPath $Path |
        Where-Object { $_ -and $_.Trim() -and -not $_.Trim().StartsWith("#") } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique

    foreach ($account in $accounts) {
        $user = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$account'" -ErrorAction SilentlyContinue
        if (-not $user) {
            Write-Action "Local account not found: $account"
            continue
        }

        if ($user.Disabled) {
            Write-Action "Local account already disabled: $account"
            continue
        }

        if ($PSCmdlet.ShouldProcess($account, "Disable local account")) {
            & net.exe user $account /active:no | Out-Null
            Write-Action "Disabled local account: $account"
        }
    }
}

New-Directory -Path $OutputDir
$script:ActionLog = New-Object System.Collections.Generic.List[string]
Write-Action "Starting containment workflow"
Write-StateSnapshot -FileName "pre-change-state.json"

if (-not $BlockInboundRdp -and -not $DisableRemoteAssistance -and -not $BlockCommonRemoteSupportTools -and -not $VendorAccountsFile) {
    Write-Action "No containment switches selected; snapshot only"
    Write-StateSnapshot -FileName "state-snapshot.json"
    Save-ActionLog
    Write-Host "Snapshot written to $OutputDir"
    return
}

if (-not (Test-IsAdministrator)) {
    Write-Action "Containment aborted because the shell is not elevated"
    Save-ActionLog
    throw "Run this script from an elevated PowerShell session when applying containment."
}

if ($BlockInboundRdp) {
    $rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    if ($rdpRules) {
        foreach ($rule in $rdpRules) {
            if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Disable inbound Remote Desktop firewall rule")) {
                Disable-NetFirewallRule -Name $rule.Name | Out-Null
                Write-Action "Disabled Remote Desktop firewall rule: $($rule.DisplayName)"
            }
        }
    }
    else {
        $fallbackName = "Stryker Response Block Inbound RDP 3389"
        $existing = Get-NetFirewallRule -DisplayName $fallbackName -ErrorAction SilentlyContinue
        if (-not $existing -and $PSCmdlet.ShouldProcess($fallbackName, "Create inbound TCP/3389 block rule")) {
            New-NetFirewallRule -DisplayName $fallbackName `
                -DisplayGroup "Stryker Response Temporary" `
                -Direction Inbound `
                -Protocol TCP `
                -LocalPort 3389 `
                -Action Block `
                -Profile Any | Out-Null
            Write-Action "Created fallback inbound TCP/3389 block rule"
        }
    }
}

if ($DisableRemoteAssistance) {
    if ($PSCmdlet.ShouldProcess("Remote Assistance", "Disable Remote Assistance registry setting and firewall group")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Action "Set Remote Assistance registry flag to disabled"
    }

    $assistRules = Get-NetFirewallRule -DisplayGroup "Remote Assistance" -ErrorAction SilentlyContinue
    foreach ($rule in $assistRules) {
        if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Disable Remote Assistance firewall rule")) {
            Disable-NetFirewallRule -Name $rule.Name | Out-Null
            Write-Action "Disabled Remote Assistance firewall rule: $($rule.DisplayName)"
        }
    }
}

if ($BlockCommonRemoteSupportTools) {
    $executables = Resolve-RemoteSupportExecutables
    if (-not $executables) {
        Write-Action "No common remote support executables found under Program Files or ProgramData"
    }

    foreach ($exe in $executables) {
        Ensure-BlockRuleForProgram -ProgramPath $exe
    }
}

if ($VendorAccountsFile) {
    Disable-ListedLocalAccounts -Path $VendorAccountsFile
}

Write-StateSnapshot -FileName "post-change-state.json"
Write-StateSnapshot -FileName "state-snapshot.json"
Save-ActionLog
Write-Host "Containment actions logged in $OutputDir"
