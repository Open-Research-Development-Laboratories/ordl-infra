[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [switch]$RestoreInboundRdp,
    [switch]$RestoreRemoteAssistance,
    [switch]$RemoveTemporaryFirewallRules,
    [string]$VendorAccountsFile,
    [string]$ResponseDir,
    [string]$OutputDir = (Join-Path -Path $PWD -ChildPath ("stryker-reverse-" + (Get-Date -Format "yyyyMMdd-HHmmss")))
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
        RemoteDesktopRules = try {
            Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop |
                Select-Object Name, DisplayName, Enabled, Direction, Action, Profile
        } catch { @() }
        RemoteAssistanceRules = try {
            Get-NetFirewallRule -DisplayGroup "Remote Assistance" -ErrorAction Stop |
                Select-Object Name, DisplayName, Enabled, Direction, Action, Profile
        } catch { @() }
        TemporaryRules = try {
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object {
                    $_.DisplayGroup -eq "Stryker Response Temporary" -or
                    $_.DisplayName -like "Stryker Response Block *"
                } |
                Select-Object Name, DisplayName, Enabled, Direction, Action, DisplayGroup
        } catch { @() }
        RdpRegistry = [pscustomobject]@{
            DenyRdpConnections = try { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop).fDenyTSConnections } catch { $null }
            RemoteAssistance   = try { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction Stop).fAllowToGetHelp } catch { $null }
        }
        LocalUsers = try {
            Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop |
                Select-Object Name, Disabled, Lockout, PasswordRequired, SID
        } catch { @() }
    }

    $snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDir $FileName) -Encoding UTF8
}

function Import-PreChangeState {
    if (-not $ResponseDir) {
        return $null
    }

    $path = Join-Path $ResponseDir "pre-change-state.json"
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Action "Pre-change snapshot not found at $path"
        return $null
    }

    try {
        Write-Action "Loaded pre-change snapshot from $path"
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Action "Failed to load pre-change snapshot from $path"
        return $null
    }
}

function Get-DesiredEnabledState {
    param(
        [Parameter(Mandatory = $true)]$PreChangeState,
        [Parameter(Mandatory = $true)][string]$CollectionName,
        [Parameter(Mandatory = $true)][string]$DisplayName
    )

    $collection = $PreChangeState.$CollectionName
    if (-not $collection) {
        return $null
    }

    $match = @($collection | Where-Object { $_.DisplayName -eq $DisplayName } | Select-Object -First 1)
    if (-not $match) {
        return $null
    }

    $value = $match[0].Enabled
    if ($value -is [bool]) {
        return $value
    }

    return ([string]$value) -eq "True"
}

function Set-RuleEnabledState {
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [Parameter(Mandatory = $true)][string]$CollectionName,
        [Parameter(Mandatory = $true)][string]$ActionDescription
    )

    $rules = @(Get-NetFirewallRule -DisplayGroup $GroupName -ErrorAction SilentlyContinue)
    foreach ($rule in $rules) {
        $desired = $null
        if ($script:PreChangeState) {
            $desired = Get-DesiredEnabledState -PreChangeState $script:PreChangeState -CollectionName $CollectionName -DisplayName $rule.DisplayName
        }

        if ($desired -eq $false) {
            Write-Action "Leaving $GroupName rule disabled based on pre-change state: $($rule.DisplayName)"
            continue
        }

        if ($rule.Enabled -eq "True") {
            Write-Action "$GroupName rule already enabled: $($rule.DisplayName)"
            continue
        }

        if ($PSCmdlet.ShouldProcess($rule.DisplayName, $ActionDescription)) {
            Enable-NetFirewallRule -Name $rule.Name | Out-Null
            Write-Action "Enabled $GroupName rule: $($rule.DisplayName)"
        }
    }
}

function Remove-TemporaryRules {
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayGroup -eq "Stryker Response Temporary" -or
            $_.DisplayName -like "Stryker Response Block *"
        })

    foreach ($rule in $rules) {
        if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Remove temporary Stryker response firewall rule")) {
            Remove-NetFirewallRule -Name $rule.Name | Out-Null
            Write-Action "Removed temporary firewall rule: $($rule.DisplayName)"
        }
    }

    if (-not $rules) {
        Write-Action "No temporary Stryker response firewall rules found"
    }
}

function Restore-RemoteAssistanceRegistry {
    $desired = 1
    if ($script:PreChangeState -and $null -ne $script:PreChangeState.RdpRegistry.RemoteAssistance) {
        $desired = [int]$script:PreChangeState.RdpRegistry.RemoteAssistance
    }

    if ($PSCmdlet.ShouldProcess("Remote Assistance", "Restore registry flag to $desired")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value $desired -PropertyType DWord -Force | Out-Null
        Write-Action "Set Remote Assistance registry flag to $desired"
    }
}

function Enable-ListedLocalAccounts {
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

        if (-not $user.Disabled) {
            Write-Action "Local account already enabled: $account"
            continue
        }

        if ($PSCmdlet.ShouldProcess($account, "Enable local account")) {
            & net.exe user $account /active:yes | Out-Null
            Write-Action "Enabled local account: $account"
        }
    }
}

New-Directory -Path $OutputDir
$script:ActionLog = New-Object System.Collections.Generic.List[string]
$script:PreChangeState = $null
Write-Action "Starting reversal workflow"
Write-StateSnapshot -FileName "pre-reversal-state.json"

if (-not (Test-IsAdministrator)) {
    Write-Action "Reversal aborted because the shell is not elevated"
    Save-ActionLog
    throw "Run this script from an elevated PowerShell session."
}

$script:PreChangeState = Import-PreChangeState

if (-not $RestoreInboundRdp -and -not $RestoreRemoteAssistance -and -not $RemoveTemporaryFirewallRules -and -not $VendorAccountsFile) {
    Write-Action "No reversal switches selected; snapshot only"
    Write-StateSnapshot -FileName "state-snapshot.json"
    Save-ActionLog
    Write-Host "Snapshot written to $OutputDir"
    return
}

if ($RemoveTemporaryFirewallRules) {
    Remove-TemporaryRules
}

if ($RestoreInboundRdp) {
    Set-RuleEnabledState -GroupName "Remote Desktop" -CollectionName "RemoteDesktopRules" -ActionDescription "Enable Remote Desktop firewall rule"
}

if ($RestoreRemoteAssistance) {
    Restore-RemoteAssistanceRegistry
    Set-RuleEnabledState -GroupName "Remote Assistance" -CollectionName "RemoteAssistanceRules" -ActionDescription "Enable Remote Assistance firewall rule"
}

if ($VendorAccountsFile) {
    Enable-ListedLocalAccounts -Path $VendorAccountsFile
}

Write-StateSnapshot -FileName "post-reversal-state.json"
Write-StateSnapshot -FileName "state-snapshot.json"
Save-ActionLog
Write-Host "Reversal actions logged in $OutputDir"
