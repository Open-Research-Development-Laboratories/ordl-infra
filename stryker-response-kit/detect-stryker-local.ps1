[CmdletBinding()]
param(
    [int]$HoursBack = 72,
    [string]$OutputDir = (Join-Path -Path $PWD -ChildPath ("stryker-detect-" + (Get-Date -Format "yyyyMMdd-HHmmss")))
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

function Export-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$InputObject
    )
    $InputObject | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-SafeWinEvent {
    param(
        [Parameter(Mandatory = $true)][hashtable]$FilterHashtable,
        [int]$MaxEvents = 200
    )

    try {
        Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Stop -MaxEvents $MaxEvents |
            Select-Object TimeCreated, Id, ProviderName, LogName, LevelDisplayName, Message
    }
    catch {
        @()
    }
}

function Get-LocalGroupMembersCompat {
    param([Parameter(Mandatory = $true)][string]$GroupName)

    try {
        $group = [ADSI]("WinNT://$env:COMPUTERNAME/$GroupName,group")
        $members = @($group.psbase.Invoke("Members"))
        foreach ($member in $members) {
            $name = $member.GetType().InvokeMember("Name", "GetProperty", $null, $member, $null)
            $class = $member.GetType().InvokeMember("Class", "GetProperty", $null, $member, $null)
            [pscustomobject]@{
                Group = $GroupName
                MemberName = $name
                MemberClass = $class
            }
        }
    }
    catch {
        @()
    }
}

function Get-UninstallEntries {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction Stop |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        }
        catch {
        }
    }
}

function Get-RemoteSupportFootprint {
    $patterns = @(
        "AnyDesk",
        "TeamViewer",
        "ScreenConnect",
        "ConnectWise",
        "Bomgar",
        "BeyondTrust",
        "GoToAssist",
        "Splashtop",
        "RustDesk",
        "LogMeIn",
        "Atera",
        "Kaseya",
        "MeshCentral",
        "UltraVNC",
        "TightVNC",
        "RealVNC"
    )

    $installed = @(
        Get-UninstallEntries | Where-Object {
            $name = $_.DisplayName
            $patterns | Where-Object { $name -like "*$_*" }
        }
    )

    $services = @()
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object {
                $test = ($_.Name + " " + $_.DisplayName + " " + $_.PathName)
                $patterns | Where-Object { $test -like "*$_*" }
            } |
            Select-Object Name, DisplayName, State, StartMode, PathName
    }
    catch {
    }

    $processes = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object {
                $test = ($_.Name + " " + $_.ExecutablePath + " " + $_.CommandLine)
                $patterns | Where-Object { $test -like "*$_*" }
            } |
            Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine
    }
    catch {
    }

    [pscustomobject]@{
        InstalledPrograms = $installed
        Services = $services
        Processes = $processes
    }
}

function Get-NetworkConnections {
    $results = @()

    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction Stop |
            Where-Object {
                $_.RemoteAddress -notmatch "^(127\.|0\.0\.0\.0|::1|fe80:)" -and
                $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)"
            }

        foreach ($conn in $connections) {
            $processName = $null
            try {
                $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction Stop).ProcessName
            }
            catch {
                $processName = "<unresolved>"
            }

            $results += [pscustomobject]@{
                LocalAddress  = $conn.LocalAddress
                LocalPort     = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort    = $conn.RemotePort
                State         = $conn.State
                ProcessId     = $conn.OwningProcess
                ProcessName   = $processName
            }
        }
    }
    catch {
    }

    $results | Sort-Object ProcessName, RemoteAddress, RemotePort
}

function Get-RecentScheduledTaskEvents {
    $startTime = (Get-Date).AddHours(-1 * $HoursBack)
    Get-SafeWinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-TaskScheduler/Operational"
        StartTime = $startTime
        Id = 106, 140, 141, 200
    }
}

function Get-FirewallProfileSnapshot {
    try {
        Get-NetFirewallProfile -ErrorAction Stop |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, NotifyOnListen
    }
    catch {
        @()
    }
}

function Get-RdpSnapshot {
    $rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $assistRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"

    [pscustomobject]@{
        DenyRdpConnections = try { (Get-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -ErrorAction Stop).fDenyTSConnections } catch { $null }
        RemoteAssistance   = try { (Get-ItemProperty -Path $assistRegPath -Name "fAllowToGetHelp" -ErrorAction Stop).fAllowToGetHelp } catch { $null }
        FirewallRules      = try {
            Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop |
                Select-Object DisplayName, Enabled, Direction, Action, Profile
        } catch { @() }
    }
}

New-Directory -Path $OutputDir
$startTime = Get-Date
$windowStart = $startTime.AddHours(-1 * $HoursBack)
$adminState = Test-IsAdministrator

$artifact = [ordered]@{
    GeneratedAt = $startTime.ToString("o")
    HoursBack = $HoursBack
    RunningAsAdministrator = $adminState
    Host = [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        Domain = $env:USERDOMAIN
        PSVersion = $PSVersionTable.PSVersion.ToString()
        Caption = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { $null }
        Version = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Version } catch { $null }
        LastBootUpTime = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { $null }
    }
    UsersAndAccess = [pscustomobject]@{
        Administrators = @(Get-LocalGroupMembersCompat -GroupName "Administrators")
        RemoteDesktopUsers = @(Get-LocalGroupMembersCompat -GroupName "Remote Desktop Users")
        LoggedOnUsers = try {
            Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop |
                Select-Object Antecedent, Dependent -Unique
        } catch { @() }
    }
    RemoteSupportFootprint = Get-RemoteSupportFootprint
    Network = [pscustomobject]@{
        IpConfig = try { Get-NetIPConfiguration -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer } catch { @() }
        DnsServers = try { Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object InterfaceAlias, ServerAddresses } catch { @() }
        PublicTcpConnections = @(Get-NetworkConnections)
        SmbShares = try { Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description, ScopeName, EncryptData } catch { @() }
        FirewallProfiles = @(Get-FirewallProfileSnapshot)
        RdpState = Get-RdpSnapshot
    }
    Events = [pscustomobject]@{
        Security = @(Get-SafeWinEvent -FilterHashtable @{
            LogName = "Security"
            StartTime = $windowStart
            Id = 4624, 4625, 4672, 4720, 4722, 4723, 4724, 4725, 4728, 4732, 4735, 4738, 4740, 4768, 4769
        } -MaxEvents 400)
        Services = @(Get-SafeWinEvent -FilterHashtable @{
            LogName = "System"
            StartTime = $windowStart
            Id = 7045
        } -MaxEvents 100)
        TaskScheduler = @(Get-RecentScheduledTaskEvents)
        PowerShell = @(Get-SafeWinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-PowerShell/Operational"
            StartTime = $windowStart
            Id = 4103, 4104
        } -MaxEvents 200)
        Defender = @(Get-SafeWinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Windows Defender/Operational"
            StartTime = $windowStart
            Id = 1116, 1117, 5007
        } -MaxEvents 200)
        RemoteDesktop = @(Get-SafeWinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
            StartTime = $windowStart
            Id = 1149
        } -MaxEvents 200)
    }
}

Export-JsonFile -Path (Join-Path $OutputDir "triage.json") -InputObject $artifact

$artifact.Network.PublicTcpConnections |
    Export-Csv -LiteralPath (Join-Path $OutputDir "public-tcp-connections.csv") -NoTypeInformation -Encoding UTF8

$artifact.Events.Security |
    Export-Csv -LiteralPath (Join-Path $OutputDir "security-events.csv") -NoTypeInformation -Encoding UTF8

$artifact.Events.Services |
    Export-Csv -LiteralPath (Join-Path $OutputDir "service-install-events.csv") -NoTypeInformation -Encoding UTF8

$artifact.Events.PowerShell |
    Export-Csv -LiteralPath (Join-Path $OutputDir "powershell-events.csv") -NoTypeInformation -Encoding UTF8

$artifact.Events.Defender |
    Export-Csv -LiteralPath (Join-Path $OutputDir "defender-events.csv") -NoTypeInformation -Encoding UTF8

$artifact.Events.RemoteDesktop |
    Export-Csv -LiteralPath (Join-Path $OutputDir "rdp-events.csv") -NoTypeInformation -Encoding UTF8

$summary = @(
    "GeneratedAt: $($artifact.GeneratedAt)"
    "HoursBack: $HoursBack"
    "RunningAsAdministrator: $adminState"
    "ComputerName: $($artifact.Host.ComputerName)"
    "OS: $($artifact.Host.Caption) $($artifact.Host.Version)"
    "AdministratorsCount: $(@($artifact.UsersAndAccess.Administrators).Count)"
    "RemoteDesktopUsersCount: $(@($artifact.UsersAndAccess.RemoteDesktopUsers).Count)"
    "RemoteSupportInstalledCount: $(@($artifact.RemoteSupportFootprint.InstalledPrograms).Count)"
    "RemoteSupportServiceCount: $(@($artifact.RemoteSupportFootprint.Services).Count)"
    "RemoteSupportProcessCount: $(@($artifact.RemoteSupportFootprint.Processes).Count)"
    "PublicTcpConnectionCount: $(@($artifact.Network.PublicTcpConnections).Count)"
    "SecurityEventCount: $(@($artifact.Events.Security).Count)"
    "ServiceInstallEventCount: $(@($artifact.Events.Services).Count)"
    "PowerShellEventCount: $(@($artifact.Events.PowerShell).Count)"
    "DefenderEventCount: $(@($artifact.Events.Defender).Count)"
    "RdpEventCount: $(@($artifact.Events.RemoteDesktop).Count)"
    "OutputDir: $OutputDir"
)
$summary | Set-Content -LiteralPath (Join-Path $OutputDir "summary.txt") -Encoding UTF8

Write-Host "Detection bundle written to $OutputDir"
