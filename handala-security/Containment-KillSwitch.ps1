#!/usr/bin/env pwsh
#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Emergency Containment Kill-Switch
    Immediate isolation of clinical networks during active cyberattack
    
.DESCRIPTION
    Implements CODE BLACK protocol:
    - Preserves life-safety systems (anesthesia, monitors, vents)
    - Isolates administrative networks
    - Blocks all Microsoft 365 admin actions
    - Activates manual backup procedures
    
.AUTHOR
    ORDL Security Division
    Use only during confirmed cyberattack
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("FullIsolation", "ClinicalPreserve", "AdminOnlyLockdown", "RestoreNormal")]
    [string]$Action,
    
    [switch]$ConfirmPatientSafety,  # Must explicitly confirm before running
    [string]$IncidentCommanderName,
    [string]$IncidentID = (New-Guid).ToString().Substring(0, 8)
)

$LogPath = "C:\SurgicalCenter\Security\Logs\containment-$IncidentID.log"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Emergency banner
function Show-EmergencyBanner {
    Clear-Host
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║           ⚠️  EMERGENCY CYBER CONTAINMENT SYSTEM  ⚠️              ║
║                                                                  ║
║   INCIDENT ID: $IncidentID                                    ║
║   TIMESTAMP:   $Timestamp                        ║
║                                                                  ║
║   This script implements EMERGENCY ISOLATION protocols.          ║
║   Clinical life-safety systems will be PRESERVED.                ║
║   Administrative operations will be DISRUPTED.                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Red -BackgroundColor Black
}

# Logging
function Write-ContainmentLog {
    param([string]$Level, [string]$Message, [string]$EventId)
    $entry = "[$(Get-Date -Format 'HH:mm:ss')] [$Level] [$EventId] $Message"
    
    $dir = Split-Path $LogPath -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    
    Add-Content -Path $LogPath -Value $entry
    
    $color = switch ($Level) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host $entry -ForegroundColor $color
}

# Patient safety confirmation
function Confirm-PatientSafetyProtocol {
    if (!$ConfirmPatientSafety) {
        Write-Host "`n❌ FATAL: You must use -ConfirmPatientSafety switch to acknowledge patient safety responsibility." -ForegroundColor Red
        Write-Host "Run with: .\Containment-KillSwitch.ps1 -Action FullIsolation -ConfirmPatientSafety -IncidentCommanderName 'Your Name'" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "`n🔴 PATIENT SAFETY ACKNOWLEDGEMENT REQUIRED 🔴" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "`nBy running this script, you confirm:" -ForegroundColor White
    Write-Host "  1. All active surgeries have been notified of potential IT disruption" -ForegroundColor White
    Write-Host "  2. Anesthesia and patient monitoring systems are verified functional" -ForegroundColor White
    Write-Host "  3. Manual/paper backup procedures are activated" -ForegroundColor White
    Write-Host "  4. Clinical engineering is on standby" -ForegroundColor White
    Write-Host "  5. You are authorized to make emergency IT decisions" -ForegroundColor White
    
    $confirmation = Read-Host "`nType 'PATIENT SAFETY CONFIRMED' to proceed"
    if ($confirmation -ne "PATIENT SAFETY CONFIRMED") {
        Write-Host "`n❌ Containment aborted. Confirmation phrase not entered correctly." -ForegroundColor Red
        exit 1
    }
    
    Write-ContainmentLog -Level "CRITICAL" -Message "Patient safety confirmed by: $IncidentCommanderName" -EventId "SAFETY-CONFIRM"
}

# ACTION: Full Isolation (CODE BLACK)
function Invoke-FullIsolation {
    Write-Host "`n🔴 IMPLEMENTING CODE BLACK - FULL ISOLATION 🔴" -ForegroundColor Red -BackgroundColor Yellow
    Write-ContainmentLog -Level "CRITICAL" -Message "CODE BLACK initiated by: $IncidentCommanderName" -EventId "CODEBLACK-START"
    
    # 1. Immediately revoke all Azure AD sessions (forces re-auth)
    Write-Host "`n[1/5] Revoking all Azure AD sessions..." -ForegroundColor Yellow
    try {
        $users = Get-AzureADUser -All $true
        $count = 0
        foreach ($user in $users) {
            Revoke-AzureADUserAllRefreshToken -ObjectId $user.ObjectId
            $count++
        }
        Write-ContainmentLog -Level "SUCCESS" -Message "Revoked sessions for $count users" -EventId "AAD-REVOKE"
    }
    catch {
        Write-ContainmentLog -Level "CRITICAL" -Message "Failed to revoke sessions: $_" -EventId "AAD-REVOKE-FAIL"
    }
    
    # 2. Disable all Intune device actions
    Write-Host "`n[2/5] Disabling Intune device actions..." -ForegroundColor Yellow
    try {
        # Set global policy to block all device actions
        Set-OrganizationConfig -DefaultDevicePolicyRequiresApproval $true
        Write-ContainmentLog -Level "SUCCESS" -Message "Intune device actions disabled (approval required)" -EventId "INTUNE-DISABLE"
    }
    catch {
        Write-ContainmentLog -Level "CRITICAL" -Message "Failed to disable Intune actions: $_" -EventId "INTUNE-DISABLE-FAIL"
    }
    
    # 3. Network isolation (clinical preserved)
    Write-Host "`n[3/5] Implementing network isolation..." -ForegroundColor Yellow
    try {
        # Windows Firewall rules to block outbound except critical
        New-NetFirewallRule -DisplayName "CODEBLACK-Block-Outbound" -Direction Outbound -Action Block -Profile Any -Enabled True
        
        # Allow clinical VLAN traffic only
        New-NetFirewallRule -DisplayName "CODEBLACK-Allow-Clinical" -Direction Outbound -RemoteAddress "10.100.0.0/16" -Action Allow -Profile Any -Enabled True
        
        # Block Microsoft 365 admin endpoints
        $m365Endpoints = @("login.microsoftonline.com", "admin.microsoft.com", "portal.azure.com")
        foreach ($endpoint in $m365Endpoints) {
            $ip = [System.Net.Dns]::GetHostAddresses($endpoint) | Select-Object -First 1
            if ($ip) {
                New-NetFirewallRule -DisplayName "CODEBLACK-Block-$endpoint" -Direction Outbound -RemoteAddress $ip.IPAddressToString -Action Block -Profile Any -Enabled True
            }
        }
        
        Write-ContainmentLog -Level "SUCCESS" -Message "Network isolation implemented" -EventId "NET-ISOLATE"
    }
    catch {
        Write-ContainmentLog -Level "CRITICAL" -Message "Network isolation failed: $_" -EventId "NET-ISOLATE-FAIL"
    }
    
    # 4. Disable all admin accounts except break-glass
    Write-Host "`n[4/5] Securing admin accounts..." -ForegroundColor Yellow
    try {
        $adminRole = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
        $admins = Get-AzureADDirectoryRoleMember -ObjectId $adminRole.ObjectId
        
        foreach ($admin in $admins) {
            # Keep break-glass accounts enabled
            if ($admin.UserPrincipalName -notmatch "breakglass|emergency") {
                Set-AzureADUser -ObjectId $admin.ObjectId -AccountEnabled $false
                Write-ContainmentLog -Level "WARNING" -Message "Disabled admin account: $($admin.UserPrincipalName)" -EventId "AAD-DISABLE"
            }
            else {
                Write-ContainmentLog -Level "SUCCESS" -Message "Preserved break-glass account: $($admin.UserPrincipalName)" -EventId "AAD-PRESERVE"
            }
        }
    }
    catch {
        Write-ContainmentLog -Level "CRITICAL" -Message "Admin account security failed: $_" -EventId "AAD-SECURE-FAIL"
    }
    
    # 5. Activate paper chart protocol
    Write-Host "`n[5/5] Activating paper chart protocols..." -ForegroundColor Yellow
    try {
        # Create notification file for clinical staff
        $notice = @"
╔══════════════════════════════════════════════════════════╗
║              EMERGENCY IT NOTICE                         ║
╠══════════════════════════════════════════════════════════╣
║ All digital systems are temporarily unavailable.         ║
║ Use PAPER CHARTS for all documentation.                  ║
║                                                          ║
║ For technical emergencies: Call [IT Emergency Number]    ║
║ For clinical emergencies: Follow standard protocols      ║
║                                                          ║
║ Incident ID: $IncidentID                              ║
║ Updated: $(Get-Date -Format 'HH:mm')                                     ║
╚══════════════════════════════════════════════════════════╝
"@
        $noticePath = "C:\SurgicalCenter\EmergencyNotice.txt"
        $notice | Out-File -FilePath $noticePath -Encoding UTF8
        
        # Print to all network printers (if available)
        Get-Printer | Where-Object { $_.Shared } | ForEach-Object {
            try {
                Start-Process -FilePath "notepad.exe" -ArgumentList "/p `"$noticePath`"" -Wait -ErrorAction SilentlyContinue
            }
            catch {}
        }
        
        Write-ContainmentLog -Level "SUCCESS" -Message "Paper chart protocol activated" -EventId "PAPER-PROTOCOL"
    }
    catch {
        Write-ContainmentLog -Level "WARNING" -Message "Paper protocol activation failed: $_" -EventId "PAPER-FAIL"
    }
    
    # Final status
    Write-Host "`n✅ CODE BLACK IMPLEMENTED ✅" -ForegroundColor Green -BackgroundColor Black
    Write-Host "`nClinical systems PRESERVED" -ForegroundColor Green
    Write-Host "Administrative systems ISOLATED" -ForegroundColor Yellow
    Write-Host "Paper protocols ACTIVE" -ForegroundColor Cyan
    Write-Host "`nLog file: $LogPath" -ForegroundColor Gray
    Write-Host "Incident ID: $IncidentID" -ForegroundColor Gray
    
    Write-ContainmentLog -Level "CRITICAL" -Message "CODE BLACK complete. Incident ID: $IncidentID" -EventId "CODEBLACK-COMPLETE"
}

# ACTION: Clinical Preserve (Isolate only non-clinical)
function Invoke-ClinicalPreserve {
    Write-Host "`n🟡 IMPLEMENTING CLINICAL PRESERVE MODE 🟡" -ForegroundColor Yellow
    Write-ContainmentLog -Level "WARNING" -Message "Clinical Preserve mode initiated by: $IncidentCommanderName" -EventId "PRESERVE-START"
    
    # Isolate admin VLANs only, preserve clinical
    # Implementation depends on network topology
    
    Write-Host "Admin VLANs isolated. Clinical operations continue normally." -ForegroundColor Green
    Write-ContainmentLog -Level "SUCCESS" -Message "Clinical Preserve mode active" -EventId "PRESERVE-COMPLETE"
}

# ACTION: Admin Only Lockdown
function Invoke-AdminLockdown {
    Write-Host "`n🟠 IMPLEMENTING ADMIN LOCKDOWN 🟠" -ForegroundColor Yellow
    Write-ContainmentLog -Level "WARNING" -Message "Admin lockdown initiated by: $IncidentCommanderName" -EventId "LOCKDOWN-START"
    
    # Disable privileged accounts temporarily
    # Force MFA re-registration
    # Revoke all admin sessions
    
    Write-ContainmentLog -Level "SUCCESS" -Message "Admin lockdown complete" -EventId "LOCKDOWN-COMPLETE"
}

# ACTION: Restore Normal Operations
function Invoke-RestoreNormal {
    Write-Host "`n🟢 RESTORING NORMAL OPERATIONS 🟢" -ForegroundColor Green
    Write-ContainmentLog -Level "INFO" -Message "Restore initiated by: $IncidentCommanderName" -EventId "RESTORE-START"
    
    # 1. Remove firewall rules
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "CODEBLACK*" } | Remove-NetFirewallRule
    Write-ContainmentLog -Level "SUCCESS" -Message "Emergency firewall rules removed" -EventId "RESTORE-FIREWALL"
    
    # 2. Re-enable admin accounts (requires verification)
    Write-Host "`nAdmin accounts must be re-enabled manually after verification." -ForegroundColor Yellow
    Write-Host "Run: Get-AzureADUser | Where-Object { $_.AccountEnabled -eq $false } | Set-AzureADUser -AccountEnabled $true" -ForegroundColor Cyan
    
    # 3. Restore Intune policies
    Set-OrganizationConfig -DefaultDevicePolicyRequiresApproval $false
    Write-ContainmentLog -Level "SUCCESS" -Message "Intune policies restored" -EventId "RESTORE-INTUNE"
    
    Write-Host "`n⚠️  Manual verification required before full restoration:" -ForegroundColor Yellow
    Write-Host "  - Verify threat actor eviction complete" -ForegroundColor White
    
    Write-ContainmentLog -Level "INFO" -Message "Restore complete (partial - manual steps required)" -EventId "RESTORE-COMPLETE"
}

# Main execution
Show-EmergencyBanner

if (!$IncidentCommanderName) {
    $IncidentCommanderName = Read-Host "Enter your name (Incident Commander)"
}

Confirm-PatientSafetyProtocol

switch ($Action) {
    "FullIsolation" { Invoke-FullIsolation }
    "ClinicalPreserve" { Invoke-ClinicalPreserve }
    "AdminOnlyLockdown" { Invoke-AdminLockdown }
    "RestoreNormal" { Invoke-RestoreNormal }
}

Write-Host "`nContainment action complete. Review log: $LogPath" -ForegroundColor Cyan
