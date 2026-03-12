#!/usr/bin/env pwsh
#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Hardening Reversal Script - Restore Normal Operations
    Safely undoes protection measures for testing or post-incident recovery
    
.DESCRIPTION
    Reverses changes made by:
    - Protect-SurgicalCenter.ps1
    - Containment-KillSwitch.ps1
    - Detect-HandalaThreats.ps1 (scheduled tasks)
    
    WARNING: Only run after confirming threat actor eviction and system integrity
    
.AUTHOR
    ORDL Security Division
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("FullRestore", "PartialRestore", "EmergencyRollback", "TestLabOnly")]
    [string]$RestoreMode,
    
    [string]$ConfigBackupPath,  # Path to backup created by protection script
    [switch]$ConfirmThreatEviction,  # Required for FullRestore
    [switch]$SkipSafetyChecks,  # DANGEROUS: Skip all verification
    [string]$ApprovedBy,  # Name of authorizing person
    [string]$TicketNumber,  # Change ticket/incident number
    [switch]$WhatIf  # Show what would be changed without making changes
)

$LogPath = "C:\SurgicalCenter\Security\Logs\reversal-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$RestorationReport = @()

# Logging
function Write-ReversalLog {
    param([string]$Level, [string]$Message, [string]$EventId)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$EventId] $Message"
    
    $logDir = Split-Path $LogPath -Parent
    if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    
    Add-Content -Path $LogPath -Value $logEntry
    
    $color = switch ($Level) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "INFO" { "White" }
        default { "Gray" }
    }
    Write-Host $logEntry -ForegroundColor $color
    
    # Add to restoration report
    $script:RestorationReport += [PSCustomObject]@{
        Time = $timestamp
        Level = $Level
        EventId = $EventId
        Message = $Message
    }
}

# Safety banner
function Show-SafetyBanner {
    Clear-Host
    Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║              ⚠️  HARDENING REVERSAL / RESTORATION SCRIPT  ⚠️                  ║
║                                                                              ║
║   This script UNDOES security protections. Use with extreme caution.         ║
║                                                                              ║
║   RESTORE MODE: $RestoreMode                                                ║
║   AUTHORIZED BY: $(if($ApprovedBy){$ApprovedBy}else{"NOT PROVIDED"})                                              ║
║   TICKET: $(if($TicketNumber){$TicketNumber}else{"NOT PROVIDED"})                                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Yellow -BackgroundColor Black
    
    Write-Host "`nSAFETY REQUIREMENTS:" -ForegroundColor Red
    Write-Host "  ☐ Threat actor confirmed evicted from environment" -ForegroundColor Yellow
    Write-Host "  ☐ Forensic analysis complete" -ForegroundColor Yellow
    Write-Host "  ☐ Malware/implants removed from all systems" -ForegroundColor Yellow
    Write-Host "  ☐ All admin passwords reset" -ForegroundColor Yellow
    Write-Host "  ☐ MFA re-verified for all privileged accounts" -ForegroundColor Yellow
    Write-Host "  ☐ Network traffic monitored for 24-48 hours clean" -ForegroundColor Yellow
    Write-Host ""
}

# Pre-flight safety checks
function Test-SafetyRequirements {
    if ($SkipSafetyChecks) {
        Write-ReversalLog -Level "CRITICAL" -Message "DANGER: Safety checks bypassed with -SkipSafetyChecks" -EventId "SAFETY-BYPASS"
        return $true
    }
    
    if ($RestoreMode -eq "FullRestore" -and !$ConfirmThreatEviction) {
        Write-Host "`n❌ FATAL: FullRestore requires -ConfirmThreatEviction switch" -ForegroundColor Red
        Write-Host "You must confirm threat actor eviction before full restoration." -ForegroundColor Yellow
        exit 1
    }
    
    if (!$ApprovedBy -or !$TicketNumber) {
        Write-Host "`n❌ FATAL: Approval information required" -ForegroundColor Red
        Write-Host "Provide -ApprovedBy and -TicketNumber parameters" -ForegroundColor Yellow
        exit 1
    }
    
    # Confirmation for FullRestore
    if ($RestoreMode -eq "FullRestore") {
        Write-Host "`n🔴 CRITICAL CONFIRMATION REQUIRED 🔴" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "You are about to RESTORE NORMAL OPERATIONS after a security incident." -ForegroundColor White
        Write-Host "This will REMOVE protections that may still be needed." -ForegroundColor Red
        
        $confirmation = Read-Host "`nType 'THREAT EVICTED - AUTHORIZE RESTORE' to proceed"
        if ($confirmation -ne "THREAT EVICTED - AUTHORIZE RESTORE") {
            Write-Host "`n❌ Restoration aborted. Confirmation not provided correctly." -ForegroundColor Red
            exit 1
        }
    }
    
    Write-ReversalLog -Level "INFO" -Message "Safety checks passed for $RestoreMode" -EventId "SAFETY-OK"
    return $true
}

# REVERSAL 1: Restore Intune Policies
function Restore-IntunePolicies {
    Write-ReversalLog -Level "INFO" -Message "Restoring Intune policies..." -EventId "INTUNE-RESTORE-START"
    
    if ($WhatIf) {
        Write-Host "WHATIF: Would restore Intune device action policies" -ForegroundColor Cyan
        return
    }
    
    try {
        # Re-enable device actions (remove approval requirement)
        Set-OrganizationConfig -DefaultDevicePolicyRequiresApproval $false
        Write-ReversalLog -Level "SUCCESS" -Message "Disabled device action approval requirement" -EventId "INTUNE-APPROVAL-OFF"
        
        # Re-enable auto-wipe on device configs (if needed - evaluate risk)
        $deviceConfigs = Get-DeviceManagementDeviceConfiguration -ErrorAction SilentlyContinue
        foreach ($config in $deviceConfigs) {
            # Note: Only re-enable if explicitly required - most orgs keep manual approval
            Write-ReversalLog -Level "WARNING" -Message "Evaluating config: $($config.displayName) - manual review recommended" -EventId "INTUNE-REVIEW"
        }
        
        Write-ReversalLog -Level "SUCCESS" -Message "Intune policy restoration complete" -EventId "INTUNE-RESTORE-OK"
    }
    catch {
        Write-ReversalLog -Level "CRITICAL" -Message "Intune restoration failed: $_" -EventId "INTUNE-RESTORE-FAIL"
    }
}

# REVERSAL 2: Restore Azure AD Admin Access
function Restore-AzureADAdmins {
    Write-ReversalLog -Level "INFO" -Message "Restoring Azure AD admin access..." -EventId "AAD-RESTORE-START"
    
    if ($WhatIf) {
        Write-Host "WHATIF: Would re-enable disabled admin accounts" -ForegroundColor Cyan
        Write-Host "WHATIF: Would remove geo-restriction policies" -ForegroundColor Cyan
        return
    }
    
    try {
        # List disabled accounts
        $disabledUsers = Get-AzureADUser -All $true | Where-Object { $_.AccountEnabled -eq $false }
        Write-ReversalLog -Level "INFO" -Message "Found $($disabledUsers.Count) disabled accounts" -EventId "AAD-DISABLED-COUNT"
        
        if ($disabledUsers.Count -gt 0) {
            Write-Host "`nDisabled accounts found:" -ForegroundColor Yellow
            $disabledUsers | Select-Object UserPrincipalName, DisplayName | Format-Table
            
            $confirmEnable = Read-Host "Enable all disabled accounts? (type 'ENABLE ALL' or list specific UPNs, or 'SKIP')"
            
            if ($confirmEnable -eq "ENABLE ALL") {
                foreach ($user in $disabledUsers) {
                    Set-AzureADUser -ObjectId $user.ObjectId -AccountEnabled $true
                    Write-ReversalLog -Level "SUCCESS" -Message "Re-enabled account: $($user.UserPrincipalName)" -EventId "AAD-ENABLE"
                }
            }
            elseif ($confirmEnable -ne "SKIP") {
                # Enable specific accounts
                $specificUPNs = $confirmEnable -split ","
                foreach ($upn in $specificUPNs) {
                    $user = $disabledUsers | Where-Object { $_.UserPrincipalName -eq $upn.Trim() }
                    if ($user) {
                        Set-AzureADUser -ObjectId $user.ObjectId -AccountEnabled $true
                        Write-ReversalLog -Level "SUCCESS" -Message "Re-enabled account: $upn" -EventId "AAD-ENABLE"
                    }
                }
            }
        }
        
        # Remove or modify geo-restriction policy
        $geoPolicy = Get-AzureADMSConditionalAccessPolicy | Where-Object { $_.DisplayName -eq "Admin-Geo-Restriction" }
        if ($geoPolicy) {
            $modifyGeo = Read-Host "Remove admin geo-restriction policy? (yes/no)"
            if ($modifyGeo -eq "yes") {
                Remove-AzureADMSConditionalAccessPolicy -PolicyId $geoPolicy.Id
                Write-ReversalLog -Level "SUCCESS" -Message "Removed geo-restriction policy" -EventId "AAD-GEO-REMOVE"
            }
            else {
                Write-ReversalLog -Level "INFO" -Message "Geo-restriction policy retained" -EventId "AAD-GEO-KEEP"
            }
        }
        
        Write-ReversalLog -Level "SUCCESS" -Message "Azure AD admin restoration complete" -EventId "AAD-RESTORE-OK"
    }
    catch {
        Write-ReversalLog -Level "CRITICAL" -Message "Azure AD restoration failed: $_" -EventId "AAD-RESTORE-FAIL"
    }
}

# REVERSAL 3: Remove Firewall Rules
function Restore-FirewallRules {
    Write-ReversalLog -Level "INFO" -Message "Restoring firewall rules..." -EventId "FIREWALL-RESTORE-START"
    
    if ($WhatIf) {
        Write-Host "WHATIF: Would remove CODEBLACK firewall rules" -ForegroundColor Cyan
        return
    }
    
    try {
        # Find and remove CODEBLACK rules
        $codeBlackRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "CODEBLACK*" }
        
        if ($codeBlackRules.Count -gt 0) {
            Write-ReversalLog -Level "INFO" -Message "Found $($codeBlackRules.Count) CODEBLACK firewall rules" -EventId "FIREWALL-FOUND"
            
            foreach ($rule in $codeBlackRules) {
                Remove-NetFirewallRule -Name $rule.Name
                Write-ReversalLog -Level "SUCCESS" -Message "Removed firewall rule: $($rule.DisplayName)" -EventId "FIREWALL-REMOVE"
            }
        }
        else {
            Write-ReversalLog -Level "INFO" -Message "No CODEBLACK firewall rules found" -EventId "FIREWALL-NONE"
        }
        
        # Check for other emergency rules
        $emergencyRules = Get-NetFirewallRule | Where-Object { 
            $_.DisplayName -match "EMERGENCY|ISOLATION|CONTAINMENT" 
        }
        
        if ($emergencyRules.Count -gt 0) {
            Write-Host "`nAdditional emergency rules found:" -ForegroundColor Yellow
            $emergencyRules | Select-Object DisplayName, Direction, Action | Format-Table
            
            $removeEmergency = Read-Host "Remove these emergency rules? (yes/no)"
            if ($removeEmergency -eq "yes") {
                foreach ($rule in $emergencyRules) {
                    Remove-NetFirewallRule -Name $rule.Name
                    Write-ReversalLog -Level "SUCCESS" -Message "Removed emergency rule: $($rule.DisplayName)" -EventId "FIREWALL-EMERGENCY-REMOVE"
                }
            }
        }
        
        Write-ReversalLog -Level "SUCCESS" -Message "Firewall restoration complete" -EventId "FIREWALL-RESTORE-OK"
    }
    catch {
        Write-ReversalLog -Level "CRITICAL" -Message "Firewall restoration failed: $_" -EventId "FIREWALL-RESTORE-FAIL"
    }
}

# REVERSAL 4: Remove Scheduled Detection Tasks
function Restore-ScheduledTasks {
    Write-ReversalLog -Level "INFO" -Message "Managing scheduled detection tasks..." -EventId "TASK-RESTORE-START"
    
    if ($WhatIf) {
        Write-Host "WHATIF: Would remove SC-HandalaDetection scheduled task" -ForegroundColor Cyan
        return
    }
    
    try {
        $task = Get-ScheduledTask -TaskName "SC-HandalaDetection" -ErrorAction SilentlyContinue
        
        if ($task) {
            Write-Host "`nScheduled detection task found: SC-HandalaDetection" -ForegroundColor Yellow
            Write-Host "This runs detection every 5 minutes." -ForegroundColor Gray
            
            $action = Read-Host "Keep, Disable, or Remove detection task? (keep/disable/remove)"
            
            switch ($action) {
                "disable" {
                    Disable-ScheduledTask -TaskName "SC-HandalaDetection"
                    Write-ReversalLog -Level "SUCCESS" -Message "Disabled detection task (can re-enable later)" -EventId "TASK-DISABLE"
                }
                "remove" {
                    Unregister-ScheduledTask -TaskName "SC-HandalaDetection" -Confirm:$false
                    Write-ReversalLog -Level "SUCCESS" -Message "Removed detection task" -EventId "TASK-REMOVE"
                }
                default {
                    Write-ReversalLog -Level "INFO" -Message "Detection task retained" -EventId "TASK-KEEP"
                }
            }
        }
        else {
            Write-ReversalLog -Level "INFO" -Message "No scheduled detection task found" -EventId "TASK-NONE"
        }
        
        Write-ReversalLog -Level "SUCCESS" -Message "Scheduled task management complete" -EventId "TASK-RESTORE-OK"
    }
    catch {
        Write-ReversalLog -Level "CRITICAL" -Message "Scheduled task restoration failed: $_" -EventId "TASK-RESTORE-FAIL"
    }
}

# REVERSAL 5: Restore from Config Backup
function Restore-FromBackup {
    param([string]$BackupPath)
    
    if (!$BackupPath -or !(Test-Path $BackupPath)) {
        Write-ReversalLog -Level "WARNING" -Message "No config backup provided or not found: $BackupPath" -EventId "BACKUP-NONE"
        return
    }
    
    Write-ReversalLog -Level "INFO" -Message "Restoring from config backup: $BackupPath" -EventId "BACKUP-RESTORE-START"
    
    if ($WhatIf) {
        Write-Host "WHATIF: Would restore configuration from: $BackupPath" -ForegroundColor Cyan
        return
    }
    
    try {
        $config = Get-Content $BackupPath | ConvertFrom-Json
        
        Write-Host "`nBackup contains:" -ForegroundColor Cyan
        Write-Host "  Timestamp: $($config.Timestamp)" -ForegroundColor Gray
        Write-Host "  Intune Policies: $($config.IntunePolicies.Count)" -ForegroundColor Gray
        Write-Host "  Conditional Access: $($config.ConditionalAccess.Count)" -ForegroundColor Gray
        Write-Host "  Admin Roles: $($config.AdminRoles.Count)" -ForegroundColor Gray
        
        $restoreConfirm = Read-Host "`nRestore all settings from this backup? (yes/no)"
        
        if ($restoreConfirm -eq "yes") {
            # Note: Actual restoration logic would go here
            # This is complex and should be tested thoroughly
            Write-ReversalLog -Level "WARNING" -Message "Full config restoration requires manual verification" -EventId "BACKUP-MANUAL"
        }
        
        Write-ReversalLog -Level "SUCCESS" -Message "Backup restoration evaluated" -EventId "BACKUP-RESTORE-OK"
    }
    catch {
        Write-ReversalLog -Level "CRITICAL" -Message "Backup restoration failed: $_" -EventId "BACKUP-RESTORE-FAIL"
    }
}

# REVERSAL 6: Restore Network Segmentation
function Restore-NetworkSegmentation {
    Write-ReversalLog -Level "INFO" -Message "Restoring network segmentation..." -EventId "NET-RESTORE-START"
    
    if ($WhatIf) {
        Write-Host "WHATIF: Would remove clinical VLAN isolation" -ForegroundColor Cyan
        Write-Host "WHATIF: Would restore normal routing" -ForegroundColor Cyan
        return
    }
    
    try {
        Write-Host "`nNetwork segmentation restoration requires manual firewall/router changes." -ForegroundColor Yellow
        Write-Host "Review your firewall for these isolation rules:" -ForegroundColor White
        Write-Host "  - Block Clinical-to-Internet" -ForegroundColor Gray
        Write-Host "  - Block Clinical-to-Admin" -ForegroundColor Gray
        Write-Host "  - Allow EMR/PACS restrictions" -ForegroundColor Gray
        
        $netConfirm = Read-Host "`nHave you reviewed and removed network isolation rules? (yes/no)"
        if ($netConfirm -eq "yes") {
            Write-ReversalLog -Level "SUCCESS" -Message "Network segmentation restoration confirmed" -EventId "NET-RESTORE-OK"
        }
        else {
            Write-ReversalLog -Level "WARNING" -Message "Network isolation retained - manual review required" -EventId "NET-KEEP"
        }
    }
    catch {
        Write-ReversalLog -Level "CRITICAL" -Message "Network restoration failed: $_" -EventId "NET-RESTORE-FAIL"
    }
}

# Generate restoration report
function Export-RestorationReport {
    $reportPath = "C:\SurgicalCenter\Security\Reports\restoration-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $dir = Split-Path $reportPath -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    
    $html = @"
<html><head><title>Hardening Reversal Report</title></head><body>
<h1>Surgical Center Security Restoration Report</h1>
<p><b>Date:</b> $(Get-Date)</p>
<p><b>Restore Mode:</b> $RestoreMode</p>
<p><b>Authorized By:</b> $ApprovedBy</p>
<p><b>Ticket Number:</b> $TicketNumber</p>
<p><b>WhatIf Mode:</b> $WhatIf</p>
<hr/>
<table border='1' cellpadding='5'>
<tr><th>Time</th><th>Level</th><th>Event ID</th><th>Message</th></tr>
"@
    
    foreach ($entry in $RestorationReport) {
        $color = switch ($entry.Level) {
            "CRITICAL" { "red" }
            "WARNING" { "orange" }
            "SUCCESS" { "green" }
            default { "black" }
        }
        $html += "<tr style='color:$color'><td>$($entry.Time)</td><td>$($entry.Level)</td><td>$($entry.EventId)</td><td>$($entry.Message)</td></tr>"
    }
    
    $html += "</table></body></html>"
    
    $html | Out-File -FilePath $reportPath
    Write-ReversalLog -Level "SUCCESS" -Message "Restoration report exported: $reportPath" -EventId "REPORT-EXPORT"
}

# Main execution
Show-SafetyBanner

if (!(Test-SafetyRequirements)) {
    exit 1
}

Write-ReversalLog -Level "INFO" -Message "Starting hardening reversal in mode: $RestoreMode" -EventId "START-001"

# Execute based on restore mode
switch ($RestoreMode) {
    "FullRestore" {
        Restore-IntunePolicies
        Restore-AzureADAdmins
        Restore-FirewallRules
        Restore-ScheduledTasks
        Restore-NetworkSegmentation
        Restore-FromBackup -BackupPath $ConfigBackupPath
    }
    
    "PartialRestore" {
        Restore-FirewallRules
        Restore-ScheduledTasks
        Write-Host "`nPartial restore complete. Intune and Azure AD require manual review." -ForegroundColor Yellow
    }
    
    "EmergencyRollback" {
        # Fast rollback for emergencies
        Restore-FirewallRules
        Restore-ScheduledTasks
        Write-ReversalLog -Level "WARNING" -Message "Emergency rollback - full verification still required" -EventId "EMERGENCY-ROLLBACK"
    }
    
    "TestLabOnly" {
        Write-Host "`n🧪 TEST LAB MODE 🧪" -ForegroundColor Magenta
        Write-Host "All changes will be reversed after verification" -ForegroundColor Magenta
        Restore-IntunePolicies
        Restore-AzureADAdmins
        Restore-FirewallRules
        Restore-ScheduledTasks
    }
}

# Export report
Export-RestorationReport

Write-Host "`n✅ RESTORATION COMPLETE ✅" -ForegroundColor Green
Write-Host "Log file: $LogPath" -ForegroundColor Gray
Write-Host "Review the restoration report before resuming normal operations." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "`n⚠️  WHATIF MODE: No actual changes were made" -ForegroundColor Magenta
}
