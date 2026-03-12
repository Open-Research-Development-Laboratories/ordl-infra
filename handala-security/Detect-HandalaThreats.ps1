#!/usr/bin/env pwsh
#Requires -Version 7.0
#Requires -Modules Az, AzureAD, Microsoft.Graph.Intune

<#
.SYNOPSIS
    Handala/Stryker-Style Wiper Attack Detection Suite
    For: Surgical Center Critical Infrastructure
    
.DESCRIPTION
    Continuous monitoring and detection for:
    - Mass Intune device wipe commands
    - Suspicious Azure AD admin activities  
    - OAuth app consent abuse
    - Abnormal EMR access patterns
    
.AUTHOR
    ORDL Security Division
    Classification: CRITICAL - Patient Safety
#>

param(
    [string]$LogPath = "C:\SurgicalCenter\Security\Logs\detection.log",
    [string]$AlertRecipients = "security@surgicalcenter.com,it-director@surgicalcenter.com",
    [int]$ThresholdWipeCommands = 5,  # Alert if >5 wipes in 5 minutes
    [switch]$AutoResponse,  # Enable automatic containment
    [switch]$TestMode  # Run without sending real alerts
)

# Initialize logging
function Write-DetectionLog {
    param([string]$Level, [string]$Message, [string]$EventId = "DETECT-001")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    $logEntry = "[$timestamp] [$Level] [$EventId] $Message"
    
    # Ensure log directory exists
    $logDir = Split-Path $LogPath -Parent
    if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force }
    
    Add-Content -Path $LogPath -Value $logEntry
    
    # Windows Event Log for SIEM integration
    if ($Level -eq "CRITICAL" -or $Level -eq "HIGH") {
        Write-EventLog -LogName Application -Source "SurgicalCenterSecurity" -EventId 1001 -EntryType Error -Message $logEntry -ErrorAction SilentlyContinue
    }
    
    Write-Host $logEntry -ForegroundColor $(if ($Level -eq "CRITICAL") { "Red" } elseif ($Level -eq "HIGH") { "Yellow" } else { "White" })
}

# Alert function
function Send-SecurityAlert {
    param(
        [string]$Severity,
        [string]$Title,
        [string]$Body,
        [string[]]$Attachments = @()
    )
    
    $recipients = $AlertRecipients -split ","
    
    foreach ($recipient in $recipients) {
        try {
            if (!$TestMode) {
                # Email alert
                Send-MailMessage -To $recipient -From "security-alerts@surgicalcenter.com" `
                    -Subject "[SECURITY ALERT - $Severity] $Title" `
                    -Body $Body -SmtpServer "mail.surgicalcenter.com" `
                    -Attachments $Attachments -Priority High -ErrorAction Stop
                
                # SMS via email-to-SMS gateway (configure with your provider)
                # Send-MailMessage -To "$recipient@txt.att.net" -Subject "ALERT" -Body "$Severity: $Title"
            }
            Write-DetectionLog -Level "INFO" -Message "Alert sent to $recipient: $Title" -EventId "ALERT-001"
        }
        catch {
            Write-DetectionLog -Level "CRITICAL" -Message "Failed to send alert to $recipient`: $_" -EventId "ALERT-FAIL"
        }
    }
}

# DETECTION RULE 1: Mass Intune Device Wipe Detection
function Test-MassIntuneWipe {
    Write-DetectionLog -Level "INFO" -Message "Running: Mass Intune Wipe Detection" -EventId "DETECT-001"
    
    try {
        $startTime = (Get-Date).AddMinutes(-5)
        
        # Query Intune audit logs for wipe commands
        $wipeActions = Get-IntuneAuditEvent -Filter "activityDateTime ge $($startTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))" | 
            Where-Object { $_.ActivityDisplayName -match "(wipe|retire|delete)" }
        
        if ($wipeActions.Count -gt $ThresholdWipeCommands) {
            $alert = @{
                Severity = "CRITICAL"
                Title = "HANDALA-STYLE MASS WIPE DETECTED"
                Body = @"
CRITICAL SECURITY ALERT - Immediate Action Required

Detection Time: $(Get-Date)
Threshold: $ThresholdWipeCommands wipe commands in 5 minutes
Actual: $($wipeActions.Count) wipe commands detected

Affected Devices:
$(($wipeActions | Select-Object -ExpandProperty TargetDisplayName) -join "`n")

Initiated By:
$(($wipeActions | Group-Object UserPrincipalName | Select-Object Name, Count) | Format-Table | Out-String)

RECOMMENDED ACTIONS:
1. IMMEDIATELY verify these are authorized administrative actions
2. If unauthorized: Activate CODE BLACK containment
3. Run: .\Containment-KillSwitch.ps1 -FullIsolation
4. Notify: Incident Commander, CISO, Legal Counsel

This pattern matches the Stryker/Handala attack methodology.
"@
            }
            
            Send-SecurityAlert @alert
            
            # Auto-response if enabled
            if ($AutoResponse) {
                Write-DetectionLog -Level "CRITICAL" -Message "Auto-response triggered: Disabling Intune device actions" -EventId "AUTO-001"
                Disable-IntuneDeviceActions
            }
            
            return $true
        }
        
        Write-DetectionLog -Level "INFO" -Message "Mass wipe check: Normal ($($wipeActions.Count) actions, threshold: $ThresholdWipeCommands)" -EventId "DETECT-001-OK"
        return $false
    }
    catch {
        Write-DetectionLog -Level "HIGH" -Message "Error in mass wipe detection: $_" -EventId "DETECT-001-ERR"
        return $false
    }
}

# DETECTION RULE 2: Suspicious Azure AD Admin Login
function Test-SuspiciousAdminLogin {
    Write-DetectionLog -Level "INFO" -Message "Running: Suspicious Admin Login Detection" -EventId "DETECT-002"
    
    try {
        $startTime = (Get-Date).AddMinutes(-15)
        $riskyCountries = @("Iran", "Russia", "China", "North Korea", "Syria")
        $riskyIps = @()  # Populate with known-bad IP ranges
        
        # Get sign-in logs
        $signIns = Get-AzureADAuditSignInLogs -Filter "createdDateTime ge $($startTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))" |
            Where-Object { 
                $_.UserPrincipalName -match "admin|administrator|global" -or
                $_.AppDisplayName -match "Intune|Azure AD|Microsoft Graph"
            }
        
        $suspicious = $signIns | Where-Object {
            $_.RiskState -eq "atRisk" -or
            $_.RiskLevelDuringSignIn -in @("high", "medium") -or
            $_.Location.CountryOrRegion -in $riskyCountries -or
            $_.IpAddress -in $riskyIps -or
            $_.ConditionalAccessStatus -eq "failure"
        }
        
        if ($suspicious.Count -gt 0) {
            $alert = @{
                Severity = "HIGH"
                Title = "Suspicious Administrative Login Detected"
                Body = @"
HIGH PRIORITY SECURITY ALERT

Suspicious administrative sign-ins detected in last 15 minutes.

Details:
$(($suspicious | Select-Object UserPrincipalName, IpAddress, Location, RiskState, RiskLevelDuringSignIn | Format-Table | Out-String))

RISK INDICATORS:
- Risk state: atRisk
- Geographic anomaly
- Conditional Access failure
- Admin privilege escalation

ACTIONS REQUIRED:
1. Verify each login with the administrator
2. If unauthorized: Revoke sessions immediately
3. Force password reset for affected accounts
4. Enable MFA if not already configured
"@
            }
            
            Send-SecurityAlert @alert
            return $true
        }
        
        Write-DetectionLog -Level "INFO" -Message "Admin login check: Normal" -EventId "DETECT-002-OK"
        return $false
    }
    catch {
        Write-DetectionLog -Level "HIGH" -Message "Error in admin login detection: $_" -EventId "DETECT-002-ERR"
        return $false
    }
}

# DETECTION RULE 3: OAuth App Consent Abuse
function Test-OAuthAbuse {
    Write-DetectionLog -Level "INFO" -Message "Running: OAuth App Consent Abuse Detection" -EventId "DETECT-003"
    
    try {
        $startTime = (Get-Date).AddHours(-1)
        
        # Get OAuth consent grants
        $consents = Get-AzureADAuditDirectoryLogs -Filter "activityDisplayName eq 'Consent to application' and activityDateTime ge $($startTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        
        $suspiciousApps = $consents | Where-Object {
            $targetResources = $_.TargetResources
            foreach ($resource in $targetResources) {
                $app = $resource.ModifiedProperties | Where-Object { $_.DisplayName -eq "AppId" }
                # Check for suspicious app names or high-risk permissions
                if ($app.NewValue -match "(wipe|delete|admin|intune|graph)" -or
                    $resource.DisplayName -notin @("Microsoft Intune", "Microsoft Graph", "Approved-App-1", "Approved-App-2")) {
                    return $true
                }
            }
            return $false
        }
        
        if ($suspiciousApps.Count -gt 0) {
            $alert = @{
                Severity = "HIGH"
                Title = "Suspicious OAuth App Consent Detected"
                Body = @"
Suspicious application consent grants detected.

This could indicate:
- Malicious app registration (backdoor)
- Compromised user account
- Supply chain attack via third-party app

Details:
$(($suspiciousApps | Select-Object ActivityDateTime, UserPrincipalName, @{N="AppName";E={$_.TargetResources[0].DisplayName}} | Format-Table | Out-String))

ACTIONS REQUIRED:
1. Review each app in Azure AD > App registrations
2. Verify if apps are business-approved
3. Revoke suspicious consents immediately
4. Audit all permissions granted
"@
            }
            
            Send-SecurityAlert @alert
            return $true
        }
        
        Write-DetectionLog -Level "INFO" -Message "OAuth consent check: Normal" -EventId "DETECT-003-OK"
        return $false
    }
    catch {
        Write-DetectionLog -Level "HIGH" -Message "Error in OAuth detection: $_" -EventId "DETECT-003-ERR"
        return $false
    }
}

# DETECTION RULE 4: EMR Access Anomaly
function Test-EMRAccessAnomaly {
    Write-DetectionLog -Level "INFO" -Message "Running: EMR Access Anomaly Detection" -EventId "DETECT-004"
    
    try {
        # This requires your EMR to expose logs (Epic, Cerner, etc.)
        # Example for Epic Hyperspace audit logs
        
        $epicLogPath = "\\epic-server\auditlogs\$(Get-Date -Format 'yyyy-MM-dd').log"
        
        if (Test-Path $epicLogPath) {
            $recentLogs = Get-Content $epicLogPath -Tail 1000 | ConvertFrom-Json
            
            # Detect bulk patient record access
            $bulkAccess = $recentLogs | Group-Object UserID | Where-Object { $_.Count -gt 50 }
            
            # Detect after-hours access
            $afterHours = $recentLogs | Where-Object { 
                $accessTime = [datetime]$_.AccessTime
                $accessTime.Hour -lt 6 -or $accessTime.Hour -gt 22
            }
            
            # Detect access from non-clinical workstations
            $nonClinicalAccess = $recentLogs | Where-Object {
                $_.Workstation -notmatch "(OR-|PACU-|ICU-|ED-|CLINIC-)"
            }
            
            if ($bulkAccess.Count -gt 0 -or $afterHours.Count -gt 10) {
                $alert = @{
                    Severity = "MEDIUM"
                    Title = "EMR Access Anomaly Detected"
                    Body = @"
Anomalous EMR access patterns detected.

Bulk Access (possible data exfiltration):
$(($bulkAccess | Select-Object Name, Count | Format-Table | Out-String))

After-Hours Access:
$($afterHours.Count) accesses outside normal hours

Non-Clinical Workstation Access:
$($nonClinicalAccess.Count) accesses from non-standard workstations

ACTIONS REQUIRED:
1. Verify with clinical staff if after-hours access is legitimate
2. Review bulk access for authorized research/billing
3. Check if non-clinical workstations are in admin areas
"@
                }
                
                Send-SecurityAlert @alert
                return $true
            }
        }
        
        Write-DetectionLog -Level "INFO" -Message "EMR access check: Normal" -EventId "DETECT-004-OK"
        return $false
    }
    catch {
        Write-DetectionLog -Level "HIGH" -Message "Error in EMR detection: $_" -EventId "DETECT-004-ERR"
        return $false
    }
}

# DETECTION RULE 5: Network Anomaly (Clinical Device Disconnect)
function Test-ClinicalDeviceDisconnect {
    Write-DetectionLog -Level "INFO" -Message "Running: Clinical Device Disconnect Detection" -EventId "DETECT-005"
    
    try {
        # Query network monitoring system (example with SNMP/Ping)
        $clinicalDevices = @(
            @{Name="Anesthesia-OR1"; IP="10.100.1.10"},
            @{Name="Monitor-OR1"; IP="10.100.1.11"},
            @{Name="Anesthesia-OR2"; IP="10.100.1.20"},
            @{Name="Monitor-OR2"; IP="10.100.1.21"}
            # Add all critical devices
        )
        
        $disconnected = @()
        foreach ($device in $clinicalDevices) {
            $ping = Test-Connection -ComputerName $device.IP -Count 1 -Quiet
            if (!$ping) {
                $disconnected += $device
            }
        }
        
        if ($disconnected.Count -gt 0) {
            $alert = @{
                Severity = "CRITICAL"
                Title = "CRITICAL: Clinical Device Network Disconnect"
                Body = @"
CRITICAL PATIENT SAFETY ALERT

The following clinical devices have lost network connectivity:
$(($disconnected | ForEach-Object { "- $($_.Name) ($($_.IP))" }) -join "`n")

POTENTIAL CAUSES:
- Cyberattack (network isolation)
- Network infrastructure failure
- Device malfunction

IMMEDIATE ACTIONS:
1. Verify physical device operation (local display)
2. If devices are hard-down: Implement manual monitoring protocols
3. Check network switch status
4. If cyberattack suspected: Activate CODE BLACK
5. Notify Clinical Engineering immediately
"@
            }
            
            Send-SecurityAlert @alert
            return $true
        }
        
        Write-DetectionLog -Level "INFO" -Message "Clinical device check: All connected" -EventId "DETECT-005-OK"
        return $false
    }
    catch {
        Write-DetectionLog -Level "HIGH" -Message "Error in device disconnect detection: $_" -EventId "DETECT-005-ERR"
        return $false
    }
}

# Main execution
function Start-DetectionSuite {
    Write-DetectionLog -Level "INFO" -Message "=== Starting Handala/Stryker Detection Suite ===" -EventId "START-001"
    
    $detections = @(
        @{ Name = "Mass Intune Wipe"; Function = ${function:Test-MassIntuneWipe} }
        @{ Name = "Suspicious Admin Login"; Function = ${function:Test-SuspiciousAdminLogin} }
        @{ Name = "OAuth Abuse"; Function = ${function:Test-OAuthAbuse} }
        @{ Name = "EMR Anomaly"; Function = ${function:Test-EMRAccessAnomaly} }
        @{ Name = "Clinical Device Disconnect"; Function = ${function:Test-ClinicalDeviceDisconnect} }
    )
    
    $threatsFound = 0
    foreach ($detection in $detections) {
        Write-Host "`nRunning detection: $($detection.Name)..." -ForegroundColor Cyan
        $result = & $detection.Function
        if ($result) { $threatsFound++ }
    }
    
    Write-DetectionLog -Level $(if ($threatsFound -gt 0) { "CRITICAL" } else { "INFO" }) `
        -Message "Detection cycle complete. Threats found: $threatsFound" -EventId "COMPLETE-001"
    
    return $threatsFound
}

# Run detection suite
Start-DetectionSuite
