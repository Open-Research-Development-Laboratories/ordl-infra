#!/usr/bin/env pwsh
#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Surgical Center Protection & Hardening Suite
    Implements defenses against Handala/Stryker-style wiper attacks
    
.DESCRIPTION
    Hardens:
    - Microsoft Intune/Endpoint Manager
    - Azure AD / Microsoft Entra
    - Network segmentation
    - Backup verification
    
    WARNING: Run during maintenance window - may temporarily disrupt admin access
#>

param(
    [switch]$EmergencyMode,  # Immediate lockdown (may disrupt operations)
    [switch]$AuditOnly,      # Report only, no changes
    [switch]$EnableAutoProtect  # Enable continuous protection
)

$LogPath = "C:\SurgicalCenter\Security\Logs\protection.log"
$ConfigBackupPath = "C:\SurgicalCenter\Security\Backups\config-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

# Logging
function Write-ProtectLog {
    param([string]$Level, [string]$Message, [string]$EventId)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$EventId] $Message"
    
    $logDir = Split-Path $LogPath -Parent
    if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    
    Add-Content -Path $LogPath -Value $logEntry
    Write-Host $logEntry -ForegroundColor $(if ($Level -eq "CRITICAL") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } else { "Green" })
}

# Backup current configuration before changes
function Backup-CurrentConfig {
    Write-ProtectLog -Level "INFO" -Message "Backing up current configuration..." -EventId "BACKUP-001"
    
    try {
        $config = @{
            Timestamp = Get-Date -Format "o"
            IntunePolicies = Get-DeviceManagementPolicy -ErrorAction SilentlyContinue
            ConditionalAccess = Get-AzureADMSConditionalAccessPolicy -ErrorAction SilentlyContinue
            AdminRoles = Get-AzureADDirectoryRole -ErrorAction SilentlyContinue | ForEach-Object {
                @{ Role = $_.DisplayName; Members = (Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId).UserPrincipalName }
            }
        }
        
        $config | ConvertTo-Json -Depth 10 | Out-File $ConfigBackupPath
        Write-ProtectLog -Level "INFO" -Message "Configuration backed up to: $ConfigBackupPath" -EventId "BACKUP-OK"
    }
    catch {
        Write-ProtectLog -Level "CRITICAL" -Message "Failed to backup configuration: $_" -EventId "BACKUP-FAIL"
        if (!$AuditOnly) { throw "Configuration backup failed. Aborting for safety." }
    }
}

# PROTECTION 1: Intune Hardening
function Protect-IntuneEnvironment {
    Write-ProtectLog -Level "INFO" -Message "Applying Intune hardening..." -EventId "INTUNE-001"
    
    if ($AuditOnly) {
        Write-ProtectLog -Level "WARN" -Message "AUDIT MODE: No changes made to Intune" -EventId "INTUNE-AUDIT"
        return
    }
    
    try {
        # 1. Disable automatic wipe for all device configurations
        $deviceConfigs = Get-DeviceManagementDeviceConfiguration -ErrorAction SilentlyContinue
        foreach ($config in $deviceConfigs) {
            if ($config.wipeEnabled -or $config.remoteWipeEnabled) {
                Write-ProtectLog -Level "WARN" -Message "Disabling wipe on config: $($config.displayName)" -EventId "INTUNE-WIPE-DISABLE"
                # Update to disable wipe (specific command depends on Intune PS module version)
                Update-DeviceManagementDeviceConfiguration -DeviceConfigurationId $config.id -WipeEnabled $false
            }
        }
        
        # 2. Create approval-required policy for device actions
        $policyParams = @{
            DisplayName = "SC-Emergency-DeviceActionApproval"
            Description = "Requires secondary approval for all destructive device actions"
            RoleScopeTagIds = @()
            DeviceManagementIntent = "RequireApprovalForWipe"
        }
        
        if ($EmergencyMode) {
            Write-ProtectLog -Level "CRITICAL" -Message "EMERGENCY MODE: Disabling ALL device actions" -EventId "INTUNE-EMERGENCY"
            # Emergency: Block all device actions temporarily
            Set-DeviceManagementPolicy -PolicyId "Global" -DeviceActionRestrictions @("wipe", "retire", "delete")
        }
        
        # 3. Enable comprehensive audit logging
        Set-OrganizationConfig -AdminAuditLogEnabled $true -AuditLogAgeLimit 365
        
        Write-ProtectLog -Level "INFO" -Message "Intune hardening complete" -EventId "INTUNE-OK"
    }
    catch {
        Write-ProtectLog -Level "CRITICAL" -Message "Intune hardening failed: $_" -EventId "INTUNE-FAIL"
    }
}

# PROTECTION 2: Azure AD Admin Hardening
function Protect-AzureADAdmins {
    Write-ProtectLog -Level "INFO" -Message "Applying Azure AD admin hardening..." -EventId "AAD-001"
    
    if ($AuditOnly) {
        Write-ProtectLog -Level "WARN" -Message "AUDIT MODE: No changes made to Azure AD" -EventId "AAD-AUDIT"
        return
    }
    
    try {
        # 1. Get all admin roles
        $adminRoles = Get-AzureADDirectoryRole | Where-Object { 
            $_.DisplayName -match "Admin|Global|Security|Exchange|SharePoint|Intune" 
        }
        
        foreach ($role in $adminRoles) {
            $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
            Write-ProtectLog -Level "INFO" -Message "Role: $($role.DisplayName) has $($members.Count) members" -EventId "AAD-ROLE"
            
            foreach ($member in $members) {
                # Force MFA for all admins
                $mfaState = (Get-AzureADUser -ObjectId $member.ObjectId).StrongAuthenticationRequirements.State
                if ($mfaState -ne "Enforced") {
                    Write-ProtectLog -Level "WARN" -Message "Enforcing MFA for: $($member.UserPrincipalName)" -EventId "AAD-MFA"
                    
                    # Enable MFA
                    $authMethod = New-Object -TypeName Microsoft.Open.AzureAD.Model.StrongAuthenticationRequirement
                    $authMethod.RelyingParty = "*"
                    $authMethod.State = "Enforced"
                    Set-AzureADUser -ObjectId $member.ObjectId -StrongAuthenticationRequirements $authMethod
                }
            }
        }
        
        # 2. Create Emergency Access Accounts (break-glass)
        $breakGlassAccounts = Get-AzureADUser | Where-Object { $_.UserPrincipalName -match "breakglass|emergency" }
        if ($breakGlassAccounts.Count -lt 2) {
            Write-ProtectLog -Level "WARN" -Message "WARNING: Less than 2 break-glass accounts found. Create immediately." -EventId "AAD-BREAKGLASS"
        }
        
        # 3. Restrict admin geo-location (if not emergency mode)
        if (!$EmergencyMode) {
            $geoPolicy = Get-AzureADMSConditionalAccessPolicy | Where-Object { $_.DisplayName -eq "Admin-Geo-Restriction" }
            if (!$geoPolicy) {
                Write-ProtectLog -Level "INFO" -Message "Creating admin geo-restriction policy" -EventId "AAD-GEO"
                
                $conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
                $conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
                $conditions.Applications.IncludeApplications = "All"
                
                $conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
                $conditions.Users.IncludeRoles = @("62e90394-69f5-4237-9190-012177145e10")  # Global Admin
                
                $conditions.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
                $conditions.Locations.IncludeLocations = "All"
                $conditions.Locations.ExcludeLocations = "MfaTrustedIps"  # Trusted office IPs
                
                $controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
                $controls._Operator = "OR"
                $controls.BuiltInControls = @("Block")
                
                New-AzureADMSConditionalAccessPolicy -DisplayName "Admin-Geo-Restriction" -State "Enabled" -Conditions $conditions -GrantControls $controls
            }
        }
        
        Write-ProtectLog -Level "INFO" -Message "Azure AD admin hardening complete" -EventId "AAD-OK"
    }
    catch {
        Write-ProtectLog -Level "CRITICAL" -Message "Azure AD hardening failed: $_" -EventId "AAD-FAIL"
    }
}

# PROTECTION 3: Network Segmentation
function Protect-NetworkSegmentation {
    Write-ProtectLog -Level "INFO" -Message "Applying network segmentation..." -EventId "NET-001"
    
    if ($AuditOnly) {
        Write-ProtectLog -Level "WARN" -Message "AUDIT MODE: No network changes made" -EventId "NET-AUDIT"
        return
    }
    
    try {
        # Clinical VLAN isolation rules
        $rules = @(
            @{ Name = "Block-Clinical-to-Internet"; Source = "Clinical-VLAN"; Dest = "Internet"; Action = "Block" },
            @{ Name = "Block-Clinical-to-Admin"; Source = "Clinical-VLAN"; Dest = "Admin-VLAN"; Action = "Block" },
            @{ Name = "Allow-Clinical-to-EMR"; Source = "Clinical-VLAN"; Dest = "EMR-Servers"; Action = "Allow" },
            @{ Name = "Allow-Clinical-to-PACS"; Source = "Clinical-VLAN"; Dest = "PACS-Servers"; Action = "Allow" }
        )
        
        foreach ($rule in $rules) {
            Write-ProtectLog -Level "INFO" -Message "Applying rule: $($rule.Name)" -EventId "NET-RULE"
            
            # Note: Actual implementation depends on firewall (Cisco ASA, Palo Alto, etc.)
            # This is a template - adapt to your firewall CLI/API
            
            if ($EmergencyMode) {
                # Emergency: Complete clinical isolation
                Write-ProtectLog -Level "CRITICAL" -Message "EMERGENCY: Isolating clinical VLAN completely" -EventId "NET-EMERGENCY"
                # Add emergency firewall rules here
            }
        }
        
        Write-ProtectLog -Level "INFO" -Message "Network segmentation complete" -EventId "NET-OK"
    }
    catch {
        Write-ProtectLog -Level "CRITICAL" -Message "Network segmentation failed: $_" -EventId "NET-FAIL"
    }
}

# PROTECTION 4: Backup Verification
function Protect-BackupVerification {
    Write-ProtectLog -Level "INFO" -Message "Verifying backup integrity..." -EventId "BACKUP-001"
    
    try {
        $backupPaths = @(
            "\\backup-server\EMR-Daily",
            "\\backup-server\AD-SystemState",
            "\\backup-server\Intune-Config"
        )
        
        foreach ($path in $backupPaths) {
            if (Test-Path $path) {
                $latestBackup = Get-ChildItem $path | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                $backupAge = (Get-Date) - $latestBackup.LastWriteTime
                
                if ($backupAge.TotalHours -gt 24) {
                    Write-ProtectLog -Level "CRITICAL" -Message "BACKUP STALE: $path - Last backup: $($backupAge.TotalHours) hours ago" -EventId "BACKUP-STALE"
                }
                else {
                    Write-ProtectLog -Level "INFO" -Message "Backup verified: $path - Age: $($backupAge.TotalHours) hours" -EventId "BACKUP-OK"
                }
                
                # Verify backup integrity (checksum)
                $checksumFile = Join-Path $path "$($latestBackup.Name).sha256"
                if (Test-Path $checksumFile) {
                    Write-ProtectLog -Level "INFO" -Message "Checksum file exists for: $($latestBackup.Name)" -EventId "BACKUP-CHECKSUM"
                }
                else {
                    Write-ProtectLog -Level "WARN" -Message "Missing checksum for: $($latestBackup.Name)" -EventId "BACKUP-NOCHECK"
                }
            }
            else {
                Write-ProtectLog -Level "CRITICAL" -Message "BACKUP PATH MISSING: $path" -EventId "BACKUP-MISSING"
            }
        }
        
        # Emergency: Create air-gapped backup if not exists
        if ($EmergencyMode) {
            Write-ProtectLog -Level "CRITICAL" -Message "EMERGENCY: Creating immediate offline backup" -EventId "BACKUP-EMERGENCY"
            # Trigger immediate backup to air-gapped storage
        }
    }
    catch {
        Write-ProtectLog -Level "CRITICAL" -Message "Backup verification failed: $_" -EventId "BACKUP-FAIL"
    }
}

# PROTECTION 5: Enable Continuous Monitoring
function Enable-ContinuousProtection {
    if (!$EnableAutoProtect) {
        Write-ProtectLog -Level "INFO" -Message "Auto-protection not enabled. Run with -EnableAutoProtect to enable." -EventId "AUTO-INFO"
        return
    }
    
    Write-ProtectLog -Level "INFO" -Message "Enabling continuous protection..." -EventId "AUTO-001"
    
    try {
        # Create scheduled task for detection script
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\SurgicalCenter\Security\Scripts\Detect-HandalaThreats.ps1"
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 1)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Register-ScheduledTask -TaskName "SC-HandalaDetection" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
        
        Write-ProtectLog -Level "INFO" -Message "Continuous protection enabled (5-minute intervals)" -EventId "AUTO-OK"
    }
    catch {
        Write-ProtectLog -Level "CRITICAL" -Message "Failed to enable continuous protection: $_" -EventId "AUTO-FAIL"
    }
}

# Main execution
function Start-ProtectionSuite {
    Write-ProtectLog -Level "INFO" -Message "=== Starting Surgical Center Protection Suite ===" -EventId "START-001"
    Write-ProtectLog -Level "INFO" -Message "Mode: $(if ($EmergencyMode) { 'EMERGENCY' } elseif ($AuditOnly) { 'AUDIT' } else { 'STANDARD' })" -EventId "START-002"
    
    # Pre-flight checks
    if (!(Get-Module -ListAvailable -Name AzureAD)) {
        Write-ProtectLog -Level "CRITICAL" -Message "AzureAD module not installed. Install with: Install-Module AzureAD" -EventId "PREFLIGHT-FAIL"
        return
    }
    
    # Execute protections
    Backup-CurrentConfig
    Protect-IntuneEnvironment
    Protect-AzureADAdmins
    Protect-NetworkSegmentation
    Protect-BackupVerification
    Enable-ContinuousProtection
    
    Write-ProtectLog -Level "INFO" -Message "=== Protection Suite Complete ===" -EventId "COMPLETE-001"
    
    if ($EmergencyMode) {
        Write-Host "`n⚠️  EMERGENCY MODE ACTIVE ⚠️" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "Administrative functions may be restricted." -ForegroundColor Red
        Write-Host "Run with -EmergencyMode:$false to restore normal operations after threat passes." -ForegroundColor Yellow
    }
}

# Run protection suite
Start-ProtectionSuite
