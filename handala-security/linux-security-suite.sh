#!/bin/bash
#
# Linux/Network Device Detection & Protection Scripts
# For: Surgical Center Network Infrastructure
# Author: ORDL Security Division
#

LOG_DIR="/var/log/surgical-center-security"
INCIDENT_ID=$(date +%Y%m%d-%H%M%S)
ALERT_EMAIL="security@surgicalcenter.com,it-director@surgicalcenter.com"

# Ensure log directory exists
mkdir -p $LOG_DIR

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S UTC')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_DIR/security-$INCIDENT_ID.log"
    
    # Send critical alerts via email
    if [[ "$level" == "CRITICAL" ]]; then
        echo "$message" | mail -s "[CRITICAL SECURITY ALERT] Surgical Center" $ALERT_EMAIL 2>/dev/null || true
    fi
}

# DETECTION 1: Mass SSH/Admin Login Attempts
detect_mass_logins() {
    log_message "INFO" "Running: Mass login detection"
    
    # Check for brute force or mass admin logins
    local failed_logins=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
    local recent_failed=$(grep "$(date '+%b %e %H')" /var/log/auth.log 2>/dev/null | grep -c "Failed password" || echo 0)
    
    if [[ $recent_failed -gt 20 ]]; then
        log_message "CRITICAL" "Mass failed login attempts detected: $recent_failed in current hour"
        
        # Show top offending IPs
        local top_ips=$(grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -5)
        log_message "WARNING" "Top offending IPs:\n$top_ips"
        
        # Auto-block if >50 attempts
        if [[ $recent_failed -gt 50 ]]; then
            log_message "CRITICAL" "Auto-blocking high-volume attack IPs"
            grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | awk '$1 > 50 {print $2}' | while read ip; do
                iptables -A INPUT -s $ip -j DROP
                log_message "INFO" "Blocked IP: $ip"
            done
        fi
        
        return 1
    fi
    
    log_message "INFO" "Login attempts normal: $recent_failed failed this hour"
    return 0
}

# DETECTION 2: Unusual Network Traffic (Wiper C2 detection)
detect_unusual_traffic() {
    log_message "INFO" "Running: Unusual traffic detection"
    
    # Check for large outbound transfers (data exfiltration)
    local large_transfers=$(netstat -tn 2>/dev/null | awk '$2 > 1000000 {print $0}' | wc -l)
    
    # Check for connections to known malicious countries (simplified - use GeoIP in production)
    local suspicious_countries=("IR" "RU" "CN" "KP")
    
    # Monitor for unusual port scanning
    local port_scan=$(grep -c "SCAN" /var/log/syslog 2>/dev/null || echo 0)
    
    if [[ $large_transfers -gt 10 ]]; then
        log_message "HIGH" "Large data transfers detected: $large_transfers connections"
        netstat -tn | awk '$2 > 1000000 {print $5}' | while read dest; do
            log_message "WARNING" "Large transfer to: $dest"
        done
        return 1
    fi
    
    if [[ $port_scan -gt 50 ]]; then
        log_message "HIGH" "Port scanning detected: $port_scan attempts"
        return 1
    fi
    
    log_message "INFO" "Network traffic patterns normal"
    return 0
}

# DETECTION 3: File System Integrity (Wiper detection)
detect_filesystem_anomalies() {
    log_message "INFO" "Running: Filesystem anomaly detection"
    
    # Monitor for rapid file deletion (wiper behavior)
    # Using auditd - requires auditd installed and configured
    
    if [[ -f /var/log/audit/audit.log ]]; then
        local deletions=$(grep -c "type=PATH.*name=.*delete" /var/log/audit/audit.log 2>/dev/null || echo 0)
        local recent_deletions=$(grep "$(date '+%H')" /var/log/audit/audit.log 2>/dev/null | grep -c "delete" || echo 0)
        
        if [[ $recent_deletions -gt 1000 ]]; then
            log_message "CRITICAL" "Mass file deletion detected: $recent_deletions files in current hour - POSSIBLE WIPER"
            
            # Emergency: Snapshot filesystem state
            find / -type f -mmin -5 2>/dev/null | head -20 | while read file; do
                log_message "WARNING" "Recently deleted/modified: $file"
            done
            
            return 1
        fi
    fi
    
    # Check for rootkit indicators
    if command -v rkhunter &> /dev/null; then
        rkhunter --check --skip-keypress 2>/dev/null | grep -i "warning\|infected" && {
            log_message "CRITICAL" "Rootkit indicators detected by rkhunter"
            return 1
        }
    fi
    
    log_message "INFO" "Filesystem integrity normal"
    return 0
}

# DETECTION 4: Critical Process Monitoring
detect_critical_processes() {
    log_message "INFO" "Running: Critical process monitoring"
    
    # Check if EMR/database processes are running
    local critical_processes=("mysqld" "postgres" "mssql" "epic" "cerner")
    local failed=0
    
    for proc in "${critical_processes[@]}"; do
        if ! pgrep -x "$proc" > /dev/null 2>&1; then
            log_message "WARNING" "Critical process not running: $proc"
            failed=$((failed + 1))
        fi
    done
    
    if [[ $failed -gt 0 ]]; then
        log_message "CRITICAL" "$failed critical processes not running - CHECK CLINICAL SYSTEMS"
        return 1
    fi
    
    # Check for suspicious processes (cryptominers, reverse shells)
    local suspicious=$(ps aux | grep -iE "(miner|xmr|pool|reverse|nc -e|bash -i)" | grep -v grep)
    if [[ ! -z "$suspicious" ]]; then
        log_message "CRITICAL" "Suspicious process detected:\n$suspicious"
        return 1
    fi
    
    log_message "INFO" "All critical processes running normally"
    return 0
}

# PROTECTION 1: Network Hardening
protect_network_hardening() {
    log_message "INFO" "Applying network hardening"
    
    # Enable strict SYN flood protection
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || true
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2>/dev/null || true
    
    # Block all traffic from high-risk countries (requires iptables + ipset)
    # This is a template - populate with actual threat intelligence
    
    # Drop invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP
    iptables -A FORWARD -m state --state INVALID -j DROP
    
    # Limit connection rate (prevent DoS)
    iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/minute --limit-burst 8 -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j DROP
    
    # Log and drop suspicious ports
    iptables -A INPUT -p tcp --dport 23,135,139,445,1433,3389 -j LOG --log-prefix "SUSPICIOUS_PORT: "
    iptables -A INPUT -p tcp --dport 23,135,139,445,1433,3389 -j DROP
    
    log_message "SUCCESS" "Network hardening applied"
}

# PROTECTION 2: File System Hardening
protect_filesystem_hardening() {
    log_message "INFO" "Applying filesystem hardening"
    
    # Make critical binaries immutable (requires chattr)
    critical_bins=("/bin/ls" "/bin/ps" "/bin/netstat" "/usr/bin/lsof")
    for bin in "${critical_bins[@]}"; do
        if [[ -f "$bin" ]]; then
            chattr +i "$bin" 2>/dev/null && log_message "INFO" "Made immutable: $bin"
        fi
    done
    
    # Enable auditd for file integrity monitoring
    if command -v auditctl &> /dev/null; then
        # Monitor critical directories for deletion
        auditctl -w /etc/passwd -p wa -k identity_changes 2>/dev/null || true
        auditctl -w /etc/shadow -p wa -k identity_changes 2>/dev/null || true
        auditctl -w /var/www/ -p wa -k web_changes 2>/dev/null || true
        auditctl -w /opt/emr/ -p wa -k emr_changes 2>/dev/null || true
        
        log_message "SUCCESS" "Auditd rules configured"
    fi
    
    # Create immutable backup marker files (detect wiper if deleted)
    for dir in "/etc" "/var/lib" "/opt"; do
        if [[ -d "$dir" ]]; then
            touch "$dir/.integrity_check_$INCIDENT_ID" 2>/dev/null || true
            chattr +i "$dir/.integrity_check_$INCIDENT_ID" 2>/dev/null || true
        fi
    done
    
    log_message "SUCCESS" "Filesystem hardening applied"
}

# PROTECTION 3: EMERGENCY KILL SWITCH
protect_emergency_isolation() {
    log_message "CRITICAL" "EMERGENCY ISOLATION REQUESTED"
    
    echo "
╔══════════════════════════════════════════════════════════╗
║     EMERGENCY NETWORK ISOLATION                         ║
╠══════════════════════════════════════════════════════════╣
║ This will ISOLATE this server from the network.          ║
║ Only emergency console access will remain.               ║
╚══════════════════════════════════════════════════════════╝
"
    
    read -p "Type 'ISOLATE NOW' to proceed: " confirm
    
    if [[ "$confirm" == "ISOLATE NOW" ]]; then
        log_message "CRITICAL" "EMERGENCY ISOLATION ACTIVATED"
        
        # Flush all rules
        iptables -F
        iptables -X
        
        # Default DROP
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT DROP
        
        # Allow loopback only
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        
        # Allow established connections (keep existing sessions)
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Allow SSH from specific admin IPs only (modify as needed)
        # iptables -A INPUT -p tcp --dport 22 -s ADMIN_IP -j ACCEPT
        
        log_message "CRITICAL" "System isolated. Only loopback traffic allowed."
        echo "System isolated. Use physical console or IPMI to restore."
    else
        log_message "INFO" "Emergency isolation cancelled"
    fi
}

# Main execution
main() {
    echo "=== Surgical Center Linux Security Suite ==="
    echo "Incident ID: $INCIDENT_ID"
    echo ""
    
    # Run detections
    local threats=0
    
    detect_mass_logins || threats=$((threats + 1))
    detect_unusual_traffic || threats=$((threats + 1))
    detect_filesystem_anomalies || threats=$((threats + 1))
    detect_critical_processes || threats=$((threats + 1))
    
    # Apply protections (run these regardless)
    protect_network_hardening
    protect_filesystem_hardening
    
    # Summary
    echo ""
    if [[ $threats -gt 0 ]]; then
        log_message "CRITICAL" "Detection complete. THREATS FOUND: $threats"
        exit 1
    else
        log_message "SUCCESS" "Detection complete. No threats detected."
        exit 0
    fi
}

# Check for emergency isolation mode
if [[ "$1" == "--emergency-isolate" ]]; then
    protect_emergency_isolation
    exit 0
fi

if [[ "$1" == "--detect-only" ]]; then
    # Run only detection, no hardening
    detect_mass_logins
    detect_unusual_traffic
    detect_filesystem_anomalies
    detect_critical_processes
    exit 0
fi

# Run full suite
main
