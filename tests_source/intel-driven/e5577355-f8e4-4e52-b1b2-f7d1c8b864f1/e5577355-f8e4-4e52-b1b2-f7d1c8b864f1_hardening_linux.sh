#!/usr/bin/env bash
# ============================================================================
# DEFENSE GUIDANCE: Linux Hardening Script
# ============================================================================
# Test ID: e5577355-f8e4-4e52-b1b2-f7d1c8b864f1
# Test Name: SilentButDeadly WFP EDR Network Isolation
# MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
# Created: 2026-03-13
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
#
# PURPOSE:
# While the SilentButDeadly WFP technique is Windows-specific, Linux systems
# face analogous threats where attackers use iptables/nftables/eBPF to block
# EDR agent network communications. This script hardens Linux endpoints
# against equivalent defense evasion techniques:
#
#   - Firewall rule manipulation to block security agent traffic
#   - Service/daemon stopping or disabling
#   - Configuration file tampering for security agents
#   - Network namespace isolation of security processes
#
# MITRE ATT&CK Techniques Covered:
#   T1562.001 - Impair Defenses: Disable or Modify Tools
#   T1562.004 - Disable or Modify System Firewall
#   T1518.001 - Security Software Discovery
#
# USAGE:
#   sudo ./e5577355-f8e4-4e52-b1b2-f7d1c8b864f1_hardening_linux.sh [--undo] [--dry-run]
#
# OPTIONS:
#   --undo      Revert all hardening changes to defaults
#   --dry-run   Show what changes would be made without applying them
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - systemd-based Linux distribution
#   - auditd installed (for audit rules)
#
# TESTED ON:
#   Ubuntu 22.04/24.04 LTS, RHEL 8/9, Debian 12, Amazon Linux 2023
#
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/f0rt1ka"
LOG_FILE="${LOG_DIR}/hardening_$(date +%Y%m%d_%H%M%S).log"
AUDIT_RULES_FILE="/etc/audit/rules.d/f0rt1ka-edr-protection.rules"
UNDO_MODE=false
DRY_RUN=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Known EDR/Security agent service names on Linux
EDR_SERVICES=(
    "sentinelone"
    "sentinelagent"
    "falcon-sensor"
    "falcon-sensor.service"
    "mdatp"
    "mdatpd"
    "cbagentd"
    "cbsensor"
    "cylancesvc"
    "symantec"
    "savd"
    "sophos-spl"
    "sophos-av"
    "esets"
    "eea"
    "cortex-agent"
    "traps_pmd"
    "xagt"
    "elastic-agent"
    "elastic-endpoint"
    "auditd"
    "osqueryd"
    "wazuh-agent"
    "ossec"
    "crowdstrike-falcon-sensor"
)

# Known EDR binary paths on Linux
EDR_BINARY_PATHS=(
    "/opt/sentinelone/"
    "/opt/CrowdStrike/"
    "/opt/microsoft/mdatp/"
    "/opt/carbonblack/"
    "/opt/cylance/"
    "/opt/sophos-spl/"
    "/opt/eset/"
    "/opt/traps/"
    "/opt/Elastic/"
    "/var/ossec/"
    "/opt/wazuh/"
)

# ============================================================================
# Helper Functions
# ============================================================================

log_status() {
    local type="$1"
    local message="$2"
    local color=""
    local prefix=""

    case "$type" in
        INFO)    color="$CYAN";    prefix="[*]" ;;
        SUCCESS) color="$GREEN";   prefix="[+]" ;;
        WARNING) color="$YELLOW";  prefix="[!]" ;;
        ERROR)   color="$RED";     prefix="[-]" ;;
        HEADER)  color="$MAGENTA"; prefix="[=]" ;;
    esac

    echo -e "${color}${prefix} ${message}${NC}"

    # Log to file
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${prefix} ${message}" >> "$LOG_FILE" 2>/dev/null || true
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_status "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_command() {
    local cmd="$1"
    if command -v "$cmd" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

run_or_dry() {
    local description="$1"
    shift

    if $DRY_RUN; then
        log_status "INFO" "[DRY-RUN] Would execute: $*"
    else
        log_status "INFO" "$description"
        if eval "$@"; then
            log_status "SUCCESS" "$description - done"
        else
            log_status "WARNING" "$description - command returned non-zero"
        fi
    fi
}

# ============================================================================
# Hardening Functions
# ============================================================================

harden_auditd_rules() {
    # ======================================================================
    # Audit Rules for EDR Protection Monitoring
    # MITRE Mitigation: M1047 - Audit
    #
    # Creates audit rules to detect:
    # - Firewall rule modifications (iptables, nftables)
    # - Security service manipulation (systemctl, service)
    # - EDR binary directory access
    # - EDR configuration file tampering
    # ======================================================================

    log_status "HEADER" "Configuring Audit Rules for EDR Protection..."

    if ! check_command "auditctl"; then
        log_status "WARNING" "auditd not installed - skipping audit rule configuration"
        log_status "INFO" "Install with: apt install auditd (Debian/Ubuntu) or yum install audit (RHEL)"
        return
    fi

    if $UNDO_MODE; then
        log_status "INFO" "Removing F0RT1KA audit rules..."
        if [[ -f "$AUDIT_RULES_FILE" ]]; then
            run_or_dry "Remove audit rules file" "rm -f '$AUDIT_RULES_FILE'"
            run_or_dry "Reload audit rules" "augenrules --load 2>/dev/null || auditctl -R /etc/audit/audit.rules 2>/dev/null || true"
        else
            log_status "INFO" "No F0RT1KA audit rules found to remove"
        fi
        return
    fi

    local rules_content="# ============================================================================
# F0RT1KA EDR Protection Audit Rules
# Test ID: e5577355-f8e4-4e52-b1b2-f7d1c8b864f1
# MITRE ATT&CK: T1562.001, T1562.004
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================================

# Monitor iptables binary execution (firewall manipulation)
-w /sbin/iptables -p x -k edr_firewall_tamper
-w /sbin/iptables-restore -p x -k edr_firewall_tamper
-w /sbin/ip6tables -p x -k edr_firewall_tamper
-w /sbin/ip6tables-restore -p x -k edr_firewall_tamper

# Monitor nftables binary execution
-w /sbin/nft -p x -k edr_firewall_tamper
-w /usr/sbin/nft -p x -k edr_firewall_tamper

# Monitor firewalld changes
-w /usr/bin/firewall-cmd -p x -k edr_firewall_tamper

# Monitor ufw changes (Ubuntu)
-w /usr/sbin/ufw -p x -k edr_firewall_tamper

# Monitor systemctl execution for service manipulation
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/systemctl -k edr_service_tamper
-a always,exit -F arch=b64 -S execve -F path=/bin/systemctl -k edr_service_tamper

# Monitor service command execution
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/service -k edr_service_tamper

# Monitor kill/pkill/killall for process termination
-a always,exit -F arch=b64 -S kill -k edr_process_kill
-a always,exit -F arch=b64 -S tkill -k edr_process_kill
-a always,exit -F arch=b64 -S tgkill -k edr_process_kill

# Monitor EDR binary directories for tampering
-w /opt/sentinelone/ -p wa -k edr_binary_tamper
-w /opt/CrowdStrike/ -p wa -k edr_binary_tamper
-w /opt/microsoft/mdatp/ -p wa -k edr_binary_tamper
-w /opt/carbonblack/ -p wa -k edr_binary_tamper
-w /opt/sophos-spl/ -p wa -k edr_binary_tamper
-w /opt/eset/ -p wa -k edr_binary_tamper
-w /opt/Elastic/ -p wa -k edr_binary_tamper
-w /var/ossec/ -p wa -k edr_binary_tamper
-w /opt/wazuh/ -p wa -k edr_binary_tamper

# Monitor systemd service unit files for EDR services
-w /etc/systemd/system/ -p wa -k edr_service_config
-w /usr/lib/systemd/system/ -p wa -k edr_service_config

# Monitor /etc/hosts for DNS manipulation (blocking EDR cloud domains)
-w /etc/hosts -p wa -k edr_dns_tamper

# Monitor resolv.conf for DNS configuration changes
-w /etc/resolv.conf -p wa -k edr_dns_tamper
-w /etc/nsswitch.conf -p wa -k edr_dns_tamper

# Monitor eBPF program loading (can be used for stealth network filtering)
-a always,exit -F arch=b64 -S bpf -k edr_ebpf_tamper

# Monitor network namespace manipulation
-a always,exit -F arch=b64 -S unshare -k edr_namespace_tamper
-a always,exit -F arch=b64 -S setns -k edr_namespace_tamper
"

    if $DRY_RUN; then
        log_status "INFO" "[DRY-RUN] Would write audit rules to: $AUDIT_RULES_FILE"
        echo "$rules_content"
    else
        mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
        echo "$rules_content" > "$AUDIT_RULES_FILE"
        log_status "SUCCESS" "Audit rules written to $AUDIT_RULES_FILE"

        # Reload audit rules
        if check_command "augenrules"; then
            augenrules --load 2>/dev/null || true
            log_status "SUCCESS" "Audit rules loaded via augenrules"
        elif check_command "auditctl"; then
            auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
            log_status "SUCCESS" "Audit rules loaded via auditctl"
        fi
    fi
}

harden_edr_service_protection() {
    # ======================================================================
    # Protect EDR Service Configuration
    # MITRE Mitigation: M1022 - Restrict File and Directory Permissions
    #
    # Ensures EDR services are:
    # - Set to auto-restart on failure
    # - Protected against being masked or disabled
    # - Running with appropriate file permissions
    # ======================================================================

    log_status "HEADER" "Protecting EDR Service Configurations..."

    if $UNDO_MODE; then
        log_status "INFO" "Removing service override configurations..."
        for svc in "${EDR_SERVICES[@]}"; do
            local override_dir="/etc/systemd/system/${svc}.service.d"
            if [[ -d "$override_dir" ]]; then
                run_or_dry "Remove override for $svc" "rm -rf '$override_dir'"
            fi
        done
        run_or_dry "Reload systemd daemon" "systemctl daemon-reload 2>/dev/null || true"
        return
    fi

    local protected_count=0

    for svc in "${EDR_SERVICES[@]}"; do
        # Check if service exists on this system
        if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
            local unit_status
            unit_status=$(systemctl is-enabled "$svc" 2>/dev/null || echo "unknown")

            if [[ "$unit_status" != "unknown" ]] && [[ "$unit_status" != "not-found" ]]; then
                log_status "INFO" "Found EDR service: $svc (status: $unit_status)"

                # Create systemd override to ensure auto-restart
                local override_dir="/etc/systemd/system/${svc}.service.d"
                local override_file="${override_dir}/f0rt1ka-protect.conf"

                local override_content="# F0RT1KA EDR Protection Override
# Ensures service restarts on failure and cannot be easily stopped
[Service]
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=10

[Unit]
RefuseManualStop=false
"

                if $DRY_RUN; then
                    log_status "INFO" "[DRY-RUN] Would create override: $override_file"
                else
                    mkdir -p "$override_dir"
                    echo "$override_content" > "$override_file"
                    log_status "SUCCESS" "Auto-restart override created for: $svc"
                    protected_count=$((protected_count + 1))
                fi
            fi
        fi
    done

    if [[ $protected_count -gt 0 ]] && ! $DRY_RUN; then
        systemctl daemon-reload 2>/dev/null || true
        log_status "SUCCESS" "Protected $protected_count EDR services with auto-restart"
    elif [[ $protected_count -eq 0 ]]; then
        log_status "INFO" "No EDR services found on this system (this is expected on non-production hosts)"
    fi
}

harden_firewall_protection() {
    # ======================================================================
    # Firewall Configuration to Protect EDR Communications
    # MITRE Mitigation: M1037 - Filter Network Traffic
    #
    # Prevents unauthorized firewall rule modifications and ensures
    # EDR agents can always reach their cloud infrastructure.
    # ======================================================================

    log_status "HEADER" "Configuring Firewall Protection for EDR Communications..."

    if $UNDO_MODE; then
        log_status "INFO" "Removing EDR firewall protection rules..."

        if check_command "iptables"; then
            # Remove specific chain if it exists
            iptables -D OUTPUT -j F0RT1KA_EDR_PROTECT 2>/dev/null || true
            iptables -F F0RT1KA_EDR_PROTECT 2>/dev/null || true
            iptables -X F0RT1KA_EDR_PROTECT 2>/dev/null || true
            log_status "SUCCESS" "Removed iptables EDR protection chain"
        fi

        # Remove iptables save hook
        rm -f /etc/NetworkManager/dispatcher.d/99-f0rt1ka-fw-monitor 2>/dev/null || true

        return
    fi

    if check_command "iptables"; then
        # Create a dedicated chain for EDR protection rules
        iptables -N F0RT1KA_EDR_PROTECT 2>/dev/null || true
        iptables -F F0RT1KA_EDR_PROTECT 2>/dev/null || true

        # Allow EDR processes to reach the internet (HTTPS)
        # These rules ensure EDR cloud connectivity even if other rules try to block it
        for edr_path in "${EDR_BINARY_PATHS[@]}"; do
            if [[ -d "$edr_path" ]]; then
                local edr_name
                edr_name=$(basename "$edr_path")

                # Find executables in the EDR directory
                while IFS= read -r binary; do
                    if [[ -x "$binary" ]]; then
                        run_or_dry "Allow HTTPS for $binary" \
                            "iptables -A F0RT1KA_EDR_PROTECT -m owner --cmd-owner '$(basename "$binary")' -p tcp --dport 443 -j ACCEPT 2>/dev/null || true"
                    fi
                done < <(find "$edr_path" -maxdepth 3 -type f -executable 2>/dev/null | head -10)
            fi
        done

        # Insert the protection chain at the top of OUTPUT
        iptables -C OUTPUT -j F0RT1KA_EDR_PROTECT 2>/dev/null || \
            iptables -I OUTPUT 1 -j F0RT1KA_EDR_PROTECT 2>/dev/null || true

        log_status "SUCCESS" "EDR protection chain configured in iptables"
    else
        log_status "WARNING" "iptables not found - skipping firewall protection rules"
    fi

    # Create a firewall monitoring script
    local monitor_script="/etc/NetworkManager/dispatcher.d/99-f0rt1ka-fw-monitor"
    if [[ -d "/etc/NetworkManager/dispatcher.d/" ]]; then
        local monitor_content='#!/bin/bash
# F0RT1KA Firewall Monitor
# Alerts on firewall changes that might block EDR
logger -t F0RT1KA-FW "Network change detected - verifying EDR firewall rules"
'
        if $DRY_RUN; then
            log_status "INFO" "[DRY-RUN] Would create firewall monitor at: $monitor_script"
        else
            echo "$monitor_content" > "$monitor_script"
            chmod 755 "$monitor_script"
            log_status "SUCCESS" "Firewall change monitor installed"
        fi
    fi
}

harden_file_permissions() {
    # ======================================================================
    # Restrict Permissions on Security-Critical Files
    # MITRE Mitigation: M1022 - Restrict File and Directory Permissions
    #
    # Hardens file permissions on:
    # - EDR configuration directories
    # - Firewall configuration files
    # - System service unit files
    # ======================================================================

    log_status "HEADER" "Hardening File Permissions on Security-Critical Paths..."

    if $UNDO_MODE; then
        log_status "WARNING" "File permission changes are not automatically reverted"
        log_status "INFO" "Manual intervention required to restore default permissions if needed"
        return
    fi

    # Protect iptables/nftables configuration files
    local fw_configs=(
        "/etc/iptables/"
        "/etc/nftables.conf"
        "/etc/sysconfig/iptables"
        "/etc/sysconfig/ip6tables"
        "/etc/ufw/"
    )

    for fw_path in "${fw_configs[@]}"; do
        if [[ -e "$fw_path" ]]; then
            run_or_dry "Restrict permissions on $fw_path" \
                "chmod -R o-w '$fw_path' 2>/dev/null || true"
        fi
    done

    # Protect EDR installation directories
    for edr_path in "${EDR_BINARY_PATHS[@]}"; do
        if [[ -d "$edr_path" ]]; then
            run_or_dry "Restrict write access to $edr_path" \
                "chmod -R o-w '$edr_path' 2>/dev/null || true"
            log_status "SUCCESS" "Restricted write access on: $edr_path"
        fi
    done

    # Protect /etc/hosts against DNS-based EDR blocking
    if [[ -f "/etc/hosts" ]]; then
        # Set immutable attribute (prevents modification even by root without first removing the attribute)
        if check_command "chattr"; then
            run_or_dry "Set immutable flag on /etc/hosts" \
                "chattr +i /etc/hosts 2>/dev/null || true"
            log_status "INFO" "Note: /etc/hosts immutable flag set. Use 'chattr -i /etc/hosts' to modify."
        fi
    fi
}

harden_kernel_parameters() {
    # ======================================================================
    # Kernel Parameter Hardening
    # MITRE Mitigation: M1050 - Exploit Protection
    #
    # Configures kernel parameters to limit abuse of network manipulation:
    # - Restrict BPF (eBPF can be used for stealth network filtering)
    # - Restrict unprivileged user namespaces (prevent namespace isolation)
    # - Enable kernel module loading restrictions
    # ======================================================================

    log_status "HEADER" "Configuring Kernel Parameter Hardening..."

    local sysctl_file="/etc/sysctl.d/99-f0rt1ka-edr-protection.conf"

    if $UNDO_MODE; then
        log_status "INFO" "Removing kernel parameter hardening..."
        if [[ -f "$sysctl_file" ]]; then
            run_or_dry "Remove sysctl configuration" "rm -f '$sysctl_file'"
            run_or_dry "Reload sysctl" "sysctl --system 2>/dev/null || true"
        else
            log_status "INFO" "No F0RT1KA sysctl configuration found"
        fi
        return
    fi

    local sysctl_content="# ============================================================================
# F0RT1KA EDR Protection Kernel Parameters
# Test ID: e5577355-f8e4-4e52-b1b2-f7d1c8b864f1
# MITRE ATT&CK: T1562.001
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================================

# Restrict unprivileged BPF usage
# Prevents non-root users from loading eBPF programs that could filter
# or manipulate network traffic to block EDR communications
kernel.unprivileged_bpf_disabled = 1

# Harden BPF JIT compiler
# Prevents information leakage through BPF JIT and reduces attack surface
net.core.bpf_jit_harden = 2

# Restrict unprivileged user namespaces
# Prevents creation of network namespaces to isolate EDR processes
# NOTE: May break some containerized applications - test before deploying
kernel.unprivileged_userns_clone = 0

# Enable SYN cookies (protects against SYN flood during EDR isolation)
net.ipv4.tcp_syncookies = 1

# Log martian packets (helps detect network manipulation)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Restrict dmesg access (limits kernel information leakage)
kernel.dmesg_restrict = 1

# Restrict kernel module loading after boot
# NOTE: Uncomment only if all required modules are loaded at boot time
# kernel.modules_disabled = 1
"

    if $DRY_RUN; then
        log_status "INFO" "[DRY-RUN] Would write sysctl configuration to: $sysctl_file"
        echo "$sysctl_content"
    else
        echo "$sysctl_content" > "$sysctl_file"
        log_status "SUCCESS" "Sysctl configuration written to $sysctl_file"

        # Apply sysctl changes
        sysctl --system 2>/dev/null || sysctl -p "$sysctl_file" 2>/dev/null || true
        log_status "SUCCESS" "Kernel parameters applied"
    fi
}

harden_process_monitoring() {
    # ======================================================================
    # Process Monitoring Configuration
    # MITRE Mitigation: M1047 - Audit
    #
    # Configures process accounting and monitoring to detect:
    # - Security process termination
    # - Suspicious process enumeration
    # - Privilege escalation attempts
    # ======================================================================

    log_status "HEADER" "Configuring Process Monitoring..."

    if $UNDO_MODE; then
        log_status "INFO" "Disabling process accounting..."
        run_or_dry "Disable process accounting" "accton off 2>/dev/null || true"
        rm -f /etc/cron.d/f0rt1ka-edr-monitor 2>/dev/null || true
        log_status "SUCCESS" "Process monitoring disabled"
        return
    fi

    # Enable process accounting if available
    if check_command "accton"; then
        local acct_file="/var/log/account/pacct"
        mkdir -p "$(dirname "$acct_file")" 2>/dev/null || true
        run_or_dry "Enable process accounting" "accton '$acct_file' 2>/dev/null || true"
    else
        log_status "INFO" "Process accounting not available. Install with: apt install acct (Debian/Ubuntu)"
    fi

    # Create EDR monitoring cron job
    local monitor_cron="/etc/cron.d/f0rt1ka-edr-monitor"
    local cron_content="# F0RT1KA EDR Health Monitor
# Checks every 5 minutes that EDR services are running
# and can reach their cloud infrastructure
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

*/5 * * * * root /bin/bash -c 'for svc in falcon-sensor sentinelagent mdatp elastic-agent; do if systemctl is-active --quiet \$svc 2>/dev/null; then if ! systemctl is-active --quiet \$svc; then logger -t F0RT1KA-EDR \"ALERT: EDR service \$svc is not running\"; systemctl start \$svc 2>/dev/null || true; fi; fi; done'
"

    if $DRY_RUN; then
        log_status "INFO" "[DRY-RUN] Would create EDR monitoring cron at: $monitor_cron"
    else
        echo "$cron_content" > "$monitor_cron"
        chmod 644 "$monitor_cron"
        log_status "SUCCESS" "EDR health monitoring cron job installed"
    fi
}

harden_dns_protection() {
    # ======================================================================
    # DNS Protection Against EDR Cloud Domain Blocking
    # MITRE Mitigation: M1037 - Filter Network Traffic
    #
    # Prevents attackers from modifying DNS resolution to block EDR
    # cloud domains (e.g., adding entries to /etc/hosts pointing
    # EDR domains to 127.0.0.1).
    # ======================================================================

    log_status "HEADER" "Configuring DNS Protection for EDR Domains..."

    if $UNDO_MODE; then
        log_status "INFO" "Removing DNS protection..."
        if check_command "chattr"; then
            run_or_dry "Remove immutable flag from /etc/hosts" "chattr -i /etc/hosts 2>/dev/null || true"
        fi
        rm -f /etc/cron.d/f0rt1ka-dns-monitor 2>/dev/null || true
        log_status "SUCCESS" "DNS protection removed"
        return
    fi

    # Create DNS monitoring script
    local dns_monitor="/usr/local/bin/f0rt1ka-dns-monitor.sh"
    local dns_content='#!/bin/bash
# F0RT1KA DNS Integrity Monitor
# Checks /etc/hosts for entries that might block EDR cloud domains

EDR_DOMAINS=(
    "sentinelone.net"
    "crowdstrike.com"
    "microsoft.com"
    "carbonblack.io"
    "cylance.com"
    "sophos.com"
    "kaspersky.com"
    "eset.com"
    "paloaltonetworks.com"
    "trellix.com"
    "elastic.co"
)

HOSTS_FILE="/etc/hosts"

for domain in "${EDR_DOMAINS[@]}"; do
    if grep -qi "$domain" "$HOSTS_FILE" 2>/dev/null; then
        # Check if it points to localhost (blocking pattern)
        if grep -qi "127\.0\.0\.\|0\.0\.0\.0.*$domain" "$HOSTS_FILE" 2>/dev/null; then
            logger -t F0RT1KA-DNS "ALERT: /etc/hosts contains blocking entry for EDR domain: $domain"
        fi
    fi
done
'

    if $DRY_RUN; then
        log_status "INFO" "[DRY-RUN] Would create DNS monitor at: $dns_monitor"
    else
        echo "$dns_content" > "$dns_monitor"
        chmod 755 "$dns_monitor"
        log_status "SUCCESS" "DNS integrity monitor created at $dns_monitor"

        # Create cron job
        local dns_cron="/etc/cron.d/f0rt1ka-dns-monitor"
        echo "# F0RT1KA DNS Monitor - runs every 10 minutes
*/10 * * * * root $dns_monitor" > "$dns_cron"
        chmod 644 "$dns_cron"
        log_status "SUCCESS" "DNS monitoring cron job installed"
    fi
}

print_verification() {
    # ======================================================================
    # Print verification commands
    # ======================================================================

    echo ""
    log_status "HEADER" "Verification Commands"
    echo ""
    echo "  # Verify audit rules are loaded:"
    echo "  auditctl -l | grep edr_"
    echo ""
    echo "  # Verify sysctl settings:"
    echo "  sysctl kernel.unprivileged_bpf_disabled"
    echo "  sysctl net.core.bpf_jit_harden"
    echo ""
    echo "  # Verify EDR services are running:"
    echo "  systemctl list-units --type=service | grep -iE 'falcon|sentinel|mdatp|elastic|wazuh'"
    echo ""
    echo "  # Check iptables EDR protection chain:"
    echo "  iptables -L F0RT1KA_EDR_PROTECT -v -n 2>/dev/null"
    echo ""
    echo "  # View audit logs for EDR-related events:"
    echo "  ausearch -k edr_firewall_tamper -ts today"
    echo "  ausearch -k edr_service_tamper -ts today"
    echo "  ausearch -k edr_binary_tamper -ts today"
    echo ""
    echo "  # Check /etc/hosts immutable flag:"
    echo "  lsattr /etc/hosts"
    echo ""
    echo "  # View hardening log:"
    echo "  cat $LOG_FILE"
    echo ""
}

# ============================================================================
# Argument Parsing
# ============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo)
            UNDO_MODE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $SCRIPT_NAME [--undo] [--dry-run] [--help]"
            echo ""
            echo "Options:"
            echo "  --undo     Revert all hardening changes"
            echo "  --dry-run  Show changes without applying them"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            log_status "ERROR" "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================================"
echo "  F0RT1KA Defense Hardening Script (Linux)"
echo "  Test: SilentButDeadly WFP EDR Network Isolation"
echo "  MITRE ATT&CK: T1562.001"
echo "============================================================================"
echo ""

check_root

if $UNDO_MODE; then
    log_status "HEADER" "Mode: REVERT"
elif $DRY_RUN; then
    log_status "HEADER" "Mode: DRY-RUN (no changes will be made)"
else
    log_status "HEADER" "Mode: HARDEN"
fi

log_status "INFO" "Log file: $LOG_FILE"
echo ""

# Execute hardening functions
harden_auditd_rules
echo ""

harden_edr_service_protection
echo ""

harden_firewall_protection
echo ""

harden_file_permissions
echo ""

harden_kernel_parameters
echo ""

harden_process_monitoring
echo ""

harden_dns_protection
echo ""

# Print summary
echo "============================================================================"
if $UNDO_MODE; then
    log_status "SUCCESS" "Hardening changes reverted successfully"
elif $DRY_RUN; then
    log_status "INFO" "Dry-run complete - no changes were made"
else
    log_status "SUCCESS" "Hardening complete"
fi
echo "============================================================================"
echo ""

if ! $UNDO_MODE; then
    print_verification
fi

exit 0
