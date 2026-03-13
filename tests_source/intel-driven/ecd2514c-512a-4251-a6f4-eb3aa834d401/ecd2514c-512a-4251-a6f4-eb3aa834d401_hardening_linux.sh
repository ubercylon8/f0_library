#!/usr/bin/env bash
# ============================================================
# F0RT1KA Linux Hardening Script
# CyberEye RAT Defense - T1562.001 Impair Defenses Countermeasures
#
# Test ID: ecd2514c-512a-4251-a6f4-eb3aa834d401
# MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
# Mitigations: M1024, M1022, M1047, M1054, M1038
#
# Description:
#   Hardens a Linux system against T1562.001 techniques that disable
#   or modify security tools. While the original test targets Windows
#   Defender, the same MITRE technique applies to Linux security
#   controls: SELinux/AppArmor, auditd, firewalld/iptables, and
#   endpoint protection agents.
#
# Usage:
#   sudo ./ecd2514c-512a-4251-a6f4-eb3aa834d401_hardening_linux.sh
#   sudo ./ecd2514c-512a-4251-a6f4-eb3aa834d401_hardening_linux.sh --undo
#   sudo ./ecd2514c-512a-4251-a6f4-eb3aa834d401_hardening_linux.sh --audit
#
# Requires: root privileges
# Idempotent: Yes (safe to run multiple times)
# ============================================================

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
SCRIPT_NAME="F0RT1KA Linux Hardening - T1562.001"
TEST_ID="ecd2514c-512a-4251-a6f4-eb3aa834d401"
LOG_DIR="/var/log/f0rtika"
LOG_FILE="${LOG_DIR}/hardening_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/var/backups/f0rtika/hardening"
MODE="harden"

# ============================================================
# Color Output
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ============================================================
# Helper Functions
# ============================================================

log_status() {
    local type="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$type" in
        INFO)    printf "${CYAN}[*]${NC} %s\n" "$message" ;;
        SUCCESS) printf "${GREEN}[+]${NC} %s\n" "$message" ;;
        WARNING) printf "${YELLOW}[!]${NC} %s\n" "$message" ;;
        ERROR)   printf "${RED}[-]${NC} %s\n" "$message" ;;
        CHECK)   printf "${MAGENTA}[?]${NC} %s\n" "$message" ;;
    esac

    echo "${timestamp} [${type}] ${message}" >> "$LOG_FILE" 2>/dev/null || true
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_status ERROR "This script must be run as root (sudo)"
        exit 1
    fi
}

ensure_dirs() {
    mkdir -p "$LOG_DIR" "$BACKUP_DIR"
}

command_exists() {
    command -v "$1" &>/dev/null
}

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        local dest="${BACKUP_DIR}/$(basename "$src").backup.$(date +%Y%m%d_%H%M%S)"
        cp -a "$src" "$dest"
        log_status INFO "Backed up $src to $dest"
    fi
}

# ============================================================
# Parse Arguments
# ============================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo|--revert)
            MODE="undo"
            shift
            ;;
        --audit|--check)
            MODE="audit"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--undo|--audit|--help]"
            echo ""
            echo "  (no args)  Apply hardening settings"
            echo "  --undo     Revert hardening changes"
            echo "  --audit    Check current security posture without changes"
            echo "  --help     Show this help"
            exit 0
            ;;
        *)
            log_status ERROR "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ============================================================
# 1. SELinux / AppArmor Enforcement
# M1054 - Software Configuration
# ============================================================

harden_mandatory_access_control() {
    log_status INFO "--- Mandatory Access Control (SELinux/AppArmor) ---"

    if command_exists getenforce; then
        local current_mode
        current_mode=$(getenforce 2>/dev/null || echo "Unknown")

        if [[ "$MODE" == "audit" ]]; then
            if [[ "$current_mode" == "Enforcing" ]]; then
                log_status SUCCESS "SELinux is in Enforcing mode"
            elif [[ "$current_mode" == "Permissive" ]]; then
                log_status WARNING "SELinux is in Permissive mode - not blocking violations"
            else
                log_status ERROR "SELinux is Disabled"
            fi
            return
        fi

        if [[ "$MODE" == "undo" ]]; then
            log_status WARNING "Setting SELinux to Permissive (undo). Re-enable manually if needed."
            setenforce 0 2>/dev/null || log_status WARNING "Could not set SELinux to Permissive"
            return
        fi

        # Harden
        if [[ "$current_mode" != "Enforcing" ]]; then
            log_status INFO "Current SELinux mode: $current_mode. Setting to Enforcing..."
            setenforce 1 2>/dev/null && \
                log_status SUCCESS "SELinux set to Enforcing mode" || \
                log_status WARNING "Could not set SELinux to Enforcing (may need reboot if Disabled)"

            # Ensure persistent enforcement
            if [[ -f /etc/selinux/config ]]; then
                backup_file /etc/selinux/config
                sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                log_status SUCCESS "SELinux configured for persistent Enforcing mode in /etc/selinux/config"
            fi
        else
            log_status SUCCESS "SELinux is already in Enforcing mode"
        fi

    elif command_exists aa-status; then
        local aa_profiles
        aa_profiles=$(aa-status 2>/dev/null | head -1 || echo "Unknown")

        if [[ "$MODE" == "audit" ]]; then
            log_status CHECK "AppArmor status: $aa_profiles"
            if systemctl is-active --quiet apparmor 2>/dev/null; then
                log_status SUCCESS "AppArmor service is running"
            else
                log_status WARNING "AppArmor service is not running"
            fi
            return
        fi

        if [[ "$MODE" == "undo" ]]; then
            log_status WARNING "AppArmor undo not performed (too disruptive). Manage manually."
            return
        fi

        # Harden
        if ! systemctl is-active --quiet apparmor 2>/dev/null; then
            systemctl start apparmor 2>/dev/null && \
                log_status SUCCESS "Started AppArmor service" || \
                log_status WARNING "Could not start AppArmor"
        fi
        systemctl enable apparmor 2>/dev/null && \
            log_status SUCCESS "AppArmor enabled at boot" || \
            log_status WARNING "Could not enable AppArmor at boot"
    else
        log_status WARNING "Neither SELinux nor AppArmor detected on this system"
    fi
}

# ============================================================
# 2. Audit Daemon (auditd) Configuration
# M1047 - Audit
# ============================================================

harden_auditd() {
    log_status INFO "--- Audit Daemon (auditd) ---"

    if ! command_exists auditctl; then
        log_status WARNING "auditd is not installed. Install with: apt install auditd / yum install audit"
        return
    fi

    if [[ "$MODE" == "audit" ]]; then
        if systemctl is-active --quiet auditd 2>/dev/null; then
            log_status SUCCESS "auditd service is running"
        else
            log_status ERROR "auditd service is NOT running"
        fi
        if systemctl is-enabled --quiet auditd 2>/dev/null; then
            log_status SUCCESS "auditd is enabled at boot"
        else
            log_status WARNING "auditd is NOT enabled at boot"
        fi
        # Check for security-relevant rules
        local rule_count
        rule_count=$(auditctl -l 2>/dev/null | wc -l)
        log_status CHECK "Current audit rules loaded: $rule_count"
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        log_status WARNING "Removing F0RT1KA audit rules..."
        local rules_file="/etc/audit/rules.d/f0rtika-t1562.rules"
        if [[ -f "$rules_file" ]]; then
            rm -f "$rules_file"
            log_status SUCCESS "Removed F0RT1KA audit rules file"
            augenrules --load 2>/dev/null || auditctl -R /etc/audit/audit.rules 2>/dev/null || true
            log_status INFO "Audit rules reloaded"
        else
            log_status INFO "No F0RT1KA audit rules to remove"
        fi
        return
    fi

    # Harden: Ensure auditd is running and enabled
    systemctl start auditd 2>/dev/null && \
        log_status SUCCESS "auditd service started" || \
        log_status WARNING "auditd may already be running"

    systemctl enable auditd 2>/dev/null && \
        log_status SUCCESS "auditd enabled at boot" || true

    # Add audit rules for T1562.001 defense evasion detection
    local rules_file="/etc/audit/rules.d/f0rtika-t1562.rules"
    cat > "$rules_file" << 'AUDITRULES'
## F0RT1KA T1562.001 - Impair Defenses Detection Rules
## Monitors security tool configuration changes and service manipulation

# Monitor changes to SELinux configuration
-w /etc/selinux/config -p wa -k f0rtika_selinux_config
-w /usr/sbin/setenforce -p x -k f0rtika_selinux_enforce

# Monitor AppArmor configuration changes
-w /etc/apparmor/ -p wa -k f0rtika_apparmor_config
-w /etc/apparmor.d/ -p wa -k f0rtika_apparmor_profiles

# Monitor auditd configuration changes (self-protection)
-w /etc/audit/ -p wa -k f0rtika_audit_config
-w /etc/audit/audit.rules -p wa -k f0rtika_audit_rules
-w /etc/audit/auditd.conf -p wa -k f0rtika_audit_conf

# Monitor firewall configuration changes
-w /etc/firewalld/ -p wa -k f0rtika_firewall_config
-w /etc/iptables/ -p wa -k f0rtika_iptables_config
-w /etc/nftables.conf -p wa -k f0rtika_nftables_config

# Monitor sysctl security parameter changes
-w /etc/sysctl.conf -p wa -k f0rtika_sysctl_config
-w /etc/sysctl.d/ -p wa -k f0rtika_sysctl_config

# Monitor systemctl commands for service manipulation
-w /usr/bin/systemctl -p x -k f0rtika_systemctl_exec

# Monitor direct security binary execution
-w /usr/sbin/iptables -p x -k f0rtika_iptables_exec
-w /usr/sbin/nft -p x -k f0rtika_nft_exec
-w /usr/sbin/ufw -p x -k f0rtika_ufw_exec

# Monitor kernel module loading (potential rootkit/defense bypass)
-w /sbin/insmod -p x -k f0rtika_kernel_module
-w /sbin/modprobe -p x -k f0rtika_kernel_module
-w /sbin/rmmod -p x -k f0rtika_kernel_module

# Monitor process kill signals to security agents
-a always,exit -F arch=b64 -S kill -S tkill -S tgkill -k f0rtika_process_kill

# Monitor sysctl writes (runtime kernel parameter changes)
-a always,exit -F arch=b64 -S sysctl -k f0rtika_sysctl_write

# Monitor attempts to delete audit logs
-w /var/log/audit/ -p wa -k f0rtika_audit_log_tamper
AUDITRULES

    log_status SUCCESS "Created audit rules at $rules_file"

    # Load the new rules
    if command_exists augenrules; then
        augenrules --load 2>/dev/null && \
            log_status SUCCESS "Audit rules loaded via augenrules" || \
            log_status WARNING "Failed to load audit rules via augenrules"
    else
        auditctl -R "$rules_file" 2>/dev/null && \
            log_status SUCCESS "Audit rules loaded via auditctl" || \
            log_status WARNING "Failed to load audit rules"
    fi
}

# ============================================================
# 3. Kernel Security Parameters (sysctl)
# M1054 - Software Configuration
# ============================================================

harden_sysctl() {
    log_status INFO "--- Kernel Security Parameters (sysctl) ---"

    local sysctl_file="/etc/sysctl.d/99-f0rtika-hardening.conf"

    if [[ "$MODE" == "audit" ]]; then
        log_status CHECK "Checking kernel security parameters..."

        local params=(
            "kernel.randomize_va_space:2:ASLR"
            "kernel.yama.ptrace_scope:1:Ptrace restriction"
            "kernel.dmesg_restrict:1:Kernel log restriction"
            "kernel.kptr_restrict:2:Kernel pointer restriction"
            "kernel.modules_disabled:0:Kernel module loading (0=allowed, 1=locked)"
            "net.ipv4.ip_forward:0:IPv4 forwarding"
            "kernel.sysrq:0:SysRq key"
            "kernel.core_uses_pid:1:Core dump with PID"
            "net.ipv4.conf.all.send_redirects:0:ICMP redirects sending"
            "net.ipv4.conf.all.accept_redirects:0:ICMP redirects accepting"
        )

        for param_spec in "${params[@]}"; do
            IFS=':' read -r param expected desc <<< "$param_spec"
            local current
            current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
            if [[ "$current" == "$expected" ]]; then
                log_status SUCCESS "$desc ($param) = $current"
            else
                log_status WARNING "$desc ($param) = $current (recommended: $expected)"
            fi
        done
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$sysctl_file" ]]; then
            rm -f "$sysctl_file"
            log_status SUCCESS "Removed F0RT1KA sysctl hardening configuration"
            sysctl --system &>/dev/null || true
            log_status INFO "Reloaded sysctl configuration (system defaults restored)"
        else
            log_status INFO "No F0RT1KA sysctl configuration to remove"
        fi
        return
    fi

    # Harden: Write sysctl configuration
    backup_file "$sysctl_file" 2>/dev/null || true

    cat > "$sysctl_file" << 'SYSCTL'
# F0RT1KA Hardening - T1562.001 Defense Against Impair Defenses
# Date: Generated by F0RT1KA Defense Guidance Builder

# Enable ASLR (Address Space Layout Randomization)
# Prevents attackers from disabling ASLR to ease exploitation
kernel.randomize_va_space = 2

# Restrict ptrace to parent processes only
# Prevents unauthorized process debugging/injection
kernel.yama.ptrace_scope = 1

# Restrict kernel log access to root
# Prevents information leakage from kernel messages
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
# Prevents kernel address leaks that aid exploitation
kernel.kptr_restrict = 2

# Disable SysRq magic key (prevents console-based attacks)
kernel.sysrq = 0

# Include PID in core dumps (aids forensic analysis)
kernel.core_uses_pid = 1

# Disable IP forwarding (prevents use as pivot point)
net.ipv4.ip_forward = 0

# Disable ICMP redirects (prevents network-level attacks)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable TCP SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Log martian packets (spoofed/malformed)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
SYSCTL

    log_status SUCCESS "Created sysctl hardening config at $sysctl_file"

    sysctl --system &>/dev/null && \
        log_status SUCCESS "Sysctl parameters applied" || \
        log_status WARNING "Some sysctl parameters may not have applied"
}

# ============================================================
# 4. Firewall Configuration
# M1054 - Software Configuration
# ============================================================

harden_firewall() {
    log_status INFO "--- Firewall Configuration ---"

    if [[ "$MODE" == "audit" ]]; then
        if command_exists firewalld && systemctl is-active --quiet firewalld 2>/dev/null; then
            log_status SUCCESS "firewalld is running"
            local zone
            zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
            log_status CHECK "Default zone: $zone"
        elif command_exists ufw; then
            local ufw_status
            ufw_status=$(ufw status 2>/dev/null | head -1)
            if echo "$ufw_status" | grep -q "active"; then
                log_status SUCCESS "UFW is active"
            else
                log_status WARNING "UFW is inactive"
            fi
        elif command_exists iptables; then
            local rule_count
            rule_count=$(iptables -L -n 2>/dev/null | grep -c "^[A-Z]" || echo "0")
            log_status CHECK "iptables chains with rules: $rule_count"
        else
            log_status ERROR "No firewall detected"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        log_status WARNING "Firewall undo not performed (too system-specific). Manage manually."
        return
    fi

    # Harden: Ensure a firewall is active
    if command_exists firewall-cmd && systemctl list-unit-files firewalld.service &>/dev/null; then
        systemctl start firewalld 2>/dev/null && \
            log_status SUCCESS "Started firewalld" || \
            log_status INFO "firewalld may already be running"
        systemctl enable firewalld 2>/dev/null && \
            log_status SUCCESS "Enabled firewalld at boot" || true
    elif command_exists ufw; then
        ufw --force enable 2>/dev/null && \
            log_status SUCCESS "Enabled UFW firewall" || \
            log_status WARNING "Could not enable UFW"
        ufw default deny incoming 2>/dev/null && \
            log_status SUCCESS "UFW default policy: deny incoming" || true
        ufw default allow outgoing 2>/dev/null && \
            log_status SUCCESS "UFW default policy: allow outgoing" || true
    else
        log_status WARNING "No supported firewall found. Install firewalld or ufw."
    fi
}

# ============================================================
# 5. Service Immutability (Protect Security Services)
# M1024 - Restrict Registry Permissions (Linux equivalent: file permissions)
# ============================================================

harden_service_protection() {
    log_status INFO "--- Security Service Protection ---"

    local protected_services=(
        "auditd"
        "apparmor"
        "firewalld"
        "ufw"
    )

    if [[ "$MODE" == "audit" ]]; then
        for svc in "${protected_services[@]}"; do
            if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
                if systemctl is-active --quiet "$svc" 2>/dev/null; then
                    log_status SUCCESS "Service '$svc' is running"
                else
                    log_status WARNING "Service '$svc' is NOT running"
                fi
                if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
                    log_status SUCCESS "Service '$svc' is enabled at boot"
                else
                    log_status WARNING "Service '$svc' is NOT enabled at boot"
                fi
            fi
        done

        # Check immutable audit rules
        if command_exists auditctl; then
            if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
                log_status SUCCESS "Audit rules are IMMUTABLE (locked, requires reboot to change)"
            else
                log_status WARNING "Audit rules are NOT immutable (can be modified at runtime)"
            fi
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        log_status WARNING "Service protection undo: no destructive changes to revert"
        return
    fi

    # Harden: Ensure security services are enabled and running
    for svc in "${protected_services[@]}"; do
        if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
            systemctl enable "$svc" 2>/dev/null && \
                log_status SUCCESS "Enabled '$svc' at boot" || true
            if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
                systemctl start "$svc" 2>/dev/null && \
                    log_status SUCCESS "Started '$svc' service" || \
                    log_status WARNING "Could not start '$svc'"
            fi
        fi
    done

    # Protect critical security binaries with immutable attribute
    local critical_binaries=(
        "/usr/sbin/auditd"
        "/usr/sbin/auditctl"
        "/usr/sbin/aureport"
        "/usr/sbin/ausearch"
    )

    for bin in "${critical_binaries[@]}"; do
        if [[ -f "$bin" ]]; then
            # Set immutable flag (requires root, prevents even root from modifying)
            chattr +i "$bin" 2>/dev/null && \
                log_status SUCCESS "Set immutable flag on $bin" || \
                log_status WARNING "Could not set immutable flag on $bin (filesystem may not support it)"
        fi
    done

    log_status INFO "Note: To make audit rules fully immutable, add '-e 2' to the end of your audit rules file"
    log_status INFO "This locks audit rules until next reboot, preventing runtime tampering"
}

# ============================================================
# 6. Endpoint Agent Watchdog (systemd)
# M1047 - Audit
# ============================================================

harden_agent_watchdog() {
    log_status INFO "--- Endpoint Agent Watchdog ---"

    local watchdog_service="f0rtika-agent-watchdog"
    local watchdog_unit="/etc/systemd/system/${watchdog_service}.service"
    local watchdog_timer="/etc/systemd/system/${watchdog_service}.timer"
    local watchdog_script="/usr/local/bin/f0rtika-agent-watchdog.sh"

    if [[ "$MODE" == "audit" ]]; then
        if systemctl is-active --quiet "${watchdog_service}.timer" 2>/dev/null; then
            log_status SUCCESS "Agent watchdog timer is running"
        else
            log_status WARNING "Agent watchdog timer is NOT configured"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        systemctl stop "${watchdog_service}.timer" 2>/dev/null || true
        systemctl disable "${watchdog_service}.timer" 2>/dev/null || true
        rm -f "$watchdog_unit" "$watchdog_timer" "$watchdog_script"
        systemctl daemon-reload 2>/dev/null || true
        log_status SUCCESS "Removed agent watchdog service and timer"
        return
    fi

    # Create watchdog script
    cat > "$watchdog_script" << 'WATCHDOG'
#!/usr/bin/env bash
# F0RT1KA Agent Watchdog - Monitors security service health
# Checks critical security services and logs/alerts if any are stopped

LOG_DIR="/var/log/f0rtika"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/agent_watchdog.log"

CRITICAL_SERVICES=(
    "auditd"
)

# Dynamically add services that exist on this system
for svc in apparmor firewalld ufw falcon-sensor cbagentd mdatp; do
    if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
        CRITICAL_SERVICES+=("$svc")
    fi
done

ALERT=false
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

for svc in "${CRITICAL_SERVICES[@]}"; do
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo "${TIMESTAMP} [ALERT] Security service '$svc' is enabled but NOT running!" >> "$LOG_FILE"
            ALERT=true
            # Attempt to restart the service
            systemctl start "$svc" 2>/dev/null && \
                echo "${TIMESTAMP} [RECOVERY] Restarted '$svc' successfully" >> "$LOG_FILE" || \
                echo "${TIMESTAMP} [CRITICAL] Failed to restart '$svc'" >> "$LOG_FILE"
        fi
    fi
done

# Check SELinux enforcement
if command -v getenforce &>/dev/null; then
    SELINUX_MODE=$(getenforce 2>/dev/null || echo "Unknown")
    if [[ "$SELINUX_MODE" == "Permissive" || "$SELINUX_MODE" == "Disabled" ]]; then
        echo "${TIMESTAMP} [ALERT] SELinux is in ${SELINUX_MODE} mode!" >> "$LOG_FILE"
        ALERT=true
    fi
fi

# Check sysctl security parameters
ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "N/A")
if [[ "$ASLR" != "2" ]]; then
    echo "${TIMESTAMP} [ALERT] ASLR is not fully enabled (current: ${ASLR}, expected: 2)" >> "$LOG_FILE"
    ALERT=true
fi

if [[ "$ALERT" == "false" ]]; then
    echo "${TIMESTAMP} [OK] All security services healthy" >> "$LOG_FILE"
fi

# Write to syslog for SIEM collection
if [[ "$ALERT" == "true" ]]; then
    logger -t f0rtika-watchdog -p auth.warning "Security service health check FAILED - check ${LOG_FILE}"
fi
WATCHDOG

    chmod 755 "$watchdog_script"
    log_status SUCCESS "Created watchdog script at $watchdog_script"

    # Create systemd service
    cat > "$watchdog_unit" << UNIT
[Unit]
Description=F0RT1KA Security Agent Watchdog
Documentation=https://attack.mitre.org/techniques/T1562/001/

[Service]
Type=oneshot
ExecStart=$watchdog_script
User=root
UNIT

    # Create systemd timer (every 5 minutes)
    cat > "$watchdog_timer" << 'TIMER'
[Unit]
Description=F0RT1KA Security Agent Watchdog Timer
Documentation=https://attack.mitre.org/techniques/T1562/001/

[Timer]
OnBootSec=60
OnUnitActiveSec=300
AccuracySec=60

[Install]
WantedBy=timers.target
TIMER

    systemctl daemon-reload 2>/dev/null
    systemctl enable "${watchdog_service}.timer" 2>/dev/null && \
        log_status SUCCESS "Enabled watchdog timer (runs every 5 minutes)" || \
        log_status WARNING "Could not enable watchdog timer"
    systemctl start "${watchdog_service}.timer" 2>/dev/null && \
        log_status SUCCESS "Started watchdog timer" || \
        log_status WARNING "Could not start watchdog timer"
}

# ============================================================
# 7. Restrict Dangerous Commands (PAM / sudoers)
# M1038 - Execution Prevention
# ============================================================

harden_command_restrictions() {
    log_status INFO "--- Command Restriction (sudoers) ---"

    local sudoers_file="/etc/sudoers.d/f0rtika-restrict-security-cmds"

    if [[ "$MODE" == "audit" ]]; then
        if [[ -f "$sudoers_file" ]]; then
            log_status SUCCESS "F0RT1KA command restrictions are in place"
        else
            log_status WARNING "No F0RT1KA command restrictions configured"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$sudoers_file" ]]; then
            rm -f "$sudoers_file"
            log_status SUCCESS "Removed F0RT1KA command restrictions"
        else
            log_status INFO "No F0RT1KA command restrictions to remove"
        fi
        return
    fi

    # Create sudoers restriction
    # This creates an alias for security-critical commands and restricts them
    # to specific admin groups, preventing regular sudo users from disabling defenses
    cat > "$sudoers_file" << 'SUDOERS'
# F0RT1KA T1562.001 - Restrict security-sensitive commands
# Only members of the 'secadmin' group can execute these commands
# All other sudo users are denied access to these commands
#
# To use: create a 'secadmin' group and add authorized administrators
#   groupadd secadmin
#   usermod -aG secadmin <admin-username>

# Define command aliases for security-critical operations
Cmnd_Alias F0RTIKA_SECURITY_CMDS = /usr/sbin/setenforce, \
    /usr/bin/systemctl stop auditd, \
    /usr/bin/systemctl disable auditd, \
    /usr/bin/systemctl stop apparmor, \
    /usr/bin/systemctl disable apparmor, \
    /usr/bin/systemctl stop firewalld, \
    /usr/bin/systemctl disable firewalld, \
    /usr/sbin/auditctl -e 0, \
    /usr/sbin/auditctl -D

# Allow secadmin group full access
%secadmin ALL=(ALL) ALL

# Note: Uncomment the line below to deny non-secadmin users from running
# security-critical commands. Test thoroughly before enabling.
# ALL ALL=(ALL) !F0RTIKA_SECURITY_CMDS
SUDOERS

    chmod 440 "$sudoers_file"

    # Validate sudoers syntax
    if command_exists visudo; then
        if visudo -cf "$sudoers_file" &>/dev/null; then
            log_status SUCCESS "Created command restrictions at $sudoers_file (syntax valid)"
        else
            log_status ERROR "Sudoers syntax validation failed - removing file"
            rm -f "$sudoers_file"
        fi
    else
        log_status SUCCESS "Created command restrictions at $sudoers_file (visudo not available for validation)"
    fi

    log_status INFO "Note: Create 'secadmin' group and uncomment deny rule to activate restrictions"
    log_status INFO "  groupadd secadmin && usermod -aG secadmin <admin-username>"
}

# ============================================================
# 8. File Integrity Monitoring (AIDE)
# M1047 - Audit
# ============================================================

harden_file_integrity() {
    log_status INFO "--- File Integrity Monitoring ---"

    if [[ "$MODE" == "audit" ]]; then
        if command_exists aide; then
            log_status SUCCESS "AIDE is installed"
            if [[ -f /var/lib/aide/aide.db ]]; then
                log_status SUCCESS "AIDE database exists"
            else
                log_status WARNING "AIDE database not initialized (run: aide --init)"
            fi
        else
            log_status WARNING "AIDE is not installed. Install with: apt install aide / yum install aide"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        local aide_conf="/etc/aide/aide.conf.d/f0rtika-security.conf"
        if [[ -f "$aide_conf" ]]; then
            rm -f "$aide_conf"
            log_status SUCCESS "Removed F0RT1KA AIDE configuration"
        fi
        return
    fi

    if ! command_exists aide; then
        log_status WARNING "AIDE not installed. Skipping file integrity configuration."
        log_status INFO "Install: apt install aide aide-common (Debian/Ubuntu) or yum install aide (RHEL/CentOS)"
        return
    fi

    # Add AIDE rules for security-critical files
    local aide_conf_dir="/etc/aide/aide.conf.d"
    if [[ ! -d "$aide_conf_dir" ]]; then
        aide_conf_dir="/etc/aide"
    fi

    local aide_conf="${aide_conf_dir}/f0rtika-security.conf"

    cat > "$aide_conf" << 'AIDE_CONF'
# F0RT1KA T1562.001 - Monitor security-critical files
# Alerts on any modification to security tool configurations

# SELinux configuration
/etc/selinux CONTENT_EX

# AppArmor profiles
/etc/apparmor.d CONTENT_EX

# Audit configuration
/etc/audit CONTENT_EX

# Firewall configuration
/etc/firewalld CONTENT_EX
/etc/iptables CONTENT_EX
/etc/nftables.conf CONTENT_EX

# Sysctl security parameters
/etc/sysctl.conf CONTENT_EX
/etc/sysctl.d CONTENT_EX

# Security binaries
/usr/sbin/auditd CONTENT_EX
/usr/sbin/auditctl CONTENT_EX
/usr/sbin/setenforce CONTENT_EX

# Systemd service files for security services
/etc/systemd/system CONTENT_EX
/usr/lib/systemd/system/auditd.service CONTENT_EX
AIDE_CONF

    log_status SUCCESS "Created AIDE monitoring configuration at $aide_conf"
    log_status INFO "Run 'aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db' to initialize"
}

# ============================================================
# Security Posture Summary
# ============================================================

show_posture_summary() {
    log_status INFO ""
    log_status INFO "========== SECURITY POSTURE SUMMARY =========="

    # SELinux/AppArmor
    if command_exists getenforce; then
        local mode
        mode=$(getenforce 2>/dev/null || echo "Unknown")
        [[ "$mode" == "Enforcing" ]] && \
            log_status SUCCESS "SELinux: $mode" || \
            log_status WARNING "SELinux: $mode"
    elif command_exists aa-status; then
        systemctl is-active --quiet apparmor 2>/dev/null && \
            log_status SUCCESS "AppArmor: Active" || \
            log_status WARNING "AppArmor: Inactive"
    fi

    # auditd
    systemctl is-active --quiet auditd 2>/dev/null && \
        log_status SUCCESS "auditd: Running" || \
        log_status WARNING "auditd: Not running"

    # Firewall
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        log_status SUCCESS "Firewall: firewalld active"
    elif command_exists ufw && ufw status 2>/dev/null | grep -q "active"; then
        log_status SUCCESS "Firewall: UFW active"
    else
        log_status WARNING "Firewall: No active firewall detected"
    fi

    # ASLR
    local aslr
    aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "N/A")
    [[ "$aslr" == "2" ]] && \
        log_status SUCCESS "ASLR: Full randomization ($aslr)" || \
        log_status WARNING "ASLR: $aslr (expected: 2)"

    # ptrace
    local ptrace
    ptrace=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "N/A")
    [[ "$ptrace" -ge 1 ]] 2>/dev/null && \
        log_status SUCCESS "Ptrace scope: Restricted ($ptrace)" || \
        log_status WARNING "Ptrace scope: $ptrace (expected: >= 1)"

    log_status INFO "=============================================="
    log_status INFO ""
}

# ============================================================
# Main Execution
# ============================================================

check_root
ensure_dirs

log_status INFO "============================================================"
log_status INFO "$SCRIPT_NAME"
log_status INFO "Test ID: $TEST_ID"
log_status INFO "Mode: $(echo "$MODE" | tr '[:lower:]' '[:upper:]')"
log_status INFO "============================================================"

case "$MODE" in
    harden)
        log_status INFO "Applying hardening settings..."
        show_posture_summary
        harden_mandatory_access_control
        harden_auditd
        harden_sysctl
        harden_firewall
        harden_service_protection
        harden_agent_watchdog
        harden_command_restrictions
        harden_file_integrity
        log_status INFO ""
        log_status INFO "========== POST-HARDENING POSTURE =========="
        show_posture_summary
        log_status SUCCESS "Hardening complete. Review log: $LOG_FILE"
        ;;
    undo)
        log_status WARNING "Reverting hardening changes..."
        harden_mandatory_access_control
        harden_auditd
        harden_sysctl
        harden_firewall
        harden_service_protection
        harden_agent_watchdog
        harden_command_restrictions
        harden_file_integrity
        log_status WARNING "Undo complete. Review changes above."
        ;;
    audit)
        log_status CHECK "Auditing current security posture..."
        show_posture_summary
        harden_mandatory_access_control
        harden_auditd
        harden_sysctl
        harden_firewall
        harden_service_protection
        harden_agent_watchdog
        harden_command_restrictions
        harden_file_integrity
        log_status INFO "Audit complete. No changes were made."
        ;;
esac

log_status INFO "Log file: $LOG_FILE"
log_status SUCCESS "Script execution completed."
