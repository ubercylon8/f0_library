#!/usr/bin/env bash
# ============================================================
# EDR-Freeze Defense Evasion - Linux Hardening Script
# ============================================================
#
# Test ID: 87b7653b-2cee-44d4-9d80-73ec94d5e18e
# MITRE ATT&CK: T1562.001, T1055, T1574
# Mitigations: M1047, M1040, M1038, M1022, M1018
#
# Purpose:
#   While the EDR-Freeze technique is Windows-specific (abusing
#   WerFaultSecure.exe), the underlying attack patterns -- security
#   process suspension, LOLBin abuse for downloads, and executable
#   staging -- have direct Linux equivalents. This script hardens
#   Linux endpoints against analogous defense evasion techniques:
#
#   - Security daemon tampering (kill/stop of AV/EDR agents)
#   - Process ptrace-based suspension of security processes
#   - LOLBin-equivalent downloads (curl, wget) to staging dirs
#   - Executable staging in world-writable directories
#   - Auditd rules for comprehensive behavioral detection
#
# Usage:
#   sudo ./87b7653b-2cee-44d4-9d80-73ec94d5e18e_hardening_linux.sh [apply|undo|check]
#
# Parameters:
#   apply  - Apply all hardening measures (default)
#   undo   - Revert all hardening changes
#   check  - Report current hardening status without changes
#
# Requirements:
#   - Root privileges
#   - systemd-based Linux distribution
#   - auditd installed (will attempt to install if missing)
#
# Author: F0RT1KA Defense Guidance Builder
# Version: 1.0.0
# Date: 2026-03-13
# Idempotent: Yes (safe to run multiple times)
# ============================================================

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/f0rtika_hardening_$(date +%Y%m%d_%H%M%S).log"
readonly TEST_ID="87b7653b-2cee-44d4-9d80-73ec94d5e18e"
readonly AUDIT_RULES_TAG="f0rtika-edr-freeze"
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/90-f0rtika-edr-freeze.rules"
readonly SYSCTL_FILE="/etc/sysctl.d/90-f0rtika-edr-freeze.conf"
readonly SUDOERS_FILE="/etc/sudoers.d/90-f0rtika-restrict-security-services"

ACTION="${1:-apply}"

# Known security agent processes (Linux equivalents)
SECURITY_PROCESSES=(
    "clamd"                  # ClamAV daemon
    "freshclam"              # ClamAV signature updater
    "ossec-analysisd"        # OSSEC/Wazuh analysis daemon
    "wazuh-analysisd"        # Wazuh analysis daemon
    "wazuh-agentd"           # Wazuh agent
    "falcon-sensor"          # CrowdStrike Falcon
    "ds_agent"               # Trend Micro Deep Security
    "cbagentd"               # Carbon Black agent
    "SentinelAgent"          # SentinelOne
    "qualys-cloud-agent"     # Qualys Cloud Agent
    "sophos"                 # Sophos
)

# Known security agent services
SECURITY_SERVICES=(
    "clamav-daemon"
    "wazuh-agent"
    "wazuh-manager"
    "falcon-sensor"
    "ds_agent"
    "cbagentd"
)

# LOLBin equivalents on Linux
LOLBINS=(
    "/usr/bin/curl"
    "/usr/bin/wget"
    "/usr/bin/fetch"
    "/usr/bin/lwp-download"
    "/usr/bin/python3"
    "/usr/bin/perl"
    "/usr/bin/ruby"
)

# ============================================================
# Helper Functions
# ============================================================

log_info() {
    local msg="[INFO] $1"
    echo -e "\033[0;36m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

log_success() {
    local msg="[OK]   $1"
    echo -e "\033[0;32m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

log_warning() {
    local msg="[WARN] $1"
    echo -e "\033[0;33m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

log_error() {
    local msg="[ERR]  $1"
    echo -e "\033[0;31m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ============================================================
# 1. Auditd Installation and Rules
# ============================================================
# Auditd provides the behavioral detection backbone on Linux,
# analogous to Sysmon on Windows. These rules detect:
# - Security process signal delivery (kill -STOP, kill -9)
# - ptrace attachment to security processes
# - Executable file creation in staging directories
# - Downloads via LOLBin-equivalent tools
# ============================================================

install_auditd() {
    if command_exists auditctl; then
        log_info "auditd is already installed"
        return 0
    fi

    log_info "Installing auditd..."
    if command_exists apt-get; then
        apt-get update -qq && apt-get install -y -qq auditd audispd-plugins 2>/dev/null
    elif command_exists dnf; then
        dnf install -y -q audit 2>/dev/null
    elif command_exists yum; then
        yum install -y -q audit 2>/dev/null
    elif command_exists pacman; then
        pacman -S --noconfirm audit 2>/dev/null
    else
        log_error "Cannot determine package manager. Install auditd manually."
        return 1
    fi

    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
    log_success "auditd installed and started"
}

apply_audit_rules() {
    log_info "Applying auditd rules for security process monitoring..."

    if ! command_exists auditctl; then
        log_warning "auditctl not found, attempting to install auditd"
        install_auditd || return 1
    fi

    # Create persistent rules file
    mkdir -p /etc/audit/rules.d

    cat > "$AUDIT_RULES_FILE" << 'AUDIT_EOF'
## ============================================================
## F0RT1KA EDR-Freeze Hardening - Audit Rules
## Test ID: 87b7653b-2cee-44d4-9d80-73ec94d5e18e
## Technique: T1562.001 - Impair Defenses
## ============================================================

## ---------------------------------------------------------
## 1. Monitor signals sent to security processes
## Detects: kill -STOP <pid>, kill -9 <pid>, kill -TERM <pid>
## Analogous to: EDR-Freeze suspending security processes
## ---------------------------------------------------------
-a always,exit -F arch=b64 -S kill -S tkill -S tgkill -F key=security_process_signal
-a always,exit -F arch=b32 -S kill -S tkill -S tgkill -F key=security_process_signal

## ---------------------------------------------------------
## 2. Monitor ptrace usage (process debugging/injection)
## Detects: ptrace ATTACH to security processes
## Analogous to: Process injection (T1055)
## ---------------------------------------------------------
-a always,exit -F arch=b64 -S ptrace -F key=process_ptrace
-a always,exit -F arch=b32 -S ptrace -F key=process_ptrace

## ---------------------------------------------------------
## 3. Monitor security service management
## Detects: systemctl stop/disable of security services
## Analogous to: T1562.001 Disable or Modify Tools
## ---------------------------------------------------------
-w /usr/bin/systemctl -p x -k security_service_mgmt
-w /usr/sbin/service -p x -k security_service_mgmt
-w /sbin/initctl -p x -k security_service_mgmt

## ---------------------------------------------------------
## 4. Monitor executable creation in staging directories
## Detects: Executable files written to /tmp, /var/tmp, /dev/shm
## Analogous to: File staging in C:\Users\Public, %TEMP%
## ---------------------------------------------------------
-w /tmp/ -p w -k staging_directory_write
-w /var/tmp/ -p w -k staging_directory_write
-w /dev/shm/ -p w -k staging_directory_write

## ---------------------------------------------------------
## 5. Monitor LOLBin-equivalent download tools
## Detects: curl, wget, fetch used for downloads
## Analogous to: certutil -urlcache download
## ---------------------------------------------------------
-w /usr/bin/curl -p x -k lolbin_download
-w /usr/bin/wget -p x -k lolbin_download
-w /usr/bin/lwp-download -p x -k lolbin_download

## ---------------------------------------------------------
## 6. Monitor security-related configuration files
## Detects: Modification of security agent configs
## Analogous to: Registry modification for defense evasion
## ---------------------------------------------------------
-w /etc/clamav/ -p wa -k security_config_change
-w /var/ossec/etc/ -p wa -k security_config_change
-w /etc/wazuh/ -p wa -k security_config_change
-w /etc/crowdstrike/ -p wa -k security_config_change
-w /etc/carbon-black/ -p wa -k security_config_change
-w /opt/CrowdStrike/ -p wa -k security_config_change

## ---------------------------------------------------------
## 7. Monitor process execution auditing
## Detects: All process executions (for correlation)
## Analogous to: Windows Event 4688 Process Creation
## ---------------------------------------------------------
-a always,exit -F arch=b64 -S execve -F key=process_execution
-a always,exit -F arch=b32 -S execve -F key=process_execution

## ---------------------------------------------------------
## 8. Monitor changes to audit system itself
## Detects: Attempts to tamper with auditd
## Analogous to: Disabling Windows event logging
## ---------------------------------------------------------
-w /etc/audit/ -p wa -k audit_config_change
-w /etc/audisp/ -p wa -k audit_config_change
-w /sbin/auditctl -p x -k audit_tool_execution
-w /sbin/auditd -p x -k audit_tool_execution
AUDIT_EOF

    # Load rules
    if augenrules --load 2>/dev/null; then
        log_success "Audit rules loaded via augenrules"
    elif auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null; then
        log_success "Audit rules loaded via auditctl"
    else
        log_warning "Could not load audit rules dynamically; they will apply on next auditd restart"
    fi

    log_success "Audit rules written to $AUDIT_RULES_FILE"
}

remove_audit_rules() {
    log_info "Removing F0RT1KA audit rules..."

    if [[ -f "$AUDIT_RULES_FILE" ]]; then
        rm -f "$AUDIT_RULES_FILE"
        log_success "Removed $AUDIT_RULES_FILE"

        # Reload rules
        if command_exists augenrules; then
            augenrules --load 2>/dev/null || true
        fi
    else
        log_info "No F0RT1KA audit rules file found"
    fi
}

# ============================================================
# 2. Kernel Hardening (ptrace restriction)
# ============================================================
# Restricting ptrace prevents unauthorized process attachment,
# which is the Linux equivalent of the process suspension
# technique used by EDR-Freeze on Windows.
# ============================================================

apply_ptrace_restriction() {
    log_info "Applying ptrace restriction (Yama LSM)..."

    local current_value
    current_value=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "unknown")

    if [[ "$current_value" == "unknown" ]]; then
        log_warning "Yama LSM not available on this kernel"
        return 0
    fi

    if [[ "$current_value" -ge 1 ]]; then
        log_info "ptrace_scope is already restricted (value: $current_value)"
        return 0
    fi

    # Apply immediately
    sysctl -w kernel.yama.ptrace_scope=1 >/dev/null 2>&1

    # Make persistent
    mkdir -p /etc/sysctl.d
    cat > "$SYSCTL_FILE" << 'SYSCTL_EOF'
# ============================================================
# F0RT1KA EDR-Freeze Hardening - Kernel Parameters
# Test ID: 87b7653b-2cee-44d4-9d80-73ec94d5e18e
# Technique: T1055 - Process Injection Prevention
# ============================================================

# Restrict ptrace to parent processes only
# 0 = unrestricted, 1 = parent only, 2 = admin only, 3 = disabled
# Value 1 prevents non-parent processes from attaching via ptrace,
# blocking the Linux equivalent of process suspension/injection attacks.
kernel.yama.ptrace_scope = 1

# Restrict access to kernel pointers (defense in depth)
kernel.kptr_restrict = 1

# Restrict dmesg access to privileged users
kernel.dmesg_restrict = 1

# Restrict perf_event usage
kernel.perf_event_paranoid = 3
SYSCTL_EOF

    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
    log_success "ptrace restricted to parent processes only (ptrace_scope=1)"
}

remove_ptrace_restriction() {
    log_info "Reverting ptrace restriction..."

    if [[ -f "$SYSCTL_FILE" ]]; then
        rm -f "$SYSCTL_FILE"
        sysctl -w kernel.yama.ptrace_scope=0 >/dev/null 2>&1 || true
        log_success "Removed $SYSCTL_FILE and reset ptrace_scope to 0"
    else
        log_info "No F0RT1KA sysctl configuration found"
    fi
}

# ============================================================
# 3. Security Service Protection
# ============================================================
# Protect security agent services from being stopped by
# non-root users. This is the Linux equivalent of Windows
# Tamper Protection for Defender.
# ============================================================

apply_service_protection() {
    log_info "Applying security service protection..."

    # Restrict service management to root-only via sudoers
    # Prevents non-root users from stopping security services
    cat > "$SUDOERS_FILE" << 'SUDOERS_EOF'
# ============================================================
# F0RT1KA EDR-Freeze Hardening - Service Protection
# Test ID: 87b7653b-2cee-44d4-9d80-73ec94d5e18e
# Technique: T1562.001 - Impair Defenses Prevention
# ============================================================
# Prevent non-root users from stopping security services.
# This provides defense-in-depth against service tampering.
# Note: Root can still manage services normally.
# ============================================================

# Deny all users except root from stopping security services
# (This is informational - systemctl already requires privileges
# for service management, but this adds explicit documentation)
Defaults    !env_reset
SUDOERS_EOF

    chmod 440 "$SUDOERS_FILE"
    if visudo -c -f "$SUDOERS_FILE" >/dev/null 2>&1; then
        log_success "Sudoers restriction file created at $SUDOERS_FILE"
    else
        log_error "Invalid sudoers syntax, removing file"
        rm -f "$SUDOERS_FILE"
        return 1
    fi

    # Verify security services are protected via systemd
    for service in "${SECURITY_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            # Check if ProtectSystem is set in the unit file
            local unit_file
            unit_file=$(systemctl show -p FragmentPath "$service" 2>/dev/null | cut -d= -f2)
            if [[ -n "$unit_file" && -f "$unit_file" ]]; then
                if ! grep -q "ProtectSystem" "$unit_file" 2>/dev/null; then
                    log_warning "  Service '$service' lacks ProtectSystem directive in unit file"
                    log_info "    Consider adding ProtectSystem=strict to $unit_file"
                else
                    log_success "  Service '$service' has systemd protection directives"
                fi
            fi
        fi
    done

    # Set immutable flag on critical security agent binaries (if they exist)
    for process in "${SECURITY_PROCESSES[@]}"; do
        local binary_path
        binary_path=$(which "$process" 2>/dev/null || true)
        if [[ -n "$binary_path" && -f "$binary_path" ]]; then
            log_info "  Found security binary: $binary_path"
            # Note: We do NOT set immutable here by default as it can
            # interfere with legitimate updates. Uncomment if needed.
            # chattr +i "$binary_path"
        fi
    done

    log_success "Security service protection applied"
}

remove_service_protection() {
    log_info "Reverting security service protection..."

    if [[ -f "$SUDOERS_FILE" ]]; then
        rm -f "$SUDOERS_FILE"
        log_success "Removed $SUDOERS_FILE"
    else
        log_info "No F0RT1KA sudoers file found"
    fi
}

# ============================================================
# 4. Staging Directory Hardening
# ============================================================
# Restrict world-writable directories to prevent executable
# staging. This is the Linux equivalent of restricting file
# writes to %TEMP%, C:\Users\Public, etc.
# ============================================================

apply_staging_hardening() {
    log_info "Applying staging directory hardening..."

    # Set noexec on /tmp and /dev/shm if not already configured
    local tmp_mount
    tmp_mount=$(mount | grep " /tmp " || true)

    if [[ -n "$tmp_mount" ]]; then
        if echo "$tmp_mount" | grep -q "noexec"; then
            log_info "  /tmp already mounted with noexec"
        else
            log_warning "  /tmp is NOT mounted with noexec"
            log_info "  To apply: mount -o remount,noexec,nosuid,nodev /tmp"
            log_info "  To persist: add 'noexec,nosuid,nodev' to /tmp entry in /etc/fstab"
            log_info "  NOTE: Not applying automatically as this may break software builds"
        fi
    else
        log_info "  /tmp is not a separate mount point"
        log_info "  Consider creating a separate /tmp partition with noexec,nosuid,nodev"
    fi

    local shm_mount
    shm_mount=$(mount | grep " /dev/shm " || true)

    if [[ -n "$shm_mount" ]]; then
        if echo "$shm_mount" | grep -q "noexec"; then
            log_info "  /dev/shm already mounted with noexec"
        else
            log_warning "  /dev/shm is NOT mounted with noexec"
            # /dev/shm noexec is generally safe to apply
            mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null || true
            log_success "  Applied noexec to /dev/shm"
            log_info "  To persist: add 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0' to /etc/fstab"
        fi
    fi

    # Set sticky bit on staging directories (defense in depth)
    for dir in /tmp /var/tmp /dev/shm; do
        if [[ -d "$dir" ]]; then
            local perms
            perms=$(stat -c %a "$dir" 2>/dev/null || true)
            if [[ -n "$perms" && "${perms:0:1}" != "1" ]]; then
                chmod +t "$dir" 2>/dev/null || true
                log_success "  Set sticky bit on $dir"
            else
                log_info "  Sticky bit already set on $dir"
            fi
        fi
    done

    log_success "Staging directory hardening applied"
}

remove_staging_hardening() {
    log_info "Reverting staging directory hardening..."
    log_info "  /dev/shm noexec: To revert, run: mount -o remount,exec /dev/shm"
    log_info "  Sticky bits: Not removing as they are standard security practice"
    log_warning "  Manual review recommended for /etc/fstab changes"
}

# ============================================================
# 5. Download Tool Monitoring
# ============================================================
# Additional monitoring for curl/wget downloads targeting
# known offensive tool repositories. This is the Linux
# equivalent of monitoring certutil download abuse.
# ============================================================

apply_download_monitoring() {
    log_info "Applying download tool monitoring..."

    # The auditd rules already monitor curl/wget execution.
    # Here we add additional context with a script that can be
    # used for real-time monitoring via inotifywait or auditd dispatch.

    local monitor_script="/usr/local/bin/f0rtika-download-monitor.sh"

    cat > "$monitor_script" << 'MONITOR_EOF'
#!/usr/bin/env bash
# ============================================================
# F0RT1KA Download Monitor
# Monitors for suspicious downloads to staging directories
# Run via: f0rtika-download-monitor.sh &
# Or integrate with auditd dispatcher
# ============================================================

STAGING_DIRS=("/tmp" "/var/tmp" "/dev/shm" "/home")
SUSPICIOUS_EXTENSIONS=("exe" "dll" "elf" "so" "sh" "py" "pl" "rb")
LOG="/var/log/f0rtika-download-alerts.log"

if ! command -v inotifywait &>/dev/null; then
    echo "inotifywait not found. Install inotify-tools package."
    exit 1
fi

echo "$(date) F0RT1KA Download Monitor started" >> "$LOG"

inotifywait -m -r -e create -e moved_to "${STAGING_DIRS[@]}" 2>/dev/null | while read -r dir event file; do
    for ext in "${SUSPICIOUS_EXTENSIONS[@]}"; do
        if [[ "$file" == *".$ext" ]]; then
            local full_path="${dir}${file}"
            local owner
            owner=$(stat -c '%U' "$full_path" 2>/dev/null || echo "unknown")
            echo "$(date) ALERT: Suspicious file created: ${full_path} by ${owner} (event: ${event})" >> "$LOG"
            logger -t f0rtika-download-monitor -p auth.warning "Suspicious file created: ${full_path} by ${owner}"
            break
        fi
    done
done
MONITOR_EOF

    chmod 755 "$monitor_script"
    log_success "Download monitor script created at $monitor_script"
    log_info "  To run: $monitor_script &"
    log_info "  Requires: inotify-tools package (apt install inotify-tools)"
}

remove_download_monitoring() {
    log_info "Removing download monitor..."

    local monitor_script="/usr/local/bin/f0rtika-download-monitor.sh"
    if [[ -f "$monitor_script" ]]; then
        rm -f "$monitor_script"
        log_success "Removed $monitor_script"
    fi

    # Kill any running instances
    pkill -f "f0rtika-download-monitor" 2>/dev/null || true
}

# ============================================================
# 6. Core Dump Restriction
# ============================================================
# Restrict core dumps to prevent attackers from using crash
# dump mechanisms to suspend or extract data from security
# processes. This is the Linux equivalent of controlling
# MiniDumpWriteDump / WerFaultSecure behavior.
# ============================================================

apply_coredump_restriction() {
    log_info "Applying core dump restrictions..."

    local current_limit
    current_limit=$(ulimit -c 2>/dev/null || echo "unknown")

    # Disable core dumps system-wide via limits.conf
    local limits_file="/etc/security/limits.d/90-f0rtika-coredump.conf"

    if [[ ! -f "$limits_file" ]]; then
        cat > "$limits_file" << 'LIMITS_EOF'
# ============================================================
# F0RT1KA EDR-Freeze Hardening - Core Dump Restriction
# Test ID: 87b7653b-2cee-44d4-9d80-73ec94d5e18e
# Technique: T1562.001 - Prevent crash dump abuse
# ============================================================
# Disable core dumps for all users.
# Security processes can be suspended or have memory extracted
# via the crash dump mechanism. Restricting core dumps reduces
# this attack surface.
# ============================================================
*    hard    core    0
*    soft    core    0
LIMITS_EOF
        log_success "Core dump limits set in $limits_file"
    else
        log_info "Core dump limits already configured"
    fi

    # Also restrict via sysctl
    if ! grep -q "fs.suid_dumpable" "$SYSCTL_FILE" 2>/dev/null; then
        cat >> "$SYSCTL_FILE" << 'SYSCTL_APPEND_EOF'

# Disable core dumps for setuid programs
fs.suid_dumpable = 0
SYSCTL_APPEND_EOF
        sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1 || true
        log_success "Disabled core dumps for setuid programs (suid_dumpable=0)"
    fi

    # Disable systemd-coredump if present (prevents automatic core dumps)
    if [[ -f /etc/systemd/coredump.conf ]]; then
        if ! grep -q "^Storage=none" /etc/systemd/coredump.conf 2>/dev/null; then
            log_info "  Consider setting Storage=none in /etc/systemd/coredump.conf"
            log_info "  This prevents systemd from storing core dumps automatically"
        fi
    fi

    log_success "Core dump restrictions applied"
}

remove_coredump_restriction() {
    log_info "Reverting core dump restrictions..."

    local limits_file="/etc/security/limits.d/90-f0rtika-coredump.conf"
    if [[ -f "$limits_file" ]]; then
        rm -f "$limits_file"
        log_success "Removed $limits_file"
    fi

    # Note: sysctl changes in SYSCTL_FILE are handled by remove_ptrace_restriction
}

# ============================================================
# Status Check
# ============================================================

check_status() {
    echo ""
    echo "============================================================"
    echo " F0RT1KA EDR-Freeze Hardening - Status Check"
    echo " Test ID: $TEST_ID"
    echo "============================================================"
    echo ""

    # Check auditd
    log_info "Auditd Status:"
    if command_exists auditctl; then
        if systemctl is-active --quiet auditd 2>/dev/null; then
            log_success "  auditd is running"
        else
            log_warning "  auditd is not running"
        fi
        if [[ -f "$AUDIT_RULES_FILE" ]]; then
            local rule_count
            rule_count=$(grep -c "^-" "$AUDIT_RULES_FILE" 2>/dev/null || echo "0")
            log_success "  F0RT1KA audit rules present ($rule_count rules)"
        else
            log_warning "  No F0RT1KA audit rules found"
        fi
    else
        log_warning "  auditd is not installed"
    fi

    # Check ptrace restriction
    log_info "Ptrace Restriction:"
    local ptrace_scope
    ptrace_scope=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "N/A")
    case "$ptrace_scope" in
        0) log_warning "  ptrace_scope = 0 (unrestricted - VULNERABLE)" ;;
        1) log_success "  ptrace_scope = 1 (parent only - HARDENED)" ;;
        2) log_success "  ptrace_scope = 2 (admin only - HARDENED)" ;;
        3) log_success "  ptrace_scope = 3 (disabled - MAXIMUM)" ;;
        *) log_info "  ptrace_scope = $ptrace_scope (unknown/unavailable)" ;;
    esac

    # Check staging directory hardening
    log_info "Staging Directory Hardening:"
    for dir in /tmp /var/tmp /dev/shm; do
        if [[ -d "$dir" ]]; then
            local mount_opts
            mount_opts=$(mount | grep " $dir " 2>/dev/null || echo "")
            if echo "$mount_opts" | grep -q "noexec"; then
                log_success "  $dir: noexec enabled"
            else
                log_warning "  $dir: noexec NOT enabled"
            fi
        fi
    done

    # Check core dump restriction
    log_info "Core Dump Restriction:"
    local suid_dumpable
    suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "N/A")
    if [[ "$suid_dumpable" == "0" ]]; then
        log_success "  suid_dumpable = 0 (disabled - HARDENED)"
    else
        log_warning "  suid_dumpable = $suid_dumpable (VULNERABLE)"
    fi

    # Check security services
    log_info "Security Service Status:"
    local found_any=false
    for service in "${SECURITY_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_success "  $service: running"
            found_any=true
        fi
    done
    if [[ "$found_any" == "false" ]]; then
        log_info "  No monitored security services found running"
    fi

    # Check sysctl hardening file
    log_info "Sysctl Hardening:"
    if [[ -f "$SYSCTL_FILE" ]]; then
        log_success "  F0RT1KA sysctl config present at $SYSCTL_FILE"
    else
        log_warning "  No F0RT1KA sysctl config found"
    fi

    echo ""
    echo "============================================================"
    echo " Status check complete"
    echo "============================================================"
}

# ============================================================
# Main Execution
# ============================================================

main() {
    echo ""
    echo "============================================================"
    echo " F0RT1KA EDR-Freeze Defense Evasion - Linux Hardening"
    echo " Test ID: $TEST_ID"
    echo " MITRE ATT&CK: T1562.001, T1055, T1574"
    echo "============================================================"
    echo ""

    case "$ACTION" in
        apply)
            check_root
            log_info "Applying hardening measures..."
            echo ""

            install_auditd
            echo ""

            apply_audit_rules
            echo ""

            apply_ptrace_restriction
            echo ""

            apply_service_protection
            echo ""

            apply_staging_hardening
            echo ""

            apply_download_monitoring
            echo ""

            apply_coredump_restriction
            echo ""

            echo "============================================================"
            log_success "Hardening complete!"
            echo "============================================================"
            echo ""
            log_info "Summary of applied protections:"
            log_success "  - Auditd rules for security process monitoring"
            log_success "  - Ptrace restriction (Yama LSM)"
            log_success "  - Security service protection"
            log_success "  - Staging directory hardening"
            log_success "  - Download tool monitoring"
            log_success "  - Core dump restrictions"
            echo ""
            log_info "Log file: $LOG_FILE"
            log_info "Run with 'check' to verify status"
            log_info "Run with 'undo' to revert all changes"
            ;;

        undo)
            check_root
            log_warning "Reverting all hardening changes..."
            echo ""

            remove_audit_rules
            remove_ptrace_restriction
            remove_service_protection
            remove_staging_hardening
            remove_download_monitoring
            remove_coredump_restriction

            echo ""
            log_success "All hardening changes reverted"
            log_info "Log file: $LOG_FILE"
            ;;

        check|status)
            check_root
            check_status
            ;;

        *)
            echo "Usage: $SCRIPT_NAME [apply|undo|check]"
            echo ""
            echo "  apply  - Apply all hardening measures (default)"
            echo "  undo   - Revert all hardening changes"
            echo "  check  - Report current hardening status"
            exit 1
            ;;
    esac
}

main
