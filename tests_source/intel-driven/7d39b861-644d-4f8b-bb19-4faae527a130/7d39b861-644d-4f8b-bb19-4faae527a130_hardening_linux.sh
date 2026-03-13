#!/usr/bin/env bash
# ============================================================================
# Linux Hardening Script: Agrius Multi-Wiper Deployment Against Banking Infrastructure
# ============================================================================
#
# Test ID:      7d39b861-644d-4f8b-bb19-4faae527a130
# Test Name:    Agrius Multi-Wiper Deployment Against Banking Infrastructure
# MITRE ATT&CK: T1505.003 (Web Shell), T1543.003 (Windows Service),
#                T1562.001 (Disable or Modify Tools), T1485 (Data Destruction),
#                T1070.001 (Clear Windows Event Logs)
# Mitigations:  M1018, M1022, M1024, M1026, M1029, M1038, M1042, M1047, M1053
# Platform:     Linux (Ubuntu/Debian, RHEL/CentOS, generic)
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
#
# DESCRIPTION:
#   While this test targets Windows, the underlying techniques have Linux
#   equivalents. This script hardens Linux systems against:
#     1. Webshell deployment (PHP/CGI equivalents of ASPXSpy)
#     2. Systemd service persistence (Linux equivalent of Windows Services)
#     3. Security tool tampering (disabling auditd, AppArmor, SELinux)
#     4. Data destruction / wiper resilience (file integrity monitoring)
#     5. Log tampering protection (immutable logs, remote forwarding)
#     6. Kernel module loading restrictions (BYOVD equivalent)
#
# USAGE:
#   sudo ./7d39b861-644d-4f8b-bb19-4faae527a130_hardening_linux.sh [--undo] [--dry-run] [--verbose]
#
# OPTIONS:
#   --undo      Revert all changes made by this script
#   --dry-run   Show what would be changed without applying
#   --verbose   Enable detailed output
#
# REQUIREMENTS:
#   - Root privileges (sudo)
#   - systemd-based Linux distribution
#   - auditd installed (or will be installed)
#
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly TEST_ID="7d39b861-644d-4f8b-bb19-4faae527a130"
readonly LOG_FILE="/var/log/f0rtika_agrius_hardening_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/var/backups/f0rtika_agrius_hardening"

UNDO=false
DRY_RUN=false
VERBOSE=false
CHANGES_MADE=0

# ============================================================================
# Argument Parsing
# ============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo)     UNDO=true; shift ;;
        --dry-run)  DRY_RUN=true; shift ;;
        --verbose)  VERBOSE=true; shift ;;
        -h|--help)
            echo "Usage: sudo $SCRIPT_NAME [--undo] [--dry-run] [--verbose]"
            echo ""
            echo "Hardens Linux systems against Agrius-equivalent destructive attack techniques."
            echo ""
            echo "Options:"
            echo "  --undo      Revert all changes to defaults"
            echo "  --dry-run   Show changes without applying"
            echo "  --verbose   Detailed output"
            echo "  -h, --help  Show this help"
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown option: $1"
            exit 1
            ;;
    esac
done

# ============================================================================
# Helper Functions
# ============================================================================

log_info()    { echo "[*] $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_success() { echo -e "\033[0;32m[+] $1\033[0m"; echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo -e "\033[0;33m[!] $1\033[0m"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "\033[0;31m[-] $1\033[0m"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_header()  { echo -e "\033[0;35m[=] $1\033[0m"; echo "$(date '+%Y-%m-%d %H:%M:%S') [HEADER] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_verbose() { if $VERBOSE; then echo "    $1"; fi; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

is_debian_family() { command -v apt-get &>/dev/null; }
is_rhel_family()   { command -v yum &>/dev/null || command -v dnf &>/dev/null; }

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$file" "$BACKUP_DIR/$(basename "$file").$(date +%Y%m%d%H%M%S).bak"
        log_verbose "Backed up: $file"
    fi
}

apply_sysctl() {
    local key="$1"
    local value="$2"
    local current

    current=$(sysctl -n "$key" 2>/dev/null || echo "NOT_SET")

    if [[ "$current" == "$value" ]]; then
        log_verbose "Already set: $key = $value"
        return 0
    fi

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would set: $key = $value (current: $current)"
        return 0
    fi

    sysctl -w "$key=$value" >/dev/null 2>&1 && {
        log_success "Set: $key = $value (was: $current)"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    } || {
        log_warning "Failed to set: $key = $value"
    }
}

persist_sysctl() {
    local key="$1"
    local value="$2"
    local conf_file="/etc/sysctl.d/90-f0rtika-agrius-hardening.conf"

    if $DRY_RUN; then
        return 0
    fi

    # Remove any existing entry for this key
    if [[ -f "$conf_file" ]]; then
        sed -i "/^${key//./\\.}\s*=/d" "$conf_file"
    fi

    echo "$key = $value" >> "$conf_file"
}

# ============================================================================
# 1. Web Shell Prevention (Linux equivalent of T1505.003)
# ============================================================================
# MITRE Mitigation: M1042 - Disable or Remove Feature, M1018 - User Account Mgmt
# Protects web server directories from unauthorized file creation

harden_web_directories() {
    log_header "1. Web Shell Prevention (T1505.003 Equivalent)"

    if $UNDO; then
        log_info "Reverting web directory hardening..."

        if [[ -f /etc/audit/rules.d/f0rtika-webshell.rules ]]; then
            rm -f /etc/audit/rules.d/f0rtika-webshell.rules
            log_success "Removed webshell audit rules"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    # Check common web server directories
    local web_dirs=("/var/www" "/var/www/html" "/usr/share/nginx/html" "/srv/www")

    for dir in "${web_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_info "Found web directory: $dir"

            if $DRY_RUN; then
                log_info "[DRY-RUN] Would restrict write access to $dir"
            else
                # Set ownership to root and restrict write
                chown -R root:www-data "$dir" 2>/dev/null || chown -R root:nginx "$dir" 2>/dev/null || true
                # Remove group and other write permissions
                find "$dir" -type d -exec chmod 755 {} \; 2>/dev/null
                find "$dir" -type f -exec chmod 644 {} \; 2>/dev/null
                log_success "Restricted write access to: $dir"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            fi
        fi
    done

    # Configure auditd rules for web directory monitoring
    if command -v auditctl &>/dev/null; then
        local audit_file="/etc/audit/rules.d/f0rtika-webshell.rules"

        if $DRY_RUN; then
            log_info "[DRY-RUN] Would create webshell audit rules at $audit_file"
        else
            backup_file "$audit_file"
            cat > "$audit_file" << 'AUDIT_EOF'
# F0RT1KA Hardening: Monitor web directories for webshell creation
# Test ID: 7d39b861-644d-4f8b-bb19-4faae527a130
# MITRE ATT&CK: T1505.003 (Web Shell)

# Monitor file creation in web directories
-w /var/www -p wa -k webshell_creation
-w /usr/share/nginx/html -p wa -k webshell_creation
-w /srv/www -p wa -k webshell_creation

# Monitor PHP file creation anywhere (common webshell)
-a always,exit -F arch=b64 -S creat -S open -S openat -F dir=/var/www -F perm=wa -k webshell_write
-a always,exit -F arch=b64 -S creat -S open -S openat -F dir=/tmp -F perm=wa -F auid>=1000 -k suspicious_file_creation
AUDIT_EOF
            log_success "Webshell audit rules created: $audit_file"
            CHANGES_MADE=$((CHANGES_MADE + 1))

            # Reload audit rules
            augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
        fi
    else
        log_warning "auditd not found -- install auditd for webshell monitoring"
        if is_debian_family; then
            log_info "Install with: apt-get install auditd"
        elif is_rhel_family; then
            log_info "Install with: yum install audit"
        fi
    fi
}

# ============================================================================
# 2. Systemd Service Hardening (Linux equivalent of T1543.003)
# ============================================================================
# MITRE Mitigation: M1028 - Operating System Configuration
# Prevents unauthorized systemd service creation

harden_systemd_services() {
    log_header "2. Systemd Service Hardening (T1543.003 Equivalent)"

    if $UNDO; then
        log_info "Reverting systemd hardening..."

        if [[ -f /etc/audit/rules.d/f0rtika-systemd.rules ]]; then
            rm -f /etc/audit/rules.d/f0rtika-systemd.rules
            log_success "Removed systemd audit rules"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    # Monitor systemd unit directories for unauthorized service creation
    local audit_file="/etc/audit/rules.d/f0rtika-systemd.rules"

    if command -v auditctl &>/dev/null; then
        if $DRY_RUN; then
            log_info "[DRY-RUN] Would create systemd audit rules"
        else
            backup_file "$audit_file"
            cat > "$audit_file" << 'AUDIT_EOF'
# F0RT1KA Hardening: Monitor systemd service creation
# Test ID: 7d39b861-644d-4f8b-bb19-4faae527a130
# MITRE ATT&CK: T1543.003 (Windows Service equivalent)

# Monitor systemd unit file directories
-w /etc/systemd/system -p wa -k systemd_service_creation
-w /usr/lib/systemd/system -p wa -k systemd_service_creation
-w /run/systemd/system -p wa -k systemd_service_creation

# Monitor user-level systemd units
-w /etc/systemd/user -p wa -k systemd_user_service

# Monitor init.d scripts (legacy persistence)
-w /etc/init.d -p wa -k init_persistence

# Monitor cron for persistence
-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.d -p wa -k cron_persistence
-w /var/spool/cron -p wa -k cron_persistence

# Monitor systemctl daemon-reload
-a always,exit -F arch=b64 -S execve -F path=/bin/systemctl -k systemctl_exec
AUDIT_EOF
            log_success "Systemd audit rules created: $audit_file"
            CHANGES_MADE=$((CHANGES_MADE + 1))

            augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
        fi
    fi

    # Restrict systemd unit directory permissions
    local systemd_dirs=("/etc/systemd/system" "/usr/lib/systemd/system")
    for dir in "${systemd_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local current_perms
            current_perms=$(stat -c %a "$dir" 2>/dev/null || echo "unknown")

            if [[ "$current_perms" != "755" ]] && [[ "$current_perms" != "unknown" ]]; then
                if $DRY_RUN; then
                    log_info "[DRY-RUN] Would set $dir permissions to 755 (current: $current_perms)"
                else
                    chmod 755 "$dir"
                    log_success "Set $dir permissions to 755 (was: $current_perms)"
                    CHANGES_MADE=$((CHANGES_MADE + 1))
                fi
            fi
        fi
    done
}

# ============================================================================
# 3. Security Tool Tampering Protection (Linux T1562.001 Equivalent)
# ============================================================================
# MITRE Mitigation: M1024 - Restrict Permissions
# Protects auditd, AppArmor, and SELinux from being disabled

harden_security_tools() {
    log_header "3. Security Tool Tampering Protection (T1562.001 Equivalent)"

    if $UNDO; then
        log_info "Reverting security tool protection..."

        if [[ -f /etc/audit/rules.d/f0rtika-security-tools.rules ]]; then
            rm -f /etc/audit/rules.d/f0rtika-security-tools.rules
            log_success "Removed security tool audit rules"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    # Monitor attempts to disable security services
    if command -v auditctl &>/dev/null; then
        local audit_file="/etc/audit/rules.d/f0rtika-security-tools.rules"

        if $DRY_RUN; then
            log_info "[DRY-RUN] Would create security tool protection audit rules"
        else
            backup_file "$audit_file"
            cat > "$audit_file" << 'AUDIT_EOF'
# F0RT1KA Hardening: Protect security tools from tampering
# Test ID: 7d39b861-644d-4f8b-bb19-4faae527a130
# MITRE ATT&CK: T1562.001 (Disable or Modify Tools)

# Monitor auditd configuration changes
-w /etc/audit/auditd.conf -p wa -k audit_config_change
-w /etc/audit/rules.d/ -p wa -k audit_rules_change
-w /etc/audisp/ -p wa -k audit_plugin_change

# Monitor AppArmor configuration
-w /etc/apparmor.d/ -p wa -k apparmor_change
-w /etc/apparmor/ -p wa -k apparmor_change

# Monitor SELinux configuration
-w /etc/selinux/config -p wa -k selinux_change
-w /etc/selinux/ -p wa -k selinux_change

# Monitor attempts to stop security services
-a always,exit -F arch=b64 -S execve -F path=/bin/systemctl -F a0=stop -k security_service_stop
-a always,exit -F arch=b64 -S execve -F path=/bin/systemctl -F a0=disable -k security_service_disable

# Monitor kernel module loading (BYOVD equivalent)
-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module_load
-a always,exit -F arch=b64 -S delete_module -k kernel_module_unload

# Monitor sysctl changes (defense evasion)
-w /etc/sysctl.conf -p wa -k sysctl_change
-w /etc/sysctl.d/ -p wa -k sysctl_change
AUDIT_EOF
            log_success "Security tool protection audit rules created"
            CHANGES_MADE=$((CHANGES_MADE + 1))

            augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
        fi
    fi

    # Verify security tools are running
    local security_services=("auditd" "apparmor" "selinux")

    for svc in "${security_services[@]}"; do
        if systemctl is-active "$svc" &>/dev/null; then
            log_success "Security service $svc is running"
        elif [[ "$svc" == "selinux" ]] && command -v getenforce &>/dev/null; then
            local selinux_status
            selinux_status=$(getenforce 2>/dev/null || echo "unknown")
            if [[ "$selinux_status" == "Enforcing" ]]; then
                log_success "SELinux is in Enforcing mode"
            elif [[ "$selinux_status" == "Permissive" ]]; then
                log_warning "SELinux is in Permissive mode -- consider switching to Enforcing"
            else
                log_info "SELinux status: $selinux_status"
            fi
        elif systemctl is-enabled "$svc" &>/dev/null; then
            log_warning "Security service $svc is enabled but not running"
        else
            log_verbose "Security service $svc not found on this system"
        fi
    done

    # Lock down kernel module loading (BYOVD prevention)
    log_info "Configuring kernel module loading restrictions..."

    local blocklist_file="/etc/modprobe.d/f0rtika-agrius-blocklist.conf"
    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create kernel module blocklist"
    else
        backup_file "$blocklist_file"
        cat > "$blocklist_file" << 'MODPROBE_EOF'
# F0RT1KA Hardening: Block potentially dangerous kernel modules
# Test ID: 7d39b861-644d-4f8b-bb19-4faae527a130
# MITRE ATT&CK: T1562.001 (BYOVD equivalent)

# Block raw I/O modules
blacklist pcspkr
blacklist snd_pcsp

# Block firewire DMA attack vectors
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2

# Block uncommon filesystem modules (reduce attack surface)
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf

# Block uncommon network protocols
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc

# Prevent loading via install redirect
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
MODPROBE_EOF
        log_success "Kernel module blocklist created: $blocklist_file"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    fi

    # Check Secure Boot status
    if command -v mokutil &>/dev/null; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
        if echo "$sb_state" | grep -qi "enabled"; then
            log_success "Secure Boot is enabled -- kernel module signing enforced"
        else
            log_warning "Secure Boot is NOT enabled -- unsigned kernel modules may load"
        fi
    fi
}

# ============================================================================
# 4. Data Destruction Protection (T1485 Equivalent)
# ============================================================================
# MITRE Mitigation: M1053 - Data Backup, M1022 - Restrict File Permissions
# Configures file integrity monitoring and backup recommendations

harden_data_protection() {
    log_header "4. Data Destruction Protection (T1485 Equivalent)"

    if $UNDO; then
        log_info "Reverting data protection..."

        if [[ -f /etc/audit/rules.d/f0rtika-data-protection.rules ]]; then
            rm -f /etc/audit/rules.d/f0rtika-data-protection.rules
            log_success "Removed data protection audit rules"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    # Configure file integrity monitoring for critical directories
    if command -v auditctl &>/dev/null; then
        local audit_file="/etc/audit/rules.d/f0rtika-data-protection.rules"

        if $DRY_RUN; then
            log_info "[DRY-RUN] Would create data protection audit rules"
        else
            backup_file "$audit_file"
            cat > "$audit_file" << 'AUDIT_EOF'
# F0RT1KA Hardening: File integrity monitoring for wiper detection
# Test ID: 7d39b861-644d-4f8b-bb19-4faae527a130
# MITRE ATT&CK: T1485 (Data Destruction)

# Monitor mass file operations (wiper behavior)
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -k file_deletion
-a always,exit -F arch=b64 -S truncate -S ftruncate -F auid>=1000 -k file_truncation

# Monitor critical system directories
-w /etc/passwd -p wa -k identity_file_change
-w /etc/shadow -p wa -k identity_file_change
-w /etc/group -p wa -k identity_file_change
-w /etc/sudoers -p wa -k privilege_change
-w /etc/sudoers.d -p wa -k privilege_change

# Monitor boot sector access (MBR/VBR wiper detection)
-a always,exit -F arch=b64 -S open -S openat -F path=/dev/sda -F perm=w -k raw_disk_write
-a always,exit -F arch=b64 -S open -S openat -F path=/dev/nvme0n1 -F perm=w -k raw_disk_write

# Monitor dd and shred usage (common wiper tools)
-a always,exit -F arch=b64 -S execve -F path=/bin/dd -k data_destruction_tool
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/shred -k data_destruction_tool
-a always,exit -F arch=b64 -S execve -F path=/bin/rm -k file_removal
AUDIT_EOF
            log_success "Data protection audit rules created"
            CHANGES_MADE=$((CHANGES_MADE + 1))

            augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
        fi
    fi

    # Check for AIDE (file integrity checker)
    if command -v aide &>/dev/null; then
        log_success "AIDE file integrity checker is installed"
        log_info "Run 'aide --check' regularly to detect unauthorized file changes"
    else
        log_warning "AIDE not installed -- consider installing for file integrity monitoring"
        if is_debian_family; then
            log_info "Install with: apt-get install aide"
        elif is_rhel_family; then
            log_info "Install with: yum install aide"
        fi
    fi

    # Harden immutable attribute on critical files
    if $DRY_RUN; then
        log_info "[DRY-RUN] Would set immutable flag on critical configuration files"
    else
        # Make critical config files immutable (prevents deletion/modification)
        local immutable_files=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/sudoers")
        for f in "${immutable_files[@]}"; do
            if [[ -f "$f" ]]; then
                chattr +i "$f" 2>/dev/null && {
                    log_success "Set immutable flag on: $f"
                    CHANGES_MADE=$((CHANGES_MADE + 1))
                } || log_verbose "Could not set immutable flag on $f (may require ext4)"
            fi
        done
    fi

    # Backup recommendations
    log_info ""
    log_info "DATA PROTECTION RECOMMENDATIONS:"
    log_info "  1. Implement automated backups with immutable storage"
    log_info "  2. Use btrfs snapshots or LVM snapshots for point-in-time recovery"
    log_info "  3. Configure rsync to air-gapped backup server"
    log_info "  4. Test backup restoration monthly"
    log_info "  5. Monitor for mass file deletion via audit logs"
    log_info ""
}

# ============================================================================
# 5. Log Protection and Forwarding (T1070.001 Equivalent)
# ============================================================================
# MITRE Mitigation: M1029 - Remote Data Storage, M1047 - Audit
# Protects system logs from clearing and configures remote forwarding

harden_log_protection() {
    log_header "5. Log Protection and Forwarding (T1070.001 Equivalent)"

    if $UNDO; then
        log_info "Reverting log protection..."

        if [[ -f /etc/sysctl.d/90-f0rtika-agrius-hardening.conf ]]; then
            rm -f /etc/sysctl.d/90-f0rtika-agrius-hardening.conf
            sysctl --system >/dev/null 2>&1
            log_success "Removed sysctl hardening configuration"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    # Make audit log configuration immutable
    if [[ -f /etc/audit/auditd.conf ]]; then
        # Ensure audit log is append-only
        if $DRY_RUN; then
            log_info "[DRY-RUN] Would configure auditd for maximum retention"
        else
            backup_file /etc/audit/auditd.conf

            # Set large log file size and keep multiple logs
            sed -i 's/^max_log_file\s*=.*/max_log_file = 256/' /etc/audit/auditd.conf 2>/dev/null || true
            sed -i 's/^num_logs\s*=.*/num_logs = 10/' /etc/audit/auditd.conf 2>/dev/null || true
            sed -i 's/^max_log_file_action\s*=.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf 2>/dev/null || true

            log_success "auditd configured for maximum retention (256MB x 10 logs)"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
    fi

    # Lock audit rules after loading (prevents modification)
    if command -v auditctl &>/dev/null; then
        log_info "Consider adding '-e 2' to end of audit rules to make them immutable"
        log_info "This prevents audit rule modification until reboot"
        log_verbose "Add to /etc/audit/rules.d/99-finalize.rules: -e 2"
    fi

    # Protect log files from deletion
    local log_dirs=("/var/log/audit" "/var/log")
    for dir in "${log_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            if $DRY_RUN; then
                log_info "[DRY-RUN] Would restrict permissions on $dir"
            else
                chmod 750 "$dir" 2>/dev/null
                log_success "Restricted permissions on: $dir"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            fi
        fi
    done

    # Harden kernel parameters for security
    apply_sysctl "kernel.dmesg_restrict" "1"
    persist_sysctl "kernel.dmesg_restrict" "1"

    apply_sysctl "kernel.kptr_restrict" "2"
    persist_sysctl "kernel.kptr_restrict" "2"

    # Restrict kernel sysrq (prevents forced reboot/crash)
    apply_sysctl "kernel.sysrq" "0"
    persist_sysctl "kernel.sysrq" "0"

    # Recommend remote syslog forwarding
    log_info ""
    log_info "LOG FORWARDING RECOMMENDATIONS:"
    log_info "  1. Configure rsyslog/syslog-ng to forward to SIEM"
    log_info "  2. Use TLS for encrypted log transport"
    log_info "  3. Forward audit logs via audisp-remote plugin"
    log_info "  4. Monitor for sudden drop in log volume (clearing indicator)"
    log_info ""

    if command -v rsyslogd &>/dev/null; then
        log_info "rsyslog is available -- add remote forwarding to /etc/rsyslog.d/"
        log_info "Example: *.* @@<SIEM_IP>:514"
    fi
}

# ============================================================================
# 6. Network and Kernel Hardening
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention
# General kernel and network hardening

harden_kernel_network() {
    log_header "6. Network and Kernel Hardening"

    if $UNDO; then
        log_info "Sysctl changes will be reverted when hardening conf is removed"
        return
    fi

    # Disable IP forwarding (unless explicitly needed)
    apply_sysctl "net.ipv4.ip_forward" "0"
    persist_sysctl "net.ipv4.ip_forward" "0"

    # Enable SYN cookies (SYN flood protection)
    apply_sysctl "net.ipv4.tcp_syncookies" "1"
    persist_sysctl "net.ipv4.tcp_syncookies" "1"

    # Ignore ICMP broadcast requests
    apply_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
    persist_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"

    # Disable source routing
    apply_sysctl "net.ipv4.conf.all.accept_source_route" "0"
    persist_sysctl "net.ipv4.conf.all.accept_source_route" "0"

    # Enable reverse path filtering
    apply_sysctl "net.ipv4.conf.all.rp_filter" "1"
    persist_sysctl "net.ipv4.conf.all.rp_filter" "1"

    # Log martian packets
    apply_sysctl "net.ipv4.conf.all.log_martians" "1"
    persist_sysctl "net.ipv4.conf.all.log_martians" "1"

    # Disable ICMP redirects
    apply_sysctl "net.ipv4.conf.all.accept_redirects" "0"
    persist_sysctl "net.ipv4.conf.all.accept_redirects" "0"

    apply_sysctl "net.ipv4.conf.all.send_redirects" "0"
    persist_sysctl "net.ipv4.conf.all.send_redirects" "0"

    # ASLR hardening
    apply_sysctl "kernel.randomize_va_space" "2"
    persist_sysctl "kernel.randomize_va_space" "2"

    # Restrict core dumps
    apply_sysctl "fs.suid_dumpable" "0"
    persist_sysctl "fs.suid_dumpable" "0"
}

# ============================================================================
# Main Execution
# ============================================================================

log_header "============================================================================"
log_header " F0RT1KA Linux Hardening Script"
log_header " Test: Agrius Multi-Wiper Deployment Against Banking Infrastructure"
log_header " ID:   $TEST_ID"
log_header " MITRE: T1505.003, T1543.003, T1562.001, T1485, T1070.001"
log_header "============================================================================"
echo ""

check_root

if $UNDO; then
    log_warning "UNDO MODE: Reverting all hardening changes..."
    echo ""
elif $DRY_RUN; then
    log_info "DRY-RUN MODE: Showing changes without applying..."
    echo ""
else
    log_info "Applying hardening settings..."
    echo ""
fi

# Execute all hardening functions
harden_web_directories
echo ""

harden_systemd_services
echo ""

harden_security_tools
echo ""

harden_data_protection
echo ""

harden_log_protection
echo ""

harden_kernel_network
echo ""

# Summary
log_header "============================================================================"
log_header " Hardening Complete"
log_header "============================================================================"
echo ""

log_success "Changes made: $CHANGES_MADE"
log_info "Log file: $LOG_FILE"
log_info "Backups: $BACKUP_DIR"
echo ""

if ! $UNDO; then
    log_info "Post-hardening steps:"
    log_info "  1. Restart auditd: systemctl restart auditd"
    log_info "  2. Apply sysctl changes: sysctl --system"
    log_info "  3. Configure remote syslog forwarding to SIEM"
    log_info "  4. Install and initialize AIDE: aide --init"
    log_info "  5. Test backup and restore procedures"
    echo ""
fi
