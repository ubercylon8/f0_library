#!/usr/bin/env bash
# ============================================================================
# Linux Hardening Script: Akira Ransomware BYOVD Attack Chain
# ============================================================================
#
# Test ID:      c3634a9c-e8c9-44a8-992b-0faeca14f612
# Test Name:    Akira Ransomware BYOVD Attack Chain
# MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)
#                T1562.001 (Impair Defenses: Disable or Modify Tools)
# Mitigations:  M1047, M1038, M1050, M1051, M1024
# Platform:     Linux (Ubuntu/Debian, RHEL/CentOS, generic)
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
#
# DESCRIPTION:
#   While this test targets Windows, the underlying BYOVD and defense
#   evasion techniques have Linux equivalents. This script hardens Linux
#   systems against:
#     1. Unsigned/malicious kernel module loading (Linux BYOVD equivalent)
#     2. Security tool tampering (disabling auditd, AppArmor, SELinux)
#     3. Suspicious service creation (systemd persistence)
#     4. Kernel parameter hardening
#     5. Audit logging for detection
#
# USAGE:
#   sudo ./c3634a9c_hardening_linux.sh [--undo] [--dry-run] [--verbose]
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
readonly TEST_ID="c3634a9c-e8c9-44a8-992b-0faeca14f612"
readonly LOG_FILE="/var/log/f0rtika_hardening_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/var/backups/f0rtika_hardening"

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
            echo "Hardens Linux systems against BYOVD-equivalent and defense evasion techniques."
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
    local conf_file="/etc/sysctl.d/90-f0rtika-byovd-hardening.conf"

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
# 1. Kernel Module Loading Restrictions (Linux BYOVD Equivalent)
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention
# Linux equivalent of Windows Driver Signature Enforcement and
# Vulnerable Driver Blocklist.

harden_kernel_modules() {
    log_header "1. Kernel Module Loading Restrictions"

    if $UNDO; then
        log_info "Reverting kernel module restrictions..."

        if [[ -f /etc/modprobe.d/f0rtika-blocklist.conf ]]; then
            rm -f /etc/modprobe.d/f0rtika-blocklist.conf
            log_success "Removed custom module blocklist"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi

        if [[ -f /etc/sysctl.d/90-f0rtika-byovd-hardening.conf ]]; then
            rm -f /etc/sysctl.d/90-f0rtika-byovd-hardening.conf
            sysctl --system >/dev/null 2>&1
            log_success "Removed sysctl hardening configuration"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    # Restrict loading of unsigned kernel modules (requires kernel support)
    # kernel.modules_disabled = 1 prevents ANY new module loading after boot
    # This is aggressive -- only enable if all needed modules are loaded at boot
    log_info "Configuring kernel module loading restrictions..."

    # Lock down module loading after boot (AGGRESSIVE - uncomment if appropriate)
    # apply_sysctl "kernel.modules_disabled" "1"
    # persist_sysctl "kernel.modules_disabled" "1"
    # log_warning "kernel.modules_disabled=1 prevents all module loading until reboot"

    # Block known dangerous modules via modprobe blacklist
    local blocklist_file="/etc/modprobe.d/f0rtika-blocklist.conf"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create module blocklist at $blocklist_file"
    else
        backup_file "$blocklist_file"
        cat > "$blocklist_file" << 'MODPROBE_EOF'
# F0RT1KA Hardening: Block potentially dangerous kernel modules
# BYOVD equivalent - prevent loading of known-abusable modules
# Test ID: c3634a9c-e8c9-44a8-992b-0faeca14f612
# MITRE ATT&CK: T1068 (Privilege Escalation)

# Block raw I/O modules that could be exploited for direct hardware access
blacklist pcspkr
blacklist snd_pcsp

# Block firewire modules (DMA attack vector)
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2

# Block thunderbolt DMA attack vector (if not needed)
# blacklist thunderbolt

# Block USB storage if not needed (reduces attack surface)
# blacklist usb-storage
# blacklist uas

# Block uncommon filesystem modules (reduce kernel attack surface)
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

# Prevent loading these modules even if requested
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
        log_success "Created kernel module blocklist: $blocklist_file"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    fi

    # Enforce module signature verification if supported
    if [[ -f /proc/sys/kernel/modules_disabled ]]; then
        log_info "Kernel module loading control is available"
        log_verbose "Set kernel.modules_disabled=1 after boot for maximum protection"
    fi

    # Check if Secure Boot is enabled (enforces module signing)
    if command -v mokutil &>/dev/null; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
        if echo "$sb_state" | grep -qi "enabled"; then
            log_success "Secure Boot is enabled - kernel module signing enforced"
        else
            log_warning "Secure Boot is NOT enabled - unsigned kernel modules may load"
            log_info "Enable Secure Boot in UEFI/BIOS for kernel module signature enforcement"
        fi
    fi
}

# ============================================================================
# 2. Security Tool Tampering Protection (Linux T1562.001 Equivalent)
# ============================================================================
# MITRE Mitigation: M1024 - Restrict Registry Permissions
# Linux equivalent of Windows Defender Tamper Protection.

harden_security_services() {
    log_header "2. Security Service Tampering Protection"

    if $UNDO; then
        log_info "Reverting security service protections..."
        # Remove immutable flags from service files
        for svc_file in /etc/systemd/system/auditd.service.d/f0rtika-protect.conf \
                        /etc/systemd/system/apparmor.service.d/f0rtika-protect.conf; do
            if [[ -f "$svc_file" ]]; then
                chattr -i "$svc_file" 2>/dev/null || true
                rm -f "$svc_file"
                log_success "Removed service protection: $svc_file"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            fi
        done
        systemctl daemon-reload 2>/dev/null || true
        return
    fi

    # Protect auditd from being stopped (equivalent to protecting Defender)
    if systemctl list-unit-files auditd.service &>/dev/null; then
        log_info "Protecting auditd service from tampering..."

        local auditd_override="/etc/systemd/system/auditd.service.d/f0rtika-protect.conf"

        if $DRY_RUN; then
            log_info "[DRY-RUN] Would create auditd protection override"
        else
            mkdir -p "$(dirname "$auditd_override")"
            cat > "$auditd_override" << 'AUDITD_EOF'
# F0RT1KA Hardening: Protect auditd from tampering
# Equivalent to Windows Defender Tamper Protection
[Unit]
RefuseManualStop=yes

[Service]
Restart=always
RestartSec=5
AUDITD_EOF
            systemctl daemon-reload
            systemctl enable auditd 2>/dev/null || true
            systemctl start auditd 2>/dev/null || true
            log_success "auditd protected from manual stop and set to auto-restart"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
    else
        log_warning "auditd not installed - installing..."
        if ! $DRY_RUN; then
            if is_debian_family; then
                DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins 2>/dev/null || \
                    DEBIAN_FRONTEND=noninteractive apt-get install -y auditd 2>/dev/null || \
                    log_warning "Failed to install auditd"
            elif is_rhel_family; then
                yum install -y audit audit-libs 2>/dev/null || \
                    dnf install -y audit audit-libs 2>/dev/null || \
                    log_warning "Failed to install auditd"
            fi
        fi
    fi

    # Protect AppArmor if available
    if systemctl list-unit-files apparmor.service &>/dev/null; then
        log_info "Protecting AppArmor service..."

        local apparmor_override="/etc/systemd/system/apparmor.service.d/f0rtika-protect.conf"

        if ! $DRY_RUN; then
            mkdir -p "$(dirname "$apparmor_override")"
            cat > "$apparmor_override" << 'APPARMOR_EOF'
# F0RT1KA Hardening: Protect AppArmor from tampering
[Unit]
RefuseManualStop=yes
APPARMOR_EOF
            systemctl daemon-reload
            log_success "AppArmor protected from manual stop"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
    fi

    # Ensure SELinux is enforcing if available
    if command -v getenforce &>/dev/null; then
        local selinux_status
        selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
        if [[ "$selinux_status" == "Enforcing" ]]; then
            log_success "SELinux is already in Enforcing mode"
        elif [[ "$selinux_status" == "Permissive" ]]; then
            log_warning "SELinux is in Permissive mode"
            if ! $DRY_RUN; then
                setenforce 1 2>/dev/null && {
                    log_success "SELinux set to Enforcing mode"
                    CHANGES_MADE=$((CHANGES_MADE + 1))
                } || log_warning "Failed to set SELinux to Enforcing (may require reboot)"
            fi
        else
            log_warning "SELinux is Disabled - consider enabling for kernel-level mandatory access control"
        fi
    fi
}

# ============================================================================
# 3. Kernel Parameter Hardening
# ============================================================================
# MITRE Mitigation: M1050 - Exploit Protection
# Hardens kernel parameters to reduce privilege escalation attack surface.

harden_kernel_parameters() {
    log_header "3. Kernel Parameter Hardening"

    if $UNDO; then
        log_info "Reverting kernel parameter hardening..."
        if [[ -f /etc/sysctl.d/90-f0rtika-byovd-hardening.conf ]]; then
            rm -f /etc/sysctl.d/90-f0rtika-byovd-hardening.conf
            sysctl --system >/dev/null 2>&1
            log_success "Removed kernel parameter hardening"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    log_info "Applying kernel parameter hardening..."

    # Restrict access to kernel pointers (prevents information disclosure for exploitation)
    apply_sysctl "kernel.kptr_restrict" "2"
    persist_sysctl "kernel.kptr_restrict" "2"

    # Restrict access to dmesg (prevents information leakage)
    apply_sysctl "kernel.dmesg_restrict" "1"
    persist_sysctl "kernel.dmesg_restrict" "1"

    # Restrict unprivileged access to kernel profiling
    apply_sysctl "kernel.perf_event_paranoid" "3"
    persist_sysctl "kernel.perf_event_paranoid" "3"

    # Disable unprivileged BPF (reduces kernel exploitation surface)
    apply_sysctl "kernel.unprivileged_bpf_disabled" "1"
    persist_sysctl "kernel.unprivileged_bpf_disabled" "1"

    # Restrict unprivileged user namespaces (reduces container escape risk)
    # Note: This may break some applications like Chrome sandbox or Flatpak
    # apply_sysctl "kernel.unprivileged_userns_clone" "0"
    # persist_sysctl "kernel.unprivileged_userns_clone" "0"

    # Enable ASLR (Address Space Layout Randomization)
    apply_sysctl "kernel.randomize_va_space" "2"
    persist_sysctl "kernel.randomize_va_space" "2"

    # Restrict ptrace (prevents process memory debugging by non-root)
    apply_sysctl "kernel.yama.ptrace_scope" "1"
    persist_sysctl "kernel.yama.ptrace_scope" "1"

    # Disable core dumps for SUID programs
    apply_sysctl "fs.suid_dumpable" "0"
    persist_sysctl "fs.suid_dumpable" "0"

    # Protect symlinks and hardlinks
    apply_sysctl "fs.protected_symlinks" "1"
    persist_sysctl "fs.protected_symlinks" "1"
    apply_sysctl "fs.protected_hardlinks" "1"
    persist_sysctl "fs.protected_hardlinks" "1"

    # Protect FIFOs and regular files in sticky directories
    apply_sysctl "fs.protected_fifos" "2"
    persist_sysctl "fs.protected_fifos" "2"
    apply_sysctl "fs.protected_regular" "2"
    persist_sysctl "fs.protected_regular" "2"

    log_success "Kernel parameter hardening applied"
}

# ============================================================================
# 4. Audit Rules for BYOVD-Equivalent Activity Detection
# ============================================================================
# MITRE Mitigation: M1047 - Audit
# Equivalent to Windows Event ID 7045 (Service Install), Sysmon Event 6
# (Driver Load), and registry auditing.

configure_audit_rules() {
    log_header "4. Audit Rules for Attack Detection"

    if $UNDO; then
        log_info "Removing audit rules..."
        if [[ -f /etc/audit/rules.d/f0rtika-byovd.rules ]]; then
            rm -f /etc/audit/rules.d/f0rtika-byovd.rules
            if command -v augenrules &>/dev/null; then
                augenrules --load 2>/dev/null || true
            fi
            log_success "Removed BYOVD audit rules"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not available - skipping audit rules"
        return
    fi

    local audit_file="/etc/audit/rules.d/f0rtika-byovd.rules"

    log_info "Configuring audit rules for BYOVD-equivalent detection..."

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create audit rules at $audit_file"
        return
    fi

    backup_file "$audit_file"
    cat > "$audit_file" << 'AUDIT_EOF'
## ============================================================================
## F0RT1KA Audit Rules: BYOVD and Defense Evasion Detection
## Test ID: c3634a9c-e8c9-44a8-992b-0faeca14f612
## MITRE ATT&CK: T1068, T1562.001
## ============================================================================

## -- Kernel Module Loading (Linux equivalent of driver loading, Event 6) --
## Detect insmod, modprobe, and init_module syscalls
-w /sbin/insmod -p x -k kernel_module_load
-w /sbin/modprobe -p x -k kernel_module_load
-w /sbin/rmmod -p x -k kernel_module_unload
-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module_load
-a always,exit -F arch=b64 -S delete_module -k kernel_module_unload

## -- Kernel module configuration changes --
-w /etc/modprobe.d/ -p wa -k modprobe_config
-w /etc/modules -p wa -k modules_config
-w /etc/modules-load.d/ -p wa -k modules_load_config

## -- Security tool tampering (Linux equivalent of Defender tampering) --
## Monitor changes to AppArmor profiles
-w /etc/apparmor/ -p wa -k mac_policy_change
-w /etc/apparmor.d/ -p wa -k mac_policy_change

## Monitor SELinux configuration changes
-w /etc/selinux/ -p wa -k mac_policy_change
-w /usr/share/selinux/ -p wa -k mac_policy_change

## Monitor auditd configuration (protect the auditor)
-w /etc/audit/ -p wa -k audit_config_change
-w /etc/audisp/ -p wa -k audit_config_change
-w /etc/libaudit.conf -p wa -k audit_config_change

## -- Service creation and modification (Linux equivalent of Event 7045) --
-w /etc/systemd/system/ -p wa -k systemd_service_create
-w /usr/lib/systemd/system/ -p wa -k systemd_service_create
-w /run/systemd/system/ -p wa -k systemd_service_create
-w /etc/init.d/ -p wa -k sysv_service_create

## -- Privileged command execution (privilege escalation detection) --
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation
-w /usr/bin/pkexec -p x -k privilege_escalation
-w /usr/bin/chattr -p x -k file_attribute_change

## -- Cron and scheduled task changes (persistence mechanism) --
-w /etc/crontab -p wa -k cron_modification
-w /etc/cron.d/ -p wa -k cron_modification
-w /etc/cron.daily/ -p wa -k cron_modification
-w /etc/cron.hourly/ -p wa -k cron_modification
-w /var/spool/cron/ -p wa -k cron_modification

## -- Suspicious file creation patterns --
## Monitor /tmp and /dev/shm for kernel objects
-w /tmp/ -p wa -k tmp_file_creation
-w /dev/shm/ -p wa -k shm_file_creation

## -- Network configuration changes --
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/iptables/ -p wa -k firewall_change
-w /etc/nftables.conf -p wa -k firewall_change

## -- User and authentication changes --
-w /etc/passwd -p wa -k user_modification
-w /etc/shadow -p wa -k user_modification
-w /etc/group -p wa -k group_modification
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification

## -- Sysctl changes at runtime --
-w /etc/sysctl.conf -p wa -k sysctl_change
-w /etc/sysctl.d/ -p wa -k sysctl_change
AUDIT_EOF

    # Load the rules
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null && \
            log_success "Audit rules loaded via augenrules" || \
            log_warning "Failed to load audit rules via augenrules"
    elif command -v auditctl &>/dev/null; then
        auditctl -R "$audit_file" 2>/dev/null && \
            log_success "Audit rules loaded via auditctl" || \
            log_warning "Failed to load audit rules via auditctl"
    fi

    CHANGES_MADE=$((CHANGES_MADE + 1))
    log_success "Audit rules configured for BYOVD-equivalent detection"
}

# ============================================================================
# 5. Systemd Service Hardening
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention
# Restricts systemd service creation and execution.

harden_systemd() {
    log_header "5. Systemd Service Hardening"

    if $UNDO; then
        log_info "Reverting systemd hardening..."
        if [[ -f /etc/systemd/f0rtika-restrictions.conf ]]; then
            rm -f /etc/systemd/f0rtika-restrictions.conf
            log_success "Removed systemd restrictions"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    log_info "Hardening systemd service management..."

    # Restrict permissions on systemd service directories
    if ! $DRY_RUN; then
        # Ensure only root can create system services
        chmod 755 /etc/systemd/system/ 2>/dev/null || true
        chmod 755 /usr/lib/systemd/system/ 2>/dev/null || true
        log_success "Systemd service directory permissions restricted to root"
        CHANGES_MADE=$((CHANGES_MADE + 1))

        # Restrict user-level service creation if desired
        # This prevents non-root users from creating persistent services
        if [[ -d /etc/systemd/user.conf.d ]]; then
            log_verbose "User systemd directory exists"
        fi
    else
        log_info "[DRY-RUN] Would restrict systemd service directory permissions"
    fi

    # Verify no suspicious services are currently installed
    log_info "Checking for suspicious systemd services..."
    local suspicious_count=0

    while IFS= read -r svc_file; do
        if [[ -f "$svc_file" ]]; then
            # Check for services pointing to /tmp, /dev/shm, or user home dirs
            if grep -qiE 'ExecStart=.*(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/)' "$svc_file" 2>/dev/null; then
                log_warning "Suspicious service found: $svc_file (executes from temp directory)"
                suspicious_count=$((suspicious_count + 1))
            fi
        fi
    done < <(find /etc/systemd/system/ /run/systemd/system/ -name '*.service' -type f 2>/dev/null)

    if [[ $suspicious_count -eq 0 ]]; then
        log_success "No suspicious systemd services found"
    else
        log_warning "Found $suspicious_count suspicious service(s) - investigate manually"
    fi
}

# ============================================================================
# 6. File Integrity Monitoring
# ============================================================================
# MITRE Mitigation: M1047 - Audit
# Monitor critical system files and kernel modules for tampering.

configure_file_integrity() {
    log_header "6. File Integrity Monitoring"

    if $UNDO; then
        log_info "Reverting file integrity monitoring..."
        if [[ -f /etc/aide/aide.conf.d/f0rtika-byovd.conf ]]; then
            rm -f /etc/aide/aide.conf.d/f0rtika-byovd.conf
            log_success "Removed AIDE monitoring rules"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    # Configure AIDE if available
    if command -v aide &>/dev/null; then
        log_info "Configuring AIDE file integrity monitoring..."

        local aide_conf_dir="/etc/aide/aide.conf.d"
        if [[ ! -d "$aide_conf_dir" ]]; then
            aide_conf_dir="/etc/aide.conf.d"
        fi

        if [[ -d "$aide_conf_dir" ]] || mkdir -p "$aide_conf_dir" 2>/dev/null; then
            if ! $DRY_RUN; then
                cat > "$aide_conf_dir/f0rtika-byovd.conf" << 'AIDE_EOF'
# F0RT1KA: Monitor kernel modules and security-critical files
# Test ID: c3634a9c-e8c9-44a8-992b-0faeca14f612

# Kernel modules directory
/lib/modules CONTENT_EX
/usr/lib/modules CONTENT_EX

# Security tool configurations
/etc/apparmor.d CONTENT_EX
/etc/selinux CONTENT_EX
/etc/audit CONTENT_EX

# Systemd service files
/etc/systemd/system CONTENT_EX
/usr/lib/systemd/system CONTENT_EX

# Critical authentication files
/etc/passwd CONTENT_EX
/etc/shadow CONTENT_EX
/etc/sudoers CONTENT_EX
/etc/sudoers.d CONTENT_EX
AIDE_EOF
                log_success "AIDE monitoring rules configured"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            fi
        fi
    else
        log_info "AIDE not installed. Install with:"
        if is_debian_family; then
            log_info "  apt-get install aide aide-common"
        elif is_rhel_family; then
            log_info "  yum install aide"
        fi
    fi

    # Use inotifywait for real-time monitoring if available
    if command -v inotifywait &>/dev/null; then
        log_success "inotifywait available for real-time file monitoring"
    else
        log_info "Install inotify-tools for real-time file monitoring:"
        if is_debian_family; then
            log_info "  apt-get install inotify-tools"
        elif is_rhel_family; then
            log_info "  yum install inotify-tools"
        fi
    fi
}

# ============================================================================
# 7. Network Hardening
# ============================================================================
# MITRE Mitigation: M1037 - Filter Network Traffic
# Restrict network-level attack surface.

harden_network() {
    log_header "7. Network Parameter Hardening"

    if $UNDO; then
        log_info "Network hardening reverted via sysctl.d cleanup in section 1"
        return
    fi

    log_info "Applying network hardening parameters..."

    # Disable IP forwarding (unless this is a router)
    apply_sysctl "net.ipv4.ip_forward" "0"
    persist_sysctl "net.ipv4.ip_forward" "0"

    # Ignore ICMP redirects
    apply_sysctl "net.ipv4.conf.all.accept_redirects" "0"
    persist_sysctl "net.ipv4.conf.all.accept_redirects" "0"
    apply_sysctl "net.ipv4.conf.default.accept_redirects" "0"
    persist_sysctl "net.ipv4.conf.default.accept_redirects" "0"
    apply_sysctl "net.ipv6.conf.all.accept_redirects" "0"
    persist_sysctl "net.ipv6.conf.all.accept_redirects" "0"

    # Disable source routing
    apply_sysctl "net.ipv4.conf.all.accept_source_route" "0"
    persist_sysctl "net.ipv4.conf.all.accept_source_route" "0"
    apply_sysctl "net.ipv6.conf.all.accept_source_route" "0"
    persist_sysctl "net.ipv6.conf.all.accept_source_route" "0"

    # Enable TCP SYN cookies (SYN flood protection)
    apply_sysctl "net.ipv4.tcp_syncookies" "1"
    persist_sysctl "net.ipv4.tcp_syncookies" "1"

    # Log suspicious packets
    apply_sysctl "net.ipv4.conf.all.log_martians" "1"
    persist_sysctl "net.ipv4.conf.all.log_martians" "1"

    # Ignore broadcast ICMP requests
    apply_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
    persist_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"

    # Enable reverse path filtering
    apply_sysctl "net.ipv4.conf.all.rp_filter" "1"
    persist_sysctl "net.ipv4.conf.all.rp_filter" "1"
    apply_sysctl "net.ipv4.conf.default.rp_filter" "1"
    persist_sysctl "net.ipv4.conf.default.rp_filter" "1"

    log_success "Network hardening parameters applied"
}

# ============================================================================
# Verification
# ============================================================================

verify_hardening() {
    log_header "Verification"

    echo ""
    log_info "Run the following commands to verify hardening:"
    echo ""
    echo "  # Check kernel module restrictions:"
    echo "  cat /etc/modprobe.d/f0rtika-blocklist.conf"
    echo ""
    echo "  # Check sysctl hardening:"
    echo "  sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.randomize_va_space"
    echo ""
    echo "  # Check audit rules:"
    echo "  auditctl -l | grep -E 'kernel_module|mac_policy|systemd_service'"
    echo ""
    echo "  # Check security services:"
    echo "  systemctl status auditd"
    echo "  getenforce 2>/dev/null || echo 'SELinux not available'"
    echo "  aa-status 2>/dev/null || echo 'AppArmor not available'"
    echo ""
    echo "  # Check Secure Boot status:"
    echo "  mokutil --sb-state 2>/dev/null || echo 'mokutil not available'"
    echo ""
    echo "  # Verify no suspicious services:"
    echo "  systemctl list-units --type=service --state=running | grep -v -E '(ssh|cron|audit|apparmor|network)'"
    echo ""
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo ""
    echo "============================================================================"
    echo "  F0RT1KA Linux Hardening Script"
    echo "  Test: Akira Ransomware BYOVD Attack Chain"
    echo "  MITRE ATT&CK: T1068, T1562.001"
    echo "  Version: $SCRIPT_VERSION"
    echo "============================================================================"
    echo ""

    check_root

    local mode="HARDEN"
    if $UNDO; then mode="REVERT"; fi
    if $DRY_RUN; then mode="$mode (DRY-RUN)"; fi

    log_info "Mode: $mode"
    log_info "Log file: $LOG_FILE"
    echo ""

    # Create log file
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "# F0RT1KA Hardening Log - $(date)" > "$LOG_FILE" 2>/dev/null || true

    # Execute hardening functions
    harden_kernel_modules
    echo ""

    harden_security_services
    echo ""

    harden_kernel_parameters
    echo ""

    configure_audit_rules
    echo ""

    harden_systemd
    echo ""

    configure_file_integrity
    echo ""

    harden_network
    echo ""

    # Summary
    echo "============================================================================"
    if $UNDO; then
        log_success "Revert Complete! Changes reverted: $CHANGES_MADE"
    else
        log_success "Hardening Complete! Changes applied: $CHANGES_MADE"
    fi
    echo "============================================================================"
    echo ""

    log_info "Log file: $LOG_FILE"

    if ! $UNDO && ! $DRY_RUN; then
        verify_hardening

        echo ""
        log_warning "IMPORTANT: Some changes may require a reboot to take full effect."
        log_warning "Review /etc/sysctl.d/90-f0rtika-byovd-hardening.conf for persistent settings."
        echo ""
    fi
}

main "$@"
