#!/usr/bin/env bash
# ============================================================================
# F0RT1KA Linux Hardening Script
# ============================================================================
# Test ID:      54a0bd24-d75a-4d89-8dce-c381d932ca97
# Test Name:    Perfctl/Symbiote LD_PRELOAD Hijacking with PAM Credential Harvesting
# MITRE ATT&CK: T1574.006, T1003.008, T1548.001, T1014, T1059.004
# Mitigations:  M1038, M1028, M1022, M1047, M1050
#
# Purpose:
#   Hardens Linux endpoints against LD_PRELOAD-based rootkits (Perfctl,
#   Symbiote, Auto-Color, WolfsBane), PAM credential hooking, SUID abuse,
#   userland rootkit network hiding, and XOR-encrypted C2 configurations.
#
# Usage:
#   sudo ./54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening_linux.sh [apply|undo|check]
#
# Requires: root privileges
# Idempotent: Yes (safe to run multiple times)
# Tested on: Ubuntu 22.04/24.04, Debian 12, RHEL 9, Rocky 9
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_NAME="$(basename "$0")"
BACKUP_DIR="/var/backups/f0rtika-hardening-54a0bd24"
LOG_FILE="/var/log/f0rtika-hardening-54a0bd24.log"
CHANGE_COUNT=0

# ============================================================================
# Helper Functions
# ============================================================================

log_info()    { echo -e "\e[36m[*]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  $1" >> "$LOG_FILE"; }
log_success() { echo -e "\e[32m[+]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [OK]    $1" >> "$LOG_FILE"; }
log_warning() { echo -e "\e[33m[!]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN]  $1" >> "$LOG_FILE"; }
log_error()   { echo -e "\e[31m[-]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

ensure_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
}

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        local dest="${BACKUP_DIR}/$(basename "$src").bak.$(date '+%Y%m%d%H%M%S')"
        cp -a "$src" "$dest"
        log_info "Backed up $src -> $dest"
    fi
}

# ============================================================================
# 1. Lock Down /etc/ld.preload and /etc/ld.so.preload (T1574.006)
# ============================================================================
# Perfctl, Auto-Color, and WolfsBane persist by writing malicious library
# paths to these files. We lock them down with immutable attributes.

harden_ld_preload() {
    log_info "=== Hardening LD_PRELOAD persistence files ==="

    # Secure /etc/ld.so.preload
    if [[ -f /etc/ld.so.preload ]]; then
        backup_file /etc/ld.so.preload
        # Check if file has suspicious content
        if grep -qvE '^\s*#|^\s*$' /etc/ld.so.preload 2>/dev/null; then
            log_warning "/etc/ld.so.preload contains active entries - review before proceeding:"
            cat /etc/ld.so.preload
        fi
        chmod 644 /etc/ld.so.preload
        chown root:root /etc/ld.so.preload
        log_success "Secured /etc/ld.so.preload permissions (644, root:root)"
    else
        log_info "/etc/ld.so.preload does not exist (clean state)"
    fi

    # Secure /etc/ld.preload (less common, used by Auto-Color)
    if [[ -f /etc/ld.preload ]]; then
        backup_file /etc/ld.preload
        if grep -qvE '^\s*#|^\s*$' /etc/ld.preload 2>/dev/null; then
            log_warning "/etc/ld.preload contains active entries - review:"
            cat /etc/ld.preload
        fi
        chmod 644 /etc/ld.preload
        chown root:root /etc/ld.preload
        log_success "Secured /etc/ld.preload permissions (644, root:root)"
    fi

    # Set immutable attribute to prevent modification (even by root without chattr)
    if command -v chattr &>/dev/null; then
        for preload_file in /etc/ld.so.preload /etc/ld.preload; do
            if [[ -f "$preload_file" ]]; then
                chattr +i "$preload_file" 2>/dev/null && \
                    log_success "Set immutable flag on $preload_file" || \
                    log_warning "Failed to set immutable flag on $preload_file (filesystem may not support it)"
            fi
        done
    else
        log_warning "chattr not available - cannot set immutable flags"
    fi

    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_ld_preload() {
    log_info "=== Reverting LD_PRELOAD hardening ==="
    for preload_file in /etc/ld.so.preload /etc/ld.preload; do
        if [[ -f "$preload_file" ]]; then
            chattr -i "$preload_file" 2>/dev/null || true
            log_success "Removed immutable flag from $preload_file"
        fi
    done
}

check_ld_preload() {
    log_info "=== Checking LD_PRELOAD file status ==="
    for preload_file in /etc/ld.so.preload /etc/ld.preload; do
        if [[ -f "$preload_file" ]]; then
            local attrs
            attrs=$(lsattr "$preload_file" 2>/dev/null | cut -d' ' -f1)
            if echo "$attrs" | grep -q "i"; then
                log_success "$preload_file is immutable (protected)"
            else
                log_warning "$preload_file exists but is NOT immutable"
            fi
            if grep -qvE '^\s*#|^\s*$' "$preload_file" 2>/dev/null; then
                log_warning "$preload_file has ACTIVE entries - investigate!"
            fi
        else
            log_success "$preload_file does not exist (clean)"
        fi
    done
}

# ============================================================================
# 2. Restrict ptrace to Prevent Runtime Hooking (T1574.006, T1014)
# ============================================================================
# Symbiote and other rootkits can use ptrace to inject hooks at runtime.
# Restrict ptrace to admin-only (YAMA LSM scope=2).

harden_ptrace() {
    log_info "=== Restricting ptrace access ==="

    local sysctl_file="/etc/sysctl.d/90-f0rtika-ptrace.conf"
    local current_ptrace
    current_ptrace=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "unknown")

    if [[ "$current_ptrace" != "2" && "$current_ptrace" != "3" ]]; then
        backup_file "$sysctl_file" 2>/dev/null || true
        cat > "$sysctl_file" <<'SYSCTL_EOF'
# F0RT1KA Hardening: Restrict ptrace to prevent API hooking / rootkit injection
# MITRE ATT&CK: T1574.006 (LD_PRELOAD), T1014 (Rootkit), T1055 (Process Injection)
# Values: 0=classic, 1=restricted, 2=admin-only, 3=disabled
kernel.yama.ptrace_scope = 2
SYSCTL_EOF
        sysctl -p "$sysctl_file" 2>/dev/null
        log_success "Restricted ptrace to admin-only (scope=2), was $current_ptrace"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_success "ptrace already restricted (scope=$current_ptrace)"
    fi
}

undo_ptrace() {
    log_info "=== Reverting ptrace restriction ==="
    local sysctl_file="/etc/sysctl.d/90-f0rtika-ptrace.conf"
    if [[ -f "$sysctl_file" ]]; then
        rm -f "$sysctl_file"
        sysctl -w kernel.yama.ptrace_scope=1 2>/dev/null || true
        log_success "Reverted ptrace to restricted (scope=1)"
    fi
}

check_ptrace() {
    local current
    current=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "unknown")
    if [[ "$current" -ge 2 ]]; then
        log_success "ptrace restricted (scope=$current)"
    else
        log_warning "ptrace NOT restricted (scope=$current) - should be 2 or 3"
    fi
}

# ============================================================================
# 3. Harden /etc/shadow Permissions (T1003.008)
# ============================================================================
# Perfctl reads /etc/shadow to harvest password hashes. Ensure strict
# permissions prevent unauthorized access.

harden_shadow() {
    log_info "=== Hardening /etc/shadow permissions ==="

    local current_perms
    current_perms=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "unknown")
    local current_owner
    current_owner=$(stat -c "%U:%G" /etc/shadow 2>/dev/null || echo "unknown")

    if [[ "$current_perms" != "000" && "$current_perms" != "640" ]]; then
        chmod 640 /etc/shadow
        log_success "Set /etc/shadow permissions to 640 (was $current_perms)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_success "/etc/shadow permissions already secure ($current_perms)"
    fi

    if [[ "$current_owner" != "root:shadow" && "$current_owner" != "root:root" ]]; then
        chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow
        log_success "Set /etc/shadow ownership to root:shadow"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_success "/etc/shadow ownership already correct ($current_owner)"
    fi

    # Also harden /etc/passwd
    chmod 644 /etc/passwd
    chown root:root /etc/passwd
    log_success "Verified /etc/passwd permissions (644, root:root)"
}

undo_shadow() {
    log_info "=== Shadow file hardening uses standard permissions, no undo needed ==="
    log_success "Permissions remain at secure defaults"
}

check_shadow() {
    local perms
    perms=$(stat -c "%a" /etc/shadow 2>/dev/null)
    if [[ "$perms" == "000" || "$perms" == "640" ]]; then
        log_success "/etc/shadow permissions secure ($perms)"
    else
        log_warning "/etc/shadow permissions too open ($perms) - should be 640 or 000"
    fi
}

# ============================================================================
# 4. Remove Unnecessary SUID Bits (T1548.001)
# ============================================================================
# Perfctl exploits SUID binaries (find, vim, nmap, bash) for privilege
# escalation. Remove SUID from non-essential binaries.

harden_suid() {
    log_info "=== Auditing and removing unnecessary SUID bits ==="

    # Binaries that should NEVER have SUID in production
    local dangerous_suid=(
        /usr/bin/nmap
        /usr/bin/vim
        /usr/bin/vim.basic
        /usr/bin/vim.tiny
        /usr/bin/nano
        /usr/bin/less
        /usr/bin/awk
        /usr/bin/gawk
        /usr/bin/env
        /usr/bin/ruby
        /usr/bin/python
        /usr/bin/python3
        /usr/bin/perl
        /usr/bin/node
        /usr/bin/php
        /usr/bin/lua
    )

    for binary in "${dangerous_suid[@]}"; do
        if [[ -f "$binary" ]]; then
            local perms
            perms=$(stat -c "%a" "$binary" 2>/dev/null)
            if [[ "$perms" =~ ^4 ]] || [[ "$perms" =~ ^6 ]]; then
                backup_file "$binary"
                chmod u-s "$binary"
                log_success "Removed SUID from $binary (was $perms)"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        fi
    done

    # Report remaining SUID binaries for review
    log_info "Current SUID binaries on system:"
    find / -type f -perm -u=s 2>/dev/null | while read -r binary; do
        log_info "  SUID: $binary"
    done

    log_success "SUID audit complete"
}

undo_suid() {
    log_info "=== SUID bits cannot be safely auto-restored ==="
    log_warning "Review backed up permissions in $BACKUP_DIR and restore manually if needed"
}

check_suid() {
    log_info "=== Checking for dangerous SUID binaries ==="
    local found=0
    local dangerous_suid=(
        /usr/bin/nmap /usr/bin/vim /usr/bin/vim.basic /usr/bin/nano
        /usr/bin/less /usr/bin/env /usr/bin/python /usr/bin/python3
        /usr/bin/perl /usr/bin/ruby
    )
    for binary in "${dangerous_suid[@]}"; do
        if [[ -f "$binary" ]]; then
            local perms
            perms=$(stat -c "%a" "$binary" 2>/dev/null)
            if [[ "$perms" =~ ^4 ]] || [[ "$perms" =~ ^6 ]]; then
                log_warning "DANGEROUS: $binary has SUID bit set ($perms)"
                found=$((found + 1))
            fi
        fi
    done
    if [[ $found -eq 0 ]]; then
        log_success "No dangerous SUID binaries found"
    else
        log_warning "$found dangerous SUID binaries found - remediate immediately"
    fi
}

# ============================================================================
# 5. Deploy auditd Rules for LD_PRELOAD Monitoring (T1574.006)
# ============================================================================
# Comprehensive auditd rules to detect LD_PRELOAD attacks in real-time.

harden_auditd() {
    log_info "=== Deploying auditd rules for LD_PRELOAD monitoring ==="

    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not installed - installing..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y auditd audispd-plugins 2>/dev/null || log_warning "Failed to install auditd"
        elif command -v yum &>/dev/null; then
            yum install -y audit audit-libs 2>/dev/null || log_warning "Failed to install auditd"
        fi
    fi

    local audit_rules_file="/etc/audit/rules.d/90-f0rtika-ldpreload.rules"
    backup_file "$audit_rules_file" 2>/dev/null || true

    cat > "$audit_rules_file" <<'AUDIT_EOF'
## F0RT1KA auditd rules - LD_PRELOAD hijacking detection
## MITRE ATT&CK: T1574.006, T1003.008, T1548.001, T1014, T1059.004
## Test ID: 54a0bd24-d75a-4d89-8dce-c381d932ca97

## LD_PRELOAD persistence file writes
-w /etc/ld.so.preload -p wa -k ld_preload_persistence
-w /etc/ld.preload -p wa -k ld_preload_persistence

## Dynamic linker configuration changes
-w /etc/ld.so.conf -p wa -k ld_config_change
-w /etc/ld.so.conf.d/ -p wa -k ld_config_change

## PAM module directory modifications
-w /etc/pam.d/ -p wa -k pam_module_change
-w /lib/security/ -p wa -k pam_module_change
-w /lib/x86_64-linux-gnu/security/ -p wa -k pam_module_change
-w /lib64/security/ -p wa -k pam_module_change

## Credential file access
-w /etc/shadow -p r -k shadow_access
-w /etc/passwd -p wa -k passwd_change
-w /etc/gshadow -p r -k gshadow_access

## Systemd service creation/modification
-w /etc/systemd/system/ -p wa -k systemd_service_change
-w /lib/systemd/system/ -p wa -k systemd_service_change
-w /usr/lib/systemd/system/ -p wa -k systemd_service_change

## Shell profile modifications
-w /etc/profile -p wa -k profile_change
-w /etc/profile.d/ -p wa -k profile_change

## Crontab binary integrity
-w /usr/bin/crontab -p wa -k crontab_integrity

## SUID/SGID changes (chmod with setuid)
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F a2&04000 -k suid_change
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F a2&04000 -k suid_change

## Monitor find command for SUID enumeration
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/find -k suid_enumeration
AUDIT_EOF

    # Reload auditd rules
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null || auditctl -R "$audit_rules_file" 2>/dev/null || true
    elif command -v auditctl &>/dev/null; then
        auditctl -R "$audit_rules_file" 2>/dev/null || true
    fi

    log_success "Deployed 15+ auditd rules for LD_PRELOAD attack chain monitoring"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_auditd() {
    log_info "=== Removing F0RT1KA auditd rules ==="
    local audit_rules_file="/etc/audit/rules.d/90-f0rtika-ldpreload.rules"
    if [[ -f "$audit_rules_file" ]]; then
        rm -f "$audit_rules_file"
        augenrules --load 2>/dev/null || true
        log_success "Removed LD_PRELOAD auditd rules"
    fi
}

check_auditd() {
    local rules_file="/etc/audit/rules.d/90-f0rtika-ldpreload.rules"
    if [[ -f "$rules_file" ]]; then
        local rule_count
        rule_count=$(grep -c "^-" "$rules_file" 2>/dev/null || echo "0")
        log_success "F0RT1KA auditd rules deployed ($rule_count rules)"
    else
        log_warning "F0RT1KA auditd rules NOT deployed"
    fi
    if command -v auditctl &>/dev/null; then
        local active_rules
        active_rules=$(auditctl -l 2>/dev/null | grep -c "ld_preload\|pam_module\|shadow_access\|suid_change" || echo "0")
        log_info "Active LD_PRELOAD-related audit rules: $active_rules"
    fi
}

# ============================================================================
# 6. Harden Shared Library Directories (T1574.006)
# ============================================================================
# Prevent unauthorized .so file drops in system library directories.

harden_lib_dirs() {
    log_info "=== Hardening shared library directory permissions ==="

    local lib_dirs=(
        /lib
        /lib64
        /usr/lib
        /usr/lib64
        /usr/local/lib
    )

    for dir in "${lib_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local current_perms
            current_perms=$(stat -c "%a" "$dir" 2>/dev/null)
            local current_owner
            current_owner=$(stat -c "%U:%G" "$dir" 2>/dev/null)

            if [[ "$current_owner" != "root:root" ]]; then
                chown root:root "$dir"
                log_success "Set $dir ownership to root:root (was $current_owner)"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi

            # Ensure only root can write to library directories
            if [[ "${current_perms:1:1}" =~ [2367] ]] || [[ "${current_perms:2:1}" =~ [2367] ]]; then
                chmod 755 "$dir"
                log_success "Secured $dir permissions to 755 (was $current_perms)"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        fi
    done

    # Harden /dev/shm against .so drops (common staging area)
    if [[ -d /dev/shm ]]; then
        log_info "Checking /dev/shm mount options..."
        if mount | grep -q "shm.*noexec"; then
            log_success "/dev/shm already mounted with noexec"
        else
            log_warning "/dev/shm does NOT have noexec - consider adding 'noexec,nosuid,nodev' to fstab"
        fi
    fi
}

undo_lib_dirs() {
    log_info "=== Library directory hardening uses standard permissions, no undo needed ==="
}

check_lib_dirs() {
    log_info "=== Checking library directory permissions ==="
    for dir in /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib; do
        if [[ -d "$dir" ]]; then
            local perms owner
            perms=$(stat -c "%a" "$dir" 2>/dev/null)
            owner=$(stat -c "%U:%G" "$dir" 2>/dev/null)
            if [[ "$owner" == "root:root" ]] && ! [[ "${perms:2:1}" =~ [2367] ]]; then
                log_success "$dir secure (perms=$perms, owner=$owner)"
            else
                log_warning "$dir may be insecure (perms=$perms, owner=$owner)"
            fi
        fi
    done
}

# ============================================================================
# 7. Enable File Integrity Monitoring (T1014, T1574.006)
# ============================================================================
# Deploy AIDE or similar for detecting rootkit modifications.

harden_fim() {
    log_info "=== Configuring file integrity monitoring ==="

    if command -v aide &>/dev/null; then
        local aide_extra="/etc/aide/aide.conf.d/90-f0rtika-ldpreload.conf"
        mkdir -p "$(dirname "$aide_extra")" 2>/dev/null || true

        cat > "$aide_extra" <<'AIDE_EOF'
# F0RT1KA AIDE rules - LD_PRELOAD attack detection
# Monitors critical files modified by Perfctl/Symbiote/Auto-Color/WolfsBane

# LD_PRELOAD persistence files
/etc/ld.preload CONTENT_EX
/etc/ld.so.preload CONTENT_EX
/etc/ld.so.conf CONTENT_EX

# PAM modules
/etc/pam.d CONTENT_EX
/lib/security CONTENT_EX
/lib/x86_64-linux-gnu/security CONTENT_EX

# Shadow and passwd files
/etc/shadow PERMS
/etc/passwd CONTENT_EX
/etc/gshadow PERMS

# System binaries (detect trojanized crontab)
/usr/bin/crontab CONTENT_EX
/usr/sbin/crontab CONTENT_EX

# Systemd service directories
/etc/systemd/system CONTENT_EX
/lib/systemd/system CONTENT_EX
AIDE_EOF

        log_success "Deployed AIDE configuration for LD_PRELOAD monitoring"
        log_info "Run 'aide --init' then 'cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db' to initialize"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_warning "AIDE not installed - consider: apt install aide"
        log_info "Alternative: use osquery, Wazuh, or Tripwire for FIM"
    fi
}

undo_fim() {
    local aide_extra="/etc/aide/aide.conf.d/90-f0rtika-ldpreload.conf"
    if [[ -f "$aide_extra" ]]; then
        rm -f "$aide_extra"
        log_success "Removed AIDE LD_PRELOAD monitoring configuration"
    fi
}

check_fim() {
    if command -v aide &>/dev/null; then
        local aide_extra="/etc/aide/aide.conf.d/90-f0rtika-ldpreload.conf"
        if [[ -f "$aide_extra" ]]; then
            log_success "AIDE LD_PRELOAD monitoring configuration deployed"
        else
            log_warning "AIDE installed but F0RT1KA rules not deployed"
        fi
    else
        log_warning "No file integrity monitoring (AIDE) installed"
    fi
}

# ============================================================================
# 8. Restrict Crontab Access (T1059.004)
# ============================================================================
# Prevent unauthorized crontab modifications used by Perfctl for persistence.

harden_crontab() {
    log_info "=== Hardening crontab access controls ==="

    # Restrict who can use crontab
    if [[ ! -f /etc/cron.allow ]]; then
        echo "root" > /etc/cron.allow
        chmod 600 /etc/cron.allow
        chown root:root /etc/cron.allow
        log_success "Created /etc/cron.allow (root only)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_success "/etc/cron.allow already exists"
    fi

    # Verify crontab binary integrity
    if command -v dpkg &>/dev/null; then
        local crontab_check
        crontab_check=$(dpkg -V cron 2>/dev/null | grep crontab || echo "")
        if [[ -n "$crontab_check" ]]; then
            log_warning "ALERT: crontab binary integrity check FAILED - possible trojanization!"
            log_warning "Details: $crontab_check"
        else
            log_success "crontab binary integrity verified via dpkg"
        fi
    elif command -v rpm &>/dev/null; then
        local crontab_check
        crontab_check=$(rpm -V cronie 2>/dev/null | grep crontab || echo "")
        if [[ -n "$crontab_check" ]]; then
            log_warning "ALERT: crontab binary integrity check FAILED!"
        else
            log_success "crontab binary integrity verified via rpm"
        fi
    fi

    # Harden cron spool directories
    chmod 700 /var/spool/cron 2>/dev/null || true
    chmod 700 /var/spool/cron/crontabs 2>/dev/null || true
    log_success "Hardened cron spool directory permissions"
}

undo_crontab() {
    if [[ -f /etc/cron.allow ]]; then
        rm -f /etc/cron.allow
        log_success "Removed /etc/cron.allow restriction"
    fi
}

check_crontab() {
    if [[ -f /etc/cron.allow ]]; then
        local users
        users=$(wc -l < /etc/cron.allow)
        log_success "/etc/cron.allow present ($users users)"
    else
        log_warning "/etc/cron.allow not present - all users can use crontab"
    fi
}

# ============================================================================
# 9. Network Connection Monitoring (T1014)
# ============================================================================
# Deploy eBPF-based monitoring to detect rootkit network hiding.

harden_network_monitoring() {
    log_info "=== Configuring network connection monitoring ==="

    # Create a cron job that compares ss and /proc/net/tcp to detect hiding
    local monitor_script="/usr/local/bin/f0rtika-rootkit-detect.sh"
    cat > "$monitor_script" <<'MONITOR_EOF'
#!/bin/bash
# F0RT1KA rootkit network hiding detector
# Compares /proc/net/tcp entries with conntrack for discrepancies

PROC_COUNT=$(wc -l < /proc/net/tcp 2>/dev/null || echo 0)
SS_COUNT=$(ss -tun 2>/dev/null | wc -l || echo 0)

# Large discrepancy may indicate rootkit
if [[ $((SS_COUNT - PROC_COUNT)) -gt 5 ]] || [[ $((PROC_COUNT - SS_COUNT)) -gt 5 ]]; then
    logger -p auth.crit -t "f0rtika-rootkit" "ALERT: Network connection count discrepancy detected (proc=$PROC_COUNT, ss=$SS_COUNT) - possible userland rootkit"
fi

# Check for hidden connections via conntrack if available
if command -v conntrack &>/dev/null; then
    CONNTRACK_COUNT=$(conntrack -C 2>/dev/null || echo 0)
    if [[ $((CONNTRACK_COUNT - SS_COUNT)) -gt 10 ]]; then
        logger -p auth.crit -t "f0rtika-rootkit" "ALERT: conntrack shows $CONNTRACK_COUNT connections but ss shows $SS_COUNT - rootkit may be hiding connections"
    fi
fi
MONITOR_EOF

    chmod 700 "$monitor_script"
    chown root:root "$monitor_script"

    # Add to cron (every 5 minutes)
    local cron_entry="*/5 * * * * $monitor_script"
    if ! crontab -l 2>/dev/null | grep -qF "$monitor_script"; then
        (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
        log_success "Deployed rootkit network hiding detection (runs every 5 minutes)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_success "Rootkit detection cron already deployed"
    fi
}

undo_network_monitoring() {
    local monitor_script="/usr/local/bin/f0rtika-rootkit-detect.sh"
    crontab -l 2>/dev/null | grep -vF "$monitor_script" | crontab - 2>/dev/null || true
    rm -f "$monitor_script"
    log_success "Removed rootkit network detection monitoring"
}

check_network_monitoring() {
    local monitor_script="/usr/local/bin/f0rtika-rootkit-detect.sh"
    if [[ -f "$monitor_script" ]]; then
        log_success "Rootkit network detection script deployed"
    else
        log_warning "Rootkit network detection NOT deployed"
    fi
}

# ============================================================================
# 10. Block Mining Pool Connections (T1059.004)
# ============================================================================
# Block outbound connections to known cryptomining pools used by Perfctl.

harden_mining_block() {
    log_info "=== Blocking known mining pool connections ==="

    if command -v iptables &>/dev/null; then
        local mining_domains=(
            "supportxmr.com"
            "xmrpool.eu"
            "pool.minexmr.com"
            "pool.hashvault.pro"
            "mine.c3pool.com"
            "rx.unmineable.com"
        )

        for domain in "${mining_domains[@]}"; do
            # Add iptables rule to block (idempotent - check first)
            if ! iptables -C OUTPUT -m string --string "$domain" --algo bm -j DROP 2>/dev/null; then
                iptables -A OUTPUT -m string --string "$domain" --algo bm -j DROP 2>/dev/null || true
                log_success "Blocked outbound connections to $domain"
            fi
        done

        # Block known Perfctl C2 IPs
        local c2_ips=("185.141.27.0/24" "91.215.85.0/24" "45.77.65.0/24")
        for ip in "${c2_ips[@]}"; do
            if ! iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null; then
                iptables -A OUTPUT -d "$ip" -j DROP 2>/dev/null || true
                log_success "Blocked outbound to known C2 range: $ip"
            fi
        done

        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_warning "iptables not available - consider using nftables or firewalld"
    fi
}

undo_mining_block() {
    log_info "=== Removing mining pool blocks ==="
    if command -v iptables &>/dev/null; then
        iptables -S OUTPUT 2>/dev/null | grep "f0rtika\|supportxmr\|xmrpool\|minexmr\|hashvault\|c3pool\|unmineable\|185.141.27\|91.215.85\|45.77.65" | while read -r rule; do
            iptables $(echo "$rule" | sed 's/-A/-D/') 2>/dev/null || true
        done
        log_success "Removed mining pool iptables rules"
    fi
}

check_mining_block() {
    if command -v iptables &>/dev/null; then
        local rules
        rules=$(iptables -S OUTPUT 2>/dev/null | grep -c "supportxmr\|xmrpool\|minexmr\|hashvault\|185.141.27\|91.215.85" || echo "0")
        if [[ "$rules" -gt 0 ]]; then
            log_success "Mining pool blocking rules active ($rules rules)"
        else
            log_warning "No mining pool blocking rules found"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    local action="${1:-apply}"

    check_root
    ensure_backup_dir

    echo ""
    log_info "============================================================"
    log_info "F0RT1KA Linux Hardening Script"
    log_info "Test: Perfctl/Symbiote LD_PRELOAD Hijacking"
    log_info "ID: 54a0bd24-d75a-4d89-8dce-c381d932ca97"
    log_info "Action: $action"
    log_info "============================================================"
    echo ""

    case "$action" in
        apply)
            harden_ld_preload
            harden_ptrace
            harden_shadow
            harden_suid
            harden_auditd
            harden_lib_dirs
            harden_fim
            harden_crontab
            harden_network_monitoring
            harden_mining_block
            echo ""
            log_info "============================================================"
            log_success "Hardening COMPLETE. $CHANGE_COUNT changes applied."
            log_info "Backups saved to: $BACKUP_DIR"
            log_info "Log file: $LOG_FILE"
            log_info "============================================================"
            ;;
        undo)
            undo_ld_preload
            undo_ptrace
            undo_shadow
            undo_suid
            undo_auditd
            undo_fim
            undo_crontab
            undo_network_monitoring
            undo_mining_block
            echo ""
            log_warning "Hardening REVERTED. Review system security posture."
            ;;
        check)
            check_ld_preload
            check_ptrace
            check_shadow
            check_suid
            check_auditd
            check_lib_dirs
            check_fim
            check_crontab
            check_network_monitoring
            check_mining_block
            echo ""
            log_info "============================================================"
            log_info "Security posture check complete."
            log_info "============================================================"
            ;;
        *)
            log_error "Usage: $SCRIPT_NAME [apply|undo|check]"
            exit 1
            ;;
    esac
}

main "$@"
