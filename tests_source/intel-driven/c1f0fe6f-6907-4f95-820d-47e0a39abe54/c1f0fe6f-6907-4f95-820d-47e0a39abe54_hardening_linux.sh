#!/usr/bin/env bash
# ============================================================================
# F0RT1KA Linux Hardening Script
# ============================================================================
# Test ID:      c1f0fe6f-6907-4f95-820d-47e0a39abe54
# Test Name:    TrollDisappearKey AMSI Bypass Detection
# MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
# Related:      T1055, T1112, T1105, T1620
# Mitigations:  M1038 (Execution Prevention), M1024 (Restrict Registry Perms)
#
# Purpose:
#   While the TrollDisappearKey attack targets Windows AMSI, the underlying
#   techniques -- API hooking via LD_PRELOAD/ptrace, security framework
#   disablement, remote tool download, and reflective code loading -- have
#   direct Linux equivalents. This script hardens Linux endpoints against
#   the same class of defense evasion attacks.
#
# Usage:
#   sudo ./c1f0fe6f-6907-4f95-820d-47e0a39abe54_hardening_linux.sh [apply|undo|check]
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
BACKUP_DIR="/var/backups/f0rtika-hardening-c1f0fe6f"
LOG_FILE="/var/log/f0rtika-hardening-c1f0fe6f.log"
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
# 1. Restrict LD_PRELOAD Abuse (Linux equivalent of API hooking)
# ============================================================================
# TrollDisappearKey hooks RegOpenKeyExW via inline patching. On Linux, the
# equivalent technique uses LD_PRELOAD to inject shared libraries that
# intercept libc functions. Restricting LD_PRELOAD prevents this class of
# attacks.

harden_ld_preload() {
    log_info "Hardening LD_PRELOAD restrictions..."

    # Ensure /etc/ld.so.preload is not writable by non-root
    if [[ -f /etc/ld.so.preload ]]; then
        backup_file /etc/ld.so.preload
        chmod 644 /etc/ld.so.preload
        chown root:root /etc/ld.so.preload
        log_success "Secured /etc/ld.so.preload permissions (644, root:root)"
    else
        log_info "/etc/ld.so.preload does not exist (clean state)"
    fi

    # Restrict ptrace to prevent runtime hooking (YAMA LSM)
    local sysctl_file="/etc/sysctl.d/90-f0rtika-ptrace.conf"
    local current_ptrace
    current_ptrace=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "unknown")

    if [[ "$current_ptrace" != "2" && "$current_ptrace" != "3" ]]; then
        backup_file "$sysctl_file" 2>/dev/null || true
        cat > "$sysctl_file" <<'SYSCTL_EOF'
# F0RT1KA Hardening: Restrict ptrace to prevent API hooking
# MITRE ATT&CK: T1055 (Process Injection), T1562.001 (Impair Defenses)
# Values: 0=classic, 1=restricted, 2=admin-only, 3=disabled
# Setting to 2: only processes with CAP_SYS_PTRACE can ptrace
kernel.yama.ptrace_scope = 2
SYSCTL_EOF
        sysctl -p "$sysctl_file" > /dev/null 2>&1
        log_success "Set kernel.yama.ptrace_scope=2 (admin-only ptrace)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "ptrace_scope already restricted ($current_ptrace)"
    fi
}

undo_ld_preload() {
    log_warning "Reverting LD_PRELOAD restrictions..."
    local sysctl_file="/etc/sysctl.d/90-f0rtika-ptrace.conf"
    if [[ -f "$sysctl_file" ]]; then
        rm -f "$sysctl_file"
        # Restore default
        sysctl -w kernel.yama.ptrace_scope=1 > /dev/null 2>&1 || true
        log_success "Removed ptrace restriction (restored to scope=1)"
    fi
}

check_ld_preload() {
    local ptrace_scope
    ptrace_scope=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "unknown")
    if [[ "$ptrace_scope" -ge 2 ]]; then
        log_success "ptrace_scope=$ptrace_scope (restricted)"
    else
        log_warning "ptrace_scope=$ptrace_scope (not sufficiently restricted, recommend >=2)"
    fi
}

# ============================================================================
# 2. Enable Comprehensive Audit Logging (Linux equivalent of AMSI logging)
# ============================================================================
# AMSI provides visibility into script and assembly execution on Windows.
# On Linux, auditd provides equivalent visibility into process execution,
# library loading, and ptrace operations.

harden_audit_logging() {
    log_info "Configuring auditd rules for defense evasion detection..."

    # Ensure auditd is installed and running
    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not installed. Attempting to install..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y auditd audispd-plugins > /dev/null 2>&1 || true
        elif command -v dnf &>/dev/null; then
            dnf install -y audit > /dev/null 2>&1 || true
        elif command -v yum &>/dev/null; then
            yum install -y audit > /dev/null 2>&1 || true
        fi
    fi

    if ! command -v auditctl &>/dev/null; then
        log_error "auditd could not be installed. Skipping audit rules."
        return
    fi

    local audit_rules_file="/etc/audit/rules.d/90-f0rtika-defense-evasion.rules"
    backup_file "$audit_rules_file" 2>/dev/null || true

    cat > "$audit_rules_file" <<'AUDIT_EOF'
## F0RT1KA Hardening: Defense Evasion Detection Audit Rules
## Test ID: c1f0fe6f-6907-4f95-820d-47e0a39abe54
## MITRE ATT&CK: T1562.001, T1055, T1105, T1620

# Monitor LD_PRELOAD modifications (API hooking equivalent)
-w /etc/ld.so.preload -p wa -k f0rtika_ld_preload_tamper
-w /etc/ld.so.conf -p wa -k f0rtika_ld_config_tamper
-w /etc/ld.so.conf.d/ -p wa -k f0rtika_ld_config_tamper

# Monitor ptrace calls (runtime hooking / injection)
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k f0rtika_ptrace_attach
-a always,exit -F arch=b64 -S ptrace -F a0=0x10 -k f0rtika_ptrace_attach
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k f0rtika_ptrace_attach

# Monitor process_vm_writev (cross-process memory writes)
-a always,exit -F arch=b64 -S process_vm_writev -k f0rtika_process_mem_write

# Monitor security framework configuration changes
-w /etc/apparmor/ -p wa -k f0rtika_security_framework_tamper
-w /etc/apparmor.d/ -p wa -k f0rtika_security_framework_tamper
-w /etc/selinux/ -p wa -k f0rtika_security_framework_tamper
-w /etc/selinux/config -p wa -k f0rtika_security_framework_tamper

# Monitor download tools execution (ingress tool transfer)
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/wget -k f0rtika_tool_download
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -k f0rtika_tool_download
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/python3 -k f0rtika_scripting_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/python -k f0rtika_scripting_exec

# Monitor .NET / Mono runtime execution (reflective code loading equivalent)
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/dotnet -k f0rtika_dotnet_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/mono -k f0rtika_dotnet_exec

# Monitor memfd_create (in-memory file execution without touching disk)
-a always,exit -F arch=b64 -S memfd_create -k f0rtika_memfd_create

# Monitor mprotect with executable pages (inline hooking)
-a always,exit -F arch=b64 -S mprotect -F a2&0x4 -k f0rtika_mprotect_exec
AUDIT_EOF

    # Reload audit rules
    augenrules --load > /dev/null 2>&1 || auditctl -R "$audit_rules_file" > /dev/null 2>&1 || true
    systemctl enable auditd > /dev/null 2>&1 || true
    systemctl start auditd > /dev/null 2>&1 || true

    log_success "Audit rules installed at $audit_rules_file"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_audit_logging() {
    log_warning "Removing F0RT1KA audit rules..."
    local audit_rules_file="/etc/audit/rules.d/90-f0rtika-defense-evasion.rules"
    if [[ -f "$audit_rules_file" ]]; then
        rm -f "$audit_rules_file"
        augenrules --load > /dev/null 2>&1 || true
        log_success "Removed audit rules"
    else
        log_info "No F0RT1KA audit rules found"
    fi
}

check_audit_logging() {
    if [[ -f "/etc/audit/rules.d/90-f0rtika-defense-evasion.rules" ]]; then
        local rule_count
        rule_count=$(grep -c '^-' /etc/audit/rules.d/90-f0rtika-defense-evasion.rules 2>/dev/null || echo "0")
        log_success "F0RT1KA audit rules present ($rule_count rules)"
    else
        log_warning "F0RT1KA audit rules not installed"
    fi

    if systemctl is-active auditd > /dev/null 2>&1; then
        log_success "auditd is running"
    else
        log_warning "auditd is not running"
    fi
}

# ============================================================================
# 3. Restrict Unauthorized Downloads (Ingress Tool Transfer prevention)
# ============================================================================
# TrollDisappearKey downloads Seatbelt.exe from GitHub. On Linux, equivalent
# attacks download payloads via curl/wget/python. This section configures
# firewall rules and restricts download tools for non-privileged users.

harden_download_controls() {
    log_info "Configuring download controls..."

    # Restrict curl/wget execution to specific groups
    local restricted_changed=false

    for tool in /usr/bin/curl /usr/bin/wget; do
        if [[ -f "$tool" ]]; then
            local current_perms
            current_perms=$(stat -c '%a' "$tool" 2>/dev/null || echo "unknown")
            if [[ "$current_perms" != "750" ]]; then
                backup_file "$tool"
                # Allow root and sudo group only
                chmod 750 "$tool"
                chown root:sudo "$tool" 2>/dev/null || chown root:wheel "$tool" 2>/dev/null || true
                log_success "Restricted $tool to root/sudo group (was $current_perms)"
                restricted_changed=true
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            else
                log_info "$tool already restricted (750)"
            fi
        fi
    done

    if [[ "$restricted_changed" == false ]]; then
        log_info "Download tools already restricted"
    fi
}

undo_download_controls() {
    log_warning "Reverting download tool restrictions..."
    for tool in /usr/bin/curl /usr/bin/wget; do
        if [[ -f "$tool" ]]; then
            chmod 755 "$tool"
            chown root:root "$tool"
            log_success "Restored $tool to default permissions (755)"
        fi
    done
}

check_download_controls() {
    for tool in /usr/bin/curl /usr/bin/wget; do
        if [[ -f "$tool" ]]; then
            local perms
            perms=$(stat -c '%a' "$tool" 2>/dev/null)
            if [[ "$perms" == "750" ]]; then
                log_success "$tool restricted ($perms)"
            else
                log_warning "$tool not restricted ($perms, recommend 750)"
            fi
        fi
    done
}

# ============================================================================
# 4. Protect Security Frameworks (AppArmor/SELinux integrity)
# ============================================================================
# On Windows, AMSI provides the security scanning interface. On Linux,
# AppArmor and SELinux provide mandatory access control. This section
# ensures these frameworks are enabled and profiles/policies cannot be
# easily disabled by an attacker.

harden_security_frameworks() {
    log_info "Verifying security framework integrity..."

    # AppArmor
    if command -v apparmor_status &>/dev/null; then
        local aa_status
        aa_status=$(apparmor_status 2>/dev/null | head -1 || echo "unknown")
        if echo "$aa_status" | grep -qi "apparmor module is loaded"; then
            log_success "AppArmor is loaded and active"
        else
            log_warning "AppArmor is not active. Enabling..."
            systemctl enable apparmor > /dev/null 2>&1 || true
            systemctl start apparmor > /dev/null 2>&1 || true
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi

        # Protect AppArmor configuration from tampering
        if [[ -d /etc/apparmor.d ]]; then
            chmod 755 /etc/apparmor.d
            chown root:root /etc/apparmor.d
            log_info "AppArmor profile directory permissions verified"
        fi
    fi

    # SELinux
    if command -v getenforce &>/dev/null; then
        local selinux_mode
        selinux_mode=$(getenforce 2>/dev/null || echo "unknown")
        if [[ "$selinux_mode" == "Enforcing" ]]; then
            log_success "SELinux is in Enforcing mode"
        elif [[ "$selinux_mode" == "Permissive" ]]; then
            log_warning "SELinux is in Permissive mode (recommend Enforcing)"
            log_info "To set Enforcing: setenforce 1 (runtime) or edit /etc/selinux/config"
        else
            log_warning "SELinux status: $selinux_mode"
        fi

        # Prevent SELinux disable via config
        if [[ -f /etc/selinux/config ]]; then
            local current_selinux
            current_selinux=$(grep '^SELINUX=' /etc/selinux/config | cut -d= -f2)
            if [[ "$current_selinux" == "disabled" ]]; then
                backup_file /etc/selinux/config
                sed -i 's/^SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
                log_success "Changed SELinux config from disabled to enforcing"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        fi
    fi
}

undo_security_frameworks() {
    log_warning "Security framework hardening should not be reverted"
    log_info "AppArmor/SELinux settings left as-is (security best practice)"
}

check_security_frameworks() {
    if command -v apparmor_status &>/dev/null; then
        if apparmor_status 2>/dev/null | grep -q "apparmor module is loaded"; then
            log_success "AppArmor: active"
        else
            log_warning "AppArmor: not active"
        fi
    fi

    if command -v getenforce &>/dev/null; then
        local mode
        mode=$(getenforce 2>/dev/null || echo "unknown")
        if [[ "$mode" == "Enforcing" ]]; then
            log_success "SELinux: $mode"
        else
            log_warning "SELinux: $mode (recommend Enforcing)"
        fi
    fi
}

# ============================================================================
# 5. Restrict .NET/Mono Runtime (Reflective code loading prevention)
# ============================================================================
# TrollDisappearKey uses Assembly.Load() to execute .NET assemblies in
# memory. On Linux, the Mono runtime and .NET Core can do the same.
# Restrict these runtimes to authorized users only.

harden_dotnet_runtime() {
    log_info "Restricting .NET/Mono runtime access..."

    for runtime in /usr/bin/dotnet /usr/bin/mono /usr/bin/mono-sgen; do
        if [[ -f "$runtime" ]]; then
            local current_perms
            current_perms=$(stat -c '%a' "$runtime" 2>/dev/null || echo "unknown")
            if [[ "$current_perms" != "750" ]]; then
                backup_file "$runtime"
                chmod 750 "$runtime"
                chown root:sudo "$runtime" 2>/dev/null || chown root:wheel "$runtime" 2>/dev/null || true
                log_success "Restricted $runtime to root/sudo group (was $current_perms)"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            else
                log_info "$runtime already restricted"
            fi
        fi
    done
}

undo_dotnet_runtime() {
    log_warning "Reverting .NET/Mono runtime restrictions..."
    for runtime in /usr/bin/dotnet /usr/bin/mono /usr/bin/mono-sgen; do
        if [[ -f "$runtime" ]]; then
            chmod 755 "$runtime"
            chown root:root "$runtime"
            log_success "Restored $runtime to default permissions (755)"
        fi
    done
}

check_dotnet_runtime() {
    for runtime in /usr/bin/dotnet /usr/bin/mono /usr/bin/mono-sgen; do
        if [[ -f "$runtime" ]]; then
            local perms
            perms=$(stat -c '%a' "$runtime" 2>/dev/null)
            if [[ "$perms" == "750" ]]; then
                log_success "$runtime restricted ($perms)"
            else
                log_warning "$runtime not restricted ($perms, recommend 750)"
            fi
        fi
    done
}

# ============================================================================
# 6. Kernel Module Loading Restrictions
# ============================================================================
# Prevent unauthorized kernel module loading, which could be used to disable
# security monitoring at the kernel level (equivalent to disabling AMSI at
# the OS level).

harden_kernel_modules() {
    log_info "Restricting kernel module loading..."

    local sysctl_file="/etc/sysctl.d/90-f0rtika-modules.conf"
    local current_modules_disabled
    current_modules_disabled=$(sysctl -n kernel.modules_disabled 2>/dev/null || echo "0")

    # Only restrict module loading via sysctl; do NOT set modules_disabled=1
    # as that is permanent until reboot and may break legitimate operations.
    # Instead, use modprobe blacklisting.

    local modprobe_file="/etc/modprobe.d/f0rtika-blacklist.conf"
    backup_file "$modprobe_file" 2>/dev/null || true

    cat > "$modprobe_file" <<'MODPROBE_EOF'
# F0RT1KA Hardening: Blacklist modules commonly used for rootkits/evasion
# MITRE ATT&CK: T1562.001 (Impair Defenses)

# Prevent loading of uncommon filesystem modules (data staging)
install cramfs /bin/false
install freevxfs /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false

# Prevent loading of uncommon network protocols
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
MODPROBE_EOF

    log_success "Module blacklist installed at $modprobe_file"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_kernel_modules() {
    log_warning "Removing kernel module blacklist..."
    local modprobe_file="/etc/modprobe.d/f0rtika-blacklist.conf"
    if [[ -f "$modprobe_file" ]]; then
        rm -f "$modprobe_file"
        log_success "Removed module blacklist"
    fi
}

check_kernel_modules() {
    if [[ -f "/etc/modprobe.d/f0rtika-blacklist.conf" ]]; then
        log_success "Module blacklist is installed"
    else
        log_warning "Module blacklist not installed"
    fi
}

# ============================================================================
# 7. Enable Process Accounting and Command Logging
# ============================================================================
# Equivalent to Windows process creation auditing with command lines,
# which is essential for detecting tool execution post-AMSI-bypass.

harden_process_accounting() {
    log_info "Enabling process accounting..."

    # Enable process accounting if available
    if command -v accton &>/dev/null; then
        local acct_file="/var/log/account/pacct"
        mkdir -p /var/log/account
        touch "$acct_file"
        accton "$acct_file" > /dev/null 2>&1 || true
        log_success "Process accounting enabled at $acct_file"
    fi

    # Ensure bash command logging via HISTTIMEFORMAT
    local profile_file="/etc/profile.d/f0rtika-history.sh"
    backup_file "$profile_file" 2>/dev/null || true

    cat > "$profile_file" <<'PROFILE_EOF'
# F0RT1KA Hardening: Enhanced command history logging
# Prevents attackers from hiding their commands after defense evasion
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=50000
export HISTFILESIZE=50000
export HISTCONTROL=""
shopt -s histappend 2>/dev/null || true
PROFILE_EOF

    chmod 644 "$profile_file"
    log_success "Enhanced command history logging configured"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_process_accounting() {
    log_warning "Reverting process accounting..."
    local profile_file="/etc/profile.d/f0rtika-history.sh"
    if [[ -f "$profile_file" ]]; then
        rm -f "$profile_file"
        log_success "Removed history logging profile"
    fi
    if command -v accton &>/dev/null; then
        accton off > /dev/null 2>&1 || true
        log_success "Process accounting disabled"
    fi
}

check_process_accounting() {
    if [[ -f "/etc/profile.d/f0rtika-history.sh" ]]; then
        log_success "Enhanced history logging is configured"
    else
        log_warning "Enhanced history logging not configured"
    fi
}

# ============================================================================
# 8. Secure Shared Library Loading
# ============================================================================
# Ensure the dynamic linker configuration cannot be tampered with to
# intercept library calls (the Linux equivalent of DLL hooking).

harden_shared_libraries() {
    log_info "Securing shared library loading configuration..."

    # Protect ld.so configuration
    for f in /etc/ld.so.conf /etc/ld.so.cache; do
        if [[ -f "$f" ]]; then
            chmod 644 "$f"
            chown root:root "$f"
        fi
    done

    if [[ -d /etc/ld.so.conf.d ]]; then
        chmod 755 /etc/ld.so.conf.d
        chown root:root /etc/ld.so.conf.d
        # Ensure all files in ld.so.conf.d are owned by root
        find /etc/ld.so.conf.d -type f ! -user root -exec chown root:root {} \; 2>/dev/null || true
    fi

    # Set fs.protected_hardlinks and fs.protected_symlinks
    local sysctl_file="/etc/sysctl.d/90-f0rtika-links.conf"
    local current_hardlinks
    current_hardlinks=$(sysctl -n fs.protected_hardlinks 2>/dev/null || echo "0")
    local current_symlinks
    current_symlinks=$(sysctl -n fs.protected_symlinks 2>/dev/null || echo "0")

    if [[ "$current_hardlinks" != "1" || "$current_symlinks" != "1" ]]; then
        cat > "$sysctl_file" <<'SYSCTL_EOF'
# F0RT1KA Hardening: Protect against symlink/hardlink attacks
# Prevents attackers from using links to redirect library loading
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYSCTL_EOF
        sysctl -p "$sysctl_file" > /dev/null 2>&1
        log_success "Protected hardlinks/symlinks enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Hardlink/symlink protections already enabled"
    fi

    log_success "Shared library configuration secured"
}

undo_shared_libraries() {
    log_warning "Reverting shared library protections..."
    local sysctl_file="/etc/sysctl.d/90-f0rtika-links.conf"
    if [[ -f "$sysctl_file" ]]; then
        rm -f "$sysctl_file"
        sysctl -w fs.protected_hardlinks=0 fs.protected_symlinks=0 > /dev/null 2>&1 || true
        log_success "Removed link protections"
    fi
}

check_shared_libraries() {
    local hardlinks
    hardlinks=$(sysctl -n fs.protected_hardlinks 2>/dev/null || echo "0")
    local symlinks
    symlinks=$(sysctl -n fs.protected_symlinks 2>/dev/null || echo "0")
    if [[ "$hardlinks" == "1" && "$symlinks" == "1" ]]; then
        log_success "Hardlink/symlink protections enabled"
    else
        log_warning "Hardlink=$hardlinks, Symlink=$symlinks (recommend both =1)"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

ACTION="${1:-apply}"

echo ""
echo "============================================================================"
echo "F0RT1KA Linux Hardening Script"
echo "Test ID: c1f0fe6f-6907-4f95-820d-47e0a39abe54"
echo "MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools"
echo "Action: $ACTION"
echo "============================================================================"
echo ""

# Initialize log
mkdir -p "$(dirname "$LOG_FILE")"
echo "$(date '+%Y-%m-%d %H:%M:%S') === F0RT1KA Hardening: $ACTION ===" >> "$LOG_FILE"

case "$ACTION" in
    apply)
        check_root
        ensure_backup_dir
        log_info "Applying hardening measures..."
        echo ""

        harden_ld_preload
        harden_audit_logging
        harden_download_controls
        harden_security_frameworks
        harden_dotnet_runtime
        harden_kernel_modules
        harden_process_accounting
        harden_shared_libraries

        echo ""
        echo "============================================================================"
        log_success "Hardening complete. $CHANGE_COUNT changes applied."
        echo "============================================================================"
        echo ""
        echo "Applied Settings:"
        echo "  - LD_PRELOAD / ptrace restrictions (anti-API-hooking)"
        echo "  - Audit rules for defense evasion detection"
        echo "  - Download tool restrictions (curl/wget)"
        echo "  - Security framework verification (AppArmor/SELinux)"
        echo "  - .NET/Mono runtime access restrictions"
        echo "  - Kernel module blacklisting"
        echo "  - Process accounting and command history logging"
        echo "  - Shared library loading security"
        echo ""
        echo "Backup location: $BACKUP_DIR"
        echo "Log file: $LOG_FILE"
        echo ""
        echo "To revert: sudo $SCRIPT_NAME undo"
        echo "To check:  sudo $SCRIPT_NAME check"
        echo ""
        ;;

    undo)
        check_root
        log_warning "Reverting hardening changes..."
        echo ""

        undo_ld_preload
        undo_audit_logging
        undo_download_controls
        undo_security_frameworks
        undo_dotnet_runtime
        undo_kernel_modules
        undo_process_accounting
        undo_shared_libraries

        echo ""
        log_success "Revert complete. Some security settings left as-is (best practice)."
        echo ""
        ;;

    check)
        check_root
        log_info "Checking hardening status..."
        echo ""

        check_ld_preload
        check_audit_logging
        check_download_controls
        check_security_frameworks
        check_dotnet_runtime
        check_kernel_modules
        check_process_accounting
        check_shared_libraries

        echo ""
        log_info "Check complete."
        echo ""
        ;;

    *)
        echo "Usage: sudo $SCRIPT_NAME [apply|undo|check]"
        echo ""
        echo "  apply  - Apply hardening settings (default)"
        echo "  undo   - Revert hardening settings"
        echo "  check  - Check current hardening status"
        exit 1
        ;;
esac

echo "============================================================================"
echo "Completed at $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================================"
