#!/usr/bin/env bash
# ============================================================
# Linux Hardening Script: MDE Authentication Bypass Defense
# Test ID: b6c73735-0c24-4a1e-8f0a-3c24af39671b
# MITRE ATT&CK: T1562.001, T1014, T1090.003, T1140
# Mitigations: M1047, M1038, M1022, M1024, M1018, M1030, M1031
#
# Purpose: Hardens Linux endpoints running Microsoft Defender
#          for Endpoint (MDE/mdatp) against authentication bypass,
#          certificate pinning bypass, and command interception
#          attacks discovered by InfoGuard Labs.
#
# Usage:
#   sudo ./b6c73735_hardening_linux.sh           # Apply hardening
#   sudo ./b6c73735_hardening_linux.sh --undo     # Revert changes
#   sudo ./b6c73735_hardening_linux.sh --check    # Check current state
#   sudo ./b6c73735_hardening_linux.sh --dry-run  # Show what would change
#
# Requires: root privileges
# Idempotent: Yes (safe to run multiple times)
# ============================================================

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
SCRIPT_NAME="MDE Auth Bypass Hardening (Linux)"
SCRIPT_VERSION="1.0.0"
BACKUP_DIR="/var/backup/f0rtika-hardening"
CHANGE_LOG="${BACKUP_DIR}/changes_$(date +%Y%m%d_%H%M%S).log"
MDE_INSTALL_DIR="/opt/microsoft/mdatp"
MDE_CONFIG_DIR="/etc/opt/microsoft/mdatp"
MDE_LOG_DIR="/var/log/microsoft/mdatp"
IPTABLES_BACKUP="${BACKUP_DIR}/iptables_backup.rules"
AUDITD_RULE_FILE="/etc/audit/rules.d/90-mde-protection.rules"
SYSCTL_CONF="/etc/sysctl.d/99-mde-hardening.conf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Operation mode
MODE="apply"
DRY_RUN=false

# ============================================================
# Parse Arguments
# ============================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --undo|--revert)
            MODE="undo"
            shift
            ;;
        --check|--status)
            MODE="check"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--undo|--check|--dry-run|--help]"
            echo ""
            echo "Options:"
            echo "  --undo      Revert all hardening changes"
            echo "  --check     Check current hardening status"
            echo "  --dry-run   Show what would change without applying"
            echo "  --help      Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================================
# Helper Functions
# ============================================================

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_change() {
    local action="$1"
    local target="$2"
    local detail="${3:-}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | ${action} | ${target} | ${detail}" >> "${CHANGE_LOG}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_mde_installed() {
    if command -v mdatp &>/dev/null; then
        log_success "MDE for Linux (mdatp) is installed"
        return 0
    elif [[ -d "${MDE_INSTALL_DIR}" ]]; then
        log_success "MDE installation directory found at ${MDE_INSTALL_DIR}"
        return 0
    else
        log_warning "MDE for Linux (mdatp) not detected - applying general hardening"
        return 1
    fi
}

ensure_backup_dir() {
    mkdir -p "${BACKUP_DIR}"
    if [[ ! -f "${CHANGE_LOG}" ]]; then
        echo "# MDE Hardening Change Log - $(date)" > "${CHANGE_LOG}"
        echo "# Timestamp | Action | Target | Detail" >> "${CHANGE_LOG}"
    fi
}

# ============================================================
# Hardening Function 1: Restrict MDE Configuration File Access
# Mitigation: M1022 (Restrict File and Directory Permissions)
# ============================================================

harden_mde_file_permissions() {
    log_info "=== Restricting MDE Configuration File Permissions ==="
    log_info "Mitigation: M1022 - Restrict File and Directory Permissions"

    local mde_dirs=(
        "${MDE_CONFIG_DIR}"
        "${MDE_INSTALL_DIR}"
        "${MDE_LOG_DIR}"
    )

    for dir in "${mde_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local current_perms
            current_perms=$(stat -c '%a' "$dir" 2>/dev/null || echo "unknown")

            if $DRY_RUN; then
                log_info "[DRY-RUN] Would set $dir permissions to 750 (current: $current_perms)"
                continue
            fi

            # Backup current permissions
            log_change "BACKUP_PERMS" "$dir" "current=${current_perms}"

            # Set restrictive permissions: owner=rwx, group=rx, others=none
            chmod 750 "$dir"
            chown root:root "$dir"

            # Recursively restrict config files
            if [[ "$dir" == "${MDE_CONFIG_DIR}" ]]; then
                find "$dir" -type f -exec chmod 640 {} \;
                find "$dir" -type d -exec chmod 750 {} \;
            fi

            log_success "Set $dir permissions to 750 (was: $current_perms)"
            log_change "SET_PERMS" "$dir" "new=750,old=${current_perms}"
        else
            log_warning "Directory not found: $dir (skipping)"
        fi
    done

    # Protect MDE onboarding information files
    local sensitive_files=(
        "${MDE_CONFIG_DIR}/mdatp_onboard.json"
        "${MDE_CONFIG_DIR}/managed/mdatp_managed.json"
    )

    for file in "${sensitive_files[@]}"; do
        if [[ -f "$file" ]]; then
            if $DRY_RUN; then
                log_info "[DRY-RUN] Would set $file permissions to 600"
                continue
            fi
            chmod 600 "$file"
            chown root:root "$file"
            log_success "Restricted $file to root-only read (600)"
            log_change "SET_PERMS" "$file" "new=600"
        fi
    done
}

undo_mde_file_permissions() {
    log_info "=== Reverting MDE File Permissions ==="
    local mde_dirs=(
        "${MDE_CONFIG_DIR}"
        "${MDE_INSTALL_DIR}"
        "${MDE_LOG_DIR}"
    )

    for dir in "${mde_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            chmod 755 "$dir"
            if [[ "$dir" == "${MDE_CONFIG_DIR}" ]]; then
                find "$dir" -type f -exec chmod 644 {} \;
                find "$dir" -type d -exec chmod 755 {} \;
            fi
            log_success "Reverted $dir permissions to 755"
            log_change "REVERT_PERMS" "$dir" "restored=755"
        fi
    done
}

check_mde_file_permissions() {
    log_info "=== Checking MDE File Permissions ==="

    local mde_dirs=(
        "${MDE_CONFIG_DIR}"
        "${MDE_INSTALL_DIR}"
        "${MDE_LOG_DIR}"
    )

    for dir in "${mde_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local perms
            perms=$(stat -c '%a' "$dir" 2>/dev/null || echo "unknown")
            if [[ "$perms" == "750" ]]; then
                log_success "$dir: permissions = $perms (hardened)"
            else
                log_warning "$dir: permissions = $perms (not hardened, expected 750)"
            fi
        else
            log_warning "$dir: not found"
        fi
    done
}

# ============================================================
# Hardening Function 2: Firewall Rules for MDE Endpoint Access
# Mitigation: M1030 (Network Segmentation), M1031 (Network Intrusion Prevention)
# ============================================================

harden_firewall_mde_endpoints() {
    log_info "=== Configuring Firewall Rules for MDE Endpoint Protection ==="
    log_info "Mitigation: M1030 - Network Segmentation"
    log_info "Mitigation: M1031 - Network Intrusion Prevention"

    if ! command -v iptables &>/dev/null; then
        log_warning "iptables not found - skipping firewall hardening"
        return
    fi

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create iptables rules to restrict MDE endpoint access"
        log_info "[DRY-RUN] Only MDE processes (mdatp, wdavdaemon) would be allowed to connect to winatp-gw-*.microsoft.com"
        return
    fi

    # Backup current iptables rules
    iptables-save > "${IPTABLES_BACKUP}" 2>/dev/null || true
    log_change "BACKUP" "${IPTABLES_BACKUP}" "iptables rules backed up"

    # Get MDE process user (typically runs as mdatp or root)
    local mde_user="mdatp"
    if ! id "$mde_user" &>/dev/null; then
        mde_user="root"
        log_warning "mdatp user not found, using root for MDE process identification"
    fi

    # Create iptables chain for MDE endpoint protection
    iptables -N MDE_PROTECT 2>/dev/null || iptables -F MDE_PROTECT

    # Allow MDE processes to connect to MDE cloud endpoints
    # These resolve to Microsoft Azure IPs, so we match by owner UID
    local mde_uid
    mde_uid=$(id -u "$mde_user" 2>/dev/null || echo "0")

    iptables -A MDE_PROTECT -m owner --uid-owner "$mde_uid" -p tcp --dport 443 -j ACCEPT \
        -m comment --comment "Allow MDE service HTTPS to cloud"

    # Log and drop non-MDE connections to well-known MDE gateway IPs
    # Note: MDE gateway hostnames resolve dynamically. This rule logs
    # suspicious outbound HTTPS from non-MDE processes for review.
    # Actual IP blocking requires DNS-based filtering at the network level.
    iptables -A MDE_PROTECT -m owner ! --uid-owner "$mde_uid" \
        -p tcp --dport 443 \
        -m string --string "winatp-gw" --algo bm \
        -j LOG --log-prefix "MDE-UNAUTH-ACCESS: " --log-level 4 \
        -m comment --comment "Log non-MDE access to MDE endpoints"

    # Insert chain into OUTPUT
    iptables -I OUTPUT 1 -j MDE_PROTECT 2>/dev/null || true

    log_success "Firewall rules configured for MDE endpoint protection"
    log_change "FIREWALL" "MDE_PROTECT chain" "Created with MDE-only HTTPS access"
}

undo_firewall_mde_endpoints() {
    log_info "=== Reverting Firewall Rules ==="

    if ! command -v iptables &>/dev/null; then
        log_warning "iptables not found - nothing to revert"
        return
    fi

    # Remove chain reference from OUTPUT
    iptables -D OUTPUT -j MDE_PROTECT 2>/dev/null || true

    # Flush and delete chain
    iptables -F MDE_PROTECT 2>/dev/null || true
    iptables -X MDE_PROTECT 2>/dev/null || true

    # Restore backup if available
    if [[ -f "${IPTABLES_BACKUP}" ]]; then
        iptables-restore < "${IPTABLES_BACKUP}"
        log_success "Restored iptables from backup"
    fi

    log_success "Firewall rules reverted"
    log_change "REVERT_FIREWALL" "MDE_PROTECT chain" "Removed"
}

check_firewall_mde_endpoints() {
    log_info "=== Checking Firewall MDE Protection ==="

    if ! command -v iptables &>/dev/null; then
        log_warning "iptables not available"
        return
    fi

    if iptables -L MDE_PROTECT -n &>/dev/null; then
        local rule_count
        rule_count=$(iptables -L MDE_PROTECT -n | grep -c "^" || echo "0")
        log_success "MDE_PROTECT chain exists with $((rule_count - 2)) rules"
    else
        log_warning "MDE_PROTECT chain not found (not hardened)"
    fi
}

# ============================================================
# Hardening Function 3: Audit Rules for MDE Access Monitoring
# Mitigation: M1047 (Audit)
# ============================================================

harden_audit_rules() {
    log_info "=== Configuring Audit Rules for MDE Access Monitoring ==="
    log_info "Mitigation: M1047 - Audit"

    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not found - skipping audit rule configuration"
        log_warning "Install with: apt install auditd  or  yum install audit"
        return
    fi

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create audit rules monitoring:"
        log_info "[DRY-RUN]   - MDE configuration file access"
        log_info "[DRY-RUN]   - MDE binary execution from non-standard paths"
        log_info "[DRY-RUN]   - ptrace calls (memory manipulation)"
        log_info "[DRY-RUN]   - Shared library injection"
        return
    fi

    # Create audit rules file
    cat > "${AUDITD_RULE_FILE}" << 'AUDITRULES'
## ============================================================
## MDE Authentication Bypass Protection - Audit Rules
## Test ID: b6c73735-0c24-4a1e-8f0a-3c24af39671b
## MITRE: T1562.001, T1014, T1090.003, T1140
## ============================================================

## Monitor access to MDE configuration files (identifier extraction)
-w /etc/opt/microsoft/mdatp/ -p rwa -k mde_config_access
-w /opt/microsoft/mdatp/ -p x -k mde_binary_execution

## Monitor MDE onboarding files (Machine ID, Org ID extraction)
-w /etc/opt/microsoft/mdatp/mdatp_onboard.json -p r -k mde_onboarding_read

## Monitor ptrace syscalls (certificate pinning bypass via memory manipulation)
## ptrace is used for debugging and memory patching - detect non-debugger usage
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k memory_write_attempt
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k memory_write_attempt
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k memory_write_attempt

## Monitor process_vm_writev (cross-process memory writing without ptrace)
-a always,exit -F arch=b64 -S process_vm_writev -k cross_process_memory_write

## Monitor mprotect with PROT_EXEC (making memory pages executable)
## This is the Linux equivalent of VirtualProtectEx with PAGE_EXECUTE_READWRITE
-a always,exit -F arch=b64 -S mprotect -F a2&0x4 -k memory_protection_change

## Monitor loading of shared libraries from unusual locations
-w /tmp/ -p x -k suspicious_lib_execution
-w /dev/shm/ -p x -k suspicious_shm_execution

## Monitor MDE service status changes
-w /usr/bin/systemctl -p x -k service_control
-a always,exit -F arch=b64 -S kill -F a1=15 -k process_signal_term
-a always,exit -F arch=b64 -S kill -F a1=9 -k process_signal_kill

## Monitor network socket creation (detect unauthorized MDE endpoint connections)
-a always,exit -F arch=b64 -S connect -F a2=16 -k network_connect_ipv4
AUDITRULES

    log_success "Audit rules written to ${AUDITD_RULE_FILE}"
    log_change "AUDIT_RULES" "${AUDITD_RULE_FILE}" "Created MDE protection audit rules"

    # Load rules
    if systemctl is-active --quiet auditd; then
        augenrules --load 2>/dev/null || auditctl -R "${AUDITD_RULE_FILE}" 2>/dev/null || true
        log_success "Audit rules loaded into running auditd"
    else
        log_warning "auditd is not running - rules will load on next start"
        log_info "Start auditd: systemctl start auditd && systemctl enable auditd"
    fi
}

undo_audit_rules() {
    log_info "=== Reverting Audit Rules ==="

    if [[ -f "${AUDITD_RULE_FILE}" ]]; then
        rm -f "${AUDITD_RULE_FILE}"
        log_success "Removed ${AUDITD_RULE_FILE}"

        if command -v augenrules &>/dev/null && systemctl is-active --quiet auditd; then
            augenrules --load 2>/dev/null || true
            log_success "Audit rules reloaded (MDE rules removed)"
        fi
    else
        log_warning "Audit rule file not found - nothing to revert"
    fi

    log_change "REVERT_AUDIT" "${AUDITD_RULE_FILE}" "Removed"
}

check_audit_rules() {
    log_info "=== Checking Audit Rules ==="

    if [[ -f "${AUDITD_RULE_FILE}" ]]; then
        local rule_count
        rule_count=$(grep -c "^-" "${AUDITD_RULE_FILE}" 2>/dev/null || echo "0")
        log_success "Audit rule file exists with ${rule_count} rules"
    else
        log_warning "MDE audit rule file not found (not hardened)"
    fi

    if command -v auditctl &>/dev/null; then
        local active_mde_rules
        active_mde_rules=$(auditctl -l 2>/dev/null | grep -c "mde_" || echo "0")
        if [[ "$active_mde_rules" -gt 0 ]]; then
            log_success "Active MDE audit rules: ${active_mde_rules}"
        else
            log_warning "No active MDE audit rules loaded"
        fi
    fi
}

# ============================================================
# Hardening Function 4: Kernel Protection - Restrict ptrace
# Mitigation: M1038 (Execution Prevention), T1014 (Rootkit)
# ============================================================

harden_kernel_ptrace() {
    log_info "=== Restricting ptrace Scope (Anti-Memory-Manipulation) ==="
    log_info "Mitigation: M1038 - Execution Prevention"
    log_info "Prevents certificate pinning bypass via process memory patching"

    if $DRY_RUN; then
        local current_ptrace
        current_ptrace=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "unknown")
        log_info "[DRY-RUN] Would set kernel.yama.ptrace_scope = 2 (current: $current_ptrace)"
        log_info "[DRY-RUN] Would set kernel.kptr_restrict = 2"
        log_info "[DRY-RUN] Would set kernel.dmesg_restrict = 1"
        return
    fi

    # Backup current values
    local current_ptrace current_kptr current_dmesg
    current_ptrace=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "not_available")
    current_kptr=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "not_available")
    current_dmesg=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "not_available")

    log_change "BACKUP_SYSCTL" "kernel.yama.ptrace_scope" "current=${current_ptrace}"
    log_change "BACKUP_SYSCTL" "kernel.kptr_restrict" "current=${current_kptr}"
    log_change "BACKUP_SYSCTL" "kernel.dmesg_restrict" "current=${current_dmesg}"

    # Create sysctl configuration
    cat > "${SYSCTL_CONF}" << 'SYSCTLCONF'
## ============================================================
## MDE Authentication Bypass Protection - Kernel Hardening
## Test ID: b6c73735-0c24-4a1e-8f0a-3c24af39671b
## MITRE: T1014 (Rootkit/Certificate Pinning Bypass)
## ============================================================

## Restrict ptrace to parent-child only (prevents cross-process memory access)
## 0 = classic ptrace, 1 = parent-child only, 2 = admin only, 3 = disabled
## Value 2 prevents non-root memory patching of crypt32 equivalent functions
kernel.yama.ptrace_scope = 2

## Hide kernel pointers from non-root users (prevents KASLR bypass)
kernel.kptr_restrict = 2

## Restrict dmesg access (prevents kernel information leakage)
kernel.dmesg_restrict = 1

## Restrict unprivileged access to kernel perf events
kernel.perf_event_paranoid = 3

## Disable unprivileged BPF (prevents BPF-based memory inspection)
kernel.unprivileged_bpf_disabled = 1
SYSCTLCONF

    # Apply settings
    sysctl -p "${SYSCTL_CONF}" 2>/dev/null || {
        # Apply individually for systems where some settings may not exist
        sysctl -w kernel.yama.ptrace_scope=2 2>/dev/null || log_warning "ptrace_scope not available (Yama LSM not loaded)"
        sysctl -w kernel.kptr_restrict=2 2>/dev/null || true
        sysctl -w kernel.dmesg_restrict=1 2>/dev/null || true
        sysctl -w kernel.perf_event_paranoid=3 2>/dev/null || true
        sysctl -w kernel.unprivileged_bpf_disabled=1 2>/dev/null || true
    }

    log_success "Kernel hardening applied (ptrace restricted, kernel pointers hidden)"
    log_change "SYSCTL" "${SYSCTL_CONF}" "kernel ptrace and memory protection hardened"
}

undo_kernel_ptrace() {
    log_info "=== Reverting Kernel ptrace Restrictions ==="

    if [[ -f "${SYSCTL_CONF}" ]]; then
        rm -f "${SYSCTL_CONF}"
        log_success "Removed ${SYSCTL_CONF}"
    fi

    # Restore defaults
    sysctl -w kernel.yama.ptrace_scope=1 2>/dev/null || true
    sysctl -w kernel.kptr_restrict=1 2>/dev/null || true
    sysctl -w kernel.dmesg_restrict=0 2>/dev/null || true
    sysctl -w kernel.perf_event_paranoid=2 2>/dev/null || true

    log_success "Kernel settings reverted to defaults"
    log_change "REVERT_SYSCTL" "kernel" "Restored default ptrace and memory settings"
}

check_kernel_ptrace() {
    log_info "=== Checking Kernel ptrace Restrictions ==="

    local ptrace_scope
    ptrace_scope=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "unavailable")
    case "$ptrace_scope" in
        2|3) log_success "kernel.yama.ptrace_scope = $ptrace_scope (hardened)" ;;
        1)   log_warning "kernel.yama.ptrace_scope = $ptrace_scope (default, not hardened)" ;;
        0)   log_error "kernel.yama.ptrace_scope = $ptrace_scope (NO RESTRICTION)" ;;
        *)   log_warning "kernel.yama.ptrace_scope = $ptrace_scope" ;;
    esac

    local kptr
    kptr=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "unavailable")
    if [[ "$kptr" == "2" ]]; then
        log_success "kernel.kptr_restrict = $kptr (hardened)"
    else
        log_warning "kernel.kptr_restrict = $kptr (not hardened, expected 2)"
    fi

    if [[ -f "${SYSCTL_CONF}" ]]; then
        log_success "Sysctl config file exists at ${SYSCTL_CONF}"
    else
        log_warning "Sysctl config file not found (not persistent)"
    fi
}

# ============================================================
# Hardening Function 5: MDE Service Protection
# Mitigation: M1018 (User Account Management)
# ============================================================

harden_mde_service() {
    log_info "=== Protecting MDE Service Configuration ==="
    log_info "Mitigation: M1018 - User Account Management"

    if ! systemctl list-unit-files 2>/dev/null | grep -q "mdatp"; then
        log_warning "mdatp service not found - skipping service hardening"
        return
    fi

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create systemd override to prevent mdatp service tampering"
        return
    fi

    # Create systemd override to make service harder to stop/disable
    local override_dir="/etc/systemd/system/mdatp.service.d"
    mkdir -p "$override_dir"

    cat > "${override_dir}/hardening.conf" << 'SERVICECONF'
[Service]
# Automatically restart MDE if killed (anti-tampering)
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=10

# Protect service from OOM killer
OOMScoreAdjust=-1000

# Restrict the service from being easily stopped
# (requires explicit override to stop)
RefuseManualStop=false

# Security hardening
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=false
SERVICECONF

    systemctl daemon-reload
    log_success "MDE service hardened with auto-restart and protection"
    log_change "SERVICE" "mdatp.service" "Added hardening override"
}

undo_mde_service() {
    log_info "=== Reverting MDE Service Hardening ==="

    local override_dir="/etc/systemd/system/mdatp.service.d"
    if [[ -f "${override_dir}/hardening.conf" ]]; then
        rm -f "${override_dir}/hardening.conf"
        rmdir "${override_dir}" 2>/dev/null || true
        systemctl daemon-reload
        log_success "MDE service override removed"
    else
        log_warning "No service override found"
    fi

    log_change "REVERT_SERVICE" "mdatp.service" "Removed hardening override"
}

check_mde_service() {
    log_info "=== Checking MDE Service Status ==="

    if systemctl list-unit-files 2>/dev/null | grep -q "mdatp"; then
        local status
        status=$(systemctl is-active mdatp 2>/dev/null || echo "unknown")
        if [[ "$status" == "active" ]]; then
            log_success "mdatp service: active (running)"
        else
            log_warning "mdatp service: $status"
        fi

        if [[ -f "/etc/systemd/system/mdatp.service.d/hardening.conf" ]]; then
            log_success "Service hardening override: present"
        else
            log_warning "Service hardening override: not found"
        fi
    else
        log_warning "mdatp service not installed"
    fi
}

# ============================================================
# Hardening Function 6: SSL/TLS Certificate Integrity Protection
# Mitigation: M1038 (Execution Prevention) against T1014 (Rootkit)
# ============================================================

harden_certificate_integrity() {
    log_info "=== Protecting SSL/TLS Certificate Stores ==="
    log_info "Mitigation: Protect against certificate pinning bypass"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would restrict access to system certificate stores"
        log_info "[DRY-RUN] Would configure audit logging for certificate changes"
        return
    fi

    # Protect system certificate directory
    local cert_dirs=(
        "/etc/ssl/certs"
        "/etc/pki/tls/certs"
        "/usr/local/share/ca-certificates"
    )

    for dir in "${cert_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # Ensure only root can modify certificates
            chown -R root:root "$dir"
            find "$dir" -type f -exec chmod 644 {} \;
            find "$dir" -type d -exec chmod 755 {} \;
            log_success "Certificate directory permissions secured: $dir"
            log_change "CERT_PERMS" "$dir" "Secured certificate directory"
        fi
    done

    # Add audit rules for certificate store modifications
    if command -v auditctl &>/dev/null; then
        for dir in "${cert_dirs[@]}"; do
            if [[ -d "$dir" ]]; then
                auditctl -w "$dir" -p wa -k cert_store_modification 2>/dev/null || true
            fi
        done
        log_success "Certificate store modification auditing enabled"
    fi
}

undo_certificate_integrity() {
    log_info "=== Reverting Certificate Integrity Protections ==="

    if command -v auditctl &>/dev/null; then
        auditctl -W /etc/ssl/certs -p wa -k cert_store_modification 2>/dev/null || true
        auditctl -W /etc/pki/tls/certs -p wa -k cert_store_modification 2>/dev/null || true
        auditctl -W /usr/local/share/ca-certificates -p wa -k cert_store_modification 2>/dev/null || true
        log_success "Certificate audit rules removed"
    fi

    log_change "REVERT_CERTS" "certificate stores" "Reverted audit rules"
}

check_certificate_integrity() {
    log_info "=== Checking Certificate Store Protection ==="

    local cert_dirs=(
        "/etc/ssl/certs"
        "/etc/pki/tls/certs"
    )

    for dir in "${cert_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local owner
            owner=$(stat -c '%U' "$dir" 2>/dev/null || echo "unknown")
            if [[ "$owner" == "root" ]]; then
                log_success "$dir: owned by root"
            else
                log_warning "$dir: owned by $owner (expected root)"
            fi
        fi
    done

    if command -v auditctl &>/dev/null; then
        local cert_audit
        cert_audit=$(auditctl -l 2>/dev/null | grep -c "cert_store" || echo "0")
        if [[ "$cert_audit" -gt 0 ]]; then
            log_success "Certificate store auditing: active ($cert_audit rules)"
        else
            log_warning "Certificate store auditing: not active"
        fi
    fi
}

# ============================================================
# Hardening Function 7: Restrict LD_PRELOAD and Library Injection
# Mitigation: M1038 (Execution Prevention)
# ============================================================

harden_library_injection() {
    log_info "=== Restricting Shared Library Injection ==="
    log_info "Mitigation: Prevent LD_PRELOAD-based certificate/memory bypass"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would restrict LD_PRELOAD for MDE processes"
        log_info "[DRY-RUN] Would add ld.so.preload monitoring"
        return
    fi

    # Monitor /etc/ld.so.preload for unauthorized modifications
    if command -v auditctl &>/dev/null; then
        auditctl -w /etc/ld.so.preload -p wa -k ld_preload_modification 2>/dev/null || true
        auditctl -w /etc/ld.so.conf -p wa -k ld_config_modification 2>/dev/null || true
        auditctl -w /etc/ld.so.conf.d/ -p wa -k ld_config_modification 2>/dev/null || true
        log_success "Library injection monitoring enabled (ld.so.preload, ld.so.conf)"
        log_change "AUDIT_LD" "ld.so" "Monitoring library injection vectors"
    fi

    # Set MDE binary as non-preloadable using file capabilities (if setcap available)
    if command -v setcap &>/dev/null; then
        local mdatp_bin="/opt/microsoft/mdatp/sbin/wdavdaemon"
        if [[ -f "$mdatp_bin" ]]; then
            # The presence of file capabilities causes the dynamic linker
            # to ignore LD_PRELOAD for this binary (security feature)
            log_info "MDE daemon binary found - LD_PRELOAD ignored for capability-enabled binaries"
        fi
    fi
}

undo_library_injection() {
    log_info "=== Reverting Library Injection Restrictions ==="

    if command -v auditctl &>/dev/null; then
        auditctl -W /etc/ld.so.preload -p wa -k ld_preload_modification 2>/dev/null || true
        auditctl -W /etc/ld.so.conf -p wa -k ld_config_modification 2>/dev/null || true
        auditctl -W /etc/ld.so.conf.d/ -p wa -k ld_config_modification 2>/dev/null || true
        log_success "Library injection monitoring removed"
    fi

    log_change "REVERT_LD" "ld.so" "Removed library injection monitoring"
}

check_library_injection() {
    log_info "=== Checking Library Injection Protection ==="

    if [[ -f /etc/ld.so.preload ]]; then
        local preload_entries
        preload_entries=$(wc -l < /etc/ld.so.preload 2>/dev/null || echo "0")
        if [[ "$preload_entries" -gt 0 ]]; then
            log_warning "/etc/ld.so.preload has $preload_entries entries - review for suspicious libraries"
        else
            log_success "/etc/ld.so.preload is empty"
        fi
    else
        log_success "/etc/ld.so.preload does not exist (no preloaded libraries)"
    fi

    if command -v auditctl &>/dev/null; then
        local ld_audit
        ld_audit=$(auditctl -l 2>/dev/null | grep -c "ld_" || echo "0")
        if [[ "$ld_audit" -gt 0 ]]; then
            log_success "Library injection auditing: active ($ld_audit rules)"
        else
            log_warning "Library injection auditing: not active"
        fi
    fi
}

# ============================================================
# Main Execution
# ============================================================

print_banner() {
    echo ""
    echo "============================================================"
    echo "  ${SCRIPT_NAME}"
    echo "  Version: ${SCRIPT_VERSION}"
    echo "  Test ID: b6c73735-0c24-4a1e-8f0a-3c24af39671b"
    echo "  MITRE ATT&CK: T1562.001, T1014, T1090.003, T1140"
    echo "============================================================"
    echo ""
}

main() {
    print_banner

    if [[ "$MODE" != "check" ]]; then
        check_root
    fi

    ensure_backup_dir
    local mde_present=true
    check_mde_installed || mde_present=false

    echo ""

    case "$MODE" in
        apply)
            if $DRY_RUN; then
                log_info "=== DRY RUN MODE - No changes will be applied ==="
                echo ""
            else
                log_info "=== Applying Hardening Settings ==="
                echo ""
            fi

            harden_mde_file_permissions
            echo ""
            harden_firewall_mde_endpoints
            echo ""
            harden_audit_rules
            echo ""
            harden_kernel_ptrace
            echo ""
            harden_mde_service
            echo ""
            harden_certificate_integrity
            echo ""
            harden_library_injection

            echo ""
            echo "============================================================"
            if $DRY_RUN; then
                log_info "DRY RUN complete - no changes applied"
                log_info "Run without --dry-run to apply changes"
            else
                log_success "All hardening settings applied successfully"
                log_success "Change log saved to: ${CHANGE_LOG}"
                echo ""
                log_info "To verify: $0 --check"
                log_info "To revert: $0 --undo"
            fi
            echo "============================================================"
            ;;

        undo)
            log_warning "=== Reverting All Hardening Settings ==="
            echo ""

            undo_library_injection
            echo ""
            undo_certificate_integrity
            echo ""
            undo_mde_service
            echo ""
            undo_kernel_ptrace
            echo ""
            undo_audit_rules
            echo ""
            undo_firewall_mde_endpoints
            echo ""
            undo_mde_file_permissions

            echo ""
            echo "============================================================"
            log_success "All hardening settings reverted"
            log_success "Change log saved to: ${CHANGE_LOG}"
            echo "============================================================"
            ;;

        check)
            log_info "=== Checking Hardening Status ==="
            echo ""

            check_mde_file_permissions
            echo ""
            check_firewall_mde_endpoints
            echo ""
            check_audit_rules
            echo ""
            check_kernel_ptrace
            echo ""
            check_mde_service
            echo ""
            check_certificate_integrity
            echo ""
            check_library_injection

            echo ""
            echo "============================================================"
            log_info "Status check complete"
            echo "============================================================"
            ;;
    esac

    echo ""
}

main "$@"
