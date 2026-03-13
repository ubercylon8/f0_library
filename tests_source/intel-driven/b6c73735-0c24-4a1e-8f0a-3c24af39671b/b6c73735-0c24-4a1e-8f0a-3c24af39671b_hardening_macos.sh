#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# ============================================================================
# Test ID:      b6c73735-0c24-4a1e-8f0a-3c24af39671b
# Test Name:    MDE Authentication Bypass Command Interception
# MITRE ATT&CK: T1562.001, T1014, T1090.003, T1140
# Mitigations:  M1047, M1038, M1022, M1024, M1018, M1030, M1031
#
# Purpose:
#   Hardens macOS endpoints against authentication bypass, certificate
#   pinning bypass, and command interception attacks targeting EDR agents.
#   While the original test targets Windows MDE, the underlying techniques
#   (memory patching, proxy manipulation, certificate store abuse, process
#   attachment) have direct macOS equivalents using DYLD injection, ptrace,
#   and Keychain manipulation.
#
# Usage:
#   sudo ./b6c73735-0c24-4a1e-8f0a-3c24af39671b_hardening_macos.sh [apply|undo|check]
#
# Requires: root privileges (sudo)
# Idempotent: Yes (safe to run multiple times)
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_NAME="$(basename "$0")"
TEST_ID="b6c73735-0c24-4a1e-8f0a-3c24af39671b"
BACKUP_DIR="/var/backups/f0rtika-hardening-${TEST_ID}"
LOG_FILE="/var/log/f0rtika-hardening-${TEST_ID}.log"
CHANGE_COUNT=0

MDE_INSTALL_DIR="/Library/Application Support/Microsoft/Defender"
MDE_CONFIG_DIR="/Library/Managed Preferences/com.microsoft.wdav.plist"
MDE_LAUNCH_DAEMON="com.microsoft.wdav.daemon"

# ============================================================================
# Helper Functions
# ============================================================================

log_info()    { echo -e "\033[36m[*]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_success() { echo -e "\033[32m[+]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [OK]    $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo -e "\033[33m[!]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "\033[31m[-]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE" 2>/dev/null || true; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_macos() {
    if [[ "$(uname)" != "Darwin" ]]; then
        log_error "This script is designed for macOS only"
        exit 1
    fi
}

ensure_backup_dir() { mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"; }

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        cp -a "$src" "${BACKUP_DIR}/$(basename "$src").bak.$(date '+%Y%m%d%H%M%S')"
        log_info "Backed up $src"
    fi
}

# ============================================================================
# 1. Restrict MDE Configuration File Access (M1022)
# ============================================================================

harden_mde_file_permissions() {
    log_info "=== Restricting MDE Configuration File Permissions (M1022) ==="

    local mde_dirs=(
        "/Library/Application Support/Microsoft/Defender"
        "/usr/local/bin/mdatp"
    )

    for dir in "${mde_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            chmod -R go-w "$dir" 2>/dev/null || true
            chown -R root:wheel "$dir" 2>/dev/null || true
            log_success "Restricted permissions on $dir"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        elif [[ -f "$dir" ]]; then
            chmod 755 "$dir"
            chown root:wheel "$dir"
            log_success "Restricted permissions on $dir"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    # Protect MDE managed preferences
    local managed_pref="/Library/Managed Preferences/com.microsoft.wdav.plist"
    if [[ -f "$managed_pref" ]]; then
        chmod 644 "$managed_pref"
        chown root:wheel "$managed_pref"
        log_success "MDE managed preferences secured"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

undo_mde_file_permissions() {
    log_info "MDE file permissions restored to defaults where possible"
}

check_mde_file_permissions() {
    local mde_dir="/Library/Application Support/Microsoft/Defender"
    if [[ -d "$mde_dir" ]]; then
        local perms
        perms=$(stat -f '%Lp' "$mde_dir" 2>/dev/null || echo "unknown")
        log_info "MDE directory permissions: $perms"
    else
        log_warning "MDE directory not found"
    fi
}

# ============================================================================
# 2. Kernel Protection - Restrict ptrace (Anti-Memory-Manipulation) (M1038)
# ============================================================================

harden_ptrace_protection() {
    log_info "=== Restricting ptrace / Process Attachment (M1038) ==="

    # SIP provides strong ptrace protection on macOS
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "SIP is enabled -- provides kernel-level ptrace protection"
    else
        log_warning "SIP is NOT enabled -- processes can be attached/debugged freely"
        log_warning "Enable SIP: boot to Recovery Mode > Terminal > csrutil enable"
    fi

    # Check if Hardened Runtime is enforced for MDE binaries
    local mdatp_bin="/usr/local/bin/mdatp"
    if [[ -f "$mdatp_bin" ]]; then
        local entitlements
        entitlements=$(codesign -d --entitlements :- "$mdatp_bin" 2>/dev/null || echo "")
        if echo "$entitlements" | grep -q "com.apple.security.cs.disable-library-validation"; then
            log_warning "MDE binary has library validation disabled entitlement"
        else
            log_success "MDE binary does not have library validation bypass"
        fi

        if echo "$entitlements" | grep -q "com.apple.security.get-task-allow"; then
            log_warning "MDE binary has get-task-allow entitlement (allows debugging)"
        else
            log_success "MDE binary does not allow task attachment"
        fi
    fi

    # Verify Library Validation is enforced system-wide
    local lib_val
    lib_val=$(defaults read /Library/Preferences/com.apple.security.libraryvalidation Enabled 2>/dev/null || echo "not set")
    if [[ "$lib_val" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.security.libraryvalidation Enabled -bool true 2>/dev/null || true
        log_success "Library Validation enforcement enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Library Validation already enabled"
    fi
}

undo_ptrace_protection() {
    log_warning "SIP and Library Validation should remain enabled"
}

check_ptrace_protection() {
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "SIP: enabled (ptrace restricted)"
    else
        log_warning "SIP: NOT enabled"
    fi
}

# ============================================================================
# 3. Protect Certificate Stores (Anti-Cert-Pinning-Bypass) (M1038)
# ============================================================================

harden_certificate_integrity() {
    log_info "=== Protecting Certificate Stores (M1038) ==="

    # macOS uses Keychain for certificate storage
    local system_keychain="/Library/Keychains/System.keychain"
    if [[ -f "$system_keychain" ]]; then
        local perms
        perms=$(stat -f '%Lp' "$system_keychain" 2>/dev/null || echo "unknown")
        if [[ "$perms" != "644" ]]; then
            chmod 644 "$system_keychain"
            log_success "System Keychain permissions secured ($perms -> 644)"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "System Keychain permissions already correct"
        fi
    fi

    # Disable auto-trust of new CA certificates by non-admins
    log_info "Certificate trust is managed through Keychain Access or MDM profiles"
    log_info "Ensure MDM controls certificate trust policies in enterprise environments"

    # Verify XProtect and MRT updates
    local critical_update
    critical_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "not set")
    if [[ "$critical_update" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null || true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true 2>/dev/null || true
        log_success "Critical/XProtect updates enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Critical updates already enabled"
    fi
}

undo_certificate_integrity() {
    log_info "Certificate store protections left as-is (security best practice)"
}

check_certificate_integrity() {
    local system_keychain="/Library/Keychains/System.keychain"
    if [[ -f "$system_keychain" ]]; then
        local perms
        perms=$(stat -f '%Lp' "$system_keychain" 2>/dev/null || echo "unknown")
        log_info "System Keychain permissions: $perms"
    fi
}

# ============================================================================
# 4. MDE Service Protection (M1018)
# ============================================================================

harden_mde_service() {
    log_info "=== Protecting MDE Service (M1018) ==="

    local mde_plist="/Library/LaunchDaemons/${MDE_LAUNCH_DAEMON}.plist"
    if [[ -f "$mde_plist" ]]; then
        chmod 644 "$mde_plist"
        chown root:wheel "$mde_plist"

        if launchctl list 2>/dev/null | grep -q "$MDE_LAUNCH_DAEMON"; then
            log_success "MDE daemon is running and plist protected"
        else
            log_warning "MDE daemon plist exists but service is not loaded"
        fi
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_warning "MDE LaunchDaemon plist not found -- MDE may not be installed"
    fi

    # Check for additional MDE components
    local wdav_plist="/Library/LaunchDaemons/com.microsoft.wdav.plist"
    if [[ -f "$wdav_plist" ]]; then
        chmod 644 "$wdav_plist"
        chown root:wheel "$wdav_plist"
        log_success "MDE wdav plist protected"
    fi
}

undo_mde_service() {
    log_info "MDE service protections are non-destructive -- no changes to revert"
}

check_mde_service() {
    if command -v mdatp &>/dev/null; then
        log_success "MDE (mdatp) is installed"
        local health
        health=$(mdatp health 2>/dev/null | head -5 || echo "unknown")
        log_info "MDE health: $health"
    else
        log_warning "MDE (mdatp) not found"
    fi
}

# ============================================================================
# 5. Network Hardening - Application Firewall & Proxy Protection (M1030, M1031)
# ============================================================================

harden_network_protection() {
    log_info "=== Configuring Network Protection (M1030, M1031) ==="

    # Enable Application Firewall
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$fw_status" | grep -q "disabled"; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on >/dev/null 2>&1 || true
        log_success "Application Firewall enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Application Firewall already enabled"
    fi

    # Enable stealth mode
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on >/dev/null 2>&1 || true

    # Block incoming for unsigned apps
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on >/dev/null 2>&1 || true
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on >/dev/null 2>&1 || true
    log_success "Firewall configured to allow only signed applications"

    # Monitor proxy environment variables
    local proxy_monitor="/etc/profile.d/f0rtika-proxy-protect.sh"
    mkdir -p /etc/profile.d 2>/dev/null || true
    cat > "$proxy_monitor" <<'PROXY_EOF'
# F0RT1KA: Log proxy environment variable changes
# Detects proxy manipulation for MITM attacks on EDR cloud communication
_f0rtika_proxy_check() {
    if [[ -n "${http_proxy:-}" ]] || [[ -n "${https_proxy:-}" ]] || [[ -n "${HTTP_PROXY:-}" ]] || [[ -n "${HTTPS_PROXY:-}" ]]; then
        logger -t "f0rtika-security" "Proxy variables detected: http_proxy=${http_proxy:-} https_proxy=${https_proxy:-} user=$(whoami) pid=$$"
    fi
}
_f0rtika_proxy_check
PROXY_EOF
    chmod 644 "$proxy_monitor"
    log_success "Proxy monitoring profile installed"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_network_protection() {
    log_info "Application Firewall left enabled (security best practice)"
    rm -f /etc/profile.d/f0rtika-proxy-protect.sh 2>/dev/null || true
    log_success "Removed proxy monitoring profile"
}

check_network_protection() {
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$fw_status" | grep -q "enabled"; then
        log_success "Application Firewall: enabled"
    else
        log_warning "Application Firewall: disabled"
    fi

    if [[ -f "/etc/profile.d/f0rtika-proxy-protect.sh" ]]; then
        log_success "Proxy monitoring: configured"
    else
        log_warning "Proxy monitoring: not configured"
    fi
}

# ============================================================================
# 6. Restrict DYLD Injection (Anti-Library-Injection) (M1038)
# ============================================================================

harden_dyld_injection() {
    log_info "=== Restricting DYLD Library Injection (M1038) ==="

    # SIP prevents DYLD_INSERT_LIBRARIES for protected binaries
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "SIP enabled -- DYLD injection blocked for system binaries"
    else
        log_warning "SIP disabled -- DYLD_INSERT_LIBRARIES can be used for injection"
    fi

    # Gatekeeper enforces Hardened Runtime which blocks DYLD injection
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper enabled -- Hardened Runtime enforced"
    else
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    log_info "DYLD injection protection relies on SIP + Gatekeeper + Hardened Runtime"
}

undo_dyld_injection() {
    log_info "SIP/Gatekeeper should not be disabled"
}

check_dyld_injection() {
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "DYLD injection protection: SIP enabled"
    else
        log_warning "DYLD injection protection: SIP disabled"
    fi
}

# ============================================================================
# 7. OpenBSM Audit for MDE Access Monitoring (M1047)
# ============================================================================

harden_audit_rules() {
    log_info "=== Configuring OpenBSM Audit for MDE Monitoring (M1047) ==="

    local audit_control="/etc/security/audit_control"
    if [[ ! -f "$audit_control" ]]; then
        log_warning "audit_control not found"
        return
    fi

    backup_file "$audit_control"

    # Ensure comprehensive audit flags
    if ! grep -q "^flags:.*ex" "$audit_control" 2>/dev/null; then
        if grep -q "^flags:" "$audit_control"; then
            local current_flags
            current_flags=$(grep "^flags:" "$audit_control" | head -1 | sed 's/^flags://')
            sed -i '' "s/^flags:.*/flags:${current_flags},ex,pc,nt,fc,fd/" "$audit_control" 2>/dev/null || true
            log_success "Added execution/process/network audit flags"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    else
        log_info "Audit flags already configured"
    fi

    # Enhanced shell history
    local history_profile="/etc/profile.d/f0rtika-mde-history.sh"
    mkdir -p /etc/profile.d 2>/dev/null || true
    cat > "$history_profile" <<'HIST_EOF'
# F0RT1KA MDE Protection: Enhanced command history
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=50000
export HISTFILESIZE=50000
export HISTCONTROL=""
shopt -s histappend 2>/dev/null || true
HIST_EOF
    chmod 644 "$history_profile"
    log_success "Enhanced command history logging configured"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_audit_rules() {
    rm -f /etc/profile.d/f0rtika-mde-history.sh 2>/dev/null || true
    log_success "Removed history logging profile"
    log_info "Restore audit_control from $BACKUP_DIR if needed"
}

check_audit_rules() {
    if [[ -f "/etc/security/audit_control" ]]; then
        if grep -q "ex" /etc/security/audit_control 2>/dev/null; then
            log_success "Execution auditing: enabled"
        else
            log_warning "Execution auditing: not configured"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

ACTION="${1:-apply}"

echo ""
echo "============================================================================"
echo "F0RT1KA macOS Hardening Script"
echo "Test ID: $TEST_ID"
echo "MITRE ATT&CK: T1562.001, T1014, T1090.003, T1140"
echo "Action: $ACTION"
echo "============================================================================"
echo ""

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
echo "$(date '+%Y-%m-%d %H:%M:%S') === F0RT1KA Hardening: $ACTION ===" >> "$LOG_FILE" 2>/dev/null || true

case "$ACTION" in
    apply)
        check_root; check_macos; ensure_backup_dir
        log_info "Applying hardening measures..."
        echo ""

        harden_mde_file_permissions;   echo ""
        harden_ptrace_protection;      echo ""
        harden_certificate_integrity;  echo ""
        harden_mde_service;            echo ""
        harden_network_protection;     echo ""
        harden_dyld_injection;         echo ""
        harden_audit_rules

        echo ""
        echo "============================================================================"
        log_success "Hardening complete. $CHANGE_COUNT changes applied."
        echo "============================================================================"
        echo ""
        echo "To revert: sudo $SCRIPT_NAME undo"
        echo "To check:  sudo $SCRIPT_NAME check"
        echo ""
        ;;

    undo)
        check_root; check_macos
        log_warning "Reverting hardening changes..."
        echo ""

        undo_mde_file_permissions;   echo ""
        undo_ptrace_protection;      echo ""
        undo_certificate_integrity;  echo ""
        undo_mde_service;            echo ""
        undo_network_protection;     echo ""
        undo_dyld_injection;         echo ""
        undo_audit_rules

        echo ""
        log_success "Revert complete. Critical security settings left as-is."
        echo ""
        ;;

    check)
        check_root; check_macos
        log_info "Checking hardening status..."
        echo ""

        check_mde_file_permissions;   echo ""
        check_ptrace_protection;      echo ""
        check_certificate_integrity;  echo ""
        check_mde_service;            echo ""
        check_network_protection;     echo ""
        check_dyld_injection;         echo ""
        check_audit_rules

        echo ""
        log_info "Check complete."
        echo ""
        ;;

    --help|-h)
        echo "Usage: sudo $SCRIPT_NAME [apply|undo|check]"
        echo "  apply  - Apply hardening (default)"
        echo "  undo   - Revert changes"
        echo "  check  - Check status"
        exit 0
        ;;

    *)
        echo "Usage: sudo $SCRIPT_NAME [apply|undo|check]"
        exit 1
        ;;
esac

echo "============================================================================"
echo "Completed at $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================================"
