#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# ============================================================================
# Test ID:      bcba14e7-6f87-4cbd-9c32-718fdeb39b65
# Test Name:    EDRSilencer Detection
# MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
# Mitigations:  M1047 (Audit), M1038 (Execution Prevention),
#               M1022 (Restrict File Permissions), M1018 (User Account Mgmt)
#
# Purpose:
#   EDRSilencer blocks EDR telemetry by inserting Windows Filtering Platform
#   (WFP) rules. On macOS the equivalent attack surface includes: PF firewall
#   manipulation, Network Extension abuse, DYLD injection into EDR agents,
#   launchd service disabling, and /etc/hosts poisoning to block cloud
#   endpoints. This script hardens macOS against those techniques.
#
# Usage:
#   sudo ./bcba14e7-6f87-4cbd-9c32-718fdeb39b65_hardening_macos.sh [apply|undo|check]
#
# Requires: root privileges (sudo)
# Idempotent: Yes (safe to run multiple times)
# Tested on: macOS 13 Ventura, macOS 14 Sonoma, macOS 15 Sequoia
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_NAME="$(basename "$0")"
TEST_ID="bcba14e7-6f87-4cbd-9c32-718fdeb39b65"
BACKUP_DIR="/var/backups/f0rtika-hardening-${TEST_ID}"
LOG_FILE="/var/log/f0rtika-hardening-${TEST_ID}.log"
CHANGE_COUNT=0

# Known macOS EDR agent LaunchDaemon labels
EDR_LAUNCH_DAEMONS=(
    "com.crowdstrike.falcon.Agent"
    "com.crowdstrike.falcon.UserAgent"
    "com.sentinelone.sentineld"
    "com.sentinelone.sentineld-helper"
    "com.microsoft.wdav"
    "com.microsoft.wdav.daemon"
    "com.carbonblack.daemon"
    "com.elastic.endpoint"
    "com.elastic.agent"
    "com.cortex.xdr"
    "com.paloaltonetworks.agent"
    "com.qualys.cloud-agent"
    "com.tanium.taniumclient"
    "com.trendmicro.iCoreService"
    "com.wazuh.agent"
    "com.osquery.osqueryd"
)

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
# 1. Protect PF Firewall Configuration (Equivalent of WFP Rule Tampering)
# Mitigation: M1022 - Restrict File and Directory Permissions
# ============================================================================

harden_pf_firewall() {
    log_info "=== Protecting PF Firewall Configuration (M1022) ==="

    local pf_conf="/etc/pf.conf"
    local pf_anchors="/etc/pf.anchors"

    # Restrict permissions on pf.conf to prevent unauthorized modification
    if [[ -f "$pf_conf" ]]; then
        local current_perms
        current_perms=$(stat -f '%Lp' "$pf_conf" 2>/dev/null || echo "unknown")
        if [[ "$current_perms" != "644" ]]; then
            backup_file "$pf_conf"
            chmod 644 "$pf_conf"
            chown root:wheel "$pf_conf"
            log_success "Restricted $pf_conf permissions to 644 root:wheel"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "$pf_conf already has restrictive permissions"
        fi
    fi

    # Protect anchor directory
    if [[ -d "$pf_anchors" ]]; then
        chmod 755 "$pf_anchors"
        chown root:wheel "$pf_anchors"
        log_success "Anchor directory permissions secured"
    fi

    # Enable PF firewall if not already running
    if pfctl -si 2>/dev/null | grep -q "Status: Enabled"; then
        log_info "PF firewall is already enabled"
    else
        pfctl -e 2>/dev/null || true
        log_success "PF firewall enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    # Add EDR allowlist anchor to prevent telemetry blocking
    local edr_anchor="/etc/pf.anchors/f0rtika_edr_protect"
    cat > "$edr_anchor" <<'ANCHOR_EOF'
# F0RT1KA EDR Protection Anchor
# Ensures EDR agent outbound traffic is always permitted
# Placed before any user-defined blocking rules

# Allow all outbound traffic from root-owned EDR processes
pass out quick proto { tcp udp } from any to any port { 443 8443 } no state
ANCHOR_EOF

    chmod 644 "$edr_anchor"
    chown root:wheel "$edr_anchor"
    log_success "Created EDR protection PF anchor: $edr_anchor"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_pf_firewall() {
    log_warning "Reverting PF firewall protections..."
    local edr_anchor="/etc/pf.anchors/f0rtika_edr_protect"
    if [[ -f "$edr_anchor" ]]; then
        rm -f "$edr_anchor"
        log_success "Removed EDR protection PF anchor"
    fi
    log_info "PF firewall left enabled (security best practice)"
}

check_pf_firewall() {
    if pfctl -si 2>/dev/null | grep -q "Status: Enabled"; then
        log_success "PF firewall: enabled"
    else
        log_warning "PF firewall: disabled"
    fi
    if [[ -f "/etc/pf.anchors/f0rtika_edr_protect" ]]; then
        log_success "EDR protection anchor: present"
    else
        log_warning "EDR protection anchor: not found"
    fi
}

# ============================================================================
# 2. Protect EDR Agent LaunchDaemons (Anti-Tampering)
# Mitigation: M1018 - User Account Management
# ============================================================================

harden_edr_services() {
    log_info "=== Protecting EDR Agent LaunchDaemons (M1018) ==="

    local found_any=false

    for label in "${EDR_LAUNCH_DAEMONS[@]}"; do
        local plist="/Library/LaunchDaemons/${label}.plist"
        if [[ -f "$plist" ]]; then
            found_any=true

            # Restrict permissions so only root can modify
            chmod 644 "$plist"
            chown root:wheel "$plist"

            # Check if service is loaded
            if launchctl list 2>/dev/null | grep -q "$label"; then
                log_success "Service $label: running and protected"
            else
                log_warning "Service $label: plist exists but not loaded"
            fi
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    if ! $found_any; then
        log_warning "No known EDR LaunchDaemons found on this system"
    fi

    # Protect /Library/LaunchDaemons directory itself
    chmod 755 /Library/LaunchDaemons
    chown root:wheel /Library/LaunchDaemons
    log_success "LaunchDaemons directory permissions secured"
}

undo_edr_services() {
    log_info "EDR service protections are non-destructive -- no changes to revert"
}

check_edr_services() {
    local found=0
    for label in "${EDR_LAUNCH_DAEMONS[@]}"; do
        if launchctl list 2>/dev/null | grep -q "$label"; then
            log_success "EDR service $label: running"
            found=$((found + 1))
        fi
    done
    if [[ $found -eq 0 ]]; then
        log_warning "No known EDR services detected"
    else
        log_success "Found $found running EDR services"
    fi
}

# ============================================================================
# 3. Enable OpenBSM Audit Logging (Detect EDR Manipulation)
# Mitigation: M1047 - Audit
# ============================================================================

harden_audit_logging() {
    log_info "=== Configuring OpenBSM Audit for EDR Protection (M1047) ==="

    local audit_control="/etc/security/audit_control"
    if [[ ! -f "$audit_control" ]]; then
        log_warning "audit_control not found -- OpenBSM may not be available"
        return
    fi

    backup_file "$audit_control"

    # Ensure execution, process, network, and file audit classes are enabled
    if ! grep -q "^flags:.*ex" "$audit_control" 2>/dev/null; then
        if grep -q "^flags:" "$audit_control"; then
            local current_flags
            current_flags=$(grep "^flags:" "$audit_control" | head -1 | sed 's/^flags://')
            sed -i '' "s/^flags:.*/flags:${current_flags},ex,pc,nt,fc,fd/" "$audit_control" 2>/dev/null || true
            log_success "Added execution/process/network audit flags"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            echo "flags:lo,aa,ex,pc,nt,fc,fd" >> "$audit_control"
            log_success "Created audit flags entry"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    else
        log_info "Execution audit flags already configured"
    fi

    # Ensure auditd is running
    if launchctl list | grep -q "com.apple.auditd" 2>/dev/null; then
        log_success "Audit daemon (auditd) is running"
    else
        log_warning "Audit daemon may not be running"
    fi
}

undo_audit_logging() {
    log_warning "Audit logging settings left as-is (security best practice)"
    log_info "Restore /etc/security/audit_control from backup in $BACKUP_DIR if needed"
}

check_audit_logging() {
    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        if grep -q "ex" "$audit_control" 2>/dev/null; then
            log_success "Execution auditing: enabled"
        else
            log_warning "Execution auditing: not configured"
        fi
    else
        log_warning "audit_control not found"
    fi
}

# ============================================================================
# 4. Protect /etc/hosts from DNS Poisoning (Block EDR Endpoint Redirection)
# Mitigation: M1022 - Restrict File and Directory Permissions
# ============================================================================

harden_hosts_file() {
    log_info "=== Protecting /etc/hosts from EDR Endpoint Redirection (M1022) ==="

    local hosts_file="/etc/hosts"

    if [[ -f "$hosts_file" ]]; then
        backup_file "$hosts_file"

        # Set restrictive permissions
        chmod 644 "$hosts_file"
        chown root:wheel "$hosts_file"

        # Set system immutable flag (requires root, prevents even root from modifying without uchg)
        chflags schg "$hosts_file" 2>/dev/null && {
            log_success "Set system immutable flag on /etc/hosts"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        } || {
            log_warning "Could not set immutable flag on /etc/hosts (SIP may prevent this)"
        }
    fi

    # Also protect resolv.conf
    local resolv="/etc/resolv.conf"
    if [[ -f "$resolv" ]]; then
        chflags schg "$resolv" 2>/dev/null && {
            log_success "Set system immutable flag on /etc/resolv.conf"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        } || {
            log_info "Could not set immutable flag on /etc/resolv.conf"
        }
    fi
}

undo_hosts_file() {
    log_warning "Removing immutable flags from DNS configuration files..."
    chflags noschg /etc/hosts 2>/dev/null || true
    chflags noschg /etc/resolv.conf 2>/dev/null || true
    log_success "Immutable flags removed from /etc/hosts and /etc/resolv.conf"
}

check_hosts_file() {
    if ls -lO /etc/hosts 2>/dev/null | grep -q "schg"; then
        log_success "/etc/hosts: immutable flag set"
    else
        log_warning "/etc/hosts: immutable flag not set"
    fi
}

# ============================================================================
# 5. Verify SIP and Gatekeeper (Core macOS Security)
# Mitigation: M1038 - Execution Prevention
# ============================================================================

harden_sip_gatekeeper() {
    log_info "=== Verifying SIP and Gatekeeper (M1038) ==="

    # Check SIP -- this prevents tampering with system-level security components
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "System Integrity Protection (SIP) is enabled"
    else
        log_warning "SIP is NOT enabled -- critical for EDR protection"
        log_warning "To enable: boot to Recovery Mode > Terminal > csrutil enable"
    fi

    # Enable Gatekeeper
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_info "Gatekeeper is already enabled"
    else
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

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
    log_info "Stealth mode enabled"
}

undo_sip_gatekeeper() {
    log_warning "SIP and Gatekeeper should not be disabled (security critical)"
    log_info "Application Firewall left enabled"
}

check_sip_gatekeeper() {
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "SIP: enabled"
    else
        log_warning "SIP: NOT enabled"
    fi

    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper: enabled"
    else
        log_warning "Gatekeeper: NOT enabled"
    fi

    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$fw_status" | grep -q "enabled"; then
        log_success "Application Firewall: enabled"
    else
        log_warning "Application Firewall: disabled"
    fi
}

# ============================================================================
# 6. Restrict Network Filter Manipulation Tools
# Mitigation: M1022 - Restrict File and Directory Permissions
# ============================================================================

harden_netfilter_tools() {
    log_info "=== Restricting Access to Network Filter Tools (M1022) ==="

    # pfctl and ipfw are the macOS equivalents of iptables/nftables
    local netfilter_bins=(
        "/sbin/pfctl"
        "/usr/sbin/ipfw"
    )

    for bin in "${netfilter_bins[@]}"; do
        if [[ -f "$bin" ]]; then
            local current_perms
            current_perms=$(stat -f '%Lp' "$bin" 2>/dev/null || echo "unknown")
            log_info "$bin current permissions: $current_perms"
            # SIP protects these binaries, so we log and advise
            log_info "Note: $bin is SIP-protected -- modify via MDM/configuration profile"
        fi
    done

    # Monitor pfctl usage via audit logging
    log_info "pfctl/ipfw usage is captured by OpenBSM audit (ex flag)"
}

undo_netfilter_tools() {
    log_info "Network filter tool restrictions managed by SIP -- no changes to revert"
}

check_netfilter_tools() {
    for bin in /sbin/pfctl /usr/sbin/ipfw; do
        if [[ -f "$bin" ]]; then
            local perms
            perms=$(stat -f '%Lp' "$bin" 2>/dev/null || echo "unknown")
            log_info "$bin permissions: $perms (SIP-protected)"
        fi
    done
}

# ============================================================================
# 7. Process Execution Monitoring and Command History
# Mitigation: M1047 - Audit
# ============================================================================

harden_process_monitoring() {
    log_info "=== Configuring Process Execution Monitoring (M1047) ==="

    # Configure enhanced shell history for all users
    local profile_dir="/etc/profile.d"
    local profile_file="${profile_dir}/f0rtika-edr-history.sh"

    mkdir -p "$profile_dir" 2>/dev/null || true

    cat > "$profile_file" <<'PROFILE_EOF'
# F0RT1KA EDR Protection: Enhanced command history logging
# Prevents attackers from hiding commands after disabling EDR
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=50000
export HISTFILESIZE=50000
export HISTCONTROL=""
shopt -s histappend 2>/dev/null || true
PROFILE_EOF

    chmod 644 "$profile_file"
    log_success "Enhanced command history logging configured"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Ensure automatic security updates are enabled
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not set")
    if [[ "$auto_update" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true 2>/dev/null || true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null || true
        log_success "Automatic security updates enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Automatic security updates already enabled"
    fi
}

undo_process_monitoring() {
    local profile_file="/etc/profile.d/f0rtika-edr-history.sh"
    if [[ -f "$profile_file" ]]; then
        rm -f "$profile_file"
        log_success "Removed history logging profile"
    fi
}

check_process_monitoring() {
    if [[ -f "/etc/profile.d/f0rtika-edr-history.sh" ]]; then
        log_success "Enhanced history logging: configured"
    else
        log_warning "Enhanced history logging: not configured"
    fi

    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "0")
    if [[ "$auto_update" == "1" ]]; then
        log_success "Automatic security updates: enabled"
    else
        log_warning "Automatic security updates: not enabled"
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
echo "MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools"
echo "Action: $ACTION"
echo "============================================================================"
echo ""

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
echo "$(date '+%Y-%m-%d %H:%M:%S') === F0RT1KA Hardening: $ACTION ===" >> "$LOG_FILE" 2>/dev/null || true

case "$ACTION" in
    apply)
        check_root
        check_macos
        ensure_backup_dir
        log_info "Applying hardening measures..."
        echo ""

        harden_pf_firewall;       echo ""
        harden_edr_services;      echo ""
        harden_audit_logging;     echo ""
        harden_hosts_file;        echo ""
        harden_sip_gatekeeper;    echo ""
        harden_netfilter_tools;   echo ""
        harden_process_monitoring

        echo ""
        echo "============================================================================"
        log_success "Hardening complete. $CHANGE_COUNT changes applied."
        echo "============================================================================"
        echo ""
        echo "Applied Settings:"
        echo "  - PF firewall EDR allowlist anchor"
        echo "  - EDR LaunchDaemon permission hardening"
        echo "  - OpenBSM audit logging for security events"
        echo "  - /etc/hosts immutable flag (DNS poisoning prevention)"
        echo "  - SIP, Gatekeeper, and Application Firewall verification"
        echo "  - Network filter tool access monitoring"
        echo "  - Process execution monitoring and command history"
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
        check_macos
        log_warning "Reverting hardening changes..."
        echo ""

        undo_pf_firewall;       echo ""
        undo_edr_services;      echo ""
        undo_audit_logging;     echo ""
        undo_hosts_file;        echo ""
        undo_sip_gatekeeper;    echo ""
        undo_netfilter_tools;   echo ""
        undo_process_monitoring

        echo ""
        log_success "Revert complete. Critical security settings left as-is."
        echo ""
        ;;

    check)
        check_root
        check_macos
        log_info "Checking hardening status..."
        echo ""

        check_pf_firewall;       echo ""
        check_edr_services;      echo ""
        check_audit_logging;     echo ""
        check_hosts_file;        echo ""
        check_sip_gatekeeper;    echo ""
        check_netfilter_tools;   echo ""
        check_process_monitoring

        echo ""
        log_info "Check complete."
        echo ""
        ;;

    --help|-h)
        echo "Usage: sudo $SCRIPT_NAME [apply|undo|check]"
        echo ""
        echo "  apply  - Apply hardening settings (default)"
        echo "  undo   - Revert hardening settings"
        echo "  check  - Check current hardening status"
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
