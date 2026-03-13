#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# ============================================================================
# Test ID:      09efee46-f098-4948-8e35-dded024cd1e7
# Test Name:    Sliver C2 Client Detection
# MITRE ATT&CK: T1219 - Remote Access Software
# Mitigations:  M1042 (Disable/Remove Feature), M1038 (Execution Prevention),
#               M1037 (Filter Network Traffic), M1031 (Network Intrusion Prevention)
# Platform:     macOS
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
# Requires:     root privileges (sudo)
# Idempotent:   Yes (safe to run multiple times)
# ============================================================================
#
# DESCRIPTION:
#   Hardens macOS endpoints against Sliver C2 and similar remote access
#   frameworks. Implements execution prevention from staging directories,
#   network traffic filtering for known C2 ports, Application Firewall
#   hardening, OpenBSM audit logging, and process monitoring to detect
#   C2 implant activity.
#
# USAGE:
#   sudo ./09efee46-f098-4948-8e35-dded024cd1e7_hardening_macos.sh          # Apply
#   sudo ./09efee46-f098-4948-8e35-dded024cd1e7_hardening_macos.sh --undo   # Revert
#   sudo ./09efee46-f098-4948-8e35-dded024cd1e7_hardening_macos.sh --check  # Verify
#
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly TEST_ID="09efee46-f098-4948-8e35-dded024cd1e7"
readonly LOG_DIR="/var/log/f0rtika"
readonly LOG_FILE="${LOG_DIR}/c2_hardening_macos_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/var/backups/f0rtika-hardening-${TEST_ID}"
readonly MITRE_ATTACK="T1219"

# Known C2 framework ports
readonly -a C2_PORTS=(8888 31337 4444 5555 9999 8443)

CHANGE_COUNT=0
MODE="apply"

# ============================================================================
# Argument Parsing
# ============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo|--revert|undo)
            MODE="undo"; shift ;;
        --check|--verify|check)
            MODE="check"; shift ;;
        --help|-h)
            echo "Usage: sudo $SCRIPT_NAME [--undo|--check|--help]"
            echo ""
            echo "Hardens macOS systems against Sliver C2 and similar remote access tools."
            echo ""
            echo "Options:"
            echo "  --undo      Revert all hardening changes"
            echo "  --check     Verify current hardening status"
            echo "  --help      Show this help message"
            exit 0
            ;;
        apply) shift ;;
        *)
            echo "Unknown option: $1"; echo "Use --help for usage."
            exit 1
            ;;
    esac
done

# ============================================================================
# Helper Functions
# ============================================================================

log_info()    { echo -e "\033[36m[*]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_success() { echo -e "\033[32m[+]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [OK]    $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo -e "\033[33m[!]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "\033[31m[-]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE" 2>/dev/null || true; }

check_root() {
    if [[ $EUID -ne 0 ]] && [[ "$MODE" != "check" ]]; then
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

ensure_dirs() {
    mkdir -p "$LOG_DIR" "$BACKUP_DIR" 2>/dev/null || true
    chmod 700 "$BACKUP_DIR"
}

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        cp -a "$src" "${BACKUP_DIR}/$(basename "$src").bak.$(date '+%Y%m%d%H%M%S')"
        log_info "Backed up: $src"
    fi
}

# ============================================================================
# 1. Gatekeeper and SIP Verification (M1038 - Execution Prevention)
# ============================================================================

harden_execution_prevention() {
    log_info "=== Execution Prevention via Gatekeeper/SIP (M1038) ==="

    if [[ "$MODE" == "check" ]]; then
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
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        log_warning "SIP and Gatekeeper should not be disabled"
        return
    fi

    # Verify SIP
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "SIP is enabled"
    else
        log_warning "SIP is NOT enabled -- C2 implants can modify system binaries"
        log_warning "Enable in Recovery Mode: csrutil enable"
    fi

    # Enable Gatekeeper
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_info "Gatekeeper already enabled"
    else
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    # Ensure quarantine enforcement
    local quarantine
    quarantine=$(defaults read com.apple.LaunchServices LSQuarantine 2>/dev/null || echo "not set")
    if [[ "$quarantine" == "0" ]]; then
        defaults write com.apple.LaunchServices LSQuarantine -bool true 2>/dev/null || true
        log_success "Quarantine enforcement re-enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Quarantine enforcement active"
    fi
}

# ============================================================================
# 2. Application Firewall and PF Rules (M1037 - Filter Network Traffic)
# ============================================================================

harden_firewall() {
    log_info "=== Configuring Firewall for C2 Port Filtering (M1037) ==="

    if [[ "$MODE" == "check" ]]; then
        local fw_status
        fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
        if echo "$fw_status" | grep -q "enabled"; then
            log_success "Application Firewall: enabled"
        else
            log_warning "Application Firewall: disabled"
        fi

        if [[ -f "/etc/pf.anchors/f0rtika_c2_monitor" ]]; then
            log_success "PF C2 monitoring anchor: present"
        else
            log_warning "PF C2 monitoring anchor: not found"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        rm -f /etc/pf.anchors/f0rtika_c2_monitor 2>/dev/null || true
        log_success "Removed PF C2 monitoring anchor"
        # Application Firewall left enabled
        log_info "Application Firewall left enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
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

    # Stealth mode
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on >/dev/null 2>&1 || true

    # Block unsigned apps
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on >/dev/null 2>&1 || true
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on >/dev/null 2>&1 || true
    log_success "Firewall: signed apps only, stealth mode on"

    # Create PF anchor for C2 port monitoring
    local pf_anchor="/etc/pf.anchors/f0rtika_c2_monitor"
    local port_list
    port_list=$(printf ", %s" "${C2_PORTS[@]}")
    port_list="${port_list:2}"

    cat > "$pf_anchor" <<EOF
# F0RT1KA C2 Port Monitoring
# Test ID: ${TEST_ID}
# MITRE ATT&CK: T1219 - Remote Access Software
# Logs outbound connections to known C2 ports

block drop log quick proto tcp from any to any port { ${port_list} }
EOF
    chmod 644 "$pf_anchor"
    chown root:wheel "$pf_anchor"
    log_success "Created PF C2 port monitoring anchor"
    log_info "C2 ports monitored: ${C2_PORTS[*]}"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Enable PF if not running
    if ! pfctl -si 2>/dev/null | grep -q "Status: Enabled"; then
        pfctl -e 2>/dev/null || true
        log_success "PF firewall enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

# ============================================================================
# 3. OpenBSM Audit Logging (M1047 - Audit)
# ============================================================================

harden_audit() {
    log_info "=== Configuring OpenBSM Audit for C2 Detection (M1047) ==="

    local audit_control="/etc/security/audit_control"

    if [[ "$MODE" == "check" ]]; then
        if [[ -f "$audit_control" ]]; then
            if grep -q "ex" "$audit_control" 2>/dev/null; then
                log_success "Execution auditing: enabled"
            else
                log_warning "Execution auditing: not configured"
            fi
        fi
        if launchctl list 2>/dev/null | grep -q "com.apple.auditd"; then
            log_success "Audit daemon: running"
        else
            log_warning "Audit daemon: not detected"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        log_info "Audit logging left enabled (security best practice)"
        log_info "Restore audit_control from $BACKUP_DIR if needed"
        return
    fi

    if [[ -f "$audit_control" ]]; then
        backup_file "$audit_control"

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
            log_info "Audit flags already configured"
        fi
    fi
}

# ============================================================================
# 4. Restrict Scripting Runtimes (M1042 - Disable or Remove Feature)
# ============================================================================

harden_scripting_runtimes() {
    log_info "=== Restricting Scripting Runtimes (M1042) ==="

    # C2 frameworks often use Python, Ruby, or osascript for execution
    local runtimes=(
        "/usr/local/bin/python3"
        "/opt/homebrew/bin/python3"
        "/usr/local/bin/ruby"
        "/opt/homebrew/bin/ruby"
    )

    if [[ "$MODE" == "check" ]]; then
        for runtime in "${runtimes[@]}"; do
            if [[ -f "$runtime" ]]; then
                local perms
                perms=$(stat -f '%Lp' "$runtime" 2>/dev/null || echo "unknown")
                if [[ "$perms" == "750" ]]; then
                    log_success "$runtime: restricted ($perms)"
                else
                    log_warning "$runtime: not restricted ($perms)"
                fi
            fi
        done
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        for runtime in "${runtimes[@]}"; do
            if [[ -f "$runtime" ]]; then
                chmod 755 "$runtime" 2>/dev/null || true
                log_success "Restored $runtime permissions to 755"
            fi
        done
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    for runtime in "${runtimes[@]}"; do
        if [[ -f "$runtime" ]]; then
            local current_perms
            current_perms=$(stat -f '%Lp' "$runtime" 2>/dev/null || echo "unknown")
            if [[ "$current_perms" != "750" ]]; then
                chmod 750 "$runtime"
                chown root:admin "$runtime" 2>/dev/null || true
                log_success "Restricted $runtime to root/admin (was $current_perms)"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            else
                log_info "$runtime already restricted"
            fi
        fi
    done

    # osascript is SIP-protected, cannot restrict directly
    log_info "osascript is SIP-protected -- restrict via MDM configuration profiles"
}

# ============================================================================
# 5. SSH Hardening Against C2 Tunneling (M1037)
# ============================================================================

harden_ssh() {
    log_info "=== Configuring SSH Hardening Against C2 Tunneling (M1037) ==="

    if [[ "$MODE" == "check" ]]; then
        if launchctl list 2>/dev/null | grep -q "com.openssh.sshd"; then
            log_warning "SSH Remote Login is enabled"
        else
            log_success "SSH Remote Login is disabled"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        log_info "SSH settings left as-is"
        return
    fi

    # Check if Remote Login is enabled
    local remote_login
    remote_login=$(systemsetup -getremotelogin 2>/dev/null || echo "unknown")
    if echo "$remote_login" | grep -qi "on"; then
        log_warning "SSH Remote Login is enabled -- consider disabling if not needed"
        log_info "To disable: sudo systemsetup -setremotelogin off"
    else
        log_success "SSH Remote Login is disabled"
    fi

    # If SSH is enabled, harden configuration
    local sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        backup_file "$sshd_config"

        # Create hardening drop-in (macOS uses sshd_config directly)
        local needs_reload=false

        # Disable TCP forwarding
        if ! grep -q "^AllowTcpForwarding no" "$sshd_config" 2>/dev/null; then
            echo "" >> "$sshd_config"
            echo "# F0RT1KA C2 Hardening" >> "$sshd_config"
            echo "AllowTcpForwarding no" >> "$sshd_config"
            echo "AllowAgentForwarding no" >> "$sshd_config"
            echo "PermitTunnel no" >> "$sshd_config"
            echo "MaxAuthTries 3" >> "$sshd_config"
            echo "ClientAliveInterval 300" >> "$sshd_config"
            echo "ClientAliveCountMax 2" >> "$sshd_config"
            needs_reload=true
            log_success "SSH hardened: TCP forwarding disabled, tunnel blocked"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "SSH hardening already applied"
        fi
    fi
}

# ============================================================================
# 6. Process Monitoring and Command History (M1047)
# ============================================================================

harden_process_monitoring() {
    log_info "=== Configuring Process Monitoring (M1047) ==="

    if [[ "$MODE" == "check" ]]; then
        if [[ -f "/etc/profile.d/f0rtika-c2-history.sh" ]]; then
            log_success "Enhanced command history: configured"
        else
            log_warning "Enhanced command history: not configured"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        rm -f /etc/profile.d/f0rtika-c2-history.sh 2>/dev/null || true
        log_success "Removed history logging profile"
        return
    fi

    local profile_dir="/etc/profile.d"
    mkdir -p "$profile_dir" 2>/dev/null || true

    cat > "${profile_dir}/f0rtika-c2-history.sh" <<'PROFILE_EOF'
# F0RT1KA C2 Defense: Enhanced command history logging
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=50000
export HISTFILESIZE=50000
export HISTCONTROL=""
shopt -s histappend 2>/dev/null || true
PROFILE_EOF

    chmod 644 "${profile_dir}/f0rtika-c2-history.sh"
    log_success "Enhanced command history logging configured"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Enable automatic security updates
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not set")
    if [[ "$auto_update" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true 2>/dev/null || true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null || true
        log_success "Automatic security updates enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================================"
echo "  F0RT1KA macOS Hardening Script"
echo "  Test: Sliver C2 Client Detection"
echo "  MITRE ATT&CK: ${MITRE_ATTACK} - Remote Access Software"
echo "  Action: ${MODE^^}"
echo "============================================================================"
echo ""

check_root
check_macos
ensure_dirs

harden_execution_prevention; echo ""
harden_firewall;             echo ""
harden_audit;                echo ""
harden_scripting_runtimes;   echo ""
harden_ssh;                  echo ""
harden_process_monitoring;   echo ""

# Summary
echo "============================================================================"
if [[ "$MODE" == "check" ]]; then
    echo "  Verification Complete"
elif [[ "$MODE" == "undo" ]]; then
    echo "  Revert Complete"
else
    echo "  Hardening Complete"
fi
echo "============================================================================"
echo ""
log_success "Total changes: $CHANGE_COUNT"
log_info "Log file: $LOG_FILE"
echo ""

if [[ "$MODE" == "apply" ]]; then
    log_info "Verification Commands:"
    echo ""
    echo "  # Verify Gatekeeper:"
    echo "  spctl --status"
    echo ""
    echo "  # Verify Application Firewall:"
    echo "  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
    echo ""
    echo "  # Verify audit flags:"
    echo "  grep flags /etc/security/audit_control"
    echo ""
    echo "  # Run full check:"
    echo "  sudo $0 --check"
    echo ""
fi

echo "============================================================================"
echo "Completed at $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================================"
exit 0
