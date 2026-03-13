#!/usr/bin/env bash
# ============================================================================
# DEFENSE GUIDANCE: macOS Hardening Script
# ============================================================================
# Test ID: 13c2d073-8e33-4fca-ab27-68f20c408ce9
# Test Name: APT33 Tickler Backdoor DLL Sideloading
# MITRE ATT&CK: T1566.001, T1574.002, T1547.001, T1053.005, T1036, T1071.001
# Created: 2026-03-13
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
#
# NOTE: The APT33 Tickler test targets Windows endpoints. This script provides
# cross-platform hardening for the equivalent macOS attack techniques:
# - Dylib hijacking (DYLD_INSERT_LIBRARIES abuse)
# - LaunchAgent/LaunchDaemon persistence
# - Binary masquerading / code signing enforcement
# - Outbound C2 port blocking via pf firewall
#
# ============================================================================

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
UNDO=false
DRY_RUN=false

# ============================================================================
# Parse Arguments
# ============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo)    UNDO=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $SCRIPT_NAME [--undo] [--dry-run]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ============================================================================
# Helper Functions
# ============================================================================

info()    { echo -e "\033[0;36m[INFO]\033[0m $1"; }
success() { echo -e "\033[0;32m[OK]\033[0m $1"; }
warn()    { echo -e "\033[0;33m[WARN]\033[0m $1"; }
error()   { echo -e "\033[0;31m[ERR]\033[0m $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (sudo)"
        exit 1
    fi
}

run_cmd() {
    if $DRY_RUN; then
        info "[DRY-RUN] Would execute: $*"
    else
        "$@"
    fi
}

# ============================================================================
# 1. Dylib Hijacking Protection (T1574.002 equivalent)
# ============================================================================

harden_dylib_loading() {
    info "=== Dylib Hijacking Protection (T1574.002) ==="

    if $UNDO; then
        info "Dylib protection changes are non-destructive - no revert needed"
        return
    fi

    # Check for DYLD_INSERT_LIBRARIES in environment files
    for f in /etc/profile /etc/bashrc /etc/zshrc; do
        if [[ -f "$f" ]] && grep -q "DYLD_INSERT_LIBRARIES\|DYLD_LIBRARY_PATH" "$f" 2>/dev/null; then
            warn "Found DYLD_INSERT_LIBRARIES or DYLD_LIBRARY_PATH in $f - review manually"
        fi
    done

    # Verify SIP (System Integrity Protection) is enabled
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        success "System Integrity Protection (SIP) is enabled"
    else
        warn "SIP is NOT fully enabled - this reduces dylib hijacking protection"
        warn "To enable SIP: Boot to Recovery Mode and run 'csrutil enable'"
    fi

    # Verify Gatekeeper is enabled
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        success "Gatekeeper is enabled"
    else
        warn "Gatekeeper is disabled - enable with: sudo spctl --master-enable"
        if ! $DRY_RUN; then
            run_cmd spctl --master-enable
            success "Gatekeeper enabled"
        fi
    fi

    # Check that Library Validation is enforced
    info "Library Validation enforcement prevents unsigned dylibs from loading"
    info "Ensure applications are signed with hardened runtime and Library Validation"
}

# ============================================================================
# 2. LaunchAgent/LaunchDaemon Persistence Hardening (T1547.001, T1053.005)
# ============================================================================

harden_launch_persistence() {
    info "=== LaunchAgent/LaunchDaemon Hardening (T1547.001, T1053.005) ==="

    if $UNDO; then
        info "LaunchAgent monitoring is non-destructive - no revert needed"
        return
    fi

    # Restrict permissions on LaunchDaemon/LaunchAgent directories
    local launch_dirs=(
        "/Library/LaunchDaemons"
        "/Library/LaunchAgents"
    )

    for dir in "${launch_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            run_cmd chmod 755 "$dir"
            run_cmd chown root:wheel "$dir"
            success "Secured permissions on $dir"
        fi
    done

    # List any non-Apple plists in launch directories for review
    info "Reviewing non-Apple LaunchDaemons/LaunchAgents:"
    for dir in "${launch_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local non_apple
            non_apple=$(find "$dir" -name "*.plist" ! -name "com.apple.*" 2>/dev/null || true)
            if [[ -n "$non_apple" ]]; then
                echo "$non_apple" | while read -r plist; do
                    warn "  Non-Apple plist: $plist"
                done
            else
                info "  No non-Apple plists in $dir"
            fi
        fi
    done

    # Check user LaunchAgents
    for user_dir in /Users/*/Library/LaunchAgents; do
        if [[ -d "$user_dir" ]]; then
            local user_plists
            user_plists=$(find "$user_dir" -name "*.plist" 2>/dev/null || true)
            if [[ -n "$user_plists" ]]; then
                info "  User LaunchAgents in $user_dir:"
                echo "$user_plists" | while read -r plist; do
                    info "    $plist"
                done
            fi
        fi
    done
}

# ============================================================================
# 3. C2 Port Blocking via pf Firewall (T1071.001)
# ============================================================================

block_c2_ports() {
    info "=== C2 Port Blocking via pf (T1071.001) ==="

    local pf_anchor_file="/etc/pf.anchors/f0rtika-c2-block"
    local pf_conf="/etc/pf.conf"

    if $UNDO; then
        if [[ -f "$pf_anchor_file" ]]; then
            run_cmd rm -f "$pf_anchor_file"
            warn "Removed pf anchor file"
        fi
        # Remove anchor reference from pf.conf
        if grep -q "f0rtika-c2-block" "$pf_conf" 2>/dev/null; then
            if ! $DRY_RUN; then
                sed -i '' '/f0rtika-c2-block/d' "$pf_conf"
                pfctl -f "$pf_conf" 2>/dev/null || true
            fi
            warn "Removed f0rtika anchor from pf.conf"
        fi
        return
    fi

    # Create pf anchor file to block APT33 C2 ports
    if ! $DRY_RUN; then
        cat > "$pf_anchor_file" << 'PFEOF'
# F0RT1KA APT33 Tickler C2 Port Blocking
# Block outbound connections on known Tickler C2 ports
block out quick proto tcp to any port 808
block out quick proto tcp to any port 880
PFEOF
        success "Created pf anchor file: $pf_anchor_file"
    fi

    # Add anchor to pf.conf if not already present
    if ! grep -q "f0rtika-c2-block" "$pf_conf" 2>/dev/null; then
        if ! $DRY_RUN; then
            echo "" >> "$pf_conf"
            echo "# F0RT1KA APT33 C2 port blocking" >> "$pf_conf"
            echo 'anchor "f0rtika-c2-block"' >> "$pf_conf"
            echo 'load anchor "f0rtika-c2-block" from "/etc/pf.anchors/f0rtika-c2-block"' >> "$pf_conf"
        fi
        success "Added anchor reference to pf.conf"
    else
        info "pf anchor already configured"
    fi

    # Reload pf
    if ! $DRY_RUN; then
        pfctl -f "$pf_conf" 2>/dev/null || warn "Failed to reload pf - may need manual reload"
        pfctl -e 2>/dev/null || true
        success "pf firewall reloaded with C2 port blocking"
    fi
}

# ============================================================================
# 4. Code Signing Enforcement (T1036)
# ============================================================================

harden_code_signing() {
    info "=== Code Signing Enforcement (T1036) ==="

    if $UNDO; then
        info "Code signing enforcement is non-destructive - no revert needed"
        return
    fi

    # Verify Gatekeeper assessment is strict
    info "Gatekeeper enforces code signing for applications"

    # Check XProtect status
    local xprotect_version
    xprotect_version=$(system_profiler SPInstallHistoryDataType 2>/dev/null | grep -i "xprotect" | head -1 || echo "unknown")
    info "XProtect status: $xprotect_version"

    # Enable automatic security updates
    if ! $DRY_RUN; then
        defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
        success "Automatic security updates enabled"
    fi

    # Verify notarization requirements
    info "Ensure all deployed software is notarized by Apple"
    info "Unsigned binaries will trigger Gatekeeper warnings"
}

# ============================================================================
# 5. Process and File Monitoring
# ============================================================================

setup_monitoring() {
    info "=== Process and File Monitoring ==="

    if $UNDO; then
        info "Monitoring is non-destructive - no revert needed"
        return
    fi

    # Check for endpoint security framework tools
    if command -v eslogger &>/dev/null; then
        info "eslogger available for Endpoint Security framework monitoring"
        info "Usage: eslogger exec create rename > /var/log/es_events.log &"
    fi

    # Enable audit logging
    local audit_conf="/etc/security/audit_control"
    if [[ -f "$audit_conf" ]]; then
        if ! grep -q "ex,pc,fc" "$audit_conf"; then
            warn "Consider adding exec, process, and file audit flags to $audit_conf"
            info "Recommended flags: lo,aa,ad,fd,fm,fc,cl,ex,pc"
        else
            info "Audit control already includes execution and file monitoring"
        fi
    fi

    # Check for osquery or Santa
    if command -v osqueryi &>/dev/null; then
        success "osquery is available for endpoint monitoring"
    elif [[ -d "/Applications/Santa.app" ]]; then
        success "Santa is available for binary allowlisting"
    else
        warn "No advanced endpoint monitoring found"
        info "Recommended: Install osquery or Google Santa for enhanced monitoring"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================"
echo "  APT33 Tickler - macOS Defense Hardening"
echo "  Test ID: 13c2d073-8e33-4fca-ab27-68f20c408ce9"
echo "============================================================"
echo ""

check_root

if $UNDO; then
    warn "REVERTING hardening changes..."
else
    info "APPLYING hardening settings..."
fi
echo ""

harden_dylib_loading
echo ""
harden_launch_persistence
echo ""
block_c2_ports
echo ""
harden_code_signing
echo ""
setup_monitoring
echo ""

echo "============================================================"
if $UNDO; then
    warn "Hardening reverted."
else
    success "Hardening complete."
fi
echo "============================================================"
echo ""
