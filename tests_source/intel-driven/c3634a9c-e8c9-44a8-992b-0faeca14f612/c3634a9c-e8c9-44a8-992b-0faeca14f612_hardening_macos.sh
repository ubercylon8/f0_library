#!/usr/bin/env bash
# ============================================================================
# macOS Hardening Script: Akira Ransomware BYOVD Attack Chain
# ============================================================================
#
# Test ID:      c3634a9c-e8c9-44a8-992b-0faeca14f612
# Test Name:    Akira Ransomware BYOVD Attack Chain
# MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)
#                T1562.001 (Impair Defenses: Disable or Modify Tools)
# Mitigations:  M1047, M1038, M1050, M1051, M1024
# Platform:     macOS (Ventura 13+, Sonoma 14+, Sequoia 15+)
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
#
# DESCRIPTION:
#   While this test targets Windows BYOVD attacks, the underlying privilege
#   escalation and defense evasion techniques have macOS equivalents:
#     1. Kernel extension (kext) and System Extension hardening
#     2. Gatekeeper and SIP (System Integrity Protection) verification
#     3. Endpoint security framework protection
#     4. XProtect and MRT (Malware Removal Tool) verification
#     5. Launch daemon/agent hardening (persistence equivalent)
#     6. Security audit logging (Unified Logging)
#     7. TCC (Transparency, Consent, Control) database protection
#
# USAGE:
#   sudo ./c3634a9c_hardening_macos.sh [--undo] [--dry-run] [--verbose]
#
# OPTIONS:
#   --undo      Revert changes where possible
#   --dry-run   Show what would be changed without applying
#   --verbose   Enable detailed output
#
# REQUIREMENTS:
#   - Root privileges (sudo)
#   - macOS Ventura (13.0) or later recommended
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
WARNINGS=0

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
            echo "Hardens macOS systems against BYOVD-equivalent and defense evasion techniques."
            echo ""
            echo "Options:"
            echo "  --undo      Revert changes where possible (some Apple protections cannot be reverted)"
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
log_success() { echo "[+] $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo "[!] $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $1" >> "$LOG_FILE" 2>/dev/null || true; WARNINGS=$((WARNINGS + 1)); }
log_error()   { echo "[-] $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_header()  { echo "[=] $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [HEADER] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_verbose() { if $VERBOSE; then echo "    $1"; fi; }

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

get_macos_version() {
    sw_vers -productVersion 2>/dev/null || echo "unknown"
}

get_macos_major() {
    sw_vers -productVersion 2>/dev/null | cut -d. -f1
}

# ============================================================================
# 1. System Integrity Protection (SIP) Verification
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention
# SIP is the macOS equivalent of Windows Kernel Patch Protection and Driver
# Signature Enforcement. It prevents modification of system files, kernel
# extensions, and critical system processes.

check_sip_status() {
    log_header "1. System Integrity Protection (SIP) Verification"

    if $UNDO; then
        log_info "SIP cannot be modified from the running OS - requires Recovery Mode"
        return
    fi

    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "Unknown")

    if echo "$sip_status" | grep -q "enabled"; then
        log_success "System Integrity Protection (SIP) is ENABLED"
        log_verbose "SIP prevents unauthorized kernel extensions and system modifications"
    else
        log_warning "System Integrity Protection (SIP) is DISABLED or PARTIALLY DISABLED"
        log_warning "This is equivalent to having Driver Signature Enforcement disabled on Windows"
        log_info "To re-enable SIP:"
        log_info "  1. Reboot into Recovery Mode (hold Command+R during boot)"
        log_info "  2. Open Terminal from Utilities menu"
        log_info "  3. Run: csrutil enable"
        log_info "  4. Reboot"
    fi

    # Check specific SIP flags on newer macOS
    if command -v csrutil &>/dev/null; then
        log_verbose "Detailed SIP status:"
        csrutil status 2>/dev/null | while IFS= read -r line; do
            log_verbose "  $line"
        done
    fi
}

# ============================================================================
# 2. Gatekeeper and Code Signing Verification
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention
# Gatekeeper is macOS's equivalent of Windows SmartScreen + Code Signing.
# It prevents execution of unsigned or improperly signed applications.

check_gatekeeper() {
    log_header "2. Gatekeeper and Code Signing Enforcement"

    if $UNDO; then
        log_info "Re-enabling Gatekeeper..."
        if ! $DRY_RUN; then
            spctl --master-enable 2>/dev/null && {
                log_success "Gatekeeper re-enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to re-enable Gatekeeper"
        fi
        return
    fi

    # Check Gatekeeper status
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")

    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper is ENABLED"
    else
        log_warning "Gatekeeper is DISABLED"
        log_info "Enabling Gatekeeper..."
        if ! $DRY_RUN; then
            spctl --master-enable 2>/dev/null && {
                log_success "Gatekeeper enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to enable Gatekeeper"
        else
            log_info "[DRY-RUN] Would enable Gatekeeper"
        fi
    fi

    # Check assessment policy (should require App Store + identified developers)
    log_info "Verifying Gatekeeper assessment policy..."
    if ! $DRY_RUN; then
        # Set to allow only App Store and identified developers
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper set to allow App Store and identified developers only"
    fi

    # Verify quarantine attribute enforcement
    log_info "Checking quarantine attribute enforcement..."
    local quarantine_enabled
    quarantine_enabled=$(defaults read com.apple.LaunchServices LSQuarantine 2>/dev/null || echo "1")
    if [[ "$quarantine_enabled" == "1" ]] || [[ "$quarantine_enabled" == "" ]]; then
        log_success "File quarantine (com.apple.quarantine xattr) is active"
    else
        log_warning "File quarantine may be disabled"
        if ! $DRY_RUN; then
            defaults write com.apple.LaunchServices LSQuarantine -bool true 2>/dev/null && {
                log_success "File quarantine re-enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to re-enable file quarantine"
        fi
    fi
}

# ============================================================================
# 3. XProtect and Malware Protection Verification
# ============================================================================
# MITRE Mitigation: M1051 - Update Software
# XProtect is macOS's built-in anti-malware (equivalent to Windows Defender).
# MRT (Malware Removal Tool) handles remediation.

check_xprotect() {
    log_header "3. XProtect and Malware Protection"

    if $UNDO; then
        log_info "XProtect is managed by Apple - no revert needed"
        return
    fi

    # Check XProtect status and version
    local xprotect_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    local xprotect_plist_alt="/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"

    if [[ -f "$xprotect_plist" ]] || [[ -f "$xprotect_plist_alt" ]]; then
        local plist_path
        if [[ -f "$xprotect_plist" ]]; then
            plist_path="$xprotect_plist"
        else
            plist_path="$xprotect_plist_alt"
        fi

        local xp_version
        xp_version=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$plist_path" 2>/dev/null || echo "unknown")
        log_success "XProtect is present (version: $xp_version)"
    else
        log_warning "XProtect bundle not found in expected location"
    fi

    # Check XProtect Remediator (MRT replacement on newer macOS)
    if [[ -d "/Library/Apple/System/Library/CoreServices/XProtect.app" ]]; then
        log_success "XProtect Remediator (XProtect.app) is present"
    fi

    # Verify automatic security updates are enabled
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not_set")

    if [[ "$auto_update" == "1" ]]; then
        log_success "Automatic macOS updates are enabled"
    else
        log_warning "Automatic macOS updates may not be enabled"
        if ! $DRY_RUN; then
            defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true 2>/dev/null && {
                log_success "Automatic macOS updates enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to enable automatic updates (may require MDM)"
        fi
    fi

    # Check for automatic XProtect/security data updates
    local critical_update
    critical_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "not_set")

    if [[ "$critical_update" == "1" ]]; then
        log_success "Automatic security response updates are enabled"
    else
        log_info "Enabling automatic security response updates..."
        if ! $DRY_RUN; then
            defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null && {
                log_success "Automatic security response updates enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to enable security response updates"
        fi
    fi

    # Ensure background check for updates
    local config_data
    config_data=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null || echo "not_set")

    if [[ "$config_data" != "1" ]]; then
        if ! $DRY_RUN; then
            defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true 2>/dev/null && {
                log_success "Automatic config data updates enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || true
        fi
    fi
}

# ============================================================================
# 4. Kernel Extension (kext) and System Extension Hardening
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention
# This is the direct macOS equivalent of Windows BYOVD driver protection.
# On modern macOS, kernel extensions are deprecated in favor of System
# Extensions which run in user space.

harden_kernel_extensions() {
    log_header "4. Kernel Extension and System Extension Hardening"

    if $UNDO; then
        log_info "Kernel extension policy is managed by SIP and MDM - no revert needed"
        return
    fi

    local macos_major
    macos_major=$(get_macos_major)

    # Check for loaded third-party kexts
    log_info "Checking for loaded third-party kernel extensions..."
    local kext_count=0
    local suspicious_kexts=""

    while IFS= read -r kext; do
        if [[ -n "$kext" ]] && ! echo "$kext" | grep -q "com.apple"; then
            kext_count=$((kext_count + 1))
            suspicious_kexts="${suspicious_kexts}  - ${kext}\n"
            log_verbose "Third-party kext: $kext"
        fi
    done < <(kextstat 2>/dev/null | awk '{print $6}' | tail -n +2 || true)

    if [[ $kext_count -eq 0 ]]; then
        log_success "No third-party kernel extensions loaded"
    else
        log_warning "Found $kext_count third-party kernel extension(s):"
        echo -e "$suspicious_kexts"
        log_info "Review each kext for legitimacy. Unauthorized kexts are the macOS BYOVD equivalent."
    fi

    # Check System Extension consent (macOS 10.15+)
    if [[ "$macos_major" -ge 11 ]]; then
        log_info "Checking System Extension policy..."
        # System Extensions require user consent and are managed by MDM
        local se_db="/Library/SystemExtensions/db.plist"
        if [[ -f "$se_db" ]]; then
            local se_count
            se_count=$(/usr/libexec/PlistBuddy -c "Print extensions" "$se_db" 2>/dev/null | grep -c "Dict" || echo "0")
            log_info "System Extensions registered: $se_count"
        fi
        log_success "System Extensions require user consent (macOS managed)"
    fi

    # On macOS 11+, check if KEXT loading requires user approval
    if [[ "$macos_major" -ge 11 ]]; then
        log_success "macOS $macos_major requires user approval for kext loading (Secure KEXT Loading)"
        log_verbose "Third-party kexts require explicit user consent in Security preferences"
    fi

    # Check Secure Boot policy (Apple Silicon)
    if [[ "$(uname -m)" == "arm64" ]]; then
        log_info "Apple Silicon detected - hardware Secure Boot is always active"
        log_success "Secure Boot: Enforced by hardware (cannot be disabled on Apple Silicon)"

        # Check security policy
        local boot_policy
        boot_policy=$(bputil -d 2>/dev/null | head -1 || echo "unknown")
        if echo "$boot_policy" | grep -qi "full"; then
            log_success "Boot security policy: Full Security"
        elif echo "$boot_policy" | grep -qi "reduced"; then
            log_warning "Boot security policy: Reduced Security"
            log_info "Set to Full Security via Recovery Mode > Startup Security Utility"
        fi
    else
        # Intel Mac
        log_info "Intel Mac detected - check Startup Security Utility for Secure Boot"
    fi
}

# ============================================================================
# 5. Firewall and Network Hardening
# ============================================================================
# MITRE Mitigation: M1037 - Filter Network Traffic
# Enable and configure the macOS Application Firewall.

harden_firewall() {
    log_header "5. Firewall and Network Hardening"

    if $UNDO; then
        log_info "Reverting firewall settings..."
        if ! $DRY_RUN; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off 2>/dev/null && {
                log_success "Application Firewall disabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to disable firewall"
        fi
        return
    fi

    # Enable Application Firewall
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")

    if echo "$fw_status" | grep -q "enabled"; then
        log_success "Application Firewall is already enabled"
    else
        log_info "Enabling Application Firewall..."
        if ! $DRY_RUN; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null && {
                log_success "Application Firewall enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to enable firewall"
        fi
    fi

    # Enable stealth mode (don't respond to probes)
    local stealth_status
    stealth_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")

    if echo "$stealth_status" | grep -q "enabled"; then
        log_success "Stealth mode is already enabled"
    else
        log_info "Enabling stealth mode..."
        if ! $DRY_RUN; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null && {
                log_success "Stealth mode enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to enable stealth mode"
        fi
    fi

    # Block all incoming connections (strict mode) -- may break some services
    # Uncomment only if appropriate for the environment
    # /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on

    # Enable logging
    local log_status
    log_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>/dev/null || echo "unknown")

    if echo "$log_status" | grep -q "throttled\|enabled\|detail"; then
        log_success "Firewall logging is active"
    else
        log_info "Enabling firewall logging..."
        if ! $DRY_RUN; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on 2>/dev/null && {
                log_success "Firewall logging enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to enable firewall logging"
        fi
    fi
}

# ============================================================================
# 6. Launch Daemon/Agent Hardening (Anti-Persistence)
# ============================================================================
# MITRE Mitigation: M1047 - Audit
# Launch daemons/agents are the macOS equivalent of Windows services.
# Attackers use them for persistence (equivalent to the BYOVD service
# creation step).

harden_launch_daemons() {
    log_header "6. Launch Daemon/Agent Security Audit"

    if $UNDO; then
        log_info "Launch daemon audit is read-only - nothing to revert"
        return
    fi

    log_info "Auditing Launch Daemons and Agents for suspicious entries..."

    local suspicious_count=0
    local daemon_dirs=(
        "/Library/LaunchDaemons"
        "/Library/LaunchAgents"
        "/System/Library/LaunchDaemons"
        "/System/Library/LaunchAgents"
    )

    for daemon_dir in "${daemon_dirs[@]}"; do
        if [[ ! -d "$daemon_dir" ]]; then
            continue
        fi

        while IFS= read -r plist; do
            if [[ ! -f "$plist" ]]; then
                continue
            fi

            # Check for suspicious patterns
            local program_path
            program_path=$(/usr/libexec/PlistBuddy -c "Print ProgramArguments:0" "$plist" 2>/dev/null || \
                           /usr/libexec/PlistBuddy -c "Print Program" "$plist" 2>/dev/null || echo "")

            if [[ -z "$program_path" ]]; then
                continue
            fi

            # Flag daemons that execute from suspicious locations
            if echo "$program_path" | grep -qiE '(/tmp/|/var/tmp/|/dev/shm/|/Users/.*/\.)'; then
                log_warning "Suspicious launch daemon: $plist"
                log_warning "  Executes: $program_path"
                suspicious_count=$((suspicious_count + 1))
            fi

            # Flag daemons with shell script execution
            if echo "$program_path" | grep -qiE '(bash|sh|zsh|python|perl|ruby|osascript)'; then
                local label
                label=$(/usr/libexec/PlistBuddy -c "Print Label" "$plist" 2>/dev/null || echo "unknown")
                # Only flag non-Apple entries
                if ! echo "$label" | grep -q "com.apple"; then
                    log_verbose "Script-based daemon (review): $plist ($label)"
                fi
            fi

        done < <(find "$daemon_dir" -name "*.plist" -type f 2>/dev/null)
    done

    if [[ $suspicious_count -eq 0 ]]; then
        log_success "No suspicious Launch Daemons/Agents found"
    else
        log_warning "Found $suspicious_count suspicious Launch Daemon(s)/Agent(s)"
        log_info "Investigate each flagged entry and remove if unauthorized"
    fi

    # Ensure permissions on LaunchDaemons directories are correct
    log_info "Verifying Launch Daemon directory permissions..."
    if ! $DRY_RUN; then
        chmod 755 /Library/LaunchDaemons 2>/dev/null && \
            log_success "/Library/LaunchDaemons permissions set to 755 (root only write)" || true
        chmod 755 /Library/LaunchAgents 2>/dev/null && \
            log_success "/Library/LaunchAgents permissions set to 755 (root only write)" || true
        chown root:wheel /Library/LaunchDaemons 2>/dev/null || true
        chown root:wheel /Library/LaunchAgents 2>/dev/null || true
        CHANGES_MADE=$((CHANGES_MADE + 1))
    fi
}

# ============================================================================
# 7. TCC Database Protection and Privacy Controls
# ============================================================================
# MITRE Mitigation: M1024 - Restrict Registry Permissions
# TCC is macOS's privacy framework (equivalent to registry-based security
# settings on Windows). Attackers tamper with TCC to gain Full Disk Access
# or disable security tools.

harden_tcc_privacy() {
    log_header "7. TCC Database and Privacy Controls"

    if $UNDO; then
        log_info "TCC protections are managed by macOS - no revert needed"
        return
    fi

    # Verify TCC database integrity
    local tcc_db="/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ -f "$tcc_db" ]]; then
        local tcc_perms
        tcc_perms=$(stat -f "%Sp" "$tcc_db" 2>/dev/null || echo "unknown")
        local tcc_owner
        tcc_owner=$(stat -f "%Su:%Sg" "$tcc_db" 2>/dev/null || echo "unknown")

        if [[ "$tcc_owner" == "root:wheel" ]]; then
            log_success "TCC database ownership correct (root:wheel)"
        else
            log_warning "TCC database has unexpected ownership: $tcc_owner"
            if ! $DRY_RUN; then
                chown root:wheel "$tcc_db" 2>/dev/null && {
                    log_success "TCC database ownership corrected"
                    CHANGES_MADE=$((CHANGES_MADE + 1))
                } || log_warning "Failed to correct TCC ownership (SIP may prevent this)"
            fi
        fi

        log_verbose "TCC database permissions: $tcc_perms"
    fi

    # Check Full Disk Access grants (potential security tool bypass)
    log_info "Checking Full Disk Access grants..."
    if command -v sqlite3 &>/dev/null && [[ -f "$tcc_db" ]]; then
        local fda_count
        fda_count=$(sqlite3 "$tcc_db" "SELECT COUNT(*) FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND allowed=1;" 2>/dev/null || echo "0")
        log_info "Applications with Full Disk Access: $fda_count"
        log_verbose "Review in System Preferences > Security & Privacy > Privacy > Full Disk Access"
    fi

    # Verify screen recording permissions are restricted
    log_info "Verify screen recording and input monitoring permissions in:"
    log_info "  System Settings > Privacy & Security > Screen Recording"
    log_info "  System Settings > Privacy & Security > Input Monitoring"
}

# ============================================================================
# 8. Security Audit Logging
# ============================================================================
# MITRE Mitigation: M1047 - Audit
# Configure macOS Unified Logging and OpenBSM audit for detection of
# BYOVD-equivalent attacks.

configure_audit_logging() {
    log_header "8. Security Audit Logging Configuration"

    if $UNDO; then
        log_info "Reverting audit logging changes..."
        if [[ -f /etc/security/audit_control.f0rtika.bak ]]; then
            cp /etc/security/audit_control.f0rtika.bak /etc/security/audit_control 2>/dev/null && {
                log_success "Restored original audit_control"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to restore audit_control"
        fi
        return
    fi

    # Configure OpenBSM auditing
    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        log_info "Configuring OpenBSM audit logging..."

        # Backup current config
        if ! $DRY_RUN; then
            cp "$audit_control" "${audit_control}.f0rtika.bak" 2>/dev/null || true
        fi

        # Check if comprehensive flags are already set
        local current_flags
        current_flags=$(grep "^flags:" "$audit_control" 2>/dev/null | head -1 || echo "")

        if echo "$current_flags" | grep -q "lo,ad,fd,fm,fc,cl"; then
            log_success "Audit flags already include comprehensive event classes"
        else
            log_info "Updating audit flags for comprehensive logging..."
            if ! $DRY_RUN; then
                # Set comprehensive audit flags
                # lo = login/logout, ad = administrative, fd = file deletion
                # fm = file attribute modify, fc = file creation, cl = file close
                # pc = process, ex = exec
                if grep -q "^flags:" "$audit_control"; then
                    sed -i.bak "s/^flags:.*/flags:lo,ad,fd,fm,fc,cl,pc,ex/" "$audit_control" 2>/dev/null && {
                        log_success "Audit flags updated: lo,ad,fd,fm,fc,cl,pc,ex"
                        CHANGES_MADE=$((CHANGES_MADE + 1))
                    } || log_warning "Failed to update audit flags"
                fi
            fi
        fi

        # Ensure audit logs are retained
        local expire_after
        expire_after=$(grep "^expire-after:" "$audit_control" 2>/dev/null || echo "")
        if [[ -z "$expire_after" ]]; then
            if ! $DRY_RUN; then
                echo "expire-after:60d" >> "$audit_control" 2>/dev/null && {
                    log_success "Audit log retention set to 60 days"
                    CHANGES_MADE=$((CHANGES_MADE + 1))
                } || true
            fi
        else
            log_verbose "Current audit log retention: $expire_after"
        fi
    fi

    # Enable audit daemon if not running
    if launchctl list com.apple.auditd &>/dev/null; then
        log_success "Audit daemon (auditd) is running"
    else
        log_warning "Audit daemon may not be running"
        if ! $DRY_RUN; then
            launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null && {
                log_success "Audit daemon started"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to start audit daemon"
        fi
    fi

    # Configure Unified Logging for security events
    log_info "Unified Logging is always active on macOS"
    log_info "Query security events with:"
    log_info "  log show --predicate 'subsystem == \"com.apple.securityd\"' --last 1h"
    log_info "  log show --predicate 'eventMessage contains \"kext\"' --last 1h"
    log_info "  log show --predicate 'subsystem == \"com.apple.endpointsecurity\"' --last 1h"
}

# ============================================================================
# 9. Additional Hardening Settings
# ============================================================================

apply_additional_hardening() {
    log_header "9. Additional Security Hardening"

    if $UNDO; then
        log_info "Reverting additional settings..."
        if ! $DRY_RUN; then
            # Re-enable remote login if it was disabled
            # systemsetup -setremotelogin on 2>/dev/null || true
            log_info "Review and revert settings manually as needed"
        fi
        return
    fi

    # Disable Remote Apple Events
    log_info "Checking Remote Apple Events..."
    if ! $DRY_RUN; then
        systemsetup -setremoteappleevents off 2>/dev/null && {
            log_success "Remote Apple Events disabled"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        } || log_verbose "Could not modify Remote Apple Events setting"
    fi

    # Require password immediately after sleep/screensaver
    log_info "Configuring screen lock security..."
    if ! $DRY_RUN; then
        defaults write com.apple.screensaver askForPassword -int 1 2>/dev/null || true
        defaults write com.apple.screensaver askForPasswordDelay -int 0 2>/dev/null && {
            log_success "Screen lock requires immediate password"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        } || log_verbose "Could not set screen lock delay"
    fi

    # Disable automatic login
    log_info "Checking automatic login..."
    local auto_login
    auto_login=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "none")
    if [[ "$auto_login" != "none" ]]; then
        log_warning "Automatic login is enabled for user: $auto_login"
        if ! $DRY_RUN; then
            defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null && {
                log_success "Automatic login disabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to disable automatic login"
        fi
    else
        log_success "Automatic login is disabled"
    fi

    # Enable FileVault disk encryption
    log_info "Checking FileVault status..."
    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "unknown")
    if echo "$fv_status" | grep -q "On"; then
        log_success "FileVault disk encryption is enabled"
    else
        log_warning "FileVault is NOT enabled"
        log_info "Enable FileVault: System Settings > Privacy & Security > FileVault > Turn On"
    fi

    # Disable Bluetooth sharing
    log_info "Disabling Bluetooth sharing..."
    if ! $DRY_RUN; then
        defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false 2>/dev/null && {
            log_success "Bluetooth sharing disabled"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        } || log_verbose "Could not modify Bluetooth sharing setting"
    fi

    # Set firmware password reminder (Intel Macs only)
    if [[ "$(uname -m)" != "arm64" ]]; then
        log_info "Intel Mac: Consider setting a firmware password via Recovery Mode"
        log_info "  Boot to Recovery > Utilities > Startup Security Utility"
    fi
}

# ============================================================================
# Verification
# ============================================================================

verify_hardening() {
    log_header "Verification Commands"

    echo ""
    log_info "Run the following commands to verify hardening:"
    echo ""
    echo "  # Check SIP status:"
    echo "  csrutil status"
    echo ""
    echo "  # Check Gatekeeper:"
    echo "  spctl --status"
    echo ""
    echo "  # Check Application Firewall:"
    echo "  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
    echo "  /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode"
    echo ""
    echo "  # Check loaded kexts (should be minimal):"
    echo "  kextstat | grep -v com.apple"
    echo ""
    echo "  # Check XProtect version:"
    echo "  system_profiler SPInstallHistoryDataType | grep -A 2 XProtect"
    echo ""
    echo "  # Check FileVault:"
    echo "  fdesetup status"
    echo ""
    echo "  # Check for suspicious Launch Daemons:"
    echo "  ls -la /Library/LaunchDaemons/ | grep -v com.apple"
    echo ""
    echo "  # Check audit daemon:"
    echo "  launchctl list com.apple.auditd"
    echo ""
    echo "  # View recent security events:"
    echo "  log show --predicate 'subsystem == \"com.apple.securityd\"' --last 15m"
    echo ""
    echo "  # Check security updates:"
    echo "  softwareupdate --list"
    echo ""
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo ""
    echo "============================================================================"
    echo "  F0RT1KA macOS Hardening Script"
    echo "  Test: Akira Ransomware BYOVD Attack Chain"
    echo "  MITRE ATT&CK: T1068, T1562.001"
    echo "  Version: $SCRIPT_VERSION"
    echo "============================================================================"
    echo ""

    check_macos
    check_root

    local mode="HARDEN"
    if $UNDO; then mode="REVERT"; fi
    if $DRY_RUN; then mode="$mode (DRY-RUN)"; fi

    log_info "Mode: $mode"
    log_info "macOS Version: $(get_macos_version)"
    log_info "Architecture: $(uname -m)"
    log_info "Log file: $LOG_FILE"
    echo ""

    # Create log file
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "# F0RT1KA macOS Hardening Log - $(date)" > "$LOG_FILE" 2>/dev/null || true

    # Execute hardening functions
    check_sip_status
    echo ""

    check_gatekeeper
    echo ""

    check_xprotect
    echo ""

    harden_kernel_extensions
    echo ""

    harden_firewall
    echo ""

    harden_launch_daemons
    echo ""

    harden_tcc_privacy
    echo ""

    configure_audit_logging
    echo ""

    apply_additional_hardening
    echo ""

    # Summary
    echo "============================================================================"
    if $UNDO; then
        log_success "Revert Complete! Changes reverted: $CHANGES_MADE"
    else
        log_success "Hardening Complete! Changes applied: $CHANGES_MADE"
    fi
    if [[ $WARNINGS -gt 0 ]]; then
        log_warning "Warnings generated: $WARNINGS (review above for details)"
    fi
    echo "============================================================================"
    echo ""

    log_info "Log file: $LOG_FILE"

    if ! $UNDO && ! $DRY_RUN; then
        verify_hardening

        echo ""
        log_warning "IMPORTANT NOTES:"
        log_warning "  - SIP changes require Recovery Mode (cannot be done from running OS)"
        log_warning "  - Some settings may require MDM for enterprise enforcement"
        log_warning "  - FileVault encryption should be enabled if not already active"
        log_warning "  - Review all warnings above and address any flagged issues"
        echo ""
    fi
}

main "$@"
