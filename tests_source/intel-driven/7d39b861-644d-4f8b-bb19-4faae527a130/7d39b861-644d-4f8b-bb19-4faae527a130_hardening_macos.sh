#!/usr/bin/env bash
# ============================================================================
# macOS Hardening Script: Agrius Multi-Wiper Deployment Against Banking Infrastructure
# ============================================================================
#
# Test ID:      7d39b861-644d-4f8b-bb19-4faae527a130
# Test Name:    Agrius Multi-Wiper Deployment Against Banking Infrastructure
# MITRE ATT&CK: T1505.003 (Web Shell), T1543.003 (Windows Service),
#                T1562.001 (Disable or Modify Tools), T1485 (Data Destruction),
#                T1070.001 (Clear Windows Event Logs)
# Mitigations:  M1018, M1022, M1024, M1026, M1029, M1038, M1042, M1047, M1053
# Platform:     macOS (Ventura 13+, Sonoma 14+, Sequoia 15+)
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
#
# DESCRIPTION:
#   While this test targets Windows, the underlying destructive attack
#   techniques have macOS equivalents:
#     1. SIP (System Integrity Protection) verification -- kernel/driver defense
#     2. Gatekeeper and code signing enforcement -- execution prevention
#     3. XProtect and malware protection verification -- anti-malware status
#     4. Launch daemon/agent hardening -- persistence equivalent of Windows Services
#     5. Endpoint Security framework verification -- EDR protection
#     6. Unified Logging protection -- anti-forensics defense
#     7. TCC database protection -- transparency/consent controls
#     8. Time Machine and backup verification -- wiper resilience
#     9. Quarantine attribute enforcement -- webshell prevention
#
# USAGE:
#   sudo ./7d39b861-644d-4f8b-bb19-4faae527a130_hardening_macos.sh [--undo] [--dry-run] [--verbose]
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
readonly TEST_ID="7d39b861-644d-4f8b-bb19-4faae527a130"
readonly LOG_FILE="/var/log/f0rtika_agrius_hardening_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/var/backups/f0rtika_agrius_hardening"

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
            echo "Hardens macOS systems against Agrius-equivalent destructive attack techniques."
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
# SIP is macOS's equivalent of kernel protection, preventing unauthorized
# driver loading and system file modification (BYOVD prevention)

check_sip_status() {
    log_header "1. System Integrity Protection (SIP) Verification"

    if $UNDO; then
        log_info "SIP cannot be modified from the running OS -- requires Recovery Mode"
        return
    fi

    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "Unknown")

    if echo "$sip_status" | grep -q "enabled"; then
        log_success "System Integrity Protection (SIP) is ENABLED"
        log_verbose "SIP prevents unauthorized kernel extensions and system modifications"
        log_verbose "This provides equivalent protection to Windows HVCI against BYOVD attacks"
    else
        log_warning "System Integrity Protection (SIP) is DISABLED or PARTIALLY DISABLED"
        log_warning "This is equivalent to having Driver Signature Enforcement disabled on Windows"
        log_warning "Agrius-style kernel driver attacks are possible with SIP disabled"
        log_info "To re-enable SIP:"
        log_info "  1. Reboot into Recovery Mode (hold Command+R during boot, or power button on Apple Silicon)"
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
# 2. Gatekeeper and Code Signing Enforcement
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention
# Prevents execution of unsigned applications (webshell/tool prevention)

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
# 3. XProtect and Malware Protection
# ============================================================================
# MITRE Mitigation: M1051 - Update Software
# XProtect is macOS's built-in anti-malware (Defender equivalent)

check_xprotect() {
    log_header "3. XProtect and Malware Protection"

    if $UNDO; then
        log_info "XProtect is managed by Apple -- no revert needed"
        return
    fi

    # Check XProtect status
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

    # Check XProtect Remediator
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

    # Check for automatic security response updates (Rapid Security Response)
    local rsr_enabled
    rsr_enabled=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallSecurityUpdates 2>/dev/null || echo "not_set")
    if [[ "$rsr_enabled" == "1" ]]; then
        log_success "Rapid Security Response updates are enabled"
    else
        log_warning "Rapid Security Response updates may not be enabled"
        if ! $DRY_RUN; then
            defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallSecurityUpdates -bool true 2>/dev/null && {
                log_success "Rapid Security Response updates enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to enable RSR updates"
        fi
    fi
}

# ============================================================================
# 4. Endpoint Security Framework Verification
# ============================================================================
# MITRE Mitigation: M1024 - Restrict Registry Permissions (equivalent)
# Verifies EDR tools are registered with macOS Endpoint Security framework

check_endpoint_security() {
    log_header "4. Endpoint Security Framework Verification"

    if $UNDO; then
        log_info "Endpoint Security framework is managed by macOS -- no revert needed"
        return
    fi

    # Check for System Extensions (EDR providers)
    log_info "Checking for registered System Extensions (EDR providers)..."

    local extensions
    extensions=$(systemextensionsctl list 2>/dev/null || echo "unavailable")

    if echo "$extensions" | grep -q "activated enabled"; then
        log_success "System Extensions with Endpoint Security entitlement detected"
        if $VERBOSE; then
            echo "$extensions" | while IFS= read -r line; do
                log_verbose "  $line"
            done
        fi
    else
        log_warning "No active Endpoint Security system extensions found"
        log_info "Consider deploying an EDR solution with EndpointSecurity framework support"
    fi

    # Check Full Disk Access permissions
    log_info "Checking Full Disk Access for security tools..."
    log_info "Verify FDA permissions in: System Settings > Privacy & Security > Full Disk Access"
    log_verbose "EDR tools require FDA to monitor all file system operations"
}

# ============================================================================
# 5. Launch Daemon/Agent Hardening (Service Persistence Equivalent)
# ============================================================================
# MITRE Mitigation: M1028 - Operating System Configuration
# Restricts creation of LaunchDaemons/Agents (service persistence equivalent)

harden_launch_daemons() {
    log_header "5. Launch Daemon/Agent Hardening (T1543.003 Equivalent)"

    if $UNDO; then
        log_info "Launch daemon hardening revert not needed -- audit-only changes"
        return
    fi

    # Check for suspicious Launch Daemons
    log_info "Scanning for potentially suspicious LaunchDaemons..."

    local suspicious_count=0
    local daemon_dirs=("/Library/LaunchDaemons" "/Library/LaunchAgents" "$HOME/Library/LaunchAgents")

    for dir in "${daemon_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r plist; do
                local label
                label=$(/usr/libexec/PlistBuddy -c "Print Label" "$plist" 2>/dev/null || echo "unknown")
                local program
                program=$(/usr/libexec/PlistBuddy -c "Print ProgramArguments:0" "$plist" 2>/dev/null || \
                    /usr/libexec/PlistBuddy -c "Print Program" "$plist" 2>/dev/null || echo "unknown")

                # Check if binary exists and is signed
                if [[ "$program" != "unknown" ]] && [[ -f "$program" ]]; then
                    if ! codesign -v "$program" 2>/dev/null; then
                        log_warning "Unsigned binary in LaunchDaemon: $label -> $program"
                        suspicious_count=$((suspicious_count + 1))
                    fi
                fi
            done < <(find "$dir" -name "*.plist" -type f 2>/dev/null)
        fi
    done

    if [[ $suspicious_count -eq 0 ]]; then
        log_success "No suspicious unsigned LaunchDaemons/Agents found"
    else
        log_warning "Found $suspicious_count unsigned LaunchDaemons/Agents -- review recommended"
    fi

    # Restrict write access to LaunchDaemons directory
    if [[ -d "/Library/LaunchDaemons" ]]; then
        local current_perms
        current_perms=$(stat -f %Lp "/Library/LaunchDaemons" 2>/dev/null || echo "unknown")

        if [[ "$current_perms" != "755" ]] && [[ "$current_perms" != "unknown" ]]; then
            if ! $DRY_RUN; then
                chmod 755 /Library/LaunchDaemons
                log_success "Set /Library/LaunchDaemons permissions to 755 (was: $current_perms)"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            else
                log_info "[DRY-RUN] Would set /Library/LaunchDaemons to 755"
            fi
        else
            log_success "/Library/LaunchDaemons permissions are correct (755)"
        fi
    fi
}

# ============================================================================
# 6. Unified Logging Protection (Anti-Forensics Defense)
# ============================================================================
# MITRE Mitigation: M1029 - Remote Data Storage, M1047 - Audit
# Protects macOS Unified Logging from clearing (T1070.001 equivalent)

harden_logging() {
    log_header "6. Unified Logging Protection (T1070.001 Equivalent)"

    if $UNDO; then
        log_info "Logging protection revert -- restoring default settings"
        if ! $DRY_RUN; then
            defaults delete com.apple.syslog 2>/dev/null || true
            log_success "Syslog settings reverted"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    # Check if audit subsystem is running
    if launchctl list com.apple.auditd &>/dev/null 2>&1; then
        log_success "macOS audit subsystem (auditd) is running"
    else
        log_warning "macOS audit subsystem may not be running"
        log_info "Enable with: launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist"
    fi

    # Verify audit configuration
    if [[ -f /etc/security/audit_control ]]; then
        log_success "Audit control file exists: /etc/security/audit_control"

        # Check audit flags
        local audit_flags
        audit_flags=$(grep "^flags:" /etc/security/audit_control 2>/dev/null || echo "not_set")
        log_verbose "Current audit flags: $audit_flags"

        # Recommend comprehensive audit flags
        if ! echo "$audit_flags" | grep -q "lo"; then
            log_warning "Login/logout auditing (lo) not enabled"
            log_info "Add 'lo' to flags in /etc/security/audit_control"
        fi

        if ! echo "$audit_flags" | grep -q "ad"; then
            log_warning "Administrative events auditing (ad) not enabled"
            log_info "Add 'ad' to flags in /etc/security/audit_control"
        fi
    else
        log_warning "Audit control file not found"
    fi

    # Enable install.log and system.log retention
    log_info "Verifying log retention settings..."

    # Check asl.conf for retention
    if [[ -f /etc/asl.conf ]]; then
        log_success "ASL configuration file exists"
    fi

    # Recommend log forwarding
    log_info ""
    log_info "LOG PROTECTION RECOMMENDATIONS:"
    log_info "  1. Forward Unified Logs to SIEM via syslog or MDM"
    log_info "  2. Use 'log collect' periodically to archive logs to secure storage"
    log_info "  3. Monitor for 'log erase' commands (anti-forensics indicator)"
    log_info "  4. Configure MDM to restrict 'log erase' capability"
    log_info "  5. Use 'log show --predicate' to create detection queries"
    log_info ""
}

# ============================================================================
# 7. TCC Database and Privacy Protection
# ============================================================================
# MITRE Mitigation: M1022 - Restrict File and Directory Permissions
# Protects TCC database from unauthorized access

check_tcc_protection() {
    log_header "7. TCC Database and Privacy Protection"

    if $UNDO; then
        log_info "TCC protection is managed by macOS -- no revert needed"
        return
    fi

    # Check TCC database integrity
    local tcc_db="/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ -f "$tcc_db" ]]; then
        local tcc_perms
        tcc_perms=$(stat -f %Lp "$tcc_db" 2>/dev/null || echo "unknown")
        if [[ "$tcc_perms" == "600" ]] || [[ "$tcc_perms" == "644" ]]; then
            log_success "TCC database permissions are appropriate ($tcc_perms)"
        else
            log_warning "TCC database has unexpected permissions: $tcc_perms"
        fi
    else
        log_info "System TCC database location may vary by macOS version"
    fi

    # Verify Full Disk Access is restricted
    log_info "Verify that only authorized applications have Full Disk Access"
    log_info "Check: System Settings > Privacy & Security > Full Disk Access"
    log_verbose "Unauthorized FDA access could allow an attacker to read/destroy any file"
}

# ============================================================================
# 8. Time Machine and Backup Verification (Wiper Resilience)
# ============================================================================
# MITRE Mitigation: M1053 - Data Backup
# Verifies backup configuration for wiper attack resilience

check_backup_status() {
    log_header "8. Time Machine and Backup Verification (T1485 Resilience)"

    if $UNDO; then
        log_info "Backup verification -- no changes to revert"
        return
    fi

    # Check Time Machine status
    if command -v tmutil &>/dev/null; then
        local tm_status
        tm_status=$(tmutil status 2>/dev/null || echo "unknown")

        if tmutil destinationinfo &>/dev/null 2>&1; then
            log_success "Time Machine has configured backup destinations"

            # Check last backup time
            local last_backup
            last_backup=$(tmutil latestbackup 2>/dev/null || echo "unknown")
            if [[ "$last_backup" != "unknown" ]]; then
                log_success "Latest backup: $last_backup"
            else
                log_warning "Could not determine last backup time"
            fi

            # Check if auto-backup is enabled
            local auto_backup
            auto_backup=$(defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup 2>/dev/null || echo "not_set")
            if [[ "$auto_backup" == "1" ]]; then
                log_success "Automatic Time Machine backups are enabled"
            else
                log_warning "Automatic Time Machine backups may not be enabled"
                if ! $DRY_RUN; then
                    tmutil enable 2>/dev/null && {
                        log_success "Time Machine auto-backup enabled"
                        CHANGES_MADE=$((CHANGES_MADE + 1))
                    } || log_warning "Failed to enable Time Machine (may need destination first)"
                fi
            fi
        else
            log_warning "Time Machine has no configured backup destinations"
            log_info "Configure Time Machine: System Settings > General > Time Machine"
        fi

        # Check local snapshots
        local snapshots
        snapshots=$(tmutil listlocalsnapshots / 2>/dev/null | wc -l || echo "0")
        if [[ "$snapshots" -gt 0 ]]; then
            log_success "Found $snapshots local APFS snapshots (point-in-time recovery available)"
        else
            log_info "No local APFS snapshots found"
        fi
    else
        log_warning "tmutil not available -- Time Machine may not be installed"
    fi

    # Backup recommendations
    log_info ""
    log_info "WIPER RESILIENCE RECOMMENDATIONS:"
    log_info "  1. Configure Time Machine to an external or network drive"
    log_info "  2. Maintain at least one air-gapped backup copy"
    log_info "  3. Test backup restoration quarterly"
    log_info "  4. Enable APFS snapshots for quick rollback"
    log_info "  5. Use FileVault encryption to protect backup data"
    log_info "  6. Consider cloud backup (iCloud, CrashPlan, etc.) for redundancy"
    log_info ""
}

# ============================================================================
# 9. FileVault Disk Encryption Verification
# ============================================================================
# MITRE Mitigation: M1022 - Restrict File and Directory Permissions
# Ensures data at rest is encrypted

check_filevault() {
    log_header "9. FileVault Disk Encryption"

    if $UNDO; then
        log_info "FileVault status check only -- no changes to revert"
        return
    fi

    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "unknown")

    if echo "$fv_status" | grep -q "On"; then
        log_success "FileVault is ENABLED"
    else
        log_warning "FileVault is NOT enabled"
        log_info "Enable FileVault: System Settings > Privacy & Security > FileVault"
        log_info "Or via command: fdesetup enable"
        log_warning "Unencrypted disks are more vulnerable to offline data theft after wiper attacks"
    fi
}

# ============================================================================
# 10. Firewall Verification
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention (network level)

check_firewall() {
    log_header "10. macOS Firewall Verification"

    if $UNDO; then
        log_info "Firewall verification -- no changes to revert"
        return
    fi

    # Check Application Firewall status
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")

    if echo "$fw_status" | grep -q "enabled"; then
        log_success "macOS Application Firewall is ENABLED"
    else
        log_warning "macOS Application Firewall is DISABLED"
        if ! $DRY_RUN; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null && {
                log_success "Application Firewall enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_warning "Failed to enable Application Firewall"
        fi
    fi

    # Check stealth mode
    local stealth_mode
    stealth_mode=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")

    if echo "$stealth_mode" | grep -q "enabled"; then
        log_success "Stealth mode is ENABLED"
    else
        log_info "Stealth mode is not enabled (optional)"
        if ! $DRY_RUN; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null && {
                log_success "Stealth mode enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            } || log_verbose "Failed to enable stealth mode"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

log_header "============================================================================"
log_header " F0RT1KA macOS Hardening Script"
log_header " Test: Agrius Multi-Wiper Deployment Against Banking Infrastructure"
log_header " ID:   $TEST_ID"
log_header " MITRE: T1505.003, T1543.003, T1562.001, T1485, T1070.001"
log_header "============================================================================"
echo ""

check_root
check_macos

local_version=$(get_macos_version)
log_info "macOS version: $local_version"
echo ""

if $UNDO; then
    log_warning "UNDO MODE: Reverting changes where possible..."
    echo ""
elif $DRY_RUN; then
    log_info "DRY-RUN MODE: Showing changes without applying..."
    echo ""
else
    log_info "Applying hardening settings..."
    echo ""
fi

# Execute all hardening functions
check_sip_status
echo ""

check_gatekeeper
echo ""

check_xprotect
echo ""

check_endpoint_security
echo ""

harden_launch_daemons
echo ""

harden_logging
echo ""

check_tcc_protection
echo ""

check_backup_status
echo ""

check_filevault
echo ""

check_firewall
echo ""

# Summary
log_header "============================================================================"
log_header " Hardening Complete"
log_header "============================================================================"
echo ""

log_success "Changes made: $CHANGES_MADE"
if [[ $WARNINGS -gt 0 ]]; then
    log_warning "Warnings: $WARNINGS (review recommended)"
fi
log_info "Log file: $LOG_FILE"
echo ""

if ! $UNDO; then
    log_info "Post-hardening steps:"
    log_info "  1. Review System Settings > Privacy & Security for FDA and TCC"
    log_info "  2. Configure Time Machine to external or network backup"
    log_info "  3. Verify EDR System Extension is approved and activated"
    log_info "  4. Configure SIEM log forwarding for Unified Logs"
    log_info "  5. Enable MDM profile to restrict 'log erase' and 'csrutil disable'"
    log_info "  6. Test backup and restore procedures"
    echo ""
fi
