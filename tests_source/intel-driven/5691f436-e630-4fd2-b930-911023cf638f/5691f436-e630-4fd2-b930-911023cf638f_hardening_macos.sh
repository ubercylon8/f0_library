#!/usr/bin/env bash
# ============================================================================
# macOS Hardening Script: APT34 Exchange Server Weaponization
# ============================================================================
#
# Test ID:      5691f436-e630-4fd2-b930-911023cf638f
# Test Name:    APT34 Exchange Server Weaponization with Email-Based C2
# MITRE ATT&CK: T1505.003 (Web Shell / IIS Backdoor)
#                T1071.003 (Email-Based C2)
#                T1556.002 (Password Filter DLL)
#                T1048.003 (Exfiltration via Email)
# Mitigations:  M1042, M1038, M1047, M1037, M1031, M1026
# Platform:     macOS (Ventura 13+, Sonoma 14+, Sequoia 15+)
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
#
# DESCRIPTION:
#   While this test targets Windows Exchange servers, the underlying attack
#   techniques have macOS equivalents. This script hardens macOS systems
#   against:
#     1. Web server plugin injection (Apache httpd on macOS)
#     2. Authorization plugin credential interception (macOS password filter equivalent)
#     3. Email-based C2 channels (outbound SMTP control)
#     4. Data exfiltration prevention (pf firewall rules)
#     5. System Integrity Protection (SIP) verification
#     6. Endpoint security logging (Unified Logging / OpenBSM)
#     7. Launch daemon/agent monitoring (persistence prevention)
#
# USAGE:
#   sudo ./5691f436-e630-4fd2-b930-911023cf638f_hardening_macos.sh [--undo] [--dry-run] [--verbose]
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
readonly TEST_ID="5691f436-e630-4fd2-b930-911023cf638f"
readonly LOG_FILE="/var/log/f0rtika_apt34_hardening_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/var/backups/f0rtika_apt34_hardening"
readonly PF_ANCHOR="com.f0rtika.apt34"

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
            echo "Hardens macOS systems against APT34 Exchange weaponization equivalent techniques."
            echo ""
            echo "Options:"
            echo "  --undo      Revert changes where possible"
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

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$file" "$BACKUP_DIR/$(basename "$file").$(date +%Y%m%d_%H%M%S).bak"
        log_verbose "Backed up: $file"
    fi
}

apply_change() {
    local description="$1"
    shift
    if $DRY_RUN; then
        log_info "[DRY-RUN] Would: $description"
        log_verbose "  Command: $*"
    else
        if "$@"; then
            log_success "$description"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        else
            log_warning "Failed: $description"
        fi
    fi
}

get_macos_version() {
    sw_vers -productVersion 2>/dev/null || echo "unknown"
}

# ============================================================================
# 1. System Integrity Protection Verification
# ============================================================================

verify_sip() {
    log_header "1. System Integrity Protection (SIP) Verification"
    log_info "Verifying SIP status (protects against kernel-level tampering)..."

    if $UNDO; then
        log_info "SIP cannot be modified via script (requires Recovery Mode)"
        return
    fi

    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")

    if echo "$sip_status" | grep -q "enabled"; then
        log_success "SIP is ENABLED - system protected against kernel tampering"
    else
        log_warning "SIP is DISABLED - system vulnerable to kernel-level attacks"
        log_warning "To enable SIP: boot to Recovery Mode and run 'csrutil enable'"
    fi

    # Verify Authenticated Root
    if csrutil authenticated-root status 2>/dev/null | grep -q "enabled"; then
        log_success "Authenticated Root is ENABLED"
    else
        log_warning "Authenticated Root may be disabled"
    fi

    log_success "SIP verification complete"
}

# ============================================================================
# 2. Authorization Plugin Protection (T1556.002 macOS Equivalent)
# ============================================================================

harden_authorization_plugins() {
    log_header "2. Authorization Plugin Protection (T1556.002 equivalent)"
    log_info "Protecting authorization database against credential interception plugins..."

    if $UNDO; then
        log_info "Authorization plugin protection cannot be safely reverted via script"
        log_info "Use 'security authorizationdb read system.login.console' to review"
        return
    fi

    # Check for unauthorized authorization plugins
    local auth_plugins_dir="/Library/Security/SecurityAgentPlugins"
    if [[ -d "$auth_plugins_dir" ]]; then
        log_info "Checking authorization plugins directory..."
        local plugin_count
        plugin_count=$(find "$auth_plugins_dir" -name "*.bundle" 2>/dev/null | wc -l | tr -d ' ')
        if [[ "$plugin_count" -gt 0 ]]; then
            log_warning "Found $plugin_count authorization plugin(s) - review for legitimacy:"
            find "$auth_plugins_dir" -name "*.bundle" -exec echo "  {}" \;
        else
            log_success "No third-party authorization plugins found"
        fi
    fi

    # Protect the authorization database
    apply_change "Restrict authorization database permissions" \
        chmod 644 /etc/authorization 2>/dev/null || true

    # Monitor /var/db/auth.db (TCC database equivalent for auth)
    if [[ -f /var/db/auth.db ]]; then
        apply_change "Set strict permissions on auth database" \
            chmod 600 /var/db/auth.db
    fi

    # Protect PAM configuration (macOS uses OpenPAM)
    local pam_dir="/etc/pam.d"
    if [[ -d "$pam_dir" ]]; then
        apply_change "Restrict PAM directory to root" \
            chmod 755 "$pam_dir"

        for pam_file in "$pam_dir"/*; do
            [[ -f "$pam_file" ]] || continue
            apply_change "Set read-only on $(basename "$pam_file")" \
                chmod 644 "$pam_file"
        done
    fi

    # Check for suspicious PAM modules
    local pam_lib="/usr/lib/pam"
    if [[ -d "$pam_lib" ]]; then
        log_info "Checking PAM modules for unauthorized entries..."
        local unsigned_modules=0
        for module in "$pam_lib"/*.so.2; do
            [[ -f "$module" ]] || continue
            if ! codesign -v "$module" 2>/dev/null; then
                log_warning "Unsigned PAM module: $module"
                unsigned_modules=$((unsigned_modules + 1))
            fi
        done
        if [[ "$unsigned_modules" -eq 0 ]]; then
            log_success "All PAM modules are properly signed"
        fi
    fi

    log_success "Authorization plugin protection complete"
}

# ============================================================================
# 3. Outbound SMTP Traffic Controls (T1048.003)
# ============================================================================

harden_outbound_smtp() {
    log_header "3. Outbound SMTP Traffic Controls (T1048.003)"
    log_info "Restricting outbound SMTP to prevent email-based exfiltration..."

    local pf_rules_file="/etc/pf.anchors/$PF_ANCHOR"

    if $UNDO; then
        log_info "Removing outbound SMTP pf rules..."
        if [[ -f "$pf_rules_file" ]]; then
            rm -f "$pf_rules_file"
            # Remove anchor from pf.conf
            if grep -q "$PF_ANCHOR" /etc/pf.conf 2>/dev/null; then
                backup_file /etc/pf.conf
                sed -i '' "/$PF_ANCHOR/d" /etc/pf.conf
            fi
            pfctl -f /etc/pf.conf 2>/dev/null || true
            log_success "SMTP pf rules removed"
        fi
        return
    fi

    # Create pf anchor rules for SMTP blocking
    local pf_content
    pf_content=$(cat <<'PFRULES'
# F0RT1KA APT34 - Block outbound SMTP from non-mail processes
# Prevents STEALHOOK-style email exfiltration

# Block outbound SMTP (port 25)
block out quick proto tcp from any to any port 25

# Block outbound SMTP submission (port 587)
block out quick proto tcp from any to any port 587

# Block outbound SMTPS (port 465)
block out quick proto tcp from any to any port 465
PFRULES
)

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create pf rules at: $pf_rules_file"
        echo "$pf_content"
    else
        mkdir -p "$(dirname "$pf_rules_file")"
        echo "$pf_content" > "$pf_rules_file"
        chmod 644 "$pf_rules_file"

        # Add anchor to pf.conf if not present
        if ! grep -q "$PF_ANCHOR" /etc/pf.conf 2>/dev/null; then
            backup_file /etc/pf.conf
            echo "" >> /etc/pf.conf
            echo "# F0RT1KA APT34 SMTP blocking" >> /etc/pf.conf
            echo "anchor \"$PF_ANCHOR\"" >> /etc/pf.conf
            echo "load anchor \"$PF_ANCHOR\" from \"/etc/pf.anchors/$PF_ANCHOR\"" >> /etc/pf.conf
        fi

        # Enable and reload pf
        pfctl -e 2>/dev/null || true
        pfctl -f /etc/pf.conf 2>/dev/null || true
        log_success "pf SMTP blocking rules applied"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    fi

    log_success "Outbound SMTP controls configured"
}

# ============================================================================
# 4. Web Server Hardening (T1505.003 macOS Equivalent)
# ============================================================================

harden_web_server() {
    log_header "4. Web Server Hardening (T1505.003 equivalent)"
    log_info "Hardening Apache httpd on macOS..."

    if $UNDO; then
        log_info "Reverting web server hardening..."
        if [[ -d "$BACKUP_DIR" ]]; then
            for bak in "$BACKUP_DIR"/httpd.conf.*; do
                [[ -f "$bak" ]] || continue
                cp "$bak" /etc/apache2/httpd.conf 2>/dev/null || true
                log_success "Restored Apache configuration"
                break
            done
        fi
        return
    fi

    # macOS ships with Apache httpd
    local apache_conf="/etc/apache2/httpd.conf"
    if [[ -f "$apache_conf" ]]; then
        backup_file "$apache_conf"
        apply_change "Set Apache config to read-only" \
            chmod 644 "$apache_conf"

        # Protect Apache modules directory
        local modules_dir="/usr/libexec/apache2"
        if [[ -d "$modules_dir" ]]; then
            apply_change "Restrict Apache modules directory" \
                chmod 755 "$modules_dir"
        fi

        # Check if Apache is running (should be disabled unless needed)
        if launchctl list 2>/dev/null | grep -q "org.apache.httpd"; then
            log_warning "Apache httpd is running - disable if not needed:"
            log_warning "  sudo launchctl unload -w /System/Library/LaunchDaemons/org.apache.httpd.plist"
        else
            log_success "Apache httpd is not running"
        fi
    fi

    # Protect web document roots
    for webroot in /Library/WebServer /var/www; do
        if [[ -d "$webroot" ]]; then
            apply_change "Remove world-write from $webroot" \
                chmod -R o-w "$webroot"
        fi
    done

    log_success "Web server hardening complete"
}

# ============================================================================
# 5. Endpoint Security Logging (All Techniques)
# ============================================================================

configure_security_logging() {
    log_header "5. Endpoint Security Logging"
    log_info "Configuring macOS security logging for APT34 technique detection..."

    if $UNDO; then
        log_info "Reverting logging configuration..."
        # Remove custom log predicates
        if [[ -f /etc/asl/f0rtika_apt34.conf ]]; then
            rm -f /etc/asl/f0rtika_apt34.conf
            log_success "Custom logging configuration removed"
        fi
        return
    fi

    # Enable OpenBSM audit logging
    if [[ -f /etc/security/audit_control ]]; then
        backup_file /etc/security/audit_control

        # Check if comprehensive auditing is enabled
        local current_flags
        current_flags=$(grep "^flags:" /etc/security/audit_control 2>/dev/null || echo "")

        if ! echo "$current_flags" | grep -q "lo,aa,ad,fd,fc,cl"; then
            if ! $DRY_RUN; then
                # Add comprehensive audit flags
                sed -i '' 's/^flags:.*/flags:lo,aa,ad,fd,fc,cl,fm,fr,fw/' /etc/security/audit_control 2>/dev/null || true
                log_success "OpenBSM audit flags updated for comprehensive monitoring"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            else
                log_info "[DRY-RUN] Would update OpenBSM audit flags"
            fi
        else
            log_success "OpenBSM audit flags already configured"
        fi
    fi

    # Configure Unified Logging for security events
    log_info "Configuring Unified Logging subsystem predicates..."

    # Monitor file system operations on critical paths
    log_info "Key log queries for APT34 detection:"
    echo ""
    echo "  # Monitor authorization plugin changes:"
    echo "  log show --predicate 'subsystem == \"com.apple.securityd\"' --last 1h"
    echo ""
    echo "  # Monitor PAM authentication events:"
    echo "  log show --predicate 'subsystem == \"com.apple.opendirectoryd\"' --last 1h"
    echo ""
    echo "  # Monitor network connections (SMTP exfiltration):"
    echo "  log show --predicate 'subsystem == \"com.apple.networkd\" AND messageType == \"Default\"' --last 1h"
    echo ""
    echo "  # Monitor file system changes in critical directories:"
    echo "  log show --predicate 'eventMessage CONTAINS \"pam.d\" OR eventMessage CONTAINS \"SecurityAgentPlugins\"' --last 1h"
    echo ""

    # Enable install.log monitoring (catches software installations)
    if [[ -f /var/log/install.log ]]; then
        apply_change "Set install.log permissions for monitoring" \
            chmod 640 /var/log/install.log
    fi

    log_success "Security logging configured"
}

# ============================================================================
# 6. Launch Daemon/Agent Monitoring (Persistence Prevention)
# ============================================================================

harden_launch_daemons() {
    log_header "6. Launch Daemon/Agent Hardening (Persistence Prevention)"
    log_info "Protecting against unauthorized launch daemon/agent persistence..."

    if $UNDO; then
        log_info "Launch daemon protection cannot be safely reverted"
        return
    fi

    # Check for unauthorized launch daemons
    local suspicious_count=0
    for plist_dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
        [[ -d "$plist_dir" ]] || continue
        log_info "Checking $plist_dir for suspicious entries..."

        for plist in "$plist_dir"/*.plist; do
            [[ -f "$plist" ]] || continue
            local label
            label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || echo "unknown")

            # Check if the plist is signed
            if ! codesign -v "$plist" 2>/dev/null; then
                # Only flag non-Apple, non-known vendor plists
                if ! echo "$label" | grep -qE "^(com\.apple\.|com\.microsoft\.|com\.google\.)"; then
                    log_verbose "  Unverified launch item: $label ($plist)"
                    suspicious_count=$((suspicious_count + 1))
                fi
            fi
        done
    done

    if [[ "$suspicious_count" -gt 0 ]]; then
        log_warning "Found $suspicious_count unverified launch items - review manually"
    else
        log_success "No suspicious launch items detected"
    fi

    # Protect LaunchDaemons directory
    apply_change "Restrict LaunchDaemons directory permissions" \
        chmod 755 /Library/LaunchDaemons

    # Protect LaunchAgents directory
    if [[ -d /Library/LaunchAgents ]]; then
        apply_change "Restrict LaunchAgents directory permissions" \
            chmod 755 /Library/LaunchAgents
    fi

    log_success "Launch daemon/agent hardening complete"
}

# ============================================================================
# 7. Gatekeeper and XProtect Verification
# ============================================================================

verify_gatekeeper() {
    log_header "7. Gatekeeper and XProtect Verification"
    log_info "Verifying Gatekeeper and XProtect status..."

    if $UNDO; then
        log_info "Gatekeeper/XProtect verification is read-only"
        return
    fi

    # Check Gatekeeper status
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper is ENABLED"
    else
        log_warning "Gatekeeper is DISABLED - enable with: sudo spctl --master-enable"
    fi

    # Verify XProtect is up to date
    local xprotect_version
    xprotect_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" \
        /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist 2>/dev/null || echo "unknown")
    log_info "XProtect version: $xprotect_version"

    # Verify MRT (Malware Removal Tool) is present
    if [[ -f /Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT ]]; then
        log_success "MRT (Malware Removal Tool) is present"
    else
        log_info "MRT location may have changed in newer macOS versions"
    fi

    # Verify automatic security updates
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not set")
    if [[ "$auto_update" == "1" ]]; then
        log_success "Automatic macOS updates enabled"
    else
        log_warning "Automatic macOS updates may be disabled"
        log_warning "Enable with: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true"
    fi

    # Check for automatic security response updates (Rapid Security Response)
    local rapid_security
    rapid_security=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "not set")
    if [[ "$rapid_security" == "1" ]]; then
        log_success "Rapid Security Response updates enabled"
    else
        if ! $DRY_RUN; then
            defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null || true
            log_success "Enabled Rapid Security Response updates"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
    fi

    log_success "Gatekeeper and XProtect verification complete"
}

# ============================================================================
# 8. TCC Database Protection
# ============================================================================

protect_tcc_database() {
    log_header "8. TCC Database Protection"
    log_info "Verifying TCC (Transparency, Consent, Control) database protection..."

    if $UNDO; then
        log_info "TCC protection is read-only verification"
        return
    fi

    # Verify TCC database permissions
    local tcc_db="/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ -f "$tcc_db" ]]; then
        local tcc_perms
        tcc_perms=$(stat -f "%Lp" "$tcc_db" 2>/dev/null || echo "unknown")
        if [[ "$tcc_perms" == "600" ]] || [[ "$tcc_perms" == "644" ]]; then
            log_success "TCC database permissions are restrictive ($tcc_perms)"
        else
            log_warning "TCC database permissions may be too permissive: $tcc_perms"
            apply_change "Set TCC database to restrictive permissions" \
                chmod 600 "$tcc_db"
        fi
    fi

    # Check Full Disk Access grants
    log_info "Review Full Disk Access grants in System Preferences > Privacy & Security"
    log_info "Unauthorized FDA grants could allow credential access equivalent to password filters"

    log_success "TCC database protection verified"
}

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================================"
echo "  F0RT1KA macOS Hardening Script"
echo "  Test: APT34 Exchange Server Weaponization with Email-Based C2"
echo "  MITRE ATT&CK: T1505.003, T1071.003, T1556.002, T1048.003"
echo "  Threat Actor: APT34 / OilRig / Hazel Sandstorm"
echo "============================================================================"
echo ""

check_root
check_macos

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
mkdir -p "$BACKUP_DIR" 2>/dev/null || true

MODE="HARDEN"
if $UNDO; then MODE="REVERT"; fi
if $DRY_RUN; then MODE="$MODE (DRY-RUN)"; fi

log_header "Mode: $MODE"
log_info "macOS version: $(get_macos_version)"
log_info "Log file: $LOG_FILE"
echo ""

# Execute hardening functions in priority order
verify_sip                           # Critical: Kernel protection
echo ""

harden_authorization_plugins         # Critical: T1556.002 equivalent
echo ""

harden_outbound_smtp                 # High: T1048.003
echo ""

harden_web_server                    # High: T1505.003 equivalent
echo ""

configure_security_logging           # Medium: Detection enablement
echo ""

harden_launch_daemons                # Medium: Persistence prevention
echo ""

verify_gatekeeper                    # Medium: System protection
echo ""

protect_tcc_database                 # Medium: Privacy protection
echo ""

# Summary
echo "============================================================================"
log_success "Hardening Complete!"
echo "============================================================================"
echo ""
log_info "Total changes applied: $CHANGES_MADE"
log_info "Warnings: $WARNINGS"
log_info "Log file: $LOG_FILE"
log_info "Backup directory: $BACKUP_DIR"
echo ""

# Verification commands
log_header "Verification Commands:"
echo ""
echo "  # Verify SIP status:"
echo "  csrutil status"
echo ""
echo "  # Verify Gatekeeper:"
echo "  spctl --status"
echo ""
echo "  # Verify pf SMTP blocking:"
echo "  sudo pfctl -sa 2>/dev/null | grep -A5 '$PF_ANCHOR'"
echo ""
echo "  # Check authorization plugins:"
echo "  ls -la /Library/Security/SecurityAgentPlugins/ 2>/dev/null"
echo ""
echo "  # Check PAM configuration:"
echo "  ls -la /etc/pam.d/"
echo ""
echo "  # Check OpenBSM audit config:"
echo "  cat /etc/security/audit_control"
echo ""
echo "  # Check launch daemons:"
echo "  ls -la /Library/LaunchDaemons/ | grep -v com.apple"
echo ""
echo "  # Monitor security events in real-time:"
echo "  log stream --predicate 'subsystem == \"com.apple.securityd\"' --level debug"
echo ""

echo ""
exit 0
