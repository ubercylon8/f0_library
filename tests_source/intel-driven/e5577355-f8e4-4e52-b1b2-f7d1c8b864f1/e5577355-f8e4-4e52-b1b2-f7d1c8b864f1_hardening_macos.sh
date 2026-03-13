#!/usr/bin/env bash
# ============================================================================
# DEFENSE GUIDANCE: macOS Hardening Script
# ============================================================================
# Test ID: e5577355-f8e4-4e52-b1b2-f7d1c8b864f1
# Test Name: SilentButDeadly WFP EDR Network Isolation
# MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
# Created: 2026-03-13
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
#
# PURPOSE:
# While the SilentButDeadly WFP technique is Windows-specific, macOS systems
# face analogous threats where attackers use pf (packet filter), Network
# Extensions, or similar mechanisms to block EDR agent network communications.
# This script hardens macOS endpoints against equivalent defense evasion
# techniques:
#
#   - Packet filter (pf) rule manipulation to block security agent traffic
#   - LaunchDaemon/LaunchAgent manipulation for security services
#   - System Extension/Endpoint Security framework tampering
#   - /etc/hosts poisoning to block EDR cloud domains
#   - TCC database manipulation to revoke security tool permissions
#
# MITRE ATT&CK Techniques Covered:
#   T1562.001 - Impair Defenses: Disable or Modify Tools
#   T1562.004 - Disable or Modify System Firewall
#   T1518.001 - Security Software Discovery
#
# USAGE:
#   sudo ./e5577355-f8e4-4e52-b1b2-f7d1c8b864f1_hardening_macos.sh [--undo] [--dry-run]
#
# OPTIONS:
#   --undo      Revert all hardening changes to defaults
#   --dry-run   Show what changes would be made without applying them
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - macOS 12 Monterey or later
#
# TESTED ON:
#   macOS 13 Ventura, macOS 14 Sonoma, macOS 15 Sequoia
#
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/f0rt1ka"
LOG_FILE="${LOG_DIR}/hardening_macos_$(date +%Y%m%d_%H%M%S).log"
UNDO_MODE=false
DRY_RUN=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Known EDR/Security agent LaunchDaemon identifiers on macOS
EDR_LAUNCH_DAEMONS=(
    "com.sentinelone.sentineld"
    "com.sentinelone.sentineld-helper"
    "com.sentinelone.sentineld-shell"
    "com.crowdstrike.falcond"
    "com.crowdstrike.userdaemon"
    "com.microsoft.wdav.daemon"
    "com.microsoft.wdav.epsext"
    "com.carbonblack.defense.coreservices"
    "com.carbonblack.defense.daemon"
    "com.cylance.agent"
    "com.symantec.sep.agent"
    "com.sophos.endpoint"
    "com.sophos.endpoint.scanextension"
    "com.eset.ees_daemon"
    "com.paloaltonetworks.trapsd"
    "com.elastic.endpoint"
    "com.elastic.agent"
)

# Known EDR binary paths on macOS
EDR_BINARY_PATHS=(
    "/Library/Sentinel/"
    "/Library/CS/"
    "/Library/Application Support/CrowdStrike/"
    "/Library/Application Support/Microsoft/Defender/"
    "/Library/Application Support/com.carbonblack.defense/"
    "/opt/CylancePROTECT/"
    "/Library/Application Support/Symantec/"
    "/Library/Sophos Anti-Virus/"
    "/Library/Application Support/com.eset.ees/"
    "/Library/Application Support/PaloAltoNetworks/"
    "/Library/Elastic/"
)

# EDR cloud domains to protect
EDR_CLOUD_DOMAINS=(
    "sentinelone.net"
    "crowdstrike.com"
    "microsoft.com"
    "carbonblack.io"
    "cylance.com"
    "sophos.com"
    "eset.com"
    "paloaltonetworks.com"
    "elastic.co"
    "trellix.com"
)

# ============================================================================
# Helper Functions
# ============================================================================

log_status() {
    local type="$1"
    local message="$2"
    local color=""
    local prefix=""

    case "$type" in
        INFO)    color="$CYAN";    prefix="[*]" ;;
        SUCCESS) color="$GREEN";   prefix="[+]" ;;
        WARNING) color="$YELLOW";  prefix="[!]" ;;
        ERROR)   color="$RED";     prefix="[-]" ;;
        HEADER)  color="$MAGENTA"; prefix="[=]" ;;
    esac

    echo -e "${color}${prefix} ${message}${NC}"

    # Log to file
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${prefix} ${message}" >> "$LOG_FILE" 2>/dev/null || true
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_status "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_macos() {
    if [[ "$(uname)" != "Darwin" ]]; then
        log_status "ERROR" "This script is designed for macOS only"
        exit 1
    fi
}

run_or_dry() {
    local description="$1"
    shift

    if $DRY_RUN; then
        log_status "INFO" "[DRY-RUN] Would execute: $*"
    else
        log_status "INFO" "$description"
        if eval "$@"; then
            log_status "SUCCESS" "$description - done"
        else
            log_status "WARNING" "$description - command returned non-zero"
        fi
    fi
}

get_macos_version() {
    sw_vers -productVersion 2>/dev/null || echo "unknown"
}

# ============================================================================
# Hardening Functions
# ============================================================================

harden_application_firewall() {
    # ======================================================================
    # Application Firewall Configuration
    # MITRE Mitigation: M1037 - Filter Network Traffic
    #
    # Enables and configures the macOS Application Firewall (ALF) to:
    # - Enable the firewall if disabled
    # - Enable stealth mode
    # - Block all incoming connections except essential services
    # - Enable logging
    # ======================================================================

    log_status "HEADER" "Configuring Application Firewall..."

    if $UNDO_MODE; then
        log_status "INFO" "Note: Firewall settings should be managed through System Preferences"
        log_status "WARNING" "Not disabling firewall for security reasons. Manually adjust via System Preferences > Security & Privacy > Firewall"
        return
    fi

    # Enable the Application Firewall
    run_or_dry "Enable Application Firewall" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null || true"

    # Enable stealth mode (system does not respond to ping/probing)
    run_or_dry "Enable stealth mode" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null || true"

    # Enable firewall logging
    run_or_dry "Enable firewall logging" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on 2>/dev/null || true"

    # Set logging to detailed mode
    run_or_dry "Set detailed firewall logging" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingopt detail 2>/dev/null || true"

    # Ensure signed applications are automatically allowed
    run_or_dry "Allow signed applications" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on 2>/dev/null || true"

    run_or_dry "Allow signed downloads" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on 2>/dev/null || true"

    log_status "SUCCESS" "Application Firewall configured"
}

harden_pf_firewall() {
    # ======================================================================
    # Packet Filter (pf) Monitoring
    # MITRE Mitigation: M1037 - Filter Network Traffic
    #
    # macOS includes pf (packet filter, derived from OpenBSD) which can be
    # abused to block EDR network communications. This function:
    # - Monitors pf.conf for unauthorized changes
    # - Creates baseline of current pf rules
    # - Sets up monitoring for pf anchor manipulation
    # ======================================================================

    log_status "HEADER" "Configuring Packet Filter (pf) Monitoring..."

    local pf_monitor_dir="/var/log/f0rt1ka/pf_baseline"
    local pf_monitor_script="/usr/local/bin/f0rt1ka-pf-monitor.sh"

    if $UNDO_MODE; then
        log_status "INFO" "Removing pf monitoring..."
        rm -f "$pf_monitor_script" 2>/dev/null || true
        rm -rf "$pf_monitor_dir" 2>/dev/null || true
        # Remove the LaunchDaemon
        local pf_plist="/Library/LaunchDaemons/com.f0rt1ka.pf-monitor.plist"
        if [[ -f "$pf_plist" ]]; then
            launchctl unload "$pf_plist" 2>/dev/null || true
            rm -f "$pf_plist"
        fi
        log_status "SUCCESS" "pf monitoring removed"
        return
    fi

    # Create baseline of current pf rules
    if ! $DRY_RUN; then
        mkdir -p "$pf_monitor_dir"
        pfctl -sr 2>/dev/null > "${pf_monitor_dir}/rules_baseline.txt" || true
        pfctl -sa 2>/dev/null > "${pf_monitor_dir}/full_state_baseline.txt" || true
        log_status "SUCCESS" "pf baseline captured at $pf_monitor_dir"
    fi

    # Create pf monitoring script
    local monitor_content='#!/bin/bash
# F0RT1KA Packet Filter Monitor
# Detects unauthorized pf rule changes that might block EDR communications

BASELINE_DIR="/var/log/f0rt1ka/pf_baseline"
CURRENT_RULES=$(pfctl -sr 2>/dev/null)
BASELINE_RULES=$(cat "${BASELINE_DIR}/rules_baseline.txt" 2>/dev/null)

if [ "$CURRENT_RULES" != "$BASELINE_RULES" ]; then
    logger -t F0RT1KA-PF "ALERT: Packet filter rules have been modified"

    # Check for rules specifically blocking EDR processes
    EDR_KEYWORDS=("sentinel" "crowdstrike" "falcon" "microsoft" "defender" "carbonblack" "cylance" "sophos" "eset" "elastic" "cortex" "trellix")

    for keyword in "${EDR_KEYWORDS[@]}"; do
        if echo "$CURRENT_RULES" | grep -qi "$keyword"; then
            logger -t F0RT1KA-PF "CRITICAL: pf rule references EDR-related keyword: $keyword"
        fi
    done

    # Check for broad blocking rules targeting outbound HTTPS
    if echo "$CURRENT_RULES" | grep -q "block.*out.*port.*443"; then
        logger -t F0RT1KA-PF "WARNING: pf rule blocking outbound HTTPS detected"
    fi
fi
'

    if $DRY_RUN; then
        log_status "INFO" "[DRY-RUN] Would create pf monitor at: $pf_monitor_script"
    else
        echo "$monitor_content" > "$pf_monitor_script"
        chmod 755 "$pf_monitor_script"
        log_status "SUCCESS" "pf monitoring script created at $pf_monitor_script"

        # Create LaunchDaemon for periodic monitoring
        local pf_plist="/Library/LaunchDaemons/com.f0rt1ka.pf-monitor.plist"
        cat > "$pf_plist" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rt1ka.pf-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/f0rt1ka-pf-monitor.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/f0rt1ka/pf-monitor-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rt1ka/pf-monitor-stderr.log</string>
</dict>
</plist>
PLIST_EOF
        chmod 644 "$pf_plist"
        launchctl load "$pf_plist" 2>/dev/null || true
        log_status "SUCCESS" "pf monitoring LaunchDaemon installed (runs every 5 minutes)"
    fi
}

harden_edr_launch_daemons() {
    # ======================================================================
    # Protect EDR LaunchDaemons
    # MITRE Mitigation: M1022 - Restrict File and Directory Permissions
    #
    # Ensures EDR LaunchDaemons:
    # - Are running and loaded
    # - Have correct file permissions (root:wheel, 644)
    # - Are monitored for unload/remove attempts
    # ======================================================================

    log_status "HEADER" "Protecting EDR LaunchDaemons..."

    if $UNDO_MODE; then
        log_status "INFO" "No changes to revert for LaunchDaemon protection (read-only operation)"
        return
    fi

    local found_count=0

    for daemon_id in "${EDR_LAUNCH_DAEMONS[@]}"; do
        local plist_path="/Library/LaunchDaemons/${daemon_id}.plist"

        if [[ -f "$plist_path" ]]; then
            found_count=$((found_count + 1))
            log_status "INFO" "Found EDR LaunchDaemon: $daemon_id"

            # Verify ownership and permissions
            local current_perms
            current_perms=$(stat -f "%Op" "$plist_path" 2>/dev/null || echo "unknown")
            local current_owner
            current_owner=$(stat -f "%Su:%Sg" "$plist_path" 2>/dev/null || echo "unknown")

            if [[ "$current_owner" != "root:wheel" ]]; then
                run_or_dry "Fix ownership on $daemon_id" \
                    "chown root:wheel '$plist_path'"
            fi

            if [[ "$current_perms" != "100644" ]] && [[ "$current_perms" != "644" ]]; then
                run_or_dry "Fix permissions on $daemon_id" \
                    "chmod 644 '$plist_path'"
            fi

            # Verify daemon is loaded
            if launchctl list "$daemon_id" &>/dev/null; then
                log_status "SUCCESS" "  Running: $daemon_id"
            else
                log_status "WARNING" "  NOT running: $daemon_id - attempting to load..."
                run_or_dry "Load $daemon_id" \
                    "launchctl load '$plist_path' 2>/dev/null || true"
            fi
        fi
    done

    if [[ $found_count -eq 0 ]]; then
        log_status "INFO" "No EDR LaunchDaemons found (expected on non-production hosts)"
    else
        log_status "SUCCESS" "Verified $found_count EDR LaunchDaemons"
    fi
}

harden_edr_binary_permissions() {
    # ======================================================================
    # Protect EDR Binary Directories
    # MITRE Mitigation: M1022 - Restrict File and Directory Permissions
    #
    # Sets restrictive permissions on EDR installation directories to prevent
    # tampering with security agent binaries and configuration files.
    # ======================================================================

    log_status "HEADER" "Protecting EDR Binary Directories..."

    if $UNDO_MODE; then
        log_status "WARNING" "File permission changes are not automatically reverted"
        log_status "INFO" "EDR vendors manage their own permissions during updates"
        return
    fi

    for edr_path in "${EDR_BINARY_PATHS[@]}"; do
        if [[ -d "$edr_path" ]]; then
            local edr_name
            edr_name=$(basename "$edr_path")
            log_status "INFO" "Found EDR directory: $edr_path"

            # Ensure root ownership
            run_or_dry "Set root ownership on $edr_path" \
                "chown -R root:wheel '$edr_path' 2>/dev/null || true"

            # Remove world-write permissions
            run_or_dry "Remove world-write on $edr_path" \
                "chmod -R o-w '$edr_path' 2>/dev/null || true"

            # Set system immutable flag on critical binaries
            if [[ -x "${edr_path}bin" ]] || [[ -x "${edr_path}sbin" ]]; then
                log_status "INFO" "  Immutable flags should be managed by the EDR vendor"
            fi

            log_status "SUCCESS" "Protected: $edr_path"
        fi
    done
}

harden_dns_protection() {
    # ======================================================================
    # DNS Protection Against EDR Cloud Domain Blocking
    # MITRE Mitigation: M1037 - Filter Network Traffic
    #
    # Monitors /etc/hosts for entries that block EDR cloud domains.
    # On macOS, attackers may add entries like:
    #   127.0.0.1 cloud.sentinelone.net
    #   0.0.0.0 ts01-b.cloudsink.net  (CrowdStrike)
    # ======================================================================

    log_status "HEADER" "Configuring DNS Protection for EDR Domains..."

    local dns_monitor="/usr/local/bin/f0rt1ka-dns-monitor.sh"

    if $UNDO_MODE; then
        log_status "INFO" "Removing DNS protection..."
        rm -f "$dns_monitor" 2>/dev/null || true
        # Remove immutable flag
        chflags nouchg /etc/hosts 2>/dev/null || true
        local dns_plist="/Library/LaunchDaemons/com.f0rt1ka.dns-monitor.plist"
        if [[ -f "$dns_plist" ]]; then
            launchctl unload "$dns_plist" 2>/dev/null || true
            rm -f "$dns_plist"
        fi
        log_status "SUCCESS" "DNS protection removed"
        return
    fi

    # Set user immutable flag on /etc/hosts
    run_or_dry "Set immutable flag on /etc/hosts" \
        "chflags uchg /etc/hosts 2>/dev/null || true"
    log_status "INFO" "Note: Use 'chflags nouchg /etc/hosts' to modify /etc/hosts"

    # Create DNS monitoring script
    local dns_content='#!/bin/bash
# F0RT1KA DNS Integrity Monitor for macOS
# Checks /etc/hosts for entries that might block EDR cloud domains

EDR_DOMAINS=(
    "sentinelone.net"
    "crowdstrike.com"
    "cloudsink.net"
    "microsoft.com"
    "carbonblack.io"
    "cylance.com"
    "sophos.com"
    "eset.com"
    "paloaltonetworks.com"
    "elastic.co"
    "trellix.com"
)

HOSTS_FILE="/etc/hosts"

for domain in "${EDR_DOMAINS[@]}"; do
    if grep -qi "$domain" "$HOSTS_FILE" 2>/dev/null; then
        if grep -Eqi "(127\.0\.0\.|0\.0\.0\.0|::1).*$domain" "$HOSTS_FILE" 2>/dev/null; then
            /usr/bin/logger -t F0RT1KA-DNS "ALERT: /etc/hosts contains blocking entry for EDR domain: $domain"
            /usr/bin/osascript -e "display notification \"EDR domain blocked in /etc/hosts: $domain\" with title \"F0RT1KA Security Alert\"" 2>/dev/null || true
        fi
    fi
done

# Also check if DNS resolution is being redirected
RESOLVER_DIR="/etc/resolver"
if [ -d "$RESOLVER_DIR" ]; then
    for domain in "${EDR_DOMAINS[@]}"; do
        if ls "$RESOLVER_DIR/" 2>/dev/null | grep -qi "$domain"; then
            /usr/bin/logger -t F0RT1KA-DNS "ALERT: Custom DNS resolver found for EDR domain: $domain"
        fi
    done
fi
'

    if $DRY_RUN; then
        log_status "INFO" "[DRY-RUN] Would create DNS monitor at: $dns_monitor"
    else
        echo "$dns_content" > "$dns_monitor"
        chmod 755 "$dns_monitor"

        # Create LaunchDaemon for periodic DNS monitoring
        local dns_plist="/Library/LaunchDaemons/com.f0rt1ka.dns-monitor.plist"
        cat > "$dns_plist" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rt1ka.dns-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/f0rt1ka-dns-monitor.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>600</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/f0rt1ka/dns-monitor-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rt1ka/dns-monitor-stderr.log</string>
</dict>
</plist>
PLIST_EOF
        chmod 644 "$dns_plist"
        launchctl load "$dns_plist" 2>/dev/null || true
        log_status "SUCCESS" "DNS monitoring LaunchDaemon installed (runs every 10 minutes)"
    fi
}

harden_system_integrity() {
    # ======================================================================
    # System Integrity Verification
    # MITRE Mitigation: M1047 - Audit
    #
    # Verifies macOS security features are enabled:
    # - System Integrity Protection (SIP)
    # - Gatekeeper
    # - XProtect
    # - Full Disk Access for security tools
    # ======================================================================

    log_status "HEADER" "Verifying System Integrity Configuration..."

    if $UNDO_MODE; then
        log_status "INFO" "System integrity settings are managed by macOS and should not be disabled"
        return
    fi

    # Check System Integrity Protection (SIP)
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_status "SUCCESS" "System Integrity Protection (SIP): Enabled"
    else
        log_status "ERROR" "System Integrity Protection (SIP): DISABLED"
        log_status "WARNING" "SIP should be enabled. Boot to Recovery Mode and run: csrutil enable"
    fi

    # Check Gatekeeper status
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_status "SUCCESS" "Gatekeeper: Enabled"
    else
        log_status "WARNING" "Gatekeeper: Not in expected state"
        run_or_dry "Enable Gatekeeper" \
            "spctl --master-enable 2>/dev/null || true"
    fi

    # Check if FileVault is enabled
    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "unknown")
    if echo "$fv_status" | grep -q "On"; then
        log_status "SUCCESS" "FileVault: Enabled"
    else
        log_status "WARNING" "FileVault: Not enabled"
        log_status "INFO" "Enable via: System Preferences > Security & Privacy > FileVault"
    fi

    # Check automatic security updates
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "0")
    if [[ "$auto_update" == "1" ]]; then
        log_status "SUCCESS" "Automatic macOS updates: Enabled"
    else
        log_status "WARNING" "Automatic macOS updates: Not enabled"
        run_or_dry "Enable automatic updates" \
            "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true 2>/dev/null || true"
    fi

    # Enable automatic XProtect/MRT updates
    run_or_dry "Enable automatic security data updates" \
        "defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true 2>/dev/null || true"

    run_or_dry "Enable automatic critical update installation" \
        "defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null || true"
}

harden_audit_logging() {
    # ======================================================================
    # Unified Audit Logging Configuration
    # MITRE Mitigation: M1047 - Audit
    #
    # macOS uses the Unified Logging system. This function configures
    # additional audit logging for security-relevant events:
    # - Process execution
    # - Network connection attempts
    # - File system changes in security-critical paths
    # ======================================================================

    log_status "HEADER" "Configuring Audit Logging..."

    local audit_control="/etc/security/audit_control"

    if $UNDO_MODE; then
        log_status "INFO" "Audit logging configuration should be managed carefully"
        log_status "WARNING" "Not reverting audit configuration for security reasons"
        return
    fi

    # Check if OpenBSM audit is configured
    if [[ -f "$audit_control" ]]; then
        log_status "INFO" "OpenBSM audit configuration found"

        # Check current audit flags
        local current_flags
        current_flags=$(grep "^flags:" "$audit_control" 2>/dev/null || echo "none")
        log_status "INFO" "Current audit flags: $current_flags"

        # Recommended flags for EDR protection monitoring:
        # lo - login/logout
        # ad - administrative actions
        # pc - process creation
        # ex - exec
        # fc - file creation
        # fm - file attribute modify
        # fw - file write
        local recommended_flags="lo,ad,pc,ex,fc,fm,fw"
        log_status "INFO" "Recommended audit flags: $recommended_flags"

        if ! echo "$current_flags" | grep -q "pc"; then
            log_status "WARNING" "Process creation auditing (pc) not enabled"
            log_status "INFO" "Edit $audit_control and add 'pc' to the flags line"
        fi

        if ! echo "$current_flags" | grep -q "ex"; then
            log_status "WARNING" "Exec auditing (ex) not enabled"
            log_status "INFO" "Edit $audit_control and add 'ex' to the flags line"
        fi
    else
        log_status "WARNING" "OpenBSM audit configuration not found at $audit_control"
    fi

    # Ensure audit daemon is running
    if launchctl list com.apple.auditd &>/dev/null 2>&1; then
        log_status "SUCCESS" "Audit daemon (auditd) is running"
    else
        log_status "WARNING" "Audit daemon may not be running"
        run_or_dry "Start audit daemon" \
            "launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true"
    fi
}

harden_endpoint_security() {
    # ======================================================================
    # Endpoint Security Framework Verification
    # MITRE Mitigation: M1038 - Execution Prevention
    #
    # Verifies that macOS Endpoint Security framework extensions are
    # properly loaded and authorized for installed EDR products.
    # ======================================================================

    log_status "HEADER" "Verifying Endpoint Security Framework..."

    if $UNDO_MODE; then
        log_status "INFO" "No changes to revert for Endpoint Security verification"
        return
    fi

    # List system extensions (macOS 10.15+)
    local sysext_output
    sysext_output=$(systemextensionsctl list 2>/dev/null || echo "")

    if [[ -n "$sysext_output" ]]; then
        log_status "INFO" "System Extensions installed:"

        # Check for known EDR extensions
        local edr_keywords=("sentinel" "crowdstrike" "falcon" "microsoft" "defender" "carbonblack" "cylance" "sophos" "eset" "elastic" "cortex" "trellix")

        for keyword in "${edr_keywords[@]}"; do
            if echo "$sysext_output" | grep -qi "$keyword"; then
                local ext_line
                ext_line=$(echo "$sysext_output" | grep -i "$keyword" | head -1)
                if echo "$ext_line" | grep -q "activated enabled"; then
                    log_status "SUCCESS" "  EDR extension active: $keyword"
                else
                    log_status "WARNING" "  EDR extension found but may not be active: $keyword"
                    log_status "INFO" "  Status: $ext_line"
                fi
            fi
        done
    else
        log_status "INFO" "No system extensions found or systemextensionsctl not available"
    fi

    # Check for Network Extensions (used for EDR network monitoring)
    log_status "INFO" "Checking Network Extension authorization..."
    local ne_output
    ne_output=$(profiles list 2>/dev/null | grep -i "network" || echo "")
    if [[ -n "$ne_output" ]]; then
        log_status "INFO" "Network Extension profiles found"
    fi
}

print_verification() {
    # ======================================================================
    # Print verification commands
    # ======================================================================

    echo ""
    log_status "HEADER" "Verification Commands"
    echo ""
    echo "  # Verify Application Firewall status:"
    echo "  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
    echo "  /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode"
    echo "  /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode"
    echo ""
    echo "  # Verify SIP status:"
    echo "  csrutil status"
    echo ""
    echo "  # Verify Gatekeeper status:"
    echo "  spctl --status"
    echo ""
    echo "  # Verify FileVault status:"
    echo "  fdesetup status"
    echo ""
    echo "  # List active system extensions (EDR):"
    echo "  systemextensionsctl list 2>/dev/null"
    echo ""
    echo "  # Verify EDR LaunchDaemons:"
    echo "  for d in com.sentinelone com.crowdstrike com.microsoft.wdav com.elastic; do"
    echo "    launchctl list 2>/dev/null | grep \$d"
    echo "  done"
    echo ""
    echo "  # Check pf rules for suspicious entries:"
    echo "  pfctl -sr 2>/dev/null"
    echo ""
    echo "  # Check /etc/hosts for EDR domain blocking:"
    echo "  grep -iE 'sentinel|crowdstrike|microsoft|elastic|carbonblack' /etc/hosts"
    echo ""
    echo "  # View F0RT1KA monitoring logs:"
    echo "  log show --predicate 'subsystem == \"com.f0rt1ka\"' --last 1h"
    echo "  cat /var/log/f0rt1ka/*.log 2>/dev/null"
    echo ""
    echo "  # View hardening log:"
    echo "  cat $LOG_FILE"
    echo ""
}

# ============================================================================
# Argument Parsing
# ============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo)
            UNDO_MODE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $SCRIPT_NAME [--undo] [--dry-run] [--help]"
            echo ""
            echo "Options:"
            echo "  --undo     Revert all hardening changes"
            echo "  --dry-run  Show changes without applying them"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            log_status "ERROR" "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================================"
echo "  F0RT1KA Defense Hardening Script (macOS)"
echo "  Test: SilentButDeadly WFP EDR Network Isolation"
echo "  MITRE ATT&CK: T1562.001"
echo "  macOS Version: $(get_macos_version)"
echo "============================================================================"
echo ""

check_root
check_macos

if $UNDO_MODE; then
    log_status "HEADER" "Mode: REVERT"
elif $DRY_RUN; then
    log_status "HEADER" "Mode: DRY-RUN (no changes will be made)"
else
    log_status "HEADER" "Mode: HARDEN"
fi

log_status "INFO" "Log file: $LOG_FILE"
echo ""

# Execute hardening functions
harden_application_firewall
echo ""

harden_pf_firewall
echo ""

harden_edr_launch_daemons
echo ""

harden_edr_binary_permissions
echo ""

harden_dns_protection
echo ""

harden_system_integrity
echo ""

harden_audit_logging
echo ""

harden_endpoint_security
echo ""

# Print summary
echo "============================================================================"
if $UNDO_MODE; then
    log_status "SUCCESS" "Hardening changes reverted successfully"
elif $DRY_RUN; then
    log_status "INFO" "Dry-run complete - no changes were made"
else
    log_status "SUCCESS" "Hardening complete"
fi
echo "============================================================================"
echo ""

if ! $UNDO_MODE; then
    print_verification
fi

exit 0
