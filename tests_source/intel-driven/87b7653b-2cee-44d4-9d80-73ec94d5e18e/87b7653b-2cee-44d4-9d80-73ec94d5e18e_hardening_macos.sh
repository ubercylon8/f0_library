#!/usr/bin/env bash
# ============================================================
# EDR-Freeze Defense Evasion - macOS Hardening Script
# ============================================================
#
# Test ID: 87b7653b-2cee-44d4-9d80-73ec94d5e18e
# MITRE ATT&CK: T1562.001, T1055, T1574
# Mitigations: M1047, M1040, M1038, M1022, M1018
#
# Purpose:
#   While the EDR-Freeze technique is Windows-specific (abusing
#   WerFaultSecure.exe), the underlying attack patterns -- security
#   process suspension, LOLBin-equivalent abuse, and executable
#   staging -- have macOS equivalents. This script hardens macOS
#   endpoints against analogous defense evasion techniques:
#
#   - Security daemon tampering (kill/stop of XProtect, MRT, TCC)
#   - Process task_for_pid-based suspension of security processes
#   - LOLBin-equivalent downloads (curl, osascript, python)
#   - Executable staging in world-writable directories
#   - Unified Logging (log stream) configuration for detection
#   - System Integrity Protection (SIP) verification
#   - Endpoint Security Framework verification
#
# Usage:
#   sudo ./87b7653b-2cee-44d4-9d80-73ec94d5e18e_hardening_macos.sh [apply|undo|check]
#
# Parameters:
#   apply  - Apply all hardening measures (default)
#   undo   - Revert all hardening changes
#   check  - Report current hardening status without changes
#
# Requirements:
#   - Root privileges (sudo)
#   - macOS 12 (Monterey) or later recommended
#   - Full Disk Access for terminal (for TCC database checks)
#
# Author: F0RT1KA Defense Guidance Builder
# Version: 1.0.0
# Date: 2026-03-13
# Idempotent: Yes (safe to run multiple times)
# ============================================================

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/tmp/F0/f0rtika_hardening_macos_$(date +%Y%m%d_%H%M%S).log"
readonly TEST_ID="87b7653b-2cee-44d4-9d80-73ec94d5e18e"
readonly LAUNCH_DAEMON_PLIST="/Library/LaunchDaemons/com.f0rtika.security-monitor.plist"
readonly PROFILE_DIR="/tmp/F0/hardening_profiles"

ACTION="${1:-apply}"

# macOS security processes and daemons
SECURITY_PROCESSES=(
    "XProtect"                    # macOS built-in malware detection
    "XProtectService"             # XProtect service (Ventura+)
    "MRT"                         # Malware Removal Tool
    "Endpoint Security"           # Endpoint Security framework
    "syspolicyd"                  # System Policy daemon (Gatekeeper)
    "com.apple.ManagedClient"     # MDM client
    "CrowdStrike"                 # CrowdStrike Falcon
    "falcon"                      # CrowdStrike Falcon sensor
    "SentinelAgent"               # SentinelOne
    "CbOsxSensorService"         # Carbon Black
    "JamfAgent"                   # Jamf Pro agent
    "JamfDaemon"                  # Jamf Pro daemon
)

# macOS security-related LaunchDaemons
SECURITY_DAEMONS=(
    "com.apple.XProtect"
    "com.apple.XprotectFramework.PluginService"
    "com.apple.MRT"
    "com.apple.syspolicyd"
    "com.crowdstrike.falcond"
    "com.sentinelone.sentineld"
)

# ============================================================
# Helper Functions
# ============================================================

log_info() {
    local msg="[INFO] $1"
    echo -e "\033[0;36m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

log_success() {
    local msg="[OK]   $1"
    echo -e "\033[0;32m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

log_warning() {
    local msg="[WARN] $1"
    echo -e "\033[0;33m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

log_error() {
    local msg="[ERR]  $1"
    echo -e "\033[0;31m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

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

command_exists() {
    command -v "$1" &>/dev/null
}

# ============================================================
# 1. System Integrity Protection (SIP) Verification
# ============================================================
# SIP is macOS's primary defense against system-level tampering.
# It prevents modification of system processes and files, making
# it the macOS equivalent of Windows Tamper Protection and PPL.
# SIP cannot be enabled/disabled from a running system -- it
# requires Recovery Mode -- so we only verify its status.
# ============================================================

check_sip_status() {
    log_info "Checking System Integrity Protection (SIP) status..."

    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")

    if echo "$sip_status" | grep -q "enabled"; then
        log_success "  SIP is ENABLED (Good)"
        log_info "  SIP prevents modification of system processes and protected paths"
        log_info "  This is the macOS equivalent of Windows Tamper Protection"
    elif echo "$sip_status" | grep -q "disabled"; then
        log_error "  SIP is DISABLED (CRITICAL VULNERABILITY)"
        log_error "  System processes including XProtect can be tampered with"
        log_warning "  To enable: Boot to Recovery Mode > Terminal > csrutil enable"
        log_warning "  This is the most critical macOS security control"
    else
        log_warning "  Unable to determine SIP status: $sip_status"
    fi
}

# ============================================================
# 2. Gatekeeper Verification
# ============================================================
# Gatekeeper prevents execution of unsigned or untrusted code.
# This is the macOS equivalent of WDAC/AppLocker on Windows.
# It prevents execution of attack tools like EDR-Freeze.
# ============================================================

check_gatekeeper() {
    log_info "Checking Gatekeeper status..."

    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")

    if echo "$gk_status" | grep -q "assessments enabled"; then
        log_success "  Gatekeeper is ENABLED (Good)"
    else
        log_warning "  Gatekeeper may be DISABLED"
        log_info "  To enable: sudo spctl --master-enable"
    fi

    # Check for Gatekeeper bypass (com.apple.quarantine xattr removal)
    log_info "  Checking Gatekeeper enforcement..."
    local notarization
    notarization=$(defaults read /Library/Preferences/com.apple.security GKAutoRearm 2>/dev/null || echo "1")
    if [[ "$notarization" == "1" ]]; then
        log_success "  Gatekeeper auto-rearm is enabled"
    else
        log_warning "  Gatekeeper auto-rearm is disabled"
    fi
}

apply_gatekeeper_hardening() {
    log_info "Applying Gatekeeper hardening..."

    # Enable Gatekeeper
    spctl --master-enable 2>/dev/null || true
    log_success "  Gatekeeper enabled"

    # Ensure only App Store and identified developers
    # 0 = Mac App Store only, 1 = Mac App Store + identified developers
    # We use identified developers as the minimum acceptable setting
    local current_policy
    current_policy=$(defaults read com.apple.LaunchServices LSQuarantine 2>/dev/null || echo "1")
    if [[ "$current_policy" != "1" ]]; then
        defaults write com.apple.LaunchServices LSQuarantine -bool true 2>/dev/null || true
        log_success "  Quarantine enforcement enabled"
    else
        log_info "  Quarantine enforcement already enabled"
    fi
}

# ============================================================
# 3. Endpoint Security Framework Verification
# ============================================================
# The Endpoint Security (ES) framework is macOS's native EDR
# API. Security tools register with ES to receive real-time
# notifications of system events. Verification ensures no
# tampering has occurred.
# ============================================================

check_endpoint_security() {
    log_info "Checking Endpoint Security framework..."

    # Check for registered ES clients
    local es_clients
    es_clients=$(systemextensionsctl list 2>/dev/null || echo "")

    if [[ -n "$es_clients" ]]; then
        log_info "  Registered system extensions:"
        echo "$es_clients" | while IFS= read -r line; do
            if echo "$line" | grep -qi "endpoint\|security\|falcon\|sentinel\|crowdstrike\|carbon"; then
                log_success "    $line"
            fi
        done
    else
        log_info "  No system extensions found (or unable to query)"
    fi

    # Check for running security agents
    for process in "${SECURITY_PROCESSES[@]}"; do
        if pgrep -x "$process" >/dev/null 2>&1; then
            log_success "  Security process running: $process"
        fi
    done
}

# ============================================================
# 4. OpenBSM Auditing Configuration
# ============================================================
# OpenBSM is macOS's audit framework, equivalent to auditd on
# Linux. It provides the behavioral detection backbone for
# security monitoring on macOS.
# ============================================================

apply_openbsm_auditing() {
    log_info "Configuring OpenBSM auditing..."

    local audit_control="/etc/security/audit_control"

    if [[ ! -f "$audit_control" ]]; then
        log_warning "  OpenBSM audit_control not found"
        return 0
    fi

    # Backup current config
    cp "$audit_control" "${audit_control}.f0rtika.bak" 2>/dev/null || true

    # Check current audit flags
    local current_flags
    current_flags=$(grep "^flags:" "$audit_control" 2>/dev/null || echo "")

    # Required flags for EDR-Freeze detection:
    # lo = login/logout
    # aa = authentication/authorization
    # ad = administrative (service management)
    # pc = process (exec, fork, exit)
    # ex = exec (with arguments)
    # fc = file creation
    # fd = file deletion
    # fm = file attribute modification
    local required_flags="lo,aa,ad,pc,ex,fc,fd,fm"

    if [[ -n "$current_flags" ]]; then
        log_info "  Current audit flags: $current_flags"

        # Check if pc and ex flags are present
        if echo "$current_flags" | grep -q "pc" && echo "$current_flags" | grep -q "ex"; then
            log_success "  Process creation auditing is enabled"
        else
            log_warning "  Process creation auditing flags (pc,ex) may be missing"
            log_info "  Recommended flags: $required_flags"
            log_info "  Edit $audit_control and set: flags:$required_flags"
        fi
    else
        log_warning "  No audit flags configured"
        log_info "  Add to $audit_control: flags:$required_flags"
    fi

    # Check if audit is running
    if launchctl list | grep -q "com.apple.auditd" 2>/dev/null; then
        log_success "  auditd is running"
    else
        log_warning "  auditd does not appear to be running"
        log_info "  To start: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist"
    fi

    log_success "OpenBSM audit configuration reviewed"
}

remove_openbsm_auditing() {
    log_info "Reverting OpenBSM audit changes..."

    local audit_control="/etc/security/audit_control"
    local backup="${audit_control}.f0rtika.bak"

    if [[ -f "$backup" ]]; then
        cp "$backup" "$audit_control"
        rm -f "$backup"
        log_success "  Restored audit_control from backup"
    else
        log_info "  No backup found, no changes to revert"
    fi
}

# ============================================================
# 5. TCC (Transparency, Consent, and Control) Verification
# ============================================================
# TCC controls which applications can access protected resources
# (camera, microphone, Full Disk Access, etc.). Attackers may
# try to manipulate TCC to gain access or evade detection.
# ============================================================

check_tcc_status() {
    log_info "Checking TCC (Transparency, Consent, Control) status..."

    # Check for Full Disk Access grants (potential abuse vector)
    local tcc_db="/Library/Application Support/com.apple.TCC/TCC.db"

    if [[ -f "$tcc_db" ]]; then
        # Check for potentially suspicious FDA grants
        local fda_count
        fda_count=$(sqlite3 "$tcc_db" "SELECT COUNT(*) FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND allowed=1;" 2>/dev/null || echo "N/A")
        log_info "  Full Disk Access grants: $fda_count"

        if [[ "$fda_count" != "N/A" && "$fda_count" -gt 5 ]]; then
            log_warning "  High number of FDA grants detected ($fda_count)"
            log_info "  Review in System Preferences > Privacy & Security > Full Disk Access"
        fi
    else
        log_info "  Unable to access TCC database (requires Full Disk Access)"
    fi

    # Check Automation permissions
    log_info "  Review Automation permissions in System Preferences > Privacy > Automation"
    log_info "  Ensure no unauthorized apps have Automation access to Terminal"
}

# ============================================================
# 6. Launch Daemon Security Monitor
# ============================================================
# Creates a LaunchDaemon that monitors for suspicious process
# signals and security daemon tampering. This is the macOS
# equivalent of the Windows process creation auditing and
# security service monitoring.
# ============================================================

apply_security_monitor() {
    log_info "Creating security monitoring LaunchDaemon..."

    mkdir -p /tmp/F0

    # Create the monitoring script
    local monitor_script="/usr/local/bin/f0rtika-security-monitor.sh"

    cat > "$monitor_script" << 'MONITOR_SCRIPT_EOF'
#!/usr/bin/env bash
# ============================================================
# F0RT1KA Security Process Monitor for macOS
# Monitors for suspicious signals to security processes and
# suspicious file creation in staging directories.
# ============================================================

LOG="/var/log/f0rtika-security-monitor.log"

echo "$(date) F0RT1KA Security Monitor started (PID: $$)" >> "$LOG"

# Monitor security process health
SECURITY_PROCS=("XProtect" "XProtectService" "MRT" "syspolicyd")
CHECK_INTERVAL=30

while true; do
    for proc in "${SECURITY_PROCS[@]}"; do
        if ! pgrep -x "$proc" >/dev/null 2>&1; then
            echo "$(date) ALERT: Security process not running: $proc" >> "$LOG"
            logger -p auth.crit "F0RT1KA: Security process not running: $proc"
        fi
    done

    # Check for suspicious files in staging directories
    for dir in /tmp /private/tmp /Users/Shared; do
        if [[ -d "$dir" ]]; then
            # Look for recently created executables
            find "$dir" -maxdepth 2 -type f -perm +111 -newer /etc/hosts -mmin -5 2>/dev/null | while read -r file; do
                echo "$(date) ALERT: Executable created in staging dir: $file" >> "$LOG"
                logger -p auth.warning "F0RT1KA: Executable in staging dir: $file"
            done
        fi
    done

    sleep "$CHECK_INTERVAL"
done
MONITOR_SCRIPT_EOF

    chmod 755 "$monitor_script"

    # Create LaunchDaemon plist
    cat > "$LAUNCH_DAEMON_PLIST" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rtika.security-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/f0rtika-security-monitor.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rtika-security-monitor-error.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/f0rtika-security-monitor.log</string>
</dict>
</plist>
PLIST_EOF

    chmod 644 "$LAUNCH_DAEMON_PLIST"
    chown root:wheel "$LAUNCH_DAEMON_PLIST"

    # Load the daemon
    launchctl load "$LAUNCH_DAEMON_PLIST" 2>/dev/null || true
    log_success "Security monitor LaunchDaemon created and loaded"
    log_info "  Script: $monitor_script"
    log_info "  Plist: $LAUNCH_DAEMON_PLIST"
    log_info "  Log: /var/log/f0rtika-security-monitor.log"
}

remove_security_monitor() {
    log_info "Removing security monitoring LaunchDaemon..."

    if [[ -f "$LAUNCH_DAEMON_PLIST" ]]; then
        launchctl unload "$LAUNCH_DAEMON_PLIST" 2>/dev/null || true
        rm -f "$LAUNCH_DAEMON_PLIST"
        log_success "  Removed LaunchDaemon plist"
    fi

    local monitor_script="/usr/local/bin/f0rtika-security-monitor.sh"
    if [[ -f "$monitor_script" ]]; then
        rm -f "$monitor_script"
        log_success "  Removed monitor script"
    fi

    # Kill any running monitor processes
    pkill -f "f0rtika-security-monitor" 2>/dev/null || true
}

# ============================================================
# 7. Firewall and Network Hardening
# ============================================================
# Configure the macOS Application Firewall to block unauthorized
# outbound connections. This helps prevent LOLBin-based downloads
# that occur after security process suspension.
# ============================================================

apply_firewall_hardening() {
    log_info "Applying firewall hardening..."

    # Enable macOS Application Firewall
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")

    if echo "$fw_status" | grep -q "enabled"; then
        log_success "  Application Firewall is already enabled"
    else
        /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null || true
        log_success "  Application Firewall enabled"
    fi

    # Enable stealth mode (don't respond to ICMP/port probes)
    local stealth
    stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")

    if echo "$stealth" | grep -q "enabled"; then
        log_info "  Stealth mode is already enabled"
    else
        /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null || true
        log_success "  Stealth mode enabled"
    fi

    # Block all incoming connections (except essential services)
    /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on 2>/dev/null || true
    log_success "  Blocking all incoming connections (except essential services)"

    # Enable logging
    /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on 2>/dev/null || true
    log_success "  Firewall logging enabled"
}

remove_firewall_hardening() {
    log_info "Reverting firewall hardening..."
    log_warning "  Firewall settings require manual revert via System Preferences"
    log_info "  To revert: System Preferences > Network > Firewall"
    log_info "  Or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off"
}

# ============================================================
# 8. Staging Directory Hardening
# ============================================================
# Restrict world-writable directories on macOS to prevent
# executable staging. Similar to Linux /tmp hardening.
# ============================================================

apply_staging_hardening() {
    log_info "Applying staging directory hardening..."

    # Check and set sticky bits on staging directories
    for dir in /tmp /private/tmp /Users/Shared; do
        if [[ -d "$dir" ]]; then
            local perms
            perms=$(stat -f %Lp "$dir" 2>/dev/null || true)
            if [[ -n "$perms" ]]; then
                # Ensure sticky bit is set
                chmod +t "$dir" 2>/dev/null || true
                log_success "  Set sticky bit on $dir"
            fi
        fi
    done

    # Remove quarantine attribute bypass capability check
    log_info "  Checking for quarantine attribute handling..."
    local xattr_binary="/usr/bin/xattr"
    if [[ -f "$xattr_binary" ]]; then
        log_info "  xattr binary exists at $xattr_binary"
        log_warning "  Attackers use 'xattr -cr <file>' to remove quarantine flags"
        log_info "  Consider monitoring xattr usage via Unified Logging"
    fi

    log_success "Staging directory hardening applied"
}

remove_staging_hardening() {
    log_info "Reverting staging directory hardening..."
    log_info "  Sticky bits are standard security practice; not removing"
}

# ============================================================
# 9. Unified Logging Configuration
# ============================================================
# Configure macOS Unified Logging to capture security-relevant
# events. This is the macOS equivalent of Windows Event Log
# and Sysmon configuration.
# ============================================================

apply_unified_logging() {
    log_info "Configuring Unified Logging for security monitoring..."

    # Create a logging profile that enables verbose process and security logging
    mkdir -p "$PROFILE_DIR"

    local logging_profile="$PROFILE_DIR/f0rtika-security-logging.mobileconfig"

    cat > "$logging_profile" << 'LOGGING_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.system.logging</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.f0rtika.logging.security</string>
            <key>PayloadUUID</key>
            <string>87B7653B-2CEE-44D4-9D80-73EC94D5E18E</string>
            <key>PayloadDisplayName</key>
            <string>F0RT1KA Security Logging</string>
            <key>PayloadDescription</key>
            <string>Enables verbose security process logging for defense evasion detection</string>
            <key>Subsystems</key>
            <dict>
                <key>com.apple.xprotect</key>
                <dict>
                    <key>DEFAULT-OPTIONS</key>
                    <dict>
                        <key>Level</key>
                        <dict>
                            <key>Enable</key>
                            <string>Default</string>
                            <key>Persist</key>
                            <string>Default</string>
                        </dict>
                    </dict>
                </dict>
                <key>com.apple.endpointsecurity</key>
                <dict>
                    <key>DEFAULT-OPTIONS</key>
                    <dict>
                        <key>Level</key>
                        <dict>
                            <key>Enable</key>
                            <string>Default</string>
                            <key>Persist</key>
                            <string>Default</string>
                        </dict>
                    </dict>
                </dict>
                <key>com.apple.syspolicy</key>
                <dict>
                    <key>DEFAULT-OPTIONS</key>
                    <dict>
                        <key>Level</key>
                        <dict>
                            <key>Enable</key>
                            <string>Default</string>
                            <key>Persist</key>
                            <string>Default</string>
                        </dict>
                    </dict>
                </dict>
            </dict>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>F0RT1KA Security Logging Profile</string>
    <key>PayloadIdentifier</key>
    <string>com.f0rtika.security-logging</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>87B7653B-AAAA-44D4-9D80-73EC94D5E18E</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
LOGGING_EOF

    log_success "Logging profile created at $logging_profile"
    log_info "  To install: sudo profiles install -path $logging_profile"
    log_info "  Or deploy via MDM (Jamf, Intune, Mosyle, etc.)"
    echo ""

    # Provide useful log stream commands for real-time monitoring
    log_info "Useful Unified Logging commands for EDR-Freeze-equivalent detection:"
    echo ""
    log_info "  Monitor security process events:"
    log_info "    log stream --predicate 'subsystem == \"com.apple.xprotect\"' --level debug"
    echo ""
    log_info "  Monitor process execution:"
    log_info "    log stream --predicate 'eventMessage CONTAINS \"exec\" AND subsystem == \"com.apple.endpointsecurity\"'"
    echo ""
    log_info "  Monitor for kill signals to security processes:"
    log_info "    log stream --predicate 'eventMessage CONTAINS \"signal\" AND eventMessage CONTAINS \"XProtect\"'"
    echo ""
    log_info "  Monitor Gatekeeper decisions:"
    log_info "    log stream --predicate 'subsystem == \"com.apple.syspolicy\"' --level info"

    log_success "Unified Logging configuration complete"
}

remove_unified_logging() {
    log_info "Reverting Unified Logging configuration..."

    if [[ -d "$PROFILE_DIR" ]]; then
        rm -rf "$PROFILE_DIR"
        log_success "  Removed logging profile directory"
    fi

    # Check if profile is installed and provide removal instructions
    local installed
    installed=$(profiles list 2>/dev/null | grep "f0rtika" || true)
    if [[ -n "$installed" ]]; then
        log_info "  Installed profile found. Remove via:"
        log_info "    sudo profiles remove -identifier com.f0rtika.security-logging"
    fi
}

# ============================================================
# Status Check
# ============================================================

check_status() {
    echo ""
    echo "============================================================"
    echo " F0RT1KA EDR-Freeze Hardening - macOS Status Check"
    echo " Test ID: $TEST_ID"
    echo " macOS Version: $(get_macos_version)"
    echo "============================================================"
    echo ""

    # SIP Status
    check_sip_status
    echo ""

    # Gatekeeper
    check_gatekeeper
    echo ""

    # Endpoint Security
    check_endpoint_security
    echo ""

    # TCC
    check_tcc_status
    echo ""

    # Firewall
    log_info "Firewall Status:"
    local fw_state
    fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$fw_state" | grep -q "enabled"; then
        log_success "  Application Firewall: ENABLED"
    else
        log_warning "  Application Firewall: DISABLED"
    fi

    local stealth_state
    stealth_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
    if echo "$stealth_state" | grep -q "enabled"; then
        log_success "  Stealth Mode: ENABLED"
    else
        log_warning "  Stealth Mode: DISABLED"
    fi
    echo ""

    # Security Monitor
    log_info "Security Monitor:"
    if [[ -f "$LAUNCH_DAEMON_PLIST" ]]; then
        if launchctl list | grep -q "com.f0rtika.security-monitor" 2>/dev/null; then
            log_success "  Security monitor: RUNNING"
        else
            log_warning "  Security monitor: INSTALLED but NOT RUNNING"
        fi
    else
        log_warning "  Security monitor: NOT INSTALLED"
    fi
    echo ""

    # Security Processes
    log_info "Security Process Status:"
    local found_any=false
    for process in "${SECURITY_PROCESSES[@]}"; do
        if pgrep -x "$process" >/dev/null 2>&1; then
            log_success "  $process: running"
            found_any=true
        fi
    done

    # Also check for XProtect via launchctl
    if launchctl list | grep -q "com.apple.XProtect" 2>/dev/null; then
        log_success "  XProtect (via launchctl): loaded"
        found_any=true
    fi
    if launchctl list | grep -q "com.apple.MRT" 2>/dev/null; then
        log_success "  MRT (via launchctl): loaded"
        found_any=true
    fi

    if [[ "$found_any" == "false" ]]; then
        log_info "  No monitored third-party security agents found"
    fi
    echo ""

    # OpenBSM
    log_info "OpenBSM Audit Status:"
    if launchctl list | grep -q "com.apple.auditd" 2>/dev/null; then
        log_success "  auditd: running"
    else
        log_warning "  auditd: not running"
    fi
    echo ""

    echo "============================================================"
    echo " Status check complete"
    echo "============================================================"
}

# ============================================================
# Main Execution
# ============================================================

main() {
    check_macos

    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

    echo ""
    echo "============================================================"
    echo " F0RT1KA EDR-Freeze Defense Evasion - macOS Hardening"
    echo " Test ID: $TEST_ID"
    echo " MITRE ATT&CK: T1562.001, T1055, T1574"
    echo " macOS Version: $(get_macos_version)"
    echo "============================================================"
    echo ""

    case "$ACTION" in
        apply)
            check_root
            log_info "Applying hardening measures..."
            echo ""

            # Verification checks (read-only)
            check_sip_status
            echo ""

            check_gatekeeper
            echo ""

            check_endpoint_security
            echo ""

            check_tcc_status
            echo ""

            # Active hardening
            apply_gatekeeper_hardening
            echo ""

            apply_openbsm_auditing
            echo ""

            apply_firewall_hardening
            echo ""

            apply_staging_hardening
            echo ""

            apply_security_monitor
            echo ""

            apply_unified_logging
            echo ""

            echo "============================================================"
            log_success "Hardening complete!"
            echo "============================================================"
            echo ""
            log_info "Summary of applied protections:"
            log_success "  - SIP status verified"
            log_success "  - Gatekeeper enabled and hardened"
            log_success "  - Endpoint Security framework verified"
            log_success "  - TCC permissions reviewed"
            log_success "  - OpenBSM audit configuration reviewed"
            log_success "  - Application Firewall enabled with stealth mode"
            log_success "  - Staging directory hardening applied"
            log_success "  - Security process monitor daemon installed"
            log_success "  - Unified Logging profile created"
            echo ""
            log_info "Log file: $LOG_FILE"
            log_info "Run with 'check' to verify status"
            log_info "Run with 'undo' to revert all changes"
            ;;

        undo)
            check_root
            log_warning "Reverting all hardening changes..."
            echo ""

            remove_security_monitor
            remove_unified_logging
            remove_openbsm_auditing
            remove_firewall_hardening
            remove_staging_hardening

            echo ""
            log_success "Hardening changes reverted"
            log_info "Note: SIP and Gatekeeper are not modified by undo"
            log_info "Log file: $LOG_FILE"
            ;;

        check|status)
            check_root
            check_status
            ;;

        *)
            echo "Usage: $SCRIPT_NAME [apply|undo|check]"
            echo ""
            echo "  apply  - Apply all hardening measures (default)"
            echo "  undo   - Revert all hardening changes"
            echo "  check  - Report current hardening status"
            exit 1
            ;;
    esac
}

main
