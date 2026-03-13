#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# CyberEye RAT Defense - T1562.001 Impair Defenses Countermeasures
# ============================================================================
# Test ID:      ecd2514c-512a-4251-a6f4-eb3aa834d401
# Test Name:    CyberEye RAT - Windows Defender Disabling via PowerShell
# MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
# Mitigations:  M1024, M1022, M1047, M1054, M1038
#
# Purpose:
#   Hardens macOS against T1562.001 techniques that disable or modify
#   security tools. While the original test targets Windows Defender via
#   PowerShell, the same MITRE technique applies to macOS security
#   controls: XProtect, Gatekeeper, SIP, Application Firewall, and
#   third-party endpoint protection agents.
#
# Usage:
#   sudo ./ecd2514c-512a-4251-a6f4-eb3aa834d401_hardening_macos.sh [apply|undo|check]
#
# Requires: root privileges (sudo)
# Idempotent: Yes (safe to run multiple times)
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_NAME="$(basename "$0")"
TEST_ID="ecd2514c-512a-4251-a6f4-eb3aa834d401"
BACKUP_DIR="/var/backups/f0rtika-hardening-${TEST_ID}"
LOG_FILE="/var/log/f0rtika-hardening-${TEST_ID}.log"
CHANGE_COUNT=0

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

ensure_dirs() {
    mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")" 2>/dev/null || true
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
# 1. SIP and Gatekeeper Enforcement (M1054 - Software Configuration)
# ============================================================================

harden_sip_gatekeeper() {
    log_info "=== SIP and Gatekeeper Enforcement (M1054) ==="

    # SIP is the macOS equivalent of Tamper Protection on Windows
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "System Integrity Protection (SIP) is enabled"
    else
        log_warning "SIP is NOT enabled -- security tools can be tampered with"
        log_warning "Enable in Recovery Mode: csrutil enable"
    fi

    # Gatekeeper prevents execution of unsigned/unnotarized apps
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_info "Gatekeeper already enabled"
    else
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    # Ensure Library Validation
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

undo_sip_gatekeeper() {
    log_warning "SIP and Gatekeeper should not be disabled (security critical)"
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
}

# ============================================================================
# 2. XProtect and Automatic Security Updates (M1054)
# ============================================================================

harden_xprotect_updates() {
    log_info "=== XProtect and Security Update Configuration (M1054) ==="

    # XProtect is macOS's built-in AV -- analogous to Windows Defender
    # Check MRT presence
    if [[ -f "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" ]]; then
        log_success "Malware Removal Tool (MRT) is present"
    elif [[ -f "/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" ]]; then
        log_success "MRT is present (legacy path)"
    else
        log_warning "MRT not found"
    fi

    # Enable automatic security updates
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not set")
    if [[ "$auto_update" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true 2>/dev/null || true
        log_success "Automatic macOS updates enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    # Enable critical/XProtect updates
    local critical_update
    critical_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "not set")
    if [[ "$critical_update" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null || true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true 2>/dev/null || true
        log_success "Critical updates (XProtect/MRT) enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Critical updates already enabled"
    fi

    # Ensure background check is enabled
    defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true 2>/dev/null || true
    defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true 2>/dev/null || true
    log_success "Background update checks enabled"
}

undo_xprotect_updates() {
    log_warning "XProtect and update settings should not be reverted"
}

check_xprotect_updates() {
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "0")
    if [[ "$auto_update" == "1" ]]; then
        log_success "Automatic updates: enabled"
    else
        log_warning "Automatic updates: not enabled"
    fi
}

# ============================================================================
# 3. Application Firewall (M1054 - Software Configuration)
# ============================================================================

harden_firewall() {
    log_info "=== Application Firewall Configuration (M1054) ==="

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
    log_info "Stealth mode enabled"

    # Allow only signed apps
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on >/dev/null 2>&1 || true
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on >/dev/null 2>&1 || true
    log_success "Firewall: signed applications only"
}

undo_firewall() {
    log_info "Application Firewall left enabled (security best practice)"
}

check_firewall() {
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$fw_status" | grep -q "enabled"; then
        log_success "Application Firewall: enabled"
    else
        log_warning "Application Firewall: disabled"
    fi
}

# ============================================================================
# 4. OpenBSM Audit Configuration (M1047 - Audit)
# ============================================================================

harden_audit() {
    log_info "=== Configuring OpenBSM Audit (M1047) ==="

    local audit_control="/etc/security/audit_control"
    if [[ ! -f "$audit_control" ]]; then
        log_warning "audit_control not found"
        return
    fi

    backup_file "$audit_control"

    if ! grep -q "^flags:.*ex" "$audit_control" 2>/dev/null; then
        if grep -q "^flags:" "$audit_control"; then
            local current_flags
            current_flags=$(grep "^flags:" "$audit_control" | head -1 | sed 's/^flags://')
            sed -i '' "s/^flags:.*/flags:${current_flags},ex,pc,fc,fd/" "$audit_control" 2>/dev/null || true
            log_success "Added execution/process audit flags"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    else
        log_info "Audit flags already configured"
    fi

    if launchctl list 2>/dev/null | grep -q "com.apple.auditd"; then
        log_success "Audit daemon is running"
    else
        log_warning "Audit daemon may not be running"
    fi
}

undo_audit() {
    log_info "Audit settings left as-is. Restore from $BACKUP_DIR if needed."
}

check_audit() {
    if [[ -f "/etc/security/audit_control" ]]; then
        if grep -q "ex" /etc/security/audit_control 2>/dev/null; then
            log_success "Execution auditing: enabled"
        else
            log_warning "Execution auditing: not configured"
        fi
    fi
}

# ============================================================================
# 5. EDR Agent Protection (M1024 - Restrict Permissions)
# ============================================================================

harden_edr_agents() {
    log_info "=== Protecting EDR Agent Services (M1024) ==="

    local edr_daemons=(
        "com.microsoft.wdav.daemon"
        "com.microsoft.wdav"
        "com.crowdstrike.falcon.Agent"
        "com.sentinelone.sentineld"
        "com.elastic.endpoint"
    )

    local found=false
    for label in "${edr_daemons[@]}"; do
        local plist="/Library/LaunchDaemons/${label}.plist"
        if [[ -f "$plist" ]]; then
            found=true
            chmod 644 "$plist"
            chown root:wheel "$plist"

            if launchctl list 2>/dev/null | grep -q "$label"; then
                log_success "EDR service $label: running, plist protected"
            else
                log_warning "EDR service $label: plist exists but not loaded"
            fi
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    if ! $found; then
        log_warning "No known EDR LaunchDaemons found"
    fi

    # Protect LaunchDaemons directory
    chmod 755 /Library/LaunchDaemons
    chown root:wheel /Library/LaunchDaemons
}

undo_edr_agents() {
    log_info "EDR agent protections are non-destructive -- no changes to revert"
}

check_edr_agents() {
    local count=0
    for label in com.microsoft.wdav.daemon com.crowdstrike.falcon.Agent com.sentinelone.sentineld; do
        if launchctl list 2>/dev/null | grep -q "$label"; then
            log_success "EDR service $label: running"
            count=$((count + 1))
        fi
    done
    if [[ $count -eq 0 ]]; then
        log_warning "No known EDR services detected"
    fi
}

# ============================================================================
# 6. Restrict PowerShell and Scripting Runtimes (M1038 - Execution Prevention)
# ============================================================================

harden_scripting_restriction() {
    log_info "=== Restricting Scripting Runtimes (M1038) ==="

    # PowerShell for macOS (pwsh) is the direct analogue of the attack
    local runtimes=(
        "/usr/local/bin/pwsh"
        "/opt/homebrew/bin/pwsh"
        "/usr/local/microsoft/powershell/7/pwsh"
    )

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

    log_info "osascript is SIP-protected -- restrict via MDM profiles"
}

undo_scripting_restriction() {
    for runtime in /usr/local/bin/pwsh /opt/homebrew/bin/pwsh /usr/local/microsoft/powershell/7/pwsh; do
        if [[ -f "$runtime" ]]; then
            chmod 755 "$runtime"
            log_success "Restored $runtime to 755"
        fi
    done
}

check_scripting_restriction() {
    for runtime in /usr/local/bin/pwsh /opt/homebrew/bin/pwsh /usr/local/microsoft/powershell/7/pwsh; do
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
}

# ============================================================================
# 7. Security Agent Watchdog (M1047)
# ============================================================================

harden_agent_watchdog() {
    log_info "=== Configuring Security Agent Watchdog (M1047) ==="

    local watchdog_script="/usr/local/bin/f0rtika-security-watchdog.sh"
    local watchdog_plist="/Library/LaunchDaemons/com.f0rtika.security-watchdog.plist"

    cat > "$watchdog_script" <<'WATCHDOG_EOF'
#!/usr/bin/env bash
# F0RT1KA Security Agent Watchdog
# Monitors security controls and logs/alerts if any are disabled

LOG="/var/log/f0rtika/security-watchdog.log"
mkdir -p "$(dirname "$LOG")"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
ALERT=false

# Check Gatekeeper
gk=$(spctl --status 2>/dev/null || echo "unknown")
if ! echo "$gk" | grep -q "enabled"; then
    echo "$TIMESTAMP [ALERT] Gatekeeper is DISABLED" >> "$LOG"
    logger -t "f0rtika-watchdog" -p auth.crit "Gatekeeper is DISABLED"
    ALERT=true
fi

# Check Application Firewall
fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
if echo "$fw" | grep -q "disabled"; then
    echo "$TIMESTAMP [ALERT] Application Firewall is DISABLED" >> "$LOG"
    logger -t "f0rtika-watchdog" -p auth.crit "Application Firewall is DISABLED"
    ALERT=true
fi

# Check EDR services
for svc in com.microsoft.wdav.daemon com.crowdstrike.falcon.Agent com.sentinelone.sentineld; do
    if [[ -f "/Library/LaunchDaemons/${svc}.plist" ]]; then
        if ! launchctl list 2>/dev/null | grep -q "$svc"; then
            echo "$TIMESTAMP [ALERT] EDR service $svc is NOT running" >> "$LOG"
            logger -t "f0rtika-watchdog" -p auth.crit "EDR service $svc not running"
            ALERT=true
        fi
    fi
done

if [[ "$ALERT" == "false" ]]; then
    echo "$TIMESTAMP [OK] All security controls healthy" >> "$LOG"
fi
WATCHDOG_EOF

    chmod 755 "$watchdog_script"

    cat > "$watchdog_plist" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rtika.security-watchdog</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/f0rtika-security-watchdog.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/f0rtika/security-watchdog-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rtika/security-watchdog-stderr.log</string>
</dict>
</plist>
PLIST_EOF

    chmod 644 "$watchdog_plist"
    chown root:wheel "$watchdog_plist"
    launchctl load -w "$watchdog_plist" 2>/dev/null || true
    log_success "Security watchdog installed (runs every 5 minutes)"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_agent_watchdog() {
    local plist="/Library/LaunchDaemons/com.f0rtika.security-watchdog.plist"
    if [[ -f "$plist" ]]; then
        launchctl unload "$plist" 2>/dev/null || true
        rm -f "$plist"
        rm -f /usr/local/bin/f0rtika-security-watchdog.sh
        log_success "Security watchdog removed"
    fi
}

check_agent_watchdog() {
    if launchctl list 2>/dev/null | grep -q "com.f0rtika.security-watchdog"; then
        log_success "Security watchdog: running"
    else
        log_warning "Security watchdog: not running"
    fi
}

# ============================================================================
# 8. Process Execution Logging (M1047)
# ============================================================================

harden_process_logging() {
    log_info "=== Configuring Process Execution Logging (M1047) ==="

    local profile_file="/etc/profile.d/f0rtika-defender-history.sh"
    mkdir -p /etc/profile.d 2>/dev/null || true

    cat > "$profile_file" <<'PROFILE_EOF'
# F0RT1KA T1562.001 Defense: Enhanced command history
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=50000
export HISTFILESIZE=50000
export HISTCONTROL=""
shopt -s histappend 2>/dev/null || true
PROFILE_EOF

    chmod 644 "$profile_file"
    log_success "Enhanced command history logging configured"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_process_logging() {
    rm -f /etc/profile.d/f0rtika-defender-history.sh 2>/dev/null || true
    log_success "Removed history logging profile"
}

check_process_logging() {
    if [[ -f "/etc/profile.d/f0rtika-defender-history.sh" ]]; then
        log_success "Enhanced history logging: configured"
    else
        log_warning "Enhanced history logging: not configured"
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

case "$ACTION" in
    apply)
        check_root; check_macos; ensure_dirs
        log_info "Applying hardening settings..."
        echo ""

        harden_sip_gatekeeper;        echo ""
        harden_xprotect_updates;      echo ""
        harden_firewall;              echo ""
        harden_audit;                 echo ""
        harden_edr_agents;            echo ""
        harden_scripting_restriction; echo ""
        harden_agent_watchdog;        echo ""
        harden_process_logging

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

        undo_sip_gatekeeper;        echo ""
        undo_xprotect_updates;      echo ""
        undo_firewall;              echo ""
        undo_audit;                 echo ""
        undo_edr_agents;            echo ""
        undo_scripting_restriction; echo ""
        undo_agent_watchdog;        echo ""
        undo_process_logging

        echo ""
        log_success "Revert complete."
        echo ""
        ;;

    check)
        check_root; check_macos
        log_info "Checking hardening status..."
        echo ""

        check_sip_gatekeeper;        echo ""
        check_xprotect_updates;      echo ""
        check_firewall;              echo ""
        check_audit;                 echo ""
        check_edr_agents;            echo ""
        check_scripting_restriction; echo ""
        check_agent_watchdog;        echo ""
        check_process_logging

        echo ""
        log_info "Check complete."
        echo ""
        ;;

    --help|-h)
        echo "Usage: sudo $SCRIPT_NAME [apply|undo|check]"
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
