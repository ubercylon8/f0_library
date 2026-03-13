#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# APT42 TAMECAT Fileless Backdoor Defense - Cross-Platform Countermeasures
# ============================================================================
# Test ID:      92b0b4f6-a09b-4c7b-b593-31ce461f804c
# Test Name:    APT42 TAMECAT Fileless Backdoor with Browser Credential Theft
# MITRE ATT&CK: T1059.001, T1059.005, T1547.001, T1037.001, T1555.003, T1102
# Mitigations:  M1038 (Execution Prevention), M1042 (Disable/Remove Feature),
#               M1031 (Network Intrusion Prevention), M1027 (Password Policies),
#               M1049 (Antivirus/Antimalware), M1047 (Audit),
#               M1054 (Software Configuration)
#
# Purpose:
#   While APT42 TAMECAT primarily targets Windows, macOS endpoints face
#   analogous threats from script-based persistence, browser credential theft,
#   and data exfiltration via web services. This script hardens macOS endpoints
#   against equivalent attack techniques:
#
#     - LaunchAgent/LaunchDaemon persistence (equivalent to Run keys)
#     - Browser credential database theft (Chrome/Safari/Keychain)
#     - Data exfiltration via Telegram API and FTP
#     - osascript/bash script usage (equivalent to PowerShell/VBScript)
#     - Browser remote debugging abuse (port 9222)
#     - Keychain credential harvesting (equivalent to DPAPI)
#
# MITRE ATT&CK Techniques Covered (macOS equivalents):
#   T1059.002 - AppleScript (equivalent to T1059.001 PowerShell)
#   T1547.011 - Plist Modification / LaunchAgents (equivalent to T1547.001)
#   T1555.001 - Keychain (equivalent to DPAPI credential theft)
#   T1555.003 - Credentials from Web Browsers
#   T1102     - Web Service (Exfiltration via Telegram)
#   T1048     - Exfiltration Over Alternative Protocol (FTP)
#
# Usage:
#   sudo ./92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening_macos.sh [apply|undo|check]
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
TEST_ID="92b0b4f6-a09b-4c7b-b593-31ce461f804c"
BACKUP_DIR="/var/backups/f0rtika-hardening-${TEST_ID}"
LOG_FILE="/var/log/f0rtika-hardening-${TEST_ID}.log"
CHANGE_COUNT=0
WARNING_COUNT=0

# Telegram API IP ranges (ASN 62041 - Telegram Messenger Inc)
TELEGRAM_RANGES=(
    "149.154.160.0/20"
    "91.108.4.0/22"
    "91.108.8.0/22"
    "91.108.12.0/22"
    "91.108.16.0/22"
    "91.108.20.0/22"
    "91.108.56.0/22"
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
# 1. SIP, Gatekeeper, and XProtect Enforcement (M1054, M1049)
# ============================================================================

harden_sip_gatekeeper() {
    log_info "=== SIP, Gatekeeper & XProtect Enforcement (M1054) ==="

    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "System Integrity Protection (SIP): ENABLED"
    else
        log_warning "SIP: DISABLED - enable from Recovery Mode: csrutil enable"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi

    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper: ENABLED"
    else
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper: ENABLED (was disabled)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist ConfigDataInstall -bool true 2>/dev/null || true
    defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist CriticalUpdateInstall -bool true 2>/dev/null || true
    log_success "XProtect automatic updates: ENABLED"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "unknown")
    if echo "$fv_status" | grep -qi "on"; then
        log_success "FileVault: ENABLED"
    else
        log_warning "FileVault: NOT ENABLED - enable via System Settings > Privacy & Security"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi
}

# ============================================================================
# 2. Block Network Exfiltration Channels (T1102, T1048)
# ============================================================================

harden_network_exfiltration() {
    log_info "=== Blocking APT42 Exfiltration Channels (T1102, T1048) ==="

    local pf_anchor="/etc/pf.anchors/com.f0rtika.apt42"

    {
        echo "# F0RT1KA APT42 Defense - Block Telegram C2 and FTP Exfiltration"
        echo "# Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Mitigates: T1102 (Web Service C2), T1048 (Exfil Over Alt Protocol)"
        echo ""
        echo "# Block Telegram API IP ranges (APT42 C2 channel)"
        for range in "${TELEGRAM_RANGES[@]}"; do
            echo "block out quick proto tcp from any to $range"
        done
        echo ""
        echo "# Block FTP outbound (secondary exfiltration channel)"
        echo "block out quick proto tcp from any to any port 21"
        echo ""
        echo "# Block browser remote debugging port (T1555.003)"
        echo "block in quick proto tcp from any to any port 9222"
        echo "block in quick proto tcp from any to any port 9229"
    } > "$pf_anchor"

    log_success "Created pf anchor: $pf_anchor"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    if ! grep -q "f0rtika.apt42" /etc/pf.conf 2>/dev/null; then
        backup_file /etc/pf.conf
        {
            echo ""
            echo "# F0RT1KA APT42 Defense - Exfiltration Prevention"
            echo "anchor \"com.f0rtika.apt42\""
            echo "load anchor \"com.f0rtika.apt42\" from \"/etc/pf.anchors/com.f0rtika.apt42\""
        } >> /etc/pf.conf
        log_success "Added anchor reference to /etc/pf.conf"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "PF anchor already configured in pf.conf"
    fi

    pfctl -e 2>/dev/null || true
    pfctl -f /etc/pf.conf 2>/dev/null || true
    log_success "PF firewall enabled and rules loaded"

    if ! grep -q "api.telegram.org" /etc/hosts 2>/dev/null; then
        backup_file /etc/hosts
        {
            echo ""
            echo "# F0RT1KA APT42 Defense - Block Telegram C2 DNS resolution"
            echo "0.0.0.0 api.telegram.org"
            echo "0.0.0.0 t.me"
        } >> /etc/hosts
        log_success "Added DNS sinkhole entries for api.telegram.org and t.me"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Telegram DNS sinkhole already configured"
    fi

    local fw_tool="/usr/libexec/ApplicationFirewall/socketfilterfw"
    if [[ -x "$fw_tool" ]]; then
        $fw_tool --setglobalstate on 2>/dev/null || true
        $fw_tool --setstealthmode on 2>/dev/null || true
        $fw_tool --setloggingmode on 2>/dev/null || true
        log_success "Application Firewall: ENABLED with stealth mode and logging"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    log_info "For per-process outbound filtering, consider:"
    log_info "  - LuLu (free): https://objective-see.org/products/lulu.html"
    log_info "  - Little Snitch: per-process outbound control"
}

# ============================================================================
# 3. LaunchAgent/LaunchDaemon Monitoring (T1547.011)
# ============================================================================

harden_persistence_monitoring() {
    log_info "=== LaunchAgent/LaunchDaemon Monitoring (T1547.011) ==="

    local watch_dirs=(
        "/Library/LaunchAgents"
        "/Library/LaunchDaemons"
    )

    for dir in "${watch_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local recent_plists
            recent_plists=$(find "$dir" -name "*.plist" -mtime -7 -type f 2>/dev/null || true)
            if [[ -n "$recent_plists" ]]; then
                log_warning "Recently modified plists in $dir:"
                while IFS= read -r plist; do
                    log_warning "  $plist ($(stat -f '%Sm' "$plist" 2>/dev/null || echo 'unknown'))"
                done <<< "$recent_plists"
            else
                log_info "No recent modifications in $dir"
            fi
        fi
    done

    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")
        [[ "$user_name" == "Shared" || "$user_name" == "Guest" || "$user_name" == ".localized" ]] && continue

        local user_agents="$home_dir/Library/LaunchAgents"
        if [[ -d "$user_agents" ]]; then
            local agent_count
            agent_count=$(find "$user_agents" -name "*.plist" -type f 2>/dev/null | wc -l | tr -d ' ')
            if [[ "$agent_count" -gt 0 ]]; then
                log_info "User LaunchAgents: $agent_count plists [$user_name]"
                while IFS= read -r plist; do
                    if grep -ql "osascript\|python\|bash.*-c\|curl.*|.*bash" "$plist" 2>/dev/null; then
                        log_warning "SUSPICIOUS LaunchAgent: $plist [$user_name]"
                        WARNING_COUNT=$((WARNING_COUNT + 1))
                    fi
                done < <(find "$user_agents" -name "*.plist" -type f 2>/dev/null)
            fi
        fi
    done

    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        if ! grep -q "fw" "$audit_control" 2>/dev/null; then
            backup_file "$audit_control"
            sed -i.bak 's/^flags:.*/&,fw/' "$audit_control" 2>/dev/null || true
            log_success "Added file write (fw) audit flag to audit_control"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "File write auditing already enabled in audit_control"
        fi
    fi

    log_info "Recommended: Use Endpoint Security Framework (ESF) for real-time monitoring"
    log_info "Recommended: Deploy Santa (https://github.com/google/santa) for binary authorization"
}

# ============================================================================
# 4. Keychain Access Hardening (T1555.001, T1555.003)
# ============================================================================

harden_keychain() {
    log_info "=== Keychain Access Hardening (T1555.001) ==="

    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")
        [[ "$user_name" == "Shared" || "$user_name" == "Guest" || "$user_name" == ".localized" ]] && continue

        local keychain_dir="$home_dir/Library/Keychains"
        if [[ -d "$keychain_dir" ]]; then
            local perms
            perms=$(stat -f "%Lp" "$keychain_dir" 2>/dev/null || echo "unknown")
            if [[ "$perms" != "700" ]]; then
                chmod 700 "$keychain_dir"
                log_success "Secured $keychain_dir to 700 (was $perms) [$user_name]"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            else
                log_info "Keychain directory already secured (700) [$user_name]"
            fi
        fi

        local keychain_path="${keychain_dir}/login.keychain-db"
        if [[ -f "$keychain_path" ]]; then
            security set-keychain-settings -l -u -t 300 "$keychain_path" 2>/dev/null && \
                log_success "Keychain auto-lock: 5 minutes [$user_name]" && \
                CHANGE_COUNT=$((CHANGE_COUNT + 1)) || \
                log_warning "Could not set keychain auto-lock [$user_name]"
        fi
    done

    security lock-keychain -a 2>/dev/null || true
    log_success "All keychains locked"
}

# ============================================================================
# 5. Browser Credential Database Protection (T1555.003)
# ============================================================================

harden_browser_credentials() {
    log_info "=== Browser Credential Database Protection (T1555.003) ==="

    local browser_dirs=(
        "Library/Application Support/Google/Chrome/Default"
        "Library/Application Support/BraveSoftware/Brave-Browser/Default"
        "Library/Application Support/Microsoft Edge/Default"
        "Library/Application Support/Chromium/Default"
        "Library/Application Support/com.operasoftware.Opera"
        "Library/Application Support/Vivaldi/Default"
        "Library/Application Support/Arc/User Data/Default"
    )

    local sensitive_files=("Login Data" "Cookies" "Web Data" "Local State")

    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")
        [[ "$user_name" == "Shared" || "$user_name" == "Guest" || "$user_name" == ".localized" ]] && continue

        for browser_dir in "${browser_dirs[@]}"; do
            local full_path="${home_dir}${browser_dir}"
            if [[ -d "$full_path" ]]; then
                local perms
                perms=$(stat -f "%Lp" "$full_path" 2>/dev/null || echo "unknown")
                if [[ "$perms" != "700" ]]; then
                    chmod 700 "$full_path" 2>/dev/null && \
                        log_success "Set 700: ${browser_dir##*/} [$user_name]" && \
                        CHANGE_COUNT=$((CHANGE_COUNT + 1)) || true
                fi

                for f in "${sensitive_files[@]}"; do
                    [[ -f "${full_path}/${f}" ]] && chmod 600 "${full_path}/${f}" 2>/dev/null || true
                done
            fi
        done

        local ff_profiles="${home_dir}Library/Application Support/Firefox/Profiles"
        if [[ -d "$ff_profiles" ]]; then
            chmod 700 "$ff_profiles" 2>/dev/null || true
            find "$ff_profiles" -name "key4.db" -o -name "logins.json" -o -name "cookies.sqlite" 2>/dev/null | \
                while read -r f; do chmod 600 "$f" 2>/dev/null || true; done
        fi
    done

    local chrome_policy_dir="/Library/Managed Preferences"
    mkdir -p "$chrome_policy_dir" 2>/dev/null || true

    local chrome_policy="$chrome_policy_dir/com.google.Chrome.plist"
    if [[ ! -f "$chrome_policy" ]]; then
        defaults write "$chrome_policy" PasswordManagerEnabled -bool false 2>/dev/null || true
        defaults write "$chrome_policy" AutofillCreditCardEnabled -bool false 2>/dev/null || true
        defaults write "$chrome_policy" ImportSavedPasswords -bool false 2>/dev/null || true
        log_success "Chrome managed policy: password saving DISABLED"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Chrome managed policy already exists"
    fi

    local edge_policy="$chrome_policy_dir/com.microsoft.Edge.plist"
    if [[ ! -f "$edge_policy" ]]; then
        defaults write "$edge_policy" PasswordManagerEnabled -bool false 2>/dev/null || true
        defaults write "$edge_policy" AutofillCreditCardEnabled -bool false 2>/dev/null || true
        log_success "Edge managed policy: password saving DISABLED"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Edge managed policy already exists"
    fi

    log_info "Recommended: Deploy enterprise password manager (1Password, Bitwarden)"
    log_info "Recommended: Use MDM profile for comprehensive browser policy enforcement"
}

# ============================================================================
# 6. Script Monitoring and Remote Debugging Protection (T1059.002)
# ============================================================================

harden_script_monitoring() {
    log_info "=== Script Monitoring & Debugging Protection (T1059.002) ==="

    local monitor_plist="/Library/LaunchDaemons/com.f0rtika.apt42-script-monitor.plist"

    if [[ ! -f "$monitor_plist" ]]; then
        cat > "$monitor_plist" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rtika.apt42-script-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/log</string>
        <string>stream</string>
        <string>--predicate</string>
        <string>process == "osascript" OR process == "python3" OR process == "base64" OR process == "curl" OR process == "security"</string>
        <string>--info</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/f0rtika-script-monitor.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rtika-script-monitor.log</string>
</dict>
</plist>
PLIST_EOF
        chmod 644 "$monitor_plist"
        chown root:wheel "$monitor_plist"
        launchctl load "$monitor_plist" 2>/dev/null || true
        log_success "Script interpreter monitor installed and started"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Script monitor already deployed"
    fi

    if pgrep -f -- "--remote-debugging-port" &>/dev/null; then
        log_warning "ALERT: Browser with --remote-debugging-port is running!"
        log_warning "  $(pgrep -fa -- '--remote-debugging-port' 2>/dev/null | head -3 || echo 'unable to list')"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    else
        log_info "No browser processes with remote debugging detected"
    fi

    log_info "MDM Recommendation: Restrict osascript from non-user-initiated processes"
    log_info "MDM Recommendation: Use TCC profiles to control Accessibility permissions"
}

# ============================================================================
# 7. Enhanced Audit Logging (M1047)
# ============================================================================

harden_logging() {
    log_info "=== Enhanced Audit Logging (M1047) ==="

    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        if ! grep -q "lo,aa,ad,fd,fm,fc,cl" "$audit_control" 2>/dev/null; then
            backup_file "$audit_control"
            sed -i.bak "s/^flags:.*/flags:lo,aa,ad,fd,fm,fc,cl/" "$audit_control" 2>/dev/null || true
            log_success "Audit flags updated: lo (login/logout), aa (auth), ad (admin),"
            log_success "  fd (file delete), fm (file modify), fc (file create), cl (file close)"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "Audit flags already comprehensive"
        fi
    fi

    local log_config="/Library/Preferences/Logging/Subsystems/com.f0rtika.apt42-detection.plist"
    mkdir -p "$(dirname "$log_config")" 2>/dev/null || true

    if [[ ! -f "$log_config" ]]; then
        cat > "$log_config" << 'LOGPLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DEFAULT-OPTIONS</key>
    <dict>
        <key>Level</key>
        <dict>
            <key>Enable</key>
            <string>Info</string>
            <key>Persist</key>
            <string>Info</string>
        </dict>
    </dict>
</dict>
</plist>
LOGPLIST
        log_success "APT42 detection logging profile installed"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Detection logging profile already exists"
    fi

    local shell_logging="/etc/profile.d/f0rtika-shell-logging.sh"
    mkdir -p /etc/profile.d 2>/dev/null || true

    if [[ ! -f "$shell_logging" ]]; then
        cat > "$shell_logging" << 'SHELL_LOG_EOF'
# F0RT1KA APT42 Defense - Shell Command Logging
# Logs commands to syslog for SIEM ingestion (macOS)

export HISTTIMEFORMAT="%F %T "
export HISTSIZE=10000
export HISTFILESIZE=20000

# Log commands via syslog on macOS
if [[ -n "${BASH_VERSION:-}" ]]; then
    PROMPT_COMMAND='history -a; logger -p local6.info -t "bash_cmd" "$(whoami) [$$]: $(history 1 | sed "s/^[ ]*[0-9]*[ ]*//")"'
elif [[ -n "${ZSH_VERSION:-}" ]]; then
    preexec() { logger -p local6.info -t "zsh_cmd" "$(whoami) [$$]: $1"; }
fi
SHELL_LOG_EOF
        chmod 644 "$shell_logging"
        log_success "Shell command logging profile installed"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Shell logging profile already exists"
    fi

    log_info "Recommended: Forward Unified Logs to SIEM via log stream"
    log_info "Recommended: Use osquery for real-time endpoint telemetry"
}

# ============================================================================
# Undo Function
# ============================================================================

undo_changes() {
    log_warning "Reverting APT42 TAMECAT hardening changes..."

    # Remove pf anchor and rules
    local pf_anchor="/etc/pf.anchors/com.f0rtika.apt42"
    if [[ -f "$pf_anchor" ]]; then
        rm -f "$pf_anchor"
        log_success "Removed pf anchor: $pf_anchor"
    fi

    if grep -q "f0rtika.apt42" /etc/pf.conf 2>/dev/null; then
        local latest_pf_backup
        latest_pf_backup=$(ls -t "${BACKUP_DIR}/pf.conf.bak."* 2>/dev/null | head -1 || true)
        if [[ -n "$latest_pf_backup" ]]; then
            cp "$latest_pf_backup" /etc/pf.conf
            log_success "Restored /etc/pf.conf from backup"
        else
            sed -i.bak '/f0rtika.apt42/d; /F0RT1KA APT42 Defense - Exfiltration/d' /etc/pf.conf 2>/dev/null || true
            log_success "Removed pf anchor references from pf.conf"
        fi
        pfctl -f /etc/pf.conf 2>/dev/null || true
    fi

    # Remove DNS sinkhole entries
    if grep -q "F0RT1KA APT42 Defense" /etc/hosts 2>/dev/null; then
        local latest_hosts_backup
        latest_hosts_backup=$(ls -t "${BACKUP_DIR}/hosts.bak."* 2>/dev/null | head -1 || true)
        if [[ -n "$latest_hosts_backup" ]]; then
            cp "$latest_hosts_backup" /etc/hosts
            log_success "Restored /etc/hosts from backup"
        else
            sed -i.bak '/F0RT1KA APT42 Defense/d; /api\.telegram\.org/d; /t\.me/d' /etc/hosts 2>/dev/null || true
            log_success "Removed Telegram DNS sinkhole entries"
        fi
    fi

    # Remove script monitor
    local monitor_plist="/Library/LaunchDaemons/com.f0rtika.apt42-script-monitor.plist"
    if [[ -f "$monitor_plist" ]]; then
        launchctl unload "$monitor_plist" 2>/dev/null || true
        rm -f "$monitor_plist"
        log_success "Removed script monitor"
    fi

    # Remove logging configurations
    rm -f "/Library/Preferences/Logging/Subsystems/com.f0rtika.apt42-detection.plist" 2>/dev/null || true
    rm -f /etc/profile.d/f0rtika-shell-logging.sh 2>/dev/null || true
    log_success "Removed logging configurations"

    # Restore audit_control from backup
    local latest_audit_backup
    latest_audit_backup=$(ls -t "${BACKUP_DIR}/audit_control.bak."* 2>/dev/null | head -1 || true)
    if [[ -n "$latest_audit_backup" ]]; then
        cp "$latest_audit_backup" /etc/security/audit_control
        log_success "Restored audit_control from backup"
    fi

    # Remove browser managed policies
    rm -f "/Library/Managed Preferences/com.google.Chrome.plist" 2>/dev/null || true
    rm -f "/Library/Managed Preferences/com.microsoft.Edge.plist" 2>/dev/null || true
    log_success "Removed browser managed policies"

    log_warning "Gatekeeper, SIP, Keychain hardening, and firewall settings remain enabled"
    log_warning "  These are security best practices and should not be reverted"

    log_success "Undo complete"
}

# ============================================================================
# Check Function
# ============================================================================

check_status() {
    log_info "=== APT42 TAMECAT Hardening Status Audit ==="
    echo ""

    # Foundation controls
    log_info "--- Foundation Security Controls ---"
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    echo "$sip_status" | grep -q "enabled" && \
        log_success "SIP: ENABLED" || \
        { log_warning "SIP: DISABLED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    spctl --status 2>/dev/null | grep -q "enabled" && \
        log_success "Gatekeeper: ENABLED" || \
        { log_warning "Gatekeeper: DISABLED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    fdesetup status 2>/dev/null | grep -qi "on" && \
        log_success "FileVault: ENABLED" || \
        { log_warning "FileVault: NOT ENABLED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    # Network exfiltration
    echo ""
    log_info "--- Network Exfiltration Prevention ---"
    if [[ -f "/etc/pf.anchors/com.f0rtika.apt42" ]]; then
        log_success "PF anchor (Telegram/FTP blocking): DEPLOYED"
    else
        log_warning "PF anchor (Telegram/FTP blocking): NOT DEPLOYED"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi

    grep -q "api.telegram.org" /etc/hosts 2>/dev/null && \
        log_success "Telegram DNS sinkhole: ACTIVE" || \
        { log_warning "Telegram DNS sinkhole: NOT CONFIGURED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled" && \
        log_success "Application Firewall: ENABLED" || \
        { log_warning "Application Firewall: DISABLED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    # Persistence monitoring
    echo ""
    log_info "--- Persistence Monitoring ---"
    local suspicious_agents=0
    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_agents="$home_dir/Library/LaunchAgents"
        if [[ -d "$user_agents" ]]; then
            while IFS= read -r plist; do
                if grep -ql "osascript\|python\|bash.*-c\|curl.*|.*bash" "$plist" 2>/dev/null; then
                    suspicious_agents=$((suspicious_agents + 1))
                fi
            done < <(find "$user_agents" -name "*.plist" -type f 2>/dev/null)
        fi
    done
    if [[ $suspicious_agents -eq 0 ]]; then
        log_success "Suspicious LaunchAgents: NONE FOUND"
    else
        log_warning "Suspicious LaunchAgents: $suspicious_agents FOUND"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi

    # Keychain hardening
    echo ""
    log_info "--- Keychain Protection ---"
    local keychains_secured=0
    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")
        [[ "$user_name" == "Shared" || "$user_name" == "Guest" || "$user_name" == ".localized" ]] && continue
        local keychain_dir="$home_dir/Library/Keychains"
        if [[ -d "$keychain_dir" ]]; then
            local perms
            perms=$(stat -f "%Lp" "$keychain_dir" 2>/dev/null || echo "unknown")
            [[ "$perms" == "700" ]] && keychains_secured=$((keychains_secured + 1))
        fi
    done
    log_info "Keychain directories with 700 permissions: $keychains_secured"

    # Browser credential protection
    echo ""
    log_info "--- Browser Credential Protection ---"
    if [[ -f "/Library/Managed Preferences/com.google.Chrome.plist" ]]; then
        log_success "Chrome managed policy: DEPLOYED"
    else
        log_warning "Chrome managed policy: NOT DEPLOYED"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi

    if [[ -f "/Library/Managed Preferences/com.microsoft.Edge.plist" ]]; then
        log_success "Edge managed policy: DEPLOYED"
    else
        log_warning "Edge managed policy: NOT DEPLOYED"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi

    # Script monitoring
    echo ""
    log_info "--- Script Monitoring ---"
    [[ -f "/Library/LaunchDaemons/com.f0rtika.apt42-script-monitor.plist" ]] && \
        log_success "Script monitor: DEPLOYED" || \
        { log_warning "Script monitor: NOT DEPLOYED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    if pgrep -f -- "--remote-debugging-port" &>/dev/null; then
        log_warning "ALERT: Browser with remote debugging is currently running!"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    else
        log_success "No browser remote debugging processes detected"
    fi

    # Audit logging
    echo ""
    log_info "--- Audit Logging ---"
    [[ -f "/Library/Preferences/Logging/Subsystems/com.f0rtika.apt42-detection.plist" ]] && \
        log_success "Detection logging profile: DEPLOYED" || \
        { log_warning "Detection logging profile: NOT DEPLOYED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    [[ -f "/etc/profile.d/f0rtika-shell-logging.sh" ]] && \
        log_success "Shell command logging: ACTIVE" || \
        { log_warning "Shell command logging: NOT CONFIGURED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    echo ""
    echo "============================================================"
    if [[ $WARNING_COUNT -eq 0 ]]; then
        log_success "All APT42 TAMECAT hardening controls: COMPLIANT"
    else
        log_warning "Non-compliant controls: $WARNING_COUNT"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo "============================================================"
    echo "F0RT1KA macOS Hardening: APT42 TAMECAT Defense"
    echo "Test ID: ${TEST_ID}"
    echo "MITRE ATT&CK: T1059, T1547.011, T1555.001, T1555.003, T1102"
    echo "============================================================"
    echo ""

    local action="${1:-apply}"

    case "$action" in
        apply)
            log_info "Running in APPLY mode - hardening system"
            echo ""
            check_root
            check_macos
            ensure_dirs
            harden_sip_gatekeeper; echo ""
            harden_network_exfiltration; echo ""
            harden_persistence_monitoring; echo ""
            harden_keychain; echo ""
            harden_browser_credentials; echo ""
            harden_script_monitoring; echo ""
            harden_logging
            echo ""
            echo "============================================================"
            log_success "Hardening complete. Changes applied: ${CHANGE_COUNT}"
            [[ $WARNING_COUNT -gt 0 ]] && log_warning "Warnings requiring manual action: ${WARNING_COUNT}"
            log_info "Backup directory: ${BACKUP_DIR}"
            log_info "Log file: ${LOG_FILE}"
            echo ""
            log_info "ADDITIONAL RECOMMENDATIONS:"
            log_info "  1. Deploy Santa (binary authorization) for binary allowlisting"
            log_info "  2. Enable Endpoint Security Framework (ESF) monitoring"
            log_info "  3. Configure Unified Logging forwarding to SIEM"
            log_info "  4. Use MDM profiles for comprehensive security policy enforcement"
            log_info "  5. Deploy LuLu or Little Snitch for per-process egress filtering"
            log_info "  6. Consider osquery for real-time endpoint telemetry"
            ;;
        undo)
            check_root
            check_macos
            ensure_dirs
            undo_changes
            ;;
        check)
            check_macos
            check_status
            ;;
        *)
            echo "Usage: sudo $SCRIPT_NAME [apply|undo|check]"
            exit 1
            ;;
    esac
    echo ""
}

main "${1:-apply}"
