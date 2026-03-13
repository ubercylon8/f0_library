#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# ============================================================================
# Test ID:      244dfb88-9068-4db4-9fa8-dbc49517f63d
# Test Name:    DPRK BlueNoroff Financial Sector Attack Chain
# MITRE ATT&CK: T1553.001, T1543.004, T1059.002, T1555.001, T1056.002,
#               T1071.001, T1573.002, T1071.004, T1041, T1567.002, T1560.001
# Mitigations:  M1038 (Execution Prevention), M1022 (Restrict Permissions),
#               M1031 (Network Intrusion Prevention), M1037 (Filter Network),
#               M1045 (Code Signing), M1027 (Password Policies),
#               M1047 (Audit), M1042 (Disable Feature)
#
# Purpose:
#   Hardens macOS endpoints against BlueNoroff/Lazarus (DPRK) attack techniques
#   targeting the financial and cryptocurrency sectors. Addresses all 5 stages
#   of the attack chain: Gatekeeper bypass, LaunchAgent persistence, credential
#   harvesting (osascript + Keychain), multi-protocol C2, and data exfiltration.
#
# Campaigns Addressed:
#   RustBucket, Hidden Risk, KANDYKORN, TodoSwift, BeaverTail
#
# Usage:
#   sudo ./244dfb88-9068-4db4-9fa8-dbc49517f63d_hardening_macos.sh [apply|undo|check]
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
BACKUP_DIR="/var/backups/f0rtika-hardening-244dfb88"
LOG_FILE="/var/log/f0rtika-hardening-244dfb88.log"
CHANGE_COUNT=0

# BlueNoroff C2 domains (high-confidence threat intelligence)
C2_DOMAINS=(
    "linkpc.net"
    "dnx.capital"
    "swissborg.blog"
    "on-offx.com"
    "tokenview.xyz"
)

# Known C2 subdomains
C2_SUBDOMAINS=(
    "beacon.linkpc.net"
    "app.linkpc.net"
    "update.linkpc.net"
    "check.linkpc.net"
    "cloud.dnx.capital"
)

# Known malicious LaunchAgent/LaunchDaemon labels
MALICIOUS_LABELS=(
    "com.apple.systemupdate"
    "com.avatar.update.wake"
    "com.apple.security.updateagent"
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
# 1. Gatekeeper & Code Signing Enforcement (T1553.001)
# ============================================================================
# BlueNoroff uses hijacked Apple Developer IDs to notarize malware and
# delivers payloads via curl (which bypasses com.apple.quarantine). The Hidden
# Risk campaign used Developer ID "Avantis Regtech Private Limited" (2S8XHJ7948).

harden_gatekeeper() {
    log_info "Section 1: Gatekeeper & Code Signing Enforcement (T1553.001)"

    # Check SIP status
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "System Integrity Protection (SIP) is enabled"
    else
        log_warning "SIP is NOT enabled -- critical for Gatekeeper enforcement"
        log_warning "To enable: boot to Recovery Mode > Terminal > csrutil enable"
    fi

    # Ensure Gatekeeper is enabled
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper is enabled"
    else
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    # Ensure quarantine enforcement is not disabled
    local quarantine_default
    quarantine_default=$(defaults read com.apple.LaunchServices LSQuarantine 2>/dev/null || echo "not set")
    if [[ "$quarantine_default" == "0" ]]; then
        defaults write com.apple.LaunchServices LSQuarantine -bool true 2>/dev/null || true
        log_success "Re-enabled quarantine flag enforcement (was disabled)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Quarantine enforcement is active"
    fi

    # Enable Library Validation
    local lib_val
    lib_val=$(defaults read /Library/Preferences/com.apple.security.libraryvalidation Enabled 2>/dev/null || echo "not set")
    if [[ "$lib_val" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.security.libraryvalidation Enabled -bool true 2>/dev/null || true
        log_success "Library Validation enforcement enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Library Validation already enabled"
    fi

    # Enable automatic XProtect and security data updates
    local critical_update
    critical_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "not set")
    if [[ "$critical_update" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null || true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true 2>/dev/null || true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true 2>/dev/null || true
        log_success "Automatic XProtect/security updates enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Automatic security updates already enabled"
    fi

    # Check FileVault status
    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "unknown")
    if echo "$fv_status" | grep -qi "on"; then
        log_success "FileVault: enabled (protects Keychain at rest)"
    else
        log_warning "FileVault is NOT enabled -- protects credential stores at rest"
        log_warning "Enable via: System Settings > Privacy & Security > FileVault"
    fi
}

undo_gatekeeper() {
    log_warning "SIP, Gatekeeper, and quarantine settings should NOT be weakened"
    log_info "These settings left as-is (security critical)"
}

check_gatekeeper() {
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

    local quarantine_default
    quarantine_default=$(defaults read com.apple.LaunchServices LSQuarantine 2>/dev/null || echo "not set")
    if [[ "$quarantine_default" != "0" ]]; then
        log_success "Quarantine enforcement: active"
    else
        log_warning "Quarantine enforcement: DISABLED"
    fi

    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "unknown")
    if echo "$fv_status" | grep -qi "on"; then
        log_success "FileVault: enabled"
    else
        log_warning "FileVault: NOT enabled"
    fi
}

# ============================================================================
# 2. LaunchAgent / LaunchDaemon Persistence Protection (T1543.004)
# ============================================================================
# BlueNoroff installs persistence via:
#   - com.apple.systemupdate.plist in ~/Library/LaunchAgents/ (RustBucket)
#   - com.avatar.update.wake.plist in ~/Library/LaunchAgents/ (BeaverTail)
#   - com.apple.security.updateagent.plist in /Library/LaunchDaemons/ (root)
# Also removes hidden payload directories in /Users/Shared/.

harden_launchagent_persistence() {
    log_info "Section 2: LaunchAgent/LaunchDaemon Persistence Protection (T1543.004)"

    # Scan for known malicious LaunchAgent labels across all user accounts
    local found_malicious=0
    for user_home in /Users/*/; do
        local la_dir="${user_home}Library/LaunchAgents"
        if [[ -d "$la_dir" ]]; then
            for label in "${MALICIOUS_LABELS[@]}"; do
                local plist_path="${la_dir}/${label}.plist"
                if [[ -f "$plist_path" ]]; then
                    log_warning "FOUND known BlueNoroff persistence: $plist_path"
                    backup_file "$plist_path"
                    launchctl unload "$plist_path" 2>/dev/null || true
                    rm -f "$plist_path"
                    log_success "Removed malicious LaunchAgent: $label"
                    found_malicious=1
                    CHANGE_COUNT=$((CHANGE_COUNT + 1))
                fi
            done

            # Scan for ANY plist with com.apple.* label from non-Apple origin
            for plist_file in "$la_dir"/com.apple.*.plist; do
                if [[ -f "$plist_file" ]]; then
                    # Check if it is a known Apple plist or suspicious
                    local plist_name
                    plist_name=$(basename "$plist_file")
                    case "$plist_name" in
                        com.apple.AddressBook*|com.apple.CalendarAgent*|com.apple.Safari*|com.apple.iCloudHelper*)
                            # Known legitimate Apple plists
                            ;;
                        *)
                            log_warning "Suspicious com.apple.* plist in user LaunchAgents: $plist_file"
                            log_warning "  Review contents: plutil -p $plist_file"
                            ;;
                    esac
                fi
            done
        fi
    done

    # Check system-level LaunchDaemons
    for label in "${MALICIOUS_LABELS[@]}"; do
        local daemon_path="/Library/LaunchDaemons/${label}.plist"
        if [[ -f "$daemon_path" ]]; then
            log_warning "FOUND known BlueNoroff persistence: $daemon_path"
            backup_file "$daemon_path"
            launchctl unload "$daemon_path" 2>/dev/null || true
            rm -f "$daemon_path"
            log_success "Removed malicious LaunchDaemon: $label"
            found_malicious=1
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    if [[ $found_malicious -eq 0 ]]; then
        log_info "No known BlueNoroff persistence mechanisms found"
    fi

    # Remove hidden payload directories used by BlueNoroff campaigns
    local hidden_dirs=(
        "/Users/Shared/.system"
        "/Users/Shared/.invisible_ferret"
        "/Library/Application Support/.security"
    )
    for hdir in "${hidden_dirs[@]}"; do
        if [[ -d "$hdir" ]]; then
            log_warning "FOUND suspicious hidden directory: $hdir"
            rm -rf "$hdir"
            log_success "Removed hidden directory: $hdir"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    # Create monitoring configuration for EDR/SIEM
    local monitor_config="/Library/Preferences/com.f0rtika.launchagent-monitor.plist"
    if [[ ! -f "$monitor_config" ]]; then
        cat > "$monitor_config" <<'MONITOR_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>MonitoredPaths</key>
    <array>
        <string>~/Library/LaunchAgents/</string>
        <string>/Library/LaunchAgents/</string>
        <string>/Library/LaunchDaemons/</string>
    </array>
    <key>AlertOnLabels</key>
    <array>
        <string>com.apple.systemupdate</string>
        <string>com.avatar.update.wake</string>
        <string>com.apple.security.updateagent</string>
    </array>
    <key>Note</key>
    <string>F0RT1KA BlueNoroff defense - alert on non-Apple com.apple.* plist creation</string>
</dict>
</plist>
MONITOR_EOF
        chmod 644 "$monitor_config"
        log_success "Created LaunchAgent monitoring configuration"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "LaunchAgent monitoring configuration already exists"
    fi
}

undo_launchagent_persistence() {
    log_info "Reverting LaunchAgent monitoring..."
    rm -f "/Library/Preferences/com.f0rtika.launchagent-monitor.plist" 2>/dev/null || true
    log_success "Removed monitoring configuration"
    log_info "Removed malicious plists were backed up to $BACKUP_DIR"
}

check_launchagent_persistence() {
    local found=0
    for user_home in /Users/*/; do
        local la_dir="${user_home}Library/LaunchAgents"
        if [[ -d "$la_dir" ]]; then
            for label in "${MALICIOUS_LABELS[@]}"; do
                if [[ -f "${la_dir}/${label}.plist" ]]; then
                    log_warning "ALERT: BlueNoroff persistence: ${la_dir}/${label}.plist"
                    found=1
                fi
            done
        fi
    done
    for label in "${MALICIOUS_LABELS[@]}"; do
        if [[ -f "/Library/LaunchDaemons/${label}.plist" ]]; then
            log_warning "ALERT: BlueNoroff persistence: /Library/LaunchDaemons/${label}.plist"
            found=1
        fi
    done
    if [[ $found -eq 0 ]]; then
        log_success "No known BlueNoroff LaunchAgent/LaunchDaemon persistence found"
    fi

    # Check for hidden payload directories
    for hdir in "/Users/Shared/.system" "/Users/Shared/.invisible_ferret" "/Library/Application Support/.security"; do
        if [[ -d "$hdir" ]]; then
            log_warning "ALERT: Suspicious hidden directory exists: $hdir"
        fi
    done
}

# ============================================================================
# 3. .zshenv Protection (T1543.004 - Hidden Risk Campaign)
# ============================================================================
# The Hidden Risk campaign (SentinelLabs, Nov 2024) abuses ~/.zshenv:
#   - Executes for EVERY new Zsh session (interactive and non-interactive)
#   - Does NOT trigger macOS Ventura background Login Items notification
#   - Makes persistence invisible to the user

harden_zshenv() {
    log_info "Section 3: .zshenv Protection (Hidden Risk Campaign, T1543.004)"

    for user_home in /Users/*/; do
        local username
        username=$(basename "$user_home")

        # Skip system/service accounts
        [[ "$username" == "Shared" || "$username" == "Guest" || "$username" == ".localized" ]] && continue

        local zshenv="${user_home}.zshenv"

        if [[ -f "$zshenv" ]]; then
            # Check for Hidden Risk campaign indicators
            if grep -qiE "(linkpc\.net|curl.*\|.*bash|wget.*\|.*sh|HIDDEN_RISK|_update_check|ioreg.*IOPlatformUUID)" "$zshenv" 2>/dev/null; then
                log_warning "ALERT: Suspicious content in ${zshenv} (possible Hidden Risk persistence)"
                backup_file "$zshenv"

                # Remove malicious lines, preserve legitimate content
                local clean_content
                clean_content=$(grep -viE "(HIDDEN_RISK|linkpc\.net|_update_check|curl.*\|.*bash|ioreg.*IOPlatformUUID)" "$zshenv" 2>/dev/null || true)
                if [[ -n "$clean_content" ]]; then
                    echo "$clean_content" > "$zshenv"
                    log_success "Cleaned suspicious content from $zshenv"
                else
                    rm -f "$zshenv"
                    log_success "Removed entirely-malicious $zshenv"
                fi
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            else
                log_info "  ${username}: .zshenv present, no suspicious content"
            fi

            # Record baseline checksum
            local checksum
            checksum=$(shasum -a 256 "$zshenv" 2>/dev/null | awk '{print $1}')
            echo "${checksum}  ${zshenv}" >> "${BACKUP_DIR}/zshenv_checksums.txt" 2>/dev/null || true
        fi
    done

    log_info "TIP: To lock .zshenv against modification:"
    log_info "  chflags uchg ~/.zshenv   (set immutable)"
    log_info "  chflags nouchg ~/.zshenv (remove when needed)"
}

undo_zshenv() {
    log_info "If .zshenv was cleaned, originals are backed up in $BACKUP_DIR"
    rm -f "${BACKUP_DIR}/zshenv_checksums.txt" 2>/dev/null || true
}

check_zshenv() {
    for user_home in /Users/*/; do
        local username
        username=$(basename "$user_home")
        [[ "$username" == "Shared" || "$username" == "Guest" || "$username" == ".localized" ]] && continue

        local zshenv="${user_home}.zshenv"
        if [[ -f "$zshenv" ]]; then
            if grep -qiE "(linkpc\.net|curl.*\|.*bash|HIDDEN_RISK)" "$zshenv" 2>/dev/null; then
                log_warning "ALERT: Suspicious .zshenv for ${username}"
            else
                log_info "  ${username}: .zshenv clean"
            fi
            # Check immutable flag
            local flags
            flags=$(ls -lO "$zshenv" 2>/dev/null | awk '{print $5}')
            if echo "$flags" | grep -q "uchg"; then
                log_success "  ${username}: .zshenv has immutable flag"
            fi
        fi
    done
}

# ============================================================================
# 4. osascript & Credential Phishing Monitoring (T1059.002, T1056.002)
# ============================================================================
# BlueNoroff, AMOS, and Banshee stealers use osascript to display fake
# password dialogs: osascript -e 'display dialog "..." with hidden answer'
# Captured passwords are validated via: dscl /Local/Default -authonly

harden_osascript() {
    log_info "Section 4: osascript Credential Phishing Monitoring (T1059.002, T1056.002)"

    # Deploy a periodic audit script for osascript abuse detection
    local audit_script="/usr/local/bin/f0rtika-osascript-audit.sh"
    mkdir -p /usr/local/bin 2>/dev/null || true

    cat > "$audit_script" <<'AUDIT_EOF'
#!/usr/bin/env bash
# F0RT1KA: Audit osascript usage for credential phishing indicators
# Detects: display dialog with hidden answer, dscl -authonly
LOG="/var/log/f0rtika-osascript-audit.log"

log show --last 5m --predicate 'process == "osascript"' 2>/dev/null | \
    grep -iE "display dialog|hidden answer|password" | while read -r line; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ALERT] Suspicious osascript: $line" >> "$LOG"
done

log show --last 5m --predicate 'process == "dscl"' 2>/dev/null | \
    grep -i "authonly" | while read -r line; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ALERT] Credential validation: $line" >> "$LOG"
done

# Detect tccutil reset attempts
log show --last 5m --predicate 'process == "tccutil"' 2>/dev/null | \
    grep -i "reset" | while read -r line; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ALERT] TCC manipulation: $line" >> "$LOG"
done
AUDIT_EOF
    chmod 755 "$audit_script"

    # Install LaunchDaemon to run audit every 5 minutes
    local audit_plist="/Library/LaunchDaemons/com.f0rtika.osascript-audit.plist"
    if [[ ! -f "$audit_plist" ]]; then
        cat > "$audit_plist" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rtika.osascript-audit</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/f0rtika-osascript-audit.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
PLIST_EOF
        chmod 644 "$audit_plist"
        launchctl load "$audit_plist" 2>/dev/null || true
        log_success "Installed osascript audit daemon (runs every 5 minutes)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "osascript audit daemon already installed"
    fi

    log_info "RECOMMENDATION: Deploy MDM profile restricting osascript to approved apps"
    log_info "  This prevents fake password dialog attacks from unknown processes"
}

undo_osascript() {
    local audit_plist="/Library/LaunchDaemons/com.f0rtika.osascript-audit.plist"
    if [[ -f "$audit_plist" ]]; then
        launchctl unload "$audit_plist" 2>/dev/null || true
        rm -f "$audit_plist"
    fi
    rm -f /usr/local/bin/f0rtika-osascript-audit.sh 2>/dev/null || true
    log_success "Removed osascript audit daemon and script"
}

check_osascript() {
    if [[ -f "/Library/LaunchDaemons/com.f0rtika.osascript-audit.plist" ]]; then
        log_success "osascript audit daemon: installed"
    else
        log_warning "osascript audit daemon: not installed"
    fi
}

# ============================================================================
# 5. Keychain Access Hardening (T1555.001)
# ============================================================================
# macOS stealers extract credentials via:
#   security dump-keychain -d ~/Library/Keychains/login.keychain-db
#   security find-generic-password -ga "Chrome" -w
#   security find-internet-password -s "coinbase.com" -g

harden_keychain() {
    log_info "Section 5: Keychain Access Hardening (T1555.001)"

    for user_home in /Users/*/; do
        local username
        username=$(basename "$user_home")
        [[ "$username" == "Shared" || "$username" == "Guest" || "$username" == ".localized" ]] && continue

        local keychain="${user_home}Library/Keychains/login.keychain-db"
        if [[ -f "$keychain" ]]; then
            # Set auto-lock timeout to 5 minutes
            security set-keychain-settings -t 300 -l "$keychain" 2>/dev/null || true
            log_success "Set Keychain auto-lock to 5 minutes for ${username}"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    log_info "RECOMMENDATION: Configure Keychain to require password for each access"
    log_info "  Prevents bulk extraction even when the user session is active"
}

undo_keychain() {
    for user_home in /Users/*/; do
        local username
        username=$(basename "$user_home")
        [[ "$username" == "Shared" || "$username" == "Guest" || "$username" == ".localized" ]] && continue
        local keychain="${user_home}Library/Keychains/login.keychain-db"
        if [[ -f "$keychain" ]]; then
            security set-keychain-settings "$keychain" 2>/dev/null || true
            log_success "Reset Keychain settings to default for ${username}"
        fi
    done
}

check_keychain() {
    for user_home in /Users/*/; do
        local username
        username=$(basename "$user_home")
        [[ "$username" == "Shared" || "$username" == "Guest" || "$username" == ".localized" ]] && continue
        local keychain="${user_home}Library/Keychains/login.keychain-db"
        if [[ -f "$keychain" ]]; then
            local settings
            settings=$(security show-keychain-info "$keychain" 2>&1 || echo "unknown")
            if echo "$settings" | grep -q "no-timeout"; then
                log_warning "${username}: Keychain has no auto-lock timeout"
            else
                log_success "${username}: Keychain has auto-lock configured"
            fi
        fi
    done
}

# ============================================================================
# 6. C2 Domain and Network Blocking (T1071.001, T1071.004, T1573.002)
# ============================================================================
# BlueNoroff C2 channels:
#   - Sliver mTLS on port 8888 (beacon.linkpc.net)
#   - HTTPS C2 (app.linkpc.net, cloud.dnx.capital, swissborg.blog)
#   - DNS tunneling (update.linkpc.net with base64-encoded subdomain queries)
#   - Google Drive URL staging (TodoSwift pattern)

harden_c2_blocking() {
    log_info "Section 6: C2 Domain and Network Blocking (T1071.001, T1071.004, T1573.002)"

    backup_file /etc/hosts

    # Block C2 parent domains
    for domain in "${C2_DOMAINS[@]}"; do
        if ! grep -qF "$domain" /etc/hosts 2>/dev/null || ! grep -qF "F0RT1KA-BlueNoroff" /etc/hosts 2>/dev/null; then
            if ! grep -qF "0.0.0.0 ${domain}" /etc/hosts 2>/dev/null; then
                echo "0.0.0.0 ${domain} # F0RT1KA-BlueNoroff C2 block" >> /etc/hosts
                log_success "Blocked C2 domain: ${domain}"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            else
                log_info "Already blocked: ${domain}"
            fi
        fi
    done

    # Block specific known C2 subdomains
    for subdomain in "${C2_SUBDOMAINS[@]}"; do
        if ! grep -qF "$subdomain" /etc/hosts 2>/dev/null; then
            echo "0.0.0.0 ${subdomain} # F0RT1KA-BlueNoroff C2 subdomain" >> /etc/hosts
            log_success "Blocked C2 subdomain: ${subdomain}"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    # Flush DNS cache
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    log_success "DNS cache flushed"

    # Block outbound port 8888 via pf (packet filter)
    local pf_anchor="/etc/pf.anchors/com.f0rtika.bluenoroff"
    if [[ ! -f "$pf_anchor" ]]; then
        cat > "$pf_anchor" <<'PF_EOF'
# F0RT1KA BlueNoroff Defense - Block Sliver C2 default port
# MITRE ATT&CK: T1573.002 - Encrypted Channel: Asymmetric Cryptography
block out proto tcp from any to any port 8888
PF_EOF
        chmod 644 "$pf_anchor"

        backup_file /etc/pf.conf
        if ! grep -qF "com.f0rtika.bluenoroff" /etc/pf.conf 2>/dev/null; then
            echo "" >> /etc/pf.conf
            echo "# F0RT1KA BlueNoroff C2 blocking" >> /etc/pf.conf
            echo 'anchor "com.f0rtika.bluenoroff"' >> /etc/pf.conf
            echo 'load anchor "com.f0rtika.bluenoroff" from "/etc/pf.anchors/com.f0rtika.bluenoroff"' >> /etc/pf.conf
        fi

        pfctl -e 2>/dev/null || true
        pfctl -f /etc/pf.conf 2>/dev/null || true
        log_success "Blocked outbound TCP port 8888 (Sliver mTLS default)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Port 8888 blocking already configured"
    fi

    # Enable macOS Application Firewall
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$fw_status" | grep -q "disabled"; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on > /dev/null 2>&1 || true
        /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on > /dev/null 2>&1 || true
        /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on > /dev/null 2>&1 || true
        log_success "Application Firewall enabled with stealth mode"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Application Firewall already enabled"
    fi
}

undo_c2_blocking() {
    # Remove hosts entries
    if [[ -f /etc/hosts ]]; then
        local filtered
        filtered=$(grep -v "F0RT1KA-BlueNoroff" /etc/hosts 2>/dev/null || cat /etc/hosts)
        echo "$filtered" > /etc/hosts
        log_success "Removed BlueNoroff C2 entries from /etc/hosts"
    fi

    # Remove pf anchor
    rm -f "/etc/pf.anchors/com.f0rtika.bluenoroff" 2>/dev/null || true
    if grep -qF "com.f0rtika.bluenoroff" /etc/pf.conf 2>/dev/null; then
        local filtered_pf
        filtered_pf=$(grep -vE "f0rtika\.bluenoroff|F0RT1KA BlueNoroff" /etc/pf.conf)
        echo "$filtered_pf" > /etc/pf.conf
        pfctl -f /etc/pf.conf 2>/dev/null || true
        log_success "Removed pf.conf BlueNoroff entries"
    fi

    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
}

check_c2_blocking() {
    for domain in "${C2_DOMAINS[@]}"; do
        if grep -qF "$domain" /etc/hosts 2>/dev/null; then
            log_success "C2 blocked: ${domain}"
        else
            log_warning "C2 NOT blocked: ${domain}"
        fi
    done

    if [[ -f "/etc/pf.anchors/com.f0rtika.bluenoroff" ]]; then
        log_success "Port 8888 block: active"
    else
        log_warning "Port 8888 block: not configured"
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
# 7. Crypto Wallet Protection (BlueNoroff Primary Objective)
# ============================================================================
# BlueNoroff targets:
#   - MetaMask vault (Chrome extension nkbihfbeogaeaoehlefnkodbefgpgknn)
#   - Exodus desktop wallet (~Library/Application Support/Exodus/)
#   - Coinbase Wallet (Chrome extension hnfanknocfeofbddgcijnmhnfnkdnaad)

harden_crypto_wallet() {
    log_info "Section 7: Crypto Wallet Data Protection"

    local wallet_paths=(
        "Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"
        "Library/Application Support/Google/Chrome/Default/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad"
        "Library/Application Support/Exodus"
    )

    local baseline_file="${BACKUP_DIR}/wallet_baseline.txt"
    echo "# F0RT1KA Crypto Wallet Integrity Baseline - $(date '+%Y-%m-%d %H:%M:%S')" > "$baseline_file"

    for user_home in /Users/*/; do
        local username
        username=$(basename "$user_home")
        [[ "$username" == "Shared" || "$username" == "Guest" || "$username" == ".localized" ]] && continue

        for wallet_rel in "${wallet_paths[@]}"; do
            local wallet_full="${user_home}${wallet_rel}"
            if [[ -d "$wallet_full" ]]; then
                log_info "  Found wallet data for ${username}: $(basename "$wallet_rel")"
                find "$wallet_full" -type f -exec shasum -a 256 {} \; >> "$baseline_file" 2>/dev/null || true
            fi
        done
    done

    chmod 600 "$baseline_file"
    log_success "Created crypto wallet integrity baseline"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    log_info "CRITICAL RECOMMENDATIONS for crypto asset protection:"
    log_info "  1. Use hardware wallets (Ledger, Trezor) for significant holdings"
    log_info "  2. Enable 2FA on all exchange accounts (hardware key preferred)"
    log_info "  3. Use a dedicated browser profile for crypto operations"
    log_info "  4. Never install cryptocurrency apps from unsolicited messages"
    log_info "  5. Be cautious of job interview requests involving code execution"
}

undo_crypto_wallet() {
    rm -f "${BACKUP_DIR}/wallet_baseline.txt" 2>/dev/null || true
    log_success "Removed wallet integrity baseline"
}

check_crypto_wallet() {
    if [[ -f "${BACKUP_DIR}/wallet_baseline.txt" ]]; then
        log_success "Wallet integrity baseline: exists"
    else
        log_warning "Wallet integrity baseline: not created"
    fi
}

# ============================================================================
# 8. Enhanced Audit Logging
# ============================================================================
# Configure comprehensive audit logging to detect all stages of the
# BlueNoroff attack chain.

harden_audit_logging() {
    log_info "Section 8: Enhanced Audit Logging"

    # Configure OpenBSM audit trail
    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        backup_file "$audit_control"

        if ! grep -q "^flags:.*ex" "$audit_control" 2>/dev/null; then
            if grep -q "^flags:" "$audit_control"; then
                local current_flags
                current_flags=$(grep "^flags:" "$audit_control" | head -1 | sed 's/^flags://')
                sed -i '' "s/^flags:.*/flags:${current_flags},ex,pc,fc,fd,nt/" "$audit_control" 2>/dev/null || true
            else
                echo "flags:lo,aa,ex,pc,fc,fd,nt" >> "$audit_control"
            fi
            log_success "Added execution/process/file/network audit flags"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "Execution audit flags already configured"
        fi
    fi

    # Deploy enhanced shell history and suspicious command alerting
    local profile_dir="/etc/profile.d"
    mkdir -p "$profile_dir" 2>/dev/null || true

    local profile_file="${profile_dir}/f0rtika-bluenoroff-defense.sh"
    cat > "$profile_file" <<'PROFILE_EOF'
# F0RT1KA BlueNoroff Defense: Enhanced command history + suspicious command alerts
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=100000
export HISTFILESIZE=100000
export HISTCONTROL=""
shopt -s histappend 2>/dev/null || true

# Log suspicious commands to syslog (non-blocking)
_f0rtika_cmd_audit() {
    local cmd
    cmd=$(history 1 2>/dev/null | sed 's/^[ ]*[0-9]*[ ]*//')
    case "$cmd" in
        *"security dump-keychain"*|*"security find-generic"*|*"security find-internet"*)
            logger -p auth.alert "F0RT1KA: Keychain extraction: $cmd" ;;
        *"xattr -d com.apple.quarantine"*|*"xattr -cr"*)
            logger -p auth.alert "F0RT1KA: Gatekeeper bypass: $cmd" ;;
        *"osascript"*"display dialog"*)
            logger -p auth.alert "F0RT1KA: osascript dialog: $cmd" ;;
        *"tccutil reset"*)
            logger -p auth.alert "F0RT1KA: TCC manipulation: $cmd" ;;
        *"dscl"*"authonly"*)
            logger -p auth.alert "F0RT1KA: Credential validation: $cmd" ;;
    esac
}
PROMPT_COMMAND="_f0rtika_cmd_audit;${PROMPT_COMMAND:-}"
PROFILE_EOF
    chmod 644 "$profile_file"
    log_success "Installed command history logging with suspicious command alerting"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_audit_logging() {
    rm -f /etc/profile.d/f0rtika-bluenoroff-defense.sh 2>/dev/null || true
    log_success "Removed enhanced history logging profile"
    log_info "Audit control changes require manual restoration from $BACKUP_DIR"
}

check_audit_logging() {
    if [[ -f "/etc/security/audit_control" ]] && grep -q "ex" /etc/security/audit_control 2>/dev/null; then
        log_success "Execution auditing: configured"
    else
        log_warning "Execution auditing: not fully configured"
    fi

    if [[ -f "/etc/profile.d/f0rtika-bluenoroff-defense.sh" ]]; then
        log_success "Suspicious command alerting: configured"
    else
        log_warning "Suspicious command alerting: not configured"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

ACTION="${1:-apply}"

echo ""
echo "============================================================================"
echo "F0RT1KA macOS Hardening: DPRK BlueNoroff Financial Sector Attack Chain"
echo "Test ID: 244dfb88-9068-4db4-9fa8-dbc49517f63d"
echo "MITRE ATT&CK: T1553.001, T1543.004, T1059.002, T1555.001, T1056.002,"
echo "              T1071.001, T1573.002, T1071.004, T1041, T1567.002, T1560.001"
echo "Campaigns: RustBucket, Hidden Risk, KANDYKORN, TodoSwift, BeaverTail"
echo "Action: $ACTION"
echo "============================================================================"
echo ""

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
echo "$(date '+%Y-%m-%d %H:%M:%S') === F0RT1KA BlueNoroff Hardening: $ACTION ===" >> "$LOG_FILE" 2>/dev/null || true

case "$ACTION" in
    apply)
        check_root
        check_macos
        ensure_backup_dir

        harden_gatekeeper
        echo ""
        harden_launchagent_persistence
        echo ""
        harden_zshenv
        echo ""
        harden_osascript
        echo ""
        harden_keychain
        echo ""
        harden_c2_blocking
        echo ""
        harden_crypto_wallet
        echo ""
        harden_audit_logging

        echo ""
        echo "============================================================================"
        log_success "Hardening complete. $CHANGE_COUNT changes applied."
        echo "============================================================================"
        echo ""
        echo "Applied Settings:"
        echo "  1. Gatekeeper/SIP/Quarantine/FileVault verification (T1553.001)"
        echo "  2. LaunchAgent/LaunchDaemon persistence scan + monitoring (T1543.004)"
        echo "  3. .zshenv protection against Hidden Risk persistence (T1543.004)"
        echo "  4. osascript credential phishing audit daemon (T1059.002, T1056.002)"
        echo "  5. Keychain auto-lock hardening (T1555.001)"
        echo "  6. C2 domain blocking + port 8888 filtering (T1071.001, T1573.002)"
        echo "  7. Crypto wallet integrity baseline (BlueNoroff primary target)"
        echo "  8. Enhanced audit logging with suspicious command alerting"
        echo ""
        echo "Backup location: $BACKUP_DIR"
        echo "Log file:        $LOG_FILE"
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

        undo_gatekeeper
        undo_launchagent_persistence
        undo_zshenv
        undo_osascript
        undo_keychain
        undo_c2_blocking
        undo_crypto_wallet
        undo_audit_logging

        echo ""
        log_success "Revert complete. Critical security settings (SIP/Gatekeeper) left as-is."
        echo ""
        ;;

    check)
        check_root
        check_macos
        log_info "Checking hardening status..."
        echo ""

        check_gatekeeper
        echo ""
        check_launchagent_persistence
        echo ""
        check_zshenv
        echo ""
        check_osascript
        echo ""
        check_keychain
        echo ""
        check_c2_blocking
        echo ""
        check_crypto_wallet
        echo ""
        check_audit_logging

        echo ""
        log_info "Check complete."
        echo ""
        ;;

    *)
        echo "Usage: sudo $SCRIPT_NAME [apply|undo|check]"
        echo ""
        echo "  apply  - Apply hardening settings (default)"
        echo "  undo   - Revert hardening settings"
        echo "  check  - Check current hardening status"
        exit 1
        ;;
esac

echo "============================================================================"
echo "Completed at $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================================"
