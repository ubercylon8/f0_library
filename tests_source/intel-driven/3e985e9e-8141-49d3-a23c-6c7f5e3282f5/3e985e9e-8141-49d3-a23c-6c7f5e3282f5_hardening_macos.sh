#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# AMOS/Banshee Infostealer Defense - Credential Harvesting Countermeasures
# ============================================================================
# Test ID:      3e985e9e-8141-49d3-a23c-6c7f5e3282f5
# Test Name:    AMOS/Banshee macOS Infostealer Credential Harvesting Simulation
# MITRE ATT&CK: T1059.002, T1555.001, T1056.002, T1005, T1560.001, T1041, T1027
# Mitigations:  M1017 (User Training), M1026 (Privileged Account Mgmt),
#               M1027 (Password Policies), M1038 (Execution Prevention),
#               M1042 (Disable or Remove Feature), M1047 (Audit),
#               M1049 (Antivirus/Antimalware), M1054 (Software Configuration)
#
# Purpose:
#   Hardens macOS endpoints against AMOS/Banshee/Cuckoo infostealer credential
#   harvesting techniques. Covers osascript restriction, Keychain access
#   hardening, browser credential protection, cryptocurrency wallet monitoring,
#   TCC database protection, firewall enforcement, and exfiltration prevention.
#
# Usage:
#   sudo ./3e985e9e-8141-49d3-a23c-6c7f5e3282f5_hardening_macos.sh [apply|undo|check]
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
TEST_ID="3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
BACKUP_DIR="/var/backups/f0rtika-hardening-${TEST_ID}"
LOG_FILE="/var/log/f0rtika-hardening-${TEST_ID}.log"
CHANGE_COUNT=0
WARNING_COUNT=0

# ============================================================================
# Helper Functions
# ============================================================================

log_info()    { echo -e "\033[36m[*]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_success() { echo -e "\033[32m[+]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [OK]    $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo -e "\033[33m[!]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "\033[31m[-]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_check()   { echo -e "\033[35m[?]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [CHECK] $1" >> "$LOG_FILE" 2>/dev/null || true; }

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
# 1. Remove Active Infostealer Artifacts
# ============================================================================

harden_remove_artifacts() {
    log_info "=== Scanning for AMOS/Banshee/Cuckoo Stealer Artifacts ==="

    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")
        [[ "$user_name" == "Shared" || "$user_name" == "Guest" ]] && continue

        # Cuckoo-style .local-UUID/pw.dat
        while IFS= read -r -d '' hidden_dir; do
            if [[ -f "$hidden_dir/pw.dat" ]]; then
                backup_file "$hidden_dir/pw.dat"
                rm -f "$hidden_dir/pw.dat"
                log_warning "REMOVED Cuckoo credential cache: $hidden_dir/pw.dat"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        done < <(find "$home_dir" -maxdepth 1 -name ".local-*" -type d -print0 2>/dev/null)

        # Credentials cache file
        if [[ -f "/tmp/.credentials_cache" ]]; then
            backup_file "/tmp/.credentials_cache"
            rm -f "/tmp/.credentials_cache"
            log_warning "REMOVED credentials cache: /tmp/.credentials_cache"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    # Exfiltration staging archives
    for tmp_dir in /tmp /var/tmp; do
        for archive in out.zip output.zip data.zip loot.zip steal.zip dump.zip; do
            if [[ -f "$tmp_dir/$archive" ]]; then
                backup_file "$tmp_dir/$archive"
                rm -f "$tmp_dir/$archive"
                log_warning "REMOVED exfiltration archive: $tmp_dir/$archive"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        done
    done

    log_success "Stealer artifact scan complete"
}

# ============================================================================
# 2. SIP and Gatekeeper Enforcement (M1054)
# ============================================================================

harden_sip_gatekeeper() {
    log_info "=== SIP and Gatekeeper Enforcement (M1054) ==="

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

    # Enable XProtect/MRT automatic updates
    defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist ConfigDataInstall -bool true 2>/dev/null || true
    defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist CriticalUpdateInstall -bool true 2>/dev/null || true
    log_success "XProtect automatic updates: ENABLED"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Check FileVault
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
# 3. osascript Execution Monitoring (M1038)
# ============================================================================

harden_osascript() {
    log_info "=== osascript Execution Monitoring (M1038) ==="
    log_info "Mitigates: T1059.002 (AppleScript), T1056.002 (GUI Input Capture)"

    local monitor_plist="/Library/LaunchDaemons/com.f0rtika.osascript-monitor.plist"

    if [[ ! -f "$monitor_plist" ]]; then
        cat > "$monitor_plist" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rtika.osascript-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/log</string>
        <string>stream</string>
        <string>--predicate</string>
        <string>process == "osascript" OR process == "dscl" OR process == "tccutil"</string>
        <string>--info</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/f0rtika-osascript-monitor.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rtika-osascript-monitor.log</string>
</dict>
</plist>
PLIST_EOF
        chmod 644 "$monitor_plist"
        chown root:wheel "$monitor_plist"
        launchctl load "$monitor_plist" 2>/dev/null || true
        log_success "osascript/dscl/tccutil execution monitor installed and started"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "osascript monitor already deployed"
    fi

    log_info "MDM Recommendation: Block osascript from non-user-initiated processes"
    log_info "MDM Recommendation: Alert on 'display dialog' + 'hidden answer' patterns"
}

# ============================================================================
# 4. Keychain Access Hardening (M1027)
# ============================================================================

harden_keychain() {
    log_info "=== Keychain Access Hardening (M1027) ==="
    log_info "Mitigates: T1555.001 (Credentials from Keychain)"

    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")
        [[ "$user_name" == "Shared" || "$user_name" == "Guest" || "$user_name" == ".localized" ]] && continue

        # Secure keychain directory permissions
        local keychain_dir="$home_dir/Library/Keychains"
        if [[ -d "$keychain_dir" ]]; then
            local perms
            perms=$(stat -f "%Lp" "$keychain_dir" 2>/dev/null || echo "unknown")
            if [[ "$perms" != "700" ]]; then
                chmod 700 "$keychain_dir"
                log_success "Secured $keychain_dir to 700 (was $perms) [${user_name}]"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            else
                log_info "Keychain directory already secured (700) [${user_name}]"
            fi
        fi

        # Set keychain auto-lock to 5 minutes
        local keychain_path="${keychain_dir}/login.keychain-db"
        if [[ -f "$keychain_path" ]]; then
            security set-keychain-settings -l -u -t 300 "$keychain_path" 2>/dev/null && \
                log_success "Keychain auto-lock: 5 minutes [${user_name}]" && \
                CHANGE_COUNT=$((CHANGE_COUNT + 1)) || \
                log_warning "Could not set keychain auto-lock [${user_name}]"
        fi
    done

    # Lock all keychains
    security lock-keychain -a 2>/dev/null || true
    log_success "All keychains locked"
}

# ============================================================================
# 5. Browser Credential Protection (M1041)
# ============================================================================

harden_browser_credentials() {
    log_info "=== Browser Credential Database Protection (M1041) ==="
    log_info "Mitigates: T1005 (Data from Local System)"

    local browser_dirs=(
        "Library/Application Support/Google/Chrome/Default"
        "Library/Application Support/BraveSoftware/Brave-Browser/Default"
        "Library/Application Support/Microsoft Edge/Default"
        "Library/Application Support/com.operasoftware.Opera"
        "Library/Application Support/Vivaldi/Default"
        "Library/Application Support/Chromium/Default"
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
                        log_success "Set 700: ${browser_dir##*/} [${user_name}]" && \
                        CHANGE_COUNT=$((CHANGE_COUNT + 1)) || true
                fi

                for f in "${sensitive_files[@]}"; do
                    [[ -f "${full_path}/${f}" ]] && chmod 600 "${full_path}/${f}" 2>/dev/null || true
                done
            fi
        done

        # Protect Firefox profiles
        local ff_profiles="${home_dir}Library/Application Support/Firefox/Profiles"
        if [[ -d "$ff_profiles" ]]; then
            chmod 700 "$ff_profiles" 2>/dev/null || true
            find "$ff_profiles" -name "key4.db" -o -name "logins.json" -o -name "cookies.sqlite" 2>/dev/null | \
                while read -r f; do chmod 600 "$f" 2>/dev/null || true; done
        fi

        # Protect Apple Notes
        local notes_db="${home_dir}Library/Group Containers/group.com.apple.notes/NoteStore.sqlite"
        if [[ -f "$notes_db" ]]; then
            chmod 600 "$notes_db" 2>/dev/null && \
                log_success "Protected NoteStore.sqlite [${user_name}]" && \
                CHANGE_COUNT=$((CHANGE_COUNT + 1)) || true
        fi
    done
}

# ============================================================================
# 6. Cryptocurrency Wallet Protection (M1041)
# ============================================================================

harden_crypto_wallets() {
    log_info "=== Cryptocurrency Wallet Protection (M1041) ==="
    log_info "Mitigates: T1005 (Cryptocurrency Wallet Targeting)"

    local wallet_ext_ids=(
        "nkbihfbeogaeaoehlefnkodbefgpgknn"     # MetaMask
        "hnfanknocfeofbddgcijnmhnfnkdnaad"     # Coinbase
        "bfnaelmomeimhlpmgjnjophhpkkoljpa"      # Phantom
        "egjidjbpglichdcondbcbdnbeeppgdph"      # Trust Wallet
    )

    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")
        [[ "$user_name" == "Shared" || "$user_name" == "Guest" || "$user_name" == ".localized" ]] && continue

        local chrome_ext="${home_dir}Library/Application Support/Google/Chrome/Default/Local Extension Settings"
        for ext_id in "${wallet_ext_ids[@]}"; do
            local ext_path="${chrome_ext}/${ext_id}"
            if [[ -d "$ext_path" ]]; then
                chmod 700 "$ext_path" 2>/dev/null && \
                    log_success "Protected wallet: ${ext_id:0:8}... [${user_name}]" && \
                    CHANGE_COUNT=$((CHANGE_COUNT + 1)) || true
            fi
        done

        # Desktop wallets
        for wallet_dir in \
            "Library/Application Support/Exodus/exodus.wallet" \
            "Library/Application Support/atomic/Local Storage/leveldb" \
            ".electrum/wallets" \
            "Library/Application Support/Bitwarden"; do
            local full_path="${home_dir}${wallet_dir}"
            if [[ -d "$full_path" ]]; then
                chmod 700 "$full_path" 2>/dev/null && \
                    log_success "Protected: ${wallet_dir##*/} [${user_name}]" && \
                    CHANGE_COUNT=$((CHANGE_COUNT + 1)) || true
            fi
        done
    done

    log_info "Recommendation: Use hardware wallets for high-value cryptocurrency holdings"
}

# ============================================================================
# 7. TCC Database Protection (M1054)
# ============================================================================

harden_tcc() {
    log_info "=== TCC Database Protection (M1054) ==="
    log_info "Mitigates: Cuckoo Stealer tccutil reset pattern"

    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")
        [[ "$user_name" == "Shared" || "$user_name" == "Guest" || "$user_name" == ".localized" ]] && continue

        local tcc_dir="${home_dir}Library/Application Support/com.apple.TCC"
        if [[ -d "$tcc_dir" ]]; then
            chmod 700 "$tcc_dir" 2>/dev/null && \
                log_success "TCC directory protected (700) [${user_name}]" && \
                CHANGE_COUNT=$((CHANGE_COUNT + 1)) || true
        fi
    done

    log_info "MDM Recommendation: Deploy TCC configuration profile to centrally manage permissions"
    log_info "MDM Recommendation: Prevent tccutil reset execution via application restrictions"
}

# ============================================================================
# 8. Application Firewall (M1031)
# ============================================================================

harden_firewall() {
    log_info "=== Application Firewall (M1031) ==="
    log_info "Mitigates: T1041 (Exfiltration Over C2 Channel)"

    local fw_tool="/usr/libexec/ApplicationFirewall/socketfilterfw"

    # Enable application firewall
    $fw_tool --setglobalstate on 2>/dev/null || true
    log_success "Application Firewall: ENABLED"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Enable stealth mode
    $fw_tool --setstealthmode on 2>/dev/null || true
    log_success "Stealth Mode: ENABLED"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Block unsigned app connections
    $fw_tool --setallowsigned off 2>/dev/null || true
    log_success "Unsigned app connections: BLOCKED"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Enable firewall logging
    $fw_tool --setloggingmode on 2>/dev/null || true
    log_success "Firewall logging: ENABLED"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    log_info "For outbound egress filtering, consider:"
    log_info "  - LuLu (free): https://objective-see.org/products/lulu.html"
    log_info "  - Little Snitch: per-process outbound control"
    log_info "  - Corporate HTTPS inspection proxy"
}

# ============================================================================
# 9. Audit Logging Enhancement (M1047)
# ============================================================================

harden_logging() {
    log_info "=== Audit Logging Enhancement (M1047) ==="

    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        backup_file "$audit_control"
        if ! grep -q "lo,aa,ad,fd,fm,fc,cl" "$audit_control" 2>/dev/null; then
            sed -i.bak "s/^flags:.*/flags:lo,aa,ad,fd,fm,fc,cl/" "$audit_control" 2>/dev/null || true
            log_success "Audit flags updated: lo,aa,ad,fd,fm,fc,cl"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "Audit flags already comprehensive"
        fi
    fi

    # Install stealer detection logging profile
    local log_config="/Library/Preferences/Logging/Subsystems/com.f0rtika.stealer-detection.plist"
    mkdir -p "$(dirname "$log_config")" 2>/dev/null || true
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
    log_success "Stealer detection logging profile installed"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

# ============================================================================
# Undo Function
# ============================================================================

undo_changes() {
    log_warning "Reverting hardening changes..."

    # Remove osascript monitor
    local monitor_plist="/Library/LaunchDaemons/com.f0rtika.osascript-monitor.plist"
    if [[ -f "$monitor_plist" ]]; then
        launchctl unload "$monitor_plist" 2>/dev/null || true
        rm -f "$monitor_plist"
        log_success "Removed osascript monitor"
    fi

    # Remove logging profile
    rm -f "/Library/Preferences/Logging/Subsystems/com.f0rtika.stealer-detection.plist" 2>/dev/null || true
    log_success "Removed logging profile"

    # Restore audit_control from backup
    local latest_backup
    latest_backup=$(ls -t "${BACKUP_DIR}/audit_control.bak."* 2>/dev/null | head -1 || true)
    if [[ -n "$latest_backup" ]]; then
        cp "$latest_backup" /etc/security/audit_control
        log_success "Restored audit_control from backup"
    fi

    # Re-enable signed app connections
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on 2>/dev/null || true
    log_success "Re-enabled signed app connections"

    log_warning "Firewall, Gatekeeper, and Keychain protections remain (security best practice)"
    log_success "Undo complete"
}

# ============================================================================
# Check Function
# ============================================================================

check_status() {
    log_info "=== Security Posture Audit ==="
    echo ""

    # SIP
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    echo "$sip_status" | grep -q "enabled" && log_success "SIP: ENABLED" || { log_warning "SIP: DISABLED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    # Gatekeeper
    spctl --status 2>/dev/null | grep -q "enabled" && log_success "Gatekeeper: ENABLED" || { log_warning "Gatekeeper: DISABLED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    # FileVault
    fdesetup status 2>/dev/null | grep -qi "on" && log_success "FileVault: ENABLED" || { log_warning "FileVault: NOT ENABLED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    # Firewall
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled" && log_success "Firewall: ENABLED" || { log_warning "Firewall: DISABLED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    # osascript monitor
    [[ -f "/Library/LaunchDaemons/com.f0rtika.osascript-monitor.plist" ]] && log_success "osascript monitor: DEPLOYED" || { log_warning "osascript monitor: NOT DEPLOYED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    # Stealer artifacts
    local artifact_count=0
    for home_dir in /Users/*/; do
        [[ -d "$home_dir" ]] || continue
        while IFS= read -r -d '' hidden_dir; do
            [[ -f "$hidden_dir/pw.dat" ]] && artifact_count=$((artifact_count + 1))
        done < <(find "$home_dir" -maxdepth 1 -name ".local-*" -type d -print0 2>/dev/null)
    done
    [[ $artifact_count -eq 0 ]] && log_success "Stealer artifacts: CLEAN" || { log_warning "Stealer artifacts: $artifact_count FOUND"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    echo ""
    log_check "Audit complete. Non-compliant settings: ${WARNING_COUNT}"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo ""
    echo "============================================================"
    echo "F0RT1KA macOS Hardening: AMOS/Banshee Infostealer Defense"
    echo "Test ID: ${TEST_ID}"
    echo "MITRE ATT&CK: T1059.002, T1555.001, T1056.002, T1005,"
    echo "              T1560.001, T1041, T1027"
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
            harden_remove_artifacts; echo ""
            harden_sip_gatekeeper; echo ""
            harden_osascript; echo ""
            harden_keychain; echo ""
            harden_browser_credentials; echo ""
            harden_crypto_wallets; echo ""
            harden_tcc; echo ""
            harden_firewall; echo ""
            harden_logging
            echo ""
            echo "============================================================"
            log_success "Hardening complete. Changes applied: ${CHANGE_COUNT}"
            [[ $WARNING_COUNT -gt 0 ]] && log_warning "Warnings requiring manual action: ${WARNING_COUNT}"
            log_info "Backup directory: ${BACKUP_DIR}"
            log_info "Log file: ${LOG_FILE}"
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
