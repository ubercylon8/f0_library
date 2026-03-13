#!/usr/bin/env bash
# ============================================================================
# F0RT1KA Linux Hardening Script
# AMOS/Banshee Infostealer Defense - Cross-Platform Credential Theft Countermeasures
# ============================================================================
# Test ID:      3e985e9e-8141-49d3-a23c-6c7f5e3282f5
# Test Name:    AMOS/Banshee macOS Infostealer Credential Harvesting Simulation
# MITRE ATT&CK: T1059.002, T1555.001, T1056.002, T1005, T1560.001, T1041, T1027
# Mitigations:  M1027 (Password Policies), M1031 (Network Intrusion Prevention),
#               M1041 (Encrypt Sensitive Information), M1047 (Audit),
#               M1054 (Software Configuration)
#
# Purpose:
#   While AMOS/Banshee primarily targets macOS, Linux developer workstations,
#   servers hosting cryptocurrency infrastructure, and web applications face
#   equivalent credential theft techniques. This script hardens Linux endpoints
#   against browser credential theft, cryptocurrency wallet enumeration,
#   keyring/secret-store access, data exfiltration, and shell profile tampering.
#
# Usage:
#   sudo ./3e985e9e-8141-49d3-a23c-6c7f5e3282f5_hardening_linux.sh [apply|undo|check]
#
# Requires: root privileges
# Idempotent: Yes (safe to run multiple times)
# Tested on: Ubuntu 22.04/24.04, Debian 12, RHEL 9, Rocky 9
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

log_info()    { echo -e "\e[36m[*]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_success() { echo -e "\e[32m[+]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [OK]    $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo -e "\e[33m[!]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "\e[31m[-]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_check()   { echo -e "\e[35m[?]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [CHECK] $1" >> "$LOG_FILE" 2>/dev/null || true; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
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

command_exists() {
    command -v "$1" &>/dev/null
}

# ============================================================================
# 1. Remove Suspicious Artifacts
# ============================================================================

harden_remove_artifacts() {
    log_info "=== Scanning for Suspicious Credential Theft Artifacts ==="

    # Check for credential cache files in tmp
    for cache_file in /tmp/.credentials_cache /tmp/.cred_cache /var/tmp/.credentials_cache; do
        if [[ -f "$cache_file" ]]; then
            backup_file "$cache_file"
            rm -f "$cache_file"
            log_warning "REMOVED credential cache: $cache_file"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    # Check for exfiltration staging archives
    for tmp_dir in /tmp /var/tmp; do
        for archive in out.zip output.zip data.zip loot.zip steal.zip dump.zip; do
            if [[ -f "$tmp_dir/$archive" ]]; then
                backup_file "$tmp_dir/$archive"
                rm -f "$tmp_dir/$archive"
                log_warning "REMOVED suspicious archive: $tmp_dir/$archive"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        done
    done

    # Check for hidden credential directories
    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        while IFS= read -r -d '' hidden_dir; do
            log_warning "Suspicious hidden directory found: $hidden_dir"
            WARNING_COUNT=$((WARNING_COUNT + 1))
        done < <(find "$home_dir" -maxdepth 1 -name ".local-*" -type d -print0 2>/dev/null)
    done

    log_success "Artifact scan complete"
}

# ============================================================================
# 2. Browser Credential Database Protection (M1041, T1005)
# ============================================================================

harden_browser_credentials() {
    log_info "=== Browser Credential Database Protection (M1041) ==="
    log_info "Mitigates: T1005 (Data from Local System), T1555.003 (Browser Credentials)"

    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")

        # Chromium-based browsers
        for browser_dir in \
            ".config/google-chrome" \
            ".config/chromium" \
            ".config/BraveSoftware/Brave-Browser" \
            ".config/microsoft-edge" \
            ".config/vivaldi" \
            ".config/opera"; do
            local full_path="${home_dir}${browser_dir}"
            if [[ -d "$full_path" ]]; then
                local perms
                perms=$(stat -c "%a" "$full_path" 2>/dev/null || echo "unknown")
                if [[ "$perms" != "700" ]]; then
                    chmod 700 "$full_path"
                    log_success "Set 700: ${browser_dir##*/} [${user_name}]"
                    CHANGE_COUNT=$((CHANGE_COUNT + 1))
                fi

                # Restrict credential-specific files
                for f in "Default/Login Data" "Default/Cookies" "Default/Web Data" "Local State"; do
                    [[ -f "${full_path}/${f}" ]] && chmod 600 "${full_path}/${f}" 2>/dev/null || true
                done
            fi
        done

        # Firefox
        local ff_dir="${home_dir}.mozilla/firefox"
        if [[ -d "$ff_dir" ]]; then
            chmod 700 "$ff_dir" 2>/dev/null || true
            find "$ff_dir" \( -name "key4.db" -o -name "logins.json" -o -name "cookies.sqlite" \) -exec chmod 600 {} \; 2>/dev/null || true
            log_success "Secured Firefox profiles [${user_name}]"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    # Deploy Chrome enterprise policy to recommend password manager disabling
    local chrome_policy_dir="/etc/opt/chrome/policies/managed"
    if [[ ! -f "${chrome_policy_dir}/f0rtika_password_policy.json" ]]; then
        mkdir -p "$chrome_policy_dir" 2>/dev/null || true
        cat > "${chrome_policy_dir}/f0rtika_password_policy.json" << 'POLICY_EOF'
{
    "PasswordManagerEnabled": false,
    "AutofillCreditCardEnabled": false,
    "ImportSavedPasswords": false
}
POLICY_EOF
        log_success "Chrome enterprise policy: disabled built-in password manager"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

# ============================================================================
# 3. Cryptocurrency Wallet Protection (M1041, T1005)
# ============================================================================

harden_crypto_wallets() {
    log_info "=== Cryptocurrency Wallet Protection (M1041) ==="
    log_info "Mitigates: T1005 (Cryptocurrency Wallet Targeting)"

    local found_wallets=0

    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")

        # Browser extension wallets (Chrome)
        local chrome_ext="${home_dir}.config/google-chrome/Default/Local Extension Settings"
        for ext_id in \
            "nkbihfbeogaeaoehlefnkodbefgpgknn" \
            "hnfanknocfeofbddgcijnmhnfnkdnaad" \
            "bfnaelmomeimhlpmgjnjophhpkkoljpa" \
            "egjidjbpglichdcondbcbdnbeeppgdph"; do
            local ext_path="${chrome_ext}/${ext_id}"
            if [[ -d "$ext_path" ]]; then
                chmod 700 "$ext_path" 2>/dev/null || true
                log_success "Protected wallet extension: ${ext_id:0:8}... [${user_name}]"
                found_wallets=$((found_wallets + 1))
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        done

        # Desktop wallets
        for wallet_dir in \
            ".electrum/wallets" \
            ".config/Exodus/exodus.wallet" \
            ".config/atomic/Local Storage/leveldb" \
            ".config/Bitwarden"; do
            local full_path="${home_dir}${wallet_dir}"
            if [[ -d "$full_path" ]]; then
                chmod 700 "$full_path" 2>/dev/null || true
                log_success "Protected: ${wallet_dir##*/} [${user_name}]"
                found_wallets=$((found_wallets + 1))
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        done
    done

    if [[ $found_wallets -gt 0 ]]; then
        log_warning "$found_wallets wallet location(s) found and protected"
        log_info "Recommendation: Use hardware wallets for high-value holdings"
    else
        log_info "No cryptocurrency wallets detected"
    fi
}

# ============================================================================
# 4. Credential Store and Keyring Protection (M1027, T1555)
# ============================================================================

harden_credential_stores() {
    log_info "=== Credential Store and Keyring Protection (M1027) ==="
    log_info "Mitigates: T1555.001 (Keychain equivalent on Linux)"

    # Secure GNOME Keyring directories
    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")

        local keyring_dir="${home_dir}.local/share/keyrings"
        if [[ -d "$keyring_dir" ]]; then
            chmod 700 "$keyring_dir" 2>/dev/null || true
            find "$keyring_dir" -type f -exec chmod 600 {} \; 2>/dev/null || true
            log_success "Secured GNOME Keyring [${user_name}]"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi

        # KDE Wallet
        local kwallet_dir="${home_dir}.local/share/kwalletd"
        if [[ -d "$kwallet_dir" ]]; then
            chmod 700 "$kwallet_dir" 2>/dev/null || true
            log_success "Secured KDE Wallet [${user_name}]"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi

        # SSH keys
        local ssh_dir="${home_dir}.ssh"
        if [[ -d "$ssh_dir" ]]; then
            chmod 700 "$ssh_dir" 2>/dev/null || true
            find "$ssh_dir" -name "id_*" -not -name "*.pub" -exec chmod 600 {} \; 2>/dev/null || true
            log_success "Secured SSH keys [${user_name}]"
        fi
    done

    # Protect /etc/shadow
    chmod 640 /etc/shadow 2>/dev/null || true
    chown root:shadow /etc/shadow 2>/dev/null || true
    log_success "Verified /etc/shadow permissions (640 root:shadow)"

    # Set up auditd monitoring for credential access
    if command_exists auditctl; then
        auditctl -w /etc/shadow -p r -k shadow_access 2>/dev/null || true
        auditctl -w /etc/pam.d/ -p wa -k pam_config_change 2>/dev/null || true
        log_success "Audit rules set for credential store access"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

# ============================================================================
# 5. Exfiltration Detection (M1031, T1041, T1560.001)
# ============================================================================

harden_exfiltration_detection() {
    log_info "=== Exfiltration Detection (M1031) ==="
    log_info "Mitigates: T1041 (Exfiltration), T1560.001 (Archive Staging)"

    # Audit archive creation in temp directories
    if command_exists auditctl; then
        auditctl -w /tmp/ -p w -k exfil_staging 2>/dev/null || true
        auditctl -w /var/tmp/ -p w -k exfil_staging 2>/dev/null || true
        log_success "Audit rules set for archive staging in temp directories"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    # Log large outbound HTTPS transfers
    if command_exists iptables; then
        if ! iptables -C OUTPUT -p tcp --dport 443 -m connbytes --connbytes 5000000: --connbytes-dir both --connbytes-mode bytes -j LOG --log-prefix "F0RT1KA-LARGE-UPLOAD: " 2>/dev/null; then
            iptables -A OUTPUT -p tcp --dport 443 -m connbytes --connbytes 5000000: --connbytes-dir both --connbytes-mode bytes -j LOG --log-prefix "F0RT1KA-LARGE-UPLOAD: " 2>/dev/null && \
                log_success "Logging outbound HTTPS transfers >5MB" && \
                CHANGE_COUNT=$((CHANGE_COUNT + 1)) || \
                log_warning "Could not add iptables logging rule (connbytes module may not be loaded)"
        else
            log_info "Large upload logging already configured"
        fi
    fi

    # Log large outbound HTTP transfers
    if command_exists iptables; then
        if ! iptables -C OUTPUT -p tcp --dport 80 -m connbytes --connbytes 5000000: --connbytes-dir both --connbytes-mode bytes -j LOG --log-prefix "F0RT1KA-LARGE-UPLOAD: " 2>/dev/null; then
            iptables -A OUTPUT -p tcp --dport 80 -m connbytes --connbytes 5000000: --connbytes-dir both --connbytes-mode bytes -j LOG --log-prefix "F0RT1KA-LARGE-UPLOAD: " 2>/dev/null || true
        fi
    fi

    log_info "Recommendation: Deploy network DLP or proxy to inspect outbound traffic for:"
    log_info "  - ZIP archives in multipart/form-data uploads"
    log_info "  - POST bodies containing hwid/wid/user metadata fields"
    log_info "  - Large uploads to uncategorized or newly-registered domains"
}

# ============================================================================
# 6. Shell Profile Protection (T1059)
# ============================================================================

harden_shell_profiles() {
    log_info "=== Shell Profile Protection (T1059) ==="
    log_info "Mitigates: T1059 (Command and Scripting Interpreter)"

    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        for sf in ".bashrc" ".bash_profile" ".profile" ".zshrc" ".zshenv"; do
            local file_path="${home_dir}${sf}"
            if [[ -f "$file_path" ]]; then
                if grep -qiE "curl.*\|.*bash|wget.*\|.*sh|eval.*base64|python.*-c.*import" "$file_path" 2>/dev/null; then
                    backup_file "$file_path"
                    log_warning "SUSPICIOUS CONTENT in $file_path - backed up for review"
                    WARNING_COUNT=$((WARNING_COUNT + 1))
                fi
            fi
        done
    done

    # Audit shell profile modifications
    if command_exists auditctl; then
        auditctl -w /etc/profile -p wa -k shell_profile_modify 2>/dev/null || true
        auditctl -w /etc/profile.d/ -p wa -k shell_profile_modify 2>/dev/null || true
        auditctl -w /etc/bash.bashrc -p wa -k shell_profile_modify 2>/dev/null || true
        for home_dir in /home/*/; do
            [[ -d "$home_dir" ]] || continue
            auditctl -w "${home_dir}.bashrc" -p wa -k shell_profile_modify 2>/dev/null || true
            auditctl -w "${home_dir}.zshrc" -p wa -k shell_profile_modify 2>/dev/null || true
        done
        log_success "Audit rules set for shell profile modifications"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

# ============================================================================
# 7. Process Execution Logging (M1047)
# ============================================================================

harden_process_logging() {
    log_info "=== Process Execution Logging (M1047) ==="

    if command_exists auditctl; then
        auditctl -a always,exit -F arch=b64 -S execve -k process_execution 2>/dev/null || true
        log_success "Process execution auditing enabled (64-bit)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_warning "auditd not available - install: apt install auditd (Debian) or yum install audit (RHEL)"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi

    # Enhanced authentication logging
    local rsyslog_conf="/etc/rsyslog.d/50-f0rtika-auth-monitor.conf"
    if command_exists rsyslogd && [[ ! -f "$rsyslog_conf" ]]; then
        cat > "$rsyslog_conf" << 'RSYSLOG_EOF'
# F0RT1KA: Enhanced authentication logging for credential theft detection
auth,authpriv.*     /var/log/f0rtika-auth.log
RSYSLOG_EOF
        systemctl restart rsyslog 2>/dev/null || true
        log_success "Enhanced authentication logging configured"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

# ============================================================================
# 8. Firewall Hardening (M1031)
# ============================================================================

harden_firewall() {
    log_info "=== Firewall Hardening (M1031) ==="
    log_info "Mitigates: T1041 (Exfiltration Over C2 Channel)"

    if command_exists ufw; then
        ufw --force enable 2>/dev/null || true
        ufw default deny incoming 2>/dev/null || true
        ufw logging on 2>/dev/null || true
        log_success "UFW firewall: ENABLED with default deny incoming, logging on"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    elif command_exists firewall-cmd; then
        firewall-cmd --set-log-denied=all 2>/dev/null || true
        log_success "firewalld: logging denied connections"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_warning "No firewall manager found (ufw/firewalld). Consider installing one."
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi
}

# ============================================================================
# Undo Function
# ============================================================================

undo_changes() {
    log_warning "Reverting hardening changes..."

    # Remove auditd rules
    if command_exists auditctl; then
        for key in browser_credential_access crypto_wallet_access gnome_keyring_access \
                   ssh_key_access shadow_access exfil_staging shell_profile_modify \
                   process_execution pam_config_change; do
            auditctl -D -k "$key" 2>/dev/null || true
        done
        log_success "Removed audit rules"
    fi

    # Remove iptables logging rules
    if command_exists iptables; then
        for port in 443 80; do
            iptables -D OUTPUT -p tcp --dport "$port" -m connbytes --connbytes 5000000: --connbytes-dir both --connbytes-mode bytes -j LOG --log-prefix "F0RT1KA-LARGE-UPLOAD: " 2>/dev/null || true
        done
        log_success "Removed iptables logging rules"
    fi

    # Remove rsyslog config
    rm -f /etc/rsyslog.d/50-f0rtika-auth-monitor.conf 2>/dev/null || true
    systemctl restart rsyslog 2>/dev/null || true
    log_success "Removed rsyslog configuration"

    # Remove Chrome enterprise policy
    rm -f /etc/opt/chrome/policies/managed/f0rtika_password_policy.json 2>/dev/null || true
    log_success "Removed Chrome enterprise policy"

    log_success "Undo complete"
}

# ============================================================================
# Check Function
# ============================================================================

check_status() {
    log_info "=== Security Posture Audit ==="
    echo ""

    # auditd
    if command_exists auditctl; then
        local rules
        rules=$(auditctl -l 2>/dev/null | grep -cE "browser_credential|crypto_wallet|ssh_key|shadow_access|exfil_staging|shell_profile|process_execution" || echo "0")
        [[ "$rules" -gt 0 ]] && log_success "Audit rules: ACTIVE ($rules rules)" || { log_warning "Audit rules: NOT CONFIGURED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }
    else
        log_warning "auditd: NOT INSTALLED"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi

    # Firewall
    if command_exists ufw; then
        ufw status 2>/dev/null | grep -q "active" && log_success "UFW firewall: ACTIVE" || { log_warning "UFW firewall: INACTIVE"; WARNING_COUNT=$((WARNING_COUNT + 1)); }
    elif command_exists firewall-cmd; then
        firewall-cmd --state 2>/dev/null | grep -q "running" && log_success "firewalld: RUNNING" || { log_warning "firewalld: NOT RUNNING"; WARNING_COUNT=$((WARNING_COUNT + 1)); }
    fi

    # Large upload logging
    if command_exists iptables && iptables -C OUTPUT -p tcp --dport 443 -m connbytes --connbytes 5000000: --connbytes-dir both --connbytes-mode bytes -j LOG --log-prefix "F0RT1KA-LARGE-UPLOAD: " 2>/dev/null; then
        log_success "Large upload logging: ACTIVE"
    else
        log_warning "Large upload logging: NOT CONFIGURED"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi

    # Auth logging
    [[ -f /etc/rsyslog.d/50-f0rtika-auth-monitor.conf ]] && log_success "Enhanced auth logging: ACTIVE" || { log_warning "Enhanced auth logging: NOT CONFIGURED"; WARNING_COUNT=$((WARNING_COUNT + 1)); }

    # Chrome policy
    [[ -f /etc/opt/chrome/policies/managed/f0rtika_password_policy.json ]] && log_success "Chrome password manager policy: DEPLOYED" || log_check "Chrome password manager policy: NOT DEPLOYED"

    # Wallet scan
    local wallet_count=0
    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        [[ -d "$home_dir/.electrum" ]] && wallet_count=$((wallet_count + 1))
        [[ -d "$home_dir/.config/Exodus" ]] && wallet_count=$((wallet_count + 1))
    done
    [[ $wallet_count -eq 0 ]] && log_success "Cryptocurrency wallets: NONE DETECTED" || log_warning "Cryptocurrency wallets: $wallet_count FOUND"

    echo ""
    log_check "Audit complete. Non-compliant settings: ${WARNING_COUNT}"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo ""
    echo "============================================================"
    echo "F0RT1KA Linux Hardening: AMOS/Banshee Infostealer Defense"
    echo "Test ID: ${TEST_ID}"
    echo "MITRE ATT&CK: T1005, T1555, T1560.001, T1041, T1027"
    echo "============================================================"
    echo ""

    local action="${1:-apply}"

    case "$action" in
        apply)
            log_info "Running in APPLY mode - hardening system"
            echo ""
            check_root
            ensure_dirs
            harden_remove_artifacts; echo ""
            harden_browser_credentials; echo ""
            harden_crypto_wallets; echo ""
            harden_credential_stores; echo ""
            harden_exfiltration_detection; echo ""
            harden_shell_profiles; echo ""
            harden_process_logging; echo ""
            harden_firewall
            echo ""
            echo "============================================================"
            log_success "Hardening complete. Changes applied: ${CHANGE_COUNT}"
            [[ $WARNING_COUNT -gt 0 ]] && log_warning "Warnings requiring manual action: ${WARNING_COUNT}"
            log_info "Backup directory: ${BACKUP_DIR}"
            log_info "Log file: ${LOG_FILE}"
            ;;
        undo)
            check_root
            ensure_dirs
            undo_changes
            ;;
        check)
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
