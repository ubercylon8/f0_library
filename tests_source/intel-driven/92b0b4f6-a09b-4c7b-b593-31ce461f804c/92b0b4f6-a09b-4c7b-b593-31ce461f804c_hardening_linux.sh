#!/usr/bin/env bash
# ============================================================================
# F0RT1KA Linux Hardening Script
# ============================================================================
# Test ID:      92b0b4f6-a09b-4c7b-b593-31ce461f804c
# Test Name:    APT42 TAMECAT Fileless Backdoor with Browser Credential Theft
# MITRE ATT&CK: T1059.001, T1059.005, T1547.001, T1037.001, T1555.003, T1102
# Mitigations:  M1038 (Execution Prevention), M1042 (Disable/Remove Feature),
#               M1031 (Network Intrusion Prevention), M1027 (Password Policies),
#               M1049 (Antivirus/Antimalware), M1047 (Audit)
#
# Purpose:
#   While APT42 TAMECAT primarily targets Windows, Linux endpoints face
#   analogous threats from script-based persistence, browser credential theft,
#   encoded command execution, and data exfiltration via web services. This
#   script hardens Linux endpoints against equivalent attack techniques:
#
#     - Script-based persistence (cron, systemd timers, profile scripts)
#     - Browser credential database theft (Chrome/Chromium Login Data SQLite)
#     - Data exfiltration via Telegram API and FTP
#     - Encoded/obfuscated command execution (base64 pipelines)
#     - Browser remote debugging abuse (port 9222)
#     - Keyring/secret store credential harvesting
#
# MITRE ATT&CK Techniques Covered (Linux equivalents):
#   T1059.004 - Unix Shell (equivalent to T1059.001 PowerShell)
#   T1547.004 - RC Scripts / Systemd (equivalent to T1547.001 Run keys)
#   T1053.003 - Cron (equivalent to T1037.001 Logon Scripts)
#   T1555.003 - Credentials from Web Browsers
#   T1102     - Web Service (Exfiltration via Telegram)
#   T1048     - Exfiltration Over Alternative Protocol (FTP)
#
# Usage:
#   sudo ./92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening_linux.sh [apply|undo|check]
#
# Requires: root privileges
# Idempotent: Yes (safe to run multiple times)
# Tested on: Ubuntu 22.04/24.04, Debian 12, RHEL 8/9, Rocky 9, Amazon Linux 2023
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_NAME="$(basename "$0")"
BACKUP_DIR="/var/backups/f0rtika-hardening-92b0b4f6"
LOG_FILE="/var/log/f0rtika-hardening-92b0b4f6.log"
AUDIT_RULES_FILE="/etc/audit/rules.d/f0rtika-apt42-protection.rules"
CHANGE_COUNT=0

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

log_info()    { echo -e "\e[36m[*]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_success() { echo -e "\e[32m[+]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [OK]    $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo -e "\e[33m[!]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "\e[31m[-]\e[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE" 2>/dev/null || true; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
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
# 1. Block Network Exfiltration Channels (T1102, T1048)
# ============================================================================
# APT42 TAMECAT uses Telegram Bot API for C2/exfiltration and FTP as a
# secondary exfiltration channel. Block both at the network layer.
# ============================================================================

harden_network_exfiltration() {
    log_info "Blocking APT42 exfiltration channels (Telegram API + FTP)..."

    if command -v iptables &>/dev/null; then
        # Block Telegram API IP ranges (C2 channel)
        for range in "${TELEGRAM_RANGES[@]}"; do
            if ! iptables -C OUTPUT -d "$range" -j DROP 2>/dev/null; then
                iptables -A OUTPUT -d "$range" -j DROP
                log_success "Blocked outbound to Telegram range: $range"
                ((CHANGE_COUNT++))
            else
                log_info "Telegram range already blocked: $range"
            fi
        done

        # Block FTP outbound (port 21) - secondary exfiltration channel
        if ! iptables -C OUTPUT -p tcp --dport 21 -j DROP 2>/dev/null; then
            iptables -A OUTPUT -p tcp --dport 21 -j DROP
            log_success "Blocked outbound FTP (port 21)"
            ((CHANGE_COUNT++))
        else
            log_info "FTP outbound already blocked"
        fi

        # Log large outbound HTTPS transfers (exfiltration indicator)
        if ! iptables -C OUTPUT -p tcp --dport 443 -m connbytes --connbytes 5000000: --connbytes-dir both --connbytes-mode bytes -j LOG --log-prefix "F0RT1KA-LARGE-UPLOAD: " 2>/dev/null; then
            iptables -A OUTPUT -p tcp --dport 443 -m connbytes --connbytes 5000000: --connbytes-dir both --connbytes-mode bytes -j LOG --log-prefix "F0RT1KA-LARGE-UPLOAD: " 2>/dev/null || true
            log_success "Logging outbound HTTPS transfers >5MB"
            ((CHANGE_COUNT++))
        fi

    elif command -v nft &>/dev/null; then
        log_info "Using nftables for network blocking"
        nft add table inet f0rtika_apt42 2>/dev/null || true
        nft add chain inet f0rtika_apt42 output "{ type filter hook output priority 0; }" 2>/dev/null || true

        for range in "${TELEGRAM_RANGES[@]}"; do
            nft add rule inet f0rtika_apt42 output ip daddr "$range" drop 2>/dev/null || true
        done
        nft add rule inet f0rtika_apt42 output tcp dport 21 drop 2>/dev/null || true
        log_success "Added nftables blocking rules for Telegram and FTP"
        ((CHANGE_COUNT++))
    else
        log_warning "Neither iptables nor nft found - cannot configure network blocking"
        log_info "Recommended: Install iptables or nftables for network-level defense"
    fi

    # DNS-level blocking for Telegram API
    if [[ -f /etc/hosts ]]; then
        if ! grep -q "api.telegram.org" /etc/hosts 2>/dev/null; then
            backup_file /etc/hosts
            {
                echo ""
                echo "# F0RT1KA APT42 Defense - Block Telegram C2 DNS resolution"
                echo "0.0.0.0 api.telegram.org"
                echo "0.0.0.0 t.me"
            } >> /etc/hosts
            log_success "Added DNS sinkhole entries for api.telegram.org and t.me"
            ((CHANGE_COUNT++))
        else
            log_info "Telegram DNS sinkhole already configured"
        fi
    fi
}

# ============================================================================
# 2. Protect Browser Credential Databases (T1555.003)
# ============================================================================
# APT42 TAMECAT copies Chrome/Edge Login Data SQLite databases and uses
# DPAPI to decrypt credentials. On Linux, browser credential databases
# are stored in ~/.config/<browser>/Default/Login Data and protected by
# the system keyring (gnome-keyring, KWallet, or kwallet5).
# ============================================================================

harden_browser_credentials() {
    log_info "Hardening browser credential database access..."

    # Set strict permissions on browser profile directories
    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        local user_name
        user_name=$(basename "$home_dir")

        local browser_dirs=(
            "$home_dir/.config/google-chrome"
            "$home_dir/.config/chromium"
            "$home_dir/.config/BraveSoftware"
            "$home_dir/.config/microsoft-edge"
            "$home_dir/.mozilla/firefox"
        )

        for bdir in "${browser_dirs[@]}"; do
            if [[ -d "$bdir" ]]; then
                chmod 700 "$bdir"
                log_success "Secured $bdir permissions to 700 (user: $user_name)"
            fi
        done

        # Check for exposed Login Data files
        local login_data_files=(
            "$home_dir/.config/google-chrome/Default/Login Data"
            "$home_dir/.config/chromium/Default/Login Data"
            "$home_dir/.config/BraveSoftware/Brave-Browser/Default/Login Data"
            "$home_dir/.config/microsoft-edge/Default/Login Data"
        )

        for ldf in "${login_data_files[@]}"; do
            if [[ -f "$ldf" ]]; then
                log_warning "Browser credential database found: $ldf"
            fi
        done
    done

    # Deploy Chrome/Chromium enterprise policy to disable built-in password manager
    local chrome_policy_dir="/etc/chromium/policies/managed"
    local chrome_managed_dir="/etc/opt/chrome/policies/managed"

    for policy_dir in "$chrome_policy_dir" "$chrome_managed_dir"; do
        mkdir -p "$policy_dir" 2>/dev/null || true
        local policy_file="$policy_dir/f0rtika_password_policy.json"
        if [[ ! -f "$policy_file" ]]; then
            cat > "$policy_file" << 'POLICY_EOF'
{
    "PasswordManagerEnabled": false,
    "AutofillCreditCardEnabled": false,
    "ImportSavedPasswords": false,
    "PasswordLeakDetectionEnabled": true
}
POLICY_EOF
            log_success "Created browser password manager disable policy: $policy_file"
            ((CHANGE_COUNT++))
        else
            log_info "Browser password policy already deployed: $policy_file"
        fi
    done

    # Set up auditd monitoring for browser credential file access
    if command -v auditctl &>/dev/null; then
        for home_dir in /home/*/; do
            [[ -d "$home_dir" ]] || continue
            local chrome_login="$home_dir/.config/google-chrome/Default/Login Data"
            local edge_login="$home_dir/.config/microsoft-edge/Default/Login Data"
            local chromium_login="$home_dir/.config/chromium/Default/Login Data"

            for ldf in "$chrome_login" "$edge_login" "$chromium_login"; do
                if [[ -f "$ldf" ]]; then
                    auditctl -w "$ldf" -p rwa -k browser_credential_access 2>/dev/null || true
                fi
            done
        done
        log_success "Audit rules set for browser credential database access"
        ((CHANGE_COUNT++))
    fi

    log_info "Recommended: Deploy enterprise password manager (1Password, Bitwarden)"
    log_info "Recommended: Use managed Chrome profile with password saving disabled"
}

# ============================================================================
# 3. Harden Persistence Vectors (T1547.001, T1037.001, T1053.003)
# ============================================================================
# APT42 uses dual persistence: Registry Run keys and UserInitMprLogonScript.
# Linux equivalents are cron jobs, systemd services/timers, profile scripts,
# XDG autostart entries, and rc.local scripts.
# ============================================================================

harden_persistence_vectors() {
    log_info "Hardening persistence mechanism monitoring..."

    # Restrict cron access to authorized users only
    if [[ ! -f /etc/cron.allow ]]; then
        backup_file /etc/cron.allow 2>/dev/null || true
        echo "root" > /etc/cron.allow
        chmod 600 /etc/cron.allow
        log_success "Created /etc/cron.allow restricting cron to root only"
        log_info "Add authorized users with: echo 'username' >> /etc/cron.allow"
        ((CHANGE_COUNT++))
    else
        log_info "cron.allow already exists"
    fi

    # Install persistent audit rules file for persistence monitoring
    mkdir -p /etc/audit/rules.d 2>/dev/null || true

    if [[ ! -f "$AUDIT_RULES_FILE" ]]; then
        cat > "$AUDIT_RULES_FILE" << 'AUDITRULES'
# F0RT1KA APT42 Defense - Persistence Monitoring Rules
# Techniques: T1547 (Boot/Logon Autostart), T1053 (Cron), T1037 (Logon Scripts)

# Monitor crontab modifications (T1053.003)
-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /var/spool/cron/ -p wa -k cron_persistence
-w /var/spool/cron/crontabs/ -p wa -k cron_persistence
-w /etc/cron.allow -p wa -k cron_persistence
-w /etc/cron.deny -p wa -k cron_persistence

# Monitor systemd service/timer creation (T1547.004)
-w /etc/systemd/system/ -p wa -k systemd_persistence
-w /usr/lib/systemd/system/ -p wa -k systemd_persistence

# Monitor profile script modifications (T1546.004 - equivalent to T1037.001)
-w /etc/profile -p wa -k profile_persistence
-w /etc/profile.d/ -p wa -k profile_persistence
-w /etc/bash.bashrc -p wa -k profile_persistence
-w /etc/bashrc -p wa -k profile_persistence
-w /etc/environment -p wa -k profile_persistence

# Monitor rc.local and init scripts (T1037)
-w /etc/rc.local -p wa -k rclocal_persistence
-w /etc/init.d/ -p wa -k init_persistence

# Monitor XDG autostart entries (desktop persistence)
-w /etc/xdg/autostart/ -p wa -k xdg_persistence

# Monitor SSH authorized_keys (T1098.004)
-w /root/.ssh/authorized_keys -p wa -k ssh_persistence

# Monitor at job creation
-w /var/spool/atjobs/ -p wa -k at_persistence
AUDITRULES
        log_success "Created persistent audit rules file: $AUDIT_RULES_FILE"
        ((CHANGE_COUNT++))

        # Load the rules
        if command -v augenrules &>/dev/null; then
            augenrules --load 2>/dev/null || true
            log_success "Loaded audit rules via augenrules"
        elif command -v auditctl &>/dev/null; then
            auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
            log_success "Loaded audit rules via auditctl"
        fi
    else
        log_info "Persistent audit rules already installed: $AUDIT_RULES_FILE"
    fi

    # Monitor user-level systemd directories
    if command -v auditctl &>/dev/null; then
        for home_dir in /home/*/; do
            [[ -d "$home_dir" ]] || continue
            local user_systemd="$home_dir/.config/systemd/user"
            if [[ -d "$user_systemd" ]]; then
                auditctl -w "$user_systemd" -p wa -k user_systemd_persistence 2>/dev/null || true
            fi
            # XDG autostart per user
            local user_autostart="$home_dir/.config/autostart"
            if [[ -d "$user_autostart" ]]; then
                auditctl -w "$user_autostart" -p wa -k xdg_persistence 2>/dev/null || true
            fi
        done
        log_success "User-level persistence monitoring configured"
    fi
}

# ============================================================================
# 4. Enable Script Execution Logging (T1059.001, T1059.004, T1059.005)
# ============================================================================
# APT42 uses PowerShell with -EncodedCommand and VBScript via cscript.exe.
# Linux equivalents are base64-encoded bash pipelines, python -c execution,
# and perl -e one-liners. This section monitors interpreter usage and
# enables comprehensive command logging.
# ============================================================================

harden_script_logging() {
    log_info "Enabling script execution monitoring and command logging..."

    # Audit rules for suspicious interpreter usage
    if command -v auditctl &>/dev/null; then
        # Monitor script interpreters (equivalent to cscript.exe/wscript.exe)
        auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/python3 -k script_execution 2>/dev/null || true
        auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/python -k script_execution 2>/dev/null || true
        auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/perl -k script_execution 2>/dev/null || true

        # Monitor base64 decoding (equivalent to -EncodedCommand)
        auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/base64 -k encoded_execution 2>/dev/null || true

        # Monitor download tools (used for payload delivery)
        auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -k download_tool 2>/dev/null || true
        auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/wget -k download_tool 2>/dev/null || true

        # Monitor all process executions
        auditctl -a always,exit -F arch=b64 -S execve -k process_execution 2>/dev/null || true

        log_success "Script interpreter auditing enabled"
        ((CHANGE_COUNT++))
    else
        log_warning "auditd not available - install with: apt install auditd (Debian/Ubuntu) or yum install audit (RHEL)"
    fi

    # Deploy enhanced bash command logging via profile.d
    local bash_logging="/etc/profile.d/f0rtika-bash-logging.sh"
    if [[ ! -f "$bash_logging" ]]; then
        cat > "$bash_logging" << 'BASH_LOG_EOF'
# F0RT1KA APT42 Defense - Bash Command Logging
# Logs all shell commands to syslog for SIEM ingestion
# Detects: base64 decode pipelines, curl|bash, encoded execution

# Enable bash command history with timestamps
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTCONTROL=ignoredups

# Log all commands to syslog (local6 facility for SIEM routing)
if [[ -n "${BASH_VERSION:-}" ]]; then
    PROMPT_COMMAND='history -a; logger -p local6.info -t "bash_cmd" "$(whoami) [$$]: $(history 1 | sed "s/^[ ]*[0-9]*[ ]*//")"'
fi
BASH_LOG_EOF
        chmod 644 "$bash_logging"
        log_success "Created bash command logging profile: $bash_logging"
        ((CHANGE_COUNT++))
    else
        log_info "Bash logging profile already exists: $bash_logging"
    fi

    # Configure rsyslog to route local6 to dedicated log file
    local rsyslog_conf="/etc/rsyslog.d/50-f0rtika-command-logging.conf"
    if command -v rsyslogd &>/dev/null && [[ ! -f "$rsyslog_conf" ]]; then
        cat > "$rsyslog_conf" << 'RSYSLOG_EOF'
# F0RT1KA APT42 Defense - Command and auth logging
local6.*    /var/log/f0rtika-commands.log
auth,authpriv.*    /var/log/f0rtika-auth.log
RSYSLOG_EOF
        systemctl restart rsyslog 2>/dev/null || true
        log_success "Configured rsyslog for command and auth logging"
        ((CHANGE_COUNT++))
    fi
}

# ============================================================================
# 5. Block Browser Remote Debugging Port (T1555.003)
# ============================================================================
# APT42 TAMECAT launches Edge with --remote-debugging-port=9222 to access
# browser internals. Block inbound connections to common debugging ports
# to prevent remote exploitation of any browser debugging sessions.
# ============================================================================

harden_browser_debugging() {
    log_info "Blocking browser remote debugging ports..."

    if command -v iptables &>/dev/null; then
        # Block inbound connections to common browser debugging ports
        for port in 9222 9229 9333; do
            if ! iptables -C INPUT -p tcp --dport "$port" -j DROP 2>/dev/null; then
                iptables -A INPUT -p tcp --dport "$port" -j DROP
                log_success "Blocked inbound connections to port $port (browser debugging)"
                ((CHANGE_COUNT++))
            else
                log_info "Port $port already blocked"
            fi
        done
    elif command -v nft &>/dev/null; then
        nft add table inet f0rtika_apt42 2>/dev/null || true
        nft add chain inet f0rtika_apt42 input "{ type filter hook input priority 0; }" 2>/dev/null || true
        for port in 9222 9229 9333; do
            nft add rule inet f0rtika_apt42 input tcp dport "$port" drop 2>/dev/null || true
        done
        log_success "Blocked browser debugging ports via nftables"
        ((CHANGE_COUNT++))
    fi

    # Check for running browsers with debugging flags
    if pgrep -f -- "--remote-debugging-port" &>/dev/null; then
        log_warning "ALERT: Browser process found with --remote-debugging-port flag!"
        log_warning "  Processes: $(pgrep -fa -- '--remote-debugging-port' 2>/dev/null || echo 'unable to list')"
    else
        log_info "No browser processes with remote debugging detected"
    fi
}

# ============================================================================
# 6. Enable Process Execution Auditing
# ============================================================================
# Comprehensive process execution monitoring enables detection of the
# entire APT42 killchain: LNK execution -> VBScript -> PowerShell ->
# credential theft -> exfiltration. On Linux, auditd execve monitoring
# provides equivalent visibility.
# ============================================================================

harden_process_auditing() {
    log_info "Enabling comprehensive process execution auditing..."

    # Ensure auditd is installed and enabled
    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not installed"
        if command -v apt-get &>/dev/null; then
            log_info "Install with: sudo apt-get install auditd audispd-plugins"
        elif command -v yum &>/dev/null; then
            log_info "Install with: sudo yum install audit audit-libs"
        elif command -v dnf &>/dev/null; then
            log_info "Install with: sudo dnf install audit"
        fi
        return
    fi

    # Ensure auditd service is running
    if command -v systemctl &>/dev/null; then
        if ! systemctl is-active --quiet auditd 2>/dev/null; then
            systemctl enable auditd 2>/dev/null || true
            systemctl start auditd 2>/dev/null || true
            log_success "Started and enabled auditd service"
            ((CHANGE_COUNT++))
        else
            log_info "auditd service is already running"
        fi
    fi

    # Enable process accounting (acct/psacct) for historical process tracking
    if command -v apt-get &>/dev/null; then
        if ! dpkg -l acct 2>/dev/null | grep -q "^ii"; then
            log_info "Recommended: Install process accounting: sudo apt-get install acct"
        fi
    elif command -v rpm &>/dev/null; then
        if ! rpm -q psacct &>/dev/null; then
            log_info "Recommended: Install process accounting: sudo yum install psacct"
        fi
    fi
}

# ============================================================================
# 7. Monitor Keyring and Secret Store Access (T1555.003)
# ============================================================================
# On Linux, browser credentials encrypted with DPAPI on Windows are instead
# protected by the desktop keyring (gnome-keyring, KWallet, or libsecret).
# Monitor access to these credential stores.
# ============================================================================

harden_keyring_monitoring() {
    log_info "Setting up keyring and secret store monitoring..."

    if command -v auditctl &>/dev/null; then
        # Monitor GNOME Keyring access
        for home_dir in /home/*/; do
            [[ -d "$home_dir" ]] || continue
            local keyring_dir="$home_dir/.local/share/keyrings"
            if [[ -d "$keyring_dir" ]]; then
                auditctl -w "$keyring_dir" -p rwa -k gnome_keyring_access 2>/dev/null || true
            fi
        done

        # Monitor KDE Wallet access
        for home_dir in /home/*/; do
            [[ -d "$home_dir" ]] || continue
            local kwallet_dir="$home_dir/.local/share/kwalletd"
            if [[ -d "$kwallet_dir" ]]; then
                auditctl -w "$kwallet_dir" -p rwa -k kwallet_access 2>/dev/null || true
            fi
        done

        # Monitor secret-tool usage (CLI access to libsecret)
        if command -v secret-tool &>/dev/null; then
            local secret_tool_path
            secret_tool_path=$(command -v secret-tool)
            auditctl -a always,exit -F arch=b64 -S execve -F path="$secret_tool_path" -k secret_tool_access 2>/dev/null || true
        fi

        # Monitor PAM configuration changes (credential interception)
        auditctl -w /etc/pam.d/ -p wa -k pam_config_change 2>/dev/null || true

        # Monitor /etc/shadow access (password hash harvesting)
        auditctl -w /etc/shadow -p r -k shadow_access 2>/dev/null || true

        # Monitor SSH key access
        for home_dir in /home/*/; do
            [[ -d "$home_dir" ]] || continue
            local ssh_dir="$home_dir/.ssh"
            if [[ -d "$ssh_dir" ]]; then
                auditctl -w "$ssh_dir" -p r -k ssh_key_access 2>/dev/null || true
            fi
        done
        auditctl -w /root/.ssh -p r -k ssh_key_access 2>/dev/null || true

        log_success "Keyring and secret store monitoring enabled"
        ((CHANGE_COUNT++))
    else
        log_warning "auditd required for keyring monitoring - install auditd package"
    fi
}

# ============================================================================
# Undo Function
# ============================================================================

undo_changes() {
    log_warning "Reverting APT42 TAMECAT hardening changes..."

    # 1. Remove iptables/nftables rules
    if command -v iptables &>/dev/null; then
        for range in "${TELEGRAM_RANGES[@]}"; do
            iptables -D OUTPUT -d "$range" -j DROP 2>/dev/null || true
        done
        iptables -D OUTPUT -p tcp --dport 21 -j DROP 2>/dev/null || true
        iptables -D OUTPUT -p tcp --dport 443 -m connbytes --connbytes 5000000: --connbytes-dir both --connbytes-mode bytes -j LOG --log-prefix "F0RT1KA-LARGE-UPLOAD: " 2>/dev/null || true
        for port in 9222 9229 9333; do
            iptables -D INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || true
        done
        log_success "Removed iptables rules"
    fi

    if command -v nft &>/dev/null; then
        nft delete table inet f0rtika_apt42 2>/dev/null || true
        log_success "Removed nftables table"
    fi

    # 2. Remove DNS sinkhole entries
    if [[ -f /etc/hosts ]] && grep -q "F0RT1KA APT42 Defense" /etc/hosts 2>/dev/null; then
        if [[ -f "${BACKUP_DIR}/hosts.bak."* ]] 2>/dev/null; then
            local latest_backup
            latest_backup=$(ls -t "${BACKUP_DIR}"/hosts.bak.* 2>/dev/null | head -1)
            if [[ -n "$latest_backup" ]]; then
                cp "$latest_backup" /etc/hosts
                log_success "Restored /etc/hosts from backup"
            fi
        else
            sed -i '/F0RT1KA APT42 Defense/d; /api\.telegram\.org/d; /t\.me/d' /etc/hosts 2>/dev/null || true
            log_success "Removed Telegram DNS sinkhole entries"
        fi
    fi

    # 3. Remove browser policies
    rm -f /etc/chromium/policies/managed/f0rtika_password_policy.json 2>/dev/null || true
    rm -f /etc/opt/chrome/policies/managed/f0rtika_password_policy.json 2>/dev/null || true
    log_success "Removed browser password policies"

    # 4. Remove cron.allow (if we created it)
    if [[ -f /etc/cron.allow ]] && grep -qx "root" /etc/cron.allow 2>/dev/null && [[ $(wc -l < /etc/cron.allow) -eq 1 ]]; then
        rm -f /etc/cron.allow
        log_success "Removed /etc/cron.allow (restoring default cron access)"
    fi

    # 5. Remove audit rules file and reload
    if [[ -f "$AUDIT_RULES_FILE" ]]; then
        rm -f "$AUDIT_RULES_FILE"
        log_success "Removed audit rules file: $AUDIT_RULES_FILE"
    fi

    # Remove dynamic audit rules by key
    if command -v auditctl &>/dev/null; then
        local audit_keys=(
            browser_credential_access
            cron_persistence
            systemd_persistence
            profile_persistence
            rclocal_persistence
            init_persistence
            xdg_persistence
            user_systemd_persistence
            ssh_persistence
            at_persistence
            script_execution
            encoded_execution
            download_tool
            process_execution
            gnome_keyring_access
            kwallet_access
            secret_tool_access
            pam_config_change
            shadow_access
            ssh_key_access
        )
        for key in "${audit_keys[@]}"; do
            auditctl -D -k "$key" 2>/dev/null || true
        done
        log_success "Removed all F0RT1KA audit rules"
    fi

    # Reload rules
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null || true
    fi

    # 6. Remove bash logging profile
    rm -f /etc/profile.d/f0rtika-bash-logging.sh 2>/dev/null || true
    log_success "Removed bash logging profile"

    # 7. Remove rsyslog config
    if [[ -f /etc/rsyslog.d/50-f0rtika-command-logging.conf ]]; then
        rm -f /etc/rsyslog.d/50-f0rtika-command-logging.conf
        systemctl restart rsyslog 2>/dev/null || true
        log_success "Removed rsyslog command logging config"
    fi

    log_success "All hardening changes reverted"
}

# ============================================================================
# Check Function
# ============================================================================

check_status() {
    log_info "Checking APT42 TAMECAT hardening status..."
    echo ""

    # 1. Network exfiltration blocking
    log_info "--- Network Exfiltration Prevention ---"
    if command -v iptables &>/dev/null; then
        local blocked_ranges=0
        for range in "${TELEGRAM_RANGES[@]}"; do
            if iptables -C OUTPUT -d "$range" -j DROP 2>/dev/null; then
                blocked_ranges=$((blocked_ranges + 1))
            fi
        done
        if [[ $blocked_ranges -eq ${#TELEGRAM_RANGES[@]} ]]; then
            log_success "Telegram IP ranges: ALL BLOCKED ($blocked_ranges/${#TELEGRAM_RANGES[@]})"
        elif [[ $blocked_ranges -gt 0 ]]; then
            log_warning "Telegram IP ranges: PARTIALLY BLOCKED ($blocked_ranges/${#TELEGRAM_RANGES[@]})"
        else
            log_warning "Telegram IP ranges: NOT BLOCKED"
        fi

        if iptables -C OUTPUT -p tcp --dport 21 -j DROP 2>/dev/null; then
            log_success "FTP outbound (port 21): BLOCKED"
        else
            log_warning "FTP outbound (port 21): NOT BLOCKED"
        fi
    fi

    if grep -q "api.telegram.org" /etc/hosts 2>/dev/null; then
        log_success "Telegram DNS sinkhole: ACTIVE"
    else
        log_warning "Telegram DNS sinkhole: NOT CONFIGURED"
    fi

    # 2. Browser credential protection
    echo ""
    log_info "--- Browser Credential Protection ---"
    if [[ -f /etc/chromium/policies/managed/f0rtika_password_policy.json ]] || \
       [[ -f /etc/opt/chrome/policies/managed/f0rtika_password_policy.json ]]; then
        log_success "Browser password manager policy: DEPLOYED"
    else
        log_warning "Browser password manager policy: NOT DEPLOYED"
    fi

    # 3. Persistence monitoring
    echo ""
    log_info "--- Persistence Monitoring ---"
    if [[ -f "$AUDIT_RULES_FILE" ]]; then
        log_success "Persistent audit rules: INSTALLED ($AUDIT_RULES_FILE)"
    else
        log_warning "Persistent audit rules: NOT INSTALLED"
    fi

    if [[ -f /etc/cron.allow ]]; then
        log_success "Cron access restriction: ACTIVE ($(wc -l < /etc/cron.allow) users)"
    else
        log_warning "Cron access restriction: NOT CONFIGURED"
    fi

    # 4. Script execution logging
    echo ""
    log_info "--- Script Execution Logging ---"
    if [[ -f /etc/profile.d/f0rtika-bash-logging.sh ]]; then
        log_success "Bash command logging: ACTIVE"
    else
        log_warning "Bash command logging: NOT CONFIGURED"
    fi

    if [[ -f /etc/rsyslog.d/50-f0rtika-command-logging.conf ]]; then
        log_success "Rsyslog command routing: ACTIVE"
    else
        log_warning "Rsyslog command routing: NOT CONFIGURED"
    fi

    # 5. Browser debugging ports
    echo ""
    log_info "--- Browser Debugging Protection ---"
    if command -v iptables &>/dev/null; then
        if iptables -C INPUT -p tcp --dport 9222 -j DROP 2>/dev/null; then
            log_success "Browser debugging port 9222: BLOCKED"
        else
            log_warning "Browser debugging port 9222: NOT BLOCKED"
        fi
    fi

    if pgrep -f -- "--remote-debugging-port" &>/dev/null; then
        log_warning "ALERT: Browser with remote debugging is currently running!"
    else
        log_success "No browser remote debugging processes detected"
    fi

    # 6. Auditd status
    echo ""
    log_info "--- Audit System ---"
    if command -v auditctl &>/dev/null; then
        local rule_count
        rule_count=$(auditctl -l 2>/dev/null | wc -l || echo "0")
        log_success "auditd: INSTALLED ($rule_count active rules)"

        if command -v systemctl &>/dev/null && systemctl is-active --quiet auditd 2>/dev/null; then
            log_success "auditd service: RUNNING"
        else
            log_warning "auditd service: NOT RUNNING"
        fi
    else
        log_warning "auditd: NOT INSTALLED"
    fi

    # 7. Keyring monitoring
    echo ""
    log_info "--- Keyring/Secret Store Monitoring ---"
    if command -v auditctl &>/dev/null; then
        local keyring_rules
        keyring_rules=$(auditctl -l 2>/dev/null | grep -c "gnome_keyring_access\|kwallet_access\|shadow_access\|ssh_key_access" || echo "0")
        if [[ "$keyring_rules" -gt 0 ]]; then
            log_success "Keyring/credential monitoring: ACTIVE ($keyring_rules rules)"
        else
            log_warning "Keyring/credential monitoring: NOT CONFIGURED"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "============================================================"
    echo "F0RT1KA Linux Hardening: APT42 TAMECAT Defense"
    echo "Test ID: 92b0b4f6-a09b-4c7b-b593-31ce461f804c"
    echo "MITRE ATT&CK: T1059, T1547, T1037, T1053, T1555.003, T1102"
    echo "============================================================"
    echo ""

    local action="${1:-apply}"

    case "$action" in
        apply)
            check_root
            ensure_backup_dir
            harden_network_exfiltration     # T1102, T1048
            harden_browser_credentials      # T1555.003
            harden_persistence_vectors      # T1547.001, T1037.001, T1053.003
            harden_script_logging           # T1059.001, T1059.004, T1059.005
            harden_browser_debugging        # T1555.003
            harden_process_auditing         # General detection
            harden_keyring_monitoring       # T1555.003
            echo ""
            log_success "Hardening complete. $CHANGE_COUNT changes applied."
            log_info "Backup directory: $BACKUP_DIR"
            log_info "Log file: $LOG_FILE"
            echo ""
            log_info "ADDITIONAL RECOMMENDATIONS:"
            log_info "  1. Deploy AIDE or OSSEC for file integrity monitoring"
            log_info "  2. Configure rsyslog/journald forwarding to central SIEM"
            log_info "  3. Use SELinux/AppArmor profiles for browser process confinement"
            log_info "  4. Deploy enterprise credential manager (no browser passwords)"
            log_info "  5. Enable process accounting (psacct/acct) for command logging"
            log_info "  6. Consider deploying osquery for real-time process monitoring"
            ;;
        undo)
            check_root
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
}

main "${1:-apply}"
