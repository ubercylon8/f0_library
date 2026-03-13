#!/usr/bin/env bash
# ============================================================================
# F0RT1KA Linux Hardening Script
# ============================================================================
# Test ID:      244dfb88-9068-4db4-9fa8-dbc49517f63d
# Test Name:    DPRK BlueNoroff Financial Sector Attack Chain
# MITRE ATT&CK: T1553.001, T1543.004, T1059.002, T1555.001, T1056.002,
#               T1071.001, T1573.002, T1071.004, T1041, T1567.002, T1560.001
# Mitigations:  M1031 (Network Intrusion Prevention), M1037 (Filter Network),
#               M1022 (Restrict Permissions), M1027 (Password Policies),
#               M1047 (Audit)
#
# Purpose:
#   While BlueNoroff primarily targets macOS, Linux servers hosting
#   cryptocurrency infrastructure, trading platforms, blockchain nodes,
#   and exchange backend systems are also at risk. This script hardens
#   Linux endpoints against the network-level, credential theft, persistence,
#   and exfiltration aspects of the BlueNoroff attack chain.
#
# Applicable Attack Stages:
#   - Stage 2 (T1543.004): Cron/systemd persistence (Linux equivalent of LaunchAgent)
#   - Stage 3 (T1555.001): Credential store and browser data protection
#   - Stage 4 (T1071.001, T1071.004, T1573.002): C2 domain/port blocking
#   - Stage 5 (T1041, T1567.002): Exfiltration channel monitoring
#
# Usage:
#   sudo ./244dfb88-9068-4db4-9fa8-dbc49517f63d_hardening_linux.sh [apply|undo|check]
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
BACKUP_DIR="/var/backups/f0rtika-hardening-244dfb88"
LOG_FILE="/var/log/f0rtika-hardening-244dfb88.log"
CHANGE_COUNT=0

# BlueNoroff C2 domains
C2_DOMAINS=(
    "linkpc.net"
    "dnx.capital"
    "swissborg.blog"
    "on-offx.com"
    "tokenview.xyz"
)

C2_SUBDOMAINS=(
    "beacon.linkpc.net"
    "app.linkpc.net"
    "update.linkpc.net"
    "check.linkpc.net"
    "cloud.dnx.capital"
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
# 1. Block DPRK C2 Domains (T1071.001, T1071.004)
# ============================================================================
# BlueNoroff uses linkpc.net (dynamic DNS provider), dnx.capital, and
# swissborg.blog domains for KANDYKORN, RustBucket, and Hidden Risk C2.
# Block at DNS level via /etc/hosts and optionally via dnsmasq/unbound.

harden_dns_blocking() {
    log_info "Section 1: C2 Domain Blocking (T1071.001, T1071.004)"

    backup_file /etc/hosts

    # Block parent C2 domains
    for domain in "${C2_DOMAINS[@]}"; do
        if ! grep -qF "$domain" /etc/hosts 2>/dev/null; then
            echo "0.0.0.0 ${domain} # F0RT1KA-BlueNoroff C2 block" >> /etc/hosts
            log_success "Blocked C2 domain: ${domain}"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "Already blocked: ${domain}"
        fi
    done

    # Block known C2 subdomains
    for subdomain in "${C2_SUBDOMAINS[@]}"; do
        if ! grep -qF "$subdomain" /etc/hosts 2>/dev/null; then
            echo "0.0.0.0 ${subdomain} # F0RT1KA-BlueNoroff C2 subdomain" >> /etc/hosts
            log_success "Blocked C2 subdomain: ${subdomain}"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    # If dnsmasq is installed, add domain-level blocking
    if command -v dnsmasq &>/dev/null; then
        local dnsmasq_conf="/etc/dnsmasq.d/f0rtika-bluenoroff-block.conf"
        if [[ ! -f "$dnsmasq_conf" ]]; then
            cat > "$dnsmasq_conf" <<DNS_EOF
# F0RT1KA BlueNoroff C2 Domain Blocking
# Blocks all subdomains of known DPRK C2 infrastructure
address=/linkpc.net/0.0.0.0
address=/dnx.capital/0.0.0.0
address=/swissborg.blog/0.0.0.0
address=/on-offx.com/0.0.0.0
address=/tokenview.xyz/0.0.0.0
DNS_EOF
            systemctl restart dnsmasq 2>/dev/null || true
            log_success "Configured dnsmasq wildcard C2 domain blocking"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    fi

    # If systemd-resolved is in use, log guidance
    if systemctl is-active systemd-resolved &>/dev/null; then
        log_info "systemd-resolved detected. For DNS-level blocking, consider:"
        log_info "  - Using a DNS sinkhole (Pi-hole, AdGuard Home)"
        log_info "  - Configuring response policy zones (RPZ) on your DNS resolver"
    fi
}

undo_dns_blocking() {
    if [[ -f /etc/hosts ]]; then
        sed -i '/F0RT1KA-BlueNoroff/d' /etc/hosts
        log_success "Removed C2 domain blocks from /etc/hosts"
    fi
    rm -f /etc/dnsmasq.d/f0rtika-bluenoroff-block.conf 2>/dev/null || true
    systemctl restart dnsmasq 2>/dev/null || true
}

check_dns_blocking() {
    local blocked=0
    for domain in "${C2_DOMAINS[@]}"; do
        if grep -qF "$domain" /etc/hosts 2>/dev/null; then
            log_success "C2 blocked: ${domain}"
            blocked=$((blocked + 1))
        else
            log_warning "C2 NOT blocked: ${domain}"
        fi
    done
    if [[ -f /etc/dnsmasq.d/f0rtika-bluenoroff-block.conf ]]; then
        log_success "dnsmasq wildcard blocking: active"
    fi
}

# ============================================================================
# 2. Block Sliver C2 Port 8888 (T1573.002)
# ============================================================================
# BlueNoroff uses Sliver C2 framework with mTLS on port 8888.
# Block outbound connections to this port via iptables or nftables.

harden_firewall() {
    log_info "Section 2: Sliver C2 Port Blocking (T1573.002)"

    if command -v nft &>/dev/null; then
        # nftables (modern Linux)
        if ! nft list tables 2>/dev/null | grep -q "f0rtika_bluenoroff"; then
            nft add table inet f0rtika_bluenoroff 2>/dev/null || true
            nft add chain inet f0rtika_bluenoroff output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
            nft add rule inet f0rtika_bluenoroff output tcp dport 8888 drop comment '"F0RT1KA: Block Sliver mTLS C2"' 2>/dev/null || true
            log_success "Blocked outbound port 8888 via nftables"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))

            # Persist nftables rules
            if command -v nft &>/dev/null && [[ -d /etc/nftables.d ]]; then
                nft list table inet f0rtika_bluenoroff > /etc/nftables.d/f0rtika-bluenoroff.nft 2>/dev/null || true
            fi
        else
            log_info "nftables rules already in place"
        fi
    elif command -v iptables &>/dev/null; then
        # iptables (legacy)
        if ! iptables -C OUTPUT -p tcp --dport 8888 -j DROP -m comment --comment "F0RT1KA-BlueNoroff-Sliver" 2>/dev/null; then
            iptables -A OUTPUT -p tcp --dport 8888 -j DROP -m comment --comment "F0RT1KA-BlueNoroff-Sliver"
            log_success "Blocked outbound port 8888 via iptables"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))

            # Persist iptables rules
            if command -v iptables-save &>/dev/null; then
                iptables-save > "${BACKUP_DIR}/iptables_after_hardening.rules" 2>/dev/null || true
            fi
        else
            log_info "iptables rules already in place"
        fi
    else
        log_warning "Neither nftables nor iptables found -- manual firewall configuration required"
    fi

    # Block outbound to known C2 IP ranges if resolved
    log_info "RECOMMENDATION: Configure network firewall to also inspect TLS certificates"
    log_info "  Sliver C2 uses self-signed or custom CA certificates on port 8888"
}

undo_firewall() {
    if command -v nft &>/dev/null; then
        nft delete table inet f0rtika_bluenoroff 2>/dev/null && log_success "Removed nftables rules" || true
        rm -f /etc/nftables.d/f0rtika-bluenoroff.nft 2>/dev/null || true
    fi
    if command -v iptables &>/dev/null; then
        iptables -D OUTPUT -p tcp --dport 8888 -j DROP -m comment --comment "F0RT1KA-BlueNoroff-Sliver" 2>/dev/null && log_success "Removed iptables rules" || true
    fi
}

check_firewall() {
    if command -v nft &>/dev/null && nft list tables 2>/dev/null | grep -q "f0rtika_bluenoroff"; then
        log_success "Port 8888 block (nftables): active"
    elif command -v iptables &>/dev/null && iptables -C OUTPUT -p tcp --dport 8888 -j DROP 2>/dev/null; then
        log_success "Port 8888 block (iptables): active"
    else
        log_warning "Port 8888 block: not configured"
    fi
}

# ============================================================================
# 3. Shell Configuration File Protection (T1543.004 equivalent)
# ============================================================================
# On macOS, BlueNoroff abuses ~/.zshenv for persistence. On Linux, the
# equivalent attack vector is shell profile files (.bashrc, .profile,
# .zshenv, .zshrc) and cron/systemd timers. This section monitors and
# protects these persistence vectors.

harden_shell_profiles() {
    log_info "Section 3: Shell Profile and Persistence Protection (T1543.004 equivalent)"

    # Collect all shell profile files to monitor
    local shell_files=()
    for home_dir in /root /home/*/; do
        [[ -d "$home_dir" ]] || continue
        for profile in .zshenv .zshrc .bashrc .bash_profile .profile; do
            [[ -f "${home_dir}${profile}" ]] && shell_files+=("${home_dir}${profile}")
        done
    done

    # Scan for suspicious content (C2 URLs, curl piped to bash, etc.)
    for sf in "${shell_files[@]}"; do
        if grep -qiE "(linkpc\.net|curl.*\|.*bash|wget.*\|.*sh|HIDDEN_RISK|_update_check|C2_URL)" "$sf" 2>/dev/null; then
            backup_file "$sf"
            log_warning "ALERT: Suspicious content in $sf"

            # Remove suspicious lines
            local clean_content
            clean_content=$(grep -viE "(HIDDEN_RISK|linkpc\.net|_update_check|curl.*\|.*bash|C2_URL)" "$sf" 2>/dev/null || true)
            if [[ -n "$clean_content" ]]; then
                echo "$clean_content" > "$sf"
                log_success "Cleaned suspicious content from $sf"
            fi
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi
    done

    # Set up auditd monitoring for shell profile modifications
    if command -v auditctl &>/dev/null; then
        local audit_rules_file="/etc/audit/rules.d/f0rtika-bluenoroff.rules"

        cat > "$audit_rules_file" <<'AUDIT_EOF'
# F0RT1KA BlueNoroff Defense - Shell Profile and Persistence Monitoring
# Detects modifications to shell configuration files (T1543.004 equivalent)

# Monitor shell profile files
-w /root/.zshenv -p wa -k bluenoroff_shell_persist
-w /root/.bashrc -p wa -k bluenoroff_shell_persist
-w /root/.profile -p wa -k bluenoroff_shell_persist

# Monitor cron directories (persistence equivalent of LaunchAgent)
-w /etc/crontab -p wa -k bluenoroff_cron_persist
-w /etc/cron.d/ -p wa -k bluenoroff_cron_persist
-w /var/spool/cron/ -p wa -k bluenoroff_cron_persist

# Monitor systemd user services (another persistence vector)
-w /etc/systemd/system/ -p wa -k bluenoroff_systemd_persist
-w /usr/lib/systemd/system/ -p wa -k bluenoroff_systemd_persist

# Monitor credential files
-w /etc/shadow -p r -k bluenoroff_credential_access
-w /etc/passwd -p wa -k bluenoroff_credential_access

# Monitor hosts and DNS configuration
-w /etc/hosts -p wa -k bluenoroff_dns_config
-w /etc/resolv.conf -p wa -k bluenoroff_dns_config

# Monitor archive creation (exfiltration preparation, T1560.001)
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/zip -k bluenoroff_archive
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/tar -k bluenoroff_archive
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/gzip -k bluenoroff_archive
AUDIT_EOF

        chmod 640 "$audit_rules_file"

        # Reload audit rules
        augenrules --load 2>/dev/null || auditctl -R "$audit_rules_file" 2>/dev/null || true
        log_success "Installed auditd rules for shell profile, cron, systemd, and credential monitoring"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_warning "auditd not available -- install with: apt install auditd (Debian/Ubuntu) or yum install audit (RHEL)"
    fi

    # Monitor user home directories for shell profile changes
    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        local username
        username=$(basename "$home_dir")
        for profile in .zshenv .bashrc .profile; do
            if [[ -f "${home_dir}${profile}" ]] && command -v auditctl &>/dev/null; then
                auditctl -w "${home_dir}${profile}" -p wa -k "bluenoroff_shell_persist_${username}" 2>/dev/null || true
            fi
        done
    done

    # Scan for suspicious cron jobs
    log_info "Scanning cron jobs for suspicious entries..."
    for crontab in /var/spool/cron/crontabs/* /etc/cron.d/* /etc/crontab; do
        if [[ -f "$crontab" ]]; then
            if grep -qiE "(linkpc\.net|curl.*\|.*bash|wget.*\|.*sh|beacon|C2)" "$crontab" 2>/dev/null; then
                log_warning "ALERT: Suspicious cron entry found in $crontab"
                backup_file "$crontab"
            fi
        fi
    done

    # Scan for suspicious systemd services
    log_info "Scanning systemd services for suspicious entries..."
    for service_file in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
        if [[ -f "$service_file" ]]; then
            if grep -qiE "(linkpc\.net|curl.*\|.*bash|beacon|update_check)" "$service_file" 2>/dev/null; then
                log_warning "ALERT: Suspicious systemd service: $service_file"
                backup_file "$service_file"
            fi
        fi
    done
}

undo_shell_profiles() {
    rm -f /etc/audit/rules.d/f0rtika-bluenoroff.rules 2>/dev/null || true
    augenrules --load 2>/dev/null || true
    log_success "Removed auditd rules for shell profile monitoring"
    log_info "Cleaned shell profiles are backed up in $BACKUP_DIR"
}

check_shell_profiles() {
    if command -v auditctl &>/dev/null && auditctl -l 2>/dev/null | grep -q "bluenoroff_shell_persist"; then
        log_success "Shell profile monitoring: active"
    else
        log_warning "Shell profile monitoring: not configured"
    fi

    if command -v auditctl &>/dev/null && auditctl -l 2>/dev/null | grep -q "bluenoroff_cron_persist"; then
        log_success "Cron persistence monitoring: active"
    else
        log_warning "Cron persistence monitoring: not configured"
    fi
}

# ============================================================================
# 4. Credential Store Protection (T1555.001 equivalent)
# ============================================================================
# On macOS, BlueNoroff targets Keychain. On Linux, credential stores include:
# - GNOME Keyring (~/.local/share/keyrings/)
# - Chrome/Chromium Login Data and Local State
# - Firefox logins.json
# - SSH private keys (~/.ssh/)
# - Crypto wallet data

harden_credential_stores() {
    log_info "Section 4: Credential Store Protection (T1555.001 equivalent)"

    # Restrict SSH private key permissions
    for home_dir in /root /home/*/; do
        local ssh_dir="${home_dir}.ssh"
        if [[ -d "$ssh_dir" ]]; then
            local username
            username=$(basename "$home_dir")
            [[ "$username" == "root" ]] && username="root"

            # Ensure proper permissions on SSH directory
            chmod 700 "$ssh_dir"
            find "$ssh_dir" -name "id_*" ! -name "*.pub" -exec chmod 600 {} \; 2>/dev/null || true
            log_info "  Secured SSH keys for ${username}"
        fi
    done

    # Monitor browser credential stores
    local browser_paths=(
        ".config/google-chrome/Default/Login Data"
        ".config/chromium/Default/Login Data"
        ".mozilla/firefox/*/logins.json"
    )

    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        local username
        username=$(basename "$home_dir")

        for browser_rel in "${browser_paths[@]}"; do
            for browser_path in ${home_dir}${browser_rel}; do
                if [[ -f "$browser_path" ]]; then
                    log_info "  Found browser credentials for ${username}: $(basename "$browser_path")"
                    if command -v auditctl &>/dev/null; then
                        auditctl -w "$browser_path" -p r -k "bluenoroff_browser_cred_${username}" 2>/dev/null || true
                    fi
                fi
            done
        done

        # Monitor crypto wallet data directories
        local wallet_paths=(
            ".config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"  # MetaMask
            ".config/google-chrome/Default/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad"  # Coinbase Wallet
            ".config/Exodus"                                                                            # Exodus
        )
        for wallet_rel in "${wallet_paths[@]}"; do
            local wallet_full="${home_dir}${wallet_rel}"
            if [[ -d "$wallet_full" ]]; then
                log_info "  Found crypto wallet data for ${username}: $(basename "$wallet_rel")"
                if command -v auditctl &>/dev/null; then
                    auditctl -w "$wallet_full" -p r -k "bluenoroff_crypto_wallet_${username}" 2>/dev/null || true
                fi
            fi
        done
    done

    # Create credential store integrity baseline
    local baseline_file="${BACKUP_DIR}/credential_baseline.txt"
    echo "# F0RT1KA Credential Store Baseline - $(date '+%Y-%m-%d %H:%M:%S')" > "$baseline_file"
    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        for cred_file in "${home_dir}.config/google-chrome/Default/Login Data" "${home_dir}.local/share/keyrings/"*; do
            if [[ -f "$cred_file" ]]; then
                sha256sum "$cred_file" >> "$baseline_file" 2>/dev/null || true
            fi
        done
    done
    chmod 600 "$baseline_file"
    log_success "Created credential store integrity baseline"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_credential_stores() {
    rm -f "${BACKUP_DIR}/credential_baseline.txt" 2>/dev/null || true
    log_success "Removed credential store baseline"
    # Audit rules are managed by the shell_profiles section
}

check_credential_stores() {
    if [[ -f "${BACKUP_DIR}/credential_baseline.txt" ]]; then
        log_success "Credential store baseline: exists"
    else
        log_warning "Credential store baseline: not created"
    fi

    if command -v auditctl &>/dev/null && auditctl -l 2>/dev/null | grep -q "bluenoroff_browser_cred"; then
        log_success "Browser credential monitoring: active"
    else
        log_warning "Browser credential monitoring: not configured"
    fi
}

# ============================================================================
# 5. Cloud Storage Exfiltration Monitoring (T1567.002, T1041)
# ============================================================================
# BlueNoroff exfiltrates via AWS S3 (NotLockBit pattern), Google Drive
# (TodoSwift), and HTTP POST. This section restricts cloud API access
# and monitors for exfiltration indicators.

harden_exfiltration_controls() {
    log_info "Section 5: Exfiltration Channel Monitoring (T1567.002, T1041)"

    # Monitor AWS CLI usage (NotLockBit uses hardcoded S3 credentials)
    if command -v auditctl &>/dev/null; then
        # Monitor AWS CLI and SDK usage
        for aws_path in /usr/local/bin/aws /usr/bin/aws; do
            if [[ -f "$aws_path" ]]; then
                auditctl -w "$aws_path" -p x -k bluenoroff_aws_exfil 2>/dev/null || true
                log_info "  Monitoring AWS CLI: $aws_path"
            fi
        done

        # Monitor gsutil (Google Cloud SDK)
        for gsutil_path in /usr/local/bin/gsutil /usr/bin/gsutil /snap/bin/gsutil; do
            if [[ -f "$gsutil_path" ]]; then
                auditctl -w "$gsutil_path" -p x -k bluenoroff_gcloud_exfil 2>/dev/null || true
                log_info "  Monitoring gsutil: $gsutil_path"
            fi
        done

        # Monitor curl and wget for exfiltration
        # (high volume, consider only alerting in combination with archive creation)
        log_info "  RECOMMENDATION: Correlate archive creation with network uploads"
        log_info "  Look for: zip/tar -> curl POST or aws s3 cp patterns"
    fi

    # Monitor for AWS credential files (hardcoded creds are a NotLockBit indicator)
    for home_dir in /root /home/*/; do
        local aws_creds="${home_dir}.aws/credentials"
        if [[ -f "$aws_creds" ]]; then
            log_info "  Found AWS credentials: $aws_creds"
            chmod 600 "$aws_creds" 2>/dev/null || true
            if command -v auditctl &>/dev/null; then
                auditctl -w "$aws_creds" -p ra -k bluenoroff_aws_creds 2>/dev/null || true
            fi
        fi
    done

    log_success "Exfiltration channel monitoring configured"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    log_info "RECOMMENDATIONS for exfiltration prevention:"
    log_info "  1. Deploy a web proxy with DLP capabilities"
    log_info "  2. Monitor S3 PutObject calls from non-approved processes"
    log_info "  3. Alert on googleapis.com/upload/drive from server processes"
    log_info "  4. Restrict outbound access to only required cloud endpoints"
    log_info "  5. Use VPC endpoints for AWS access (blocks public S3 uploads)"
}

undo_exfiltration_controls() {
    log_info "Exfiltration audit rules removed with main audit rules cleanup"
}

check_exfiltration_controls() {
    if command -v auditctl &>/dev/null && auditctl -l 2>/dev/null | grep -q "bluenoroff_aws_exfil"; then
        log_success "AWS CLI monitoring: active"
    else
        log_warning "AWS CLI monitoring: not configured"
    fi

    if command -v auditctl &>/dev/null && auditctl -l 2>/dev/null | grep -q "bluenoroff_archive"; then
        log_success "Archive creation monitoring: active"
    else
        log_warning "Archive creation monitoring: not configured"
    fi
}

# ============================================================================
# 6. Enhanced Audit Logging and Command Monitoring
# ============================================================================
# Comprehensive audit logging for detecting BlueNoroff attack patterns
# across all stages of the killchain.

harden_audit_logging() {
    log_info "Section 6: Enhanced Audit Logging"

    # Ensure auditd is installed and running
    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not installed. Attempting to install..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y auditd audispd-plugins 2>/dev/null || log_warning "Failed to install auditd"
        elif command -v yum &>/dev/null; then
            yum install -y audit 2>/dev/null || log_warning "Failed to install auditd"
        elif command -v dnf &>/dev/null; then
            dnf install -y audit 2>/dev/null || log_warning "Failed to install auditd"
        fi
    fi

    if command -v auditctl &>/dev/null; then
        # Enable process execution auditing
        auditctl -a always,exit -F arch=b64 -S execve -k bluenoroff_exec 2>/dev/null || true
        log_success "Process execution auditing enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))

        # Ensure auditd is running and enabled
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null || true
    fi

    # Deploy enhanced command history logging
    local profile_file="/etc/profile.d/f0rtika-bluenoroff-defense.sh"
    cat > "$profile_file" <<'PROFILE_EOF'
# F0RT1KA BlueNoroff Defense: Enhanced command history + suspicious command alerts
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=100000
export HISTFILESIZE=100000
export HISTCONTROL=""
shopt -s histappend 2>/dev/null || true

# Alert on suspicious commands via syslog (non-blocking)
_f0rtika_cmd_audit() {
    local cmd
    cmd=$(history 1 2>/dev/null | sed 's/^[ ]*[0-9]*[ ]*//')
    case "$cmd" in
        *"aws s3 cp"*|*"aws s3 mv"*|*"aws s3api put"*)
            logger -p auth.alert "F0RT1KA: AWS S3 upload detected: $cmd" ;;
        *"curl"*"-X POST"*|*"curl"*"--upload"*)
            logger -p auth.alert "F0RT1KA: Data upload via curl: $cmd" ;;
        *"zip"*|*"tar czf"*|*"tar -czf"*)
            logger -p auth.alert "F0RT1KA: Archive creation: $cmd" ;;
    esac
}
PROMPT_COMMAND="_f0rtika_cmd_audit;${PROMPT_COMMAND:-}"
PROFILE_EOF
    chmod 644 "$profile_file"
    log_success "Installed command history logging with suspicious command alerting"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Configure journald for persistent logging
    local journald_conf="/etc/systemd/journald.conf.d/f0rtika-hardening.conf"
    if [[ ! -d /etc/systemd/journald.conf.d ]]; then
        mkdir -p /etc/systemd/journald.conf.d
    fi
    if [[ ! -f "$journald_conf" ]]; then
        cat > "$journald_conf" <<'JOURNALD_EOF'
# F0RT1KA: Ensure persistent journal logging for security events
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=2G
SystemKeepFree=1G
MaxRetentionSec=90day
JOURNALD_EOF
        systemctl restart systemd-journald 2>/dev/null || true
        log_success "Configured persistent journald logging (90-day retention)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

undo_audit_logging() {
    rm -f /etc/profile.d/f0rtika-bluenoroff-defense.sh 2>/dev/null || true
    rm -f /etc/systemd/journald.conf.d/f0rtika-hardening.conf 2>/dev/null || true
    systemctl restart systemd-journald 2>/dev/null || true
    log_success "Removed enhanced history logging and journald configuration"
}

check_audit_logging() {
    if command -v auditctl &>/dev/null && systemctl is-active auditd &>/dev/null; then
        log_success "auditd: running"
    else
        log_warning "auditd: not running"
    fi

    if [[ -f /etc/profile.d/f0rtika-bluenoroff-defense.sh ]]; then
        log_success "Suspicious command alerting: configured"
    else
        log_warning "Suspicious command alerting: not configured"
    fi

    if [[ -f /etc/systemd/journald.conf.d/f0rtika-hardening.conf ]]; then
        log_success "Persistent journal logging: configured"
    else
        log_warning "Persistent journal logging: not configured"
    fi
}

# ============================================================================
# 7. Network Egress Monitoring
# ============================================================================
# Monitor outbound network connections for C2 and exfiltration patterns.

harden_network_monitoring() {
    log_info "Section 7: Network Egress Monitoring"

    # Create a periodic network monitoring script
    local monitor_script="/usr/local/bin/f0rtika-network-monitor.sh"
    cat > "$monitor_script" <<'NETMON_EOF'
#!/usr/bin/env bash
# F0RT1KA: Periodic network monitoring for BlueNoroff C2 indicators
LOG="/var/log/f0rtika-network-monitor.log"

# Check for connections to known C2 domains
for domain in linkpc.net dnx.capital swissborg.blog on-offx.com; do
    if ss -tnp 2>/dev/null | grep -i "$domain"; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [CRITICAL] Active connection to C2 domain: $domain" >> "$LOG"
    fi
done

# Check for connections on port 8888 (Sliver mTLS)
if ss -tnp sport = :8888 2>/dev/null | grep -v "^State"; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [HIGH] Outbound connection on port 8888 detected" >> "$LOG"
fi

# Check for DNS tunneling indicators (high volume of DNS queries)
if command -v journalctl &>/dev/null; then
    local dns_count
    dns_count=$(journalctl -u systemd-resolved --since "5 minutes ago" 2>/dev/null | grep -c "linkpc.net" || echo 0)
    if [[ "$dns_count" -gt 10 ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [HIGH] High DNS query rate to linkpc.net: $dns_count queries" >> "$LOG"
    fi
fi
NETMON_EOF
    chmod 755 "$monitor_script"

    # Create systemd timer for periodic monitoring
    local service_file="/etc/systemd/system/f0rtika-network-monitor.service"
    local timer_file="/etc/systemd/system/f0rtika-network-monitor.timer"

    if [[ ! -f "$timer_file" ]]; then
        cat > "$service_file" <<'SVC_EOF'
[Unit]
Description=F0RT1KA BlueNoroff Network Monitor

[Service]
Type=oneshot
ExecStart=/usr/local/bin/f0rtika-network-monitor.sh
SVC_EOF

        cat > "$timer_file" <<'TMR_EOF'
[Unit]
Description=F0RT1KA BlueNoroff Network Monitor Timer

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
TMR_EOF

        systemctl daemon-reload 2>/dev/null || true
        systemctl enable f0rtika-network-monitor.timer 2>/dev/null || true
        systemctl start f0rtika-network-monitor.timer 2>/dev/null || true
        log_success "Installed network monitoring timer (runs every 5 minutes)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Network monitoring timer already installed"
    fi
}

undo_network_monitoring() {
    systemctl stop f0rtika-network-monitor.timer 2>/dev/null || true
    systemctl disable f0rtika-network-monitor.timer 2>/dev/null || true
    rm -f /etc/systemd/system/f0rtika-network-monitor.service 2>/dev/null || true
    rm -f /etc/systemd/system/f0rtika-network-monitor.timer 2>/dev/null || true
    rm -f /usr/local/bin/f0rtika-network-monitor.sh 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    log_success "Removed network monitoring timer and script"
}

check_network_monitoring() {
    if systemctl is-active f0rtika-network-monitor.timer &>/dev/null; then
        log_success "Network monitoring timer: active"
    else
        log_warning "Network monitoring timer: not active"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

ACTION="${1:-apply}"

echo ""
echo "============================================================================"
echo "F0RT1KA Linux Hardening: DPRK BlueNoroff Financial Sector Attack Chain"
echo "Test ID: 244dfb88-9068-4db4-9fa8-dbc49517f63d"
echo "MITRE ATT&CK: T1553.001, T1543.004, T1059.002, T1555.001, T1056.002,"
echo "              T1071.001, T1573.002, T1071.004, T1041, T1567.002, T1560.001"
echo "Action: $ACTION"
echo "============================================================================"
echo ""

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
echo "$(date '+%Y-%m-%d %H:%M:%S') === F0RT1KA BlueNoroff Hardening: $ACTION ===" >> "$LOG_FILE" 2>/dev/null || true

case "$ACTION" in
    apply)
        check_root
        ensure_backup_dir

        harden_dns_blocking
        echo ""
        harden_firewall
        echo ""
        harden_shell_profiles
        echo ""
        harden_credential_stores
        echo ""
        harden_exfiltration_controls
        echo ""
        harden_audit_logging
        echo ""
        harden_network_monitoring

        echo ""
        echo "============================================================================"
        log_success "Hardening complete. $CHANGE_COUNT changes applied."
        echo "============================================================================"
        echo ""
        echo "Applied Settings:"
        echo "  1. C2 domain blocking via /etc/hosts and dnsmasq (T1071.001, T1071.004)"
        echo "  2. Outbound port 8888 blocking via firewall (T1573.002)"
        echo "  3. Shell profile and persistence monitoring via auditd (T1543.004)"
        echo "  4. Credential store protection and integrity baseline (T1555.001)"
        echo "  5. Cloud exfiltration channel monitoring (T1567.002, T1041)"
        echo "  6. Enhanced audit logging with suspicious command alerting"
        echo "  7. Periodic network monitoring for C2 indicators"
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
        log_warning "Reverting hardening changes..."
        echo ""

        undo_dns_blocking
        undo_firewall
        undo_shell_profiles
        undo_credential_stores
        undo_exfiltration_controls
        undo_audit_logging
        undo_network_monitoring

        echo ""
        log_success "Hardening changes reverted."
        echo ""
        ;;

    check)
        log_info "Checking hardening status..."
        echo ""

        check_dns_blocking
        echo ""
        check_firewall
        echo ""
        check_shell_profiles
        echo ""
        check_credential_stores
        echo ""
        check_exfiltration_controls
        echo ""
        check_audit_logging
        echo ""
        check_network_monitoring

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
