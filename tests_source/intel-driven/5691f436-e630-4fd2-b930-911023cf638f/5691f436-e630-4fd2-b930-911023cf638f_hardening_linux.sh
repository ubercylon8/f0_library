#!/usr/bin/env bash
# ============================================================================
# Linux Hardening Script: APT34 Exchange Server Weaponization
# ============================================================================
#
# Test ID:      5691f436-e630-4fd2-b930-911023cf638f
# Test Name:    APT34 Exchange Server Weaponization with Email-Based C2
# MITRE ATT&CK: T1505.003 (Web Shell / IIS Backdoor)
#                T1071.003 (Email-Based C2)
#                T1556.002 (Password Filter DLL)
#                T1048.003 (Exfiltration via Email)
# Mitigations:  M1042, M1038, M1047, M1037, M1031, M1026
# Platform:     Linux (Ubuntu/Debian, RHEL/CentOS, generic)
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
#
# DESCRIPTION:
#   While this test targets Windows Exchange servers, the underlying attack
#   techniques have Linux equivalents. This script hardens Linux systems
#   against:
#     1. Web shell deployment (Apache/Nginx module injection)
#     2. Email-based C2 channels (Postfix/sendmail abuse)
#     3. PAM credential interception (Linux password filter equivalent)
#     4. Data exfiltration via email protocols
#     5. Audit logging for detection (auditd rules)
#     6. Outbound SMTP traffic controls (iptables/nftables)
#
# USAGE:
#   sudo ./5691f436-e630-4fd2-b930-911023cf638f_hardening_linux.sh [--undo] [--dry-run] [--verbose]
#
# OPTIONS:
#   --undo      Revert all changes made by this script
#   --dry-run   Show what would be changed without applying
#   --verbose   Enable detailed output
#
# REQUIREMENTS:
#   - Root privileges (sudo)
#   - systemd-based Linux distribution
#   - auditd installed (or will be installed)
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
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/f0rtika-apt34.rules"

UNDO=false
DRY_RUN=false
VERBOSE=false
CHANGES_MADE=0

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
            echo "Hardens Linux systems against APT34 Exchange weaponization equivalent techniques."
            echo ""
            echo "Options:"
            echo "  --undo      Revert all changes to defaults"
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
log_success() { echo -e "\033[0;32m[+] $1\033[0m"; echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo -e "\033[0;33m[!] $1\033[0m"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "\033[0;31m[-] $1\033[0m"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_header()  { echo -e "\033[0;35m[=] $1\033[0m"; echo "$(date '+%Y-%m-%d %H:%M:%S') [HEADER] $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_verbose() { if $VERBOSE; then echo "    $1"; fi; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
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

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

# ============================================================================
# 1. Web Server Module Hardening (T1505.003 Linux Equivalent)
# ============================================================================

harden_web_server_modules() {
    log_header "1. Web Server Module Hardening (T1505.003 equivalent)"
    log_info "Protecting Apache/Nginx against unauthorized module injection..."

    if $UNDO; then
        log_info "Reverting web server module hardening..."
        # Restore backed-up configurations
        if [[ -d "$BACKUP_DIR" ]]; then
            for bak in "$BACKUP_DIR"/apache2.conf.* "$BACKUP_DIR"/nginx.conf.*; do
                [[ -f "$bak" ]] || continue
                local orig_name
                orig_name=$(basename "$bak" | sed 's/\.[0-9]*_[0-9]*\.bak$//')
                if [[ "$orig_name" == "apache2.conf" ]] && [[ -d /etc/apache2 ]]; then
                    cp "$bak" /etc/apache2/apache2.conf
                    log_success "Restored Apache configuration"
                elif [[ "$orig_name" == "nginx.conf" ]] && [[ -d /etc/nginx ]]; then
                    cp "$bak" /etc/nginx/nginx.conf
                    log_success "Restored Nginx configuration"
                fi
                break  # Only restore latest backup
            done
        fi
        return
    fi

    # Apache hardening
    if command -v apache2 &>/dev/null || command -v httpd &>/dev/null; then
        log_info "Apache detected - hardening module directories..."

        # Restrict mods-available directory
        local mods_dir="/etc/apache2/mods-available"
        [[ -d "$mods_dir" ]] || mods_dir="/etc/httpd/conf.modules.d"

        if [[ -d "$mods_dir" ]]; then
            apply_change "Restrict Apache modules directory to root" \
                chmod 750 "$mods_dir"
            apply_change "Set Apache modules directory ownership to root" \
                chown root:root "$mods_dir"
        fi

        # Backup and protect main config
        local apache_conf="/etc/apache2/apache2.conf"
        [[ -f "$apache_conf" ]] || apache_conf="/etc/httpd/conf/httpd.conf"
        if [[ -f "$apache_conf" ]]; then
            backup_file "$apache_conf"
            apply_change "Set Apache config to read-only for non-root" \
                chmod 644 "$apache_conf"
        fi
    fi

    # Nginx hardening
    if command -v nginx &>/dev/null; then
        log_info "Nginx detected - hardening module directories..."

        local nginx_modules="/etc/nginx/modules-enabled"
        if [[ -d "$nginx_modules" ]]; then
            apply_change "Restrict Nginx modules directory to root" \
                chmod 750 "$nginx_modules"
        fi

        local nginx_conf="/etc/nginx/nginx.conf"
        if [[ -f "$nginx_conf" ]]; then
            backup_file "$nginx_conf"
            apply_change "Set Nginx config to read-only for non-root" \
                chmod 644 "$nginx_conf"
        fi
    fi

    # Protect web root directories from unauthorized writes
    for webroot in /var/www /srv/www /usr/share/nginx; do
        if [[ -d "$webroot" ]]; then
            apply_change "Remove world-write from $webroot" \
                chmod -R o-w "$webroot"
        fi
    done

    log_success "Web server module hardening complete"
}

# ============================================================================
# 2. PAM Credential Interception Protection (T1556.002 Linux Equivalent)
# ============================================================================

harden_pam_credential_protection() {
    log_header "2. PAM Credential Interception Protection (T1556.002 equivalent)"
    log_info "Protecting PAM configuration against unauthorized modifications..."

    if $UNDO; then
        log_info "Reverting PAM hardening (restoring from backup)..."
        if [[ -d "$BACKUP_DIR" ]]; then
            for bak in "$BACKUP_DIR"/common-password.* "$BACKUP_DIR"/system-auth.*; do
                [[ -f "$bak" ]] || continue
                local orig_name
                orig_name=$(basename "$bak" | sed 's/\.[0-9]*_[0-9]*\.bak$//')
                local target="/etc/pam.d/$orig_name"
                if [[ -f "$target" ]]; then
                    cp "$bak" "$target"
                    log_success "Restored PAM config: $orig_name"
                fi
                break
            done
        fi
        return
    fi

    # Protect PAM configuration directory
    local pam_dir="/etc/pam.d"
    if [[ -d "$pam_dir" ]]; then
        apply_change "Restrict PAM directory to root only" \
            chmod 750 "$pam_dir"

        # Backup key PAM files
        for pam_file in common-password common-auth system-auth password-auth; do
            if [[ -f "$pam_dir/$pam_file" ]]; then
                backup_file "$pam_dir/$pam_file"
                apply_change "Set $pam_file to read-only" \
                    chmod 644 "$pam_dir/$pam_file"
            fi
        done
    fi

    # Protect PAM shared library directories
    for libdir in /lib/x86_64-linux-gnu/security /lib64/security /usr/lib64/security; do
        if [[ -d "$libdir" ]]; then
            apply_change "Restrict PAM library directory: $libdir" \
                chmod 755 "$libdir"
            # Verify no unexpected PAM modules
            log_info "PAM modules in $libdir:"
            ls -la "$libdir"/*.so 2>/dev/null | while read -r line; do
                log_verbose "  $line"
            done
        fi
    done

    # Protect /etc/security (password quality configs)
    if [[ -d /etc/security ]]; then
        apply_change "Restrict /etc/security directory" \
            chmod 750 /etc/security
    fi

    # Set immutable bit on critical PAM files (prevents modification even by root without unsetting)
    if command -v chattr &>/dev/null; then
        for pam_file in common-password common-auth system-auth password-auth; do
            if [[ -f "$pam_dir/$pam_file" ]]; then
                apply_change "Set immutable attribute on $pam_file" \
                    chattr +i "$pam_dir/$pam_file"
            fi
        done
        log_info "Note: Use 'chattr -i' to remove immutable attribute before making legitimate changes"
    fi

    log_success "PAM credential protection hardening complete"
}

# ============================================================================
# 3. Outbound SMTP Traffic Controls (T1048.003)
# ============================================================================

harden_outbound_smtp() {
    log_header "3. Outbound SMTP Traffic Controls (T1048.003)"
    log_info "Restricting outbound SMTP to prevent email-based exfiltration..."

    if $UNDO; then
        log_info "Removing outbound SMTP iptables rules..."
        for port in 25 587 465; do
            iptables -D OUTPUT -p tcp --dport "$port" -m owner ! --uid-owner root -j DROP 2>/dev/null || true
            iptables -D OUTPUT -p tcp --dport "$port" -m owner ! --uid-owner postfix -j DROP 2>/dev/null || true
        done
        # Remove nftables rules if present
        if command -v nft &>/dev/null; then
            nft delete table inet f0rtika_smtp 2>/dev/null || true
        fi
        log_success "Outbound SMTP rules removed"
        return
    fi

    # Determine firewall tool
    if command -v nft &>/dev/null; then
        log_info "Using nftables for SMTP egress control..."

        local nft_rules
        nft_rules=$(cat <<'NFTRULES'
table inet f0rtika_smtp {
    chain output {
        type filter hook output priority 0; policy accept;

        # Allow SMTP from Postfix/Exim mail transport agents
        tcp dport { 25, 587, 465 } meta skuid postfix accept
        tcp dport { 25, 587, 465 } meta skuid Debian-exim accept

        # Block all other outbound SMTP
        tcp dport { 25, 587, 465 } log prefix "F0RT1KA-SMTP-BLOCK: " drop
    }
}
NFTRULES
)
        if $DRY_RUN; then
            log_info "[DRY-RUN] Would create nftables SMTP rules"
            echo "$nft_rules"
        else
            # Remove existing table if present
            nft delete table inet f0rtika_smtp 2>/dev/null || true
            echo "$nft_rules" | nft -f -
            log_success "nftables SMTP egress rules applied"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi

    elif command -v iptables &>/dev/null; then
        log_info "Using iptables for SMTP egress control..."

        for port in 25 587 465; do
            # Remove existing rules (idempotent)
            iptables -D OUTPUT -p tcp --dport "$port" -m owner ! --uid-owner root -j DROP 2>/dev/null || true

            # Allow from mail transport agents, block everything else
            if id postfix &>/dev/null; then
                apply_change "Block non-postfix SMTP on port $port" \
                    iptables -A OUTPUT -p tcp --dport "$port" -m owner ! --uid-owner postfix -j DROP
            else
                apply_change "Block all outbound SMTP on port $port" \
                    iptables -A OUTPUT -p tcp --dport "$port" -j DROP
            fi
        done

        # Save rules for persistence
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables.rules 2>/dev/null || true
            log_info "iptables rules saved to /etc/iptables.rules"
        fi
    else
        log_warning "No firewall tool found (nft or iptables) - skipping SMTP controls"
    fi

    log_success "Outbound SMTP controls configured"
}

# ============================================================================
# 4. Audit Logging Rules (All Techniques)
# ============================================================================

configure_audit_rules() {
    log_header "4. Audit Logging Rules (All Techniques)"
    log_info "Configuring auditd rules for APT34 technique detection..."

    if $UNDO; then
        log_info "Removing F0RT1KA audit rules..."
        if [[ -f "$AUDIT_RULES_FILE" ]]; then
            rm -f "$AUDIT_RULES_FILE"
            if command -v augenrules &>/dev/null; then
                augenrules --load 2>/dev/null || true
            elif command -v auditctl &>/dev/null; then
                service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
            fi
            log_success "F0RT1KA audit rules removed"
        fi
        return
    fi

    # Ensure auditd is installed
    if ! command -v auditctl &>/dev/null; then
        log_info "Installing auditd..."
        local distro
        distro=$(detect_distro)
        case "$distro" in
            ubuntu|debian)
                apt-get install -y auditd audispd-plugins 2>/dev/null || true
                ;;
            centos|rhel|fedora|rocky|alma)
                yum install -y audit audit-libs 2>/dev/null || dnf install -y audit audit-libs 2>/dev/null || true
                ;;
        esac
    fi

    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not available - skipping audit rules"
        return
    fi

    # Create audit rules file
    local rules_content
    rules_content=$(cat <<'AUDITRULES'
# ============================================================================
# F0RT1KA APT34 Exchange Weaponization - Linux Audit Rules
# Test ID: 5691f436-e630-4fd2-b930-911023cf638f
# Generated: 2026-03-13
# ============================================================================

# --- T1505.003 Equivalent: Web server module/config changes ---
# Monitor Apache configuration changes
-w /etc/apache2/ -p wa -k f0rtika_webserver_config
-w /etc/httpd/ -p wa -k f0rtika_webserver_config
-w /etc/nginx/ -p wa -k f0rtika_webserver_config

# Monitor web server module directories
-w /usr/lib/apache2/modules/ -p wa -k f0rtika_webserver_modules
-w /usr/lib64/httpd/modules/ -p wa -k f0rtika_webserver_modules
-w /etc/nginx/modules-enabled/ -p wa -k f0rtika_webserver_modules

# Monitor web root for unauthorized file creation
-w /var/www/ -p wa -k f0rtika_webroot_changes

# --- T1556.002 Equivalent: PAM credential interception ---
# Monitor PAM configuration changes (password filter equivalent)
-w /etc/pam.d/ -p wa -k f0rtika_pam_modification
-w /etc/security/ -p wa -k f0rtika_pam_security
-w /etc/nsswitch.conf -p wa -k f0rtika_nsswitch

# Monitor PAM shared library directory for new modules
-w /lib/x86_64-linux-gnu/security/ -p wa -k f0rtika_pam_modules
-w /lib64/security/ -p wa -k f0rtika_pam_modules
-w /usr/lib64/security/ -p wa -k f0rtika_pam_modules

# Monitor /etc/shadow and /etc/passwd for credential access
-w /etc/shadow -p rwa -k f0rtika_credential_access
-w /etc/passwd -p wa -k f0rtika_credential_access
-w /etc/gshadow -p rwa -k f0rtika_credential_access

# --- T1071.003 Equivalent: Email-based C2 ---
# Monitor mail configuration
-w /etc/postfix/ -p wa -k f0rtika_mail_config
-w /etc/exim4/ -p wa -k f0rtika_mail_config
-w /etc/sendmail.cf -p wa -k f0rtika_mail_config
-w /etc/aliases -p wa -k f0rtika_mail_config

# Monitor cron for C2 polling (email C2 equivalent)
-w /etc/crontab -p wa -k f0rtika_cron_modification
-w /var/spool/cron/ -p wa -k f0rtika_cron_modification
-w /etc/cron.d/ -p wa -k f0rtika_cron_modification

# --- T1048.003: Outbound connections ---
# Monitor outbound network connections (SMTP exfiltration)
-a always,exit -F arch=b64 -S connect -F a2=16 -k f0rtika_network_connect
-a always,exit -F arch=b32 -S connect -F a2=16 -k f0rtika_network_connect

# --- General: Process execution monitoring ---
# Monitor execution of mail commands
-w /usr/sbin/sendmail -p x -k f0rtika_mail_execution
-w /usr/bin/mail -p x -k f0rtika_mail_execution
-w /usr/bin/mutt -p x -k f0rtika_mail_execution

# Monitor compression tools (data staging)
-w /usr/bin/zip -p x -k f0rtika_data_staging
-w /usr/bin/tar -p x -k f0rtika_data_staging
-w /usr/bin/gzip -p x -k f0rtika_data_staging
-w /usr/bin/7z -p x -k f0rtika_data_staging

# Monitor curl/wget (potential exfiltration channels)
-w /usr/bin/curl -p x -k f0rtika_exfil_tool
-w /usr/bin/wget -p x -k f0rtika_exfil_tool
AUDITRULES
)

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create audit rules at: $AUDIT_RULES_FILE"
        echo "$rules_content"
    else
        mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
        echo "$rules_content" > "$AUDIT_RULES_FILE"
        chmod 640 "$AUDIT_RULES_FILE"

        # Load rules
        if command -v augenrules &>/dev/null; then
            augenrules --load 2>/dev/null || true
        else
            auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
        fi

        log_success "Audit rules installed at $AUDIT_RULES_FILE"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    fi

    # Ensure auditd is running
    if command -v systemctl &>/dev/null; then
        apply_change "Enable and start auditd" \
            systemctl enable --now auditd
    fi

    log_success "Audit logging configured for APT34 technique detection"
}

# ============================================================================
# 5. Email Server Hardening (T1071.003 + T1048.003)
# ============================================================================

harden_email_server() {
    log_header "5. Email Server Hardening (T1071.003 + T1048.003)"
    log_info "Hardening email server configuration..."

    if $UNDO; then
        log_info "Reverting email server hardening..."
        # Restore Postfix config if backed up
        if [[ -d "$BACKUP_DIR" ]]; then
            for bak in "$BACKUP_DIR"/main.cf.*; do
                [[ -f "$bak" ]] || continue
                cp "$bak" /etc/postfix/main.cf 2>/dev/null || true
                systemctl restart postfix 2>/dev/null || true
                log_success "Restored Postfix configuration"
                break
            done
        fi
        return
    fi

    # Postfix hardening
    if [[ -f /etc/postfix/main.cf ]]; then
        log_info "Postfix detected - applying hardening..."
        backup_file /etc/postfix/main.cf

        # Restrict relay to prevent unauthorized email sending
        if ! grep -q "^smtpd_relay_restrictions" /etc/postfix/main.cf; then
            if ! $DRY_RUN; then
                echo "" >> /etc/postfix/main.cf
                echo "# F0RT1KA APT34 Hardening - Restrict relay" >> /etc/postfix/main.cf
                echo "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination" >> /etc/postfix/main.cf
                log_success "Postfix relay restrictions configured"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            else
                log_info "[DRY-RUN] Would add relay restrictions to Postfix"
            fi
        fi

        # Enable verbose logging for mail activity detection
        if ! grep -q "^smtpd_log_access_permit_actions" /etc/postfix/main.cf 2>/dev/null; then
            if ! $DRY_RUN; then
                echo "# F0RT1KA - Enhanced mail logging" >> /etc/postfix/main.cf
                echo "smtpd_log_access_permit_actions = static:all" >> /etc/postfix/main.cf
                log_success "Postfix enhanced logging enabled"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            fi
        fi

        # Restart Postfix to apply changes
        if ! $DRY_RUN; then
            systemctl restart postfix 2>/dev/null || true
        fi
    else
        log_info "Postfix not installed - skipping email server hardening"
    fi

    log_success "Email server hardening complete"
}

# ============================================================================
# 6. Kernel and System Hardening
# ============================================================================

harden_kernel_settings() {
    log_header "6. Kernel and System Hardening"
    log_info "Applying kernel-level security settings..."

    local sysctl_file="/etc/sysctl.d/99-f0rtika-apt34.conf"

    if $UNDO; then
        log_info "Removing kernel hardening settings..."
        if [[ -f "$sysctl_file" ]]; then
            rm -f "$sysctl_file"
            sysctl --system 2>/dev/null || true
            log_success "Kernel hardening settings removed"
        fi
        return
    fi

    local sysctl_content
    sysctl_content=$(cat <<'SYSCTL'
# ============================================================================
# F0RT1KA APT34 Kernel Hardening
# Test ID: 5691f436-e630-4fd2-b930-911023cf638f
# ============================================================================

# Restrict kernel module loading (prevents unauthorized module injection)
kernel.modules_disabled = 1

# Enable kernel address space layout randomization
kernel.randomize_va_space = 2

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Restrict access to kernel pointers
kernel.kptr_restrict = 2

# Restrict ptrace to parent process only (prevents credential sniffing)
kernel.yama.ptrace_scope = 1

# Disable IP forwarding (prevents relay abuse)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Log martian packets (detect network anomalies)
net.ipv4.conf.all.log_martians = 1

# Disable ICMP redirects (prevent network manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Enable SYN cookies (prevent SYN flood)
net.ipv4.tcp_syncookies = 1
SYSCTL
)

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create sysctl config at: $sysctl_file"
        echo "$sysctl_content"
    else
        echo "$sysctl_content" > "$sysctl_file"
        chmod 644 "$sysctl_file"

        # Apply settings (skip modules_disabled in non-reboot scenario)
        sysctl --system 2>/dev/null || true
        log_success "Kernel hardening settings applied"
        CHANGES_MADE=$((CHANGES_MADE + 1))

        log_warning "kernel.modules_disabled=1 will prevent module loading until next reboot"
        log_warning "Remove this setting if you need to load kernel modules"
    fi

    log_success "Kernel and system hardening complete"
}

# ============================================================================
# 7. File Integrity Monitoring
# ============================================================================

configure_file_integrity() {
    log_header "7. File Integrity Monitoring"
    log_info "Setting up file integrity monitoring for critical paths..."

    if $UNDO; then
        log_info "File integrity monitoring removal requires manual aide/OSSEC reconfiguration"
        return
    fi

    # Check for AIDE
    if command -v aide &>/dev/null; then
        log_info "AIDE detected - updating configuration..."

        local aide_extra="/etc/aide/aide.conf.d/99_f0rtika_apt34"
        if [[ -d /etc/aide/aide.conf.d ]]; then
            if ! $DRY_RUN; then
                cat > "$aide_extra" <<'AIDECONF'
# F0RT1KA APT34 - File Integrity Monitoring
# Web server configurations
/etc/apache2 CONTENT_EX
/etc/nginx CONTENT_EX
/etc/httpd CONTENT_EX

# PAM configuration (password filter equivalent)
/etc/pam.d CONTENT_EX
/etc/security CONTENT_EX

# Mail configuration
/etc/postfix CONTENT_EX
/etc/exim4 CONTENT_EX

# Critical system files
/etc/shadow PERMS
/etc/passwd CONTENT_EX
/etc/nsswitch.conf CONTENT_EX
AIDECONF
                log_success "AIDE configuration updated for APT34 monitoring"
                CHANGES_MADE=$((CHANGES_MADE + 1))

                # Reinitialize AIDE database
                aide --init 2>/dev/null &
                log_info "AIDE database reinitialization started in background"
            fi
        fi
    else
        log_info "AIDE not installed - consider installing: apt install aide (Debian) or yum install aide (RHEL)"
    fi

    log_success "File integrity monitoring configured"
}

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================================"
echo "  F0RT1KA Linux Hardening Script"
echo "  Test: APT34 Exchange Server Weaponization with Email-Based C2"
echo "  MITRE ATT&CK: T1505.003, T1071.003, T1556.002, T1048.003"
echo "  Threat Actor: APT34 / OilRig / Hazel Sandstorm"
echo "============================================================================"
echo ""

check_root

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
mkdir -p "$BACKUP_DIR" 2>/dev/null || true

MODE="HARDEN"
if $UNDO; then MODE="REVERT"; fi
if $DRY_RUN; then MODE="$MODE (DRY-RUN)"; fi

log_header "Mode: $MODE"
log_info "Distribution: $(detect_distro)"
log_info "Log file: $LOG_FILE"
echo ""

# Execute hardening functions
harden_pam_credential_protection     # Critical: T1556.002 equivalent
echo ""

harden_web_server_modules            # High: T1505.003 equivalent
echo ""

harden_outbound_smtp                 # High: T1048.003
echo ""

configure_audit_rules                # Medium: Detection enablement
echo ""

harden_email_server                  # Medium: T1071.003 + T1048.003
echo ""

harden_kernel_settings               # Medium: System hardening
echo ""

configure_file_integrity             # Low: Monitoring enhancement
echo ""

# Summary
echo "============================================================================"
log_success "Hardening Complete!"
echo "============================================================================"
echo ""
log_info "Total changes applied: $CHANGES_MADE"
log_info "Log file: $LOG_FILE"
log_info "Backup directory: $BACKUP_DIR"
echo ""

# Verification commands
log_header "Verification Commands:"
echo ""
echo "  # Check audit rules:"
echo "  auditctl -l | grep f0rtika"
echo ""
echo "  # Check PAM configuration integrity:"
echo "  ls -la /etc/pam.d/"
echo "  lsattr /etc/pam.d/common-password 2>/dev/null"
echo ""
echo "  # Check firewall SMTP rules:"
echo "  iptables -L OUTPUT -n | grep -E '(25|587|465)'"
echo "  nft list table inet f0rtika_smtp 2>/dev/null"
echo ""
echo "  # Check kernel settings:"
echo "  sysctl kernel.modules_disabled kernel.yama.ptrace_scope"
echo ""
echo "  # Check web server permissions:"
echo "  ls -la /etc/apache2/mods-available/ 2>/dev/null"
echo "  ls -la /etc/nginx/modules-enabled/ 2>/dev/null"
echo ""

if ! $UNDO; then
    log_warning "IMPORTANT: kernel.modules_disabled=1 prevents loading new kernel modules."
    log_warning "Review /etc/sysctl.d/99-f0rtika-apt34.conf before rebooting."
fi

echo ""
exit 0
