#!/usr/bin/env bash
# ============================================================
# F0RT1KA Linux Hardening Script
# Tailscale Remote Access and Data Exfiltration
#
# Test ID:    eafce2fc-75fd-4c62-92dc-32cabe5cf206
# Techniques: T1105, T1219, T1543.003, T1021.004, T1041
# Mitigations: M1031, M1037, M1038, M1042, M1047
#
# Purpose:
#   Hardens a Linux system against the attack techniques
#   simulated by this test: unauthorized remote access tool
#   deployment, SSH abuse, service persistence, and data
#   exfiltration. While the test targets Windows, these
#   techniques have direct Linux equivalents.
#
# Usage:
#   sudo ./eafce2fc-..._hardening_linux.sh          # Apply hardening
#   sudo ./eafce2fc-..._hardening_linux.sh --undo    # Revert changes
#   sudo ./eafce2fc-..._hardening_linux.sh --check   # Audit current state
#
# Requirements:
#   - Root privileges
#   - systemd-based Linux distribution
#   - iptables or nftables
#
# Author: F0RT1KA Defense Guidance Builder
# Date:   2026-03-13
# ============================================================

set -euo pipefail

# ============================================================
# Constants
# ============================================================
SCRIPT_NAME="$(basename "$0")"
BACKUP_DIR="/var/backups/f0rt1ka-hardening"
BACKUP_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/f0rt1ka-hardening.log"
UNDO_MODE=false
CHECK_MODE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================
# Parse Arguments
# ============================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo|--revert)
            UNDO_MODE=true
            shift
            ;;
        --check|--audit)
            CHECK_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: sudo $SCRIPT_NAME [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --undo, --revert   Revert all hardening changes"
            echo "  --check, --audit   Audit current hardening state"
            echo "  --help, -h         Show this help message"
            echo ""
            echo "Mitigations applied:"
            echo "  M1031 - Network Intrusion Prevention"
            echo "  M1037 - Filter Network Traffic"
            echo "  M1038 - Execution Prevention"
            echo "  M1042 - Disable or Remove Feature"
            echo "  M1047 - Audit"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================================
# Helper Functions
# ============================================================

log_msg() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true

    case "$level" in
        INFO)    echo -e "${CYAN}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[OK]${NC}   $message" ;;
        WARNING) echo -e "${YELLOW}[WARN]${NC} $message" ;;
        ERROR)   echo -e "${RED}[FAIL]${NC} $message" ;;
        CHECK)   echo -e "${CYAN}[AUDIT]${NC} $message" ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_msg "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
}

backup_file() {
    local filepath="$1"
    if [[ -f "$filepath" ]]; then
        mkdir -p "$BACKUP_DIR"
        local backup_name
        backup_name="${BACKUP_DIR}/$(basename "$filepath").${BACKUP_TIMESTAMP}.bak"
        cp -p "$filepath" "$backup_name"
        log_msg "INFO" "Backed up: $filepath -> $backup_name"
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ============================================================
# 1. Block Tailscale Infrastructure (M1037 - Filter Network Traffic)
# ============================================================

apply_tailscale_block() {
    log_msg "INFO" "--- Blocking Tailscale infrastructure (M1037) ---"

    # Block DNS resolution for Tailscale domains
    local hosts_marker="# F0RT1KA-HARDENING: Tailscale block"
    if ! grep -q "$hosts_marker" /etc/hosts 2>/dev/null; then
        backup_file /etc/hosts
        cat >> /etc/hosts <<EOF

$hosts_marker
# Block Tailscale coordination and control plane
0.0.0.0 controlplane.tailscale.com
0.0.0.0 login.tailscale.com
0.0.0.0 log.tailscale.com
0.0.0.0 pkgs.tailscale.com
0.0.0.0 derp1.tailscale.com
0.0.0.0 derp2.tailscale.com
0.0.0.0 derp3.tailscale.com
0.0.0.0 derp4.tailscale.com
0.0.0.0 derp5.tailscale.com
0.0.0.0 derp6.tailscale.com
0.0.0.0 derp7.tailscale.com
0.0.0.0 derp8.tailscale.com
0.0.0.0 derp9.tailscale.com
0.0.0.0 derp10.tailscale.com
# $hosts_marker END
EOF
        log_msg "SUCCESS" "Tailscale domains blocked in /etc/hosts"
    else
        log_msg "INFO" "Tailscale domains already blocked in /etc/hosts"
    fi

    # Block Tailscale-specific ports via iptables (WireGuard 41641, STUN 3478)
    if command_exists iptables; then
        local chain_name="F0RT1KA_BLOCK_RAT"

        if ! iptables -L "$chain_name" &>/dev/null; then
            iptables -N "$chain_name" 2>/dev/null || true
            iptables -A "$chain_name" -p udp --dport 41641 -j DROP -m comment --comment "Block Tailscale WireGuard"
            iptables -A "$chain_name" -p udp --dport 3478 -j DROP -m comment --comment "Block STUN (Tailscale NAT traversal)"
            iptables -A "$chain_name" -p tcp --dport 41641 -j DROP -m comment --comment "Block Tailscale TCP fallback"

            # Insert the chain into OUTPUT
            iptables -I OUTPUT -j "$chain_name" 2>/dev/null || true
            log_msg "SUCCESS" "iptables rules added to block Tailscale ports (41641, 3478)"
        else
            log_msg "INFO" "iptables chain $chain_name already exists"
        fi
    else
        log_msg "WARNING" "iptables not found - skipping port blocking"
    fi
}

undo_tailscale_block() {
    log_msg "INFO" "--- Reverting Tailscale infrastructure block ---"

    # Remove hosts entries
    local hosts_marker="# F0RT1KA-HARDENING: Tailscale block"
    if grep -q "$hosts_marker" /etc/hosts 2>/dev/null; then
        sed -i "/$hosts_marker/,/$hosts_marker END/d" /etc/hosts
        log_msg "SUCCESS" "Tailscale domain blocks removed from /etc/hosts"
    fi

    # Remove iptables chain
    if command_exists iptables; then
        local chain_name="F0RT1KA_BLOCK_RAT"
        if iptables -L "$chain_name" &>/dev/null; then
            iptables -D OUTPUT -j "$chain_name" 2>/dev/null || true
            iptables -F "$chain_name" 2>/dev/null || true
            iptables -X "$chain_name" 2>/dev/null || true
            log_msg "SUCCESS" "iptables chain $chain_name removed"
        fi
    fi
}

check_tailscale_block() {
    log_msg "CHECK" "--- Tailscale Infrastructure Block Status ---"

    if grep -q "F0RT1KA-HARDENING: Tailscale block" /etc/hosts 2>/dev/null; then
        log_msg "SUCCESS" "Tailscale domains blocked in /etc/hosts"
    else
        log_msg "WARNING" "Tailscale domains NOT blocked in /etc/hosts"
    fi

    if command_exists iptables; then
        if iptables -L F0RT1KA_BLOCK_RAT &>/dev/null; then
            log_msg "SUCCESS" "iptables rules active for Tailscale port blocking"
        else
            log_msg "WARNING" "iptables rules NOT active for Tailscale port blocking"
        fi
    fi
}

# ============================================================
# 2. Harden SSH Configuration (M1042 - Disable or Remove Feature)
# ============================================================

apply_ssh_hardening() {
    log_msg "INFO" "--- Hardening SSH configuration (M1042, M1031) ---"

    local sshd_config="/etc/ssh/sshd_config"
    local hardening_config="/etc/ssh/sshd_config.d/99-f0rt1ka-hardening.conf"

    if [[ ! -f "$sshd_config" ]]; then
        log_msg "WARNING" "SSH server not installed - skipping SSH hardening"
        return 0
    fi

    backup_file "$sshd_config"

    # Create a drop-in configuration file for hardening
    mkdir -p /etc/ssh/sshd_config.d

    if [[ ! -f "$hardening_config" ]]; then
        cat > "$hardening_config" <<'SSHEOF'
# F0RT1KA Hardening - SSH Configuration
# Test ID: eafce2fc-75fd-4c62-92dc-32cabe5cf206
# Mitigations: M1042, M1031, M1035

# Disable root login
PermitRootLogin no

# Disable password authentication (require key-based auth)
PasswordAuthentication no

# Disable empty passwords
PermitEmptyPasswords no

# Limit authentication attempts
MaxAuthTries 3

# Set login grace time
LoginGraceTime 30

# Disable X11 forwarding (reduces attack surface)
X11Forwarding no

# Disable TCP forwarding to prevent tunnel abuse
AllowTcpForwarding no

# Disable agent forwarding
AllowAgentForwarding no

# Disable gateway ports
GatewayPorts no

# Disable tunnel devices
PermitTunnel no

# Set strict modes for file permissions
StrictModes yes

# Use only strong ciphers
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr

# Use only strong MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Use only strong key exchange
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org

# Enable verbose logging for forensics
LogLevel VERBOSE

# Set maximum sessions
MaxSessions 3

# Set client alive interval for idle timeout
ClientAliveInterval 300
ClientAliveCountMax 2
SSHEOF
        log_msg "SUCCESS" "SSH hardening configuration written to $hardening_config"

        # Verify sshd config is valid before restarting
        if sshd -t 2>/dev/null; then
            # Restart SSH service to apply changes
            if systemctl is-active sshd &>/dev/null; then
                systemctl restart sshd
                log_msg "SUCCESS" "SSH service restarted with hardened configuration"
            elif systemctl is-active ssh &>/dev/null; then
                systemctl restart ssh
                log_msg "SUCCESS" "SSH service restarted with hardened configuration"
            fi
        else
            log_msg "ERROR" "SSH configuration validation failed - reverting"
            rm -f "$hardening_config"
            return 1
        fi
    else
        log_msg "INFO" "SSH hardening configuration already in place"
    fi
}

undo_ssh_hardening() {
    log_msg "INFO" "--- Reverting SSH hardening ---"

    local hardening_config="/etc/ssh/sshd_config.d/99-f0rt1ka-hardening.conf"

    if [[ -f "$hardening_config" ]]; then
        rm -f "$hardening_config"
        log_msg "SUCCESS" "SSH hardening configuration removed"

        # Restart SSH to apply
        if systemctl is-active sshd &>/dev/null; then
            systemctl restart sshd
        elif systemctl is-active ssh &>/dev/null; then
            systemctl restart ssh
        fi
        log_msg "SUCCESS" "SSH service restarted with default configuration"
    else
        log_msg "INFO" "No SSH hardening configuration found to revert"
    fi
}

check_ssh_hardening() {
    log_msg "CHECK" "--- SSH Hardening Status ---"

    local hardening_config="/etc/ssh/sshd_config.d/99-f0rt1ka-hardening.conf"

    if [[ -f "$hardening_config" ]]; then
        log_msg "SUCCESS" "SSH hardening drop-in configuration present"
    else
        log_msg "WARNING" "SSH hardening drop-in configuration NOT present"
    fi

    # Check key settings from effective config
    if command_exists sshd; then
        local effective
        effective="$(sshd -T 2>/dev/null)" || true

        if echo "$effective" | grep -qi "permitrootlogin no"; then
            log_msg "SUCCESS" "Root login disabled"
        else
            log_msg "WARNING" "Root login NOT disabled"
        fi

        if echo "$effective" | grep -qi "passwordauthentication no"; then
            log_msg "SUCCESS" "Password authentication disabled"
        else
            log_msg "WARNING" "Password authentication NOT disabled"
        fi

        if echo "$effective" | grep -qi "allowtcpforwarding no"; then
            log_msg "SUCCESS" "TCP forwarding disabled"
        else
            log_msg "WARNING" "TCP forwarding NOT disabled"
        fi

        if echo "$effective" | grep -qi "permittunnel no"; then
            log_msg "SUCCESS" "Tunnel devices disabled"
        else
            log_msg "WARNING" "Tunnel devices NOT disabled"
        fi
    fi
}

# ============================================================
# 3. Restrict Unauthorized Software Installation (M1038)
# ============================================================

apply_software_restriction() {
    log_msg "INFO" "--- Restricting unauthorized software installation (M1038) ---"

    # Prevent Tailscale package installation via package manager
    # APT-based systems
    if [[ -d /etc/apt/preferences.d ]]; then
        local apt_pin="/etc/apt/preferences.d/f0rt1ka-block-rat.pref"
        if [[ ! -f "$apt_pin" ]]; then
            cat > "$apt_pin" <<'APTEOF'
# F0RT1KA Hardening - Block unauthorized remote access tools
# Test ID: eafce2fc-75fd-4c62-92dc-32cabe5cf206
Package: tailscale
Pin: origin *
Pin-Priority: -1

Package: anydesk
Pin: origin *
Pin-Priority: -1

Package: teamviewer
Pin: origin *
Pin-Priority: -1

Package: rustdesk
Pin: origin *
Pin-Priority: -1
APTEOF
            log_msg "SUCCESS" "APT pinning configured to block remote access tool packages"
        else
            log_msg "INFO" "APT pinning already configured"
        fi

        # Remove Tailscale APT repository if present
        if [[ -f /etc/apt/sources.list.d/tailscale.list ]]; then
            backup_file /etc/apt/sources.list.d/tailscale.list
            rm -f /etc/apt/sources.list.d/tailscale.list
            log_msg "SUCCESS" "Tailscale APT repository removed"
        fi
    fi

    # YUM/DNF-based systems
    if [[ -d /etc/yum.repos.d ]]; then
        local yum_exclude="/etc/yum.repos.d/f0rt1ka-block-rat.repo"
        if [[ ! -f "$yum_exclude" ]]; then
            cat > "$yum_exclude" <<'YUMEOF'
# F0RT1KA Hardening - Block unauthorized remote access tools
[f0rt1ka-block]
name=F0RT1KA Block Unauthorized RAT Packages
enabled=0
exclude=tailscale anydesk teamviewer rustdesk
YUMEOF
            # Add exclude to all enabled repos
            if command_exists dnf; then
                log_msg "INFO" "For DNF: Add 'excludepkgs=tailscale,anydesk,teamviewer,rustdesk' to /etc/dnf/dnf.conf"
            fi
            log_msg "SUCCESS" "YUM/DNF exclusion hint configured"
        fi

        # Remove Tailscale YUM repo if present
        if [[ -f /etc/yum.repos.d/tailscale.repo ]]; then
            backup_file /etc/yum.repos.d/tailscale.repo
            rm -f /etc/yum.repos.d/tailscale.repo
            log_msg "SUCCESS" "Tailscale YUM repository removed"
        fi
    fi

    # Disable and mask Tailscale service if installed
    if systemctl list-unit-files tailscaled.service &>/dev/null 2>&1; then
        systemctl stop tailscaled 2>/dev/null || true
        systemctl disable tailscaled 2>/dev/null || true
        systemctl mask tailscaled 2>/dev/null || true
        log_msg "SUCCESS" "Tailscale service stopped, disabled, and masked"
    fi

    # Restrict /tmp and /var/tmp with noexec mount option if not already set
    if mount | grep -q "on /tmp " && ! mount | grep "on /tmp " | grep -q "noexec"; then
        log_msg "WARNING" "/tmp is not mounted with noexec - consider adding 'noexec' mount option"
        log_msg "INFO" "Add to /etc/fstab: tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0"
    else
        log_msg "INFO" "/tmp noexec status checked"
    fi
}

undo_software_restriction() {
    log_msg "INFO" "--- Reverting software installation restrictions ---"

    # Remove APT pinning
    local apt_pin="/etc/apt/preferences.d/f0rt1ka-block-rat.pref"
    if [[ -f "$apt_pin" ]]; then
        rm -f "$apt_pin"
        log_msg "SUCCESS" "APT pinning for remote access tools removed"
    fi

    # Remove YUM exclusion file
    local yum_exclude="/etc/yum.repos.d/f0rt1ka-block-rat.repo"
    if [[ -f "$yum_exclude" ]]; then
        rm -f "$yum_exclude"
        log_msg "SUCCESS" "YUM/DNF exclusion file removed"
    fi

    # Unmask Tailscale service if masked by this script
    if systemctl is-enabled tailscaled 2>/dev/null | grep -q "masked"; then
        systemctl unmask tailscaled 2>/dev/null || true
        log_msg "SUCCESS" "Tailscale service unmasked"
    fi
}

check_software_restriction() {
    log_msg "CHECK" "--- Software Installation Restriction Status ---"

    if [[ -f /etc/apt/preferences.d/f0rt1ka-block-rat.pref ]]; then
        log_msg "SUCCESS" "APT pinning active for remote access tools"
    else
        log_msg "WARNING" "APT pinning NOT configured for remote access tools"
    fi

    if command_exists tailscale; then
        log_msg "WARNING" "Tailscale CLI is installed on this system"
    else
        log_msg "SUCCESS" "Tailscale CLI not found"
    fi

    if systemctl is-active tailscaled &>/dev/null; then
        log_msg "WARNING" "Tailscale service is RUNNING"
    elif systemctl is-enabled tailscaled 2>/dev/null | grep -q "masked"; then
        log_msg "SUCCESS" "Tailscale service is masked"
    else
        log_msg "INFO" "Tailscale service not installed or not active"
    fi
}

# ============================================================
# 4. Enable Security Auditing (M1047 - Audit)
# ============================================================

apply_audit_rules() {
    log_msg "INFO" "--- Configuring security audit rules (M1047) ---"

    if ! command_exists auditctl; then
        log_msg "WARNING" "auditd not installed - install with: apt install auditd (Debian) or yum install audit (RHEL)"
        return 0
    fi

    local audit_rules="/etc/audit/rules.d/f0rt1ka-hardening.rules"

    if [[ ! -f "$audit_rules" ]]; then
        cat > "$audit_rules" <<'AUDITEOF'
# F0RT1KA Hardening - Audit Rules
# Test ID: eafce2fc-75fd-4c62-92dc-32cabe5cf206
# Techniques: T1105, T1219, T1543.003, T1021.004, T1041

# Monitor service creation and modification (T1543.003)
-w /etc/systemd/system/ -p wa -k f0rt1ka_service_creation
-w /usr/lib/systemd/system/ -p wa -k f0rt1ka_service_creation
-w /etc/init.d/ -p wa -k f0rt1ka_service_creation

# Monitor SSH configuration changes (T1021.004)
-w /etc/ssh/sshd_config -p wa -k f0rt1ka_ssh_config
-w /etc/ssh/sshd_config.d/ -p wa -k f0rt1ka_ssh_config
-w /etc/ssh/authorized_keys -p wa -k f0rt1ka_ssh_keys

# Monitor user authorized_keys files (T1021.004)
-w /root/.ssh/ -p wa -k f0rt1ka_ssh_keys
-w /home/ -p wa -k f0rt1ka_ssh_keys

# Monitor firewall rule changes (T1562.004)
-w /etc/iptables/ -p wa -k f0rt1ka_firewall
-w /etc/nftables.conf -p wa -k f0rt1ka_firewall
-w /etc/ufw/ -p wa -k f0rt1ka_firewall

# Monitor software installation (T1105, T1219)
-w /usr/bin/ -p wa -k f0rt1ka_binary_install
-w /usr/local/bin/ -p wa -k f0rt1ka_binary_install
-w /opt/ -p wa -k f0rt1ka_binary_install

# Monitor archive creation tools (T1560.001, T1041)
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/zip -k f0rt1ka_archive
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/tar -k f0rt1ka_archive
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/gzip -k f0rt1ka_archive
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/7z -k f0rt1ka_archive

# Monitor package manager usage (T1105)
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/apt -k f0rt1ka_package_mgr
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/apt-get -k f0rt1ka_package_mgr
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/dpkg -k f0rt1ka_package_mgr
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/yum -k f0rt1ka_package_mgr
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/dnf -k f0rt1ka_package_mgr
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/rpm -k f0rt1ka_package_mgr

# Monitor curl/wget for tool downloads (T1105)
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -k f0rt1ka_download
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/wget -k f0rt1ka_download

# Monitor Tailscale binary execution (T1219)
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/tailscale -k f0rt1ka_rat
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/tailscaled -k f0rt1ka_rat
-a always,exit -F arch=b64 -S execve -F path=/usr/local/bin/tailscale -k f0rt1ka_rat
AUDITEOF

        # Reload audit rules
        augenrules --load 2>/dev/null || auditctl -R "$audit_rules" 2>/dev/null || true
        log_msg "SUCCESS" "Audit rules configured and loaded"
    else
        log_msg "INFO" "Audit rules already configured"
    fi

    # Ensure auditd is enabled and running
    if systemctl is-active auditd &>/dev/null; then
        log_msg "SUCCESS" "auditd service is running"
    else
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null || true
        log_msg "SUCCESS" "auditd service enabled and started"
    fi
}

undo_audit_rules() {
    log_msg "INFO" "--- Reverting audit rules ---"

    local audit_rules="/etc/audit/rules.d/f0rt1ka-hardening.rules"

    if [[ -f "$audit_rules" ]]; then
        rm -f "$audit_rules"
        augenrules --load 2>/dev/null || true
        log_msg "SUCCESS" "F0RT1KA audit rules removed and rules reloaded"
    else
        log_msg "INFO" "No F0RT1KA audit rules found to remove"
    fi
}

check_audit_rules() {
    log_msg "CHECK" "--- Audit Rules Status ---"

    if [[ -f /etc/audit/rules.d/f0rt1ka-hardening.rules ]]; then
        log_msg "SUCCESS" "F0RT1KA audit rules file present"
    else
        log_msg "WARNING" "F0RT1KA audit rules file NOT present"
    fi

    if command_exists auditctl; then
        local rule_count
        rule_count="$(auditctl -l 2>/dev/null | grep -c "f0rt1ka" || true)"
        if [[ "$rule_count" -gt 0 ]]; then
            log_msg "SUCCESS" "$rule_count F0RT1KA audit rules active"
        else
            log_msg "WARNING" "No F0RT1KA audit rules currently loaded"
        fi
    else
        log_msg "WARNING" "auditctl not available - cannot check active rules"
    fi

    if systemctl is-active auditd &>/dev/null; then
        log_msg "SUCCESS" "auditd service is running"
    else
        log_msg "WARNING" "auditd service is NOT running"
    fi
}

# ============================================================
# 5. Network Egress Filtering (M1031 - Network Intrusion Prevention)
# ============================================================

apply_egress_filtering() {
    log_msg "INFO" "--- Configuring egress filtering (M1031) ---"

    if ! command_exists iptables; then
        log_msg "WARNING" "iptables not found - skipping egress filtering"
        return 0
    fi

    local chain_name="F0RT1KA_EGRESS"

    if ! iptables -L "$chain_name" &>/dev/null; then
        iptables -N "$chain_name" 2>/dev/null || true

        # Block common remote access tool ports (outbound)
        # AnyDesk
        iptables -A "$chain_name" -p tcp --dport 6568 -j DROP -m comment --comment "Block AnyDesk"
        iptables -A "$chain_name" -p tcp --dport 7070 -j DROP -m comment --comment "Block AnyDesk relay"

        # TeamViewer
        iptables -A "$chain_name" -p tcp --dport 5938 -j DROP -m comment --comment "Block TeamViewer"

        # RustDesk
        iptables -A "$chain_name" -p tcp --dport 21115 -j DROP -m comment --comment "Block RustDesk signal"
        iptables -A "$chain_name" -p tcp --dport 21116 -j DROP -m comment --comment "Block RustDesk relay"
        iptables -A "$chain_name" -p tcp --dport 21117 -j DROP -m comment --comment "Block RustDesk relay"
        iptables -A "$chain_name" -p tcp --dport 21118 -j DROP -m comment --comment "Block RustDesk websocket"
        iptables -A "$chain_name" -p tcp --dport 21119 -j DROP -m comment --comment "Block RustDesk websocket"

        # Tailscale WireGuard
        iptables -A "$chain_name" -p udp --dport 41641 -j DROP -m comment --comment "Block Tailscale WireGuard"

        # Insert into OUTPUT chain
        iptables -I OUTPUT -j "$chain_name" 2>/dev/null || true
        log_msg "SUCCESS" "Egress filtering rules added for remote access tool ports"
    else
        log_msg "INFO" "Egress filtering chain $chain_name already exists"
    fi

    # Save rules for persistence across reboots
    if command_exists iptables-save; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            log_msg "SUCCESS" "iptables rules saved for persistence"
        elif [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            log_msg "SUCCESS" "iptables rules saved for persistence"
        fi
    fi
}

undo_egress_filtering() {
    log_msg "INFO" "--- Reverting egress filtering ---"

    if command_exists iptables; then
        local chain_name="F0RT1KA_EGRESS"
        if iptables -L "$chain_name" &>/dev/null; then
            iptables -D OUTPUT -j "$chain_name" 2>/dev/null || true
            iptables -F "$chain_name" 2>/dev/null || true
            iptables -X "$chain_name" 2>/dev/null || true
            log_msg "SUCCESS" "Egress filtering chain $chain_name removed"
        fi
    fi
}

check_egress_filtering() {
    log_msg "CHECK" "--- Egress Filtering Status ---"

    if command_exists iptables; then
        if iptables -L F0RT1KA_EGRESS &>/dev/null; then
            local rule_count
            rule_count="$(iptables -L F0RT1KA_EGRESS --line-numbers 2>/dev/null | grep -c "DROP" || true)"
            log_msg "SUCCESS" "Egress filtering active with $rule_count block rules"
        else
            log_msg "WARNING" "Egress filtering chain NOT active"
        fi
    else
        log_msg "WARNING" "iptables not available"
    fi
}

# ============================================================
# 6. Data Exfiltration Prevention (M1057 - Data Loss Prevention)
# ============================================================

apply_dlp_controls() {
    log_msg "INFO" "--- Configuring data exfiltration prevention controls ---"

    # Restrict archive creation tools for non-root users (optional, aggressive)
    # This creates a wrapper that logs archive creation activity
    local wrapper_dir="/usr/local/libexec/f0rt1ka"
    mkdir -p "$wrapper_dir"

    # Create a logging wrapper for zip
    if command_exists zip && [[ ! -f "$wrapper_dir/zip-monitor.sh" ]]; then
        cat > "$wrapper_dir/zip-monitor.sh" <<'WRAPEOF'
#!/usr/bin/env bash
# F0RT1KA DLP Monitor - logs archive creation activity
logger -t "f0rt1ka-dlp" -p auth.warning "Archive creation detected: user=$(whoami) pid=$$ ppid=$PPID cmd=zip args=$*"
exec /usr/bin/zip.real "$@"
WRAPEOF
        chmod 755 "$wrapper_dir/zip-monitor.sh"
        log_msg "SUCCESS" "Archive creation monitoring wrapper created"
        log_msg "INFO" "To activate: mv /usr/bin/zip /usr/bin/zip.real && ln -s $wrapper_dir/zip-monitor.sh /usr/bin/zip"
        log_msg "WARNING" "Archive monitoring wrapper created but NOT activated (manual step required)"
    fi

    # Ensure rsyslog or journald captures auth.warning for DLP alerts
    if [[ -d /etc/rsyslog.d ]]; then
        local dlp_log="/etc/rsyslog.d/f0rt1ka-dlp.conf"
        if [[ ! -f "$dlp_log" ]]; then
            echo ':programname, isequal, "f0rt1ka-dlp"  /var/log/f0rt1ka-dlp.log' > "$dlp_log"
            systemctl restart rsyslog 2>/dev/null || true
            log_msg "SUCCESS" "DLP logging configured to /var/log/f0rt1ka-dlp.log"
        fi
    fi
}

undo_dlp_controls() {
    log_msg "INFO" "--- Reverting DLP controls ---"

    rm -rf /usr/local/libexec/f0rt1ka 2>/dev/null || true
    rm -f /etc/rsyslog.d/f0rt1ka-dlp.conf 2>/dev/null || true
    systemctl restart rsyslog 2>/dev/null || true
    log_msg "SUCCESS" "DLP monitoring artifacts removed"
}

check_dlp_controls() {
    log_msg "CHECK" "--- Data Exfiltration Prevention Status ---"

    if [[ -f /usr/local/libexec/f0rt1ka/zip-monitor.sh ]]; then
        log_msg "SUCCESS" "Archive monitoring wrapper present"
    else
        log_msg "WARNING" "Archive monitoring wrapper NOT present"
    fi

    if [[ -f /etc/rsyslog.d/f0rt1ka-dlp.conf ]]; then
        log_msg "SUCCESS" "DLP logging configured"
    else
        log_msg "WARNING" "DLP logging NOT configured"
    fi
}

# ============================================================
# Main Execution
# ============================================================

main() {
    check_root

    echo ""
    echo "============================================================"
    echo " F0RT1KA Linux Hardening Script"
    echo " Test: Tailscale Remote Access and Data Exfiltration"
    echo " ID:   eafce2fc-75fd-4c62-92dc-32cabe5cf206"
    echo "============================================================"
    echo ""

    if $CHECK_MODE; then
        log_msg "INFO" "Running in AUDIT mode - no changes will be made"
        echo ""
        check_tailscale_block
        echo ""
        check_ssh_hardening
        echo ""
        check_software_restriction
        echo ""
        check_audit_rules
        echo ""
        check_egress_filtering
        echo ""
        check_dlp_controls
        echo ""
        log_msg "INFO" "Audit complete"

    elif $UNDO_MODE; then
        log_msg "WARNING" "Running in UNDO mode - reverting all hardening changes"
        echo ""
        undo_tailscale_block
        undo_ssh_hardening
        undo_software_restriction
        undo_audit_rules
        undo_egress_filtering
        undo_dlp_controls
        echo ""
        log_msg "SUCCESS" "All hardening changes reverted"

    else
        log_msg "INFO" "Running in APPLY mode - hardening system"
        echo ""
        apply_tailscale_block
        echo ""
        apply_ssh_hardening
        echo ""
        apply_software_restriction
        echo ""
        apply_audit_rules
        echo ""
        apply_egress_filtering
        echo ""
        apply_dlp_controls
        echo ""
        log_msg "SUCCESS" "All hardening measures applied"
        log_msg "INFO" "Backups stored in: $BACKUP_DIR"
        log_msg "INFO" "Log file: $LOG_FILE"
        log_msg "INFO" "To revert: sudo $SCRIPT_NAME --undo"
        log_msg "INFO" "To audit:  sudo $SCRIPT_NAME --check"
    fi

    echo ""
    echo "============================================================"
    echo " Complete"
    echo "============================================================"
}

main "$@"
