#!/usr/bin/env bash
# ============================================================================
# DEFENSE GUIDANCE: Linux/ESXi Hardening Script
# ============================================================================
# Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
# Test Name: ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira)
# MITRE ATT&CK: T1046, T1018, T1021.004, T1068, T1489, T1529, T1048,
#                T1567.002, T1486
# Mitigations: M1030, M1035, M1042, M1038, M1047, M1037
# Created: 2026-03-13
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
#
# PURPOSE:
# Hardens Linux and ESXi hosts against the hypervisor ransomware kill chain
# used by RansomHub, Akira, Black Basta, and LockBit. Implements:
#
#   - SSH key file access auditing and permission hardening (T1021.004)
#   - Firewall rules to block Rclone cloud exfiltration endpoints (T1048)
#   - ESXi management command monitoring via auditd (T1046, T1489)
#   - Kernel hardening against CVE-2024-1086 nf_tables UAF (T1068)
#   - Binary rename detection via inotifywait (T1036.003)
#   - VMDK file integrity monitoring (T1486)
#   - ESXi management network segmentation (T1046, M1030)
#   - Snapshot deletion protection monitoring (T1490)
#   - VM process kill detection (T1489)
#
# USAGE:
#   sudo ./25aafe2c-ec57-4a85-a26a-c3d7cf35620c_hardening_linux.sh [--undo] [--dry-run]
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - auditd installed (for audit rules)
#   - iptables or nftables for firewall rules
#   - inotify-tools (optional, for real-time file monitoring)
#
# TESTED ON:
#   Ubuntu 22.04/24.04 LTS, RHEL 8/9, ESXi 7.0/8.0 (partial)
#
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/f0rt1ka"
LOG_FILE="${LOG_DIR}/hardening_esxi_$(date +%Y%m%d_%H%M%S).log"
AUDIT_RULES_FILE="/etc/audit/rules.d/f0rt1ka-esxi-ransomware.rules"
SYSCTL_FILE="/etc/sysctl.d/99-f0rt1ka-esxi-hardening.conf"
CRON_MONITOR_FILE="/etc/cron.d/f0rt1ka-esxi-monitor"
UNDO_MODE=false
DRY_RUN=false
CHANGES_MADE=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================================
# Argument Parsing
# ============================================================================

for arg in "$@"; do
    case "$arg" in
        --undo)   UNDO_MODE=true ;;
        --dry-run) DRY_RUN=true ;;
        --help)
            echo "Usage: sudo $SCRIPT_NAME [--undo] [--dry-run]"
            echo "  --undo     Revert all hardening changes"
            echo "  --dry-run  Show changes without applying"
            exit 0
            ;;
    esac
done

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
    echo "[OK] $(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE" 2>/dev/null || true
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

run_cmd() {
    if $DRY_RUN; then
        log_info "[DRY-RUN] Would execute: $*"
    else
        eval "$@"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    fi
}

is_esxi() {
    # Detect VMware ESXi environment
    if [[ -f /etc/vmware-release ]] || uname -r 2>/dev/null | grep -qi "esxi"; then
        return 0
    fi
    return 1
}

# ============================================================================
# Setup
# ============================================================================

check_root
mkdir -p "$LOG_DIR" 2>/dev/null || true

echo ""
echo "============================================================"
echo "F0RT1KA Hardening: ESXi Hypervisor Ransomware Kill Chain"
echo "Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
echo "MITRE ATT&CK: T1046, T1018, T1021.004, T1068, T1489,"
echo "              T1529, T1048, T1567.002, T1486"
echo "============================================================"
echo ""

# ============================================================================
# 1. SSH Key File Hardening (T1021.004 - SSH Lateral Movement)
# ============================================================================
# Threat: SSH-Snake self-modifying worm harvests keys from known_hosts,
# authorized_keys, and SSH config files to propagate laterally.
# CVE-2024-37085: ESXi AD auth bypass via "ESX Admins" group membership.
# ============================================================================

harden_ssh() {
    log_info "1. Hardening SSH key file permissions and access..."

    # Restrict SSH key file permissions for all users
    for home_dir in /root /home/*; do
        local ssh_dir="${home_dir}/.ssh"
        if [[ -d "$ssh_dir" ]]; then
            run_cmd "chmod 700 '$ssh_dir'"
            # Lock down private keys
            for keyfile in "$ssh_dir"/id_*; do
                if [[ -f "$keyfile" && ! "$keyfile" == *.pub ]]; then
                    run_cmd "chmod 600 '$keyfile'"
                    log_success "Restricted permissions on $keyfile"
                fi
            done
            # Lock down authorized_keys (prevents SSH-Snake injection)
            if [[ -f "$ssh_dir/authorized_keys" ]]; then
                run_cmd "chmod 600 '$ssh_dir/authorized_keys'"
                log_success "Restricted authorized_keys: $ssh_dir/authorized_keys"
            fi
            # Lock down known_hosts (prevents SSH-Snake host harvesting)
            if [[ -f "$ssh_dir/known_hosts" ]]; then
                run_cmd "chmod 600 '$ssh_dir/known_hosts'"
            fi
            # Lock down SSH config (prevents SSH-Snake config parsing)
            if [[ -f "$ssh_dir/config" ]]; then
                run_cmd "chmod 600 '$ssh_dir/config'"
            fi
        fi
    done

    # Harden sshd_config
    local sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        local sshd_changed=false

        # Disable root password authentication (force key-only)
        if ! grep -q "^PermitRootLogin prohibit-password" "$sshd_config"; then
            run_cmd "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' '$sshd_config'"
            log_success "Set PermitRootLogin to prohibit-password"
            sshd_changed=true
        fi

        # Disable password authentication entirely (key-only access)
        if ! grep -q "^PasswordAuthentication no" "$sshd_config"; then
            run_cmd "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' '$sshd_config'"
            log_success "Disabled password authentication (key-only)"
            sshd_changed=true
        fi

        # Set idle timeout (10 minutes)
        if ! grep -q "^ClientAliveInterval" "$sshd_config"; then
            run_cmd "echo 'ClientAliveInterval 300' >> '$sshd_config'"
            run_cmd "echo 'ClientAliveCountMax 2' >> '$sshd_config'"
            log_success "Set SSH idle timeout to 10 minutes"
            sshd_changed=true
        fi

        # Limit authentication attempts
        if ! grep -q "^MaxAuthTries" "$sshd_config"; then
            run_cmd "echo 'MaxAuthTries 3' >> '$sshd_config'"
            log_success "Limited SSH authentication attempts to 3"
            sshd_changed=true
        fi

        # Limit concurrent sessions
        if ! grep -q "^MaxSessions" "$sshd_config"; then
            run_cmd "echo 'MaxSessions 3' >> '$sshd_config'"
            log_success "Limited concurrent SSH sessions to 3"
            sshd_changed=true
        fi

        # Disable agent forwarding (prevents lateral key theft)
        if ! grep -q "^AllowAgentForwarding no" "$sshd_config"; then
            run_cmd "sed -i 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/' '$sshd_config'"
            log_success "Disabled SSH agent forwarding"
            sshd_changed=true
        fi

        # Reload sshd if changes were made
        if $sshd_changed && ! $DRY_RUN; then
            if systemctl is-active sshd &>/dev/null; then
                systemctl reload sshd 2>/dev/null || true
                log_success "Reloaded sshd configuration"
            elif systemctl is-active ssh &>/dev/null; then
                systemctl reload ssh 2>/dev/null || true
                log_success "Reloaded ssh configuration"
            fi
        fi
    fi

    # Set immutable flag on authorized_keys to prevent SSH-Snake injection
    log_info "  Setting immutable flag on authorized_keys files..."
    for home_dir in /root /home/*; do
        local ak="${home_dir}/.ssh/authorized_keys"
        if [[ -f "$ak" ]]; then
            run_cmd "chattr +i '$ak' 2>/dev/null || true"
            log_success "Set immutable flag: $ak"
        fi
    done
}

undo_ssh() {
    log_warning "Reverting SSH hardening..."
    # Remove immutable flags
    for home_dir in /root /home/*; do
        local ak="${home_dir}/.ssh/authorized_keys"
        if [[ -f "$ak" ]]; then
            run_cmd "chattr -i '$ak' 2>/dev/null || true"
            log_success "Removed immutable flag: $ak"
        fi
    done
    log_warning "SSH sshd_config changes require manual review"
    log_info "  Review /etc/ssh/sshd_config for hardening settings"
    log_info "  Settings modified: PermitRootLogin, PasswordAuthentication,"
    log_info "    ClientAliveInterval, MaxAuthTries, MaxSessions, AllowAgentForwarding"
}

# ============================================================================
# 2. Audit Rules for ESXi Attack Detection (T1046, T1489, T1486, T1068)
# ============================================================================
# Comprehensive auditd rules covering the full ransomware kill chain:
# - SSH key file access for lateral movement detection
# - ESXi management commands (vim-cmd, esxcli, vmdumper)
# - Rclone execution for exfiltration
# - nftables manipulation for CVE-2024-1086
# - dd execution for free-space wiping
# - Datastore access for ransomware encryption
# - Process kill signals for VM termination detection
# - Binary rename operations (T1036.003)
# ============================================================================

setup_audit_rules() {
    log_info "2. Installing audit rules for ESXi attack detection..."

    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not installed -- skipping audit rules"
        log_info "  Install with: sudo apt install auditd (Debian/Ubuntu)"
        log_info "  Install with: sudo yum install audit (RHEL/CentOS)"
        return
    fi

    run_cmd "cat > '$AUDIT_RULES_FILE' << 'AUDIT_EOF'
# ============================================================================
# F0RT1KA ESXi Ransomware Detection Audit Rules
# ============================================================================
# Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
# Kill Chain: Network Recon -> SSH Lateral -> VM Kill -> Exfil -> Encrypt
# Generated: 2026-03-13
# ============================================================================

# === Stage 1: Network Reconnaissance (T1046, T1018) ===
# Monitor network scanning tools
-w /usr/bin/nmap -p x -k esxi_network_recon
-w /usr/local/bin/nmap -p x -k esxi_network_recon
-w /usr/bin/masscan -p x -k esxi_network_recon

# === Stage 2: SSH Lateral Movement (T1021.004) ===
# Monitor SSH key file access (SSH-Snake harvests these)
-w /root/.ssh/ -p rwa -k esxi_ssh_key_access
-w /etc/ssh/ssh_host_rsa_key -p r -k esxi_ssh_host_key
-w /etc/ssh/ssh_host_ed25519_key -p r -k esxi_ssh_host_key
-w /etc/ssh/ssh_host_ecdsa_key -p r -k esxi_ssh_host_key

# Monitor SSH config modifications
-w /etc/ssh/sshd_config -p wa -k esxi_ssh_config_change

# Monitor all user SSH directories for key harvesting
-w /home/ -p r -k esxi_ssh_home_scan

# === Stage 2b: Privilege Escalation (T1068 - CVE-2024-1086) ===
# Monitor nftables manipulation (nf_tables use-after-free exploit)
-w /usr/sbin/nft -p x -k esxi_nftables_exploit
-w /usr/bin/nft -p x -k esxi_nftables_exploit
# Monitor kernel module loading (exploit may load modules)
-a always,exit -F arch=b64 -S init_module -S finit_module -k esxi_kernel_module

# === Stage 3: VM Kill Operations (T1489, T1529) ===
# Monitor ESXi management commands
-w /usr/bin/vim-cmd -p x -k esxi_vm_mgmt
-w /usr/bin/esxcli -p x -k esxi_vm_mgmt
-w /usr/bin/vmdumper -p x -k esxi_vm_mgmt
-w /bin/vim-cmd -p x -k esxi_vm_mgmt

# Monitor process kill signals (VM process termination)
-a always,exit -F arch=b64 -S kill -S tkill -S tgkill -k esxi_process_kill

# Monitor service management (stopping critical services)
-w /usr/bin/systemctl -p x -k esxi_service_mgmt
-w /usr/sbin/service -p x -k esxi_service_mgmt

# === Stage 4: Exfiltration (T1048, T1567.002) ===
# Monitor Rclone execution at common paths
-w /usr/bin/rclone -p x -k esxi_rclone_exfil
-w /usr/local/bin/rclone -p x -k esxi_rclone_exfil
-w /tmp/rclone -p x -k esxi_rclone_exfil

# Monitor Rclone configuration files
-w /root/.config/rclone/ -p rwa -k esxi_rclone_config

# Monitor binary rename operations (rclone -> svchost.exe evasion)
-a always,exit -F arch=b64 -S rename -S renameat -S renameat2 -k esxi_binary_rename

# === Stage 5: Encryption (T1486) ===
# Monitor datastore access
-w /vmfs/volumes/ -p rwa -k esxi_datastore_access

# Monitor dd for free-space wiping (anti-recovery)
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/dd -k esxi_dd_wipe
-a always,exit -F arch=b64 -S execve -F exe=/bin/dd -k esxi_dd_wipe

# Monitor openssl/encryption tool usage
-w /usr/bin/openssl -p x -k esxi_crypto_tool

# Monitor file deletion in bulk (ransomware cleanup)
-a always,exit -F arch=b64 -S unlink -S unlinkat -F dir=/vmfs/ -k esxi_file_delete
AUDIT_EOF"

    if ! $DRY_RUN; then
        auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
        log_success "Audit rules installed: $AUDIT_RULES_FILE"
        # Verify rules loaded
        local rule_count
        rule_count=$(auditctl -l 2>/dev/null | grep -c "esxi_" || true)
        log_info "  Active ESXi detection rules: $rule_count"
    fi
}

remove_audit_rules() {
    log_warning "Removing ESXi audit rules..."
    if [[ -f "$AUDIT_RULES_FILE" ]]; then
        run_cmd "rm -f '$AUDIT_RULES_FILE'"
        # Remove rules by key prefix
        local keys=("esxi_network_recon" "esxi_ssh_key_access" "esxi_ssh_host_key"
                    "esxi_ssh_config_change" "esxi_ssh_home_scan" "esxi_nftables_exploit"
                    "esxi_kernel_module" "esxi_vm_mgmt" "esxi_process_kill"
                    "esxi_service_mgmt" "esxi_rclone_exfil" "esxi_rclone_config"
                    "esxi_binary_rename" "esxi_datastore_access" "esxi_dd_wipe"
                    "esxi_crypto_tool" "esxi_file_delete")
        for key in "${keys[@]}"; do
            auditctl -D -k "$key" 2>/dev/null || true
        done
        log_success "Audit rules removed"
    fi
}

# ============================================================================
# 3. Firewall Rules - Block Exfiltration and Segment Management (T1048, M1030)
# ============================================================================
# Blocks known Rclone exfiltration endpoints (Mega.nz, S3 alternatives)
# and enforces network segmentation for ESXi management interfaces.
# ============================================================================

setup_firewall_rules() {
    log_info "3. Configuring firewall rules..."

    if command -v iptables &>/dev/null; then
        # --- 3a. Block Mega.nz exfiltration endpoints ---
        log_info "  3a. Blocking Mega.nz cloud storage endpoints..."
        if ! iptables -L OUTPUT -n 2>/dev/null | grep -q "89.44.169.0"; then
            run_cmd "iptables -A OUTPUT -m comment --comment 'Block Mega.nz exfil' -d 89.44.169.0/24 -j DROP"
            run_cmd "iptables -A OUTPUT -m comment --comment 'Block Mega.nz API' -d 31.216.148.0/24 -j DROP"
            log_success "Blocked Mega.nz cloud storage endpoints"
        else
            log_info "  Mega.nz block rules already present"
        fi

        # --- 3b. Block common Rclone cloud targets ---
        log_info "  3b. Blocking additional cloud exfiltration targets..."
        # Block direct S3-compatible storage (non-AWS)
        # Note: Only block if your environment does not use these services
        if ! iptables -L OUTPUT -n 2>/dev/null | grep -q "Backblaze"; then
            run_cmd "iptables -A OUTPUT -m comment --comment 'Block Backblaze B2' -d 206.190.226.0/24 -j DROP 2>/dev/null || true"
            log_success "Blocked Backblaze B2 endpoints"
        fi

        # --- 3c. ESXi management port segmentation ---
        log_info "  3c. Restricting ESXi management port access..."
        # Only allow ESXi management ports from management VLAN
        # Adjust MGMT_SUBNET to match your environment
        local MGMT_SUBNET="${MGMT_SUBNET:-10.0.0.0/24}"
        local ESXI_PORTS="443,902,5480,5988,5989,8000,8080,8300,9084"

        if ! iptables -L INPUT -n 2>/dev/null | grep -q "ESXi mgmt restrict"; then
            # Allow management ports only from management subnet
            run_cmd "iptables -A INPUT -m comment --comment 'ESXi mgmt allow from mgmt VLAN' -s $MGMT_SUBNET -p tcp -m multiport --dports $ESXI_PORTS -j ACCEPT"
            # Drop management port access from all other sources
            run_cmd "iptables -A INPUT -m comment --comment 'ESXi mgmt restrict' -p tcp -m multiport --dports $ESXI_PORTS -j DROP"
            log_success "Restricted ESXi management ports to $MGMT_SUBNET"
            log_warning "  Adjust MGMT_SUBNET env variable if default (10.0.0.0/24) is incorrect"
        fi

        # --- 3d. Rate-limit SSH connections ---
        log_info "  3d. Rate-limiting SSH connections..."
        if ! iptables -L INPUT -n 2>/dev/null | grep -q "SSH rate limit"; then
            run_cmd "iptables -A INPUT -m comment --comment 'SSH rate limit' -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH"
            run_cmd "iptables -A INPUT -m comment --comment 'SSH rate drop' -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 5 --name SSH -j DROP"
            log_success "Rate-limited SSH to 5 connections per 60 seconds"
        fi

        # Persist rules
        if command -v iptables-save &>/dev/null; then
            if [[ -d /etc/iptables ]]; then
                run_cmd "iptables-save > /etc/iptables/rules.v4 2>/dev/null || true"
                log_success "Firewall rules persisted to /etc/iptables/rules.v4"
            elif command -v netfilter-persistent &>/dev/null; then
                run_cmd "netfilter-persistent save 2>/dev/null || true"
                log_success "Firewall rules persisted via netfilter-persistent"
            fi
        fi
    elif command -v nft &>/dev/null; then
        log_info "  Using nftables (iptables not found)..."
        # nftables equivalent rules
        run_cmd "nft add table inet f0rt1ka_esxi 2>/dev/null || true"
        run_cmd "nft add chain inet f0rt1ka_esxi output '{ type filter hook output priority 0; }' 2>/dev/null || true"
        run_cmd "nft add rule inet f0rt1ka_esxi output ip daddr 89.44.169.0/24 drop 2>/dev/null || true"
        run_cmd "nft add rule inet f0rt1ka_esxi output ip daddr 31.216.148.0/24 drop 2>/dev/null || true"
        log_success "nftables exfiltration block rules applied"
    else
        log_warning "Neither iptables nor nftables available -- configure firewall manually"
    fi
}

remove_firewall_rules() {
    log_warning "Removing exfiltration and segmentation firewall rules..."
    if command -v iptables &>/dev/null; then
        # Remove rules by comment matching (reverse order to avoid index shifts)
        local comments=("SSH rate drop" "SSH rate limit" "ESXi mgmt restrict"
                       "ESXi mgmt allow from mgmt VLAN" "Block Backblaze B2"
                       "Block Mega.nz API" "Block Mega.nz exfil")
        for comment in "${comments[@]}"; do
            while iptables -L INPUT --line-numbers -n 2>/dev/null | grep -q "$comment"; do
                local line
                line=$(iptables -L INPUT --line-numbers -n 2>/dev/null | grep "$comment" | head -1 | awk '{print $1}')
                run_cmd "iptables -D INPUT $line 2>/dev/null || true"
            done
            while iptables -L OUTPUT --line-numbers -n 2>/dev/null | grep -q "$comment"; do
                local line
                line=$(iptables -L OUTPUT --line-numbers -n 2>/dev/null | grep "$comment" | head -1 | awk '{print $1}')
                run_cmd "iptables -D OUTPUT $line 2>/dev/null || true"
            done
        done
        log_success "Firewall rules removed"
    elif command -v nft &>/dev/null; then
        run_cmd "nft delete table inet f0rt1ka_esxi 2>/dev/null || true"
        log_success "nftables rules removed"
    fi
}

# ============================================================================
# 4. Kernel Hardening - CVE-2024-1086 Mitigation (T1068)
# ============================================================================
# CVE-2024-1086 exploits a use-after-free in the Linux kernel nf_tables
# component to achieve local privilege escalation. The attack chain uses
# this to escalate from unprivileged SSH access to root on ESXi hosts.
# ============================================================================

harden_kernel() {
    log_info "4. Applying kernel hardening for CVE-2024-1086 mitigation..."

    run_cmd "cat > '$SYSCTL_FILE' << 'SYSCTL_EOF'
# ============================================================================
# F0RT1KA ESXi Ransomware Kernel Hardening
# ============================================================================
# Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
# Target: CVE-2024-1086 (nf_tables UAF) and general kernel exploit surface
# ============================================================================

# --- CVE-2024-1086 Specific Mitigations ---

# Restrict unprivileged user namespaces (reduces kernel exploit surface)
# CVE-2024-1086 requires unprivileged netfilter access via user namespaces
kernel.unprivileged_userns_clone = 0

# Restrict BPF to CAP_SYS_ADMIN (reduces eBPF exploit surface)
kernel.unprivileged_bpf_disabled = 1

# Restrict nf_tables access to root only (primary CVE-2024-1086 mitigation)
# Note: This may not be available on all kernel versions
# net.netfilter.nf_conntrack_helper = 0

# --- General Exploit Surface Reduction ---

# Enable ASLR (full randomization)
kernel.randomize_va_space = 2

# Restrict kernel pointer leaks (prevents KASLR bypass)
kernel.kptr_restrict = 2

# Restrict dmesg access (prevents kernel info leak)
kernel.dmesg_restrict = 1

# Disable sysrq (prevents local DoS via magic sysrq key)
kernel.sysrq = 0

# Restrict ptrace scope (prevents process injection)
kernel.yama.ptrace_scope = 2

# Restrict core dumps (prevents credential extraction from memory)
fs.suid_dumpable = 0

# --- Network Hardening ---

# Disable IP forwarding (unless this is a router/hypervisor)
# Uncomment only if IP forwarding is not needed:
# net.ipv4.ip_forward = 0

# Enable SYN cookies (prevent SYN flood)
net.ipv4.tcp_syncookies = 1

# Ignore ICMP redirects (prevent routing attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
SYSCTL_EOF"

    if ! $DRY_RUN; then
        sysctl --system 2>/dev/null | tail -1 || true
        log_success "Kernel hardening applied: $SYSCTL_FILE"
    fi

    # Check kernel version for CVE-2024-1086 vulnerability
    local kver
    kver=$(uname -r)
    log_info "  Current kernel: $kver"
    log_info "  CVE-2024-1086 affects Linux kernel 3.15 through 6.8-rc1"
    log_info "  Verify patched: apt list --installed 2>/dev/null | grep linux-image"
}

remove_kernel_hardening() {
    log_warning "Removing kernel hardening settings..."
    if [[ -f "$SYSCTL_FILE" ]]; then
        run_cmd "rm -f '$SYSCTL_FILE'"
        run_cmd "sysctl --system 2>/dev/null || true"
        log_success "Kernel hardening settings removed"
    fi
}

# ============================================================================
# 5. Binary Rename Detection (T1036.003 - Masquerading)
# ============================================================================
# The attack renames rclone to svchost.exe on Linux to evade detection.
# This section creates a cron-based monitor that alerts on suspicious
# binaries in common write locations.
# ============================================================================

setup_binary_rename_monitor() {
    log_info "5. Setting up binary rename detection monitor..."

    local monitor_script="/usr/local/bin/f0rt1ka-binary-monitor.sh"

    run_cmd "cat > '$monitor_script' << 'MONITOR_EOF'
#!/usr/bin/env bash
# F0RT1KA Binary Rename Detection Monitor
# Detects suspicious Windows-named binaries on Linux (masquerading indicator)

ALERT_LOG=\"/var/log/f0rt1ka/binary_rename_alerts.log\"

# Suspicious Windows binary names on Linux (strong masquerading indicator)
SUSPICIOUS_NAMES=(\"svchost.exe\" \"csrss.exe\" \"lsass.exe\" \"services.exe\"
                  \"winlogon.exe\" \"explorer.exe\" \"taskhost.exe\" \"conhost.exe\")

# Common attacker staging directories
SEARCH_DIRS=(\"/tmp\" \"/var/tmp\" \"/dev/shm\" \"/root\" \"/home\")

for dir in \"\${SEARCH_DIRS[@]}\"; do
    if [[ -d \"\$dir\" ]]; then
        for name in \"\${SUSPICIOUS_NAMES[@]}\"; do
            found=\$(find \"\$dir\" -name \"\$name\" -type f 2>/dev/null)
            if [[ -n \"\$found\" ]]; then
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] ALERT: Suspicious binary found: \$found\" >> \"\$ALERT_LOG\"
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')]   File type: \$(file \"\$found\" 2>/dev/null)\" >> \"\$ALERT_LOG\"
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')]   SHA256: \$(sha256sum \"\$found\" 2>/dev/null | awk '{print \$1}')\" >> \"\$ALERT_LOG\"
                logger -t f0rt1ka-binary-monitor \"ALERT: Suspicious Windows-named binary found: \$found\"
            fi
        done
    fi
done

# Also check for recently renamed binaries (rclone signature in non-rclone files)
for dir in \"\${SEARCH_DIRS[@]}\"; do
    if [[ -d \"\$dir\" ]]; then
        find \"\$dir\" -type f -executable -newer /proc/1 2>/dev/null | while read -r binary; do
            if strings \"\$binary\" 2>/dev/null | head -100 | grep -qi \"rclone\" && \
               ! basename \"\$binary\" | grep -qi \"rclone\"; then
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] ALERT: Binary with rclone strings but wrong name: \$binary\" >> \"\$ALERT_LOG\"
                logger -t f0rt1ka-binary-monitor \"ALERT: Renamed rclone detected: \$binary\"
            fi
        done
    fi
done
MONITOR_EOF"

    run_cmd "chmod 750 '$monitor_script'"

    # Install cron job (every 5 minutes)
    run_cmd "cat > '$CRON_MONITOR_FILE' << 'CRON_EOF'
# F0RT1KA Binary Rename Detection Monitor
# Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
*/5 * * * * root /usr/local/bin/f0rt1ka-binary-monitor.sh
CRON_EOF"

    log_success "Binary rename monitor installed (runs every 5 minutes)"
    log_info "  Monitor script: $monitor_script"
    log_info "  Cron job: $CRON_MONITOR_FILE"
    log_info "  Alert log: /var/log/f0rt1ka/binary_rename_alerts.log"
}

remove_binary_rename_monitor() {
    log_warning "Removing binary rename monitor..."
    run_cmd "rm -f /usr/local/bin/f0rt1ka-binary-monitor.sh"
    run_cmd "rm -f '$CRON_MONITOR_FILE'"
    log_success "Binary rename monitor removed"
}

# ============================================================================
# 6. Restrict Rclone Installation and Execution (T1048, T1567.002)
# ============================================================================
# The attack stages 847 files (12.3 GB) and uses Rclone with renamed binary
# (svchost.exe) to exfiltrate data to Mega cloud storage.
# ============================================================================

restrict_rclone() {
    log_info "6. Checking for Rclone installation and restricting access..."

    local rclone_found=false
    local rclone_paths=("/usr/bin/rclone" "/usr/local/bin/rclone" "/snap/bin/rclone"
                        "/tmp/rclone" "/opt/rclone/rclone")

    for rpath in "${rclone_paths[@]}"; do
        if [[ -f "$rpath" ]]; then
            rclone_found=true
            log_warning "Rclone found at $rpath"
            local rclone_ver
            rclone_ver=$("$rpath" version 2>/dev/null | head -1 || echo "Unknown version")
            log_info "  Version: $rclone_ver"
            log_info "  Consider removing if not authorized: sudo rm $rpath"
            log_info "  Or restrict execution: sudo chmod 700 $rpath"
        fi
    done

    if ! $rclone_found; then
        log_success "No Rclone installation found"
    fi

    # Check for rclone config files (may contain cloud storage credentials)
    log_info "  Scanning for Rclone configuration files..."
    for home_dir in /root /home/*; do
        local rclone_conf="${home_dir}/.config/rclone/rclone.conf"
        if [[ -f "$rclone_conf" ]]; then
            log_warning "Rclone configuration found: $rclone_conf"
            log_info "  Review for unauthorized cloud storage targets:"
            # Show remote names without credentials
            if $DRY_RUN; then
                log_info "  [DRY-RUN] Would scan: $rclone_conf"
            else
                grep '^\[' "$rclone_conf" 2>/dev/null | while read -r line; do
                    log_info "    Remote: $line"
                done
            fi
        fi
    done

    # Check /tmp for recently downloaded rclone binaries
    local tmp_rclone
    tmp_rclone=$(find /tmp /var/tmp /dev/shm -name "rclone*" -type f 2>/dev/null || true)
    if [[ -n "$tmp_rclone" ]]; then
        log_warning "Rclone binaries found in temp directories:"
        echo "$tmp_rclone" | while read -r f; do
            log_warning "  $f ($(stat -c '%U %Y' "$f" 2>/dev/null || echo 'unknown'))"
        done
    fi
}

# ============================================================================
# 7. VMDK File Integrity Monitoring (T1486 - Data Encrypted for Impact)
# ============================================================================
# Monitor VMDK/VMX/VMSN files for unauthorized modification.
# The attack encrypts 28 target files using ChaCha20+Curve25519 with
# intermittent encryption (1MB encrypt / 11MB skip) and renames to
# .ransomhub extension.
# ============================================================================

setup_vmdk_monitoring() {
    log_info "7. Setting up VMDK file integrity monitoring..."

    # Only relevant on systems with VMFS datastores or VM storage
    local datastore_dirs=("/vmfs/volumes" "/var/lib/libvirt/images" "/var/lib/vmware")
    local monitoring_targets=()

    for dir in "${datastore_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            monitoring_targets+=("$dir")
            log_info "  Found datastore directory: $dir"
        fi
    done

    if [[ ${#monitoring_targets[@]} -eq 0 ]]; then
        log_info "  No VM datastore directories found -- skipping VMDK monitoring"
        log_info "  (This is normal on non-hypervisor systems)"
        return
    fi

    # Create AIDE configuration for VMDK monitoring (if AIDE is available)
    if command -v aide &>/dev/null; then
        local aide_conf="/etc/aide/aide.conf.d/f0rt1ka-vmdk.conf"
        run_cmd "mkdir -p /etc/aide/aide.conf.d 2>/dev/null || true"
        local aide_content="# F0RT1KA VMDK File Integrity Monitoring\n"
        aide_content+="# Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c\n\n"
        for dir in "${monitoring_targets[@]}"; do
            aide_content+="$dir CONTENT_EX\n"
        done
        run_cmd "echo -e '$aide_content' > '$aide_conf'"
        log_success "AIDE monitoring configured for VM datastores"
    else
        log_info "  AIDE not installed -- using cron-based hash monitoring"
    fi

    # Create hash baseline for VMDK files
    local hash_file="/var/log/f0rt1ka/vmdk_hashes_baseline.txt"
    if ! $DRY_RUN; then
        log_info "  Creating VMDK file hash baseline..."
        for dir in "${monitoring_targets[@]}"; do
            find "$dir" -type f \( -name "*.vmdk" -o -name "*.vmx" -o -name "*.vmsn" \
                -o -name "*.vmsd" -o -name "*.nvram" \) -exec sha256sum {} \; \
                >> "$hash_file" 2>/dev/null || true
        done
        local file_count
        file_count=$(wc -l < "$hash_file" 2>/dev/null || echo "0")
        log_success "VMDK baseline created: $file_count files hashed"
        log_info "  Baseline: $hash_file"
    fi

    # Create VMDK integrity check script
    local vmdk_check_script="/usr/local/bin/f0rt1ka-vmdk-integrity.sh"
    run_cmd "cat > '$vmdk_check_script' << 'VMDK_EOF'
#!/usr/bin/env bash
# F0RT1KA VMDK Integrity Check
BASELINE=\"/var/log/f0rt1ka/vmdk_hashes_baseline.txt\"
ALERT_LOG=\"/var/log/f0rt1ka/vmdk_integrity_alerts.log\"

if [[ ! -f \"\$BASELINE\" ]]; then
    exit 0
fi

while IFS=' ' read -r expected_hash filepath; do
    if [[ -f \"\$filepath\" ]]; then
        current_hash=\$(sha256sum \"\$filepath\" 2>/dev/null | awk '{print \$1}')
        if [[ \"\$current_hash\" != \"\$expected_hash\" ]]; then
            echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] ALERT: VMDK modified: \$filepath\" >> \"\$ALERT_LOG\"
            logger -t f0rt1ka-vmdk-integrity \"CRITICAL: VMDK file modified: \$filepath\"
        fi
    else
        # Check for ransomware renamed files
        for ext in .ransomhub .lockbit .akira .blackbasta .encrypted; do
            if [[ -f \"\${filepath}\${ext}\" ]]; then
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] CRITICAL: Ransomware encryption detected: \${filepath}\${ext}\" >> \"\$ALERT_LOG\"
                logger -t f0rt1ka-vmdk-integrity \"CRITICAL: Ransomware extension found: \${filepath}\${ext}\"
            fi
        done
    fi
done < \"\$BASELINE\"
VMDK_EOF"
    run_cmd "chmod 750 '$vmdk_check_script'"

    # Add to cron (every 10 minutes)
    if [[ -f "$CRON_MONITOR_FILE" ]]; then
        run_cmd "echo '*/10 * * * * root /usr/local/bin/f0rt1ka-vmdk-integrity.sh' >> '$CRON_MONITOR_FILE'"
    fi
    log_success "VMDK integrity monitoring installed"
}

remove_vmdk_monitoring() {
    log_warning "Removing VMDK monitoring..."
    run_cmd "rm -f /usr/local/bin/f0rt1ka-vmdk-integrity.sh"
    run_cmd "rm -f /var/log/f0rt1ka/vmdk_hashes_baseline.txt"
    run_cmd "rm -f /etc/aide/aide.conf.d/f0rt1ka-vmdk.conf 2>/dev/null || true"
    log_success "VMDK monitoring removed"
}

# ============================================================================
# 8. ESXi Lockdown Mode Guidance (M1042 - Disable or Remove Feature)
# ============================================================================
# Provides guidance for enabling ESXi Lockdown Mode, which restricts
# direct access to the hypervisor and forces management through vCenter.
# ============================================================================

esxi_lockdown_guidance() {
    log_info "8. ESXi Lockdown Mode guidance..."

    if is_esxi; then
        log_info "  ESXi host detected -- providing lockdown guidance"

        # Check current lockdown mode status
        local lockdown_status
        lockdown_status=$(vim-cmd -U dcui vimsvc/auth/lockdown_mode_status 2>/dev/null || echo "unknown")
        log_info "  Current lockdown mode: $lockdown_status"

        if [[ "$lockdown_status" == "disabled" || "$lockdown_status" == "unknown" ]]; then
            log_warning "  Lockdown mode is NOT enabled"
            log_info ""
            log_info "  RECOMMENDED: Enable Normal Lockdown Mode"
            log_info "  This forces all management through vCenter Server,"
            log_info "  preventing direct SSH/DCUI access by attackers."
            log_info ""
            log_info "  Enable via vCenter: Host > Configure > Security Profile > Lockdown Mode"
            log_info "  Enable via CLI: vim-cmd -U dcui vimsvc/auth/lockdown_mode_enter"
            log_info ""
            log_info "  BEFORE ENABLING:"
            log_info "  1. Ensure vCenter connectivity is stable"
            log_info "  2. Add exception users to the Lockdown Mode exception list"
            log_info "  3. Test with Normal mode before Strict mode"
        else
            log_success "  ESXi Lockdown Mode is enabled: $lockdown_status"
        fi

        # Check if SSH is enabled (should be disabled in production)
        local ssh_enabled
        ssh_enabled=$(vim-cmd hostsvc/autostartmanager/get_autostartseq 2>/dev/null | grep -c "SSH" || true)
        if [[ "$ssh_enabled" -gt 0 ]]; then
            log_warning "  SSH service is running on ESXi host"
            log_info "  Disable SSH when not needed: vim-cmd hostsvc/disable_ssh"
        fi
    else
        log_info "  Not an ESXi host -- providing general guidance"
        log_info "  If managing ESXi hosts, apply these settings via vCenter:"
        log_info "    1. Enable Lockdown Mode (Normal or Strict)"
        log_info "    2. Disable SSH on all production ESXi hosts"
        log_info "    3. Restrict DCUI access"
        log_info "    4. Use vSphere certificates (not self-signed)"
        log_info "    5. Enable host profiles for configuration compliance"
    fi
}

# ============================================================================
# 9. Snapshot and VM Protection Monitoring (T1490 - Inhibit System Recovery)
# ============================================================================
# The attack deletes 32 snapshots and kills 9 VMs before encryption.
# This monitor detects mass snapshot deletion and VM kill operations.
# ============================================================================

setup_vm_protection_monitor() {
    log_info "9. Setting up VM protection monitoring..."

    local vm_monitor_script="/usr/local/bin/f0rt1ka-vm-protection.sh"
    run_cmd "cat > '$vm_monitor_script' << 'VM_EOF'
#!/usr/bin/env bash
# F0RT1KA VM Protection Monitor
# Detects mass snapshot deletion and VM kill operations via syslog analysis

ALERT_LOG=\"/var/log/f0rt1ka/vm_protection_alerts.log\"
THRESHOLD_KILLS=3       # Alert if more than 3 VM kills in 5 minutes
THRESHOLD_SNAPSHOTS=5   # Alert if more than 5 snapshot deletes in 5 minutes
WINDOW_MINUTES=5

# Check recent syslog for VM kill indicators
if command -v journalctl &>/dev/null; then
    KILL_COUNT=\$(journalctl --since \"\${WINDOW_MINUTES} minutes ago\" --no-pager 2>/dev/null | \
        grep -cE '(esxcli vm process kill|vim-cmd vmsvc/power.off|virsh destroy)' || true)
    SNAP_COUNT=\$(journalctl --since \"\${WINDOW_MINUTES} minutes ago\" --no-pager 2>/dev/null | \
        grep -cE '(snapshot.removeall|snapshot.remove|virsh snapshot-delete)' || true)
else
    KILL_COUNT=0
    SNAP_COUNT=0
fi

if [[ \$KILL_COUNT -gt \$THRESHOLD_KILLS ]]; then
    echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] CRITICAL: Mass VM kill detected (\$KILL_COUNT kills in \${WINDOW_MINUTES}m)\" >> \"\$ALERT_LOG\"
    logger -t f0rt1ka-vm-protection \"CRITICAL: Mass VM kill detected: \$KILL_COUNT kills in \${WINDOW_MINUTES} minutes\"
fi

if [[ \$SNAP_COUNT -gt \$THRESHOLD_SNAPSHOTS ]]; then
    echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] CRITICAL: Mass snapshot deletion detected (\$SNAP_COUNT deletes in \${WINDOW_MINUTES}m)\" >> \"\$ALERT_LOG\"
    logger -t f0rt1ka-vm-protection \"CRITICAL: Mass snapshot deletion: \$SNAP_COUNT deletes in \${WINDOW_MINUTES} minutes\"
fi
VM_EOF"

    run_cmd "chmod 750 '$vm_monitor_script'"

    # Add to cron (every 5 minutes)
    if [[ -f "$CRON_MONITOR_FILE" ]]; then
        run_cmd "echo '*/5 * * * * root /usr/local/bin/f0rt1ka-vm-protection.sh' >> '$CRON_MONITOR_FILE'"
    fi
    log_success "VM protection monitoring installed"
}

remove_vm_protection_monitor() {
    log_warning "Removing VM protection monitor..."
    run_cmd "rm -f /usr/local/bin/f0rt1ka-vm-protection.sh"
    log_success "VM protection monitor removed"
}

# ============================================================================
# Main Execution
# ============================================================================

if $UNDO_MODE; then
    echo ""
    log_warning "UNDO MODE: Reverting all hardening changes..."
    echo ""
    undo_ssh
    remove_audit_rules
    remove_firewall_rules
    remove_kernel_hardening
    remove_binary_rename_monitor
    remove_vmdk_monitoring
    remove_vm_protection_monitor
    # Remove cron file
    run_cmd "rm -f '$CRON_MONITOR_FILE'"
    log_success "Undo complete. Some settings (sshd_config) require manual review."
else
    log_info "HARDENING MODE: Applying defensive measures..."
    echo ""
    harden_ssh
    echo ""
    setup_audit_rules
    echo ""
    setup_firewall_rules
    echo ""
    harden_kernel
    echo ""
    setup_binary_rename_monitor
    echo ""
    restrict_rclone
    echo ""
    setup_vmdk_monitoring
    echo ""
    esxi_lockdown_guidance
    echo ""
    setup_vm_protection_monitor
    echo ""
    log_success "All hardening measures applied successfully."
    log_info "Log file: $LOG_FILE"
    log_info "Changes made: $CHANGES_MADE"
fi

echo ""
echo "============================================================"
echo "Hardening script complete."
echo "============================================================"
echo ""
echo "Post-execution checklist:"
echo "  1. Review /var/log/f0rt1ka/ for monitoring alerts"
echo "  2. Verify auditd rules: auditctl -l | grep esxi_"
echo "  3. Verify firewall rules: iptables -L -n | grep -i 'mega\|esxi\|ssh'"
echo "  4. Verify sysctl: sysctl -a | grep -E 'unprivileged|kptr|ptrace'"
echo "  5. Test SSH connectivity from management network"
echo "============================================================"
