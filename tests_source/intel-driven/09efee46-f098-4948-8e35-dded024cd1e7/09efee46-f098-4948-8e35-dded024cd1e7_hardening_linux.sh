#!/usr/bin/env bash
# ============================================================================
# F0RT1KA Defense Hardening Script - Linux
# ============================================================================
# Test ID:     09efee46-f098-4948-8e35-dded024cd1e7
# Test Name:   Sliver C2 Client Detection
# MITRE ATT&CK: T1219 - Remote Access Software
# Mitigations: M1042 (Disable/Remove Feature), M1038 (Execution Prevention),
#              M1037 (Filter Network Traffic), M1031 (Network Intrusion Prevention)
# Created:     2026-03-13
# Author:      F0RT1KA Defense Guidance Builder
# Platform:    Linux (Debian/Ubuntu, RHEL/CentOS, Arch)
# Requires:    root privileges
# Idempotent:  Yes (safe to run multiple times)
# ============================================================================
#
# USAGE:
#   sudo ./09efee46-f098-4948-8e35-dded024cd1e7_hardening_linux.sh          # Apply hardening
#   sudo ./09efee46-f098-4948-8e35-dded024cd1e7_hardening_linux.sh --undo   # Revert changes
#   sudo ./09efee46-f098-4948-8e35-dded024cd1e7_hardening_linux.sh --check  # Verify settings
#   ./09efee46-f098-4948-8e35-dded024cd1e7_hardening_linux.sh --dry-run     # Preview changes
#
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_DIR="/var/log/f0rtika"
readonly LOG_FILE="${LOG_DIR}/c2_hardening_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/var/backups/f0rtika-hardening"
readonly TEST_ID="09efee46-f098-4948-8e35-dded024cd1e7"
readonly MITRE_ATTACK="T1219"

# Known C2 framework port list
readonly -a C2_PORTS=(8888 31337 4444 5555 9999 8443)

# Change counter
CHANGES_MADE=0

# ============================================================================
# Argument Parsing
# ============================================================================
MODE="harden"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo|--revert)
            MODE="undo"
            shift
            ;;
        --check|--verify)
            MODE="check"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $SCRIPT_NAME [OPTIONS]"
            echo ""
            echo "Hardens Linux systems against Sliver C2 and similar remote access tools."
            echo ""
            echo "Options:"
            echo "  --undo, --revert   Revert all hardening changes"
            echo "  --check, --verify  Verify current hardening status"
            echo "  --dry-run          Preview changes without applying"
            echo "  --help, -h         Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

# ============================================================================
# Helper Functions
# ============================================================================

log_msg() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local prefix
    local color

    case "$level" in
        INFO)    prefix="[*]"; color="\033[0;36m" ;;
        SUCCESS) prefix="[+]"; color="\033[0;32m" ;;
        WARNING) prefix="[!]"; color="\033[0;33m" ;;
        ERROR)   prefix="[-]"; color="\033[0;31m" ;;
        HEADER)  prefix="[=]"; color="\033[0;35m" ;;
        *)       prefix="[?]"; color="\033[0m" ;;
    esac

    echo -e "${color}${prefix} ${message}\033[0m"

    if [[ -d "$LOG_DIR" ]] || mkdir -p "$LOG_DIR" 2>/dev/null; then
        echo "${timestamp} ${prefix} ${message}" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]] && [[ "$MODE" != "check" ]] && [[ "$DRY_RUN" == false ]]; then
        log_msg ERROR "This script must be run as root (use sudo)."
        exit 1
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$src" "${BACKUP_DIR}/$(basename "$src").bak.$(date +%Y%m%d%H%M%S)"
        log_msg INFO "Backed up: $src"
    fi
}

has_command() {
    command -v "$1" &>/dev/null
}

run_or_preview() {
    local description="$1"
    shift
    if [[ "$DRY_RUN" == true ]]; then
        log_msg INFO "[DRY-RUN] Would: $description"
    else
        log_msg INFO "$description"
        "$@"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    fi
}

# ============================================================================
# 1. Filesystem Hardening - Restrict Execution from Temp Directories
# MITRE Mitigation: M1038 - Execution Prevention
# ============================================================================

harden_tmp_noexec() {
    log_msg HEADER "Configuring noexec on temporary directories (M1038)..."

    local fstab="/etc/fstab"
    local targets=("/tmp" "/var/tmp" "/dev/shm")

    if [[ "$MODE" == "undo" ]]; then
        log_msg WARNING "Reverting noexec mount options..."
        for mount_point in "${targets[@]}"; do
            if grep -q "${mount_point}.*noexec" "$fstab" 2>/dev/null; then
                backup_file "$fstab"
                sed -i "s|\(${mount_point}.*\)noexec,\?|\1|g" "$fstab"
                mount -o remount "$mount_point" 2>/dev/null || true
                log_msg SUCCESS "Removed noexec from $mount_point"
                CHANGES_MADE=$((CHANGES_MADE + 1))
            fi
        done
        return
    fi

    if [[ "$MODE" == "check" ]]; then
        for mount_point in "${targets[@]}"; do
            if mount | grep -q "$mount_point.*noexec"; then
                log_msg SUCCESS "$mount_point is mounted with noexec"
            else
                log_msg WARNING "$mount_point is NOT mounted with noexec"
            fi
        done
        return
    fi

    for mount_point in "${targets[@]}"; do
        if mount | grep -q "$mount_point.*noexec"; then
            log_msg SUCCESS "$mount_point already has noexec"
            continue
        fi

        if mountpoint -q "$mount_point" 2>/dev/null; then
            run_or_preview "Remounting $mount_point with noexec" \
                mount -o remount,noexec,nosuid,nodev "$mount_point"
            log_msg SUCCESS "Applied noexec to $mount_point (runtime)"
        else
            log_msg INFO "$mount_point is not a separate mount point - consider adding to fstab"
        fi

        # Add to fstab for persistence if not already present
        if ! grep -q "^tmpfs.*${mount_point}.*noexec" "$fstab" 2>/dev/null && [[ "$DRY_RUN" == false ]]; then
            backup_file "$fstab"
            if grep -q "^[^#].*${mount_point}" "$fstab"; then
                sed -i "s|\(.*${mount_point}.*defaults\)|\1,noexec,nosuid,nodev|" "$fstab"
                log_msg SUCCESS "Updated fstab entry for $mount_point with noexec"
            fi
        fi
    done

    log_msg SUCCESS "Temporary directory execution restriction configured"
}

# ============================================================================
# 2. Firewall Rules - Block Common C2 Ports (Outbound)
# MITRE Mitigation: M1037 - Filter Network Traffic
# ============================================================================

harden_firewall() {
    log_msg HEADER "Configuring firewall rules for C2 port filtering (M1037)..."

    if [[ "$MODE" == "undo" ]]; then
        log_msg WARNING "Removing C2 port blocking rules..."

        if has_command iptables; then
            for port in "${C2_PORTS[@]}"; do
                iptables -D OUTPUT -p tcp --dport "$port" -m comment \
                    --comment "F0RT1KA-C2-Block-${TEST_ID}" -j LOG \
                    --log-prefix "F0RT1KA_C2_PORT_${port}: " 2>/dev/null || true
            done
            log_msg SUCCESS "Removed iptables C2 logging rules"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi

        if has_command nft; then
            nft delete table inet f0rtika_c2_monitor 2>/dev/null || true
            log_msg SUCCESS "Removed nftables C2 monitoring table"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi

        if has_command ufw; then
            for port in "${C2_PORTS[@]}"; do
                ufw delete deny out to any port "$port" proto tcp 2>/dev/null || true
            done
            log_msg SUCCESS "Removed UFW C2 port rules"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    if [[ "$MODE" == "check" ]]; then
        if has_command iptables; then
            local blocked=0
            for port in "${C2_PORTS[@]}"; do
                if iptables -L OUTPUT -n 2>/dev/null | grep -q "dpt:${port}"; then
                    blocked=$((blocked + 1))
                fi
            done
            log_msg INFO "iptables: ${blocked}/${#C2_PORTS[@]} C2 ports have rules"
        fi
        if has_command nft; then
            if nft list table inet f0rtika_c2_monitor &>/dev/null; then
                log_msg SUCCESS "nftables: C2 monitoring table present"
            else
                log_msg WARNING "nftables: C2 monitoring table not found"
            fi
        fi
        return
    fi

    # Prefer nftables if available, fall back to iptables
    if has_command nft; then
        log_msg INFO "Using nftables for C2 port monitoring..."
        local port_set
        port_set=$(printf ", %s" "${C2_PORTS[@]}")
        port_set="${port_set:2}"

        if [[ "$DRY_RUN" == false ]]; then
            nft delete table inet f0rtika_c2_monitor 2>/dev/null || true

            nft add table inet f0rtika_c2_monitor
            nft add chain inet f0rtika_c2_monitor output '{ type filter hook output priority 0; policy accept; }'
            nft add rule inet f0rtika_c2_monitor output tcp dport "{ ${port_set} }" log prefix "\"F0RT1KA_C2: \"" counter
            log_msg SUCCESS "nftables C2 port monitoring rules created (logging mode)"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        else
            log_msg INFO "[DRY-RUN] Would create nftables table for C2 port monitoring"
        fi

    elif has_command iptables; then
        log_msg INFO "Using iptables for C2 port monitoring..."
        for port in "${C2_PORTS[@]}"; do
            iptables -D OUTPUT -p tcp --dport "$port" -m comment \
                --comment "F0RT1KA-C2-Block-${TEST_ID}" -j LOG \
                --log-prefix "F0RT1KA_C2_PORT_${port}: " 2>/dev/null || true

            run_or_preview "Adding iptables logging rule for port $port" \
                iptables -A OUTPUT -p tcp --dport "$port" -m comment \
                    --comment "F0RT1KA-C2-Block-${TEST_ID}" -j LOG \
                    --log-prefix "F0RT1KA_C2_PORT_${port}: "
        done
        log_msg SUCCESS "iptables C2 port logging rules created"

    elif has_command ufw; then
        log_msg INFO "Using UFW for C2 port monitoring..."
        for port in "${C2_PORTS[@]}"; do
            run_or_preview "Adding UFW deny rule for outbound port $port" \
                ufw deny out to any port "$port" proto tcp comment "F0RT1KA C2 block"
        done
        log_msg SUCCESS "UFW C2 port deny rules created"
    else
        log_msg WARNING "No firewall tool found (nftables, iptables, ufw). Skipping."
    fi

    log_msg SUCCESS "Firewall C2 port filtering configured"
}

# ============================================================================
# 3. Audit Framework - Process and File Monitoring
# MITRE Mitigation: M1047 - Audit (supports detection of M1038 violations)
# ============================================================================

harden_auditd() {
    log_msg HEADER "Configuring auditd rules for C2 detection (M1047)..."

    local audit_rules_file="/etc/audit/rules.d/f0rtika-c2-detection.rules"

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$audit_rules_file" ]]; then
            rm -f "$audit_rules_file"
            if has_command augenrules; then
                augenrules --load 2>/dev/null || true
            elif has_command auditctl; then
                auditctl -R /etc/audit/audit.rules 2>/dev/null || true
            fi
            log_msg SUCCESS "Removed F0RT1KA audit rules"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        else
            log_msg INFO "No F0RT1KA audit rules to remove"
        fi
        return
    fi

    if [[ "$MODE" == "check" ]]; then
        if [[ -f "$audit_rules_file" ]]; then
            log_msg SUCCESS "F0RT1KA audit rules file exists: $audit_rules_file"
            if has_command auditctl; then
                local rule_count
                rule_count=$(auditctl -l 2>/dev/null | grep -c "f0rtika-c2" || echo "0")
                log_msg INFO "Active F0RT1KA audit rules: $rule_count"
            fi
        else
            log_msg WARNING "F0RT1KA audit rules file not found"
        fi

        if has_command auditd || has_command auditctl; then
            if systemctl is-active auditd &>/dev/null; then
                log_msg SUCCESS "auditd service is running"
            else
                log_msg WARNING "auditd service is NOT running"
            fi
        else
            log_msg WARNING "auditd is not installed"
        fi
        return
    fi

    # Check if auditd is available
    if ! has_command auditctl; then
        log_msg WARNING "auditd is not installed. Installing..."
        local distro
        distro=$(detect_distro)
        case "$distro" in
            debian|ubuntu)
                run_or_preview "Installing auditd" apt-get install -y auditd audispd-plugins
                ;;
            rhel|centos|fedora|rocky|alma)
                run_or_preview "Installing audit" yum install -y audit
                ;;
            arch|manjaro)
                run_or_preview "Installing audit" pacman -S --noconfirm audit
                ;;
            *)
                log_msg ERROR "Cannot auto-install auditd on $distro. Install manually."
                return
                ;;
        esac
    fi

    # Create audit rules for C2 detection
    if [[ "$DRY_RUN" == false ]]; then
        mkdir -p /etc/audit/rules.d

        cat > "$audit_rules_file" << 'AUDIT_EOF'
# ============================================================================
# F0RT1KA C2 Detection Audit Rules
# Test ID: 09efee46-f098-4948-8e35-dded024cd1e7
# MITRE ATT&CK: T1219 - Remote Access Software
# ============================================================================

# Monitor execution from world-writable directories (C2 implant staging)
-a always,exit -F arch=b64 -S execve -F dir=/tmp -F key=f0rtika-c2-tmp-exec
-a always,exit -F arch=b32 -S execve -F dir=/tmp -F key=f0rtika-c2-tmp-exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -F key=f0rtika-c2-tmp-exec
-a always,exit -F arch=b32 -S execve -F dir=/var/tmp -F key=f0rtika-c2-tmp-exec
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -F key=f0rtika-c2-tmp-exec
-a always,exit -F arch=b32 -S execve -F dir=/dev/shm -F key=f0rtika-c2-tmp-exec

# Monitor file creation in staging directories
-w /tmp -p wa -k f0rtika-c2-file-staging
-w /var/tmp -p wa -k f0rtika-c2-file-staging
-w /dev/shm -p wa -k f0rtika-c2-file-staging

# Monitor cron persistence mechanisms
-w /etc/crontab -p wa -k f0rtika-c2-persistence
-w /etc/cron.d -p wa -k f0rtika-c2-persistence
-w /var/spool/cron -p wa -k f0rtika-c2-persistence

# Monitor systemd service creation (C2 persistence)
-w /etc/systemd/system -p wa -k f0rtika-c2-persistence
-w /usr/lib/systemd/system -p wa -k f0rtika-c2-persistence

# Monitor network socket operations from non-standard locations
-a always,exit -F arch=b64 -S connect -F key=f0rtika-c2-network
-a always,exit -F arch=b32 -S connect -F key=f0rtika-c2-network

# Monitor memfd_create (fileless execution technique)
-a always,exit -F arch=b64 -S memfd_create -F key=f0rtika-c2-fileless
-a always,exit -F arch=b32 -S memfd_create -F key=f0rtika-c2-fileless

# Monitor ptrace (process injection/debugging)
-a always,exit -F arch=b64 -S ptrace -F key=f0rtika-c2-injection
-a always,exit -F arch=b32 -S ptrace -F key=f0rtika-c2-injection

# Monitor user/group modification (privilege escalation indicators)
-w /etc/passwd -p wa -k f0rtika-c2-identity
-w /etc/shadow -p wa -k f0rtika-c2-identity
-w /etc/sudoers -p wa -k f0rtika-c2-identity
-w /etc/sudoers.d -p wa -k f0rtika-c2-identity
AUDIT_EOF

        log_msg SUCCESS "Created audit rules: $audit_rules_file"
        CHANGES_MADE=$((CHANGES_MADE + 1))

        # Load the rules
        if has_command augenrules; then
            augenrules --load 2>/dev/null || auditctl -R "$audit_rules_file" 2>/dev/null || true
        else
            auditctl -R "$audit_rules_file" 2>/dev/null || true
        fi
        log_msg SUCCESS "Audit rules loaded"

        # Ensure auditd is enabled and running
        if has_command systemctl; then
            systemctl enable auditd 2>/dev/null || true
            systemctl start auditd 2>/dev/null || true
            log_msg SUCCESS "auditd service enabled and started"
        fi
    else
        log_msg INFO "[DRY-RUN] Would create audit rules at $audit_rules_file"
    fi

    log_msg SUCCESS "Audit framework configured for C2 detection"
}

# ============================================================================
# 4. AppArmor / SELinux - Restrict Binary Execution
# MITRE Mitigation: M1038 - Execution Prevention (MAC layer)
# ============================================================================

harden_mac() {
    log_msg HEADER "Configuring Mandatory Access Control for C2 prevention (M1038)..."

    if [[ "$MODE" == "check" ]]; then
        if has_command aa-status; then
            if aa-status 2>/dev/null | grep -q "profiles are in enforce mode"; then
                log_msg SUCCESS "AppArmor is active with enforced profiles"
            else
                log_msg WARNING "AppArmor has no enforced profiles"
            fi
        elif has_command getenforce; then
            local se_status
            se_status=$(getenforce 2>/dev/null || echo "Unknown")
            if [[ "$se_status" == "Enforcing" ]]; then
                log_msg SUCCESS "SELinux is in Enforcing mode"
            else
                log_msg WARNING "SELinux is in $se_status mode (should be Enforcing)"
            fi
        else
            log_msg WARNING "No MAC system (AppArmor/SELinux) detected"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        local apparmor_profile="/etc/apparmor.d/f0rtika-c2-restrict"
        if [[ -f "$apparmor_profile" ]]; then
            apparmor_parser -R "$apparmor_profile" 2>/dev/null || true
            rm -f "$apparmor_profile"
            log_msg SUCCESS "Removed F0RT1KA AppArmor restriction profile"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    # AppArmor-based systems (Debian, Ubuntu, SUSE)
    if has_command apparmor_parser; then
        local apparmor_profile="/etc/apparmor.d/f0rtika-c2-restrict"

        if [[ "$DRY_RUN" == false ]]; then
            cat > "$apparmor_profile" << 'APPARMOR_EOF'
# F0RT1KA C2 Restriction Profile
# Restricts execution from world-writable directories
# Test ID: 09efee46-f098-4948-8e35-dded024cd1e7

abi <abi/3.0>,

profile f0rtika-c2-restrict /tmp/** flags=(complain) {
  # Deny network access for binaries in /tmp
  deny network inet stream,
  deny network inet dgram,
  deny network inet6 stream,
  deny network inet6 dgram,

  # Allow read but not execute
  /tmp/** r,
  deny /tmp/** x,
}
APPARMOR_EOF

            apparmor_parser -r "$apparmor_profile" 2>/dev/null || true
            log_msg SUCCESS "Created AppArmor restriction profile (complain mode)"
            log_msg INFO "To enforce: aa-enforce $apparmor_profile"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        else
            log_msg INFO "[DRY-RUN] Would create AppArmor restriction profile"
        fi

    # SELinux-based systems (RHEL, CentOS, Fedora)
    elif has_command getenforce; then
        local se_status
        se_status=$(getenforce 2>/dev/null || echo "Unknown")
        if [[ "$se_status" != "Enforcing" ]]; then
            log_msg WARNING "SELinux is $se_status. For C2 protection, set to Enforcing:"
            log_msg INFO "  Edit /etc/selinux/config: SELINUX=enforcing"
            log_msg INFO "  Run: setenforce 1"
        else
            log_msg SUCCESS "SELinux is already in Enforcing mode"
        fi

        # Set boolean to prevent user execution of tmp files
        if has_command setsebool && [[ "$DRY_RUN" == false ]]; then
            setsebool -P user_exec_content off 2>/dev/null || true
            log_msg SUCCESS "SELinux: user_exec_content set to off"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
    else
        log_msg WARNING "No MAC system detected. Consider installing AppArmor or SELinux."
    fi

    log_msg SUCCESS "Mandatory Access Control configured"
}

# ============================================================================
# 5. Sysctl Hardening - Network and Kernel Parameters
# MITRE Mitigation: M1037 - Filter Network Traffic, M1042 - Disable Features
# ============================================================================

harden_sysctl() {
    log_msg HEADER "Configuring sysctl parameters for C2 prevention (M1037, M1042)..."

    local sysctl_file="/etc/sysctl.d/99-f0rtika-c2-hardening.conf"

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$sysctl_file" ]]; then
            rm -f "$sysctl_file"
            sysctl --system &>/dev/null || true
            log_msg SUCCESS "Removed F0RT1KA sysctl hardening"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    if [[ "$MODE" == "check" ]]; then
        local checks=(
            "net.ipv4.tcp_syncookies:1"
            "net.ipv4.conf.all.rp_filter:1"
            "net.ipv4.conf.all.log_martians:1"
            "kernel.yama.ptrace_scope:1"
        )
        for check in "${checks[@]}"; do
            local key="${check%%:*}"
            local expected="${check##*:}"
            local actual
            actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
            if [[ "$actual" == "$expected" ]]; then
                log_msg SUCCESS "$key = $actual (expected: $expected)"
            else
                log_msg WARNING "$key = $actual (expected: $expected)"
            fi
        done
        return
    fi

    if [[ "$DRY_RUN" == false ]]; then
        cat > "$sysctl_file" << 'SYSCTL_EOF'
# ============================================================================
# F0RT1KA C2 Defense - Sysctl Hardening
# Test ID: 09efee46-f098-4948-8e35-dded024cd1e7
# MITRE ATT&CK: T1219 - Remote Access Software
# ============================================================================

# -- Network Hardening (M1037) --

# Enable SYN cookies (prevent SYN flood attacks)
net.ipv4.tcp_syncookies = 1

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets (impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IP source routing (prevents C2 routing tricks)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# -- Kernel Hardening (M1042) --

# Restrict ptrace to parent processes only (prevents C2 process injection)
kernel.yama.ptrace_scope = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict access to kernel perf events
kernel.perf_event_paranoid = 3

# Disable unprivileged BPF (prevents BPF-based evasion)
kernel.unprivileged_bpf_disabled = 1

# Restrict core dumps (prevent credential/memory leakage)
fs.suid_dumpable = 0
SYSCTL_EOF

        sysctl --system &>/dev/null || sysctl -p "$sysctl_file" 2>/dev/null || true
        log_msg SUCCESS "Sysctl hardening parameters applied"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    else
        log_msg INFO "[DRY-RUN] Would create sysctl hardening at $sysctl_file"
    fi

    log_msg SUCCESS "Sysctl hardening configured"
}

# ============================================================================
# 6. ClamAV Configuration - Antivirus for C2 Binary Detection
# MITRE Mitigation: M1038 - Execution Prevention (signature detection)
# ============================================================================

harden_antivirus() {
    log_msg HEADER "Configuring antivirus for C2 binary detection (M1038)..."

    if [[ "$MODE" == "check" ]]; then
        if has_command clamscan; then
            log_msg SUCCESS "ClamAV is installed"
            if systemctl is-active clamav-freshclam &>/dev/null; then
                log_msg SUCCESS "ClamAV signature updater (freshclam) is running"
            else
                log_msg WARNING "ClamAV freshclam is NOT running"
            fi
            if systemctl is-active clamav-daemon &>/dev/null; then
                log_msg SUCCESS "ClamAV daemon (clamd) is running"
            else
                log_msg WARNING "ClamAV daemon is NOT running"
            fi
        else
            log_msg WARNING "ClamAV is not installed"
        fi
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        log_msg INFO "ClamAV removal is not performed (security software should remain)"
        log_msg INFO "To remove manually: apt remove clamav clamav-daemon (or yum remove clamav)"
        local scan_script="/etc/cron.daily/f0rtika-c2-scan"
        if [[ -f "$scan_script" ]]; then
            rm -f "$scan_script"
            log_msg SUCCESS "Removed daily C2 scan script"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    if ! has_command clamscan; then
        log_msg INFO "ClamAV not installed. Installing..."
        local distro
        distro=$(detect_distro)
        case "$distro" in
            debian|ubuntu)
                run_or_preview "Installing ClamAV" apt-get install -y clamav clamav-daemon
                ;;
            rhel|centos|fedora|rocky|alma)
                run_or_preview "Installing ClamAV" yum install -y clamav clamav-update clamd
                ;;
            arch|manjaro)
                run_or_preview "Installing ClamAV" pacman -S --noconfirm clamav
                ;;
            *)
                log_msg WARNING "Cannot auto-install ClamAV on $distro. Install manually."
                return
                ;;
        esac
    fi

    if [[ "$DRY_RUN" == false ]]; then
        # Update signatures
        freshclam 2>/dev/null || log_msg WARNING "freshclam update may require configuration"

        # Enable and start services
        if has_command systemctl; then
            systemctl enable clamav-freshclam 2>/dev/null || true
            systemctl start clamav-freshclam 2>/dev/null || true
            systemctl enable clamav-daemon 2>/dev/null || true
            systemctl start clamav-daemon 2>/dev/null || true
        fi

        log_msg SUCCESS "ClamAV configured and signature update initiated"
        CHANGES_MADE=$((CHANGES_MADE + 1))

        # Create a scheduled scan for C2 staging directories
        local scan_script="/etc/cron.daily/f0rtika-c2-scan"
        cat > "$scan_script" << 'SCAN_EOF'
#!/bin/bash
# F0RT1KA Daily C2 Staging Directory Scan
# Scans common attacker staging locations for C2 implants

LOG="/var/log/f0rtika/clamav-c2-scan.log"
mkdir -p "$(dirname "$LOG")"

echo "=== F0RT1KA C2 Scan: $(date) ===" >> "$LOG"
clamscan --recursive --infected --log="$LOG" \
    /tmp/ /var/tmp/ /dev/shm/ \
    /home/*/Downloads/ \
    /home/*/.local/ \
    /home/*/.cache/ \
    2>/dev/null || true
SCAN_EOF
        chmod 755 "$scan_script"
        log_msg SUCCESS "Created daily C2 staging directory scan: $scan_script"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    fi

    log_msg SUCCESS "Antivirus configuration completed"
}

# ============================================================================
# 7. Process Restriction - Limit Execution Capabilities
# MITRE Mitigation: M1042 - Disable or Remove Feature
# ============================================================================

harden_process_restrictions() {
    log_msg HEADER "Configuring process execution restrictions (M1042)..."

    local limits_file="/etc/security/limits.d/99-f0rtika-c2-hardening.conf"

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$limits_file" ]]; then
            rm -f "$limits_file"
            log_msg SUCCESS "Removed F0RT1KA process limits"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    if [[ "$MODE" == "check" ]]; then
        if [[ -f "$limits_file" ]]; then
            log_msg SUCCESS "F0RT1KA process limits file exists"
        else
            log_msg WARNING "F0RT1KA process limits not configured"
        fi

        local core_val
        core_val=$(ulimit -c 2>/dev/null || echo "unknown")
        if [[ "$core_val" == "0" ]]; then
            log_msg SUCCESS "Core dumps are disabled (ulimit -c = 0)"
        else
            log_msg WARNING "Core dumps are enabled (ulimit -c = $core_val)"
        fi
        return
    fi

    if [[ "$DRY_RUN" == false ]]; then
        cat > "$limits_file" << 'LIMITS_EOF'
# ============================================================================
# F0RT1KA C2 Defense - Process Limits
# Test ID: 09efee46-f098-4948-8e35-dded024cd1e7
# ============================================================================

# Disable core dumps for all users (prevent credential leakage)
*               hard    core            0
*               soft    core            0

# Limit number of processes per user (prevent fork bombs, process spawning)
*               hard    nproc           4096
*               soft    nproc           2048
LIMITS_EOF

        log_msg SUCCESS "Process restriction limits configured"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    else
        log_msg INFO "[DRY-RUN] Would create process limits at $limits_file"
    fi

    log_msg SUCCESS "Process execution restrictions configured"
}

# ============================================================================
# 8. SSH Hardening - Prevent Remote C2 via SSH Tunneling
# MITRE Mitigation: M1037 - Filter Network Traffic
# ============================================================================

harden_ssh() {
    log_msg HEADER "Configuring SSH hardening against C2 tunneling (M1037)..."

    local sshd_config="/etc/ssh/sshd_config"
    local sshd_drop_in="/etc/ssh/sshd_config.d/99-f0rtika-c2-hardening.conf"

    if [[ ! -f "$sshd_config" ]]; then
        log_msg INFO "SSH server not installed. Skipping SSH hardening."
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$sshd_drop_in" ]]; then
            rm -f "$sshd_drop_in"
            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
            log_msg SUCCESS "Removed F0RT1KA SSH hardening"
            CHANGES_MADE=$((CHANGES_MADE + 1))
        fi
        return
    fi

    if [[ "$MODE" == "check" ]]; then
        local issues=0
        if sshd -T 2>/dev/null | grep -qi "allowtcpforwarding yes"; then
            log_msg WARNING "SSH TCP forwarding is enabled (potential C2 tunnel)"
            issues=$((issues + 1))
        else
            log_msg SUCCESS "SSH TCP forwarding is restricted"
        fi
        if sshd -T 2>/dev/null | grep -qi "permitrootlogin yes"; then
            log_msg WARNING "SSH root login is enabled"
            issues=$((issues + 1))
        else
            log_msg SUCCESS "SSH root login is restricted"
        fi
        if [[ $issues -eq 0 ]]; then
            log_msg SUCCESS "SSH hardening looks good"
        fi
        return
    fi

    if [[ "$DRY_RUN" == false ]]; then
        mkdir -p /etc/ssh/sshd_config.d

        cat > "$sshd_drop_in" << 'SSH_EOF'
# ============================================================================
# F0RT1KA C2 Defense - SSH Hardening
# Test ID: 09efee46-f098-4948-8e35-dded024cd1e7
# Prevents SSH from being abused as a C2 tunnel
# ============================================================================

# Disable TCP forwarding (prevents SSH tunnel C2)
AllowTcpForwarding no

# Disable agent forwarding
AllowAgentForwarding no

# Disable X11 forwarding
X11Forwarding no

# Disable tunnel device forwarding
PermitTunnel no

# Restrict root login
PermitRootLogin prohibit-password

# Use strong authentication
MaxAuthTries 3
LoginGraceTime 30

# Set idle timeout (disconnects idle sessions C2 could abuse)
ClientAliveInterval 300
ClientAliveCountMax 2
SSH_EOF

        # Test configuration before reloading
        if sshd -t 2>/dev/null; then
            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
            log_msg SUCCESS "SSH hardening applied and service reloaded"
        else
            log_msg ERROR "SSH config test failed. Removing hardening to prevent lockout."
            rm -f "$sshd_drop_in"
        fi
        CHANGES_MADE=$((CHANGES_MADE + 1))
    else
        log_msg INFO "[DRY-RUN] Would create SSH hardening at $sshd_drop_in"
    fi

    log_msg SUCCESS "SSH hardening configured"
}

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================================"
echo "  F0RT1KA Defense Hardening Script - Linux"
echo "  Test: Sliver C2 Client Detection"
echo "  MITRE ATT&CK: ${MITRE_ATTACK} - Remote Access Software"
echo "============================================================================"
echo ""

check_root

DISTRO=$(detect_distro)
log_msg INFO "Detected distribution: $DISTRO"
log_msg INFO "Mode: ${MODE^^}"
if [[ "$DRY_RUN" == true ]]; then
    log_msg INFO "DRY-RUN mode: no changes will be made"
fi
log_msg INFO "Log file: $LOG_FILE"
echo ""

# Execute hardening functions
harden_tmp_noexec
echo ""

harden_firewall
echo ""

harden_auditd
echo ""

harden_mac
echo ""

harden_sysctl
echo ""

harden_antivirus
echo ""

harden_process_restrictions
echo ""

harden_ssh
echo ""

# Summary
echo "============================================================================"
if [[ "$MODE" == "check" ]]; then
    echo "  Verification Complete"
elif [[ "$DRY_RUN" == true ]]; then
    echo "  Dry-Run Complete (no changes made)"
else
    echo "  Hardening Complete!"
fi
echo "============================================================================"
echo ""
log_msg SUCCESS "Total changes: $CHANGES_MADE"
log_msg INFO "Log file: $LOG_FILE"
echo ""

# Verification commands
if [[ "$MODE" == "harden" ]] && [[ "$DRY_RUN" == false ]]; then
    log_msg HEADER "Verification Commands:"
    echo ""
    echo "  # Verify noexec on /tmp:"
    echo "  mount | grep '/tmp.*noexec'"
    echo ""
    echo "  # Verify firewall rules:"
    echo "  nft list table inet f0rtika_c2_monitor 2>/dev/null || iptables -L OUTPUT -n | grep F0RT1KA"
    echo ""
    echo "  # Verify audit rules:"
    echo "  auditctl -l | grep f0rtika-c2"
    echo ""
    echo "  # Verify sysctl settings:"
    echo "  sysctl kernel.yama.ptrace_scope net.ipv4.tcp_syncookies"
    echo ""
    echo "  # Verify ClamAV:"
    echo "  systemctl status clamav-daemon"
    echo ""
    echo "  # Run full check:"
    echo "  sudo $0 --check"
    echo ""
fi

exit 0
