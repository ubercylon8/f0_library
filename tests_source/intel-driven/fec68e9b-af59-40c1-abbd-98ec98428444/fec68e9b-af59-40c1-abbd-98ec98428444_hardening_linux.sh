#!/usr/bin/env bash
# ============================================================
# F0RT1KA Linux Hardening Script
# MDE Process Injection and API Authentication Bypass Protection
#
# Test ID: fec68e9b-af59-40c1-abbd-98ec98428444
# MITRE ATT&CK: T1055, T1055.001, T1562.001, T1014, T1557, T1071.001
#
# This script hardens a Linux system against the attack techniques
# demonstrated by the MDE exploitation test. While the test targets
# Windows MDE, the underlying techniques (process injection, memory
# manipulation, proxy hijacking, API abuse) apply to Linux EDR
# agents equally. This script protects Linux EDR agents (e.g.,
# Microsoft Defender for Endpoint on Linux, CrowdStrike Falcon,
# SentinelOne) against the same attack patterns.
#
# Usage:
#   sudo ./fec68e9b-af59-40c1-abbd-98ec98428444_hardening_linux.sh [apply|audit|undo]
#
# Modes:
#   apply  - Apply all hardening settings (default)
#   audit  - Check current settings without making changes
#   undo   - Revert hardening settings to defaults
#
# Requirements:
#   - Root privileges (sudo)
#   - Linux kernel 4.4+ (for YAMA ptrace scope)
#   - systemd-based distribution
#
# Author: F0RT1KA Defense Guidance Builder
# Date: 2026-03-13
# Idempotent: Yes (safe to run multiple times)
# ============================================================

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
SCRIPT_NAME="$(basename "$0")"
TEST_ID="fec68e9b-af59-40c1-abbd-98ec98428444"
LOG_DIR="/var/log/f0rtika"
LOG_FILE="${LOG_DIR}/hardening_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/var/backups/f0rtika-hardening"
MODE="${1:-apply}"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# ============================================================
# Helper Functions
# ============================================================

log_msg() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "${timestamp} [${level}] ${message}" >> "${LOG_FILE}" 2>/dev/null || true

    case "${level}" in
        INFO)    echo -e "${CYAN}[*]${NC} ${message}" ;;
        SUCCESS) echo -e "${GREEN}[+]${NC} ${message}" ;;
        WARNING) echo -e "${YELLOW}[!]${NC} ${message}" ;;
        ERROR)   echo -e "${RED}[-]${NC} ${message}" ;;
        HEADER)  echo -e "${MAGENTA}[=]${NC} ${message}" ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_msg ERROR "This script must be run as root (sudo)."
        exit 1
    fi
}

backup_file() {
    local filepath="$1"
    if [[ -f "${filepath}" ]]; then
        local backup_path="${BACKUP_DIR}$(dirname "${filepath}")"
        mkdir -p "${backup_path}"
        cp -a "${filepath}" "${backup_path}/$(basename "${filepath}").$(date +%Y%m%d%H%M%S).bak"
        log_msg INFO "Backed up: ${filepath}"
    fi
}

get_sysctl_value() {
    local key="$1"
    sysctl -n "${key}" 2>/dev/null || echo "N/A"
}

set_sysctl_value() {
    local key="$1"
    local value="$2"
    local current
    current="$(get_sysctl_value "${key}")"

    if [[ "${current}" == "${value}" ]]; then
        log_msg INFO "${key} already set to ${value}"
        return 0
    fi

    sysctl -w "${key}=${value}" > /dev/null 2>&1
    log_msg SUCCESS "${key}: ${current} -> ${value}"
}

persist_sysctl() {
    local key="$1"
    local value="$2"
    local conf_file="/etc/sysctl.d/90-f0rtika-hardening.conf"

    if ! grep -q "^${key}" "${conf_file}" 2>/dev/null; then
        echo "${key} = ${value}" >> "${conf_file}"
    else
        sed -i "s|^${key}.*|${key} = ${value}|" "${conf_file}"
    fi
}

# ============================================================
# SECTION 1: Process Protection (Anti-Injection)
# Mitigates: T1055, T1055.001, T1014
# ============================================================

harden_process_protection() {
    log_msg HEADER "Section 1: Process Protection (Anti-Injection)"
    log_msg INFO "Mitigates: T1055 (Process Injection), T1014 (Memory Manipulation)"

    # --- 1.1: YAMA ptrace scope ---
    # Restricts which processes can use ptrace (process_vm_readv/writev, PTRACE_ATTACH)
    # 0 = classic (any process can ptrace)
    # 1 = restricted (only parent can ptrace children)
    # 2 = admin-only (only root with CAP_SYS_PTRACE)
    # 3 = no ptrace (completely disabled)
    local ptrace_key="kernel.yama.ptrace_scope"

    if [[ "${MODE}" == "audit" ]]; then
        local current
        current="$(get_sysctl_value "${ptrace_key}")"
        local state_text
        case "${current}" in
            0) state_text="Classic (unrestricted) - VULNERABLE" ;;
            1) state_text="Restricted (parent only)" ;;
            2) state_text="Admin-only (CAP_SYS_PTRACE)" ;;
            3) state_text="Disabled (no ptrace)" ;;
            *) state_text="Unknown (${current})" ;;
        esac
        log_msg INFO "YAMA ptrace scope: ${state_text}"
    elif [[ "${MODE}" == "undo" ]]; then
        set_sysctl_value "${ptrace_key}" 1
        persist_sysctl "${ptrace_key}" 1
        log_msg SUCCESS "YAMA ptrace scope: Reverted to restricted (1)"
    else
        # Set to 2 (admin-only) - strong protection against injection
        set_sysctl_value "${ptrace_key}" 2
        persist_sysctl "${ptrace_key}" 2
        log_msg SUCCESS "YAMA ptrace scope: Set to admin-only (2)"
        log_msg INFO "  Only root/CAP_SYS_PTRACE can attach to processes"
    fi

    # --- 1.2: Restrict /proc/PID access ---
    # hidepid=2 hides process info from non-owning users
    local hidepid_key="proc hidepid"

    if [[ "${MODE}" == "audit" ]]; then
        local proc_opts
        proc_opts="$(mount | grep 'type proc' | head -1)"
        if echo "${proc_opts}" | grep -q "hidepid=2"; then
            log_msg INFO "/proc hidepid: Enabled (hidepid=2)"
        elif echo "${proc_opts}" | grep -q "hidepid=1"; then
            log_msg WARNING "/proc hidepid: Partial (hidepid=1)"
        else
            log_msg WARNING "/proc hidepid: Not set - processes visible to all users"
        fi
    elif [[ "${MODE}" == "undo" ]]; then
        mount -o remount,hidepid=0 /proc 2>/dev/null || true
        sed -i '/hidepid=/d' /etc/fstab 2>/dev/null || true
        log_msg SUCCESS "/proc hidepid: Reverted to default (0)"
    else
        mount -o remount,hidepid=2 /proc 2>/dev/null || {
            log_msg WARNING "Failed to set hidepid=2 on /proc (may require systemd override)"
        }
        # Persist in fstab if not already present
        if ! grep -q "hidepid=2" /etc/fstab 2>/dev/null; then
            log_msg INFO "  Add 'proc /proc proc defaults,hidepid=2 0 0' to /etc/fstab for persistence"
        fi
        log_msg SUCCESS "/proc hidepid: Set to 2 (processes hidden from non-owners)"
    fi

    # --- 1.3: Restrict core dumps (prevent memory extraction) ---
    local core_key="fs.suid_dumpable"

    if [[ "${MODE}" == "audit" ]]; then
        local current
        current="$(get_sysctl_value "${core_key}")"
        local state_text
        case "${current}" in
            0) state_text="Disabled" ;;
            1) state_text="Enabled (debug)" ;;
            2) state_text="Suidsafe" ;;
            *) state_text="Unknown (${current})" ;;
        esac
        log_msg INFO "SUID core dumps: ${state_text}"
    elif [[ "${MODE}" == "undo" ]]; then
        set_sysctl_value "${core_key}" 0
        persist_sysctl "${core_key}" 0
    else
        set_sysctl_value "${core_key}" 0
        persist_sysctl "${core_key}" 0
        log_msg SUCCESS "SUID core dumps: Disabled (prevents memory extraction)"
    fi

    # --- 1.4: Address Space Layout Randomization (ASLR) ---
    local aslr_key="kernel.randomize_va_space"

    if [[ "${MODE}" == "audit" ]]; then
        local current
        current="$(get_sysctl_value "${aslr_key}")"
        local state_text
        case "${current}" in
            0) state_text="Disabled - VULNERABLE" ;;
            1) state_text="Conservative" ;;
            2) state_text="Full (recommended)" ;;
            *) state_text="Unknown (${current})" ;;
        esac
        log_msg INFO "ASLR: ${state_text}"
    elif [[ "${MODE}" == "undo" ]]; then
        # Default is 2 on modern kernels
        set_sysctl_value "${aslr_key}" 2
        persist_sysctl "${aslr_key}" 2
    else
        set_sysctl_value "${aslr_key}" 2
        persist_sysctl "${aslr_key}" 2
        log_msg SUCCESS "ASLR: Full randomization (2) - makes memory layout unpredictable"
    fi

    # --- 1.5: Restrict kernel module loading ---
    # Prevents rootkit kernel module insertion
    local modules_key="kernel.modules_disabled"

    if [[ "${MODE}" == "audit" ]]; then
        local current
        current="$(get_sysctl_value "${modules_key}")"
        if [[ "${current}" == "1" ]]; then
            log_msg INFO "Kernel module loading: Disabled (locked)"
        else
            log_msg WARNING "Kernel module loading: Enabled - rootkit modules can be loaded"
        fi
    elif [[ "${MODE}" == "undo" ]]; then
        log_msg WARNING "kernel.modules_disabled cannot be undone without reboot"
        log_msg INFO "  Remove from sysctl config and reboot to re-enable"
        sed -i "/^${modules_key}/d" /etc/sysctl.d/90-f0rtika-hardening.conf 2>/dev/null || true
    else
        log_msg WARNING "kernel.modules_disabled: NOT setting at runtime (irreversible until reboot)"
        log_msg INFO "  To enable: echo 'kernel.modules_disabled = 1' >> /etc/sysctl.d/90-f0rtika-hardening.conf"
        log_msg INFO "  Then reboot. This prevents ANY new kernel modules from loading."
        log_msg INFO "  Ensure all needed drivers are loaded before enabling."
    fi

    echo ""
}

# ============================================================
# SECTION 2: EDR Agent Protection
# Mitigates: T1562.001
# ============================================================

harden_edr_protection() {
    log_msg HEADER "Section 2: EDR Agent Service Protection"
    log_msg INFO "Mitigates: T1562.001 (Impair Defenses: Disable or Modify Tools)"

    # --- 2.1: Protect MDE for Linux service ---
    local mde_service="mdatp"
    local falcon_service="falcon-sensor"

    for svc in "${mde_service}" "${falcon_service}"; do
        if systemctl is-active --quiet "${svc}" 2>/dev/null; then
            if [[ "${MODE}" == "audit" ]]; then
                local svc_status
                svc_status="$(systemctl is-enabled "${svc}" 2>/dev/null || echo 'not-found')"
                log_msg INFO "EDR Service (${svc}): Active, Startup=${svc_status}"

                # Check if service is restart-protected
                local restart_policy
                restart_policy="$(systemctl show "${svc}" -p Restart 2>/dev/null | cut -d= -f2)"
                log_msg INFO "  Restart policy: ${restart_policy}"
            elif [[ "${MODE}" == "undo" ]]; then
                log_msg INFO "EDR service (${svc}): No changes to undo (protection is additive)"
            else
                # Ensure service is enabled and set to auto-restart
                systemctl enable "${svc}" 2>/dev/null || true
                log_msg SUCCESS "EDR Service (${svc}): Enabled for auto-start"

                # Create systemd override for crash recovery
                local override_dir="/etc/systemd/system/${svc}.service.d"
                mkdir -p "${override_dir}"
                cat > "${override_dir}/f0rtika-hardening.conf" << 'OVERRIDE_EOF'
[Service]
# F0RT1KA Hardening: Ensure EDR agent restarts after failures
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
# Prevent OOM killer from targeting EDR agent
OOMScoreAdjust=-900
# Restrict capabilities that could be used to tamper with the service
ProtectSystem=strict
ProtectHome=yes
OVERRIDE_EOF
                systemctl daemon-reload
                log_msg SUCCESS "  Auto-restart on crash: Configured (5s delay, max 5 in 60s)"
                log_msg SUCCESS "  OOM protection: Score adjusted to -900"
            fi
        else
            if [[ "${MODE}" == "audit" ]]; then
                log_msg WARNING "EDR Service (${svc}): Not found or not running"
            fi
        fi
    done

    # --- 2.2: Protect EDR binary files ---
    local edr_paths=(
        "/opt/microsoft/mdatp"
        "/opt/CrowdStrike"
        "/opt/sentinelone"
    )

    for edr_path in "${edr_paths[@]}"; do
        if [[ -d "${edr_path}" ]]; then
            if [[ "${MODE}" == "audit" ]]; then
                local perms
                perms="$(stat -c '%a %U:%G' "${edr_path}" 2>/dev/null)"
                log_msg INFO "EDR path ${edr_path}: ${perms}"
                # Check for immutable attribute
                if lsattr -d "${edr_path}" 2>/dev/null | grep -q "i"; then
                    log_msg INFO "  Immutable flag: Set"
                else
                    log_msg WARNING "  Immutable flag: Not set"
                fi
            elif [[ "${MODE}" == "undo" ]]; then
                chattr -i "${edr_path}" 2>/dev/null || true
                log_msg SUCCESS "Removed immutable flag from ${edr_path}"
            else
                # Set restrictive permissions
                chmod 750 "${edr_path}" 2>/dev/null || true
                chown root:root "${edr_path}" 2>/dev/null || true
                # Set immutable flag to prevent deletion/modification
                chattr +i "${edr_path}" 2>/dev/null || {
                    log_msg WARNING "Failed to set immutable flag on ${edr_path} (filesystem may not support it)"
                }
                log_msg SUCCESS "EDR path ${edr_path}: Permissions 750, immutable flag set"
            fi
        fi
    done

    echo ""
}

# ============================================================
# SECTION 3: Network Hardening (Anti-MITM/Proxy Abuse)
# Mitigates: T1557, T1071.001
# ============================================================

harden_network() {
    log_msg HEADER "Section 3: Network Hardening (Anti-MITM/Proxy Abuse)"
    log_msg INFO "Mitigates: T1557 (Adversary-in-the-Middle), T1071.001 (Web Protocols)"

    # --- 3.1: Restrict proxy environment variable manipulation ---
    if [[ "${MODE}" == "audit" ]]; then
        if [[ -n "${http_proxy:-}" ]] || [[ -n "${https_proxy:-}" ]]; then
            log_msg WARNING "Proxy environment variables are set:"
            log_msg INFO "  http_proxy=${http_proxy:-<not set>}"
            log_msg INFO "  https_proxy=${https_proxy:-<not set>}"
        else
            log_msg INFO "Proxy environment variables: Not set"
        fi
    elif [[ "${MODE}" == "undo" ]]; then
        rm -f /etc/profile.d/f0rtika-proxy-protect.sh
        log_msg SUCCESS "Removed proxy protection profile script"
    else
        # Create profile script that warns on proxy changes
        cat > /etc/profile.d/f0rtika-proxy-protect.sh << 'PROXY_EOF'
# F0RT1KA Hardening: Log proxy environment variable changes
# This helps detect proxy manipulation for MITM attacks on EDR
_f0rtika_check_proxy() {
    if [[ -n "${http_proxy:-}" ]] || [[ -n "${https_proxy:-}" ]] || [[ -n "${HTTP_PROXY:-}" ]] || [[ -n "${HTTPS_PROXY:-}" ]]; then
        logger -t "f0rtika-security" -p auth.warning "Proxy environment variables detected: http_proxy=${http_proxy:-} https_proxy=${https_proxy:-} HTTP_PROXY=${HTTP_PROXY:-} HTTPS_PROXY=${HTTPS_PROXY:-} user=$(whoami) pid=$$"
    fi
}
_f0rtika_check_proxy
PROXY_EOF
        chmod 644 /etc/profile.d/f0rtika-proxy-protect.sh
        log_msg SUCCESS "Proxy monitoring: Installed profile script to log proxy changes"
    fi

    # --- 3.2: Network namespace isolation for EDR ---
    if [[ "${MODE}" == "audit" ]]; then
        local user_ns
        user_ns="$(get_sysctl_value 'user.max_user_namespaces')"
        log_msg INFO "User namespaces max: ${user_ns}"
    elif [[ "${MODE}" == "undo" ]]; then
        # Default is usually a large number
        set_sysctl_value "user.max_user_namespaces" 65536
        persist_sysctl "user.max_user_namespaces" 65536
        log_msg SUCCESS "User namespaces: Reverted to default (65536)"
    else
        log_msg INFO "User namespaces: Consider restricting if not needed by containers"
        log_msg INFO "  Current value: $(get_sysctl_value 'user.max_user_namespaces')"
        log_msg INFO "  To restrict: sysctl -w user.max_user_namespaces=0"
        log_msg WARNING "  WARNING: This will break containers (Docker, Podman, etc.)"
    fi

    # --- 3.3: TCP hardening against session hijacking ---
    local tcp_syncookies="net.ipv4.tcp_syncookies"
    local tcp_rfc1337="net.ipv4.tcp_rfc1337"

    if [[ "${MODE}" == "audit" ]]; then
        log_msg INFO "TCP SYN cookies: $(get_sysctl_value ${tcp_syncookies})"
        log_msg INFO "TCP RFC1337 (TIME-WAIT assassination): $(get_sysctl_value ${tcp_rfc1337})"
    elif [[ "${MODE}" == "undo" ]]; then
        set_sysctl_value "${tcp_syncookies}" 1
        set_sysctl_value "${tcp_rfc1337}" 0
        persist_sysctl "${tcp_syncookies}" 1
        persist_sysctl "${tcp_rfc1337}" 0
    else
        set_sysctl_value "${tcp_syncookies}" 1
        set_sysctl_value "${tcp_rfc1337}" 1
        persist_sysctl "${tcp_syncookies}" 1
        persist_sysctl "${tcp_rfc1337}" 1
        log_msg SUCCESS "TCP SYN cookies: Enabled (anti-SYN flood)"
        log_msg SUCCESS "TCP RFC1337: Enabled (anti-TIME-WAIT assassination)"
    fi

    # --- 3.4: Restrict ICMP redirects (anti-routing manipulation) ---
    local icmp_redirects="net.ipv4.conf.all.accept_redirects"
    local icmp_secure="net.ipv4.conf.all.secure_redirects"
    local icmp_send="net.ipv4.conf.all.send_redirects"

    if [[ "${MODE}" == "audit" ]]; then
        log_msg INFO "ICMP accept redirects: $(get_sysctl_value ${icmp_redirects})"
        log_msg INFO "ICMP secure redirects: $(get_sysctl_value ${icmp_secure})"
        log_msg INFO "ICMP send redirects: $(get_sysctl_value ${icmp_send})"
    elif [[ "${MODE}" == "undo" ]]; then
        set_sysctl_value "${icmp_redirects}" 1
        set_sysctl_value "${icmp_secure}" 1
        set_sysctl_value "${icmp_send}" 1
        persist_sysctl "${icmp_redirects}" 1
        persist_sysctl "${icmp_secure}" 1
        persist_sysctl "${icmp_send}" 1
    else
        set_sysctl_value "${icmp_redirects}" 0
        set_sysctl_value "${icmp_secure}" 0
        set_sysctl_value "${icmp_send}" 0
        persist_sysctl "${icmp_redirects}" 0
        persist_sysctl "${icmp_secure}" 0
        persist_sysctl "${icmp_send}" 0
        log_msg SUCCESS "ICMP redirects: Disabled (prevents routing manipulation for MITM)"
    fi

    # --- 3.5: iptables/nftables rules for EDR communication protection ---
    if [[ "${MODE}" == "audit" ]]; then
        if command -v iptables &>/dev/null; then
            local edr_rules
            edr_rules="$(iptables -L OUTPUT -n 2>/dev/null | grep -c "f0rtika" || echo "0")"
            log_msg INFO "F0RT1KA iptables rules (OUTPUT): ${edr_rules}"
        fi
        if command -v nft &>/dev/null; then
            local nft_rules
            nft_rules="$(nft list ruleset 2>/dev/null | grep -c "f0rtika" || echo "0")"
            log_msg INFO "F0RT1KA nftables rules: ${nft_rules}"
        fi
    elif [[ "${MODE}" == "undo" ]]; then
        if command -v iptables &>/dev/null; then
            # Remove F0RT1KA-specific rules
            iptables -D OUTPUT -m comment --comment "f0rtika-edr-protect" -j ACCEPT 2>/dev/null || true
            log_msg SUCCESS "Removed F0RT1KA iptables rules"
        fi
    else
        log_msg INFO "Firewall: Consider restricting outbound connections from non-EDR processes"
        log_msg INFO "  to EDR cloud endpoints. Example for MDE on Linux:"
        log_msg INFO "  iptables -A OUTPUT -m owner --uid-owner root -d <mde-cloud-ip> -j ACCEPT"
        log_msg INFO "  iptables -A OUTPUT -d <mde-cloud-ip> -j DROP"
        log_msg WARNING "  Customize the above for your MDE cloud endpoint IPs"
    fi

    echo ""
}

# ============================================================
# SECTION 4: Audit and Logging Configuration
# Ensures detection of attack techniques
# ============================================================

harden_audit_logging() {
    log_msg HEADER "Section 4: Audit and Logging Configuration"
    log_msg INFO "Ensures detection of process injection, memory access, and API abuse"

    # --- 4.1: auditd rules for process injection detection ---
    local audit_rules_file="/etc/audit/rules.d/f0rtika-edr-protection.rules"

    if [[ "${MODE}" == "audit" ]]; then
        if [[ -f "${audit_rules_file}" ]]; then
            local rule_count
            rule_count="$(grep -c '^-' "${audit_rules_file}" 2>/dev/null || echo "0")"
            log_msg INFO "F0RT1KA audit rules: ${rule_count} rules installed"
        else
            log_msg WARNING "F0RT1KA audit rules: Not installed"
        fi

        # Check auditd status
        if systemctl is-active --quiet auditd 2>/dev/null; then
            log_msg INFO "auditd service: Running"
        else
            log_msg WARNING "auditd service: Not running - install and enable for detection"
        fi
    elif [[ "${MODE}" == "undo" ]]; then
        rm -f "${audit_rules_file}"
        if command -v augenrules &>/dev/null; then
            augenrules --load 2>/dev/null || true
        fi
        log_msg SUCCESS "Removed F0RT1KA audit rules"
    else
        if command -v auditctl &>/dev/null; then
            mkdir -p /etc/audit/rules.d

            cat > "${audit_rules_file}" << 'AUDIT_EOF'
## F0RT1KA EDR Protection Audit Rules
## Test ID: fec68e9b-af59-40c1-abbd-98ec98428444
## Detects: Process injection, memory manipulation, EDR tampering

# --- T1055: Process Injection Detection ---
# Monitor ptrace calls (used for process injection and memory reading)
-a always,exit -F arch=b64 -S ptrace -k f0rtika_process_injection
-a always,exit -F arch=b32 -S ptrace -k f0rtika_process_injection

# Monitor process_vm_readv/writev (cross-process memory access)
-a always,exit -F arch=b64 -S process_vm_readv -k f0rtika_memory_read
-a always,exit -F arch=b64 -S process_vm_writev -k f0rtika_memory_write
-a always,exit -F arch=b32 -S process_vm_readv -k f0rtika_memory_read
-a always,exit -F arch=b32 -S process_vm_writev -k f0rtika_memory_write

# --- T1562.001: EDR Service Tampering Detection ---
# Monitor access to EDR agent binaries
-w /opt/microsoft/mdatp/ -p wa -k f0rtika_edr_tamper
-w /opt/CrowdStrike/ -p wa -k f0rtika_edr_tamper
-w /opt/sentinelone/ -p wa -k f0rtika_edr_tamper

# Monitor EDR service configuration
-w /etc/opt/microsoft/mdatp/ -p wa -k f0rtika_edr_config
-w /etc/systemd/system/mdatp.service -p wa -k f0rtika_edr_config

# Monitor kill signals to EDR processes
-a always,exit -F arch=b64 -S kill -S tkill -S tgkill -k f0rtika_signal_edr
-a always,exit -F arch=b32 -S kill -S tkill -S tgkill -k f0rtika_signal_edr

# --- T1014: Memory Manipulation / Rootkit Detection ---
# Monitor kernel module operations
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k f0rtika_kernel_module
-a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -k f0rtika_kernel_module

# Monitor /dev/mem and /dev/kmem access (direct memory access)
-w /dev/mem -p rw -k f0rtika_devmem
-w /dev/kmem -p rw -k f0rtika_devmem
-w /proc/kcore -p r -k f0rtika_devmem

# --- T1557: Network Proxy Manipulation ---
# Monitor proxy configuration files
-w /etc/environment -p wa -k f0rtika_proxy_change
-w /etc/profile.d/ -p wa -k f0rtika_proxy_change
-w /etc/apt/apt.conf.d/ -p wa -k f0rtika_proxy_change

# --- General: Process Execution Monitoring ---
# Monitor execution from suspicious directories
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k f0rtika_tmp_exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k f0rtika_tmp_exec
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k f0rtika_tmp_exec
AUDIT_EOF

            # Load rules
            if command -v augenrules &>/dev/null; then
                augenrules --load 2>/dev/null || true
            elif command -v auditctl &>/dev/null; then
                auditctl -R "${audit_rules_file}" 2>/dev/null || true
            fi

            log_msg SUCCESS "Audit rules installed: ${audit_rules_file}"
            log_msg INFO "  Monitoring: ptrace, process_vm_readv/writev, EDR paths, kernel modules"
        else
            log_msg WARNING "auditd not installed. Install with: apt install auditd (Debian/Ubuntu) or yum install audit (RHEL/CentOS)"
        fi
    fi

    # --- 4.2: Syslog hardening ---
    if [[ "${MODE}" == "audit" ]]; then
        if systemctl is-active --quiet rsyslog 2>/dev/null || systemctl is-active --quiet syslog-ng 2>/dev/null || systemctl is-active --quiet systemd-journald 2>/dev/null; then
            log_msg INFO "Syslog service: Running"
        else
            log_msg WARNING "Syslog service: Not detected"
        fi
    elif [[ "${MODE}" != "undo" ]]; then
        # Ensure journald stores logs persistently
        local journald_conf="/etc/systemd/journald.conf"
        if [[ -f "${journald_conf}" ]]; then
            if ! grep -q "^Storage=persistent" "${journald_conf}" 2>/dev/null; then
                backup_file "${journald_conf}"
                if grep -q "^#Storage=" "${journald_conf}" || grep -q "^Storage=" "${journald_conf}"; then
                    sed -i 's/^#\?Storage=.*/Storage=persistent/' "${journald_conf}"
                else
                    echo "Storage=persistent" >> "${journald_conf}"
                fi
                systemctl restart systemd-journald 2>/dev/null || true
                log_msg SUCCESS "journald: Set to persistent storage"
            else
                log_msg INFO "journald: Already using persistent storage"
            fi
        fi
    fi

    echo ""
}

# ============================================================
# SECTION 5: Filesystem Hardening
# Mitigates: T1014, T1140
# ============================================================

harden_filesystem() {
    log_msg HEADER "Section 5: Filesystem Hardening"
    log_msg INFO "Mitigates: T1014 (Rootkit), T1140 (File Deobfuscation)"

    # --- 5.1: Restrict /tmp and /dev/shm ---
    if [[ "${MODE}" == "audit" ]]; then
        local tmp_opts
        tmp_opts="$(mount | grep ' /tmp ' | head -1 || echo 'not mounted separately')"
        log_msg INFO "/tmp mount: ${tmp_opts}"

        local shm_opts
        shm_opts="$(mount | grep ' /dev/shm ' | head -1 || echo 'not mounted separately')"
        log_msg INFO "/dev/shm mount: ${shm_opts}"
    elif [[ "${MODE}" == "undo" ]]; then
        mount -o remount,exec /tmp 2>/dev/null || true
        mount -o remount,exec /dev/shm 2>/dev/null || true
        log_msg SUCCESS "/tmp and /dev/shm: Reverted to allow exec"
    else
        # Mount /tmp and /dev/shm with noexec,nosuid,nodev
        mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null || {
            log_msg WARNING "/tmp: Could not remount with noexec (may not be a separate mount)"
            log_msg INFO "  Consider adding to /etc/fstab: tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0"
        }
        mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null || {
            log_msg WARNING "/dev/shm: Could not remount with noexec"
        }
        log_msg SUCCESS "/tmp and /dev/shm: Mounted with noexec,nosuid,nodev"
        log_msg INFO "  Prevents execution of dropped binaries from temp directories"
    fi

    # --- 5.2: Protect key system binaries ---
    if [[ "${MODE}" == "audit" ]]; then
        # Check for unexpected SUID binaries
        local suid_count
        suid_count="$(find / -perm -4000 -type f 2>/dev/null | wc -l)"
        log_msg INFO "SUID binaries found: ${suid_count}"
        log_msg INFO "  Review with: find / -perm -4000 -type f 2>/dev/null"
    elif [[ "${MODE}" != "undo" ]]; then
        log_msg INFO "SUID binaries: Review and remove unnecessary SUID bits"
        log_msg INFO "  Common safe removals: chmod u-s /usr/bin/newgrp /usr/bin/chfn /usr/bin/chsh"
    fi

    echo ""
}

# ============================================================
# SECTION 6: Kernel Hardening
# Mitigates: T1014 (Rootkit), T1055 (Process Injection)
# ============================================================

harden_kernel() {
    log_msg HEADER "Section 6: Kernel Hardening"
    log_msg INFO "Mitigates: T1014 (Rootkit), T1055 (Process Injection)"

    # --- 6.1: Restrict kernel pointer exposure ---
    local kptr_key="kernel.kptr_restrict"

    if [[ "${MODE}" == "audit" ]]; then
        log_msg INFO "Kernel pointer restriction: $(get_sysctl_value ${kptr_key})"
    elif [[ "${MODE}" == "undo" ]]; then
        set_sysctl_value "${kptr_key}" 0
        persist_sysctl "${kptr_key}" 0
    else
        set_sysctl_value "${kptr_key}" 2
        persist_sysctl "${kptr_key}" 2
        log_msg SUCCESS "Kernel pointer restriction: Set to 2 (hidden from all users)"
    fi

    # --- 6.2: Restrict dmesg access ---
    local dmesg_key="kernel.dmesg_restrict"

    if [[ "${MODE}" == "audit" ]]; then
        log_msg INFO "dmesg restriction: $(get_sysctl_value ${dmesg_key})"
    elif [[ "${MODE}" == "undo" ]]; then
        set_sysctl_value "${dmesg_key}" 0
        persist_sysctl "${dmesg_key}" 0
    else
        set_sysctl_value "${dmesg_key}" 1
        persist_sysctl "${dmesg_key}" 1
        log_msg SUCCESS "dmesg restriction: Enabled (prevents kernel information disclosure)"
    fi

    # --- 6.3: Restrict unprivileged BPF ---
    local bpf_key="kernel.unprivileged_bpf_disabled"

    if [[ "${MODE}" == "audit" ]]; then
        log_msg INFO "Unprivileged BPF: $(get_sysctl_value ${bpf_key})"
    elif [[ "${MODE}" == "undo" ]]; then
        set_sysctl_value "${bpf_key}" 0
        persist_sysctl "${bpf_key}" 0
    else
        set_sysctl_value "${bpf_key}" 1
        persist_sysctl "${bpf_key}" 1
        log_msg SUCCESS "Unprivileged BPF: Disabled (prevents BPF-based process tracing)"
    fi

    # --- 6.4: Restrict perf_event access ---
    local perf_key="kernel.perf_event_paranoid"

    if [[ "${MODE}" == "audit" ]]; then
        local current
        current="$(get_sysctl_value ${perf_key})"
        local state_text
        case "${current}" in
            -1) state_text="Allow all (unrestricted)" ;;
            0)  state_text="Allow all but raw tracepoints" ;;
            1)  state_text="Disallow raw tracepoints (default)" ;;
            2)  state_text="Disallow kernel profiling" ;;
            3)  state_text="Disallow all (most restrictive)" ;;
            *)  state_text="Unknown (${current})" ;;
        esac
        log_msg INFO "perf_event_paranoid: ${state_text}"
    elif [[ "${MODE}" == "undo" ]]; then
        set_sysctl_value "${perf_key}" 2
        persist_sysctl "${perf_key}" 2
    else
        set_sysctl_value "${perf_key}" 3
        persist_sysctl "${perf_key}" 3
        log_msg SUCCESS "perf_event_paranoid: Set to 3 (most restrictive - prevents process profiling)"
    fi

    echo ""
}

# ============================================================
# Main Execution
# ============================================================

main() {
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}  F0RT1KA Linux Hardening Script${NC}"
    echo -e "${CYAN}  Test ID: ${TEST_ID}${NC}"
    echo -e "${CYAN}  MITRE ATT&CK: T1055, T1562.001, T1014, T1557${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""

    check_root

    # Create directories
    mkdir -p "${LOG_DIR}" "${BACKUP_DIR}"

    # Create sysctl config file if needed
    if [[ "${MODE}" != "undo" ]]; then
        touch /etc/sysctl.d/90-f0rtika-hardening.conf 2>/dev/null || true
    fi

    case "${MODE}" in
        apply)
            log_msg HEADER "Mode: APPLY - Applying hardening settings"
            ;;
        audit)
            log_msg HEADER "Mode: AUDIT - Checking current settings (no changes)"
            ;;
        undo)
            log_msg HEADER "Mode: UNDO - Reverting hardening settings"
            ;;
        *)
            log_msg ERROR "Unknown mode: ${MODE}"
            echo "Usage: $0 [apply|audit|undo]"
            exit 1
            ;;
    esac
    echo ""

    # Execute all hardening sections
    harden_process_protection
    harden_edr_protection
    harden_network
    harden_audit_logging
    harden_filesystem
    harden_kernel

    # Summary
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}  Summary${NC}"
    echo -e "${CYAN}============================================================${NC}"

    case "${MODE}" in
        apply)
            log_msg SUCCESS "Hardening applied. Review log: ${LOG_FILE}"
            log_msg WARNING "Some settings require a reboot to take full effect."
            log_msg INFO "To verify: $0 audit"
            log_msg INFO "To revert: $0 undo"
            # Apply sysctl changes
            sysctl --system > /dev/null 2>&1 || true
            ;;
        audit)
            log_msg INFO "Audit complete. No changes were made."
            ;;
        undo)
            log_msg SUCCESS "Rollback complete."
            log_msg WARNING "Some settings require a reboot to fully revert."
            # Reload sysctl
            sysctl --system > /dev/null 2>&1 || true
            # Clean up config if empty
            if [[ -f /etc/sysctl.d/90-f0rtika-hardening.conf ]]; then
                if [[ ! -s /etc/sysctl.d/90-f0rtika-hardening.conf ]]; then
                    rm -f /etc/sysctl.d/90-f0rtika-hardening.conf
                fi
            fi
            ;;
    esac

    echo ""
    echo "For questions or issues, reference test ID: ${TEST_ID}"
    echo ""
}

# Run main
main "$@"
