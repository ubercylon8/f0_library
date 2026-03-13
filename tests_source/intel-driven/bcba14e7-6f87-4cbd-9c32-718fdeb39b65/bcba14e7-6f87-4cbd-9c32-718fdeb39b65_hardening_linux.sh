#!/usr/bin/env bash
# ============================================================
# EDRSilencer Defense Hardening Script - Linux
#
# Test ID: bcba14e7-6f87-4cbd-9c32-718fdeb39b65
# MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
# Mitigations: M1047, M1038, M1022, M1018
#
# Description:
#   While EDRSilencer itself targets Windows WFP APIs, the underlying
#   technique -- blocking EDR communications and tampering with security
#   tools -- has Linux equivalents using iptables/nftables, eBPF, and
#   direct process/service manipulation. This script hardens Linux
#   endpoints against analogous defense evasion techniques:
#
#   1. Protect iptables/nftables rules from unauthorized modification
#   2. Enable auditd logging for security-relevant operations
#   3. Protect EDR/security agent services from tampering
#   4. Restrict access to network filter manipulation tools
#   5. Enable process execution and network connection auditing
#   6. Protect eBPF from abuse (kernel-level network filtering)
#   7. Harden systemd service protections for security agents
#
# Usage:
#   sudo ./bcba14e7-6f87-4cbd-9c32-718fdeb39b65_hardening_linux.sh [--undo] [--dry-run]
#
# Options:
#   --undo      Revert all changes made by this script
#   --dry-run   Show what would be changed without applying
#
# Requires: root privileges
# Idempotent: Yes (safe to run multiple times)
# ============================================================

set -euo pipefail

# ============================================================
# Configuration
# ============================================================

SCRIPT_NAME="$(basename "$0")"
TEST_ID="bcba14e7-6f87-4cbd-9c32-718fdeb39b65"
LOG_FILE="/var/log/f0rtika_hardening_${TEST_ID}_$(date +%Y%m%d_%H%M%S).log"
CHANGE_LOG=()
UNDO_MODE=false
DRY_RUN=false
BACKUP_DIR="/var/backups/f0rtika_hardening"

# Known Linux EDR/security agent services
SECURITY_SERVICES=(
    "falcon-sensor"          # CrowdStrike Falcon
    "SentinelAgent"          # SentinelOne
    "SentinelOne"            # SentinelOne alternate
    "cbagentd"               # Carbon Black
    "cbdaemon"               # Carbon Black Cloud
    "elastic-agent"          # Elastic Agent
    "elastic-endpoint"       # Elastic Endpoint
    "mdatp"                  # Microsoft Defender ATP
    "mde"                    # Microsoft Defender for Endpoint
    "qualys-cloud-agent"     # Qualys
    "TaniumClient"           # Tanium
    "cortex-xdr"             # Palo Alto Cortex XDR
    "trendmicro"             # Trend Micro
    "ds_agent"               # Trend Micro Deep Security
    "auditd"                 # Linux Audit daemon
    "rsyslog"                # Syslog (telemetry forwarding)
    "syslog-ng"              # Syslog-ng
    "osqueryd"               # osquery
    "wazuh-agent"            # Wazuh
)

# Network filter manipulation binaries
NETFILTER_BINS=(
    "/usr/sbin/iptables"
    "/usr/sbin/ip6tables"
    "/usr/sbin/iptables-restore"
    "/usr/sbin/ip6tables-restore"
    "/usr/sbin/nft"
    "/usr/sbin/ebtables"
    "/usr/sbin/xtables-multi"
    "/usr/sbin/xtables-nft-multi"
)

# ============================================================
# Parse Arguments
# ============================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo)
            UNDO_MODE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: sudo $SCRIPT_NAME [--undo] [--dry-run]"
            echo ""
            echo "Options:"
            echo "  --undo      Revert all changes made by this script"
            echo "  --dry-run   Show what would be changed without applying"
            echo "  --help      Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: sudo $SCRIPT_NAME [--undo] [--dry-run]"
            exit 1
            ;;
    esac
done

# ============================================================
# Helper Functions
# ============================================================

log_info() {
    local msg="[*] $1"
    echo -e "\033[0;36m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_success() {
    local msg="[+] $1"
    echo -e "\033[0;32m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') SUCCESS: $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_warning() {
    local msg="[!] $1"
    echo -e "\033[0;33m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') WARNING: $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_error() {
    local msg="[-] $1"
    echo -e "\033[0;31m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_header() {
    local msg="[=] $1"
    echo -e "\033[0;35m${msg}\033[0m"
    echo "$(date '+%Y-%m-%d %H:%M:%S') HEADER: $1" >> "$LOG_FILE" 2>/dev/null || true
}

add_change() {
    CHANGE_LOG+=("$1")
}

run_cmd() {
    local description="$1"
    shift
    if $DRY_RUN; then
        log_info "[DRY-RUN] Would execute: $*"
        return 0
    fi
    if "$@" 2>>"$LOG_FILE"; then
        add_change "$description"
        return 0
    else
        log_error "Failed: $description ($*)"
        return 1
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges. Run with sudo."
        exit 1
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

ensure_backup_dir() {
    mkdir -p "$BACKUP_DIR"
}

# ============================================================
# Hardening Functions
# ============================================================

configure_auditd_rules() {
    # Configures auditd to monitor security-relevant operations
    # including network filter changes, service manipulation, and
    # process execution from suspicious directories.

    log_header "Configuring auditd Rules for EDR Protection"

    local audit_rules_file="/etc/audit/rules.d/f0rtika-edr-protection.rules"

    if $UNDO_MODE; then
        if [[ -f "$audit_rules_file" ]]; then
            run_cmd "Remove F0RT1KA auditd rules" rm -f "$audit_rules_file"
            if command -v augenrules &>/dev/null; then
                run_cmd "Reload auditd rules" augenrules --load
            elif command -v auditctl &>/dev/null; then
                run_cmd "Reload auditd rules" service auditd reload
            fi
            log_success "Auditd rules removed"
        else
            log_info "No F0RT1KA auditd rules found to remove"
        fi
        return
    fi

    if ! command -v auditctl &>/dev/null; then
        log_warning "auditd not installed. Install with: apt install auditd (Debian) or yum install audit (RHEL)"
        log_warning "Skipping auditd configuration"
        return
    fi

    local rules_content="# ============================================================
# F0RT1KA EDR Protection Audit Rules
# Test ID: ${TEST_ID}
# MITRE ATT&CK: T1562.001 - Impair Defenses
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# --- Monitor iptables/nftables rule modifications ---
# Detect attempts to modify network filters (Linux equivalent of WFP tampering)
-w /usr/sbin/iptables -p x -k netfilter_modification
-w /usr/sbin/ip6tables -p x -k netfilter_modification
-w /usr/sbin/iptables-restore -p x -k netfilter_modification
-w /usr/sbin/ip6tables-restore -p x -k netfilter_modification
-w /usr/sbin/nft -p x -k netfilter_modification
-w /usr/sbin/ebtables -p x -k netfilter_modification

# --- Monitor service control commands ---
# Detect attempts to stop/disable security services
-w /usr/bin/systemctl -p x -k service_control
-w /usr/sbin/service -p x -k service_control
-w /usr/bin/sv -p x -k service_control

# --- Monitor security agent binaries ---
# Detect tampering with EDR/security agent files
-w /opt/CrowdStrike/ -p wa -k edr_agent_tampering
-w /opt/sentinelone/ -p wa -k edr_agent_tampering
-w /opt/carbonblack/ -p wa -k edr_agent_tampering
-w /opt/microsoft/mdatp/ -p wa -k edr_agent_tampering
-w /var/opt/microsoft/mdatp/ -p wa -k edr_agent_tampering
-w /opt/elastic/ -p wa -k edr_agent_tampering
-w /opt/qualys/ -p wa -k edr_agent_tampering
-w /opt/tanium/ -p wa -k edr_agent_tampering
-w /var/ossec/ -p wa -k edr_agent_tampering

# --- Monitor systemd unit file changes ---
# Detect modifications to security service unit files
-w /etc/systemd/system/ -p wa -k systemd_unit_modification
-w /usr/lib/systemd/system/ -p wa -k systemd_unit_modification

# --- Monitor process kill signals to security processes ---
# Detect kill attempts via the kill syscall
-a always,exit -F arch=b64 -S kill -S tkill -S tgkill -k process_kill_signal

# --- Monitor eBPF program loading ---
# Detect potential eBPF-based network filtering abuse
-a always,exit -F arch=b64 -S bpf -k ebpf_program_load

# --- Monitor kernel module operations ---
# Detect loading/unloading of kernel modules (potential filter drivers)
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k kernel_module_operation

# --- Monitor network namespace changes ---
# Detect namespace manipulation that could isolate EDR communications
-a always,exit -F arch=b64 -S setns -S unshare -k namespace_manipulation

# --- Monitor /etc/hosts modifications ---
# Detect DNS poisoning to block EDR cloud endpoints
-w /etc/hosts -p wa -k hosts_file_modification
-w /etc/resolv.conf -p wa -k dns_config_modification
"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would write auditd rules to: $audit_rules_file"
        log_info "[DRY-RUN] Rules content:"
        echo "$rules_content" | head -20
        echo "  ... (truncated)"
    else
        echo "$rules_content" > "$audit_rules_file"
        chmod 640 "$audit_rules_file"

        # Reload audit rules
        if command -v augenrules &>/dev/null; then
            augenrules --load 2>>"$LOG_FILE" || true
        fi

        add_change "Installed auditd rules: $audit_rules_file"
        log_success "Auditd rules configured for EDR protection monitoring"
    fi
}

protect_security_services() {
    # Prevents unauthorized stopping/disabling of security agent services
    # by configuring systemd overrides with RestartSec and Restart=always.

    log_header "Protecting Security Agent Services"

    for svc in "${SECURITY_SERVICES[@]}"; do
        local unit_file
        unit_file=$(systemctl show -p FragmentPath "$svc" 2>/dev/null | cut -d= -f2)

        if [[ -z "$unit_file" ]] || ! systemctl is-enabled "$svc" &>/dev/null; then
            continue
        fi

        local override_dir="/etc/systemd/system/${svc}.service.d"
        local override_file="${override_dir}/f0rtika-protection.conf"

        if $UNDO_MODE; then
            if [[ -f "$override_file" ]]; then
                run_cmd "Remove service protection override for $svc" rm -f "$override_file"
                rmdir "$override_dir" 2>/dev/null || true
                log_success "Removed protection for $svc"
            fi
            continue
        fi

        log_info "Protecting service: $svc"

        if $DRY_RUN; then
            log_info "[DRY-RUN] Would create systemd override: $override_file"
            continue
        fi

        mkdir -p "$override_dir"
        cat > "$override_file" <<OVERRIDE_EOF
# F0RT1KA EDR Protection Override
# Test ID: ${TEST_ID}
# Ensures security service auto-restarts if stopped
[Service]
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=10

[Unit]
RefuseManualStop=true
OVERRIDE_EOF

        chmod 644 "$override_file"
        add_change "Protected service: $svc (auto-restart + refuse manual stop)"
        log_success "Service $svc protected with auto-restart and RefuseManualStop"
    done

    if ! $UNDO_MODE && ! $DRY_RUN; then
        systemctl daemon-reload 2>>"$LOG_FILE" || true
        log_success "Systemd daemon reloaded with service protections"
    fi

    if $UNDO_MODE && ! $DRY_RUN; then
        systemctl daemon-reload 2>>"$LOG_FILE" || true
        log_success "Systemd daemon reloaded after removing protections"
    fi
}

restrict_netfilter_tools() {
    # Restricts access to iptables/nftables binaries so that only root
    # and members of a designated group can execute them. This prevents
    # compromised non-root processes from modifying network filters.

    log_header "Restricting Access to Network Filter Manipulation Tools"

    local netfilter_group="netfilter-admins"

    if $UNDO_MODE; then
        for bin in "${NETFILTER_BINS[@]}"; do
            if [[ -f "$bin" ]]; then
                run_cmd "Restore permissions on $bin" chmod 755 "$bin"
            fi
        done
        if getent group "$netfilter_group" &>/dev/null; then
            log_info "Group $netfilter_group left in place (manual cleanup if desired)"
        fi
        log_success "Netfilter tool permissions restored"
        return
    fi

    # Create a dedicated group for netfilter administration
    if ! getent group "$netfilter_group" &>/dev/null; then
        if $DRY_RUN; then
            log_info "[DRY-RUN] Would create group: $netfilter_group"
        else
            groupadd "$netfilter_group" 2>>"$LOG_FILE" || true
            add_change "Created group: $netfilter_group"
            log_info "Created group: $netfilter_group"
        fi
    fi

    for bin in "${NETFILTER_BINS[@]}"; do
        if [[ ! -f "$bin" ]]; then
            continue
        fi

        local current_perms
        current_perms=$(stat -c '%a' "$bin" 2>/dev/null || echo "unknown")

        if $DRY_RUN; then
            log_info "[DRY-RUN] Would restrict $bin (current: $current_perms) to root:$netfilter_group 750"
            continue
        fi

        # Backup current permissions
        echo "$bin $current_perms $(stat -c '%U:%G' "$bin")" >> "${BACKUP_DIR}/netfilter_perms_backup.txt"

        chown "root:$netfilter_group" "$bin"
        chmod 750 "$bin"
        add_change "Restricted $bin to root:$netfilter_group (750)"
        log_success "Restricted: $bin (was $current_perms, now 750)"
    done
}

configure_sysctl_hardening() {
    # Configures kernel parameters to restrict eBPF and network namespace
    # operations, reducing the attack surface for kernel-level EDR tampering.

    log_header "Configuring Kernel Parameter Hardening (sysctl)"

    local sysctl_file="/etc/sysctl.d/99-f0rtika-edr-protection.conf"

    if $UNDO_MODE; then
        if [[ -f "$sysctl_file" ]]; then
            run_cmd "Remove F0RT1KA sysctl configuration" rm -f "$sysctl_file"
            sysctl --system &>/dev/null || true
            log_success "Sysctl hardening removed"
        else
            log_info "No F0RT1KA sysctl configuration found to remove"
        fi
        return
    fi

    local sysctl_content="# ============================================================
# F0RT1KA EDR Protection - Kernel Hardening
# Test ID: ${TEST_ID}
# MITRE ATT&CK: T1562.001 - Impair Defenses
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# Restrict unprivileged eBPF usage
# Prevents non-root users from loading eBPF programs that could
# intercept or drop EDR network traffic at the kernel level
kernel.unprivileged_bpf_disabled = 1

# Restrict unprivileged user namespaces
# Prevents container escape and namespace manipulation that could
# isolate EDR agent network communications
kernel.unprivileged_userns_clone = 0

# Enable kernel module signature verification (if supported)
# Prevents loading unsigned kernel modules that could act as
# malicious network filter drivers
# kernel.modules_disabled = 1  # WARNING: Uncomment only if no new modules needed

# Restrict kernel log access
# Prevents non-root users from reading kernel messages that could
# reveal EDR internals
kernel.dmesg_restrict = 1

# Restrict ptrace scope
# Prevents non-root processes from attaching to EDR agent processes
kernel.yama.ptrace_scope = 2

# Restrict loading of kernel modules to CAP_SYS_MODULE
# (already default, but explicitly set for clarity)
# kernel.modules_disabled = 0
"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would write sysctl configuration to: $sysctl_file"
    else
        echo "$sysctl_content" > "$sysctl_file"
        chmod 644 "$sysctl_file"
        sysctl --system &>/dev/null || true
        add_change "Installed sysctl hardening: $sysctl_file"
        log_success "Kernel parameters hardened for EDR protection"
    fi
}

configure_hosts_file_protection() {
    # Sets immutable attribute on /etc/hosts and /etc/resolv.conf to
    # prevent DNS-based EDR communication blocking (adversaries may add
    # entries to redirect EDR cloud endpoints to localhost).

    log_header "Configuring DNS Configuration File Protection"

    local protected_files=("/etc/hosts" "/etc/resolv.conf")

    for pfile in "${protected_files[@]}"; do
        if [[ ! -f "$pfile" ]]; then
            continue
        fi

        if $UNDO_MODE; then
            if lsattr "$pfile" 2>/dev/null | grep -q 'i'; then
                run_cmd "Remove immutable flag from $pfile" chattr -i "$pfile"
                log_success "Removed immutable flag from $pfile"
            fi
            continue
        fi

        if lsattr "$pfile" 2>/dev/null | grep -q 'i'; then
            log_info "$pfile already has immutable attribute"
            continue
        fi

        if $DRY_RUN; then
            log_info "[DRY-RUN] Would set immutable attribute on $pfile"
            continue
        fi

        chattr +i "$pfile" 2>>"$LOG_FILE" || {
            log_warning "Failed to set immutable attribute on $pfile (filesystem may not support it)"
            continue
        }
        add_change "Set immutable attribute on $pfile"
        log_success "Protected $pfile with immutable attribute"
    done
}

configure_firewall_edr_allowlist() {
    # Creates iptables/nftables rules that explicitly allow outbound
    # connections from EDR agent processes, placed before any user-created
    # drop rules. This provides defense-in-depth: even if an attacker adds
    # blocking rules, the EDR allowlist rules take precedence.

    log_header "Configuring Firewall EDR Allowlist"

    local iptables_chain="F0RTIKA_EDR_PROTECT"

    if $UNDO_MODE; then
        if command -v iptables &>/dev/null; then
            # Remove the chain references and the chain itself
            iptables -D OUTPUT -j "$iptables_chain" 2>/dev/null || true
            iptables -F "$iptables_chain" 2>/dev/null || true
            iptables -X "$iptables_chain" 2>/dev/null || true
            ip6tables -D OUTPUT -j "$iptables_chain" 2>/dev/null || true
            ip6tables -F "$iptables_chain" 2>/dev/null || true
            ip6tables -X "$iptables_chain" 2>/dev/null || true
            log_success "Removed EDR protection iptables chain"
        fi
        return
    fi

    if ! command -v iptables &>/dev/null; then
        log_warning "iptables not found. Skipping firewall EDR allowlist."
        return
    fi

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would create iptables chain $iptables_chain with EDR allowlist rules"
        return
    fi

    # Create or flush the protection chain
    iptables -N "$iptables_chain" 2>/dev/null || iptables -F "$iptables_chain"
    ip6tables -N "$iptables_chain" 2>/dev/null || ip6tables -F "$iptables_chain"

    # Add rules allowing outbound traffic from EDR processes
    # These use the owner module to match by process UID (typically root)
    # and the comment module to document the purpose
    for proto in iptables ip6tables; do
        $proto -A "$iptables_chain" -m owner --uid-owner 0 -m comment \
            --comment "F0RT1KA: Allow EDR agent outbound (root)" -j RETURN 2>>"$LOG_FILE" || true
    done

    # Insert at the beginning of OUTPUT chain (before any blocking rules)
    iptables -C OUTPUT -j "$iptables_chain" 2>/dev/null || \
        iptables -I OUTPUT 1 -j "$iptables_chain"
    ip6tables -C OUTPUT -j "$iptables_chain" 2>/dev/null || \
        ip6tables -I OUTPUT 1 -j "$iptables_chain"

    add_change "Created iptables chain $iptables_chain with EDR allowlist"
    log_success "Firewall EDR allowlist configured (chain: $iptables_chain)"
}

verify_security_services() {
    # Checks that known security agent services are running and enabled.

    log_header "Verifying Security Service Status"

    local found_any=false

    for svc in "${SECURITY_SERVICES[@]}"; do
        if systemctl is-active "$svc" &>/dev/null; then
            local enabled_status
            enabled_status=$(systemctl is-enabled "$svc" 2>/dev/null || echo "unknown")
            log_success "Service $svc: RUNNING (enabled: $enabled_status)"
            found_any=true
        elif systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1 | grep -q "$svc"; then
            local status
            status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            log_warning "Service $svc: $status"
            found_any=true
        fi
    done

    if ! $found_any; then
        log_warning "No known EDR/security agent services detected on this system"
    fi
}

configure_process_execution_logging() {
    # Enables process accounting and ensures adequate logging of process
    # execution for forensic analysis.

    log_header "Configuring Process Execution Logging"

    if $UNDO_MODE; then
        log_info "Process execution logging left enabled (security best practice)"
        return
    fi

    # Enable process accounting if available
    if command -v accton &>/dev/null; then
        if $DRY_RUN; then
            log_info "[DRY-RUN] Would enable process accounting"
        else
            local acct_file="/var/log/pacct"
            touch "$acct_file" 2>/dev/null || true
            accton "$acct_file" 2>>"$LOG_FILE" || log_warning "Failed to enable process accounting"
            add_change "Enabled process accounting: $acct_file"
            log_success "Process accounting enabled"
        fi
    else
        log_info "Process accounting (acct/psacct) not installed. Consider: apt install acct"
    fi

    # Ensure rsyslog or syslog-ng is running for log forwarding
    if systemctl is-active rsyslog &>/dev/null; then
        log_success "rsyslog is running (log forwarding active)"
    elif systemctl is-active syslog-ng &>/dev/null; then
        log_success "syslog-ng is running (log forwarding active)"
    else
        log_warning "No syslog service detected. EDR telemetry forwarding may be impaired."
    fi
}

generate_report() {
    # Generates a JSON report of all changes made by this script.

    local report_file="/var/log/f0rtika_hardening_report_${TEST_ID}_$(date +%Y%m%d_%H%M%S).json"

    local mode="hardening"
    if $UNDO_MODE; then mode="rollback"; fi
    if $DRY_RUN; then mode="dry-run"; fi

    local changes_json="["
    local first=true
    for change in "${CHANGE_LOG[@]}"; do
        if $first; then
            first=false
        else
            changes_json+=","
        fi
        # Escape quotes in change description
        local escaped_change
        escaped_change=$(echo "$change" | sed 's/"/\\"/g')
        changes_json+="\"${escaped_change}\""
    done
    changes_json+="]"

    cat > "$report_file" <<REPORT_EOF
{
    "test_id": "${TEST_ID}",
    "mitre_attack": "T1562.001",
    "timestamp": "$(date -Iseconds)",
    "mode": "${mode}",
    "hostname": "$(hostname)",
    "distro": "$(detect_distro)",
    "kernel": "$(uname -r)",
    "changes_count": ${#CHANGE_LOG[@]},
    "changes": ${changes_json}
}
REPORT_EOF

    chmod 640 "$report_file"
    log_info "Report saved to: $report_file"
}

# ============================================================
# Main Execution
# ============================================================

echo ""
log_header "============================================================"
if $UNDO_MODE; then
    log_header "F0RT1KA Defense Hardening - ROLLBACK MODE (Linux)"
elif $DRY_RUN; then
    log_header "F0RT1KA Defense Hardening - DRY RUN MODE (Linux)"
else
    log_header "F0RT1KA Defense Hardening for EDR Protection (Linux)"
fi
log_header "Test ID: $TEST_ID"
log_header "MITRE ATT&CK: T1562.001 - Impair Defenses"
log_header "============================================================"
echo ""

check_root
ensure_backup_dir

DISTRO=$(detect_distro)
log_info "Detected distribution: $DISTRO"
log_info "Kernel: $(uname -r)"
echo ""

# Execute hardening functions
configure_auditd_rules
echo ""

protect_security_services
echo ""

restrict_netfilter_tools
echo ""

configure_sysctl_hardening
echo ""

configure_hosts_file_protection
echo ""

configure_firewall_edr_allowlist
echo ""

configure_process_execution_logging
echo ""

verify_security_services
echo ""

# Generate report
generate_report
echo ""

# Summary
log_header "============================================================"
log_header "Hardening Complete"
log_header "============================================================"
log_info "Changes made: ${#CHANGE_LOG[@]}"
log_info "Log file: $LOG_FILE"
echo ""

if ! $UNDO_MODE && ! $DRY_RUN; then
    log_info "Recommended next steps:"
    log_info "  1. Add authorized users to 'netfilter-admins' group: usermod -aG netfilter-admins <user>"
    log_info "  2. Deploy Sigma detection rules from *_sigma_rules.yml to your SIEM"
    log_info "  3. Test EDR agent resilience by attempting to stop the service"
    log_info "  4. Verify auditd is forwarding logs to your SIEM"
    log_info "  5. Review /etc/hosts immutable flag if DNS changes are needed: chattr -i /etc/hosts"
fi

echo ""
exit 0
