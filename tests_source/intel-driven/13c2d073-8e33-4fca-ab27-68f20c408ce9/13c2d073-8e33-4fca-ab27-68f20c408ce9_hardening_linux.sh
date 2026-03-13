#!/usr/bin/env bash
# ============================================================================
# DEFENSE GUIDANCE: Linux Hardening Script
# ============================================================================
# Test ID: 13c2d073-8e33-4fca-ab27-68f20c408ce9
# Test Name: APT33 Tickler Backdoor DLL Sideloading
# MITRE ATT&CK: T1566.001, T1574.002, T1547.001, T1053.005, T1036, T1071.001
# Created: 2026-03-13
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
#
# NOTE: The APT33 Tickler test targets Windows endpoints. This script provides
# cross-platform hardening for the equivalent Linux attack techniques:
# - Shared library hijacking (LD_PRELOAD / LD_LIBRARY_PATH abuse)
# - Cron/systemd persistence
# - Binary masquerading
# - Outbound C2 port blocking
#
# ============================================================================

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
STATE_FILE="/var/lib/f0rtika/hardening_apt33_state.json"
UNDO=false

# ============================================================================
# Parse Arguments
# ============================================================================
usage() {
    echo "Usage: $SCRIPT_NAME [--undo] [--dry-run]"
    echo ""
    echo "Options:"
    echo "  --undo     Revert all hardening changes"
    echo "  --dry-run  Show what would be done without making changes"
    exit 1
}

DRY_RUN=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo)   UNDO=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ============================================================================
# Helper Functions
# ============================================================================

info()    { echo -e "\033[0;36m[INFO]\033[0m $1"; }
success() { echo -e "\033[0;32m[OK]\033[0m $1"; }
warn()    { echo -e "\033[0;33m[WARN]\033[0m $1"; }
error()   { echo -e "\033[0;31m[ERR]\033[0m $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

run_cmd() {
    if $DRY_RUN; then
        info "[DRY-RUN] Would execute: $*"
    else
        "$@"
    fi
}

# ============================================================================
# 1. Shared Library Hijacking Protection (T1574.002 equivalent)
# ============================================================================

harden_library_loading() {
    info "=== Shared Library Hijacking Protection (T1574.002) ==="

    if $UNDO; then
        if [[ -f /etc/ld.so.conf.d/f0rtika-hardening.conf ]]; then
            run_cmd rm -f /etc/ld.so.conf.d/f0rtika-hardening.conf
            run_cmd ldconfig
            warn "Removed library loading hardening"
        fi
        return
    fi

    # Ensure LD_PRELOAD and LD_LIBRARY_PATH are not set system-wide
    # Check /etc/environment and /etc/profile.d/
    for f in /etc/environment /etc/profile.d/*.sh; do
        if [[ -f "$f" ]] && grep -q "LD_PRELOAD\|LD_LIBRARY_PATH" "$f" 2>/dev/null; then
            warn "Found LD_PRELOAD or LD_LIBRARY_PATH in $f - review manually"
        fi
    done

    # Set secure library search path permissions
    if [[ -d /usr/local/lib ]]; then
        run_cmd chmod 755 /usr/local/lib
        success "Secured /usr/local/lib permissions"
    fi

    # Ensure /etc/ld.so.preload has restricted permissions if it exists
    if [[ -f /etc/ld.so.preload ]]; then
        run_cmd chmod 644 /etc/ld.so.preload
        run_cmd chown root:root /etc/ld.so.preload
        success "Secured /etc/ld.so.preload permissions"
    fi

    success "Library loading hardening applied"
}

# ============================================================================
# 2. Cron and Systemd Persistence Hardening (T1053.005, T1547.001 equivalent)
# ============================================================================

harden_persistence_mechanisms() {
    info "=== Persistence Mechanism Hardening (T1053.005, T1547.001) ==="

    if $UNDO; then
        # Restore cron access
        if [[ -f /etc/cron.allow.f0rtika-backup ]]; then
            run_cmd mv /etc/cron.allow.f0rtika-backup /etc/cron.allow
            warn "Restored original cron.allow"
        fi
        return
    fi

    # Enable cron logging
    local cron_log="/etc/rsyslog.d/50-cron.conf"
    if [[ ! -f "$cron_log" ]]; then
        if ! $DRY_RUN; then
            echo "cron.*    /var/log/cron.log" > "$cron_log"
        fi
        success "Enabled cron logging to /var/log/cron.log"
    else
        info "Cron logging already configured"
    fi

    # Set restrictive permissions on crontab directories
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$dir" ]]; then
            run_cmd chmod 700 "$dir"
        fi
    done
    success "Restricted cron directory permissions to root only"

    # Monitor systemd user unit directories
    local systemd_dirs=(
        "/etc/systemd/system"
        "/usr/lib/systemd/system"
    )
    for dir in "${systemd_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            run_cmd chmod 755 "$dir"
            run_cmd chown root:root "$dir"
        fi
    done
    success "Secured systemd unit directories"

    # Enable auditd rules for persistence monitoring
    if command -v auditctl &>/dev/null; then
        run_cmd auditctl -w /etc/crontab -p wa -k persistence_cron
        run_cmd auditctl -w /etc/cron.d/ -p wa -k persistence_cron
        run_cmd auditctl -w /var/spool/cron/ -p wa -k persistence_cron
        run_cmd auditctl -w /etc/systemd/system/ -p wa -k persistence_systemd
        success "Added auditd watches for persistence directories"
    else
        warn "auditd not installed - skipping audit rules"
    fi
}

# ============================================================================
# 3. Outbound C2 Port Blocking (T1071.001)
# ============================================================================

block_c2_ports() {
    info "=== C2 Port Blocking (T1071.001) ==="

    local c2_ports=(808 880)
    local chain_name="F0RTIKA_C2_BLOCK"

    if $UNDO; then
        if iptables -L "$chain_name" &>/dev/null 2>&1; then
            run_cmd iptables -D OUTPUT -j "$chain_name" 2>/dev/null || true
            run_cmd iptables -F "$chain_name" 2>/dev/null || true
            run_cmd iptables -X "$chain_name" 2>/dev/null || true
            warn "Removed C2 port blocking iptables chain"
        fi
        # Also try nftables
        if command -v nft &>/dev/null; then
            run_cmd nft delete table inet f0rtika_c2_block 2>/dev/null || true
            warn "Removed C2 port blocking nftables table"
        fi
        return
    fi

    # Use iptables if available
    if command -v iptables &>/dev/null; then
        # Create chain if it does not exist
        if ! iptables -L "$chain_name" &>/dev/null 2>&1; then
            run_cmd iptables -N "$chain_name"
        fi

        for port in "${c2_ports[@]}"; do
            if ! iptables -C "$chain_name" -p tcp --dport "$port" -j DROP 2>/dev/null; then
                run_cmd iptables -A "$chain_name" -p tcp --dport "$port" -j DROP
                success "Blocked outbound TCP port $port (APT33 Tickler C2)"
            else
                info "Port $port already blocked"
            fi
        done

        # Attach chain to OUTPUT if not already attached
        if ! iptables -C OUTPUT -j "$chain_name" 2>/dev/null; then
            run_cmd iptables -A OUTPUT -j "$chain_name"
        fi

    elif command -v nft &>/dev/null; then
        # Use nftables as fallback
        if ! $DRY_RUN; then
            nft add table inet f0rtika_c2_block 2>/dev/null || true
            nft add chain inet f0rtika_c2_block output "{ type filter hook output priority 0; policy accept; }" 2>/dev/null || true
            for port in "${c2_ports[@]}"; do
                nft add rule inet f0rtika_c2_block output tcp dport "$port" drop 2>/dev/null || true
                success "Blocked outbound TCP port $port via nftables"
            done
        fi
    else
        warn "Neither iptables nor nft found - skipping firewall rules"
    fi
}

# ============================================================================
# 4. Binary Execution Auditing (T1036)
# ============================================================================

harden_binary_execution() {
    info "=== Binary Execution Auditing (T1036) ==="

    if $UNDO; then
        if command -v auditctl &>/dev/null; then
            run_cmd auditctl -d -a always,exit -F arch=b64 -S execve -k exec_monitoring 2>/dev/null || true
            warn "Removed execve audit rule"
        fi
        return
    fi

    if command -v auditctl &>/dev/null; then
        # Monitor all process executions
        run_cmd auditctl -a always,exit -F arch=b64 -S execve -k exec_monitoring
        success "Added execve audit rule for process creation monitoring"

        # Monitor /tmp and user writable execution
        run_cmd auditctl -w /tmp -p x -k tmp_exec
        run_cmd auditctl -w /var/tmp -p x -k tmp_exec
        run_cmd auditctl -w /dev/shm -p x -k shm_exec
        success "Added execution monitoring for /tmp, /var/tmp, /dev/shm"
    else
        warn "auditd not available - install auditd for process monitoring"
    fi

    # Ensure noexec on /tmp if not already set (check fstab)
    if grep -q "/tmp" /etc/fstab 2>/dev/null; then
        if ! grep "/tmp" /etc/fstab | grep -q "noexec"; then
            warn "/tmp is NOT mounted with noexec - consider adding noexec mount option"
        else
            info "/tmp already has noexec mount option"
        fi
    else
        warn "/tmp not in /etc/fstab - consider mounting /tmp with noexec"
    fi
}

# ============================================================================
# 5. File Integrity Monitoring
# ============================================================================

setup_file_monitoring() {
    info "=== File Integrity Monitoring ==="

    if $UNDO; then
        info "File monitoring is non-destructive - no revert needed"
        return
    fi

    # Check for AIDE or similar
    if command -v aide &>/dev/null; then
        info "AIDE is available - ensure database is initialized: aide --init"
    elif command -v tripwire &>/dev/null; then
        info "Tripwire is available - ensure it is configured"
    else
        warn "No file integrity monitoring tool found"
        info "Recommended: Install AIDE (apt install aide) or OSSEC"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================"
echo "  APT33 Tickler - Linux Defense Hardening"
echo "  Test ID: 13c2d073-8e33-4fca-ab27-68f20c408ce9"
echo "============================================================"
echo ""

check_root

if $UNDO; then
    warn "REVERTING hardening changes..."
else
    info "APPLYING hardening settings..."
fi
echo ""

harden_library_loading
echo ""
harden_persistence_mechanisms
echo ""
block_c2_ports
echo ""
harden_binary_execution
echo ""
setup_file_monitoring
echo ""

echo "============================================================"
if $UNDO; then
    warn "Hardening reverted."
else
    success "Hardening complete."
fi
echo "============================================================"
echo ""
