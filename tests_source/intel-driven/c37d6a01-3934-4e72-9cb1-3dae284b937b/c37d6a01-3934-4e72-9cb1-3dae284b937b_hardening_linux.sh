#!/bin/bash
# ============================================================
# Linux Hardening: Kothamine Tailcat Encrypted C2 Channel and
# Data Exfiltration (technique class)
# Test ID: c37d6a01-3934-4e72-9cb1-3dae284b937b
# MITRE ATT&CK: T1105, T1572, T1021.004, T1005, T1041
# Mitigations: M1031, M1037, M1042, M1035, M1030, M1057
#
# Hardens against the TECHNIQUE, not any specific tool:
#   1. auditd execution monitoring for dual-use tunneling tooling
#      (tailcat/tailscaled-style servers, ssh/scp spawned by
#      non-service parents) and downloads landing in temp paths
#   2. npm supply-chain hardening (ignore-scripts, lockfile-only
#      installs) — Kothamine's delivery vector
#   3. Egress alerting chain for Tailscale DERP / tunneling-SaaS
#      destinations where Tailscale is not sanctioned
#   4. noexec mount guidance for /tmp, /var/tmp, /dev/shm
#
# Usage:
#   sudo ./c37d6a01-3934-4e72-9cb1-3dae284b937b_hardening_linux.sh          # Apply
#   sudo ./c37d6a01-3934-4e72-9cb1-3dae284b937b_hardening_linux.sh --undo   # Revert
#   sudo ./c37d6a01-3934-4e72-9cb1-3dae284b937b_hardening_linux.sh --check  # Report state
#
# Requirements: root privileges
# Idempotent: Yes (safe to run multiple times)
# ============================================================

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
BACKUP_DIR="/var/backup/f0rtika-hardening"
LOG_FILE="/var/log/f0rtika-hardening.log"
AUDIT_RULES_FILE="/etc/audit/rules.d/f0rtika-tunnel-hardening.rules"
SYSCTL_FILE="/etc/sysctl.d/99-f0rtika-hardening.conf"
NPMRC_GLOBAL="/etc/npmrc"
EGRESS_CHAIN="F0RTIKA-TUNNEL-EGRESS"

# ============================================================
# Helpers
# ============================================================

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE" 2>/dev/null || echo "$1"; }
info() { log "[INFO] $1"; }
warn() { log "[WARN] $1"; }
ok()   { log "[ OK ] $1"; }
err()  { log "[ERR ] $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (use sudo)"
        exit 1
    fi
}

backup_file() {
    local file="$1"
    mkdir -p "$BACKUP_DIR"
    if [[ -f "$file" ]]; then
        cp -p "$file" "${BACKUP_DIR}/$(basename "$file").$(date +%s).bak"
        info "Backed up: $file"
    fi
}

# ============================================================
# 1. auditd — execution + download monitoring
# ============================================================

harden_auditd() {
    info "Configuring auditd rules for tunneling-tool execution and transfer tooling..."

    if [[ "$MODE" == "undo" ]]; then
        rm -f "$AUDIT_RULES_FILE"
        (augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true)
        ok "Removed auditd hardening rules"
        return
    fi

    if ! command -v auditctl >/dev/null 2>&1; then
        warn "auditd not installed — install it (apt/dnf install auditd) and re-run."
        return
    fi

    cat > "$AUDIT_RULES_FILE" << 'AUDIT'
# F0RT1KA tunnel-hardening audit rules — technique-focused (T1105/T1572/T1021.004/T1041)
#
# Rationale: encrypted tunnel C2 (tailcat/Tailscale DERP, ngrok, chisel, etc.)
# cannot be content-inspected. The durable host signal is EXECUTION:
# tunneling binaries running, ssh/scp being driven as tunnel transport, and
# downloaded executables landing in user-writable/temp paths.

# Executions of common dual-use tunneling tools (any path)
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/ssh -k tunnel_ssh_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/scp -k tunnel_scp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/sftp -k tunnel_sftp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/curl -k tool_download_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/wget -k tool_download_exec

# Executions out of user-writable / temp paths (downloaded-tool landing zone)
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k exec_from_tmp
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k exec_from_tmp
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k exec_from_tmp
-a always,exit -F arch=b64 -S execve -F dir=/home -k exec_from_home

# File creation in temp paths by download tooling is correlatable via
# the exec keys above plus: -k dropped_file below
-w /tmp -p w -k dropped_file_tmp
-w /var/tmp -p w -k dropped_file_tmp
AUDIT

    augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || \
        warn "Could not load audit rules immediately (auditd may need a restart)"
    ok "Applied auditd rules ($AUDIT_RULES_FILE)"
    warn "NOTE: exec-from-/home and /tmp watches are noisy on build hosts — scope to server fleets or tune exclusions for your environment."
}

# ============================================================
# 2. npm supply-chain hardening (delivery vector)
# ============================================================

harden_npm() {
    info "Hardening npm supply chain (install scripts, lockfile enforcement)..."

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$NPMRC_GLOBAL" ]]; then
            sed -i '/^ignore-scripts=true$/d' "$NPMRC_GLOBAL"
            sed -i '/^# F0RT1KA supply-chain hardening$/d' "$NPMRC_GLOBAL"
            ok "Removed ignore-scripts from $NPMRC_GLOBAL (per-user .npmrc entries are NOT touched — review manually)"
        else
            ok "No global npmrc changes to revert"
        fi
        return
    fi

    if ! command -v npm >/dev/null 2>&1; then
        info "npm not installed on this host — skipping npm hardening"
        return
    fi

    backup_file "$NPMRC_GLOBAL"
    touch "$NPMRC_GLOBAL"

    if ! grep -q '^ignore-scripts=true' "$NPMRC_GLOBAL" 2>/dev/null; then
        {
            echo "# F0RT1KA supply-chain hardening"
            echo "ignore-scripts=true"
        } >> "$NPMRC_GLOBAL"
        ok "Set ignore-scripts=true in $NPMRC_GLOBAL (blocks npm install-time code execution — Kothamine delivery vector)"
    else
        ok "ignore-scripts=true already set in $NPMRC_GLOBAL"
    fi

    warn "Also enforce in CI: use 'npm ci' (lockfile-only) instead of 'npm install'; route installs through a private registry with a quarantine window; review lockfile diffs in PRs."
    warn "Per-user ~/.npmrc can override the global file — audit developer workstations for user-level ignore-scripts=false."
}

# ============================================================
# 3. Egress alerting on tunneling infrastructure
# ============================================================

harden_egress() {
    info "Configuring egress alerting chain for tunneling-SaaS destinations..."

    if ! command -v iptables >/dev/null 2>&1; then
        warn "iptables not present — apply the equivalent egress policy at your firewall/proxy (see DEFENSE_GUIDANCE.md)"
        return
    fi

    if [[ "$MODE" == "undo" ]]; then
        iptables -D OUTPUT -j "$EGRESS_CHAIN" 2>/dev/null || true
        iptables -F "$EGRESS_CHAIN" 2>/dev/null || true
        iptables -X "$EGRESS_CHAIN" 2>/dev/null || true
        ok "Removed egress alerting chain"
        return
    fi

    # LOG-then-RETURN chain: alerts on outbound contact with Tailscale DERP /
    # control-plane destinations without breaking sanctioned use. Flip LOG to
    # DROP where Tailscale is confirmed unsanctioned.
    iptables -N "$EGRESS_CHAIN" 2>/dev/null || iptables -F "$EGRESS_CHAIN"

    # Hostname-based destinations resolve at load time; re-run after DNS changes.
    local host
    for host in login.tailscale.com controlplane.tailscale.com tailcat.dev derp1.tailscale.com; do
        iptables -C "$EGRESS_CHAIN" -d "$host" -j LOG --log-prefix "F0-TUNNEL-EGRESS: " --log-level 4 2>/dev/null \
            || iptables -A "$EGRESS_CHAIN" -d "$host" -j LOG --log-prefix "F0-TUNNEL-EGRESS: " --log-level 4 \
            || warn "Could not add egress alert for $host (DNS resolution failed?)"
    done

    iptables -C "$EGRESS_CHAIN" -j RETURN 2>/dev/null || iptables -A "$EGRESS_CHAIN" -j RETURN
    iptables -C OUTPUT -j "$EGRESS_CHAIN" 2>/dev/null || iptables -I OUTPUT -j "$EGRESS_CHAIN"

    ok "Applied egress alerting chain $EGRESS_CHAIN (LOG-only; switch LOG to DROP where Tailscale is unsanctioned)"
    warn "iptables rules are not persistent — save with iptables-save/netfilter-persistent or your distro's firewall service."
    warn "DERP relay hostnames are numerous and change; the authoritative list is the DERP map. Prefer proxy/DNS-layer blocks on *.tailscale.com relay hostnames over per-host iptables entries."
}

# ============================================================
# 4. noexec mounts (advisory + optional sysctl)
# ============================================================

harden_mounts() {
    info "Reviewing noexec mount posture for user-writable filesystems..."

    if [[ "$MODE" == "undo" ]]; then
        rm -f "$SYSCTL_FILE"
        sysctl --system > /dev/null 2>&1 || true
        ok "Removed sysctl hardening file (mount flags must be reverted in /etc/fstab manually if you changed them)"
        return
    fi

    # Advisory: report current state and write the recommended fstab guidance.
    # We do NOT remount live filesystems automatically — that can break running
    # services and is not safely reversible in one step.
    local mp opts
    for mp in /tmp /var/tmp /dev/shm; do
        opts="$(findmnt -no OPTIONS "$mp" 2>/dev/null || echo 'not-a-mountpoint')"
        if [[ "$opts" == *noexec* ]]; then
            ok "$mp already mounted noexec ($opts)"
        else
            warn "$mp is NOT noexec ($opts) — recommended: add noexec,nosuid,nodev to its /etc/fstab entry and remount."
        fi
    done

    cat > "$SYSCTL_FILE" << 'SYSCTL'
# F0RT1KA hardening — restrict kernel-level surfaces abused by tunneling tooling
# Unprivileged user namespaces are a common sandbox-escape/tunnel-enabler
# primitive; disable where container workloads do not require them.
kernel.unprivileged_userns_clone=0
SYSCTL
    sysctl --system > /dev/null 2>&1 || true
    ok "Wrote $SYSCTL_FILE (unprivileged user namespaces disabled where not needed)"
    warn "If this host runs rootless containers (podman/docker rootless), remove kernel.unprivileged_userns_clone=0 from $SYSCTL_FILE."
}

# ============================================================
# --check: report current state
# ============================================================

check_state() {
    info "Checking current hardening state..."
    echo ""
    echo "Linux Tunnel-C2 Hardening Status Report"
    echo "======================================="

    echo -n "auditd rules file: "
    [[ -f "$AUDIT_RULES_FILE" ]] && echo "present ($AUDIT_RULES_FILE)" || echo "ABSENT"

    echo -n "auditd loaded rules (tunnel keys): "
    auditctl -l 2>/dev/null | grep -cE 'tunnel_|exec_from_|dropped_file|tool_download' || echo "0 (or auditctl unavailable)"

    echo -n "npm ignore-scripts (global): "
    if [[ -f "$NPMRC_GLOBAL" ]] && grep -q '^ignore-scripts=true' "$NPMRC_GLOBAL"; then
        echo "enabled"
    else
        echo "NOT SET"
    fi

    echo -n "egress alert chain $EGRESS_CHAIN: "
    iptables -L "$EGRESS_CHAIN" -n >/dev/null 2>&1 && echo "present" || echo "ABSENT"

    echo "noexec posture:"
    for mp in /tmp /var/tmp /dev/shm; do
        echo "  $mp: $(findmnt -no OPTIONS "$mp" 2>/dev/null || echo 'not-a-mountpoint')"
    done

    echo -n "unprivileged userns: "
    cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "n/a"
}

# ============================================================
# Main
# ============================================================

check_root
mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR"

MODE="apply"
case "${1:-}" in
    --undo)     MODE="undo" ;;
    --check)    check_state; exit 0 ;;
    --help|-h)  echo "Usage: sudo $SCRIPT_NAME [--undo|--check]"; exit 0 ;;
esac

info "Mode: $MODE | Techniques: T1105, T1572, T1021.004, T1005, T1041"

harden_auditd
harden_npm
harden_egress
harden_mounts

ok "Hardening $MODE complete. Log: $LOG_FILE"
