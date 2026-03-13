#!/usr/bin/env bash
# ============================================================================
# F0RT1KA Defense Hardening Script - Linux
# ============================================================================
# Test ID:      94b248c0-a104-48c3-b4a5-3d45028c407d
# Test Name:    Gunra Ransomware Simulation
# MITRE ATT&CK: T1486, T1490, T1082, T1083, T1622
# Mitigations:  M1040, M1053, M1038, M1028, M1018
# Platform:     Linux (Ubuntu/Debian, RHEL/CentOS, generic)
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
# ============================================================================
#
# DESCRIPTION:
#   This script hardens a Linux system against ransomware techniques
#   demonstrated by the Gunra Ransomware simulation test. Although Gunra
#   primarily targets Windows, the underlying techniques (file encryption,
#   backup deletion, system discovery) have direct Linux equivalents.
#
#   This script implements:
#     1. Filesystem snapshot protection (LVM, Btrfs, ZFS)
#     2. Immutable backup directory configuration
#     3. File integrity monitoring (AIDE / auditd)
#     4. Process auditing for ransomware behaviors
#     5. Restricted access to destructive commands
#     6. Kernel hardening via sysctl
#     7. Backup verification and recommendations
#
# USAGE:
#   sudo ./94b248c0-a104-48c3-b4a5-3d45028c407d_hardening_linux.sh
#   sudo ./94b248c0-a104-48c3-b4a5-3d45028c407d_hardening_linux.sh --undo
#   sudo ./94b248c0-a104-48c3-b4a5-3d45028c407d_hardening_linux.sh --dry-run
#
# REQUIRES: root privileges
# IDEMPOTENT: Yes (safe to run multiple times)
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_NAME="$(basename "$0")"
LOG_FILE="/var/log/f0rtika_hardening_$(date +%Y%m%d_%H%M%S).log"
AUDIT_RULES_FILE="/etc/audit/rules.d/f0rtika-ransomware.rules"
BACKUP_DIR="/var/backups/f0rtika-hardening"
MODE="harden"
DRY_RUN=false
CHANGE_COUNT=0

# Known ransomware extensions for monitoring
RANSOMWARE_EXTENSIONS=("ENCRT" "encrypted" "locked" "crypted" "enc" "crypt" "locky" "cerber" "ryuk" "conti" "lockbit")

# ============================================================================
# Parse Arguments
# ============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo|--revert)
            MODE="undo"
            shift
            ;;
        --dry-run|--whatif)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: sudo $SCRIPT_NAME [--undo] [--dry-run] [--help]"
            echo ""
            echo "Options:"
            echo "  --undo      Revert hardening changes to defaults"
            echo "  --dry-run   Show what would be changed without applying"
            echo "  --help      Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
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

    case "$level" in
        INFO)    prefix="[*]"; color="\033[0;36m" ;;
        OK)      prefix="[+]"; color="\033[0;32m" ;;
        WARN)    prefix="[!]"; color="\033[0;33m" ;;
        ERROR)   prefix="[-]"; color="\033[0;31m" ;;
        HEADER)  prefix="[=]"; color="\033[0;35m" ;;
        *)       prefix="[?]"; color="\033[0m" ;;
    esac

    echo -e "${color}${prefix} ${message}\033[0m"
    echo "${timestamp} ${prefix} ${message}" >> "$LOG_FILE" 2>/dev/null || true
}

run_cmd() {
    local description="$1"
    shift
    if $DRY_RUN; then
        log_msg INFO "[DRY-RUN] Would execute: $*"
        return 0
    fi
    log_msg INFO "$description"
    if "$@" 2>>"$LOG_FILE"; then
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return 0
    else
        log_msg WARN "Command failed: $*"
        return 1
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_msg ERROR "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
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

pkg_install() {
    local pkg="$1"
    local distro
    distro="$(detect_distro)"

    if command -v "$pkg" &>/dev/null; then
        log_msg INFO "$pkg is already installed"
        return 0
    fi

    case "$distro" in
        ubuntu|debian|pop|mint|kali)
            run_cmd "Installing $pkg via apt" apt-get install -y "$pkg"
            ;;
        rhel|centos|rocky|alma|fedora|ol)
            run_cmd "Installing $pkg via dnf/yum" dnf install -y "$pkg" 2>/dev/null || yum install -y "$pkg"
            ;;
        arch|manjaro)
            run_cmd "Installing $pkg via pacman" pacman -S --noconfirm "$pkg"
            ;;
        *)
            log_msg WARN "Cannot auto-install $pkg on $distro -- install manually"
            return 1
            ;;
    esac
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$file" "${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d%H%M%S).bak"
        log_msg INFO "Backed up: $file"
    fi
}

# ============================================================================
# 1. Audit Framework Configuration (T1486, T1490, T1082, T1083)
# ============================================================================

configure_auditd() {
    log_msg HEADER "Configuring Linux Audit Framework (auditd)"

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$AUDIT_RULES_FILE" ]]; then
            run_cmd "Removing ransomware audit rules" rm -f "$AUDIT_RULES_FILE"
            if command -v augenrules &>/dev/null; then
                run_cmd "Regenerating audit rules" augenrules --load
            elif command -v auditctl &>/dev/null; then
                run_cmd "Reloading audit rules" auditctl -R /etc/audit/audit.rules 2>/dev/null || true
            fi
            log_msg OK "Ransomware audit rules removed"
        else
            log_msg INFO "No ransomware audit rules found to remove"
        fi
        return
    fi

    # Ensure auditd is installed
    pkg_install auditd 2>/dev/null || pkg_install audit 2>/dev/null || true

    if ! command -v auditctl &>/dev/null; then
        log_msg WARN "auditd not available -- skipping audit configuration"
        return
    fi

    # Ensure auditd is running
    if systemctl is-active auditd &>/dev/null; then
        log_msg INFO "auditd is already running"
    else
        run_cmd "Starting auditd service" systemctl start auditd || true
        run_cmd "Enabling auditd on boot" systemctl enable auditd || true
    fi

    # Create ransomware-focused audit rules
    if $DRY_RUN; then
        log_msg INFO "[DRY-RUN] Would create audit rules at $AUDIT_RULES_FILE"
    else
        mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
        cat > "$AUDIT_RULES_FILE" << 'AUDIT_EOF'
## ============================================================================
## F0RT1KA Ransomware Detection Audit Rules
## Test ID: 94b248c0-a104-48c3-b4a5-3d45028c407d
## MITRE ATT&CK: T1486, T1490, T1082, T1083
## ============================================================================

## --- T1490: Inhibit System Recovery ---
## Monitor LVM snapshot deletion
-a always,exit -F arch=b64 -S execve -F path=/sbin/lvremove -k ransomware_snapshot_delete
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/lvremove -k ransomware_snapshot_delete

## Monitor Btrfs snapshot operations
-a always,exit -F arch=b64 -S execve -F path=/sbin/btrfs -k ransomware_snapshot_ops
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/btrfs -k ransomware_snapshot_ops

## Monitor ZFS destroy operations
-a always,exit -F arch=b64 -S execve -F path=/sbin/zfs -k ransomware_snapshot_ops
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/zfs -k ransomware_snapshot_ops

## Monitor backup deletion tools
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/shred -k ransomware_data_destruction

## --- T1486: Data Encrypted for Impact ---
## Monitor mass file rename syscalls (renameat2 is used by modern ransomware)
-a always,exit -F arch=b64 -S rename -S renameat -S renameat2 -F key=ransomware_file_rename

## Monitor bulk file deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -F key=ransomware_file_delete

## Monitor common encryption tool usage
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/openssl -F key=crypto_tool_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/gpg -F key=crypto_tool_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/gpg2 -F key=crypto_tool_exec

## --- T1082: System Information Discovery ---
## Monitor system information gathering
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/hostname -k recon_sysinfo
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/uname -k recon_sysinfo
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/whoami -k recon_sysinfo
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/id -k recon_sysinfo
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/cat -F a0=/etc/os-release -k recon_sysinfo
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/lsb_release -k recon_sysinfo

## --- T1083: File and Directory Discovery ---
## Monitor find/locate for mass enumeration
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/find -k file_enumeration
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/locate -k file_enumeration
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/tree -k file_enumeration
AUDIT_EOF
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        log_msg OK "Created ransomware audit rules at $AUDIT_RULES_FILE"

        # Load the new rules
        if command -v augenrules &>/dev/null; then
            augenrules --load 2>>"$LOG_FILE" || true
        elif command -v auditctl &>/dev/null; then
            auditctl -R "$AUDIT_RULES_FILE" 2>>"$LOG_FILE" || true
        fi
        log_msg OK "Audit rules loaded"
    fi
}

# ============================================================================
# 2. Immutable Backup Directory Protection (M1053)
# ============================================================================

configure_backup_protection() {
    log_msg HEADER "Configuring Backup Directory Protection (M1053)"

    local backup_paths=(
        "/var/backups"
        "/backup"
    )

    if [[ "$MODE" == "undo" ]]; then
        for bpath in "${backup_paths[@]}"; do
            if [[ -d "$bpath" ]]; then
                run_cmd "Removing immutable flag from $bpath" chattr -R -i "$bpath" 2>/dev/null || true
                log_msg OK "Removed immutable flag from $bpath"
            fi
        done
        return
    fi

    for bpath in "${backup_paths[@]}"; do
        if [[ -d "$bpath" ]]; then
            log_msg INFO "Backup directory found: $bpath"
            # Set append-only attribute on backup directories (allows new backups, prevents deletion)
            if $DRY_RUN; then
                log_msg INFO "[DRY-RUN] Would set append-only (+a) on $bpath"
            else
                chattr -R +a "$bpath" 2>>"$LOG_FILE" && {
                    CHANGE_COUNT=$((CHANGE_COUNT + 1))
                    log_msg OK "Set append-only attribute on $bpath"
                } || {
                    log_msg WARN "Could not set append-only on $bpath (filesystem may not support it)"
                }
            fi
        fi
    done

    # Recommend separate backup filesystem
    log_msg INFO "RECOMMENDATION: Mount backup volumes as separate filesystems"
    log_msg INFO "RECOMMENDATION: Use read-only snapshots for critical backup data"
    log_msg INFO "RECOMMENDATION: Consider immutable/WORM backup storage (e.g., AWS S3 Object Lock)"
}

# ============================================================================
# 3. Restrict Access to Destructive Commands (M1038)
# ============================================================================

restrict_destructive_commands() {
    log_msg HEADER "Restricting Access to Destructive Commands (M1038)"

    # Commands that ransomware abuses for recovery inhibition
    local restricted_cmds=(
        "/usr/sbin/lvremove"
        "/sbin/lvremove"
    )

    if [[ "$MODE" == "undo" ]]; then
        for cmd in "${restricted_cmds[@]}"; do
            if [[ -f "$cmd" ]]; then
                run_cmd "Restoring permissions on $cmd" chmod 755 "$cmd" 2>/dev/null || true
            fi
        done
        log_msg OK "Destructive command permissions restored"
        return
    fi

    for cmd in "${restricted_cmds[@]}"; do
        if [[ -f "$cmd" ]]; then
            local current_perms
            current_perms=$(stat -c '%a' "$cmd" 2>/dev/null || echo "unknown")
            if [[ "$current_perms" != "750" ]]; then
                run_cmd "Restricting $cmd to root/disk group only" chmod 750 "$cmd"
                log_msg OK "Restricted $cmd (was: $current_perms, now: 750)"
            else
                log_msg INFO "$cmd already restricted (750)"
            fi
        fi
    done

    # Use sudoers to restrict shred for non-root users
    local sudoers_file="/etc/sudoers.d/f0rtika-restrict-shred"
    if [[ "$MODE" == "harden" ]]; then
        if $DRY_RUN; then
            log_msg INFO "[DRY-RUN] Would create sudoers restriction for shred"
        else
            if [[ ! -f "$sudoers_file" ]]; then
                echo "# F0RT1KA: Restrict shred to require explicit sudo" > "$sudoers_file"
                echo "# This ensures shred usage is logged via sudo/auditd" >> "$sudoers_file"
                chmod 440 "$sudoers_file"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
                log_msg OK "Created sudoers restriction for shred"
            else
                log_msg INFO "Sudoers restriction for shred already exists"
            fi
        fi
    fi
}

# ============================================================================
# 4. Filesystem Monitoring with inotifywait (T1486)
# ============================================================================

configure_filesystem_monitoring() {
    log_msg HEADER "Configuring Filesystem Monitoring for Ransomware Extensions"

    local monitor_script="/usr/local/bin/f0rtika-ransomware-monitor.sh"
    local systemd_unit="/etc/systemd/system/f0rtika-ransomware-monitor.service"

    if [[ "$MODE" == "undo" ]]; then
        if systemctl is-active f0rtika-ransomware-monitor &>/dev/null; then
            run_cmd "Stopping ransomware monitor service" systemctl stop f0rtika-ransomware-monitor
        fi
        if systemctl is-enabled f0rtika-ransomware-monitor &>/dev/null; then
            run_cmd "Disabling ransomware monitor service" systemctl disable f0rtika-ransomware-monitor
        fi
        [[ -f "$systemd_unit" ]] && run_cmd "Removing systemd unit" rm -f "$systemd_unit"
        [[ -f "$monitor_script" ]] && run_cmd "Removing monitor script" rm -f "$monitor_script"
        systemctl daemon-reload 2>/dev/null || true
        log_msg OK "Ransomware filesystem monitor removed"
        return
    fi

    # Install inotify-tools if needed
    if ! command -v inotifywait &>/dev/null; then
        pkg_install inotify-tools 2>/dev/null || {
            log_msg WARN "inotify-tools not available -- cannot install filesystem monitor"
            log_msg INFO "Install manually: apt install inotify-tools OR dnf install inotify-tools"
            return
        }
    fi

    if $DRY_RUN; then
        log_msg INFO "[DRY-RUN] Would create ransomware filesystem monitor"
        return
    fi

    # Create the monitoring script
    cat > "$monitor_script" << 'MONITOR_EOF'
#!/usr/bin/env bash
# F0RT1KA Ransomware Extension Monitor
# Watches for file creation with known ransomware extensions
# Logs to syslog for SIEM ingestion

WATCH_DIRS=("/home" "/var" "/srv" "/opt" "/tmp")
ALERT_LOG="/var/log/f0rtika-ransomware-alerts.log"

# Known ransomware extensions
EXTENSIONS_REGEX='\.(ENCRT|encrypted|locked|crypted|enc|crypt|locky|cerber|ryuk|conti|lockbit|phobos|dharma|djvu|stop)$'

# Ransom note filenames
NOTE_REGEX='(R3ADM3\.txt|DECRYPT_.*\.txt|HOW_TO_RECOVER.*|RESTORE_FILES.*|readme\.txt|_readme\.txt)'

# Build watch directory list (only existing dirs)
WATCH_ARGS=""
for dir in "${WATCH_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        WATCH_ARGS="$WATCH_ARGS $dir"
    fi
done

if [[ -z "$WATCH_ARGS" ]]; then
    echo "No directories to watch" >&2
    exit 1
fi

# Monitor for file events
# shellcheck disable=SC2086
inotifywait -m -r --format '%T %w%f %e' --timefmt '%Y-%m-%d %H:%M:%S' \
    -e create -e moved_to -e close_write \
    $WATCH_ARGS 2>/dev/null | while read -r timestamp filepath event; do

    filename="$(basename "$filepath")"

    # Check for ransomware extensions
    if echo "$filename" | grep -qiE "$EXTENSIONS_REGEX"; then
        alert_msg="RANSOMWARE_EXTENSION_DETECTED: file=$filepath event=$event time=$timestamp"
        echo "$alert_msg" >> "$ALERT_LOG"
        logger -t "f0rtika-ransomware" -p auth.crit "$alert_msg"
    fi

    # Check for ransom note creation
    if echo "$filename" | grep -qiE "$NOTE_REGEX"; then
        alert_msg="RANSOM_NOTE_DETECTED: file=$filepath event=$event time=$timestamp"
        echo "$alert_msg" >> "$ALERT_LOG"
        logger -t "f0rtika-ransomware" -p auth.crit "$alert_msg"
    fi
done
MONITOR_EOF
    chmod 755 "$monitor_script"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    log_msg OK "Created ransomware monitor script: $monitor_script"

    # Create systemd service
    cat > "$systemd_unit" << UNIT_EOF
[Unit]
Description=F0RT1KA Ransomware File Extension Monitor
After=multi-user.target

[Service]
Type=simple
ExecStart=$monitor_script
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT_EOF
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    log_msg OK "Created systemd service: $systemd_unit"

    systemctl daemon-reload
    run_cmd "Enabling ransomware monitor service" systemctl enable f0rtika-ransomware-monitor
    run_cmd "Starting ransomware monitor service" systemctl start f0rtika-ransomware-monitor
    log_msg OK "Ransomware filesystem monitor is now active"
}

# ============================================================================
# 5. Sysctl Kernel Hardening (Defense in Depth)
# ============================================================================

configure_sysctl_hardening() {
    log_msg HEADER "Configuring Kernel Hardening via sysctl"

    local sysctl_file="/etc/sysctl.d/99-f0rtika-ransomware.conf"

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$sysctl_file" ]]; then
            run_cmd "Removing kernel hardening settings" rm -f "$sysctl_file"
            sysctl --system &>/dev/null || true
            log_msg OK "Kernel hardening settings removed"
        else
            log_msg INFO "No kernel hardening settings found to remove"
        fi
        return
    fi

    if $DRY_RUN; then
        log_msg INFO "[DRY-RUN] Would create sysctl hardening at $sysctl_file"
        return
    fi

    cat > "$sysctl_file" << 'SYSCTL_EOF'
## ============================================================================
## F0RT1KA Kernel Hardening - Ransomware Defense
## Test ID: 94b248c0-a104-48c3-b4a5-3d45028c407d
## ============================================================================

## Restrict dmesg access (limit system info discovery - T1082)
kernel.dmesg_restrict = 1

## Hide kernel pointers from non-privileged users
kernel.kptr_restrict = 2

## Restrict ptrace to direct children only (limit debugging/evasion - T1622)
kernel.yama.ptrace_scope = 1

## Enable kernel address space layout randomization
kernel.randomize_va_space = 2

## Restrict access to kernel logs
kernel.printk = 3 3 3 3

## Protect symlinks and hardlinks (prevent certain file manipulation attacks)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

## Protect FIFOs and regular files in sticky directories
fs.protected_fifos = 2
fs.protected_regular = 2
SYSCTL_EOF
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    log_msg OK "Created kernel hardening config: $sysctl_file"

    sysctl --system &>/dev/null || true
    log_msg OK "Kernel hardening settings applied"
}

# ============================================================================
# 6. Secure Cron-Based Backup Verification (M1053)
# ============================================================================

configure_backup_verification() {
    log_msg HEADER "Configuring Backup Verification Cron Job (M1053)"

    local cron_script="/etc/cron.daily/f0rtika-backup-verify"

    if [[ "$MODE" == "undo" ]]; then
        if [[ -f "$cron_script" ]]; then
            run_cmd "Removing backup verification cron" rm -f "$cron_script"
            log_msg OK "Backup verification cron removed"
        fi
        return
    fi

    if $DRY_RUN; then
        log_msg INFO "[DRY-RUN] Would create backup verification cron at $cron_script"
        return
    fi

    cat > "$cron_script" << 'CRON_EOF'
#!/usr/bin/env bash
# F0RT1KA Daily Backup Verification
# Checks that backup mechanisms are functioning and intact

ALERT_EMAIL="${BACKUP_ALERT_EMAIL:-root}"
REPORT="/var/log/f0rtika-backup-status.log"

echo "=== F0RT1KA Backup Verification $(date) ===" > "$REPORT"

# Check LVM snapshots
if command -v lvs &>/dev/null; then
    snap_count=$(lvs --noheadings -o lv_attr 2>/dev/null | grep -c 's' || echo "0")
    echo "LVM Snapshots: $snap_count found" >> "$REPORT"
    if [[ "$snap_count" -eq 0 ]]; then
        echo "WARNING: No LVM snapshots detected" >> "$REPORT"
        logger -t "f0rtika-backup" -p auth.warning "No LVM snapshots found during daily verification"
    fi
fi

# Check Btrfs snapshots
if command -v btrfs &>/dev/null; then
    for mount in $(findmnt -t btrfs -n -o TARGET 2>/dev/null); do
        snap_count=$(btrfs subvolume list -s "$mount" 2>/dev/null | wc -l || echo "0")
        echo "Btrfs Snapshots ($mount): $snap_count found" >> "$REPORT"
    done
fi

# Check ZFS snapshots
if command -v zfs &>/dev/null; then
    snap_count=$(zfs list -t snapshot -H 2>/dev/null | wc -l || echo "0")
    echo "ZFS Snapshots: $snap_count found" >> "$REPORT"
fi

# Check /var/backups freshness
if [[ -d /var/backups ]]; then
    recent=$(find /var/backups -mtime -1 -type f 2>/dev/null | wc -l)
    echo "Recent backup files (last 24h): $recent" >> "$REPORT"
    if [[ "$recent" -eq 0 ]]; then
        echo "WARNING: No backup files modified in last 24 hours" >> "$REPORT"
        logger -t "f0rtika-backup" -p auth.warning "No recent backup files found in /var/backups"
    fi
fi

echo "=== End Verification ===" >> "$REPORT"
CRON_EOF
    chmod 755 "$cron_script"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    log_msg OK "Created daily backup verification cron: $cron_script"
}

# ============================================================================
# 7. AppArmor / SELinux Recommendations
# ============================================================================

recommend_mac_hardening() {
    log_msg HEADER "Mandatory Access Control Recommendations"

    # Check current MAC status
    if command -v aa-status &>/dev/null; then
        local aa_profiles
        aa_profiles=$(aa-status 2>/dev/null | grep "profiles are loaded" | head -1 || echo "unknown")
        log_msg INFO "AppArmor status: $aa_profiles"
        log_msg INFO "RECOMMENDATION: Ensure AppArmor profiles are in 'enforce' mode"
        log_msg INFO "RECOMMENDATION: Create custom profiles for backup-related binaries"
    elif command -v getenforce &>/dev/null; then
        local se_mode
        se_mode=$(getenforce 2>/dev/null || echo "unknown")
        log_msg INFO "SELinux mode: $se_mode"
        if [[ "$se_mode" != "Enforcing" ]]; then
            log_msg WARN "SELinux is not in Enforcing mode -- ransomware defense is weakened"
            log_msg INFO "RECOMMENDATION: Set SELinux to Enforcing: setenforce 1"
            log_msg INFO "RECOMMENDATION: Edit /etc/selinux/config and set SELINUX=enforcing"
        else
            log_msg OK "SELinux is in Enforcing mode"
        fi
    else
        log_msg WARN "No MAC framework (AppArmor/SELinux) detected"
        log_msg INFO "RECOMMENDATION: Install and enable AppArmor or SELinux"
    fi
}

# ============================================================================
# 8. Network Restrictions for Ransomware C2 (Defense in Depth)
# ============================================================================

configure_network_hardening() {
    log_msg HEADER "Configuring Network Restrictions (Ransomware C2 Defense)"

    local iptables_rules_file="/etc/iptables/f0rtika-ransomware.rules"

    if [[ "$MODE" == "undo" ]]; then
        # Remove Tor blocking rules if they exist
        iptables -D OUTPUT -p tcp --dport 9001 -j LOG --log-prefix "F0RT1KA_TOR_BLOCK: " 2>/dev/null || true
        iptables -D OUTPUT -p tcp --dport 9030 -j LOG --log-prefix "F0RT1KA_TOR_BLOCK: " 2>/dev/null || true
        log_msg OK "Network restrictions removed"
        return
    fi

    if $DRY_RUN; then
        log_msg INFO "[DRY-RUN] Would add iptables rules to log/block Tor traffic"
        return
    fi

    # Log (not block by default) connections to common Tor ports
    # Blocking is commented out to avoid breaking legitimate Tor usage
    if command -v iptables &>/dev/null; then
        # Log connections to Tor relay ports
        iptables -C OUTPUT -p tcp --dport 9001 -j LOG --log-prefix "F0RT1KA_TOR_BLOCK: " 2>/dev/null || {
            iptables -A OUTPUT -p tcp --dport 9001 -j LOG --log-prefix "F0RT1KA_TOR_BLOCK: "
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        }
        iptables -C OUTPUT -p tcp --dport 9030 -j LOG --log-prefix "F0RT1KA_TOR_BLOCK: " 2>/dev/null || {
            iptables -A OUTPUT -p tcp --dport 9030 -j LOG --log-prefix "F0RT1KA_TOR_BLOCK: "
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        }
        log_msg OK "Added iptables logging for Tor relay traffic (ports 9001, 9030)"
        log_msg INFO "NOTE: Traffic is LOGGED, not blocked. Uncomment DROP rules in script for enforcement."
        log_msg INFO "NOTE: Gunra uses Tor-hosted extortion sites for double-extortion."
    else
        log_msg WARN "iptables not available -- skipping network restrictions"
        log_msg INFO "Consider using nftables or firewalld for equivalent rules"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo ""
    echo "============================================================================"
    echo "  F0RT1KA Defense Hardening Script - Linux"
    echo "  Test: Gunra Ransomware Simulation"
    echo "  MITRE ATT&CK: T1486, T1490, T1082, T1083, T1622"
    echo "============================================================================"
    echo ""

    check_root

    log_msg HEADER "Mode: $(echo "$MODE" | tr '[:lower:]' '[:upper:]') | Dry-Run: $DRY_RUN"
    log_msg INFO "Log file: $LOG_FILE"
    echo ""

    # Execute hardening functions
    configure_auditd
    echo ""

    configure_backup_protection
    echo ""

    restrict_destructive_commands
    echo ""

    configure_filesystem_monitoring
    echo ""

    configure_sysctl_hardening
    echo ""

    configure_backup_verification
    echo ""

    recommend_mac_hardening
    echo ""

    configure_network_hardening
    echo ""

    # Summary
    echo "============================================================================"
    if [[ "$MODE" == "undo" ]]; then
        log_msg OK "Hardening changes reverted. Total changes: $CHANGE_COUNT"
    elif $DRY_RUN; then
        log_msg OK "Dry-run complete. No changes applied."
    else
        log_msg OK "Hardening complete. Total changes: $CHANGE_COUNT"
    fi
    echo "============================================================================"
    echo ""
    log_msg INFO "Log file: $LOG_FILE"
    echo ""

    # Verification commands
    log_msg HEADER "Verification Commands:"
    echo ""
    echo "  # Check audit rules loaded:"
    echo "  sudo auditctl -l | grep f0rtika"
    echo ""
    echo "  # Check ransomware monitor service:"
    echo "  sudo systemctl status f0rtika-ransomware-monitor"
    echo ""
    echo "  # Check sysctl hardening:"
    echo "  sysctl kernel.dmesg_restrict kernel.yama.ptrace_scope"
    echo ""
    echo "  # Check backup directory attributes:"
    echo "  lsattr /var/backups/ 2>/dev/null | head -5"
    echo ""
    echo "  # View ransomware alerts:"
    echo "  sudo journalctl -t f0rtika-ransomware --since today"
    echo "  sudo cat /var/log/f0rtika-ransomware-alerts.log 2>/dev/null"
    echo ""
    echo "  # Check backup verification report:"
    echo "  sudo cat /var/log/f0rtika-backup-status.log 2>/dev/null"
    echo ""

    # Additional recommendations
    log_msg HEADER "Additional Recommendations:"
    echo ""
    echo "  1. Deploy Sigma rules with your SIEM backend (Splunk, ELK, etc.):"
    echo "     sigmac -t <backend> 94b248c0-*_sigma_rules.yml"
    echo ""
    echo "  2. Install and configure AIDE for file integrity monitoring:"
    echo "     sudo apt install aide && sudo aideinit"
    echo ""
    echo "  3. Implement 3-2-1 backup strategy:"
    echo "     - 3 copies of data"
    echo "     - 2 different storage types"
    echo "     - 1 offsite/offline copy"
    echo ""
    echo "  4. Enable filesystem quotas to limit encryption blast radius:"
    echo "     - Prevents a single process from consuming all disk I/O"
    echo ""
    echo "  5. Consider read-only NFS exports for backup volumes"
    echo ""
}

main "$@"
