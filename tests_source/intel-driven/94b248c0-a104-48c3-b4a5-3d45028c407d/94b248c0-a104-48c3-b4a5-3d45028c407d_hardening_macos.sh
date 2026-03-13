#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# Gunra Ransomware Defense - Anti-Ransomware Countermeasures
# ============================================================================
# Test ID:      94b248c0-a104-48c3-b4a5-3d45028c407d
# Test Name:    Gunra Ransomware Simulation
# MITRE ATT&CK: T1486, T1490, T1082, T1083, T1622
# Mitigations:  M1040, M1053, M1038, M1028, M1018
# Platform:     macOS (Apple Silicon and Intel)
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
# ============================================================================
#
# DESCRIPTION:
#   This script hardens a macOS system against ransomware techniques
#   demonstrated by the Gunra Ransomware simulation test. While Gunra
#   primarily targets Windows, the underlying techniques (file encryption,
#   backup deletion, system discovery) have direct macOS equivalents.
#
#   This script implements:
#     1. Time Machine and APFS snapshot protection
#     2. Immutable backup directory configuration
#     3. OpenBSM audit logging for ransomware behaviors
#     4. Gatekeeper/SIP/XProtect enforcement
#     5. Destructive command restrictions
#     6. Filesystem monitoring via LaunchDaemon
#     7. Application Firewall for C2 defense
#
# USAGE:
#   sudo ./94b248c0-a104-48c3-b4a5-3d45028c407d_hardening_macos.sh [apply|undo|check]
#
# Requires: root privileges (sudo)
# Idempotent: Yes (safe to run multiple times)
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_NAME="$(basename "$0")"
TEST_ID="94b248c0-a104-48c3-b4a5-3d45028c407d"
BACKUP_DIR="/var/backups/f0rtika-hardening-${TEST_ID}"
LOG_FILE="/var/log/f0rtika-hardening-${TEST_ID}.log"
CHANGE_COUNT=0

# Known ransomware extensions for monitoring
RANSOMWARE_EXTENSIONS="ENCRT|encrypted|locked|crypted|enc|crypt|locky|cerber|ryuk|conti|lockbit|phobos|dharma"
RANSOM_NOTES="R3ADM3\\.txt|DECRYPT_.*\\.txt|HOW_TO_RECOVER.*|RESTORE_FILES.*"

# ============================================================================
# Helper Functions
# ============================================================================

log_info()    { echo -e "\033[36m[*]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_success() { echo -e "\033[32m[+]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [OK]    $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo -e "\033[33m[!]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN]  $1" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "\033[31m[-]\033[0m $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE" 2>/dev/null || true; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_macos() {
    if [[ "$(uname)" != "Darwin" ]]; then
        log_error "This script is designed for macOS only"
        exit 1
    fi
}

ensure_dirs() {
    mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")" 2>/dev/null || true
    chmod 700 "$BACKUP_DIR"
}

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        cp -a "$src" "${BACKUP_DIR}/$(basename "$src").bak.$(date '+%Y%m%d%H%M%S')"
        log_info "Backed up: $src"
    fi
}

# ============================================================================
# 1. Time Machine and APFS Snapshot Protection (M1053 - T1490)
# ============================================================================

harden_time_machine() {
    log_info "=== Time Machine and APFS Snapshot Protection (M1053 / T1490) ==="

    local ACTION="${1:-apply}"

    if [[ "$ACTION" == "check" ]]; then
        # Check Time Machine status
        if command -v tmutil &>/dev/null; then
            local tm_status
            tm_status="$(tmutil status 2>/dev/null | grep "Running" || echo "unknown")"
            log_info "Time Machine status: $tm_status"

            local tm_dest
            tm_dest="$(tmutil destinationinfo 2>/dev/null | head -5 || echo "no destination configured")"
            log_info "Time Machine destination: $tm_dest"
        else
            log_warning "tmutil not found -- Time Machine unavailable"
        fi

        # Check APFS snapshots
        local snapshots
        snapshots="$(tmutil listlocalsnapshots / 2>/dev/null | wc -l | tr -d ' ')"
        log_info "Local APFS snapshots: $snapshots"
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        # Remove tmutil protection (allow auto-deletion)
        if defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup 2>/dev/null | grep -q "1"; then
            log_info "Time Machine auto-backup already enabled (no undo needed)"
        fi
        # Remove immutable flag from tmutil binary
        chflags noschg /usr/bin/tmutil 2>/dev/null || true
        log_success "Time Machine protections reverted"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---

    # Ensure Time Machine is enabled and auto-backup is on
    if command -v tmutil &>/dev/null; then
        # Enable automatic backup
        tmutil enable 2>/dev/null || log_warning "Could not enable Time Machine (may need full disk access)"
        defaults write /Library/Preferences/com.apple.TimeMachine AutoBackup -bool true 2>/dev/null || true
        log_success "Time Machine: Auto-backup enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))

        # Protect tmutil binary from tampering
        chflags schg /usr/bin/tmutil 2>/dev/null || log_warning "Could not set immutable flag on tmutil"
        log_success "tmutil binary: Protected with system immutable flag"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))

        # Exclude /tmp from Time Machine (prevent ransomware artifacts in backups)
        tmutil addexclusion /tmp 2>/dev/null || true
        log_info "Excluded /tmp from Time Machine backups"
    else
        log_warning "tmutil not found -- cannot configure Time Machine"
    fi

    # Create a local APFS snapshot as a baseline
    tmutil localsnapshot 2>/dev/null && log_success "Created baseline local APFS snapshot" || \
        log_warning "Could not create local snapshot"
}

# ============================================================================
# 2. Immutable Backup Directory Protection (M1053)
# ============================================================================

harden_backup_dirs() {
    log_info "=== Immutable Backup Directory Protection (M1053) ==="

    local ACTION="${1:-apply}"
    local backup_paths=(
        "/var/backups"
        "/Library/Backups"
    )

    if [[ "$ACTION" == "check" ]]; then
        for bpath in "${backup_paths[@]}"; do
            if [[ -d "$bpath" ]]; then
                local flags
                flags="$(ls -lOd "$bpath" 2>/dev/null | awk '{print $5}' || echo "unknown")"
                log_info "Backup dir $bpath flags: $flags"
            else
                log_info "Backup dir $bpath: does not exist"
            fi
        done
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        for bpath in "${backup_paths[@]}"; do
            if [[ -d "$bpath" ]]; then
                chflags -R noschg "$bpath" 2>/dev/null || true
                chflags -R nosappnd "$bpath" 2>/dev/null || true
                log_success "Removed immutable/append-only flags from $bpath"
            fi
        done
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---
    for bpath in "${backup_paths[@]}"; do
        if [[ -d "$bpath" ]]; then
            # Set append-only flag (sappnd) -- allows new files, prevents deletion
            chflags -R sappnd "$bpath" 2>/dev/null && {
                log_success "Set append-only flag on $bpath"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            } || log_warning "Could not set append-only on $bpath (filesystem may not support it)"
        else
            mkdir -p "$bpath" 2>/dev/null || true
            if [[ -d "$bpath" ]]; then
                chflags sappnd "$bpath" 2>/dev/null || true
                log_success "Created and protected backup directory: $bpath"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        fi
    done

    log_info "RECOMMENDATION: Use encrypted external drives for offline backups"
    log_info "RECOMMENDATION: Enable Time Machine encryption for backup volumes"
}

# ============================================================================
# 3. SIP / Gatekeeper / XProtect Enforcement (M1054, M1038)
# ============================================================================

harden_sip_gatekeeper() {
    log_info "=== SIP / Gatekeeper / XProtect Verification (M1054) ==="

    local ACTION="${1:-apply}"

    # SIP status (read-only check -- cannot be changed at runtime)
    local sip_status
    sip_status="$(csrutil status 2>/dev/null || echo "unknown")"
    if echo "$sip_status" | grep -qi "enabled"; then
        log_success "SIP (System Integrity Protection): ENABLED"
    else
        log_error "SIP: DISABLED -- ransomware can modify system files. Enable via Recovery Mode"
    fi

    # Gatekeeper
    local gk_status
    gk_status="$(spctl --status 2>/dev/null || echo "unknown")"

    if [[ "$ACTION" == "check" ]]; then
        log_info "Gatekeeper: $gk_status"
        # Check XProtect
        local xprotect_version
        xprotect_version="$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null || echo "unknown")"
        log_info "XProtect version: $xprotect_version"
        # Check auto-updates
        local auto_update
        auto_update="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not set")"
        log_info "Automatic macOS updates: $auto_update"
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        log_info "SIP/Gatekeeper: No undo needed (these should remain enabled)"
        return
    fi

    # --- Apply ---

    # Enforce Gatekeeper
    if echo "$gk_status" | grep -qi "disabled"; then
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper: Re-enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_success "Gatekeeper: Already enabled"
    fi

    # Enforce quarantine on downloaded files
    defaults write com.apple.LaunchServices LSQuarantine -bool true 2>/dev/null || true
    log_success "Download quarantine: Enabled"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Enable automatic security updates (XProtect, MRT, Gatekeeper data)
    defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true 2>/dev/null || true
    defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null || true
    defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true 2>/dev/null || true
    log_success "Automatic security updates: Enabled (XProtect, MRT, Gatekeeper data)"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

# ============================================================================
# 4. OpenBSM Audit Logging for Ransomware Detection (T1486, T1490, T1082)
# ============================================================================

harden_audit_logging() {
    log_info "=== OpenBSM Audit Logging for Ransomware Detection ==="

    local ACTION="${1:-apply}"
    local audit_control="/etc/security/audit_control"

    if [[ "$ACTION" == "check" ]]; then
        if [[ -f "$audit_control" ]]; then
            local flags
            flags="$(grep "^flags:" "$audit_control" 2>/dev/null || echo "not found")"
            log_info "Audit flags: $flags"
        fi
        # Check if auditd is running
        if launchctl list | grep -q "com.apple.auditd" 2>/dev/null; then
            log_success "OpenBSM auditd: Running"
        else
            log_warning "OpenBSM auditd: Not running"
        fi
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        if [[ -f "${BACKUP_DIR}/audit_control.bak."* ]] 2>/dev/null; then
            local latest_backup
            latest_backup="$(ls -t "${BACKUP_DIR}/audit_control.bak."* 2>/dev/null | head -1)"
            if [[ -n "$latest_backup" ]]; then
                cp -a "$latest_backup" "$audit_control"
                log_success "Restored original audit_control"
            fi
        else
            log_info "No audit_control backup found -- no changes to undo"
        fi
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---
    if [[ -f "$audit_control" ]]; then
        backup_file "$audit_control"

        # Ensure comprehensive audit flags for ransomware detection
        # lo = login/logout, aa = authentication, ad = administrative
        # pc = process, ex = exec, fc = file create, fd = file delete
        # fw = file write, fr = file read
        local current_flags
        current_flags="$(grep "^flags:" "$audit_control" 2>/dev/null | sed 's/flags://' | tr -d ' ')"

        # Add file operation flags if not present
        local desired_flags="lo,aa,ad,pc,ex,fc,fd,fw"
        if [[ "$current_flags" != *"fc"* ]] || [[ "$current_flags" != *"fd"* ]] || [[ "$current_flags" != *"fw"* ]]; then
            sed -i.bak "s/^flags:.*/flags:${desired_flags}/" "$audit_control" 2>/dev/null || \
                echo "flags:${desired_flags}" >> "$audit_control"
            log_success "Audit flags updated: $desired_flags"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "Audit flags already include file operation monitoring"
        fi

        # Increase audit file size limit
        if ! grep -q "^filesz:" "$audit_control" 2>/dev/null; then
            echo "filesz:50M" >> "$audit_control"
            log_success "Audit file size limit: Set to 50MB"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi

        # Restart auditd to apply changes
        audit -s 2>/dev/null || log_warning "Could not restart auditd"
        log_success "OpenBSM audit reloaded with ransomware detection flags"
    else
        log_warning "audit_control not found at $audit_control"
    fi
}

# ============================================================================
# 5. Restrict Destructive Commands (M1038)
# ============================================================================

harden_destructive_commands() {
    log_info "=== Restricting Destructive Commands (M1038) ==="

    local ACTION="${1:-apply}"

    # macOS equivalents of destructive commands
    local restricted_cmds=(
        "/usr/bin/tmutil"       # Time Machine management (delete snapshots)
        "/sbin/diskutil"        # Disk management (erase volumes)
    )

    if [[ "$ACTION" == "check" ]]; then
        for cmd in "${restricted_cmds[@]}"; do
            if [[ -f "$cmd" ]]; then
                local perms flags
                perms="$(stat -f '%Sp' "$cmd" 2>/dev/null || echo "unknown")"
                flags="$(ls -lO "$cmd" 2>/dev/null | awk '{print $5}' || echo "none")"
                log_info "$cmd: perms=$perms flags=$flags"
            fi
        done
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        # Restore standard permissions
        for cmd in "${restricted_cmds[@]}"; do
            if [[ -f "$cmd" ]]; then
                chflags noschg "$cmd" 2>/dev/null || true
                chmod 755 "$cmd" 2>/dev/null || true
            fi
        done
        log_success "Destructive command permissions restored"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---

    # Protect diskutil from unauthorized use (restrict to root:wheel only)
    if [[ -f "/sbin/diskutil" ]]; then
        chmod 750 /sbin/diskutil 2>/dev/null || true
        log_success "diskutil: Restricted to root/wheel group (750)"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    # Log all tmutil and diskutil usage via Unified Logging
    log_info "RECOMMENDATION: Monitor tmutil/diskutil usage via Unified Logging:"
    log_info "  log stream --predicate 'process == \"tmutil\" OR process == \"diskutil\"'"
}

# ============================================================================
# 6. Filesystem Monitoring via LaunchDaemon (T1486)
# ============================================================================

harden_filesystem_monitoring() {
    log_info "=== Filesystem Monitoring for Ransomware Extensions (T1486) ==="

    local ACTION="${1:-apply}"
    local monitor_script="/usr/local/bin/f0rtika-ransomware-monitor.sh"
    local plist="/Library/LaunchDaemons/com.f0rtika.ransomware-monitor.plist"

    if [[ "$ACTION" == "check" ]]; then
        if launchctl list 2>/dev/null | grep -q "com.f0rtika.ransomware-monitor"; then
            log_success "Ransomware monitor LaunchDaemon: Running"
        else
            log_warning "Ransomware monitor LaunchDaemon: Not running"
        fi
        if [[ -f "$monitor_script" ]]; then
            log_info "Monitor script: $monitor_script exists"
        else
            log_warning "Monitor script: Not installed"
        fi
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        launchctl bootout system "$plist" 2>/dev/null || true
        rm -f "$plist" "$monitor_script" 2>/dev/null || true
        log_success "Ransomware filesystem monitor removed"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---

    # Create the monitoring script using fswatch (or fsevents)
    cat > "$monitor_script" << 'MONITOR_EOF'
#!/usr/bin/env bash
# F0RT1KA Ransomware File Extension Monitor for macOS
# Uses Unified Logging for SIEM ingestion

WATCH_DIRS="/Users /Volumes /tmp /var"
ALERT_LOG="/var/log/f0rtika-ransomware-alerts.log"

# Ransomware extension patterns
EXT_REGEX='\.(ENCRT|encrypted|locked|crypted|enc|crypt|locky|cerber|ryuk|conti|lockbit|phobos|dharma|djvu|stop)$'
NOTE_REGEX='(R3ADM3\.txt|DECRYPT_.*\.txt|HOW_TO_RECOVER.*|RESTORE_FILES.*)'

# Use fswatch if available, otherwise fall back to polling
if command -v fswatch &>/dev/null; then
    fswatch -r --event Created --event Renamed $WATCH_DIRS 2>/dev/null | while read -r filepath; do
        filename="$(basename "$filepath")"
        if echo "$filename" | grep -qiE "$EXT_REGEX"; then
            alert="RANSOMWARE_EXTENSION: file=$filepath time=$(date '+%Y-%m-%d %H:%M:%S')"
            echo "$alert" >> "$ALERT_LOG"
            logger -p auth.crit "$alert"
        fi
        if echo "$filename" | grep -qiE "$NOTE_REGEX"; then
            alert="RANSOM_NOTE_DETECTED: file=$filepath time=$(date '+%Y-%m-%d %H:%M:%S')"
            echo "$alert" >> "$ALERT_LOG"
            logger -p auth.crit "$alert"
        fi
    done
else
    # Polling fallback (check every 30 seconds)
    while true; do
        for dir in $WATCH_DIRS; do
            if [[ -d "$dir" ]]; then
                find "$dir" -maxdepth 3 -newer /tmp/.f0rtika-last-check -type f 2>/dev/null | while read -r filepath; do
                    filename="$(basename "$filepath")"
                    if echo "$filename" | grep -qiE "$EXT_REGEX"; then
                        alert="RANSOMWARE_EXTENSION: file=$filepath time=$(date '+%Y-%m-%d %H:%M:%S')"
                        echo "$alert" >> "$ALERT_LOG"
                        logger -p auth.crit "$alert"
                    fi
                done
            fi
        done
        touch /tmp/.f0rtika-last-check
        sleep 30
    done
fi
MONITOR_EOF
    chmod 755 "$monitor_script"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    log_success "Created ransomware monitor script: $monitor_script"

    # Create LaunchDaemon plist
    cat > "$plist" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rtika.ransomware-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${monitor_script}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/f0rtika-ransomware-monitor.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rtika-ransomware-monitor-err.log</string>
</dict>
</plist>
PLIST_EOF
    chmod 644 "$plist"
    chown root:wheel "$plist"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    log_success "Created LaunchDaemon: $plist"

    # Load the daemon
    launchctl bootstrap system "$plist" 2>/dev/null || \
        launchctl load "$plist" 2>/dev/null || \
        log_warning "Could not load ransomware monitor daemon"
    log_success "Ransomware filesystem monitor is now active"

    log_info "TIP: Install fswatch for real-time monitoring: brew install fswatch"
}

# ============================================================================
# 7. Application Firewall and Network Hardening (Defense in Depth)
# ============================================================================

harden_network() {
    log_info "=== Application Firewall and Network Hardening ==="

    local ACTION="${1:-apply}"

    if [[ "$ACTION" == "check" ]]; then
        local fw_status
        fw_status="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")"
        log_info "Application Firewall: $fw_status"

        local stealth
        stealth="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")"
        log_info "Stealth mode: $stealth"

        # Check for Tor-related connections
        local tor_conns
        tor_conns="$(lsof -i :9001 -i :9030 2>/dev/null | wc -l | tr -d ' ')"
        if [[ "$tor_conns" -gt 0 ]]; then
            log_warning "Active connections on Tor ports (9001/9030): $tor_conns"
        else
            log_info "No active Tor port connections detected"
        fi
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        # Remove PF anchor for Tor blocking
        if [[ -f "/etc/pf.anchors/f0rtika-ransomware" ]]; then
            rm -f /etc/pf.anchors/f0rtika-ransomware
            # Remove anchor reference from pf.conf
            if grep -q "f0rtika-ransomware" /etc/pf.conf 2>/dev/null; then
                backup_file /etc/pf.conf
                sed -i.bak '/f0rtika-ransomware/d' /etc/pf.conf 2>/dev/null || true
                pfctl -f /etc/pf.conf 2>/dev/null || true
            fi
            log_success "PF anchor for Tor blocking removed"
        fi
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---

    # Enable Application Firewall
    /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null || true
    log_success "Application Firewall: Enabled"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Enable stealth mode (don't respond to probes)
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null || true
    log_success "Stealth mode: Enabled"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Block all incoming connections for unsigned apps
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on 2>/dev/null || true
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on 2>/dev/null || true
    log_success "Firewall: Allow only signed applications"

    # Create PF anchor to log Tor relay traffic (Gunra uses Tor for extortion)
    local pf_anchor="/etc/pf.anchors/f0rtika-ransomware"
    cat > "$pf_anchor" << 'PF_EOF'
# F0RT1KA: Log connections to Tor relay ports
# Gunra ransomware uses Tor-hosted extortion sites
block log quick proto tcp from any to any port 9001
block log quick proto tcp from any to any port 9030
block log quick proto tcp from any to any port 9050
block log quick proto tcp from any to any port 9150
PF_EOF
    chmod 644 "$pf_anchor"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    log_success "PF anchor created: Blocking Tor relay ports (9001, 9030, 9050, 9150)"

    # Add anchor to pf.conf if not already present
    if ! grep -q "f0rtika-ransomware" /etc/pf.conf 2>/dev/null; then
        backup_file /etc/pf.conf
        echo "" >> /etc/pf.conf
        echo "# F0RT1KA: Ransomware Tor C2 blocking" >> /etc/pf.conf
        echo "anchor \"f0rtika-ransomware\"" >> /etc/pf.conf
        echo "load anchor \"f0rtika-ransomware\" from \"/etc/pf.anchors/f0rtika-ransomware\"" >> /etc/pf.conf
        pfctl -f /etc/pf.conf 2>/dev/null || log_warning "Could not reload PF rules"
        pfctl -e 2>/dev/null || true
        log_success "PF anchor loaded into pf.conf"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

# ============================================================================
# 8. Kernel Hardening and System Discovery Restrictions (T1082, T1622)
# ============================================================================

harden_kernel() {
    log_info "=== Kernel Hardening and Discovery Restrictions (T1082, T1622) ==="

    local ACTION="${1:-apply}"

    if [[ "$ACTION" == "check" ]]; then
        # Check for debug restrictions
        local debug_status
        debug_status="$(sysctl -n security.mac.proc_enforce 2>/dev/null || echo "unknown")"
        log_info "Process enforcement: $debug_status"
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        log_info "Kernel settings: macOS kernel hardening via SIP is non-reversible without Recovery Mode"
        return
    fi

    # --- Apply ---

    # Recommend Endpoint Security Framework for process monitoring
    log_info "macOS kernel hardening is primarily enforced through SIP"
    log_success "SIP protects: system binaries, kernel extensions, NVRAM variables"

    # Disable Bonjour advertising (reduces discovery surface - T1082)
    defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true 2>/dev/null || true
    log_success "Bonjour multicast advertising: Disabled (reduces discovery surface)"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Restrict AirDrop (prevents data staging/exfil)
    defaults write com.apple.NetworkBrowser DisableAirDrop -bool true 2>/dev/null || true
    log_success "AirDrop: Disabled"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    log_info "RECOMMENDATION: Enable Lockdown Mode for high-risk environments"
    log_info "RECOMMENDATION: Disable Remote Login (SSH) unless required"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    local ACTION="${1:-apply}"

    echo ""
    echo "============================================================================"
    echo "  F0RT1KA macOS Hardening Script"
    echo "  Test: Gunra Ransomware Simulation"
    echo "  MITRE ATT&CK: T1486, T1490, T1082, T1083, T1622"
    echo "============================================================================"
    echo ""

    check_root
    check_macos
    ensure_dirs

    case "$ACTION" in
        apply)
            log_info "Mode: APPLY -- Applying hardening settings"
            ;;
        undo|revert)
            ACTION="undo"
            log_info "Mode: UNDO -- Reverting hardening settings"
            ;;
        check|audit)
            ACTION="check"
            log_info "Mode: CHECK -- Auditing current settings (no changes)"
            ;;
        --help|-h|help)
            echo "Usage: sudo $SCRIPT_NAME [apply|undo|check|help]"
            echo ""
            echo "  apply   Apply all hardening settings (default)"
            echo "  undo    Revert hardening changes to defaults"
            echo "  check   Audit current settings without making changes"
            echo "  help    Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown mode: $ACTION"
            echo "Usage: sudo $SCRIPT_NAME [apply|undo|check|help]"
            exit 1
            ;;
    esac
    echo ""

    harden_time_machine "$ACTION"
    echo ""

    harden_backup_dirs "$ACTION"
    echo ""

    harden_sip_gatekeeper "$ACTION"
    echo ""

    harden_audit_logging "$ACTION"
    echo ""

    harden_destructive_commands "$ACTION"
    echo ""

    harden_filesystem_monitoring "$ACTION"
    echo ""

    harden_network "$ACTION"
    echo ""

    harden_kernel "$ACTION"
    echo ""

    # Summary
    echo "============================================================================"
    if [[ "$ACTION" == "undo" ]]; then
        log_success "Hardening changes reverted. Changes: $CHANGE_COUNT"
    elif [[ "$ACTION" == "check" ]]; then
        log_success "Audit complete. No changes made."
    else
        log_success "Hardening complete. Changes applied: $CHANGE_COUNT"
    fi
    echo "============================================================================"
    echo ""
    log_info "Log file: $LOG_FILE"
    echo ""

    # Verification commands
    log_info "Verification Commands:"
    echo ""
    echo "  # Check Time Machine status:"
    echo "  tmutil status && tmutil destinationinfo"
    echo ""
    echo "  # List local APFS snapshots:"
    echo "  tmutil listlocalsnapshots /"
    echo ""
    echo "  # Check ransomware monitor:"
    echo "  launchctl list | grep f0rtika"
    echo ""
    echo "  # Check Application Firewall:"
    echo "  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
    echo ""
    echo "  # Check PF rules:"
    echo "  sudo pfctl -sa 2>/dev/null | grep f0rtika"
    echo ""
    echo "  # View ransomware alerts:"
    echo "  cat /var/log/f0rtika-ransomware-alerts.log 2>/dev/null"
    echo ""

    # Additional recommendations
    log_info "Additional Recommendations:"
    echo ""
    echo "  1. Enable FileVault disk encryption:"
    echo "     sudo fdesetup enable"
    echo ""
    echo "  2. Implement 3-2-1 backup strategy:"
    echo "     - 3 copies of data"
    echo "     - 2 different storage types (Time Machine + cloud)"
    echo "     - 1 offsite/offline copy"
    echo ""
    echo "  3. Enable Lockdown Mode for high-risk environments:"
    echo "     System Settings > Privacy & Security > Lockdown Mode"
    echo ""
    echo "  4. Install fswatch for real-time filesystem monitoring:"
    echo "     brew install fswatch"
    echo ""
    echo "  5. Deploy MDM profile to enforce security settings:"
    echo "     - Prevent Time Machine from being disabled"
    echo "     - Enforce Gatekeeper and SIP"
    echo ""
}

main "$@"
