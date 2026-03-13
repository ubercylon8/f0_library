#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# MDE Process Injection and API Authentication Bypass Protection
# ============================================================================
# Test ID:      fec68e9b-af59-40c1-abbd-98ec98428444
# Test Name:    MDE Process Injection and API Authentication Bypass
# MITRE ATT&CK: T1055, T1055.001, T1562.001, T1014, T1557, T1071.001
# Mitigations:  M1040, M1026, M1018, M1038, M1050
# Platform:     macOS (Apple Silicon and Intel)
# Created:      2026-03-13
# Author:       F0RT1KA Defense Guidance Builder
# ============================================================================
#
# DESCRIPTION:
#   This script hardens a macOS system against process injection, memory
#   manipulation, EDR tampering, and proxy-based MITM attacks as demonstrated
#   by the MDE exploitation test. While the test targets Windows MDE, the
#   underlying techniques apply to macOS EDR agents (Microsoft Defender for
#   Endpoint on Mac, CrowdStrike Falcon, SentinelOne) equally.
#
#   This script implements:
#     1. Process protection (SIP, ptrace/task_for_pid, DYLD injection)
#     2. EDR agent LaunchDaemon/binary protection
#     3. Network hardening (proxy, firewall, ICMP)
#     4. OpenBSM audit logging for injection detection
#     5. Filesystem hardening (noexec on tmp, binary protection)
#     6. Kernel-level hardening via SIP and Endpoint Security
#
# USAGE:
#   sudo ./fec68e9b-af59-40c1-abbd-98ec98428444_hardening_macos.sh [apply|undo|check]
#
# Requires: root privileges (sudo)
# Idempotent: Yes (safe to run multiple times)
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_NAME="$(basename "$0")"
TEST_ID="fec68e9b-af59-40c1-abbd-98ec98428444"
BACKUP_DIR="/var/backups/f0rtika-hardening-${TEST_ID}"
LOG_FILE="/var/log/f0rtika-hardening-${TEST_ID}.log"
CHANGE_COUNT=0

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
# 1. Process Protection - Anti-Injection (T1055, T1055.001, T1014)
# ============================================================================

harden_process_protection() {
    log_info "=== Process Protection - Anti-Injection (T1055, T1055.001, T1014) ==="

    local ACTION="${1:-apply}"

    # --- 1.1: SIP Status (System Integrity Protection) ---
    # SIP is the macOS equivalent of preventing ptrace/process_vm_readv
    local sip_status
    sip_status="$(csrutil status 2>/dev/null || echo "unknown")"
    if echo "$sip_status" | grep -qi "enabled"; then
        log_success "SIP (System Integrity Protection): ENABLED"
        log_info "  SIP prevents: unsigned code injection, task_for_pid abuse, kernel extension loading"
    else
        log_error "SIP: DISABLED -- process injection attacks are possible"
        log_error "  Enable via Recovery Mode: csrutil enable"
    fi

    if [[ "$ACTION" == "check" ]]; then
        # Check Library Validation
        local lib_val
        lib_val="$(defaults read /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation 2>/dev/null || echo "not set (default: enabled)")"
        log_info "Library Validation: $lib_val"

        # Check DYLD environment restrictions
        if [[ -f /etc/environment ]] && grep -qi "DYLD_" /etc/environment 2>/dev/null; then
            log_warning "DYLD_ variables found in /etc/environment -- potential injection vector"
        else
            log_info "No DYLD_ injection variables in /etc/environment"
        fi

        # Check Hardened Runtime enforcement
        log_info "Hardened Runtime: Enforced by codesign for notarized apps"
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        # Remove DYLD restriction profile
        rm -f /etc/profile.d/f0rtika-dyld-protect.sh 2>/dev/null || true
        log_success "DYLD injection protection profile removed"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---

    # 1.2: Block DYLD_INSERT_LIBRARIES injection (macOS equivalent of LD_PRELOAD)
    # This is the primary library injection vector on macOS
    mkdir -p /etc/profile.d 2>/dev/null || true
    cat > /etc/profile.d/f0rtika-dyld-protect.sh << 'DYLD_EOF'
# F0RT1KA Hardening: Monitor DYLD injection attempts
# DYLD_INSERT_LIBRARIES is the macOS equivalent of LD_PRELOAD
_f0rtika_check_dyld() {
    if [[ -n "${DYLD_INSERT_LIBRARIES:-}" ]]; then
        logger -t "f0rtika-security" -p auth.crit \
            "DYLD_INSERT_LIBRARIES detected: ${DYLD_INSERT_LIBRARIES} user=$(whoami) pid=$$"
        echo "[F0RT1KA WARNING] DYLD_INSERT_LIBRARIES is set -- potential library injection"
    fi
    if [[ -n "${DYLD_LIBRARY_PATH:-}" ]]; then
        logger -t "f0rtika-security" -p auth.warning \
            "DYLD_LIBRARY_PATH override detected: ${DYLD_LIBRARY_PATH} user=$(whoami) pid=$$"
    fi
}
_f0rtika_check_dyld
DYLD_EOF
    chmod 644 /etc/profile.d/f0rtika-dyld-protect.sh
    log_success "DYLD injection monitoring: Installed at /etc/profile.d/"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # 1.3: Enforce Library Validation (prevent unsigned dylib loading)
    defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation -bool false 2>/dev/null || true
    log_success "Library Validation: Enforced (blocks unsigned dylib injection)"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # 1.4: Restrict debugging via DevToolsSecurity
    DevToolsSecurity -disable 2>/dev/null || true
    log_success "Developer tools debugging: Disabled (restricts task_for_pid)"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    log_info "NOTE: Hardened Runtime is enforced automatically for notarized binaries"
    log_info "NOTE: task_for_pid() requires entitlement or root + SIP disabled"
}

# ============================================================================
# 2. EDR Agent Protection (T1562.001)
# ============================================================================

harden_edr_protection() {
    log_info "=== EDR Agent Service Protection (T1562.001) ==="

    local ACTION="${1:-apply}"

    # macOS EDR agent paths and LaunchDaemon identifiers
    local -A edr_agents=(
        ["/Library/Application Support/Microsoft/Defender"]="com.microsoft.wdav.daemon"
        ["/Library/CS"]="com.crowdstrike.falcond"
        ["/Library/Sentinel"]="com.sentinelone.sentinel-agent"
    )

    if [[ "$ACTION" == "check" ]]; then
        for edr_path in "${!edr_agents[@]}"; do
            local daemon_label="${edr_agents[$edr_path]}"
            if [[ -d "$edr_path" ]]; then
                local perms flags
                perms="$(stat -f '%Sp' "$edr_path" 2>/dev/null || echo "unknown")"
                flags="$(ls -lOd "$edr_path" 2>/dev/null | awk '{print $5}' || echo "none")"
                log_info "EDR path $edr_path: perms=$perms flags=$flags"

                # Check if daemon is running
                if launchctl list 2>/dev/null | grep -q "$daemon_label"; then
                    log_success "  Daemon $daemon_label: Running"
                else
                    log_warning "  Daemon $daemon_label: Not running"
                fi
            else
                log_info "EDR path $edr_path: Not installed"
            fi
        done
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        for edr_path in "${!edr_agents[@]}"; do
            if [[ -d "$edr_path" ]]; then
                chflags -R noschg "$edr_path" 2>/dev/null || true
                log_success "Removed immutable flag from $edr_path"
            fi
        done
        # Remove watchdog daemon
        local watchdog_plist="/Library/LaunchDaemons/com.f0rtika.edr-watchdog.plist"
        launchctl bootout system "$watchdog_plist" 2>/dev/null || true
        rm -f "$watchdog_plist" /usr/local/bin/f0rtika-edr-watchdog.sh 2>/dev/null || true
        log_success "EDR watchdog daemon removed"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---
    for edr_path in "${!edr_agents[@]}"; do
        local daemon_label="${edr_agents[$edr_path]}"
        if [[ -d "$edr_path" ]]; then
            # Set restrictive permissions
            chmod -R 750 "$edr_path" 2>/dev/null || true
            chown -R root:wheel "$edr_path" 2>/dev/null || true

            # Set system immutable flag (prevents modification/deletion)
            chflags -R schg "$edr_path" 2>/dev/null || \
                log_warning "Could not set immutable flag on $edr_path"
            log_success "EDR path $edr_path: Permissions 750, immutable flag set"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))

            # Protect the LaunchDaemon plist
            local plist_path="/Library/LaunchDaemons/${daemon_label}.plist"
            if [[ -f "$plist_path" ]]; then
                chflags schg "$plist_path" 2>/dev/null || true
                log_success "  LaunchDaemon plist protected: $plist_path"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        fi
    done

    # Create EDR watchdog LaunchDaemon (restarts agents if killed)
    local watchdog_script="/usr/local/bin/f0rtika-edr-watchdog.sh"
    cat > "$watchdog_script" << 'WATCHDOG_EOF'
#!/usr/bin/env bash
# F0RT1KA EDR Agent Watchdog
# Checks EDR agent status and restarts if stopped

EDR_DAEMONS=(
    "com.microsoft.wdav.daemon"
    "com.crowdstrike.falcond"
    "com.sentinelone.sentinel-agent"
)

for daemon in "${EDR_DAEMONS[@]}"; do
    if launchctl print "system/${daemon}" &>/dev/null; then
        # Daemon is known to launchd -- check if running
        pid="$(launchctl print "system/${daemon}" 2>/dev/null | grep 'pid =' | awk '{print $3}')"
        if [[ -z "$pid" ]] || [[ "$pid" == "-" ]]; then
            logger -t "f0rtika-edr-watchdog" -p auth.crit \
                "EDR agent ${daemon} is not running -- attempting restart"
            launchctl kickstart -k "system/${daemon}" 2>/dev/null || true
        fi
    fi
done
WATCHDOG_EOF
    chmod 755 "$watchdog_script"

    local watchdog_plist="/Library/LaunchDaemons/com.f0rtika.edr-watchdog.plist"
    cat > "$watchdog_plist" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rtika.edr-watchdog</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${watchdog_script}</string>
    </array>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/f0rtika-edr-watchdog.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rtika-edr-watchdog-err.log</string>
</dict>
</plist>
PLIST_EOF
    chmod 644 "$watchdog_plist"
    chown root:wheel "$watchdog_plist"
    launchctl bootstrap system "$watchdog_plist" 2>/dev/null || \
        launchctl load "$watchdog_plist" 2>/dev/null || \
        log_warning "Could not load EDR watchdog daemon"
    log_success "EDR watchdog daemon: Installed (checks every 5 minutes)"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

# ============================================================================
# 3. Network Hardening - Anti-MITM / Proxy Abuse (T1557, T1071.001)
# ============================================================================

harden_network() {
    log_info "=== Network Hardening - Anti-MITM / Proxy Abuse (T1557, T1071.001) ==="

    local ACTION="${1:-apply}"

    if [[ "$ACTION" == "check" ]]; then
        # Check proxy settings
        local http_proxy_val="${http_proxy:-${HTTP_PROXY:-not set}}"
        local https_proxy_val="${https_proxy:-${HTTPS_PROXY:-not set}}"
        log_info "http_proxy: $http_proxy_val"
        log_info "https_proxy: $https_proxy_val"

        # Check system proxy
        local net_service
        net_service="$(networksetup -listallnetworkservices 2>/dev/null | grep -v '^An asterisk' | head -1)"
        if [[ -n "$net_service" ]]; then
            local web_proxy
            web_proxy="$(networksetup -getwebproxy "$net_service" 2>/dev/null || echo "unknown")"
            log_info "System web proxy ($net_service): $web_proxy"
        fi

        # Check Application Firewall
        local fw_status
        fw_status="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")"
        log_info "Application Firewall: $fw_status"

        # Check stealth mode
        local stealth
        stealth="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")"
        log_info "Stealth mode: $stealth"
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        # Remove proxy monitoring profile
        rm -f /etc/profile.d/f0rtika-proxy-protect.sh 2>/dev/null || true
        # Remove PF anchor
        if [[ -f /etc/pf.anchors/f0rtika-edr-network ]]; then
            rm -f /etc/pf.anchors/f0rtika-edr-network
            if grep -q "f0rtika-edr-network" /etc/pf.conf 2>/dev/null; then
                backup_file /etc/pf.conf
                sed -i.bak '/f0rtika-edr-network/d' /etc/pf.conf 2>/dev/null || true
                pfctl -f /etc/pf.conf 2>/dev/null || true
            fi
            log_success "PF network anchor removed"
        fi
        log_success "Network hardening reverted"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---

    # 3.1: Enable Application Firewall
    /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null || true
    log_success "Application Firewall: Enabled"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Enable stealth mode
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null || true
    log_success "Stealth mode: Enabled (prevents network probing)"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # Block incoming connections for unsigned apps
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on 2>/dev/null || true
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on 2>/dev/null || true
    log_success "Firewall: Allow only signed applications for incoming connections"

    # 3.2: Proxy manipulation monitoring
    mkdir -p /etc/profile.d 2>/dev/null || true
    cat > /etc/profile.d/f0rtika-proxy-protect.sh << 'PROXY_EOF'
# F0RT1KA Hardening: Log proxy environment variable changes
# Detects MITM proxy setup attempts targeting EDR cloud communication
_f0rtika_check_proxy() {
    if [[ -n "${http_proxy:-}" ]] || [[ -n "${https_proxy:-}" ]] || \
       [[ -n "${HTTP_PROXY:-}" ]] || [[ -n "${HTTPS_PROXY:-}" ]]; then
        logger -t "f0rtika-security" -p auth.warning \
            "Proxy env vars detected: http_proxy=${http_proxy:-} https_proxy=${https_proxy:-} user=$(whoami) pid=$$"
    fi
}
_f0rtika_check_proxy
PROXY_EOF
    chmod 644 /etc/profile.d/f0rtika-proxy-protect.sh
    log_success "Proxy monitoring: Installed profile script"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # 3.3: PF anchor for EDR communication protection
    local pf_anchor="/etc/pf.anchors/f0rtika-edr-network"
    cat > "$pf_anchor" << 'PF_EOF'
# F0RT1KA: Protect EDR cloud communication channels
# Block ICMP redirects (routing manipulation for MITM - T1557)
block in quick proto icmp from any to any icmp-type redirect
block in quick proto icmp from any to any icmp-type routeradv

# Log connections on common proxy ports (detect rogue proxies)
pass log proto tcp from any to any port { 3128, 8080, 8888 }
PF_EOF
    chmod 644 "$pf_anchor"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    log_success "PF anchor created: ICMP redirect blocking, proxy port logging"

    # Add anchor to pf.conf if not present
    if ! grep -q "f0rtika-edr-network" /etc/pf.conf 2>/dev/null; then
        backup_file /etc/pf.conf
        echo "" >> /etc/pf.conf
        echo "# F0RT1KA: EDR network protection" >> /etc/pf.conf
        echo "anchor \"f0rtika-edr-network\"" >> /etc/pf.conf
        echo "load anchor \"f0rtika-edr-network\" from \"/etc/pf.anchors/f0rtika-edr-network\"" >> /etc/pf.conf
        pfctl -f /etc/pf.conf 2>/dev/null || log_warning "Could not reload PF rules"
        pfctl -e 2>/dev/null || true
        log_success "PF anchor loaded into pf.conf"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi
}

# ============================================================================
# 4. OpenBSM Audit Logging for Injection Detection (T1055, T1562.001)
# ============================================================================

harden_audit_logging() {
    log_info "=== OpenBSM Audit Logging for Injection Detection ==="

    local ACTION="${1:-apply}"
    local audit_control="/etc/security/audit_control"

    if [[ "$ACTION" == "check" ]]; then
        if [[ -f "$audit_control" ]]; then
            local flags
            flags="$(grep "^flags:" "$audit_control" 2>/dev/null || echo "not found")"
            log_info "Audit flags: $flags"
        fi
        if launchctl list 2>/dev/null | grep -q "com.apple.auditd"; then
            log_success "OpenBSM auditd: Running"
        else
            log_warning "OpenBSM auditd: Not running"
        fi

        # Check Unified Logging for security events
        local recent_auth
        recent_auth="$(log show --last 1h --predicate 'category == "security"' 2>/dev/null | wc -l | tr -d ' ')"
        log_info "Security log entries (last hour): $recent_auth"
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        if ls "${BACKUP_DIR}/audit_control.bak."* &>/dev/null 2>&1; then
            local latest_backup
            latest_backup="$(ls -t "${BACKUP_DIR}/audit_control.bak."* 2>/dev/null | head -1)"
            if [[ -n "$latest_backup" ]]; then
                cp -a "$latest_backup" "$audit_control"
                audit -s 2>/dev/null || true
                log_success "Restored original audit_control"
            fi
        else
            log_info "No audit_control backup found"
        fi
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---
    if [[ -f "$audit_control" ]]; then
        backup_file "$audit_control"

        # Configure comprehensive audit flags for injection detection
        # pc = process (fork, exec, exit) -- detects suspicious process creation
        # ex = exec -- detects binary execution from unusual locations
        # fc = file create -- detects dropper activity
        # fd = file delete -- detects cleanup/anti-forensics
        # fw = file write -- detects memory dump/extraction
        # lo = login/logout, aa = authentication, ad = administrative
        local desired_flags="lo,aa,ad,pc,ex,fc,fd,fw"
        local current_flags
        current_flags="$(grep "^flags:" "$audit_control" 2>/dev/null | sed 's/flags://' | tr -d ' ')"

        if [[ "$current_flags" != *"pc"* ]] || [[ "$current_flags" != *"ex"* ]]; then
            sed -i.bak "s/^flags:.*/flags:${desired_flags}/" "$audit_control" 2>/dev/null || \
                echo "flags:${desired_flags}" >> "$audit_control"
            log_success "Audit flags updated: $desired_flags"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "Audit flags already include process/exec monitoring"
        fi

        # Increase audit file size
        if ! grep -q "^filesz:" "$audit_control" 2>/dev/null; then
            echo "filesz:50M" >> "$audit_control"
            log_success "Audit file size limit: Set to 50MB"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        fi

        audit -s 2>/dev/null || log_warning "Could not restart auditd"
        log_success "OpenBSM audit reloaded with process injection detection flags"
    else
        log_warning "audit_control not found at $audit_control"
    fi

    # Configure Unified Logging predicates for monitoring
    log_info "Unified Logging monitoring commands:"
    log_info "  Process injection: log stream --predicate 'eventMessage CONTAINS \"task_for_pid\"'"
    log_info "  DYLD injection: log stream --predicate 'eventMessage CONTAINS \"DYLD_INSERT\"'"
    log_info "  EDR tampering: log stream --predicate 'process == \"mdatp\" OR process == \"falcond\"'"
}

# ============================================================================
# 5. Filesystem Hardening (T1014, T1055)
# ============================================================================

harden_filesystem() {
    log_info "=== Filesystem Hardening (T1014, T1055) ==="

    local ACTION="${1:-apply}"

    if [[ "$ACTION" == "check" ]]; then
        # Check /tmp mount options (macOS uses a synthetic firm link)
        local tmp_info
        tmp_info="$(mount | grep ' /tmp' || echo "/tmp: standard mount")"
        log_info "/tmp mount: $tmp_info"

        # Check for suspicious binaries in temp dirs
        local suspicious
        suspicious="$(find /tmp /var/tmp -perm +111 -type f 2>/dev/null | wc -l | tr -d ' ')"
        log_info "Executable files in /tmp and /var/tmp: $suspicious"

        # Check for quarantine attributes
        log_info "Quarantine checking: Use 'xattr -l <file>' to check com.apple.quarantine"
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        # Remove LaunchDaemon that monitors temp execution
        local plist="/Library/LaunchDaemons/com.f0rtika.tmp-exec-monitor.plist"
        launchctl bootout system "$plist" 2>/dev/null || true
        rm -f "$plist" /usr/local/bin/f0rtika-tmp-exec-monitor.sh 2>/dev/null || true
        log_success "Temp execution monitor removed"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---

    # 5.1: Monitor execution from temp directories
    local monitor_script="/usr/local/bin/f0rtika-tmp-exec-monitor.sh"
    cat > "$monitor_script" << 'TMP_EOF'
#!/usr/bin/env bash
# F0RT1KA: Monitor for executable creation in temp directories
# Detects dropper/injection staging activity

WATCH_DIRS="/tmp /var/tmp /private/tmp"

for dir in $WATCH_DIRS; do
    if [[ -d "$dir" ]]; then
        find "$dir" -perm +111 -type f -newer /tmp/.f0rtika-tmp-check 2>/dev/null | while read -r filepath; do
            logger -t "f0rtika-security" -p auth.crit \
                "EXECUTABLE_IN_TMP: file=$filepath user=$(stat -f '%Su' "$filepath" 2>/dev/null) time=$(date)"
        done
    fi
done
touch /tmp/.f0rtika-tmp-check
TMP_EOF
    chmod 755 "$monitor_script"

    local plist="/Library/LaunchDaemons/com.f0rtika.tmp-exec-monitor.plist"
    cat > "$plist" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rtika.tmp-exec-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${monitor_script}</string>
    </array>
    <key>StartInterval</key>
    <integer>60</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/f0rtika-tmp-exec-monitor.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rtika-tmp-exec-monitor-err.log</string>
</dict>
</plist>
PLIST_EOF
    chmod 644 "$plist"
    chown root:wheel "$plist"
    launchctl bootstrap system "$plist" 2>/dev/null || \
        launchctl load "$plist" 2>/dev/null || \
        log_warning "Could not load tmp exec monitor daemon"
    log_success "Temp directory execution monitor: Installed (checks every 60s)"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # 5.2: Protect key system directories
    log_info "SIP protects /System, /usr, /bin, /sbin from modification"
    log_info "RECOMMENDATION: Use MDM to enforce additional path restrictions"
}

# ============================================================================
# 6. Kernel-Level Hardening (T1014)
# ============================================================================

harden_kernel() {
    log_info "=== Kernel-Level Hardening (T1014) ==="

    local ACTION="${1:-apply}"

    if [[ "$ACTION" == "check" ]]; then
        # SIP covers most kernel protections on macOS
        log_info "SIP status: $(csrutil status 2>/dev/null || echo 'unknown')"

        # Check for loaded kernel extensions (kexts)
        local kext_count
        kext_count="$(kextstat 2>/dev/null | wc -l | tr -d ' ')"
        log_info "Loaded kernel extensions: $kext_count"

        # Check Secure Boot
        log_info "Secure Boot: Check via System Information > Hardware Overview"

        # Check FileVault
        local fv_status
        fv_status="$(fdesetup status 2>/dev/null || echo "unknown")"
        log_info "FileVault: $fv_status"
        return
    fi

    if [[ "$ACTION" == "undo" ]]; then
        # Re-enable Bonjour if it was disabled
        defaults delete /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements 2>/dev/null || true
        log_success "Bonjour multicast: Re-enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
        return
    fi

    # --- Apply ---

    # 6.1: Disable Bonjour advertising (reduces attack surface)
    defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true 2>/dev/null || true
    log_success "Bonjour multicast advertising: Disabled"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))

    # 6.2: Recommend FileVault (full-disk encryption protects memory dumps at rest)
    local fv_status
    fv_status="$(fdesetup status 2>/dev/null || echo "unknown")"
    if echo "$fv_status" | grep -qi "On"; then
        log_success "FileVault: Enabled (protects at-rest memory dumps)"
    else
        log_warning "FileVault: Not enabled -- enable for data-at-rest protection"
        log_info "  Enable: sudo fdesetup enable"
    fi

    # 6.3: Kernel extension (kext) restrictions
    log_info "macOS 11+: Third-party kexts require user approval in Security preferences"
    log_info "macOS 12+: System Extensions (DriverKit) replace most kexts"
    log_info "RECOMMENDATION: Review loaded kexts: kextstat | grep -v com.apple"

    # 6.4: Disable remote login unless required
    local remote_login
    remote_login="$(systemsetup -getremotelogin 2>/dev/null || echo "unknown")"
    if echo "$remote_login" | grep -qi "on"; then
        log_warning "Remote Login (SSH): Enabled -- disable if not required"
        log_info "  Disable: sudo systemsetup -setremotelogin off"
    else
        log_success "Remote Login (SSH): Disabled"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    local ACTION="${1:-apply}"

    echo ""
    echo "============================================================================"
    echo "  F0RT1KA macOS Hardening Script"
    echo "  Test: MDE Process Injection and API Authentication Bypass"
    echo "  MITRE ATT&CK: T1055, T1055.001, T1562.001, T1014, T1557, T1071.001"
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

    harden_process_protection "$ACTION"
    echo ""

    harden_edr_protection "$ACTION"
    echo ""

    harden_network "$ACTION"
    echo ""

    harden_audit_logging "$ACTION"
    echo ""

    harden_filesystem "$ACTION"
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
    echo "  # Check SIP status:"
    echo "  csrutil status"
    echo ""
    echo "  # Check Library Validation:"
    echo "  defaults read /Library/Preferences/com.apple.security.libraryvalidation.plist 2>/dev/null"
    echo ""
    echo "  # Check EDR agents:"
    echo "  launchctl list | grep -E 'wdav|falcon|sentinel'"
    echo ""
    echo "  # Check Application Firewall:"
    echo "  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
    echo ""
    echo "  # Check PF rules:"
    echo "  sudo pfctl -sa 2>/dev/null | grep f0rtika"
    echo ""
    echo "  # Check audit configuration:"
    echo "  grep flags /etc/security/audit_control"
    echo ""
    echo "  # Monitor for process injection attempts:"
    echo "  log stream --predicate 'eventMessage CONTAINS \"task_for_pid\"' --level error"
    echo ""
    echo "  # Check temp directory executables:"
    echo "  find /tmp /var/tmp -perm +111 -type f 2>/dev/null"
    echo ""

    # Additional recommendations
    log_info "Additional Recommendations:"
    echo ""
    echo "  1. Enable Lockdown Mode for high-security environments:"
    echo "     System Settings > Privacy & Security > Lockdown Mode"
    echo ""
    echo "  2. Deploy Endpoint Security Framework-based EDR:"
    echo "     - Uses Apple's ES framework for tamper-resistant monitoring"
    echo "     - Cannot be bypassed without disabling SIP"
    echo ""
    echo "  3. Use MDM to enforce hardening policies:"
    echo "     - Prevent SIP from being disabled"
    echo "     - Enforce Library Validation"
    echo "     - Restrict kernel extension approvals"
    echo ""
    echo "  4. Enable FileVault for full-disk encryption:"
    echo "     sudo fdesetup enable"
    echo ""
    echo "  5. Review and restrict DYLD environment variables:"
    echo "     env | grep DYLD"
    echo ""
}

main "$@"
