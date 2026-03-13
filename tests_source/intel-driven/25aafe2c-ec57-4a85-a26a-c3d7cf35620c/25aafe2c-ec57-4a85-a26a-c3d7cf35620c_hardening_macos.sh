#!/usr/bin/env bash
# ============================================================================
# DEFENSE GUIDANCE: macOS Hardening Script
# ============================================================================
# Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
# Test Name: ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira)
# MITRE ATT&CK: T1046, T1018, T1021.004, T1048, T1567.002, T1486
# Mitigations: M1030, M1035, M1042, M1038, M1047, M1037
# Created: 2026-03-13
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
#
# PURPOSE:
# While the ESXi ransomware kill chain primarily targets Linux/ESXi hosts,
# macOS systems face analogous threats related to SSH lateral movement,
# data exfiltration via Rclone, and credential harvesting. This script
# hardens macOS endpoints against these techniques:
#
#   - SSH key file access monitoring and permission hardening (T1021.004)
#   - sshd_config hardening with key-only auth and session limits
#   - Packet filter rules to block Rclone exfiltration endpoints (T1048)
#   - Rclone detection and restriction (T1567.002)
#   - Binary rename detection for masquerading (T1036.003)
#   - Endpoint security posture validation (FileVault, Gatekeeper, EDR)
#   - Application firewall enforcement (T1048, M1037)
#   - Launch daemon monitoring for persistence detection (T1543.004)
#
# USAGE:
#   sudo ./25aafe2c-ec57-4a85-a26a-c3d7cf35620c_hardening_macos.sh [--undo] [--dry-run]
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - macOS 12 Monterey or later
#
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_NAME="$(basename "$0")"
UNDO_MODE=false
DRY_RUN=false
PF_ANCHOR_FILE="/etc/pf.anchors/f0rt1ka-esxi-hardening"
LOG_DIR="/var/log/f0rt1ka"
LOG_FILE="${LOG_DIR}/hardening_macos_$(date +%Y%m%d_%H%M%S).log"
LAUNCH_DAEMON_MONITOR="/Library/LaunchDaemons/com.f0rt1ka.binary-monitor.plist"
MONITOR_SCRIPT="/usr/local/bin/f0rt1ka-binary-monitor-macos.sh"
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

run_cmd() {
    if $DRY_RUN; then
        log_info "[DRY-RUN] Would execute: $*"
    else
        eval "$@"
        CHANGES_MADE=$((CHANGES_MADE + 1))
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_macos_version() {
    local ver
    ver=$(sw_vers -productVersion 2>/dev/null || echo "0.0")
    local major
    major=$(echo "$ver" | cut -d. -f1)
    if [[ "$major" -lt 12 ]]; then
        log_warning "macOS version $ver detected -- this script requires macOS 12+"
    else
        log_info "macOS version: $ver"
    fi
}

# ============================================================================
# Setup
# ============================================================================

check_root
mkdir -p "$LOG_DIR" 2>/dev/null || true

echo ""
echo "============================================================"
echo "F0RT1KA macOS Hardening: ESXi Ransomware Kill Chain"
echo "Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
echo "MITRE ATT&CK: T1046, T1018, T1021.004, T1048, T1567.002,"
echo "              T1486"
echo "============================================================"
echo ""

check_macos_version

# ============================================================================
# 1. SSH Key Hardening (T1021.004 - SSH Lateral Movement)
# ============================================================================
# Threat: SSH-Snake worm harvests keys from known_hosts, authorized_keys,
# and SSH config files. macOS stores SSH keys in /Users/<user>/.ssh/ and
# /var/root/.ssh/ (for root).
# ============================================================================

harden_ssh() {
    log_info "1. Hardening SSH key file permissions and sshd configuration..."

    # --- 1a. Restrict SSH key file permissions ---
    log_info "  1a. Restricting SSH key file permissions..."
    for home_dir in /Users/* /var/root; do
        local ssh_dir="${home_dir}/.ssh"
        if [[ -d "$ssh_dir" ]]; then
            run_cmd "chmod 700 '$ssh_dir'"
            # Lock down private keys
            for keyfile in "$ssh_dir"/id_*; do
                if [[ -f "$keyfile" && ! "$keyfile" == *.pub ]]; then
                    run_cmd "chmod 600 '$keyfile'"
                    log_success "Restricted: $keyfile"
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
            # Lock down SSH config
            if [[ -f "$ssh_dir/config" ]]; then
                run_cmd "chmod 600 '$ssh_dir/config'"
            fi
        fi
    done

    # --- 1b. Harden sshd_config ---
    log_info "  1b. Hardening sshd_config..."
    local sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        local sshd_changed=false

        # Disable root login
        if ! grep -q "^PermitRootLogin no" "$sshd_config"; then
            run_cmd "sed -i '' 's/^#*PermitRootLogin.*/PermitRootLogin no/' '$sshd_config'"
            log_success "Disabled root SSH login"
            sshd_changed=true
        fi

        # Disable password authentication (key-only)
        if ! grep -q "^PasswordAuthentication no" "$sshd_config"; then
            run_cmd "sed -i '' 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' '$sshd_config'"
            log_success "Disabled password authentication (key-only)"
            sshd_changed=true
        fi

        # Set idle timeout
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

        # Disable agent forwarding
        if ! grep -q "^AllowAgentForwarding no" "$sshd_config"; then
            run_cmd "sed -i '' 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/' '$sshd_config'"
            log_success "Disabled SSH agent forwarding"
            sshd_changed=true
        fi
    fi

    # --- 1c. Check Remote Login status ---
    log_info "  1c. Checking Remote Login (SSH) status..."
    local ssh_status
    ssh_status=$(systemsetup -getremotelogin 2>/dev/null | grep -c "On" || true)
    if [[ "$ssh_status" -gt 0 ]]; then
        log_warning "Remote Login (SSH) is enabled"
        log_info "  Disable if not needed: sudo systemsetup -setremotelogin off"
        log_info "  Or restrict to specific users via System Preferences > Sharing"

        # Show which users/groups have SSH access
        local ssh_access
        ssh_access=$(dscl . -read /Groups/com.apple.access_ssh GroupMembership 2>/dev/null || echo "Not restricted")
        log_info "  SSH access: $ssh_access"
    else
        log_success "Remote Login (SSH) is disabled"
    fi

    # --- 1d. Set immutable flags on authorized_keys ---
    log_info "  1d. Setting immutable flags on authorized_keys files..."
    for home_dir in /Users/* /var/root; do
        local ak="${home_dir}/.ssh/authorized_keys"
        if [[ -f "$ak" ]]; then
            run_cmd "chflags uchg '$ak' 2>/dev/null || true"
            log_success "Set immutable flag: $ak"
        fi
    done
}

undo_ssh() {
    log_warning "Reverting SSH hardening..."
    # Remove immutable flags
    for home_dir in /Users/* /var/root; do
        local ak="${home_dir}/.ssh/authorized_keys"
        if [[ -f "$ak" ]]; then
            run_cmd "chflags nouchg '$ak' 2>/dev/null || true"
            log_success "Removed immutable flag: $ak"
        fi
    done
    log_warning "sshd_config changes require manual review"
    log_info "  Review /etc/ssh/sshd_config for hardening settings"
}

# ============================================================================
# 2. Packet Filter Rules - Block Exfiltration (T1048, T1567.002)
# ============================================================================
# Blocks Mega.nz and other cloud storage endpoints used by Rclone for
# data exfiltration. Uses macOS PF (Packet Filter) with anchor files.
# ============================================================================

setup_pf_rules() {
    log_info "2. Configuring packet filter rules to block exfiltration targets..."

    run_cmd "cat > '$PF_ANCHOR_FILE' << 'PF_EOF'
# ============================================================================
# F0RT1KA ESXi Ransomware Hardening - Exfiltration Block Rules
# ============================================================================
# Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
# Purpose: Block known exfiltration targets used by RansomHub/Akira
# ============================================================================

# Block Mega.nz cloud storage (primary Rclone exfiltration target)
block drop out quick proto tcp to 89.44.169.0/24
block drop out quick proto tcp to 31.216.148.0/24

# Block additional Mega.nz API endpoints
block drop out quick proto tcp to 66.203.127.0/24

# Block Backblaze B2 (alternative exfil target)
block drop out quick proto tcp to 206.190.226.0/24

# Log blocked attempts for monitoring
block drop out log quick proto tcp to 89.44.169.0/24
block drop out log quick proto tcp to 31.216.148.0/24
PF_EOF"

    # Add anchor to pf.conf if not present
    if ! grep -q "f0rt1ka-esxi-hardening" /etc/pf.conf 2>/dev/null; then
        run_cmd "echo '' >> /etc/pf.conf"
        run_cmd "echo '# F0RT1KA ESXi Ransomware Exfiltration Protection' >> /etc/pf.conf"
        run_cmd "echo 'anchor \"f0rt1ka-esxi-hardening\"' >> /etc/pf.conf"
        run_cmd "echo 'load anchor \"f0rt1ka-esxi-hardening\" from \"$PF_ANCHOR_FILE\"' >> /etc/pf.conf"
    fi

    if ! $DRY_RUN; then
        pfctl -f /etc/pf.conf 2>/dev/null || true
        pfctl -e 2>/dev/null || true
        log_success "Packet filter rules loaded"
        # Verify rules
        local rule_count
        rule_count=$(pfctl -a f0rt1ka-esxi-hardening -sr 2>/dev/null | wc -l | tr -d ' ' || echo "0")
        log_info "  Active PF rules in anchor: $rule_count"
    fi
}

remove_pf_rules() {
    log_warning "Removing packet filter exfiltration rules..."
    if [[ -f "$PF_ANCHOR_FILE" ]]; then
        run_cmd "rm -f '$PF_ANCHOR_FILE'"
        # Remove anchor lines from pf.conf
        run_cmd "sed -i '' '/f0rt1ka-esxi-hardening/d' /etc/pf.conf 2>/dev/null || true"
        run_cmd "sed -i '' '/F0RT1KA ESXi Ransomware Exfiltration/d' /etc/pf.conf 2>/dev/null || true"
        run_cmd "pfctl -f /etc/pf.conf 2>/dev/null || true"
        log_success "Packet filter rules removed"
    fi
}

# ============================================================================
# 3. Rclone Detection and Restriction (T1048, T1567.002)
# ============================================================================
# The attack uses Rclone renamed to svchost.exe for cloud exfiltration
# to Mega, S3, and SFTP targets. This section detects installed Rclone
# binaries and their configuration files.
# ============================================================================

check_rclone() {
    log_info "3. Checking for Rclone installation..."

    local rclone_found=false
    local rclone_paths=("/usr/local/bin/rclone" "/opt/homebrew/bin/rclone"
                        "/usr/bin/rclone" "/tmp/rclone")

    for rpath in "${rclone_paths[@]}"; do
        if [[ -f "$rpath" ]]; then
            rclone_found=true
            log_warning "Rclone found at $rpath"
            local rclone_ver
            rclone_ver=$("$rpath" version 2>/dev/null | head -1 || echo "Unknown")
            log_info "  Version: $rclone_ver"
            log_info "  Remove if unauthorized: sudo rm $rpath"
        fi
    done

    if ! $rclone_found; then
        log_success "No Rclone installation found in standard paths"
    fi

    # Check Homebrew cask installations
    if command -v brew &>/dev/null; then
        if brew list --cask 2>/dev/null | grep -q rclone; then
            log_warning "Rclone installed via Homebrew cask"
            log_info "  Remove: brew uninstall --cask rclone"
        fi
        if brew list --formula 2>/dev/null | grep -q rclone; then
            log_warning "Rclone installed via Homebrew formula"
            log_info "  Remove: brew uninstall rclone"
        fi
    fi

    # Check for rclone configs
    log_info "  Scanning for Rclone configuration files..."
    for home_dir in /Users/* /var/root; do
        local rclone_conf="${home_dir}/.config/rclone/rclone.conf"
        if [[ -f "$rclone_conf" ]]; then
            log_warning "Rclone config found: $rclone_conf"
            # Show remote names without credentials
            if ! $DRY_RUN; then
                grep '^\[' "$rclone_conf" 2>/dev/null | while read -r line; do
                    log_info "    Remote configured: $line"
                done
            fi
        fi
    done

    # Check for rclone in temp directories
    local tmp_rclone
    tmp_rclone=$(find /tmp /private/tmp /var/folders -name "rclone*" -type f 2>/dev/null || true)
    if [[ -n "$tmp_rclone" ]]; then
        log_warning "Rclone binaries found in temp directories:"
        echo "$tmp_rclone" | while read -r f; do
            log_warning "  $f"
        done
    fi
}

# ============================================================================
# 4. Binary Rename Detection (T1036.003 - Masquerading)
# ============================================================================
# Detects Windows-named binaries on macOS (strong masquerading indicator).
# The attack renames rclone to svchost.exe -- a Windows process name
# that should never appear on macOS.
# ============================================================================

setup_binary_monitor() {
    log_info "4. Setting up binary rename detection monitor..."

    run_cmd "cat > '$MONITOR_SCRIPT' << 'MONITOR_EOF'
#!/usr/bin/env bash
# F0RT1KA Binary Rename Detection Monitor (macOS)
# Detects suspicious Windows-named binaries and renamed rclone instances

ALERT_LOG=\"/var/log/f0rt1ka/binary_rename_alerts.log\"
mkdir -p /var/log/f0rt1ka 2>/dev/null || true

# Suspicious Windows binary names on macOS
SUSPICIOUS_NAMES=(\"svchost.exe\" \"csrss.exe\" \"lsass.exe\" \"services.exe\"
                  \"winlogon.exe\" \"explorer.exe\" \"taskhost.exe\" \"conhost.exe\"
                  \"rundll32.exe\" \"cmd.exe\" \"powershell.exe\")

# Common staging directories on macOS
SEARCH_DIRS=(\"/tmp\" \"/private/tmp\" \"/var/tmp\" \"/Users\")

for dir in \"\${SEARCH_DIRS[@]}\"; do
    if [[ -d \"\$dir\" ]]; then
        for name in \"\${SUSPICIOUS_NAMES[@]}\"; do
            found=\$(find \"\$dir\" -name \"\$name\" -type f 2>/dev/null)
            if [[ -n \"\$found\" ]]; then
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] ALERT: Suspicious binary: \$found\" >> \"\$ALERT_LOG\"
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')]   File type: \$(file \"\$found\" 2>/dev/null)\" >> \"\$ALERT_LOG\"
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')]   SHA256: \$(shasum -a 256 \"\$found\" 2>/dev/null | awk '{print \$1}')\" >> \"\$ALERT_LOG\"
                logger -t f0rt1ka-binary-monitor \"ALERT: Suspicious binary found: \$found\"
            fi
        done
    fi
done

# Check for binaries containing rclone strings but with wrong names
for dir in \"/tmp\" \"/private/tmp\" \"/var/tmp\"; do
    if [[ -d \"\$dir\" ]]; then
        find \"\$dir\" -type f -perm +111 -maxdepth 3 2>/dev/null | while read -r binary; do
            if strings \"\$binary\" 2>/dev/null | head -100 | grep -qi \"rclone\" && \
               ! basename \"\$binary\" | grep -qi \"rclone\"; then
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] ALERT: Renamed rclone binary: \$binary\" >> \"\$ALERT_LOG\"
                logger -t f0rt1ka-binary-monitor \"ALERT: Renamed rclone detected: \$binary\"
            fi
        done
    fi
done
MONITOR_EOF"

    run_cmd "chmod 750 '$MONITOR_SCRIPT'"

    # Create LaunchDaemon for periodic monitoring (every 5 minutes)
    run_cmd "cat > '$LAUNCH_DAEMON_MONITOR' << 'PLIST_EOF'
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.f0rt1ka.binary-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/f0rt1ka-binary-monitor-macos.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/f0rt1ka/binary-monitor-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rt1ka/binary-monitor-stderr.log</string>
</dict>
</plist>
PLIST_EOF"

    if ! $DRY_RUN; then
        launchctl load "$LAUNCH_DAEMON_MONITOR" 2>/dev/null || true
        log_success "Binary rename monitor installed (runs every 5 minutes)"
    fi
    log_info "  Monitor script: $MONITOR_SCRIPT"
    log_info "  Launch daemon: $LAUNCH_DAEMON_MONITOR"
    log_info "  Alert log: /var/log/f0rt1ka/binary_rename_alerts.log"
}

remove_binary_monitor() {
    log_warning "Removing binary rename monitor..."
    if [[ -f "$LAUNCH_DAEMON_MONITOR" ]]; then
        run_cmd "launchctl unload '$LAUNCH_DAEMON_MONITOR' 2>/dev/null || true"
        run_cmd "rm -f '$LAUNCH_DAEMON_MONITOR'"
    fi
    run_cmd "rm -f '$MONITOR_SCRIPT'"
    log_success "Binary rename monitor removed"
}

# ============================================================================
# 5. Application Firewall Enforcement (M1037 - Filter Network Traffic)
# ============================================================================
# Ensures the macOS Application Firewall is enabled and configured
# to block incoming connections and prevent unauthorized applications
# from accepting network connections.
# ============================================================================

enforce_app_firewall() {
    log_info "5. Enforcing macOS Application Firewall settings..."

    # Check if ALF (Application Layer Firewall) is enabled
    local alf_status
    alf_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")

    if echo "$alf_status" | grep -q "enabled"; then
        log_success "Application Firewall is enabled"
    else
        log_warning "Application Firewall is NOT enabled"
        run_cmd "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null || true"
        log_success "Enabled Application Firewall"
    fi

    # Enable stealth mode (don't respond to probes)
    local stealth_status
    stealth_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
    if echo "$stealth_status" | grep -q "enabled"; then
        log_success "Stealth mode is enabled"
    else
        run_cmd "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null || true"
        log_success "Enabled stealth mode"
    fi

    # Block all incoming connections (most restrictive)
    local block_status
    block_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null || echo "unknown")
    if echo "$block_status" | grep -q "enabled"; then
        log_success "Block-all incoming connections is enabled"
    else
        log_warning "Block-all is NOT enabled (incoming connections may be accepted)"
        log_info "  Enable if no incoming services needed:"
        log_info "  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on"
    fi

    # Enable logging
    local log_status
    log_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>/dev/null || echo "unknown")
    if echo "$log_status" | grep -q "throttled\|detail"; then
        log_success "Firewall logging is enabled"
    else
        run_cmd "/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on 2>/dev/null || true"
        log_success "Enabled firewall logging"
    fi
}

undo_app_firewall() {
    log_warning "Application Firewall settings require manual review"
    log_info "  Manage via System Preferences > Network > Firewall"
}

# ============================================================================
# 6. Endpoint Security Posture Validation
# ============================================================================
# Validates that critical macOS security features are enabled:
# FileVault, Gatekeeper, SIP, EDR agents, and TCC protections.
# ============================================================================

check_endpoint_security() {
    log_info "6. Checking endpoint security posture..."

    local issues_found=0

    # --- 6a. EDR/AV Agent Detection ---
    log_info "  6a. Checking for EDR/AV agents..."
    local agents_found=0
    local agents=(
        "com.crowdstrike:CrowdStrike Falcon"
        "com.sentinelone:SentinelOne"
        "com.microsoft.wdav:Microsoft Defender"
        "com.sophos:Sophos"
        "com.carbonblack:CarbonBlack"
        "com.jamf:Jamf Protect"
    )
    for agent_entry in "${agents[@]}"; do
        local agent_id="${agent_entry%%:*}"
        local agent_name="${agent_entry##*:}"
        if launchctl list 2>/dev/null | grep -qi "$agent_id" || \
           pgrep -f "$agent_name" &>/dev/null 2>&1; then
            log_success "EDR agent running: $agent_name"
            agents_found=$((agents_found + 1))
        fi
    done

    if [[ $agents_found -eq 0 ]]; then
        log_warning "No EDR agents detected -- endpoint may be unprotected"
        issues_found=$((issues_found + 1))
    fi

    # --- 6b. FileVault Status ---
    log_info "  6b. Checking FileVault (disk encryption)..."
    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "Unknown")
    if echo "$fv_status" | grep -q "On"; then
        log_success "FileVault is enabled (disk encryption active)"
    else
        log_warning "FileVault is NOT enabled -- enable for data protection"
        log_info "  Enable: sudo fdesetup enable"
        issues_found=$((issues_found + 1))
    fi

    # --- 6c. Gatekeeper Status ---
    log_info "  6c. Checking Gatekeeper..."
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "Unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper is enabled"
    else
        log_warning "Gatekeeper is disabled -- enable for application security"
        log_info "  Enable: sudo spctl --master-enable"
        issues_found=$((issues_found + 1))
    fi

    # --- 6d. System Integrity Protection (SIP) ---
    log_info "  6d. Checking System Integrity Protection (SIP)..."
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "Unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "System Integrity Protection (SIP) is enabled"
    else
        log_warning "SIP is disabled -- this significantly weakens system security"
        log_info "  Enable via Recovery Mode: csrutil enable"
        issues_found=$((issues_found + 1))
    fi

    # --- 6e. XProtect Status ---
    log_info "  6e. Checking XProtect (built-in malware protection)..."
    local xprotect_version
    xprotect_version=$(system_profiler SPInstallHistoryDataType 2>/dev/null | \
        grep -A2 "XProtect" | grep "Version" | tail -1 | awk -F': ' '{print $2}' || echo "Unknown")
    log_info "  XProtect version: $xprotect_version"

    # --- 6f. Automatic Updates ---
    log_info "  6f. Checking automatic updates..."
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "0")
    if [[ "$auto_update" == "1" ]]; then
        log_success "Automatic software update checks enabled"
    else
        log_warning "Automatic update checks are disabled"
        log_info "  Enable: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true"
        issues_found=$((issues_found + 1))
    fi

    echo ""
    if [[ $issues_found -eq 0 ]]; then
        log_success "Endpoint security posture: GOOD (no issues found)"
    else
        log_warning "Endpoint security posture: $issues_found issue(s) found"
    fi
}

# ============================================================================
# 7. Launch Daemon Monitoring (T1543.004 - Create or Modify System Process)
# ============================================================================
# Monitors for unauthorized LaunchDaemons and LaunchAgents that could
# be used for persistence by ransomware operators.
# ============================================================================

check_launch_daemons() {
    log_info "7. Scanning for suspicious LaunchDaemons and LaunchAgents..."

    local suspicious_count=0
    local daemon_dirs=(
        "/Library/LaunchDaemons"
        "/Library/LaunchAgents"
    )

    for daemon_dir in "${daemon_dirs[@]}"; do
        if [[ -d "$daemon_dir" ]]; then
            log_info "  Scanning: $daemon_dir"
            for plist in "$daemon_dir"/*.plist; do
                if [[ -f "$plist" ]]; then
                    local label
                    label=$(defaults read "$plist" Label 2>/dev/null || basename "$plist" .plist)

                    # Check for suspicious indicators
                    local program
                    program=$(defaults read "$plist" Program 2>/dev/null || \
                             defaults read "$plist" ProgramArguments 2>/dev/null | head -2 | tail -1 || echo "")

                    # Flag items running from temp directories
                    if echo "$program" | grep -qE "^(/tmp|/var/tmp|/private/tmp|/dev/shm)"; then
                        log_warning "  SUSPICIOUS: $label runs from temp directory"
                        log_info "    Program: $program"
                        suspicious_count=$((suspicious_count + 1))
                    fi

                    # Flag items with .exe extension (unusual on macOS)
                    if echo "$program" | grep -qi "\.exe"; then
                        log_warning "  SUSPICIOUS: $label references .exe file"
                        log_info "    Program: $program"
                        suspicious_count=$((suspicious_count + 1))
                    fi
                fi
            done
        fi
    done

    # Also check per-user LaunchAgents
    for home_dir in /Users/*; do
        local user_agents="${home_dir}/Library/LaunchAgents"
        if [[ -d "$user_agents" ]]; then
            for plist in "$user_agents"/*.plist; do
                if [[ -f "$plist" ]]; then
                    local program
                    program=$(defaults read "$plist" Program 2>/dev/null || echo "")
                    if echo "$program" | grep -qE "^(/tmp|/var/tmp)" || \
                       echo "$program" | grep -qi "rclone\|svchost"; then
                        log_warning "  SUSPICIOUS user agent: $plist"
                        log_info "    Program: $program"
                        suspicious_count=$((suspicious_count + 1))
                    fi
                fi
            done
        fi
    done

    if [[ $suspicious_count -eq 0 ]]; then
        log_success "No suspicious LaunchDaemons/Agents found"
    else
        log_warning "Found $suspicious_count suspicious LaunchDaemon/Agent entries"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

if $UNDO_MODE; then
    echo ""
    log_warning "UNDO MODE: Reverting hardening changes..."
    echo ""
    undo_ssh
    remove_pf_rules
    remove_binary_monitor
    undo_app_firewall
    echo ""
    log_success "Undo complete. Some settings require manual review."
else
    log_info "HARDENING MODE: Applying defensive measures..."
    echo ""
    harden_ssh
    echo ""
    setup_pf_rules
    echo ""
    check_rclone
    echo ""
    setup_binary_monitor
    echo ""
    enforce_app_firewall
    echo ""
    check_endpoint_security
    echo ""
    check_launch_daemons
    echo ""
    log_success "All hardening measures applied."
    log_info "Log file: $LOG_FILE"
    log_info "Changes made: $CHANGES_MADE"
fi

echo ""
echo "============================================================"
echo "macOS hardening script complete."
echo "============================================================"
echo ""
echo "Post-execution checklist:"
echo "  1. Review /var/log/f0rt1ka/ for monitoring alerts"
echo "  2. Verify PF rules: sudo pfctl -a f0rt1ka-esxi-hardening -sr"
echo "  3. Verify firewall: /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
echo "  4. Verify FileVault: fdesetup status"
echo "  5. Verify SIP: csrutil status"
echo "  6. Test SSH connectivity from management network"
echo "============================================================"
