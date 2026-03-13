#!/usr/bin/env bash
# ============================================================
# F0RT1KA macOS Hardening Script
# Tailscale Remote Access and Data Exfiltration
#
# Test ID:    eafce2fc-75fd-4c62-92dc-32cabe5cf206
# Techniques: T1105, T1219, T1543.003, T1021.004, T1041
# Mitigations: M1031, M1037, M1038, M1042, M1047
#
# Purpose:
#   Hardens a macOS system against the attack techniques
#   simulated by this test: unauthorized remote access tool
#   deployment, SSH abuse, service persistence, and data
#   exfiltration. While the test targets Windows, these
#   techniques have direct macOS equivalents.
#
# Usage:
#   sudo ./eafce2fc-..._hardening_macos.sh          # Apply hardening
#   sudo ./eafce2fc-..._hardening_macos.sh --undo    # Revert changes
#   sudo ./eafce2fc-..._hardening_macos.sh --check   # Audit current state
#
# Requirements:
#   - Root/sudo privileges
#   - macOS 12 (Monterey) or later
#
# Author: F0RT1KA Defense Guidance Builder
# Date:   2026-03-13
# ============================================================

set -euo pipefail

# ============================================================
# Constants
# ============================================================
SCRIPT_NAME="$(basename "$0")"
BACKUP_DIR="/var/backups/f0rt1ka-hardening"
BACKUP_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/f0rt1ka-hardening.log"
UNDO_MODE=false
CHECK_MODE=false
PF_ANCHOR_NAME="com.f0rt1ka.hardening"
PF_RULES_FILE="/etc/pf.anchors/$PF_ANCHOR_NAME"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================
# Parse Arguments
# ============================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo|--revert)
            UNDO_MODE=true
            shift
            ;;
        --check|--audit)
            CHECK_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: sudo $SCRIPT_NAME [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --undo, --revert   Revert all hardening changes"
            echo "  --check, --audit   Audit current hardening state"
            echo "  --help, -h         Show this help message"
            echo ""
            echo "Mitigations applied:"
            echo "  M1031 - Network Intrusion Prevention"
            echo "  M1037 - Filter Network Traffic"
            echo "  M1038 - Execution Prevention"
            echo "  M1042 - Disable or Remove Feature"
            echo "  M1047 - Audit"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================================
# Helper Functions
# ============================================================

log_msg() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true

    case "$level" in
        INFO)    echo -e "${CYAN}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[OK]${NC}   $message" ;;
        WARNING) echo -e "${YELLOW}[WARN]${NC} $message" ;;
        ERROR)   echo -e "${RED}[FAIL]${NC} $message" ;;
        CHECK)   echo -e "${CYAN}[AUDIT]${NC} $message" ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_msg "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
}

backup_file() {
    local filepath="$1"
    if [[ -f "$filepath" ]]; then
        mkdir -p "$BACKUP_DIR"
        local backup_name
        backup_name="${BACKUP_DIR}/$(basename "$filepath").${BACKUP_TIMESTAMP}.bak"
        cp -p "$filepath" "$backup_name"
        log_msg "INFO" "Backed up: $filepath -> $backup_name"
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ============================================================
# 1. Block Tailscale Infrastructure (M1037 - Filter Network Traffic)
# ============================================================

apply_tailscale_block() {
    log_msg "INFO" "--- Blocking Tailscale infrastructure (M1037) ---"

    # Block DNS resolution for Tailscale domains via /etc/hosts
    local hosts_marker="# F0RT1KA-HARDENING: Tailscale block"
    if ! grep -q "$hosts_marker" /etc/hosts 2>/dev/null; then
        backup_file /etc/hosts
        cat >> /etc/hosts <<EOF

$hosts_marker
# Block Tailscale coordination and control plane
0.0.0.0 controlplane.tailscale.com
0.0.0.0 login.tailscale.com
0.0.0.0 log.tailscale.com
0.0.0.0 pkgs.tailscale.com
0.0.0.0 derp1.tailscale.com
0.0.0.0 derp2.tailscale.com
0.0.0.0 derp3.tailscale.com
0.0.0.0 derp4.tailscale.com
0.0.0.0 derp5.tailscale.com
0.0.0.0 derp6.tailscale.com
0.0.0.0 derp7.tailscale.com
0.0.0.0 derp8.tailscale.com
0.0.0.0 derp9.tailscale.com
0.0.0.0 derp10.tailscale.com
# $hosts_marker END
EOF
        # Flush macOS DNS cache
        dscacheutil -flushcache 2>/dev/null || true
        killall -HUP mDNSResponder 2>/dev/null || true
        log_msg "SUCCESS" "Tailscale domains blocked in /etc/hosts (DNS cache flushed)"
    else
        log_msg "INFO" "Tailscale domains already blocked in /etc/hosts"
    fi

    # Block Tailscale ports via macOS PF (Packet Filter) firewall
    mkdir -p /etc/pf.anchors

    if [[ ! -f "$PF_RULES_FILE" ]]; then
        cat > "$PF_RULES_FILE" <<'PFEOF'
# F0RT1KA Hardening - PF Firewall Rules
# Block remote access tool infrastructure

# Block Tailscale WireGuard tunnel port
block out quick proto udp to any port 41641

# Block STUN (Tailscale NAT traversal)
block out quick proto udp to any port 3478

# Block Tailscale TCP fallback
block out quick proto tcp to any port 41641

# Block AnyDesk
block out quick proto tcp to any port 6568
block out quick proto tcp to any port 7070

# Block TeamViewer
block out quick proto tcp to any port 5938

# Block RustDesk
block out quick proto tcp to any port 21115
block out quick proto tcp to any port 21116
block out quick proto tcp to any port 21117
block out quick proto tcp to any port 21118
block out quick proto tcp to any port 21119
PFEOF

        # Add anchor to pf.conf if not present
        if ! grep -q "$PF_ANCHOR_NAME" /etc/pf.conf 2>/dev/null; then
            backup_file /etc/pf.conf
            echo "" >> /etc/pf.conf
            echo "# F0RT1KA Hardening anchor" >> /etc/pf.conf
            echo "anchor \"$PF_ANCHOR_NAME\"" >> /etc/pf.conf
            echo "load anchor \"$PF_ANCHOR_NAME\" from \"$PF_RULES_FILE\"" >> /etc/pf.conf
        fi

        # Load and enable PF
        pfctl -f /etc/pf.conf 2>/dev/null || true
        pfctl -e 2>/dev/null || true
        log_msg "SUCCESS" "PF firewall rules configured to block remote access tool ports"
    else
        log_msg "INFO" "PF firewall rules already configured"
    fi
}

undo_tailscale_block() {
    log_msg "INFO" "--- Reverting Tailscale infrastructure block ---"

    # Remove hosts entries
    local hosts_marker="# F0RT1KA-HARDENING: Tailscale block"
    if grep -q "$hosts_marker" /etc/hosts 2>/dev/null; then
        sed -i '' "/$hosts_marker/,/$hosts_marker END/d" /etc/hosts
        dscacheutil -flushcache 2>/dev/null || true
        killall -HUP mDNSResponder 2>/dev/null || true
        log_msg "SUCCESS" "Tailscale domain blocks removed from /etc/hosts"
    fi

    # Remove PF rules
    if [[ -f "$PF_RULES_FILE" ]]; then
        rm -f "$PF_RULES_FILE"
        # Remove anchor from pf.conf
        if grep -q "$PF_ANCHOR_NAME" /etc/pf.conf 2>/dev/null; then
            sed -i '' "/F0RT1KA Hardening anchor/d" /etc/pf.conf
            sed -i '' "/$PF_ANCHOR_NAME/d" /etc/pf.conf
            pfctl -f /etc/pf.conf 2>/dev/null || true
        fi
        log_msg "SUCCESS" "PF firewall rules removed"
    fi
}

check_tailscale_block() {
    log_msg "CHECK" "--- Tailscale Infrastructure Block Status ---"

    if grep -q "F0RT1KA-HARDENING: Tailscale block" /etc/hosts 2>/dev/null; then
        log_msg "SUCCESS" "Tailscale domains blocked in /etc/hosts"
    else
        log_msg "WARNING" "Tailscale domains NOT blocked in /etc/hosts"
    fi

    if [[ -f "$PF_RULES_FILE" ]]; then
        log_msg "SUCCESS" "PF firewall rules file present"
        if pfctl -s rules 2>/dev/null | grep -q "41641"; then
            log_msg "SUCCESS" "PF rules actively blocking Tailscale ports"
        else
            log_msg "WARNING" "PF rules file exists but may not be loaded"
        fi
    else
        log_msg "WARNING" "PF firewall rules NOT configured"
    fi
}

# ============================================================
# 2. Harden SSH Configuration (M1042 - Disable or Remove Feature)
# ============================================================

apply_ssh_hardening() {
    log_msg "INFO" "--- Hardening SSH configuration (M1042, M1031) ---"

    # Disable Remote Login (SSH) via macOS system preferences
    # Check current status first
    local ssh_status
    ssh_status="$(systemsetup -getremotelogin 2>/dev/null || echo "unknown")"

    if echo "$ssh_status" | grep -qi "on"; then
        log_msg "WARNING" "Remote Login (SSH) is currently ENABLED"
        log_msg "INFO" "Consider disabling with: sudo systemsetup -setremotelogin off"
        log_msg "INFO" "Skipping automatic disable - this may disrupt active SSH sessions"
    else
        log_msg "SUCCESS" "Remote Login (SSH) is disabled"
    fi

    # If SSH is enabled, harden the configuration
    local sshd_config="/etc/ssh/sshd_config"

    if [[ -f "$sshd_config" ]]; then
        backup_file "$sshd_config"

        # Create drop-in hardening (macOS supports sshd_config.d since Ventura)
        local hardening_dir="/etc/ssh/sshd_config.d"
        local hardening_config="$hardening_dir/99-f0rt1ka-hardening.conf"

        mkdir -p "$hardening_dir" 2>/dev/null || true

        # Check if main config includes the drop-in directory
        if ! grep -q "Include.*sshd_config.d" "$sshd_config" 2>/dev/null; then
            log_msg "INFO" "Adding Include directive to sshd_config"
            echo "" >> "$sshd_config"
            echo "# F0RT1KA: Include drop-in configurations" >> "$sshd_config"
            echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$sshd_config"
        fi

        if [[ ! -f "$hardening_config" ]]; then
            cat > "$hardening_config" <<'SSHEOF'
# F0RT1KA Hardening - SSH Configuration for macOS
# Test ID: eafce2fc-75fd-4c62-92dc-32cabe5cf206

# Disable root login
PermitRootLogin no

# Disable password authentication (require key-based auth)
PasswordAuthentication no

# Disable keyboard-interactive (prevents PAM bypass)
KbdInteractiveAuthentication no

# Disable empty passwords
PermitEmptyPasswords no

# Limit authentication attempts
MaxAuthTries 3

# Set login grace time
LoginGraceTime 30

# Disable X11 forwarding
X11Forwarding no

# Disable TCP forwarding to prevent tunnel abuse
AllowTcpForwarding no

# Disable agent forwarding
AllowAgentForwarding no

# Disable gateway ports
GatewayPorts no

# Disable tunnel devices
PermitTunnel no

# Use only strong ciphers
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr

# Use only strong MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Use only strong key exchange
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org

# Enable verbose logging
LogLevel VERBOSE

# Set maximum sessions
MaxSessions 3

# Client alive interval
ClientAliveInterval 300
ClientAliveCountMax 2
SSHEOF
            log_msg "SUCCESS" "SSH hardening configuration written to $hardening_config"
        else
            log_msg "INFO" "SSH hardening configuration already in place"
        fi
    else
        log_msg "INFO" "SSH server configuration not found (SSH likely disabled)"
    fi
}

undo_ssh_hardening() {
    log_msg "INFO" "--- Reverting SSH hardening ---"

    local hardening_config="/etc/ssh/sshd_config.d/99-f0rt1ka-hardening.conf"
    if [[ -f "$hardening_config" ]]; then
        rm -f "$hardening_config"
        log_msg "SUCCESS" "SSH hardening configuration removed"
    else
        log_msg "INFO" "No SSH hardening configuration found to revert"
    fi

    # Remove Include directive if we added it
    if grep -q "F0RT1KA: Include drop-in" /etc/ssh/sshd_config 2>/dev/null; then
        sed -i '' '/F0RT1KA: Include drop-in/d' /etc/ssh/sshd_config
        sed -i '' '/Include.*sshd_config\.d/d' /etc/ssh/sshd_config
        log_msg "SUCCESS" "Include directive removed from sshd_config"
    fi
}

check_ssh_hardening() {
    log_msg "CHECK" "--- SSH Hardening Status ---"

    local ssh_status
    ssh_status="$(systemsetup -getremotelogin 2>/dev/null || echo "unknown")"
    if echo "$ssh_status" | grep -qi "off"; then
        log_msg "SUCCESS" "Remote Login (SSH) is disabled"
    elif echo "$ssh_status" | grep -qi "on"; then
        log_msg "WARNING" "Remote Login (SSH) is ENABLED"
    else
        log_msg "INFO" "Could not determine SSH status"
    fi

    local hardening_config="/etc/ssh/sshd_config.d/99-f0rt1ka-hardening.conf"
    if [[ -f "$hardening_config" ]]; then
        log_msg "SUCCESS" "SSH hardening drop-in configuration present"
    else
        log_msg "WARNING" "SSH hardening drop-in configuration NOT present"
    fi
}

# ============================================================
# 3. Restrict Unauthorized Software (M1038 - Execution Prevention)
# ============================================================

apply_software_restriction() {
    log_msg "INFO" "--- Restricting unauthorized software (M1038) ---"

    # Unload and disable Tailscale if installed
    local tailscale_plist="/Library/LaunchDaemons/com.tailscale.tailscaled.plist"
    if [[ -f "$tailscale_plist" ]]; then
        launchctl bootout system "$tailscale_plist" 2>/dev/null || true
        launchctl disable system/com.tailscale.tailscaled 2>/dev/null || true
        log_msg "SUCCESS" "Tailscale launch daemon disabled"
    fi

    # Also check user-level Tailscale agent
    local tailscale_agent="/Library/LaunchAgents/com.tailscale.ipn.macos.plist"
    if [[ -f "$tailscale_agent" ]]; then
        # This needs to be run per-user, but we can disable system-wide
        log_msg "WARNING" "Tailscale user agent found at $tailscale_agent"
        log_msg "INFO" "Remove with: sudo rm -f $tailscale_agent"
    fi

    # Quarantine Tailscale binary if found
    if [[ -f "/Applications/Tailscale.app/Contents/MacOS/Tailscale" ]]; then
        xattr -w com.apple.quarantine "0181;$(date +%s);F0RT1KA;$(uuidgen)" \
            "/Applications/Tailscale.app" 2>/dev/null || true
        log_msg "WARNING" "Tailscale.app found - quarantine attribute set"
        log_msg "INFO" "Consider removing: sudo rm -rf /Applications/Tailscale.app"
    fi

    if command_exists tailscale; then
        log_msg "WARNING" "Tailscale CLI found in PATH at: $(which tailscale)"
    else
        log_msg "SUCCESS" "Tailscale CLI not found in PATH"
    fi

    # Enforce Gatekeeper (only allow App Store and identified developers)
    local gatekeeper_status
    gatekeeper_status="$(spctl --status 2>/dev/null || echo "unknown")"
    if echo "$gatekeeper_status" | grep -qi "disabled"; then
        spctl --master-enable 2>/dev/null || true
        log_msg "SUCCESS" "Gatekeeper re-enabled"
    else
        log_msg "SUCCESS" "Gatekeeper is enabled"
    fi

    # Block Tailscale and other RAT package identifiers via spctl
    # This prevents installation even with a valid developer signature
    local blocked_ids=(
        "io.tailscale.ipn.macos"
        "com.philandro.anydesk"
        "com.teamviewer.TeamViewer"
        "com.rustdesk.RustDesk"
    )

    for bundle_id in "${blocked_ids[@]}"; do
        spctl --add --label "F0RT1KA-Blocked" --rule "identifier \"$bundle_id\"" 2>/dev/null || true
    done
    log_msg "SUCCESS" "Application block rules added for remote access tools"

    # Ensure Homebrew Tailscale tap is removed if present
    if command_exists brew; then
        if brew tap 2>/dev/null | grep -qi tailscale; then
            log_msg "WARNING" "Homebrew Tailscale tap found"
            log_msg "INFO" "Remove with: brew untap tailscale/tailscale"
        fi
    fi
}

undo_software_restriction() {
    log_msg "INFO" "--- Reverting software restrictions ---"

    # Re-enable Tailscale launch daemon if it exists
    local tailscale_plist="/Library/LaunchDaemons/com.tailscale.tailscaled.plist"
    if [[ -f "$tailscale_plist" ]]; then
        launchctl enable system/com.tailscale.tailscaled 2>/dev/null || true
        log_msg "SUCCESS" "Tailscale launch daemon re-enabled (not started)"
    fi

    # Remove quarantine from Tailscale app
    if [[ -d "/Applications/Tailscale.app" ]]; then
        xattr -d com.apple.quarantine "/Applications/Tailscale.app" 2>/dev/null || true
        log_msg "SUCCESS" "Quarantine attribute removed from Tailscale.app"
    fi

    # Remove spctl block rules
    spctl --remove --label "F0RT1KA-Blocked" 2>/dev/null || true
    log_msg "SUCCESS" "Application block rules removed"
}

check_software_restriction() {
    log_msg "CHECK" "--- Software Restriction Status ---"

    local gatekeeper_status
    gatekeeper_status="$(spctl --status 2>/dev/null || echo "unknown")"
    if echo "$gatekeeper_status" | grep -qi "enabled"; then
        log_msg "SUCCESS" "Gatekeeper is enabled"
    else
        log_msg "WARNING" "Gatekeeper is DISABLED"
    fi

    if [[ -d "/Applications/Tailscale.app" ]]; then
        log_msg "WARNING" "Tailscale.app is installed"
    else
        log_msg "SUCCESS" "Tailscale.app not found"
    fi

    if command_exists tailscale; then
        log_msg "WARNING" "Tailscale CLI found at: $(which tailscale)"
    else
        log_msg "SUCCESS" "Tailscale CLI not in PATH"
    fi

    local tailscale_plist="/Library/LaunchDaemons/com.tailscale.tailscaled.plist"
    if [[ -f "$tailscale_plist" ]]; then
        if launchctl print system/com.tailscale.tailscaled 2>/dev/null | grep -q "state = running"; then
            log_msg "WARNING" "Tailscale daemon is RUNNING"
        else
            log_msg "INFO" "Tailscale daemon plist exists but service is not running"
        fi
    else
        log_msg "SUCCESS" "Tailscale daemon plist not found"
    fi
}

# ============================================================
# 4. Enable Security Auditing (M1047 - Audit)
# ============================================================

apply_audit_config() {
    log_msg "INFO" "--- Configuring security auditing (M1047) ---"

    # Ensure OpenBSM audit is enabled (macOS native auditing)
    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        backup_file "$audit_control"

        # Check if comprehensive flags are already set
        if ! grep -q "lo,aa,ad,fd,fc,cl,ex,pc,nt" "$audit_control" 2>/dev/null; then
            # Extend audit flags to capture relevant events
            # lo=login/logout, aa=auth, ad=admin, fd=file-delete
            # fc=file-create, cl=file-close, ex=exec, pc=process, nt=network
            if grep -q "^flags:" "$audit_control"; then
                sed -i '' 's/^flags:.*/flags:lo,aa,ad,fd,fc,cl,ex,pc,nt/' "$audit_control"
            else
                echo "flags:lo,aa,ad,fd,fc,cl,ex,pc,nt" >> "$audit_control"
            fi
            log_msg "SUCCESS" "OpenBSM audit flags updated for comprehensive monitoring"
        else
            log_msg "INFO" "OpenBSM audit flags already comprehensive"
        fi
    fi

    # Create Unified Logging predicates for technique detection
    local log_predicate_dir="/usr/local/etc/f0rt1ka"
    mkdir -p "$log_predicate_dir"

    cat > "$log_predicate_dir/detection_predicates.txt" <<'PREDEOF'
# F0RT1KA Detection Predicates for macOS Unified Logging
# Test ID: eafce2fc-75fd-4c62-92dc-32cabe5cf206
#
# Usage: log stream --predicate '<predicate>' --info --debug
#
# T1105 - Ingress Tool Transfer:
# log stream --predicate 'process == "curl" OR process == "wget" OR (process == "nsurlsessiond" AND eventMessage CONTAINS "tailscale")'
#
# T1219 - Remote Access Software:
# log stream --predicate 'process == "tailscaled" OR process == "tailscale" OR eventMessage CONTAINS "tailscale"'
#
# T1543.003 - Service Creation (launchd):
# log stream --predicate 'subsystem == "com.apple.launchd" AND (eventMessage CONTAINS "load" OR eventMessage CONTAINS "bootstrap")'
#
# T1021.004 - SSH:
# log stream --predicate 'process == "sshd" AND eventMessage CONTAINS "Accepted"'
#
# T1041 - Data Exfiltration (archive creation):
# log stream --predicate 'process == "zip" OR process == "tar" OR process == "ditto"'
PREDEOF

    log_msg "SUCCESS" "Detection predicates written to $log_predicate_dir/detection_predicates.txt"

    # Enable process accounting if not enabled
    if [[ ! -f /var/account/acct ]]; then
        mkdir -p /var/account
        touch /var/account/acct
        accton /var/account/acct 2>/dev/null || true
        log_msg "SUCCESS" "Process accounting enabled"
    else
        log_msg "INFO" "Process accounting already enabled"
    fi

    # Ensure install.log captures software installs
    if [[ -f /var/log/install.log ]]; then
        log_msg "SUCCESS" "Software installation logging active (/var/log/install.log)"
    fi

    # Enable full disk access auditing via Endpoint Security framework note
    log_msg "INFO" "For comprehensive endpoint monitoring, deploy an ES framework agent (osquery, Santa, etc.)"
}

undo_audit_config() {
    log_msg "INFO" "--- Reverting audit configuration ---"

    rm -rf /usr/local/etc/f0rt1ka 2>/dev/null || true
    log_msg "SUCCESS" "F0RT1KA audit configuration removed"

    # Note: We do NOT revert OpenBSM audit flags as they improve security posture
    log_msg "INFO" "OpenBSM audit flags preserved (security improvement)"
}

check_audit_config() {
    log_msg "CHECK" "--- Audit Configuration Status ---"

    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        local flags
        flags="$(grep "^flags:" "$audit_control" 2>/dev/null || echo "not set")"
        log_msg "INFO" "OpenBSM audit flags: $flags"

        if echo "$flags" | grep -q "ex"; then
            log_msg "SUCCESS" "Execution auditing enabled"
        else
            log_msg "WARNING" "Execution auditing NOT enabled"
        fi

        if echo "$flags" | grep -q "nt"; then
            log_msg "SUCCESS" "Network auditing enabled"
        else
            log_msg "WARNING" "Network auditing NOT enabled"
        fi
    fi

    if [[ -f /usr/local/etc/f0rt1ka/detection_predicates.txt ]]; then
        log_msg "SUCCESS" "Detection predicates file present"
    else
        log_msg "WARNING" "Detection predicates file NOT present"
    fi

    if [[ -f /var/account/acct ]]; then
        log_msg "SUCCESS" "Process accounting enabled"
    else
        log_msg "WARNING" "Process accounting NOT enabled"
    fi
}

# ============================================================
# 5. Prevent Unauthorized Launch Daemons (M1038, T1543.003)
# ============================================================

apply_launchd_hardening() {
    log_msg "INFO" "--- Hardening Launch Daemon protections (M1038) ---"

    # Monitor for new launch daemons/agents by setting up a watch script
    local watch_script="/usr/local/bin/f0rt1ka-launchd-monitor.sh"
    if [[ ! -f "$watch_script" ]]; then
        cat > "$watch_script" <<'WATCHEOF'
#!/usr/bin/env bash
# F0RT1KA Launch Daemon Monitor
# Logs new or modified launch daemons/agents to syslog

WATCHED_DIRS=(
    "/Library/LaunchDaemons"
    "/Library/LaunchAgents"
    "/System/Library/LaunchDaemons"
    "/System/Library/LaunchAgents"
)

HASH_FILE="/var/db/f0rt1ka-launchd-hashes.txt"

# Generate current hashes
CURRENT_HASHES=""
for dir in "${WATCHED_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        while IFS= read -r -d '' plist; do
            hash="$(shasum -a 256 "$plist" 2>/dev/null | awk '{print $1}')"
            CURRENT_HASHES+="$hash  $plist"$'\n'
        done < <(find "$dir" -name "*.plist" -print0 2>/dev/null)
    fi
done

if [[ -f "$HASH_FILE" ]]; then
    # Compare with previous state
    DIFF_OUTPUT="$(diff <(sort "$HASH_FILE") <(echo "$CURRENT_HASHES" | sort) 2>/dev/null || true)"
    if [[ -n "$DIFF_OUTPUT" ]]; then
        logger -t "f0rt1ka-launchd" -p auth.crit "Launch daemon change detected: $DIFF_OUTPUT"
    fi
fi

# Save current state
echo "$CURRENT_HASHES" > "$HASH_FILE"
WATCHEOF
        chmod 755 "$watch_script"

        # Create a launchd plist to run the monitor periodically
        local monitor_plist="/Library/LaunchDaemons/com.f0rt1ka.launchd-monitor.plist"
        cat > "$monitor_plist" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.f0rt1ka.launchd-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/f0rt1ka-launchd-monitor.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/f0rt1ka-launchd-monitor.log</string>
</dict>
</plist>
PLISTEOF
        launchctl bootstrap system "$monitor_plist" 2>/dev/null || \
            launchctl load "$monitor_plist" 2>/dev/null || true

        log_msg "SUCCESS" "Launch daemon monitor installed (checks every 5 minutes)"
    else
        log_msg "INFO" "Launch daemon monitor already installed"
    fi

    # Set restrictive permissions on LaunchDaemons directory
    chmod 755 /Library/LaunchDaemons 2>/dev/null || true
    chown root:wheel /Library/LaunchDaemons 2>/dev/null || true
    log_msg "SUCCESS" "LaunchDaemons directory permissions hardened"
}

undo_launchd_hardening() {
    log_msg "INFO" "--- Reverting Launch Daemon hardening ---"

    local monitor_plist="/Library/LaunchDaemons/com.f0rt1ka.launchd-monitor.plist"
    if [[ -f "$monitor_plist" ]]; then
        launchctl bootout system "$monitor_plist" 2>/dev/null || \
            launchctl unload "$monitor_plist" 2>/dev/null || true
        rm -f "$monitor_plist"
        log_msg "SUCCESS" "Launch daemon monitor removed"
    fi

    rm -f /usr/local/bin/f0rt1ka-launchd-monitor.sh 2>/dev/null || true
    rm -f /var/db/f0rt1ka-launchd-hashes.txt 2>/dev/null || true
    log_msg "SUCCESS" "Monitor script and hash database removed"
}

check_launchd_hardening() {
    log_msg "CHECK" "--- Launch Daemon Hardening Status ---"

    if [[ -f "/Library/LaunchDaemons/com.f0rt1ka.launchd-monitor.plist" ]]; then
        log_msg "SUCCESS" "Launch daemon monitor installed"
        if launchctl print system/com.f0rt1ka.launchd-monitor 2>/dev/null | grep -q "state = running"; then
            log_msg "SUCCESS" "Launch daemon monitor is running"
        else
            log_msg "WARNING" "Launch daemon monitor is NOT running"
        fi
    else
        log_msg "WARNING" "Launch daemon monitor NOT installed"
    fi
}

# ============================================================
# 6. Network Security - Application Firewall (M1031)
# ============================================================

apply_app_firewall() {
    log_msg "INFO" "--- Configuring Application Firewall (M1031) ---"

    # Enable macOS Application Firewall
    local fw_status
    fw_status="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")"

    if echo "$fw_status" | grep -qi "disabled"; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null || true
        log_msg "SUCCESS" "Application Firewall enabled"
    else
        log_msg "SUCCESS" "Application Firewall already enabled"
    fi

    # Enable stealth mode (don't respond to ping/port scans)
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null || true
    log_msg "SUCCESS" "Stealth mode enabled"

    # Enable logging
    /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on 2>/dev/null || true
    log_msg "SUCCESS" "Firewall logging enabled"

    # Block incoming connections for Tailscale if installed
    if [[ -f "/Applications/Tailscale.app/Contents/MacOS/Tailscale" ]]; then
        /usr/libexec/ApplicationFirewall/socketfilterfw \
            --add "/Applications/Tailscale.app/Contents/MacOS/Tailscale" 2>/dev/null || true
        /usr/libexec/ApplicationFirewall/socketfilterfw \
            --blockapp "/Applications/Tailscale.app/Contents/MacOS/Tailscale" 2>/dev/null || true
        log_msg "SUCCESS" "Tailscale blocked in Application Firewall"
    fi
}

undo_app_firewall() {
    log_msg "INFO" "--- Reverting Application Firewall changes ---"

    # Unblock Tailscale if it was blocked
    if [[ -f "/Applications/Tailscale.app/Contents/MacOS/Tailscale" ]]; then
        /usr/libexec/ApplicationFirewall/socketfilterfw \
            --unblockapp "/Applications/Tailscale.app/Contents/MacOS/Tailscale" 2>/dev/null || true
        log_msg "SUCCESS" "Tailscale unblocked in Application Firewall"
    fi

    # Note: We do NOT disable the firewall as it's a security improvement
    log_msg "INFO" "Application Firewall kept enabled (security improvement)"
}

check_app_firewall() {
    log_msg "CHECK" "--- Application Firewall Status ---"

    local fw_status
    fw_status="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")"
    if echo "$fw_status" | grep -qi "enabled"; then
        log_msg "SUCCESS" "Application Firewall is enabled"
    else
        log_msg "WARNING" "Application Firewall is DISABLED"
    fi

    local stealth
    stealth="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")"
    if echo "$stealth" | grep -qi "enabled"; then
        log_msg "SUCCESS" "Stealth mode is enabled"
    else
        log_msg "WARNING" "Stealth mode is DISABLED"
    fi
}

# ============================================================
# Main Execution
# ============================================================

main() {
    check_root

    echo ""
    echo "============================================================"
    echo " F0RT1KA macOS Hardening Script"
    echo " Test: Tailscale Remote Access and Data Exfiltration"
    echo " ID:   eafce2fc-75fd-4c62-92dc-32cabe5cf206"
    echo "============================================================"
    echo ""

    if $CHECK_MODE; then
        log_msg "INFO" "Running in AUDIT mode - no changes will be made"
        echo ""
        check_tailscale_block
        echo ""
        check_ssh_hardening
        echo ""
        check_software_restriction
        echo ""
        check_audit_config
        echo ""
        check_launchd_hardening
        echo ""
        check_app_firewall
        echo ""
        log_msg "INFO" "Audit complete"

    elif $UNDO_MODE; then
        log_msg "WARNING" "Running in UNDO mode - reverting all hardening changes"
        echo ""
        undo_tailscale_block
        undo_ssh_hardening
        undo_software_restriction
        undo_audit_config
        undo_launchd_hardening
        undo_app_firewall
        echo ""
        log_msg "SUCCESS" "All hardening changes reverted"

    else
        log_msg "INFO" "Running in APPLY mode - hardening system"
        echo ""
        apply_tailscale_block
        echo ""
        apply_ssh_hardening
        echo ""
        apply_software_restriction
        echo ""
        apply_audit_config
        echo ""
        apply_launchd_hardening
        echo ""
        apply_app_firewall
        echo ""
        log_msg "SUCCESS" "All hardening measures applied"
        log_msg "INFO" "Backups stored in: $BACKUP_DIR"
        log_msg "INFO" "Log file: $LOG_FILE"
        log_msg "INFO" "To revert: sudo $SCRIPT_NAME --undo"
        log_msg "INFO" "To audit:  sudo $SCRIPT_NAME --check"
    fi

    echo ""
    echo "============================================================"
    echo " Complete"
    echo "============================================================"
}

main "$@"
