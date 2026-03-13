#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# ============================================================================
# Test ID:      54a0bd24-d75a-4d89-8dce-c381d932ca97
# Test Name:    Perfctl/Symbiote LD_PRELOAD Hijacking with PAM Credential Harvesting
# MITRE ATT&CK: T1574.006, T1003.008, T1548.001, T1014, T1059.004
# Mitigations:  M1038, M1028, M1022, M1047, M1050
#
# Purpose:
#   While Perfctl/Symbiote primarily target Linux, macOS has equivalent
#   attack surfaces: DYLD_INSERT_LIBRARIES (LD_PRELOAD equivalent), PAM
#   modules, SUID binaries, and LaunchDaemon/LaunchAgent persistence.
#   This script hardens macOS endpoints against the same class of attacks.
#
# Usage:
#   sudo ./54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening_macos.sh [apply|undo|check]
#
# Requires: root privileges (sudo)
# Idempotent: Yes (safe to run multiple times)
# Tested on: macOS 13 Ventura, macOS 14 Sonoma, macOS 15 Sequoia
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_NAME="$(basename "$0")"
BACKUP_DIR="/var/backups/f0rtika-hardening-54a0bd24"
LOG_FILE="/var/log/f0rtika-hardening-54a0bd24.log"
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

ensure_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
}

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        local dest="${BACKUP_DIR}/$(basename "$src").bak.$(date '+%Y%m%d%H%M%S')"
        cp -a "$src" "$dest"
        log_info "Backed up $src -> $dest"
    fi
}

# ============================================================================
# 1. Verify SIP and DYLD_INSERT_LIBRARIES Protection (T1574.006)
# ============================================================================
# macOS equivalent of LD_PRELOAD is DYLD_INSERT_LIBRARIES. SIP blocks
# this for protected binaries, but third-party apps remain vulnerable.

harden_dyld() {
    log_info "=== Checking DYLD_INSERT_LIBRARIES protection ==="

    # Check System Integrity Protection status
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")

    if echo "$sip_status" | grep -q "enabled"; then
        log_success "System Integrity Protection (SIP) is ENABLED"
        log_info "  SIP blocks DYLD_INSERT_LIBRARIES for Apple system binaries"
    else
        log_warning "CRITICAL: SIP is DISABLED - system vulnerable to DYLD injection"
        log_warning "  Re-enable SIP: boot to Recovery Mode -> csrutil enable"
    fi

    # Check Gatekeeper status
    local gatekeeper
    gatekeeper=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gatekeeper" | grep -q "enabled"; then
        log_success "Gatekeeper is enabled - unsigned dylibs will be blocked"
    else
        log_warning "Gatekeeper is disabled - enable with: sudo spctl --master-enable"
    fi

    # Check for any DYLD environment variables in LaunchDaemons/Agents
    log_info "Scanning LaunchDaemons/Agents for DYLD_INSERT_LIBRARIES..."
    local suspicious=0
    for dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents /System/Library/LaunchDaemons; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' plist; do
                if grep -q "DYLD_INSERT_LIBRARIES\|DYLD_LIBRARY_PATH\|DYLD_FRAMEWORK_PATH" "$plist" 2>/dev/null; then
                    log_warning "SUSPICIOUS: $plist contains DYLD environment variable"
                    suspicious=$((suspicious + 1))
                fi
            done < <(find "$dir" -name "*.plist" -print0 2>/dev/null)
        fi
    done
    if [[ $suspicious -eq 0 ]]; then
        log_success "No suspicious DYLD variables found in LaunchDaemons/Agents"
    fi

    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_dyld() {
    log_info "=== DYLD protection relies on SIP - no changes to undo ==="
}

check_dyld() {
    harden_dyld
}

# ============================================================================
# 2. Harden PAM Configuration (T1003.008)
# ============================================================================
# macOS uses PAM for authentication. Protect against rogue PAM modules.

harden_pam() {
    log_info "=== Hardening PAM configuration ==="

    # Verify PAM directory permissions
    if [[ -d /etc/pam.d ]]; then
        chmod 755 /etc/pam.d
        chown root:wheel /etc/pam.d
        log_success "Secured /etc/pam.d directory permissions"

        # Check PAM module integrity
        for pamfile in /etc/pam.d/*; do
            if [[ -f "$pamfile" ]]; then
                chmod 644 "$pamfile"
                chown root:wheel "$pamfile"
            fi
        done
        log_success "Secured all PAM configuration file permissions"
    fi

    # Check for non-Apple PAM modules
    log_info "Checking for unauthorized PAM modules..."
    local pam_dir="/usr/lib/pam"
    if [[ -d "$pam_dir" ]]; then
        while IFS= read -r module; do
            # Check if module is signed by Apple
            local sig
            sig=$(codesign -v "$module" 2>&1 || echo "unsigned")
            if echo "$sig" | grep -q "invalid\|unsigned\|not signed"; then
                log_warning "SUSPICIOUS: Unsigned PAM module: $module"
            fi
        done < <(find "$pam_dir" -name "*.so" -o -name "*.dylib" 2>/dev/null)
    fi

    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_pam() {
    log_info "=== PAM hardening uses standard permissions, no undo needed ==="
}

check_pam() {
    harden_pam
}

# ============================================================================
# 3. Credential File Protection (T1003.008)
# ============================================================================
# macOS stores credentials in the Keychain and Open Directory.

harden_credentials() {
    log_info "=== Hardening credential storage ==="

    # macOS uses /var/db/dslocal/nodes/Default/ for local user database
    local dslocal="/var/db/dslocal/nodes/Default"
    if [[ -d "$dslocal" ]]; then
        chmod 700 "$dslocal"
        chown root:wheel "$dslocal"
        log_success "Secured Open Directory local store permissions"
    fi

    # Protect the Keychain database directory
    local keychain_db="/Library/Keychains"
    if [[ -d "$keychain_db" ]]; then
        chmod 755 "$keychain_db"
        chown root:admin "$keychain_db"
        log_success "Secured system Keychain directory permissions"
    fi

    # Check for password hash exposure
    local master_passwd="/etc/master.passwd"
    if [[ -f "$master_passwd" ]]; then
        local perms
        perms=$(stat -f "%Lp" "$master_passwd" 2>/dev/null)
        if [[ "$perms" != "600" ]]; then
            chmod 600 "$master_passwd"
            log_success "Secured /etc/master.passwd (was $perms, now 600)"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_success "/etc/master.passwd already secure (600)"
        fi
    fi

    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_credentials() {
    log_info "=== Credential hardening uses standard permissions, no undo needed ==="
}

check_credentials() {
    harden_credentials
}

# ============================================================================
# 4. Audit SUID Binaries (T1548.001)
# ============================================================================
# macOS has fewer SUID binaries than Linux, but they still exist.

harden_suid() {
    log_info "=== Auditing SUID binaries on macOS ==="

    # Dangerous SUID binaries (should not have SUID on macOS)
    local dangerous_suid=(
        /usr/bin/vim
        /usr/bin/nano
        /usr/bin/python
        /usr/bin/python3
        /usr/bin/perl
        /usr/bin/ruby
        /usr/bin/env
        /usr/local/bin/nmap
    )

    for binary in "${dangerous_suid[@]}"; do
        if [[ -f "$binary" ]]; then
            local perms
            perms=$(stat -f "%Lp" "$binary" 2>/dev/null)
            if [[ "$perms" =~ ^4 ]] || [[ "$perms" =~ ^6 ]]; then
                backup_file "$binary"
                chmod u-s "$binary"
                log_success "Removed SUID from $binary (was $perms)"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        fi
    done

    # List all SUID binaries for review
    log_info "Current SUID binaries on system:"
    find / -type f -perm -u=s 2>/dev/null | while read -r binary; do
        log_info "  SUID: $binary"
    done

    log_success "SUID audit complete"
}

undo_suid() {
    log_info "=== SUID bits cannot be safely auto-restored ==="
    log_warning "Review backed up permissions in $BACKUP_DIR"
}

check_suid() {
    log_info "=== Checking for dangerous SUID binaries ==="
    local found=0
    for binary in /usr/bin/vim /usr/bin/nano /usr/bin/python /usr/bin/python3 /usr/bin/perl /usr/bin/ruby /usr/bin/env; do
        if [[ -f "$binary" ]]; then
            local perms
            perms=$(stat -f "%Lp" "$binary" 2>/dev/null)
            if [[ "$perms" =~ ^4 ]] || [[ "$perms" =~ ^6 ]]; then
                log_warning "DANGEROUS: $binary has SUID ($perms)"
                found=$((found + 1))
            fi
        fi
    done
    if [[ $found -eq 0 ]]; then
        log_success "No dangerous SUID binaries found"
    fi
}

# ============================================================================
# 5. LaunchDaemon/Agent Monitoring (Persistence Prevention)
# ============================================================================
# macOS equivalent of systemd service creation for persistence.

harden_launchdaemons() {
    log_info "=== Hardening LaunchDaemon/Agent directories ==="

    # Secure LaunchDaemon directories
    for dir in /Library/LaunchDaemons /Library/LaunchAgents; do
        if [[ -d "$dir" ]]; then
            chmod 755 "$dir"
            chown root:wheel "$dir"
            log_success "Secured $dir permissions"
        fi
    done

    # Check for suspicious LaunchDaemons
    log_info "Scanning for suspicious LaunchDaemons..."
    local suspicious=0
    for plist in /Library/LaunchDaemons/*.plist; do
        if [[ -f "$plist" ]]; then
            # Check if referencing binaries in unusual locations
            if grep -q "/tmp/\|/var/tmp/\|/dev/shm/\|/Users/" "$plist" 2>/dev/null; then
                log_warning "SUSPICIOUS LaunchDaemon: $plist references temp/user directory"
                suspicious=$((suspicious + 1))
            fi
        fi
    done

    if [[ $suspicious -eq 0 ]]; then
        log_success "No suspicious LaunchDaemons found"
    fi

    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_launchdaemons() {
    log_info "=== LaunchDaemon hardening uses standard permissions, no undo needed ==="
}

check_launchdaemons() {
    harden_launchdaemons
}

# ============================================================================
# 6. Enable Enhanced Logging (Detection Enhancement)
# ============================================================================

harden_logging() {
    log_info "=== Configuring enhanced logging ==="

    # Enable audit logging
    if [[ -f /etc/security/audit_control ]]; then
        backup_file /etc/security/audit_control

        # Check if file_create/exec flags are already present
        if ! grep -q "fc,fd,pc,ex" /etc/security/audit_control 2>/dev/null; then
            log_info "Consider adding 'fc,fd,pc,ex' to audit flags in /etc/security/audit_control"
            log_info "This enables: file creation, deletion, process creation, exec monitoring"
        fi
    fi

    # macOS Unified Logging recommendations
    log_info "macOS Unified Logging recommendations:"
    log_info "  - Enable Endpoint Security framework events via MDM"
    log_info "  - Deploy an EDR agent with file and process monitoring"
    log_info "  - Monitor /var/log/install.log for package installations"

    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_logging() {
    log_info "=== Logging enhancements should not be reverted ==="
}

check_logging() {
    if [[ -f /etc/security/audit_control ]]; then
        log_info "macOS audit_control:"
        grep "^flags" /etc/security/audit_control 2>/dev/null || log_warning "No flags line found"
    fi
}

# ============================================================================
# 7. Firewall and DNS Blocking (Block Mining Pools)
# ============================================================================

harden_firewall() {
    log_info "=== Configuring firewall rules ==="

    # Enable macOS Application Firewall
    /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null || true
    /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off 2>/dev/null || true
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null || true
    log_success "Enabled macOS Application Firewall with stealth mode"

    # Block known mining pool DNS via /etc/hosts
    local hosts_file="/etc/hosts"
    backup_file "$hosts_file"

    local mining_domains=(
        "supportxmr.com"
        "xmrpool.eu"
        "pool.minexmr.com"
        "pool.hashvault.pro"
        "mine.c3pool.com"
        "rx.unmineable.com"
    )

    for domain in "${mining_domains[@]}"; do
        if ! grep -qF "$domain" "$hosts_file" 2>/dev/null; then
            echo "0.0.0.0 $domain  # F0RT1KA: Block mining pool" >> "$hosts_file"
            echo "0.0.0.0 www.$domain  # F0RT1KA: Block mining pool" >> "$hosts_file"
            log_success "Blocked DNS resolution for $domain"
        fi
    done

    # Flush DNS cache
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    log_success "Flushed DNS cache"

    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_firewall() {
    log_info "=== Removing mining pool DNS blocks ==="
    local hosts_file="/etc/hosts"
    if [[ -f "$hosts_file" ]]; then
        backup_file "$hosts_file"
        grep -v "F0RT1KA: Block mining pool" "$hosts_file" > "${hosts_file}.tmp"
        mv "${hosts_file}.tmp" "$hosts_file"
        dscacheutil -flushcache 2>/dev/null || true
        killall -HUP mDNSResponder 2>/dev/null || true
        log_success "Removed mining pool DNS blocks"
    fi
}

check_firewall() {
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$fw_status" | grep -q "enabled"; then
        log_success "macOS Application Firewall enabled"
    else
        log_warning "macOS Application Firewall NOT enabled"
    fi

    local blocked
    blocked=$(grep -c "F0RT1KA: Block mining pool" /etc/hosts 2>/dev/null || echo "0")
    if [[ "$blocked" -gt 0 ]]; then
        log_success "Mining pool DNS blocks active ($blocked entries)"
    else
        log_warning "No mining pool DNS blocks found"
    fi
}

# ============================================================================
# 8. Shell Profile Protection (T1574.006)
# ============================================================================

harden_profiles() {
    log_info "=== Checking shell profiles for DYLD/LD_PRELOAD injection ==="

    local profiles=(
        "$HOME/.profile"
        "$HOME/.bashrc"
        "$HOME/.bash_profile"
        "$HOME/.zshrc"
        "$HOME/.zprofile"
        /etc/profile
    )

    for profile in "${profiles[@]}"; do
        if [[ -f "$profile" ]]; then
            if grep -q "DYLD_INSERT_LIBRARIES\|LD_PRELOAD\|DYLD_LIBRARY_PATH" "$profile" 2>/dev/null; then
                log_warning "SUSPICIOUS: $profile contains library injection variable"
                grep "DYLD_INSERT_LIBRARIES\|LD_PRELOAD\|DYLD_LIBRARY_PATH" "$profile"
            fi
        fi
    done

    log_success "Shell profile scan complete"
}

undo_profiles() {
    log_info "=== Profile checking is non-destructive, no undo needed ==="
}

check_profiles() {
    harden_profiles
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    local action="${1:-apply}"

    check_root
    check_macos
    ensure_backup_dir

    echo ""
    log_info "============================================================"
    log_info "F0RT1KA macOS Hardening Script"
    log_info "Test: Perfctl/Symbiote LD_PRELOAD Hijacking"
    log_info "ID: 54a0bd24-d75a-4d89-8dce-c381d932ca97"
    log_info "Action: $action"
    log_info "============================================================"
    echo ""

    case "$action" in
        apply)
            harden_dyld
            harden_pam
            harden_credentials
            harden_suid
            harden_launchdaemons
            harden_logging
            harden_firewall
            harden_profiles
            echo ""
            log_info "============================================================"
            log_success "Hardening COMPLETE. $CHANGE_COUNT areas addressed."
            log_info "Backups saved to: $BACKUP_DIR"
            log_info "Log file: $LOG_FILE"
            log_info "============================================================"
            ;;
        undo)
            undo_dyld
            undo_pam
            undo_credentials
            undo_suid
            undo_launchdaemons
            undo_logging
            undo_firewall
            undo_profiles
            echo ""
            log_warning "Hardening REVERTED. Review system security posture."
            ;;
        check)
            check_dyld
            check_pam
            check_credentials
            check_suid
            check_launchdaemons
            check_logging
            check_firewall
            check_profiles
            echo ""
            log_info "============================================================"
            log_info "Security posture check complete."
            log_info "============================================================"
            ;;
        *)
            log_error "Usage: $SCRIPT_NAME [apply|undo|check]"
            exit 1
            ;;
    esac
}

main "$@"
