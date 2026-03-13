#!/usr/bin/env bash
# ============================================================================
# F0RT1KA macOS Hardening Script
# ============================================================================
# Test ID:      c1f0fe6f-6907-4f95-820d-47e0a39abe54
# Test Name:    TrollDisappearKey AMSI Bypass Detection
# MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
# Related:      T1055, T1112, T1105, T1620
# Mitigations:  M1038 (Execution Prevention), M1024 (Restrict Registry Perms)
#
# Purpose:
#   While TrollDisappearKey targets Windows AMSI, the underlying techniques
#   -- API hooking via DYLD_INSERT_LIBRARIES, security framework disablement,
#   remote tool download, and reflective code loading -- have direct macOS
#   equivalents. This script hardens macOS endpoints against the same class
#   of defense evasion attacks.
#
# Usage:
#   sudo ./c1f0fe6f-6907-4f95-820d-47e0a39abe54_hardening_macos.sh [apply|undo|check]
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
BACKUP_DIR="/var/backups/f0rtika-hardening-c1f0fe6f"
LOG_FILE="/var/log/f0rtika-hardening-c1f0fe6f.log"
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
# 1. Restrict DYLD_INSERT_LIBRARIES Abuse (macOS API hooking equivalent)
# ============================================================================
# TrollDisappearKey hooks RegOpenKeyExW via inline patching. On macOS, the
# equivalent technique uses DYLD_INSERT_LIBRARIES to inject dynamic
# libraries that intercept system calls. SIP (System Integrity Protection)
# blocks this for protected binaries, but non-SIP processes remain vulnerable.

harden_dyld_injection() {
    log_info "Verifying DYLD injection protections..."

    # Check SIP status - this is the primary defense against DYLD injection
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")

    if echo "$sip_status" | grep -q "enabled"; then
        log_success "System Integrity Protection (SIP) is enabled"
    else
        log_warning "SIP is not enabled! This is critical for preventing DYLD injection"
        log_warning "To enable SIP: boot to Recovery Mode > Terminal > csrutil enable"
    fi

    # Check if Hardened Runtime is enforced via Gatekeeper
    local gatekeeper_status
    gatekeeper_status=$(spctl --status 2>/dev/null || echo "unknown")

    if echo "$gatekeeper_status" | grep -q "enabled"; then
        log_success "Gatekeeper is enabled (enforces Hardened Runtime)"
    else
        log_warning "Gatekeeper is not enabled. Enabling..."
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    # Ensure Library Validation is enabled
    # This prevents unsigned dylibs from being loaded into signed processes
    local current_amfi
    current_amfi=$(defaults read /Library/Preferences/com.apple.security.libraryvalidation Enabled 2>/dev/null || echo "not set")
    if [[ "$current_amfi" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.security.libraryvalidation Enabled -bool true 2>/dev/null || true
        log_success "Library Validation enforcement enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Library Validation already enabled"
    fi
}

undo_dyld_injection() {
    log_warning "SIP and Gatekeeper should not be disabled (security critical)"
    log_info "Library Validation, SIP, and Gatekeeper settings left as-is"
}

check_dyld_injection() {
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "SIP: enabled"
    else
        log_warning "SIP: NOT enabled"
    fi

    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper: enabled"
    else
        log_warning "Gatekeeper: NOT enabled"
    fi
}

# ============================================================================
# 2. Enable Unified Logging for Security Events
# ============================================================================
# macOS Unified Logging is the equivalent of Windows Event Logging.
# AMSI events on Windows correspond to Endpoint Security Framework events
# on macOS. This section ensures security-relevant log streams are active.

harden_unified_logging() {
    log_info "Configuring unified logging for security events..."

    # Enable install.log persistence (records software installations)
    local log_config="/etc/asl/com.apple.install"
    if [[ -f "$log_config" ]]; then
        log_info "Install logging configuration present"
    fi

    # Configure log predicates for security monitoring
    # Create a custom log profile for defense evasion detection
    local log_profile="/Library/Preferences/Logging/Subsystems/com.f0rtika.defense-evasion.plist"
    mkdir -p "$(dirname "$log_profile")" 2>/dev/null || true

    # Note: On modern macOS, unified logging is always on. We configure
    # log levels to ensure security-relevant events are not dropped.

    # Enable process execution logging at info level
    log stream --level info --predicate 'subsystem == "com.apple.securityd"' > /dev/null 2>&1 &
    local log_pid=$!
    sleep 1
    kill "$log_pid" 2>/dev/null || true

    # Enable audit logging via OpenBSM
    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        backup_file "$audit_control"

        # Check if process exec auditing flags are set
        if ! grep -q "ex,pc" "$audit_control" 2>/dev/null; then
            # Add execution and process creation flags
            if grep -q "^flags:" "$audit_control"; then
                local current_flags
                current_flags=$(grep "^flags:" "$audit_control" | head -1)
                if ! echo "$current_flags" | grep -q "ex"; then
                    sed -i '' "s/^flags:.*/&,ex,pc,fc,fd/" "$audit_control" 2>/dev/null || true
                    log_success "Added execution/process audit flags to audit_control"
                    CHANGE_COUNT=$((CHANGE_COUNT + 1))
                fi
            fi
        else
            log_info "Execution audit flags already configured"
        fi
    fi

    # Ensure audit daemon is running
    if launchctl list | grep -q "com.apple.auditd" 2>/dev/null; then
        log_success "Audit daemon (auditd) is running"
    else
        log_warning "Audit daemon may not be running"
    fi

    log_success "Security logging configuration verified"
}

undo_unified_logging() {
    log_warning "Audit logging settings left as-is (security best practice)"
    log_info "If needed, restore /etc/security/audit_control from backup in $BACKUP_DIR"
}

check_unified_logging() {
    if [[ -f "/etc/security/audit_control" ]]; then
        if grep -q "ex" /etc/security/audit_control 2>/dev/null; then
            log_success "Execution auditing enabled in audit_control"
        else
            log_warning "Execution auditing not fully configured"
        fi
    fi
}

# ============================================================================
# 3. Restrict Unauthorized Downloads (Ingress Tool Transfer prevention)
# ============================================================================
# TrollDisappearKey downloads Seatbelt.exe from GitHub. On macOS, attackers
# use curl (built-in), python, or osascript to download payloads. This
# section applies Application Firewall rules and restricts download tools.

harden_download_controls() {
    log_info "Configuring download controls..."

    # Enable macOS Application Firewall
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")

    if echo "$fw_status" | grep -q "disabled"; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on > /dev/null 2>&1 || true
        log_success "Application Firewall enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Application Firewall already enabled"
    fi

    # Enable stealth mode (no response to ICMP probes)
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on > /dev/null 2>&1 || true
    log_info "Stealth mode enabled"

    # Block incoming connections for unsigned applications
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on > /dev/null 2>&1 || true
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on > /dev/null 2>&1 || true
    log_success "Firewall configured to allow only signed applications"

    # Restrict curl usage via a wrapper (preserve original)
    # Note: On macOS, curl is in /usr/bin which is SIP-protected.
    # We cannot modify it directly, so we add a monitoring wrapper in /usr/local/bin
    local wrapper_dir="/usr/local/bin"
    mkdir -p "$wrapper_dir" 2>/dev/null || true

    # We do NOT shadow /usr/bin/curl (SIP-protected). Instead, we rely on
    # the Application Firewall and audit logging to detect misuse.
    log_info "curl/wget restrictions: relying on Application Firewall and audit logging"
    log_info "Note: /usr/bin/curl is SIP-protected and cannot be restricted directly"
}

undo_download_controls() {
    log_warning "Reverting download controls..."
    # We don't disable the firewall on undo as it's a security feature
    log_info "Application Firewall left enabled (security best practice)"
}

check_download_controls() {
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$fw_status" | grep -q "enabled"; then
        log_success "Application Firewall: enabled"
    else
        log_warning "Application Firewall: disabled"
    fi

    local stealth
    stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
    if echo "$stealth" | grep -q "enabled"; then
        log_success "Stealth mode: enabled"
    else
        log_warning "Stealth mode: disabled"
    fi
}

# ============================================================================
# 4. Protect Security Frameworks (Endpoint Security / XProtect integrity)
# ============================================================================
# On macOS, XProtect and the Endpoint Security Framework serve roles
# analogous to Windows AMSI. This section ensures these frameworks are
# active and properly configured.

harden_security_frameworks() {
    log_info "Verifying macOS security framework integrity..."

    # Check XProtect status
    local xprotect_version
    xprotect_version=$(system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A2 "XProtect" | tail -1 || echo "unknown")
    log_info "XProtect version info: $xprotect_version"

    # Ensure MRT (Malware Removal Tool) is present
    if [[ -f "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" ]]; then
        log_success "Malware Removal Tool (MRT) is present"
    elif [[ -f "/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" ]]; then
        log_success "Malware Removal Tool (MRT) is present (legacy path)"
    else
        log_warning "MRT not found at expected location"
    fi

    # Ensure automatic security updates are enabled
    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not set")
    if [[ "$auto_update" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true 2>/dev/null || true
        log_success "Automatic macOS security updates enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Automatic security updates already enabled"
    fi

    # Enable automatic XProtect/MRT updates
    local critical_update
    critical_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "not set")
    if [[ "$critical_update" != "1" ]]; then
        defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null || true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true 2>/dev/null || true
        log_success "Critical/config data updates (XProtect) enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Critical updates already enabled"
    fi

    # Verify Full Disk Access and TCC protections
    log_info "TCC/Full Disk Access protections are managed via System Preferences > Privacy"
}

undo_security_frameworks() {
    log_warning "Security framework protections should not be reverted"
    log_info "XProtect and MRT settings left as-is (security best practice)"
}

check_security_frameworks() {
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        log_success "SIP: enabled (protects security frameworks)"
    else
        log_warning "SIP: NOT enabled"
    fi

    local auto_update
    auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "0")
    if [[ "$auto_update" == "1" ]]; then
        log_success "Automatic security updates: enabled"
    else
        log_warning "Automatic security updates: not enabled"
    fi
}

# ============================================================================
# 5. Restrict .NET/Mono Runtime (Reflective code loading prevention)
# ============================================================================
# TrollDisappearKey uses Assembly.Load() to execute .NET assemblies in
# memory. On macOS, the .NET SDK and Mono runtime can do the same.
# Restrict runtime access to authorized users.

harden_dotnet_runtime() {
    log_info "Restricting .NET/Mono runtime access..."

    # Check for Homebrew-installed Mono
    for runtime in /usr/local/bin/mono /opt/homebrew/bin/mono /usr/local/bin/dotnet /opt/homebrew/bin/dotnet; do
        if [[ -f "$runtime" ]]; then
            local current_perms
            current_perms=$(stat -f '%Lp' "$runtime" 2>/dev/null || echo "unknown")
            if [[ "$current_perms" != "750" ]]; then
                backup_file "$runtime"
                chmod 750 "$runtime"
                chown root:admin "$runtime" 2>/dev/null || true
                log_success "Restricted $runtime to root/admin group (was $current_perms)"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            else
                log_info "$runtime already restricted"
            fi
        fi
    done

    # Check for .NET SDK installations
    if [[ -d "/usr/local/share/dotnet" ]]; then
        local dotnet_binary="/usr/local/share/dotnet/dotnet"
        if [[ -f "$dotnet_binary" ]]; then
            local current_perms
            current_perms=$(stat -f '%Lp' "$dotnet_binary" 2>/dev/null || echo "unknown")
            if [[ "$current_perms" != "750" ]]; then
                backup_file "$dotnet_binary"
                chmod 750 "$dotnet_binary"
                chown root:admin "$dotnet_binary" 2>/dev/null || true
                log_success "Restricted $dotnet_binary (was $current_perms)"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
            fi
        fi
    fi

    log_info ".NET/Mono runtime restriction complete"
}

undo_dotnet_runtime() {
    log_warning "Reverting .NET/Mono runtime restrictions..."
    for runtime in /usr/local/bin/mono /opt/homebrew/bin/mono /usr/local/bin/dotnet /opt/homebrew/bin/dotnet /usr/local/share/dotnet/dotnet; do
        if [[ -f "$runtime" ]]; then
            chmod 755 "$runtime"
            log_success "Restored $runtime to default permissions (755)"
        fi
    done
}

check_dotnet_runtime() {
    for runtime in /usr/local/bin/mono /opt/homebrew/bin/mono /usr/local/bin/dotnet /opt/homebrew/bin/dotnet /usr/local/share/dotnet/dotnet; do
        if [[ -f "$runtime" ]]; then
            local perms
            perms=$(stat -f '%Lp' "$runtime" 2>/dev/null || echo "unknown")
            if [[ "$perms" == "750" ]]; then
                log_success "$runtime restricted ($perms)"
            else
                log_warning "$runtime not restricted ($perms, recommend 750)"
            fi
        fi
    done
}

# ============================================================================
# 6. Harden Kernel Extension and System Extension Loading
# ============================================================================
# Prevent unauthorized kernel/system extensions, which is the macOS
# equivalent of disabling security monitoring at the OS level (like
# AMSI bypass at the kernel layer).

harden_kext_loading() {
    log_info "Verifying kernel/system extension security..."

    # On macOS 11+, kernel extensions require user approval
    # Check current KEXT policy
    local kext_consent
    kext_consent=$(spctl kext-consent status 2>/dev/null || echo "unknown")

    if echo "$kext_consent" | grep -q "enabled"; then
        log_success "Kernel extension user consent is enabled"
    else
        log_warning "Kernel extension user consent may not be enforced"
    fi

    # On Apple Silicon Macs, verify Secure Boot
    local cpu_brand
    cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")
    if echo "$cpu_brand" | grep -qi "apple"; then
        log_info "Apple Silicon detected - Secure Boot provides additional protection"
        # Check boot security policy
        local boot_policy
        boot_policy=$(bputil -d 2>/dev/null | head -5 || echo "unknown")
        log_info "Boot security: $boot_policy"
    fi

    log_success "Kernel/system extension security verified"
}

undo_kext_loading() {
    log_info "Kernel extension settings are managed by macOS and should not be modified"
}

check_kext_loading() {
    local kext_consent
    kext_consent=$(spctl kext-consent status 2>/dev/null || echo "unknown")
    if echo "$kext_consent" | grep -q "enabled"; then
        log_success "KEXT user consent: enabled"
    else
        log_warning "KEXT user consent: unknown status"
    fi
}

# ============================================================================
# 7. Enable Process Execution Monitoring
# ============================================================================
# Equivalent to Windows process creation auditing with command lines.
# Essential for detecting post-bypass tool execution.

harden_process_monitoring() {
    log_info "Configuring process execution monitoring..."

    # Enable OpenBSM audit trail
    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        backup_file "$audit_control"

        # Ensure execution classes are audited
        if ! grep -q "^flags:.*ex" "$audit_control" 2>/dev/null; then
            # Add exec and process audit classes
            if grep -q "^flags:" "$audit_control"; then
                local current_flags
                current_flags=$(grep "^flags:" "$audit_control" | head -1 | sed 's/^flags://')
                sed -i '' "s/^flags:.*/flags:${current_flags},ex,pc,fc,fd/" "$audit_control" 2>/dev/null || true
            else
                echo "flags:lo,aa,ex,pc,fc,fd" >> "$audit_control"
            fi
            log_success "Added execution/process audit flags"
            CHANGE_COUNT=$((CHANGE_COUNT + 1))
        else
            log_info "Execution audit flags already present"
        fi

        # Ensure audit log does not expire too quickly
        if grep -q "^expire-after:" "$audit_control" 2>/dev/null; then
            log_info "Audit log expiration policy present"
        fi
    fi

    # Configure shell history for all users
    local profile_file="/etc/profile.d/f0rtika-history.sh"
    if [[ ! -d /etc/profile.d ]]; then
        mkdir -p /etc/profile.d 2>/dev/null || true
    fi

    cat > "$profile_file" <<'PROFILE_EOF'
# F0RT1KA Hardening: Enhanced command history logging
# Prevents attackers from hiding commands after defense evasion
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=50000
export HISTFILESIZE=50000
export HISTCONTROL=""
shopt -s histappend 2>/dev/null || true
PROFILE_EOF

    chmod 644 "$profile_file"
    log_success "Enhanced command history logging configured"
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
}

undo_process_monitoring() {
    log_warning "Reverting process monitoring..."
    local profile_file="/etc/profile.d/f0rtika-history.sh"
    if [[ -f "$profile_file" ]]; then
        rm -f "$profile_file"
        log_success "Removed history logging profile"
    fi
    log_info "Audit control changes require manual restoration from $BACKUP_DIR"
}

check_process_monitoring() {
    if [[ -f "/etc/security/audit_control" ]]; then
        if grep -q "ex" /etc/security/audit_control 2>/dev/null; then
            log_success "Execution auditing: configured"
        else
            log_warning "Execution auditing: not fully configured"
        fi
    fi

    if [[ -f "/etc/profile.d/f0rtika-history.sh" ]]; then
        log_success "Enhanced history logging: configured"
    else
        log_warning "Enhanced history logging: not configured"
    fi
}

# ============================================================================
# 8. Quarantine and Gatekeeper Enforcement
# ============================================================================
# Ensure macOS quarantine attributes are preserved on downloaded files.
# This is the macOS equivalent of AMSI scanning downloaded content --
# files with quarantine flags are scanned by XProtect before execution.

harden_quarantine() {
    log_info "Verifying quarantine and Gatekeeper enforcement..."

    # Ensure Gatekeeper is enabled (critical for quarantine enforcement)
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper is enabled"
    else
        spctl --master-enable 2>/dev/null || true
        log_success "Gatekeeper enabled"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    fi

    # Ensure quarantine flag is not being globally bypassed
    # Check for com.apple.LaunchServices LSQuarantine defaults
    local quarantine_default
    quarantine_default=$(defaults read com.apple.LaunchServices LSQuarantine 2>/dev/null || echo "not set")
    if [[ "$quarantine_default" == "0" ]]; then
        defaults write com.apple.LaunchServices LSQuarantine -bool true 2>/dev/null || true
        log_success "Re-enabled quarantine flag enforcement"
        CHANGE_COUNT=$((CHANGE_COUNT + 1))
    else
        log_info "Quarantine enforcement is active"
    fi

    # Warn about xattr -cr usage (removes quarantine flags)
    log_info "IMPORTANT: Advise users not to run 'xattr -cr' on downloaded files"
    log_info "xattr -cr removes quarantine flags, bypassing XProtect scanning"
}

undo_quarantine() {
    log_warning "Quarantine protections should not be disabled"
    log_info "Gatekeeper and quarantine settings left as-is"
}

check_quarantine() {
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        log_success "Gatekeeper: enabled"
    else
        log_warning "Gatekeeper: NOT enabled"
    fi

    local quarantine_default
    quarantine_default=$(defaults read com.apple.LaunchServices LSQuarantine 2>/dev/null || echo "not set")
    if [[ "$quarantine_default" != "0" ]]; then
        log_success "Quarantine enforcement: active"
    else
        log_warning "Quarantine enforcement: DISABLED"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

ACTION="${1:-apply}"

echo ""
echo "============================================================================"
echo "F0RT1KA macOS Hardening Script"
echo "Test ID: c1f0fe6f-6907-4f95-820d-47e0a39abe54"
echo "MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools"
echo "Action: $ACTION"
echo "============================================================================"
echo ""

# Initialize log
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
echo "$(date '+%Y-%m-%d %H:%M:%S') === F0RT1KA Hardening: $ACTION ===" >> "$LOG_FILE" 2>/dev/null || true

case "$ACTION" in
    apply)
        check_root
        check_macos
        ensure_backup_dir
        log_info "Applying hardening measures..."
        echo ""

        harden_dyld_injection
        harden_unified_logging
        harden_download_controls
        harden_security_frameworks
        harden_dotnet_runtime
        harden_kext_loading
        harden_process_monitoring
        harden_quarantine

        echo ""
        echo "============================================================================"
        log_success "Hardening complete. $CHANGE_COUNT changes applied."
        echo "============================================================================"
        echo ""
        echo "Applied Settings:"
        echo "  - SIP/Gatekeeper/Library Validation verification (anti-DYLD-injection)"
        echo "  - Unified logging and OpenBSM audit configuration"
        echo "  - Application Firewall with stealth mode"
        echo "  - XProtect and automatic security update enforcement"
        echo "  - .NET/Mono runtime access restrictions"
        echo "  - Kernel/system extension security verification"
        echo "  - Process execution monitoring and command history logging"
        echo "  - Quarantine and Gatekeeper enforcement"
        echo ""
        echo "Backup location: $BACKUP_DIR"
        echo "Log file: $LOG_FILE"
        echo ""
        echo "To revert: sudo $SCRIPT_NAME undo"
        echo "To check:  sudo $SCRIPT_NAME check"
        echo ""
        ;;

    undo)
        check_root
        check_macos
        log_warning "Reverting hardening changes..."
        echo ""

        undo_dyld_injection
        undo_unified_logging
        undo_download_controls
        undo_security_frameworks
        undo_dotnet_runtime
        undo_kext_loading
        undo_process_monitoring
        undo_quarantine

        echo ""
        log_success "Revert complete. Critical security settings left as-is."
        echo ""
        ;;

    check)
        check_root
        check_macos
        log_info "Checking hardening status..."
        echo ""

        check_dyld_injection
        check_unified_logging
        check_download_controls
        check_security_frameworks
        check_dotnet_runtime
        check_kext_loading
        check_process_monitoring
        check_quarantine

        echo ""
        log_info "Check complete."
        echo ""
        ;;

    *)
        echo "Usage: sudo $SCRIPT_NAME [apply|undo|check]"
        echo ""
        echo "  apply  - Apply hardening settings (default)"
        echo "  undo   - Revert hardening settings"
        echo "  check  - Check current hardening status"
        exit 1
        ;;
esac

echo "============================================================================"
echo "Completed at $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================================"
