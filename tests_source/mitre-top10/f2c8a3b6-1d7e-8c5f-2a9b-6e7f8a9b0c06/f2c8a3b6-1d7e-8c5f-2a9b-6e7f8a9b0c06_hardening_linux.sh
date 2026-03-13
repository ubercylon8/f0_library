#!/usr/bin/env bash
# ============================================================================
# DEFENSE GUIDANCE: Linux Hardening Script
# ============================================================================
# Test ID: f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06
# Test Name: LOLBIN Download Detection
# MITRE ATT&CK: T1105 - Ingress Tool Transfer, T1059.001 - PowerShell
# Created: 2026-03-13
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
#
# Linux equivalent of LOLBIN download hardening. Targets native Linux
# utilities commonly abused for ingress tool transfer:
# - curl, wget (direct downloads)
# - python, perl, ruby (scripted downloads)
# - nc/ncat/socat (raw socket transfers)
# - scp, sftp (file transfer protocols)
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
# 1. Process Execution Auditing (T1105)
# ============================================================================

setup_process_auditing() {
    info "=== Process Execution Auditing (T1105) ==="

    if $UNDO; then
        if command -v auditctl &>/dev/null; then
            run_cmd auditctl -d -a always,exit -F arch=b64 -S execve -k lolbin_exec 2>/dev/null || true
            warn "Removed LOLBIN execution audit rules"
        fi
        return
    fi

    if ! command -v auditctl &>/dev/null; then
        warn "auditd not installed. Install with: apt install auditd (Debian) or yum install audit (RHEL)"
        return
    fi

    # Monitor execution of common download utilities
    local download_tools=(
        "/usr/bin/curl"
        "/usr/bin/wget"
        "/usr/bin/nc"
        "/usr/bin/ncat"
        "/usr/bin/socat"
        "/usr/bin/scp"
        "/usr/bin/sftp"
        "/usr/bin/fetch"
    )

    for tool in "${download_tools[@]}"; do
        if [[ -f "$tool" ]]; then
            run_cmd auditctl -w "$tool" -p x -k lolbin_download
            success "Added audit watch: $tool"
        fi
    done

    # Monitor python/perl/ruby execution (often used as download helpers)
    for interp in /usr/bin/python3 /usr/bin/python /usr/bin/perl /usr/bin/ruby; do
        if [[ -f "$interp" ]]; then
            run_cmd auditctl -w "$interp" -p x -k script_download
            success "Added audit watch: $interp"
        fi
    done

    # Monitor general execve for command line capture
    run_cmd auditctl -a always,exit -F arch=b64 -S execve -k lolbin_exec
    success "Added execve audit rule for process creation monitoring"

    # Make rules persistent
    local audit_rules_file="/etc/audit/rules.d/f0rtika-lolbin.rules"
    if ! $DRY_RUN; then
        cat > "$audit_rules_file" << 'EOF'
# F0RT1KA LOLBIN Download Detection - Audit Rules
# Monitor download tool execution
-w /usr/bin/curl -p x -k lolbin_download
-w /usr/bin/wget -p x -k lolbin_download
-w /usr/bin/nc -p x -k lolbin_download
-w /usr/bin/ncat -p x -k lolbin_download
-w /usr/bin/socat -p x -k lolbin_download
-w /usr/bin/scp -p x -k lolbin_download
-w /usr/bin/sftp -p x -k lolbin_download
# Monitor scripting interpreters
-w /usr/bin/python3 -p x -k script_download
-w /usr/bin/python -p x -k script_download
-w /usr/bin/perl -p x -k script_download
-w /usr/bin/ruby -p x -k script_download
EOF
        success "Persistent audit rules written to $audit_rules_file"
    fi
}

# ============================================================================
# 2. File Integrity Monitoring for Download Destinations
# ============================================================================

setup_file_monitoring() {
    info "=== File Integrity Monitoring for Common Download Paths ==="

    if $UNDO; then
        if command -v auditctl &>/dev/null; then
            run_cmd auditctl -d -w /tmp -p wa -k file_download 2>/dev/null || true
            run_cmd auditctl -d -w /var/tmp -p wa -k file_download 2>/dev/null || true
            run_cmd auditctl -d -w /dev/shm -p wa -k file_download 2>/dev/null || true
            warn "Removed file monitoring audit rules"
        fi
        return
    fi

    if command -v auditctl &>/dev/null; then
        # Monitor common download/staging directories
        local watch_dirs=("/tmp" "/var/tmp" "/dev/shm")
        for dir in "${watch_dirs[@]}"; do
            if [[ -d "$dir" ]]; then
                run_cmd auditctl -w "$dir" -p wa -k file_download
                success "Added file monitoring for: $dir"
            fi
        done
    else
        warn "auditd not available for file monitoring"
    fi

    # Check /tmp noexec mount option
    if grep -q "/tmp" /etc/fstab 2>/dev/null; then
        if grep "/tmp" /etc/fstab | grep -q "noexec"; then
            info "/tmp is mounted with noexec (good)"
        else
            warn "/tmp is NOT mounted with noexec - consider adding noexec mount option"
        fi
    else
        warn "/tmp not configured in /etc/fstab - consider adding separate /tmp with noexec"
    fi
}

# ============================================================================
# 3. Outbound Connection Restrictions
# ============================================================================

restrict_outbound_connections() {
    info "=== Outbound Connection Restrictions ==="

    if $UNDO; then
        if command -v iptables &>/dev/null; then
            # Remove owner-based restrictions
            run_cmd iptables -D OUTPUT -m owner --uid-owner root -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
            run_cmd iptables -D OUTPUT -m owner --uid-owner root -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
            warn "Removed outbound connection restrictions"
        fi
        return
    fi

    info "NOTE: Outbound restrictions require careful tuning per environment"
    info "Consider implementing the following with iptables or nftables:"
    echo ""
    info "  # Allow only specific users/groups to make outbound HTTP connections"
    info "  iptables -A OUTPUT -m owner --uid-owner www-data -p tcp --dport 80 -j ACCEPT"
    info "  iptables -A OUTPUT -m owner --uid-owner www-data -p tcp --dport 443 -j ACCEPT"
    info "  iptables -A OUTPUT -m owner --uid-owner root -p tcp --dport 80 -j ACCEPT"
    info "  iptables -A OUTPUT -m owner --uid-owner root -p tcp --dport 443 -j ACCEPT"
    echo ""
    info "  # Alternatively, use proxy enforcement:"
    info "  export http_proxy=http://proxy:3128"
    info "  export https_proxy=http://proxy:3128"
    echo ""

    # Block nc/ncat/socat from making outbound connections (if AppArmor available)
    if command -v aa-status &>/dev/null; then
        info "AppArmor detected - consider creating profiles for nc, ncat, socat"
        info "  sudo aa-genprof /usr/bin/nc"
    elif command -v sestatus &>/dev/null; then
        info "SELinux detected - consider creating policies for download utilities"
    fi
}

# ============================================================================
# 4. PowerShell Core Hardening (if installed)
# ============================================================================

harden_pwsh() {
    info "=== PowerShell Core Hardening (T1059.001) ==="

    if $UNDO; then
        local pwsh_profile="/opt/microsoft/powershell/7/profile.ps1"
        if [[ -f "$pwsh_profile.f0rtika-backup" ]]; then
            run_cmd mv "$pwsh_profile.f0rtika-backup" "$pwsh_profile"
            warn "Restored original PowerShell profile"
        fi
        return
    fi

    if ! command -v pwsh &>/dev/null; then
        info "PowerShell Core (pwsh) not installed - skipping"
        return
    fi

    info "PowerShell Core found at: $(which pwsh)"

    # Enable PowerShell logging on Linux
    local pwsh_config_dir="/opt/microsoft/powershell/7"
    if [[ -d "$pwsh_config_dir" ]]; then
        local logging_config="$pwsh_config_dir/powershell.config.json"
        if ! $DRY_RUN; then
            cat > "$logging_config" << 'EOF'
{
    "LogLevel": "Verbose",
    "LogChannels": "Operational",
    "LogKeywords": "Runspace,Pipeline,Protocol,Transport,Host,Cmdlets,Serialization,Session,ManagedPlugin",
    "PowerShellPolicies": {
        "ScriptBlockLogging": {
            "EnableScriptBlockLogging": true,
            "EnableScriptBlockInvocationLogging": true
        },
        "ModuleLogging": {
            "EnableModuleLogging": true,
            "ModuleNames": ["*"]
        },
        "ProtectedEventLogging": {
            "EnableProtectedEventLogging": false
        }
    }
}
EOF
            success "PowerShell logging configuration created: $logging_config"
        fi
    fi
}

# ============================================================
# 5. DNS and Network Logging
# ============================================================

setup_network_logging() {
    info "=== DNS and Network Logging ==="

    if $UNDO; then
        info "Network logging is non-destructive - no revert needed"
        return
    fi

    # Check if DNS query logging is available
    if command -v tcpdump &>/dev/null; then
        info "tcpdump available for network capture"
        info "Monitor LOLBIN network activity:"
        info "  tcpdump -i any -n 'port 80 or port 443' -l"
    fi

    # Check for conntrack
    if command -v conntrack &>/dev/null; then
        info "conntrack available for connection tracking"
    fi

    # Enable netfilter logging for outbound connections
    if command -v iptables &>/dev/null; then
        info "Consider adding iptables LOG rules for download monitoring:"
        info "  iptables -A OUTPUT -p tcp --dport 80 -j LOG --log-prefix 'HTTP_OUT: '"
        info "  iptables -A OUTPUT -p tcp --dport 443 -j LOG --log-prefix 'HTTPS_OUT: '"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

echo ""
echo "============================================================"
echo "  LOLBIN Download Detection - Linux Hardening"
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

setup_process_auditing
echo ""
setup_file_monitoring
echo ""
restrict_outbound_connections
echo ""
harden_pwsh
echo ""
setup_network_logging
echo ""

echo "============================================================"
if $UNDO; then
    warn "Hardening reverted."
else
    success "Hardening complete."
fi
echo "============================================================"
echo ""
