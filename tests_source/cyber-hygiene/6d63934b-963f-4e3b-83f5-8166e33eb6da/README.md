# CIS macOS Endpoint Level 1 Hardening Bundle

**Test Score**: **9.1/10**

## Overview

Validates 22 CIS macOS Benchmark Level 1 security controls across 5 independent validator binaries. Uses multi-binary architecture for quarantine resilience -- if an EDR/AV quarantines one validator, the remaining validators still execute and report results. Each control maps to specific CIS Benchmark recommendations and MITRE ATT&CK techniques.

## Test Information

| Field | Value |
|-------|-------|
| **UUID** | `6d63934b-963f-4e3b-83f5-8166e33eb6da` |
| **Category** | Cyber-Hygiene |
| **Subcategory** | CIS macOS Level 1 |
| **Platform** | macOS 12+ (Monterey or later) |
| **Architecture** | Multi-binary (5 embedded signed validators) |
| **Controls** | 22 |
| **Severity** | High |

## MITRE ATT&CK Mapping

| Technique | Name | Validator |
|-----------|------|-----------|
| T1562.001 | Impair Defenses: Disable or Modify Tools | sysprefs, auditlog, eprotect |
| T1553.001 | Subvert Trust Controls: Gatekeeper Bypass | eprotect |
| T1071.001 | Application Layer Protocol: Web Protocols | network |
| T1021.004 | Remote Services: SSH | accessctl |
| T1548.004 | Abuse Elevation Control Mechanism | accessctl |
| T1070.002 | Indicator Removal: Clear System Logs | auditlog |
| T1059.004 | Command Interpreter: Unix Shell | (overall) |

## Validators

| # | Validator | Controls | Description |
|---|-----------|----------|-------------|
| 1 | **sysprefs** | CH-CM1-001 to CH-CM1-008 (8) | Auto updates, Bluetooth, screensaver, FileVault, firewall, stealth mode |
| 2 | **auditlog** | CH-CM1-009 to CH-CM1-011 (3) | BSM audit daemon, install log retention, firewall logging |
| 3 | **network** | CH-CM1-012 to CH-CM1-014 (3) | HTTP server, NFS server, AirDrop |
| 4 | **accessctl** | CH-CM1-015 to CH-CM1-019 (5) | Secure keyboard entry, password on wake, SSH, guest account, Secure Boot |
| 5 | **eprotect** | CH-CM1-020 to CH-CM1-022 (3) | SIP, Gatekeeper, XProtect |

## Requirements

- **macOS 12+** (Monterey or later)
- **Root privileges** (`sudo`)
- Some checks use `systemsetup`, `fdesetup`, `csrutil`, `spctl`, and `bputil` which require elevated access

## Build Instructions

```bash
# Build on macOS (Apple Silicon)
cd tests_source/cyber-hygiene/6d63934b-963f-4e3b-83f5-8166e33eb6da/
./build_all.sh

# Build with ES export
./build_all.sh --es prod

# Cross-compile from Linux (for deployment to macOS)
GOOS=darwin GOARCH=arm64 ./build_all.sh
```

## Deployment

```bash
# Copy to macOS endpoint
scp build/6d63934b-963f-4e3b-83f5-8166e33eb6da/6d63934b-963f-4e3b-83f5-8166e33eb6da mac:/opt/f0/

# Remove Gatekeeper quarantine and execute as root
ssh mac 'xattr -cr /opt/f0/6d63934b-963f-4e3b-83f5-8166e33eb6da && sudo /opt/f0/6d63934b-963f-4e3b-83f5-8166e33eb6da'
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 126 | COMPLIANT - All 22 controls pass |
| 101 | NON-COMPLIANT - One or more controls failed or validators were skipped |
| 999 | ERROR - Prerequisites not met (e.g., not running as root) |

## Output Files

| File | Location | Description |
|------|----------|-------------|
| `test_execution_log.json` | `/tmp/F0/` | Schema v2.0 structured test results |
| `bundle_results.json` | `/tmp/F0/` | Per-control granularity for Elasticsearch fan-out |

## Controls Reference

### System Preferences & Security (CH-CM1-001 to CH-CM1-008)
- CH-CM1-001: Auto Update Check Enabled
- CH-CM1-002: Auto Install macOS Updates
- CH-CM1-003: Auto Install Security Updates (Critical + ConfigData)
- CH-CM1-004: Bluetooth Discoverability Disabled
- CH-CM1-005: Screen Saver Idle Time <= 20 Minutes
- CH-CM1-006: FileVault Full Disk Encryption
- CH-CM1-007: Application Firewall Enabled
- CH-CM1-008: Firewall Stealth Mode Enabled

### Audit & Logging (CH-CM1-009 to CH-CM1-011)
- CH-CM1-009: BSM Audit (auditd) Running
- CH-CM1-010: Install Log File Retained
- CH-CM1-011: Firewall Logging Enabled

### Network Security (CH-CM1-012 to CH-CM1-014)
- CH-CM1-012: HTTP Server (httpd) Disabled
- CH-CM1-013: NFS Server Disabled
- CH-CM1-014: AirDrop Disabled

### Access Control (CH-CM1-015 to CH-CM1-019)
- CH-CM1-015: Secure Keyboard Entry in Terminal
- CH-CM1-016: Password Required on Wake
- CH-CM1-017: SSH Remote Login Disabled
- CH-CM1-018: Guest Account Disabled
- CH-CM1-019: Startup Security / Secure Boot

### Endpoint Protection (CH-CM1-020 to CH-CM1-022)
- CH-CM1-020: System Integrity Protection (SIP) Enabled
- CH-CM1-021: Gatekeeper Enabled
- CH-CM1-022: XProtect Definitions Updated
