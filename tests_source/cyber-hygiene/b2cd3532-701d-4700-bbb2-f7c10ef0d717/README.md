# Cyber-Hygiene Bundle (CrowdStrike Falcon Edition)

**Test UUID**: `b2cd3532-701d-4700-bbb2-f7c10ef0d717`

## Overview

This bundled security test consolidates 10 Windows cyber-hygiene validators into a single binary. It validates that a Windows endpoint with CrowdStrike Falcon as the primary EDR solution has all critical security configurations properly enabled according to CIS Benchmark standards.

**Test Score**: **9.0/10**

## Included Validators

| # | Validator | Checks | Key Configurations |
|---|-----------|--------|-------------------|
| 1 | CrowdStrike Falcon Configuration | 6 | Service Running, Sensor Operational, Prevention Mode, Sensor Version, Cloud Connectivity, Tamper Protection |
| 2 | LSASS Protection | 3 | RunAsPPL, Credential Guard, VBS |
| 3 | Attack Surface Reduction Rules | 8 | Critical ASR rules in Block mode |
| 4 | SMB Hardening | 5 | SMBv1 disabled, signing, encryption |
| 5 | PowerShell Security | 4 | Script Block, Module Logging, Transcription |
| 6 | Network Protocol Hardening | 4 | LLMNR, NetBIOS, WPAD, IPv6 tunnels |
| 7 | Windows Audit Logging | 9 | Critical audit categories enabled |
| 8 | Account Lockout Policy | 5 | CIS-compliant lockout thresholds |
| 9 | LAPS | 2 | Windows LAPS or Legacy LAPS configured |
| 10 | Print Spooler Hardening | 2 | PrintNightmare mitigations |

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 126 | COMPLIANT | All 10 validators passed - endpoint is properly hardened |
| 101 | NON-COMPLIANT | One or more validators failed - security gaps detected |
| 999 | ERROR | Test error (administrator privileges required) |

## MITRE ATT&CK Coverage

- **T1562.001** - Impair Defenses: Disable or Modify Tools
- **T1562.004** - Impair Defenses: Disable or Modify System Firewall
- **T1070** - Indicator Removal
- **T1003.001** - OS Credential Dumping: LSASS Memory
- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1021.002** - Remote Services: SMB/Windows Admin Shares
- **T1110** - Brute Force
- **T1547.001** - Boot or Logon Autostart Execution
- **T1548.002** - Abuse Elevation Control Mechanism
- **T1569.002** - System Services: Service Execution

## Requirements

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- CrowdStrike Falcon sensor installed as the primary EDR solution

## Build

```bash
# Using build script (recommended)
cd tests_source/cyber-hygiene/b2cd3532-701d-4700-bbb2-f7c10ef0d717/
./build_all.sh

# With Elasticsearch export
./build_all.sh --es prod
```

## Usage

```powershell
# Run as Administrator
.\b2cd3532-701d-4700-bbb2-f7c10ef0d717.exe
```

## Output

The test produces:
1. Console output with formatted results for each validator
2. JSON log file at `C:\F0\b2cd3532-701d-4700-bbb2-f7c10ef0d717_execution_log.json`
3. Bundle results at `C:\F0\bundle_results.json` (per-control granularity for Elasticsearch)

## CrowdStrike Falcon Checks

The CrowdStrike validator performs 6 checks specific to Falcon sensor configuration:

| Control ID | Check | Expected | Method |
|-----------|-------|----------|--------|
| CH-CRW-001 | Falcon Service Running | CSFalconService running, auto-start | `sc query` + registry |
| CH-CRW-002 | Sensor Operational Status | AG + Agent ID present | Registry query |
| CH-CRW-003 | Prevention Mode | Prevention policy enabled | Registry query |
| CH-CRW-004 | Sensor Version | Valid version detected | File version query |
| CH-CRW-005 | Cloud Connectivity | Cloud connection established | Registry (provisioning state) |
| CH-CRW-006 | Tamper Protection | Tamper protection enabled | Registry query |

## Differences from Baseline Bundle

This bundle is identical to the baseline bundle (`a3c923ae`) except:
- Validator #1 is **CrowdStrike Falcon Configuration** instead of **Microsoft Defender Configuration**
- Control IDs use `CH-CRW-*` prefix instead of `CH-DEF-*`
- Designed for environments using CrowdStrike Falcon as the primary EDR solution
- The remaining 9 validators (LSASS, ASR, SMB, PowerShell, Network, Audit, Lockout, LAPS, Print Spooler) are identical

## References

- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [CrowdStrike Falcon Documentation](https://falcon.crowdstrike.com/documentation/)
- [MITRE ATT&CK](https://attack.mitre.org/)
