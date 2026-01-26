# Cyber-Hygiene Bundle (Windows Defender Edition)

**Test UUID**: `a3c923ae-1a46-4b1f-b696-be6c2731a628`

## Overview

This bundled security test consolidates 10 Windows cyber-hygiene validators into a single binary. It validates that a Windows endpoint with Microsoft Defender has all critical security configurations properly enabled according to CIS Benchmark standards.

**Test Score**: **9.0/10**

## Included Validators

| # | Validator | Checks | Key Configurations |
|---|-----------|--------|-------------------|
| 1 | Microsoft Defender Configuration | 6 | Real-time, Behavior, Tamper, Cloud, Sample, PUA |
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
- Microsoft Defender as the primary AV solution

## Build

```bash
cd tests_source/cyber-hygiene/a3c923ae-1a46-4b1f-b696-be6c2731a628/
go mod tidy
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ../../../build/a3c923ae-1a46-4b1f-b696-be6c2731a628/a3c923ae-1a46-4b1f-b696-be6c2731a628.exe *.go
```

## Usage

```powershell
# Run as Administrator
.\a3c923ae-1a46-4b1f-b696-be6c2731a628.exe
```

## Output

The test produces:
1. Console output with formatted results for each validator
2. JSON log file at `C:\F0\a3c923ae-1a46-4b1f-b696-be6c2731a628_execution_log.json`

## References

- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [MITRE ATT&CK](https://attack.mitre.org/)
