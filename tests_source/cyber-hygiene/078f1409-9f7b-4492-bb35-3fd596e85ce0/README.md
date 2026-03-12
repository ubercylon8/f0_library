# CIS Windows Endpoint Level 1 Hardening Bundle

**Test UUID**: `078f1409-9f7b-4492-bb35-3fd596e85ce0`

**Test Score**: **9.4/10**

## Overview

This bundled security test validates 52 CIS Benchmark Level 1 security controls across 7 security domains for Windows endpoints. It uses multi-binary architecture with quarantine-resilient validator binaries, ensuring that if AV/EDR quarantines one validator, the remaining validators still execute and report results.

## Included Validators

| # | Validator | Checks | Key Configurations |
|---|-----------|--------|-------------------|
| 1 | Credential & Password Policy | 10 | Password history, age, length, complexity, lockout |
| 2 | Account Management | 8 | Microsoft accounts, Guest, LAPS, account renaming |
| 3 | Network Authentication Hardening | 8 | NULL sessions, PKU2U, Kerberos, NTLM, SMBv1, SMB signing |
| 4 | Credential Protection | 3 | LSASS RunAsPPL, WDigest, Credential Guard |
| 5 | Windows Firewall | 4 | Domain/Private/Public profiles, inbound blocking |
| 6 | Audit & Logging Policy | 11 | Audit subcategories, PowerShell logging, CLM |
| 7 | Endpoint Protection & Access | 8 | ASR rules, RDP hardening, BitLocker |

**Total: 52 controls across 7 validators**

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 126 | COMPLIANT | All 7 validators passed - endpoint meets CIS Level 1 |
| 101 | NON-COMPLIANT | One or more validators failed - compliance gaps detected |
| 999 | ERROR | Test error (administrator privileges required) |

## MITRE ATT&CK Coverage

- **T1110** - Brute Force (password policy, lockout)
- **T1078.001** - Valid Accounts: Default Accounts (account management)
- **T1557.001** - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning (network auth)
- **T1003.001** - OS Credential Dumping: LSASS Memory (credential protection)
- **T1562.001** - Impair Defenses: Disable or Modify Tools (ASR rules)
- **T1562.004** - Impair Defenses: Disable or Modify System Firewall
- **T1059.001** - Command and Scripting Interpreter: PowerShell (audit logging)
- **T1021.001** - Remote Services: Remote Desktop Protocol (RDP hardening)

## Requirements

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- No specific AV vendor dependency (checks Windows built-in security features)

## Build

```bash
cd tests_source/cyber-hygiene/078f1409-9f7b-4492-bb35-3fd596e85ce0/
./build_all.sh
```

## Usage

```powershell
# Run as Administrator
.\078f1409-9f7b-4492-bb35-3fd596e85ce0.exe
```

## Output

The test produces:
1. Console output with formatted results for each validator and control
2. JSON log file at `C:\F0\078f1409-9f7b-4492-bb35-3fd596e85ce0_execution_log.json`
3. Bundle results at `C:\F0\bundle_results.json` (52 individual control results for Elasticsearch)

## References

- [CIS Microsoft Windows 11 Enterprise Benchmark v3.0](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [CIS Microsoft Windows Server 2022 Benchmark v3.0](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

## Compliance Frameworks

This test supports validation for:
- **CIS Benchmarks** - Level 1 Profile (Member Server / Workstation)
- **NIST 800-53** - Security and Privacy Controls
- **PCI-DSS** - Endpoint hardening requirements
- **DORA** - Digital Operational Resilience Act
