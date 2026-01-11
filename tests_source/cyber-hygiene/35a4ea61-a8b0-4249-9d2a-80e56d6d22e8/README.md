# LSASS Protection Validator

**Test Score**: **8.0/10**

## Overview

This cyber hygiene test validates that LSASS (Local Security Authority Subsystem Service) protection mechanisms are properly configured to prevent credential theft attacks. The test checks critical security configurations that defend against tools like Mimikatz and similar credential dumping techniques.

## MITRE ATT&CK Mapping

- **Tactic**: Credential Access
- **Techniques**:
  - T1003.001 - OS Credential Dumping: LSASS Memory
  - T1003.002 - OS Credential Dumping: Security Account Manager
  - T1550.002 - Use Alternate Authentication Material: Pass the Hash

## Configuration Checks

| Check | Registry/Method | Compliant Value |
|-------|-----------------|-----------------|
| RunAsPPL | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | 1 or 2 |
| VBS Enabled | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity` | 1 |
| Credential Guard | WMI: `Win32_DeviceGuard.SecurityServicesRunning` contains 2 | True |

## Test Characteristics

- **Type**: Configuration Validation (READ-ONLY)
- **Category**: Cyber Hygiene
- **Priority**: CRITICAL
- **Admin Required**: Yes
- **Destructive**: No
- **Network Required**: No

## Expected Outcomes

- **Code 126 (COMPLIANT)**: All 3 protection checks pass
- **Code 101 (NON-COMPLIANT)**: One or more checks fail
- **Code 999 (ERROR)**: Test error (e.g., insufficient privileges)

## CIS Benchmark Reference

- **CIS Controls v8: 4.1** - Establish and Maintain a Secure Configuration Process
- **CIS Controls v8: 10.5** - Enable Anti-Exploitation Features

## Build Instructions

```bash
# Build the test
./utils/gobuild build tests_source/cyber-hygiene/35a4ea61-a8b0-4249-9d2a-80e56d6d22e8/

# Sign the binary
./utils/codesign sign build/35a4ea61-a8b0-4249-9d2a-80e56d6d22e8/35a4ea61-a8b0-4249-9d2a-80e56d6d22e8.exe
```

## Remediation Guidance

If the test returns NON-COMPLIANT (exit code 101), apply the following remediations:

### Enable RunAsPPL

```powershell
# Set RunAsPPL registry value (requires reboot)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
```

### Enable Virtualization Based Security

```powershell
# Enable VBS via registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
```

### Enable Credential Guard

Use one of the following methods:

1. **Windows Security**: Settings > Device Security > Core isolation > Memory integrity
2. **Group Policy**: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security
3. **PowerShell**: Use the Device Guard Readiness Tool from Microsoft

**Hardware Requirements for Credential Guard**:
- TPM 2.0
- UEFI firmware
- Secure Boot enabled
- Virtualization extensions (Intel VT-x or AMD-V)

## Output Files

After execution, the test produces:
- `c:\F0\test_execution_log.json` - Structured JSON log (Schema v2.0)
- `c:\F0\test_execution_log.txt` - Human-readable text log
- `c:\F0\credentialguard_output.txt` - Credential Guard WMI query output
