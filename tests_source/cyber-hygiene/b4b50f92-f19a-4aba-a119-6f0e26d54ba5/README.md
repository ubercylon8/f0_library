# SMB Protocol Hardening Validator

**Test Score**: **8.0/10**

## Overview

This cyber hygiene test validates that SMB (Server Message Block) protocol is properly hardened with SMBv1 disabled and signing/encryption enabled. SMBv1 vulnerabilities enabled devastating attacks like WannaCry and NotPetya that caused billions of dollars in damages worldwide.

## MITRE ATT&CK Mapping

- **Tactics**: Lateral Movement, Credential Access
- **Techniques**:
  - T1021.002 - Remote Services: SMB/Windows Admin Shares
  - T1570 - Lateral Tool Transfer
  - T1210 - Exploitation of Remote Services
  - T1557 - Adversary-in-the-Middle

## Configuration Checks

| Check | Registry/Method | Compliant Value |
|-------|-----------------|-----------------|
| SMBv1 Server Disabled | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1` | 0 |
| SMBv1 Client Disabled | `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start` | 4 (Disabled) |
| Server Signing Required | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature` | 1 |
| Client Signing Required | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature` | 1 |
| SMB Encryption Enabled | PowerShell: `(Get-SmbServerConfiguration).EncryptData` | True |

## Test Characteristics

- **Type**: Configuration Validation (READ-ONLY)
- **Category**: Cyber Hygiene
- **Priority**: CRITICAL
- **Admin Required**: Yes
- **Destructive**: No
- **Network Required**: No

## Expected Outcomes

- **Code 126 (COMPLIANT)**: All 5 protection checks pass
- **Code 101 (NON-COMPLIANT)**: One or more checks fail
- **Code 999 (ERROR)**: Test error (e.g., insufficient privileges)

## CIS Benchmark Reference

- **CIS Controls v8: 4.8** - Uninstall or Disable Unnecessary Services
- **CIS Controls v8: 3.10** - Encrypt Sensitive Data in Transit

## Build Instructions

```bash
# Build the test
./utils/gobuild build tests_source/cyber-hygiene/b4b50f92-f19a-4aba-a119-6f0e26d54ba5/

# Sign the binary
./utils/codesign sign build/b4b50f92-f19a-4aba-a119-6f0e26d54ba5/b4b50f92-f19a-4aba-a119-6f0e26d54ba5.exe
```

## Remediation Guidance

If the test returns NON-COMPLIANT (exit code 101), apply the following remediations:

### Disable SMBv1 Server

```powershell
# Method 1: Registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord

# Method 2: Windows Feature (recommended)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Method 3: PowerShell SMB cmdlet
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
```

### Disable SMBv1 Client

```powershell
# Disable mrxsmb10 driver
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord

# OR via sc command
sc.exe config mrxsmb10 start= disabled
```

### Enable SMB Signing

```powershell
# Server signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord

# Client signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
```

### Enable SMB Encryption

```powershell
# Enable SMB encryption (requires SMB 3.0+)
Set-SmbServerConfiguration -EncryptData $true -Force
```

**Important Notes:**
- SMB signing adds approximately 15% performance overhead but significantly improves security
- SMB encryption requires SMB 3.0 or later on both endpoints
- A system reboot may be required after making these changes

## Output Files

After execution, the test produces:
- `c:\F0\test_execution_log.json` - Structured JSON log (Schema v2.0)
- `c:\F0\test_execution_log.txt` - Human-readable text log
- `c:\F0\smbv1_server_ps.txt` - SMBv1 PowerShell query output
- `c:\F0\smb_encryption.txt` - SMB encryption query output
