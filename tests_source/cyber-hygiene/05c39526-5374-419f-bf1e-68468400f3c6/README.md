# Local Administrator Password Solution (LAPS) Validator

**Test Score**: **7.5/10**

## Overview

This cyber hygiene test validates that Local Administrator Password Solution (LAPS) is properly configured to prevent shared local admin password attacks. NSA/CISA's Top 10 Misconfigurations highlights "poor credential hygiene" as critical. Shared local admin passwords across systems enable lateral movement attacks where compromising one system grants access to all systems with the same password.

## MITRE ATT&CK Mapping

- **Tactics**: Credential Access, Lateral Movement
- **Techniques**:
  - T1078.003 - Valid Accounts: Local Accounts
  - T1021.002 - Remote Services: SMB/Windows Admin Shares
  - T1550.002 - Use Alternate Authentication Material: Pass the Hash

## Configuration Checks

The test validates if **at least one** LAPS method is configured:

### Windows LAPS (Built-in, Windows 11/Server 2019+)

| Check | Method | Compliant Value |
|-------|--------|-----------------|
| Cmdlet Available | PowerShell: `Get-LapsDiagnostics` exists | Cmdlet available |
| GPO Configured | Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS` | BackupDirectory != 0 |

### Legacy LAPS (Microsoft LAPS)

| Check | Method | Compliant Value |
|-------|--------|-----------------|
| AdmPwdEnabled | Registry: `HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled` | 1 |
| CSE Installed | File: `C:\Program Files\LAPS\CSE\AdmPwd.dll` | File exists |

### Password Policy (Informational)

| Setting | Recommendation |
|---------|----------------|
| Password Length | >= 14 characters |
| Password Age | <= 30 days |

## Test Characteristics

- **Type**: Configuration Validation (READ-ONLY)
- **Category**: Cyber Hygiene
- **Priority**: HIGH
- **Admin Required**: Yes
- **Destructive**: No
- **Network Required**: No

## Expected Outcomes

- **Code 126 (COMPLIANT)**: At least one LAPS method is configured
- **Code 101 (NON-COMPLIANT)**: No LAPS configuration detected
- **Code 999 (ERROR)**: Test error (e.g., insufficient privileges)

## CIS Benchmark Reference

- **CIS Controls v8: 4.7** - Manage Default Accounts on Enterprise Assets and Software
- **CIS Controls v8: 5.2** - Use Unique Passwords

## GPO Paths

- **Windows LAPS**: `Computer Configuration > Administrative Templates > System > LAPS`
- **Legacy LAPS**: `Computer Configuration > Administrative Templates > LAPS`

## Build Instructions

```bash
# Build the test
./utils/gobuild build tests_source/cyber-hygiene/05c39526-5374-419f-bf1e-68468400f3c6/

# Sign the binary
./utils/codesign sign build/05c39526-5374-419f-bf1e-68468400f3c6/05c39526-5374-419f-bf1e-68468400f3c6.exe
```

## Remediation Guidance

If the test returns NON-COMPLIANT (exit code 101), implement one of the following:

### Option 1: Windows LAPS (Recommended)

Windows LAPS is built into Windows 11 22H2+ and Server 2019+ (with April 2023 update).

1. **Configure via Group Policy**:
   ```
   Computer Configuration > Administrative Templates > System > LAPS
   ```

2. **Required Settings**:
   - Enable "Configure password backup directory" (set to Azure AD or Active Directory)
   - Configure "Password Settings":
     - Complexity: Large letters + small letters + numbers + specials
     - Length: >= 14 characters
     - Age: <= 30 days

3. **For Azure AD joined devices**: Set backup directory to Azure AD
4. **For hybrid/AD joined devices**: Set backup directory to Active Directory

### Option 2: Legacy Microsoft LAPS

For older systems not supporting Windows LAPS:

1. **Download LAPS** from Microsoft Download Center

2. **Extend AD Schema** (run once on DC):
   ```powershell
   Import-Module AdmPwd.PS
   Update-AdmPwdADSchema
   ```

3. **Set AD Permissions**:
   ```powershell
   Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=domain,DC=com"
   ```

4. **Install CSE** on all managed systems via SCCM/GPO

5. **Configure GPO**:
   ```
   Computer Configuration > Administrative Templates > LAPS
   - Enable local admin password management: Enabled
   - Password Settings: complexity, length, age
   ```

## Notes

- LAPS does not apply to Domain Controllers
- Windows LAPS and Legacy LAPS can coexist but may cause conflicts
- Test accounts other than the built-in Administrator may not be managed

## Output Files

After execution, the test produces:
- `c:\F0\test_execution_log.json` - Structured JSON log (Schema v2.0)
- `c:\F0\test_execution_log.txt` - Human-readable text log
- `c:\F0\laps_diagnostic.txt` - System diagnostic information
