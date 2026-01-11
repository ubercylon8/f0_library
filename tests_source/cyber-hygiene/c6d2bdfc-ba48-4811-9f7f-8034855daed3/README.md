# Print Spooler Hardening Validator

**Test Score**: **7.5/10**

## Overview

This cyber hygiene test validates that the Windows Print Spooler service is properly hardened or disabled to mitigate PrintNightmare (CVE-2021-34527) and related vulnerabilities. The test checks service status and Point and Print restrictions that can allow remote code execution with SYSTEM privileges. CISA issued Emergency Directive 21-04 specifically for this vulnerability class.

## MITRE ATT&CK Mapping

- **Tactics**: Persistence, Privilege Escalation
- **Techniques**:
  - T1547.012 - Boot or Logon Autostart Execution: Print Processors
  - T1569.002 - System Services: Service Execution
  - T1068 - Exploitation for Privilege Escalation

## Configuration Checks

| Check | Registry/Method | Compliant Value |
|-------|-----------------|-----------------|
| Spooler Service Status | `sc query Spooler` / Registry Start value | Disabled (4) OR Not Running |
| NoWarningNoElevationOnInstall | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall` | 0 (or not configured) |
| UpdatePromptSettings | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdatePromptSettings` | 0 (or not configured) |
| RestrictDriverInstallationToAdministrators | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators` | 1 (or not configured*) |

*Windows defaults changed after July 2021 security updates to restrict driver installation by default.

## Test Characteristics

- **Type**: Configuration Validation (READ-ONLY)
- **Category**: Cyber Hygiene
- **Priority**: HIGH
- **Admin Required**: Yes
- **Destructive**: No
- **Network Required**: No

## Compliance Logic

The test uses the following compliance logic:

1. **Service Disabled/Stopped = COMPLIANT** (Best practice, especially for non-print servers)
2. **Service Running + ALL Point and Print restrictions = COMPLIANT** (Acceptable for print servers)
3. **Service Running + ANY restriction missing = NON-COMPLIANT**

**Special Note**: Domain Controllers should ALWAYS have the Print Spooler service DISABLED, regardless of printing needs.

## Expected Outcomes

- **Code 126 (COMPLIANT)**: Service disabled OR running with all restrictions
- **Code 101 (NON-COMPLIANT)**: Service running without proper restrictions
- **Code 999 (ERROR)**: Test error (e.g., insufficient privileges)

## CIS Benchmark Reference

- **CIS Controls v8: 4.8** - Uninstall or Disable Unnecessary Services on Enterprise Assets and Software
- **CIS Controls v8: 7.7** - Remediate Detected Vulnerabilities

## GPO Paths

- `Computer Configuration > Windows Settings > Security Settings > System Services > Print Spooler`
- `Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions`
- `Computer Configuration > Administrative Templates > Printers > Limits print driver installation to Administrators`

## Build Instructions

```bash
# Build the test
./utils/gobuild build tests_source/cyber-hygiene/c6d2bdfc-ba48-4811-9f7f-8034855daed3/

# Sign the binary
./utils/codesign sign build/c6d2bdfc-ba48-4811-9f7f-8034855daed3/c6d2bdfc-ba48-4811-9f7f-8034855daed3.exe
```

## Remediation Guidance

If the test returns NON-COMPLIANT (exit code 101), apply one of the following:

### Option 1: Disable Print Spooler (Recommended for Non-Print Servers)

```powershell
# Stop and disable the Print Spooler service
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# Verify
Get-Service -Name Spooler | Select-Object Status, StartType
```

### Option 2: Enable Point and Print Restrictions (Print Servers Only)

```powershell
# Create the registry path if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Force | Out-Null

# Set secure values
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord
```

### Domain Controllers

Domain Controllers should ALWAYS have Print Spooler disabled:

```powershell
# Disable on all Domain Controllers (run via GPO or on each DC)
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```

## Output Files

After execution, the test produces:
- `c:\F0\test_execution_log.json` - Structured JSON log (Schema v2.0)
- `c:\F0\test_execution_log.txt` - Human-readable text log
- `c:\F0\spooler_service_output.txt` - Service query output

## CVE References

- **CVE-2021-34527** - Windows Print Spooler Remote Code Execution (PrintNightmare)
- **CVE-2021-1675** - Windows Print Spooler Elevation of Privilege
- **CVE-2021-34481** - Windows Print Spooler Elevation of Privilege
- **CVE-2021-36936** - Windows Print Spooler Remote Code Execution
