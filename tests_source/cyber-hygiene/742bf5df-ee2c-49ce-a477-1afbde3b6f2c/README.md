# Microsoft Defender Configuration Validator

**Test Score**: **8.5/10**

## Overview

This cyber hygiene test validates that Microsoft Defender Antivirus is properly configured with all critical protection features enabled. Proper Defender configuration is essential for preventing ransomware and other malware attacks, particularly Tamper Protection which prevents ransomware from disabling Defender pre-encryption.

## MITRE ATT&CK Mapping

- **Tactic**: Defense Evasion
- **Techniques**:
  - T1562.001 - Impair Defenses: Disable or Modify Tools
  - T1562.004 - Impair Defenses: Disable or Modify System Firewall
  - T1070 - Indicator Removal

## Configuration Checks

All 6 checks must pass for COMPLIANT status (exit code 126):

| # | Check | Method | Compliant Value |
|---|-------|--------|-----------------|
| 1 | Real-time Protection | `Get-MpComputerStatus` | RealTimeProtectionEnabled = True |
| 2 | Behavior Monitoring | `Get-MpComputerStatus` | BehaviorMonitorEnabled = True |
| 3 | Tamper Protection | `Get-MpComputerStatus` | IsTamperProtected = True |
| 4 | Cloud Protection (MAPS) | `Get-MpPreference` | MAPSReporting = 2 (Advanced) |
| 5 | Sample Submission | `Get-MpPreference` | SubmitSamplesConsent = 1 or 3 |
| 6 | PUA Protection | `Get-MpPreference` | PUAProtection = 1 |

### Alternative Registry Checks

If PowerShell cmdlets fail, the test falls back to registry checks:

| Check | Registry Path | Compliant Value |
|-------|---------------|-----------------|
| Real-time | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` | 0 or missing |
| MAPS | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting` | 2 |
| PUA | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection` | 1 |

## Test Characteristics

- **Type**: Configuration Validation (READ-ONLY)
- **Category**: Cyber Hygiene
- **Priority**: CRITICAL
- **Admin Required**: Yes
- **Destructive**: No
- **Network Required**: No

## Expected Outcomes

- **Code 126 (COMPLIANT)**: All 6 protection checks pass
- **Code 101 (NON-COMPLIANT)**: One or more checks fail
- **Code 999 (ERROR)**: Test error (e.g., Defender not installed, third-party AV, insufficient privileges)

## CIS Benchmark Reference

- **CIS Controls v8: 10.1** - Deploy and Maintain Anti-Malware Software
- **CIS Controls v8: 10.2** - Configure Automatic Updates for Anti-Malware Signature Files

## Build Instructions

```bash
# Build the test
./utils/gobuild build tests_source/cyber-hygiene/742bf5df-ee2c-49ce-a477-1afbde3b6f2c/

# Sign the binary
./utils/codesign sign build/742bf5df-ee2c-49ce-a477-1afbde3b6f2c/742bf5df-ee2c-49ce-a477-1afbde3b6f2c.exe
```

## Remediation Guidance

If the test returns NON-COMPLIANT (exit code 101), apply the following remediations:

### Enable Real-time Protection

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
```

### Enable Behavior Monitoring

```powershell
Set-MpPreference -DisableBehaviorMonitoring $false
```

### Enable Tamper Protection

Tamper Protection must be enabled via:
1. **Windows Security**: Settings > Virus & threat protection > Tamper Protection
2. **Microsoft Intune**: Endpoint security > Antivirus > Windows Security experience
3. **Group Policy**: Not available via GPO (by design for security)

### Enable Cloud Protection (MAPS)

```powershell
Set-MpPreference -MAPSReporting Advanced
```

### Enable Sample Submission

```powershell
# Option 1: Send all samples automatically
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Option 2: Send safe samples only
Set-MpPreference -SubmitSamplesConsent SendSafeSamples
```

### Enable PUA Protection

```powershell
Set-MpPreference -PUAProtection Enabled
```

## Signature Age Warning

The test also checks the age of antivirus signatures (warning only, does not affect compliance):
- **< 7 days**: Current (OK)
- **>= 7 days**: Outdated (Warning logged)

## Output Files

After execution, the test produces:
- `c:\F0\test_execution_log.json` - Structured JSON log (Schema v2.0)
- `c:\F0\test_execution_log.txt` - Human-readable text log
- `c:\F0\defender_status_output.txt` - Get-MpComputerStatus output
- `c:\F0\defender_preferences_output.txt` - Get-MpPreference output

## Why Tamper Protection Matters

Tamper Protection is critical because it prevents:
- Ransomware from disabling Windows Defender before encryption
- Malware from modifying protection settings via registry/WMI
- Scripts from disabling real-time scanning during infection

Without Tamper Protection, sophisticated malware can completely disable Defender before executing its payload, making the endpoint essentially unprotected.
