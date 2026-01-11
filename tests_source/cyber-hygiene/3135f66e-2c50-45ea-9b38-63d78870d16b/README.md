# Attack Surface Reduction Rules Validator

**Test Score**: **8.5/10**

## Overview

Validates that all 8 critical Attack Surface Reduction (ASR) rules are configured in Block mode. ASR rules prevent 93% of common malware execution patterns when properly configured. This is a READ-ONLY configuration validation test that makes no system modifications.

## MITRE ATT&CK Mapping

- **Tactics**: Defense Evasion, Execution, Initial Access
- **Techniques**:
  - T1059.001 - PowerShell (blocked by obfuscated script rule)
  - T1059.005 - Visual Basic (blocked by Office macro rules)
  - T1055 - Process Injection (blocked by credential stealing rule)
  - T1566.001 - Spearphishing Attachment (blocked by email content rules)

## Critical ASR Rules Validated

| Check | ASR Rule GUID | Description |
|-------|---------------|-------------|
| 1 | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` | Block LSASS credential stealing |
| 2 | `56a863a9-875e-4185-98a7-b882c64b5ce5` | Block vulnerable signed drivers |
| 3 | `e6db77e5-3df2-4cf1-b95a-636979351e5b` | Block WMI persistence |
| 4 | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Block Office child processes |
| 5 | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Block email executable content |
| 6 | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Block obfuscated scripts |
| 7 | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` | Block Office macro Win32 API calls |
| 8 | `c1db55ab-c21a-4637-bb3f-a12568109d35` | Advanced ransomware protection |

## Test Execution

The test performs a dual-method check:

1. **Registry Check**: Reads ASR configuration from `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`

2. **PowerShell Fallback**: Queries `Get-MpPreference` for AttackSurfaceReductionRules_Ids and AttackSurfaceReductionRules_Actions

## Expected Outcomes

- **COMPLIANT (Code 126)**: All 8 ASR rules are configured in Block mode (value = 1)
- **NON-COMPLIANT (Code 101)**: One or more rules are missing, disabled, or in Audit/Warn mode
- **Error (Code 999)**: Test execution error

## Build Instructions

```bash
# Build the test binary
./utils/gobuild build tests_source/cyber-hygiene/3135f66e-2c50-45ea-9b38-63d78870d16b/

# Sign the binary
./utils/codesign sign build/3135f66e-2c50-45ea-9b38-63d78870d16b/3135f66e-2c50-45ea-9b38-63d78870d16b.exe
```

## CIS Benchmark References

- **CIS Controls v8**: 2.5 (Allowlist Authorized Software), 10.5 (Enable Anti-Exploitation Features)
- **CIS Microsoft Windows 11 Benchmark**: Section 9.3 (Attack Surface Reduction)

## Remediation

If the test returns NON-COMPLIANT, configure ASR rules via:

**Group Policy**:
```
Computer Configuration > Administrative Templates > Windows Components
> Microsoft Defender Antivirus > Microsoft Defender Exploit Guard
> Attack Surface Reduction > Configure Attack Surface Reduction rules
```

**PowerShell** (Run as Administrator):
```powershell
# Enable all critical ASR rules in Block mode
$rules = @(
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
    "c1db55ab-c21a-4637-bb3f-a12568109d35"
)
$actions = @(1,1,1,1,1,1,1,1)
Set-MpPreference -AttackSurfaceReductionRules_Ids $rules -AttackSurfaceReductionRules_Actions $actions
```

**Microsoft Intune**:
Navigate to Endpoint Security > Attack surface reduction > Create a new policy with the above rules enabled.
