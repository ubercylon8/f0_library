# PowerShell Security and Logging Validator

**Test Score**: **8.0/10**

## Overview

This cyber-hygiene test validates that PowerShell security controls and comprehensive logging are enabled. PowerShell abuse (T1059.001) is the #1 attack technique with 46,155+ observed instances in 2024, making this configuration critical for every organization. This is a READ-ONLY configuration validation test that makes no system changes.

## MITRE ATT&CK Mapping

- **Tactic**: Execution, Defense Evasion
- **Technique**: T1059.001 - PowerShell
- **Related Techniques**:
  - T1027 - Obfuscated Files or Information
  - T1140 - Deobfuscate/Decode Files or Information
  - T1105 - Ingress Tool Transfer

## Configuration Checks

| Check | Registry Path | Compliant Value | Priority |
|-------|---------------|-----------------|----------|
| Script Block Logging | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` | 1 | CRITICAL |
| Module Logging | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging` | 1 | CRITICAL |
| Transcription | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting` | 1 | CRITICAL |
| Constrained Language Mode | PowerShell: `$ExecutionContext.SessionState.LanguageMode` | ConstrainedLanguage | INFORMATIONAL |

## Why This Matters

Without PowerShell logging enabled, attackers can:
- Execute malicious scripts undetected
- Use encoded/obfuscated commands
- Download and execute payloads from the internet
- Move laterally through the network
- Exfiltrate data using PowerShell

## Exit Codes

- **126 (COMPLIANT)**: All 3 critical logging settings are enabled
- **101 (NON-COMPLIANT)**: One or more critical logging settings are disabled
- **999 (ERROR)**: Test execution error

## Event Log Reference

When logging is enabled, look for these events:
- **Event ID 4103**: Module Logging events
- **Event ID 4104**: Script Block Logging events

## Remediation

### Group Policy

Navigate to:
```
Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell
```

Enable:
1. Turn on PowerShell Script Block Logging
2. Turn on Module Logging (add `*` to Module Names)
3. Turn on PowerShell Transcription

### PowerShell Commands

```powershell
# Enable Script Block Logging
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1

# Enable Module Logging
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1

# Enable Transcription
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1
```

## CIS Benchmark Reference

- **CIS Controls v8**: 8.2 (Collect Audit Logs), 8.5 (Collect Detailed Audit Logs)

## Build Instructions

```bash
# Build the test
./utils/gobuild build tests_source/cyber-hygiene/67165014-0377-4300-8197-ab459bd9249b/

# Sign the binary
./utils/codesign sign build/67165014-0377-4300-8197-ab459bd9249b/67165014-0377-4300-8197-ab459bd9249b.exe
```

## Expected Outcomes

### Compliant System (Exit 126)
- Script Block Logging enabled
- Module Logging enabled
- Transcription enabled
- All PowerShell activity logged to Event Log

### Non-Compliant System (Exit 101)
- One or more logging settings disabled
- Remediation steps provided in output
