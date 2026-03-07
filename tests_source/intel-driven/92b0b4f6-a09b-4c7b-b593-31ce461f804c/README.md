# APT42 TAMECAT Fileless Backdoor with Browser Credential Theft

**Test Score**: **9.4/10**

## Overview
Simulates an APT42 (Magic Hound / Educated Manticore / UNC788) multi-stage attack chain featuring the TAMECAT fileless PowerShell backdoor, dual persistence mechanisms, browser credential theft targeting financial applications, and multi-channel exfiltration via Telegram API. This test validates endpoint detection capabilities against Iranian state-sponsored threat actor TTPs targeting banking and financial sector organizations.

## MITRE ATT&CK Mapping

| Stage | Technique | Name | Tactic |
|-------|-----------|------|--------|
| 1 | T1204.002 | User Execution: Malicious File | Execution |
| 1 | T1059.005 | VBScript (via WMI enumeration) | Execution |
| 2 | T1059.001 | PowerShell | Execution |
| 3 | T1547.001 | Registry Run Keys | Persistence |
| 3 | T1037.001 | Logon Script (UserInitMprLogonScript) | Persistence |
| 4 | T1555.003 | Credentials from Web Browsers | Credential Access |
| 5 | T1102 | Web Service (Telegram API) | Command and Control |

## Architecture
Multi-stage (5 stages) with per-technique signed binaries embedded in a single orchestrator. Each stage can be independently detected and blocked by EDR, providing technique-level detection precision.

## Test Execution

```bash
# Build
./build_all.sh --org sb

# Deploy single binary to target
scp build/92b0b4f6-a09b-4c7b-b593-31ce461f804c/92b0b4f6-a09b-4c7b-b593-31ce461f804c.exe target:C:\F0\

# Execute
C:\F0\92b0b4f6-a09b-4c7b-b593-31ce461f804c.exe
```

## Expected Outcomes

- **Code 126 (Protected)**: EDR blocked one or more stages
- **Code 101 (Unprotected)**: All 5 stages completed without detection
- **Code 105 (Quarantined)**: Stage binary quarantined before execution
- **Code 999 (Error)**: Prerequisites not met

## Key Detection Opportunities

1. LNK file creation with cscript.exe target
2. VBScript WMI AV enumeration (SecurityCenter2)
3. PowerShell -EncodedCommand via conhost.exe
4. AMSI/Script Block Logging triggers
5. Registry Run key creation ("Renovation" value)
6. UserInitMprLogonScript registry modification
7. Chrome/Edge Login Data file access
8. Edge remote debugging port (9222) activation
9. Outbound Telegram API traffic (api.telegram.org)
10. HTTPS POST to external data collection endpoints

## Financial Relevance
Tests detection of credential theft targeting banking applications accessed through browsers. Simulates compromise of trading platforms, payment portals, and treasury management systems accessed via web browsers.

## Threat Actor
APT42 / Magic Hound / Educated Manticore / UNC788 (Iranian state-sponsored)
