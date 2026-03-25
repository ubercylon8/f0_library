# UNK_RobotDreams Rust Backdoor Execution Chain

**Test Score**: **9.2/10**

## Overview

Simulates the UNK_RobotDreams threat actor's multi-stage attack chain targeting India-based offices of Middle Eastern government organizations. The attack uses spearphishing PDFs themed as "Gulf Security Alerts" from the Indian Ministry of External Affairs, PowerShell download cradles for Rust backdoor delivery, and Azure Front Door CDN for C2 domain fronting. This test evaluates EDR detection capabilities against a 3-stage killchain derived from threat intelligence on the 2026 Middle East Conflict Cluster.

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Name |
|-------|--------|-----------|------|
| 1 | Execution | T1204.002 | User Execution: Malicious File |
| 2 | Execution | T1059.001 | Command and Scripting Interpreter: PowerShell |
| 2 | Command and Control | T1105 | Ingress Tool Transfer |
| 3 | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| 3 | Command and Control | T1573.001 | Encrypted Channel: Symmetric Cryptography |
| 3 | Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location |

## Test Architecture

Multi-stage (3 stages) with per-stage ES fan-out for technique-level detection precision.

## Test Execution

```bash
# Build
./tests_source/intel-driven/414a4c61-019f-48ba-934d-d5e91a29a878/build_all.sh

# Deploy single binary to target
# Copy build/414a4c61-019f-48ba-934d-d5e91a29a878/414a4c61-019f-48ba-934d-d5e91a29a878.exe to C:\F0\
```

## Expected Outcomes

- **Protected (Exit 126)**: EDR detects and blocks at least one stage (PDF lure creation, PowerShell download cradle, or C2 communication)
- **Unprotected (Exit 101)**: All 3 stages complete without prevention -- full attack chain successful
- **Error (Exit 999)**: Prerequisites not met (e.g., PowerShell unavailable)

## Detection Opportunities

5 KQL behavioral detection queries provided in `414a4c61-019f-48ba-934d-d5e91a29a878_detections.kql` covering:
1. PDF with embedded URI action triggering executable download
2. Hidden PowerShell window with Invoke-WebRequest download cradle
3. HTTPS traffic to Azure Front Door / CDN with domain fronting headers
4. AES-encrypted beacon data staged to disk
5. Combined behavioral correlation across all stages

## References

- MITRE ATT&CK - T1204.002: https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK - T1059.001: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK - T1071.001: https://attack.mitre.org/techniques/T1071/001/
- Iran War Bait Fuels TA453, TA473 Phishing Campaigns - GBHackers
