# TA453 NICECURL VBScript Backdoor Detection

**Test Score**: **9.2/10**

## Overview

Simulates the TA453 (APT42 / Charming Kitten / Mint Sandstorm) NICECURL VBScript backdoor attack chain, which uses malicious LNK files disguised as PDF forms to deliver a VBScript payload via wscript.exe, performs WMI-based security software discovery, and uses curl.exe for HTTPS C2 communication to Glitch.me-themed infrastructure. This test evaluates EDR detection capabilities against Living off the Land (LotL) techniques employed by Iran-aligned IRGC-IO threat actors targeting espionage objectives.

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Name |
|-------|--------|-----------|------|
| 1 | Execution | T1204.002 | User Execution: Malicious File |
| 1 | Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic |
| 1 | Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service |
| 2 | Discovery | T1047 | Windows Management Instrumentation |
| 2 | Discovery | T1518.001 | Software Discovery: Security Software Discovery |
| 3 | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| 3 | Command and Control | T1105 | Ingress Tool Transfer |

## Test Architecture

Multi-stage (3 stages) with per-stage ES fan-out for technique-level detection precision.

## Test Execution

```bash
# Build
./tests_source/intel-driven/8e2cf534-857b-4d29-a1ac-0f23d248db93/build_all.sh

# Deploy single binary to target
# Copy build/8e2cf534-857b-4d29-a1ac-0f23d248db93/8e2cf534-857b-4d29-a1ac-0f23d248db93.exe to C:\F0\
```

## Expected Outcomes

- **Protected (Exit 126)**: EDR detects and blocks at least one stage (LNK-to-wscript chain, WMI discovery, or curl.exe C2)
- **Unprotected (Exit 101)**: All 3 stages complete without prevention -- full NICECURL attack chain successful
- **Error (Exit 999)**: Prerequisites not met (e.g., curl.exe not available, wscript.exe blocked by policy)

## Detection Opportunities

5 KQL behavioral detection queries provided in `8e2cf534-857b-4d29-a1ac-0f23d248db93_detections.kql` covering:
1. LNK file with wscript.exe target and double extension masquerading
2. wscript.exe/cscript.exe executing VBScript from non-standard paths
3. WMI queries to SecurityCenter2 AntiVirusProduct namespace
4. curl.exe HTTPS POST to suspicious domains from script context
5. Combined behavioral correlation across all three stages

## References

- APT42 / Charming Kitten Threat Advisory: https://hawk-eye.io/wp-content/advisories/apt42-threat-advisory.html
- Uncharmed: Untangling Iran's APT42 Operations: https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations
- MITRE ATT&CK - Magic Hound / TA453: https://attack.mitre.org/groups/G0059/
