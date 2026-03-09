# APT33 Tickler Backdoor DLL Sideloading

**Test Score**: **8.7/10**

## Overview

Simulates the APT33 (Elfin / Peach Sandstorm / Refined Kitten) Tickler backdoor attack chain, which uses DLL sideloading via legitimate Microsoft binaries, dual persistence mechanisms (registry Run key + scheduled task), and HTTP POST exfiltration to Azure-hosted C2 on non-standard ports. This test evaluates EDR detection capabilities against a 6-stage killchain derived from threat intelligence on APT33's evolved tradecraft targeting defense, satellite, and financial sector organizations.

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Name |
|-------|--------|-----------|------|
| 1 | Initial Access | T1566.001 | Spearphishing Attachment |
| 2 | Defense Evasion | T1574.002 | DLL Side-Loading |
| 3 | Persistence | T1547.001 | Registry Run Keys |
| 4 | Persistence | T1053.005 | Scheduled Task |
| 5 | Defense Evasion | T1036 | Masquerading |
| 6 | Command and Control | T1071.001 | Web Protocols |

## Test Architecture

Multi-stage (6 stages) with per-stage ES fan-out for technique-level detection precision.

## Test Execution

```bash
# Build
./tests_source/intel-driven/13c2d073-8e33-4fca-ab27-68f20c408ce9/build_all.sh --org sb

# Deploy single binary to target
# Copy build/13c2d073-8e33-4fca-ab27-68f20c408ce9/13c2d073-8e33-4fca-ab27-68f20c408ce9.exe to C:\F0\
```

## Expected Outcomes

- **Protected (Exit 126)**: EDR detects and blocks at least one stage (DLL sideloading, registry persistence, scheduled task creation, or masqueraded binary execution)
- **Unprotected (Exit 101)**: All 6 stages complete without prevention -- full Tickler attack chain successful
- **Error (Exit 999)**: Prerequisites not met (e.g., insufficient privileges for registry/task operations)

## Detection Opportunities

7 KQL behavioral detection queries provided in `13c2d073-8e33-4fca-ab27-68f20c408ce9_detections.kql` covering:
1. DLL sideloading from non-standard paths
2. Registry Run key with SharePoint masquerading
3. Suspicious scheduled task creation
4. Renamed Microsoft binary execution
5. HTTP POST C2 on non-standard ports (808/880)
6. ZIP archives with double extensions
7. Combined behavioral correlation

## References

- MITRE ATT&CK - APT33: https://attack.mitre.org/groups/G0064/
- Microsoft Threat Intelligence - Peach Sandstorm Tickler Analysis
- FBI/CISA Advisory AA24-241a - Iranian APT Threat to Critical Infrastructure
