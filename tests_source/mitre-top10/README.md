# MITRE Top 10 Ransomware Techniques - Test Suite

This folder contains security tests based on MITRE's **Top 10 Techniques for Ransomware** attacks. These tests evaluate AV/EDR detection capabilities against the most common techniques used by ransomware operators.

## Test Suite Overview

| # | UUID | Technique | Test Name | Tool |
|---|------|-----------|-----------|------|
| 1 | `f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01` | T1059.001 | PowerShell Execution & AMSI Detection | Native |
| 2 | `b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02` | T1078.003 | Local Account Enumeration | Rubeus |
| 3 | `c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03` | T1021.001 | RDP Lateral Movement Simulation | SharpRDP |
| 4 | `d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04` | T1047 | WMI Execution Simulation | wmiexec-Pro |
| 5 | `e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05` | T1490 | System Recovery Inhibition (Safe Mode) | Native |
| 6 | `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06` | T1105 | LOLBIN Download Detection | Native |
| 7 | `a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07` | T1083 | Pre-Encryption File Enumeration | Seatbelt |
| 8 | `b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08` | T1486 | Ransomware Encryption (Safe Mode) | Native |
| 9 | `c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09` | T1190 | Webshell Post-Exploitation Simulation | Native |
| 10 | `d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10` | T1489 | Security Service Stop Simulation | NetExec |

## Source Data

Tests are based on:
- **MITRE ATT&CK Top 10 Techniques for Ransomware** (TopTenTechniques.json)
- **Tool Selection Matrix v2** (tool_selection_matrix_v2.md)

## Path Conventions

| Artifact Type | Path | Reason |
|--------------|------|--------|
| Test binaries (.exe) | `c:\F0` | Whitelisted - allows execution |
| Embedded tools | `c:\F0` | Same as above |
| Log files | `c:\F0` | Standard location |
| Simulation artifacts (docs, PDFs) | `c:\Users\fortika-test` | NOT whitelisted - EDR detects |
| Ransom notes | `c:\Users\fortika-test` | Realistic user directory |

## Tests with External Tools (5)

The following tests require user-provided tools:

1. **T1078.003** - Rubeus (GhostPack/Rubeus)
2. **T1021.001** - SharpRDP (0xthirteen/SharpRDP)
3. **T1047** - wmiexec-Pro (XiaoliChan/wmiexec-Pro)
4. **T1083** - Seatbelt (GhostPack/Seatbelt)
5. **T1489** - NetExec (Pennyw0rth/NetExec)

Place tools in each test's `tools/` directory before building.

## Build Instructions

```bash
# Build all tests in this suite
for dir in tests_source/mitre-top10/*/; do
    ./utils/gobuild build "$dir"
done

# Sign all tests
./utils/codesign sign-all
```

## MITRE ATT&CK Reference

Source: [MITRE ATT&CK Top Techniques for Ransomware](https://top-attack-techniques.mitre-engenuity.org/)

| Rank | Technique | Score |
|------|-----------|-------|
| 1 | T1059 - Command and Scripting Interpreter | 2.91 |
| 2 | T1078 - Valid Accounts | 1.36 |
| 3 | T1047 - Windows Management Instrumentation | 2.18 |
| 4 | T1105 - Ingress Tool Transfer | 1.59 |
| 5 | T1190 - Exploit Public-Facing Application | 1.08 |
| 6 | T1021.001 - Remote Desktop Protocol | 0.69 |
| 7 | T1490 - Inhibit System Recovery | 0.62 |
| 8 | T1489 - Service Stop | 0.59 |
| 9 | T1083 - File and Directory Discovery | 0.38 |
| 10 | T1486 - Data Encrypted for Impact | 0.30 |
