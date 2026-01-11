# Intel-Driven - Threat Intelligence Test Suite

This folder contains security tests derived from **real-world threat intelligence**, including APT reports, ransomware analysis, CVE exploits, and malware research. These tests simulate actual attack techniques observed in the wild.

## Test Suite Overview

| # | UUID | Test Name | Source |
|---|------|-----------|--------|
| 1 | `09efee46-f098-4948-8e35-dded024cd1e7` | Sliver C2 Client Detection | Sliver C2 Framework |
| 2 | `109266e2-2310-40ea-9f63-b97e4b7fda61` | SafePay Enhanced Ransomware Simulation | SafePay Ransomware |
| 3 | `12afe0fc-597b-4e79-9cc4-40b4675ee83c` | (Unnamed Test) | - |
| 4 | `2cf59d3e-ae82-48bb-9779-4a5ba5bd9c11` | SafePay UAC Bypass & Defense Evasion | SafePay Ransomware |
| 5 | `4b4bd24c-fff5-4de8-982e-6d0fa5e22284` | Data Exfiltration and Encryption Simulation | Generic Ransomware |
| 6 | `581e0f20-13f0-4374-9686-be3abd110ae0` | Ransomware Encryption via BitLocker | BitLocker Abuse |
| 7 | `5ed12ef2-5e29-49a2-8f26-269d8e9edcea` | Multi-Stage Ransomware Killchain | Generic Ransomware |
| 8 | `6717c98c-b3db-490e-b03c-7b3bd3fb02ee` | SafePay Go-Native Ransomware Simulation | SafePay Ransomware |
| 9 | `7e93865c-0033-4db3-af3c-a9f4215c1c49` | Process Injection via CreateRemoteThread | Process Injection |
| 10 | `87b7653b-2cee-44d4-9d80-73ec94d5e18e` | EDR-Freeze Defense Evasion | EDR Evasion |
| 11 | `94b248c0-a104-48c3-b4a5-3d45028c407d` | Gunra Ransomware Simulation | Gunra Ransomware |
| 12 | `b6c73735-0c24-4a1e-8f0a-3c24af39671b` | MDE Authentication Bypass Command Interception | MDE Bypass |
| 13 | `b83616c2-84ee-4738-b398-d2d57eebecec` | NativeDump (NimDump) Detection | Credential Dumping |
| 14 | `bcba14e7-6f87-4cbd-9c32-718fdeb39b65` | EDRSilencer Detection | EDR Evasion |
| 15 | `c1f0fe6f-6907-4f95-820d-47e0a39abe54` | TrollDisappearKey AMSI Bypass Detection | AMSI Bypass |
| 16 | `c3634a9c-e8c9-44a8-992b-0faeca14f612` | Akira Ransomware BYOVD Attack Chain | Akira Ransomware |
| 17 | `e5577355-f8e4-4e52-b1b2-f7d1c8b864f1` | SilentButDeadly WFP EDR Network Isolation | EDR Evasion |
| 18 | `eafce2fc-75fd-4c62-92dc-32cabe5cf206` | Tailscale Remote Access and Data Exfiltration | Tailscale Abuse |
| 19 | `ecd2514c-512a-4251-a6f4-eb3aa834d401` | CyberEye RAT - Windows Defender Disabling | CyberEye RAT |
| 20 | `fec68e9b-af59-40c1-abbd-98ec98428444` | MDE Process Injection and API Authentication Bypass | MDE Bypass |

## Purpose

Intel-Driven tests are created from:

- **APT Campaign Reports** - Techniques used by nation-state actors
- **Ransomware Analysis** - SafePay, Akira, Gunra, and other families
- **CVE Exploits** - Proof-of-concept implementations
- **Red Team Tools** - Sliver, EDRSilencer, NativeDump detection
- **Defense Evasion Research** - AMSI bypass, EDR freeze techniques

## Path Conventions

| Artifact Type | Path | Reason |
|--------------|------|--------|
| Test binaries (.exe) | `c:\F0` | Whitelisted - allows execution |
| Embedded tools | `c:\F0` | Same as above |
| Log files | `c:\F0` | Standard location |
| Simulation artifacts (docs, PDFs) | `c:\Users\fortika-test` | NOT whitelisted - EDR detects |

## Test Categories

### Ransomware Simulation
- SafePay variants (UAC bypass, encryption, exfiltration)
- Akira BYOVD attack chain
- Gunra ransomware simulation
- BitLocker abuse for encryption

### Defense Evasion
- EDRSilencer - Blocks EDR network communications
- EDR-Freeze - Suspends EDR processes
- SilentButDeadly - WFP-based EDR isolation
- AMSI bypass techniques

### Credential Access
- NativeDump (NimDump) - LSASS dumping
- MDE authentication bypass

### Command & Control
- Sliver C2 client detection
- Tailscale remote access abuse

## Build Instructions

```bash
# Build all tests in this suite
for dir in tests_source/intel-driven/*/; do
    ./utils/gobuild build "$dir"
done

# Sign all tests
./utils/codesign sign-all
```

## Attack Flow Diagrams

Sample attack flow visualizations are available:
- `sample_attack_flow.html` - Standard theme
- `sample_attack_flow_terminal_theme.html` - Terminal theme

## Expected Results

| Exit Code | Meaning |
|-----------|---------|
| 101 | Attack succeeded - endpoint unprotected |
| 105 | File/binary quarantined |
| 126 | Execution blocked - endpoint protected |
| 999 | Test prerequisites not met |
