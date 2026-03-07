# AMOS/Banshee macOS Infostealer Credential Harvesting Simulation

**Test Score**: **9.3/10**

## Overview

Simulates the complete credential harvesting chain used by AMOS (Atomic Stealer), Banshee Stealer, and Cuckoo Stealer -- the three dominant macOS infostealer families operating as Malware-as-a-Service (MaaS) at $3,000/month. Red Canary reported a 400% increase in macOS threats from 2023 to 2024, with osascript identified as the single most abused execution mechanism on macOS. This test evaluates EDR/AV detection capabilities against 8 simulation phases covering credential phishing via fake password dialogs, Keychain extraction via Chainbreaker, browser credential theft across 9+ browsers, cryptocurrency wallet enumeration, TCC database manipulation, XProtect-style XOR evasion, and data exfiltration via HTTP POST.

## MITRE ATT&CK Mapping

- **Tactic**: Execution, Credential Access, Collection, Exfiltration, Defense Evasion
- **Technique**: T1059.002 - Command and Scripting Interpreter: AppleScript
- **Technique**: T1555.001 - Credentials from Password Stores: Keychain
- **Technique**: T1056.002 - Input Capture: GUI Input Capture
- **Technique**: T1005 - Data from Local System
- **Technique**: T1560.001 - Archive Collected Data: Archive via Utility
- **Technique**: T1041 - Exfiltration Over C2 Channel
- **Technique**: T1027 - Obfuscated Files or Information

## Test Execution

Simulates the full AMOS/Banshee infostealer killchain across 8 sequential phases:

1. **osascript Credential Phishing** (T1059.002, T1056.002) - Creates realistic AppleScript credential dialog artifact with retry logic (Banshee pattern) and dscl validation
2. **dscl Credential Validation** (T1059.002) - Documents the `dscl /Local/Default -authonly` pattern used by all major macOS stealers
3. **Keychain Credential Dumping** (T1555.001) - Simulates Chainbreaker-style extraction with Chrome Safe Storage key and 10+ keychain entries
4. **Browser Credential Theft** (T1005) - Enumerates credential databases across 9 browsers (Chrome, Firefox, Safari, Brave, Edge, Opera, Vivaldi, Chromium, Arc) plus Apple Notes
5. **Cryptocurrency Wallet Targeting** (T1005) - Enumerates 8 wallet extensions/applications (MetaMask, Coinbase, Exodus, Atomic, Electrum, Phantom, Trust Wallet, Bitwarden)
6. **TCC Database Reset** - Simulates the Cuckoo Stealer `tccutil reset AppleEvents` pattern
7. **XProtect XOR String Encryption** (T1027) - Demonstrates Banshee's adoption of Apple's XProtect string encryption (evaded VirusTotal for 2+ months)
8. **Data Staging and Exfiltration** (T1560.001, T1041) - Creates "out.zip" staging archive and HTTP POST exfiltration with hwid/wid/user metadata

## Expected Outcomes

- **Protected (Code 126)**: EDR/AV detects and blocks simulation artifact creation
- **Protected (Code 127)**: EDR/AV quarantines artifacts after creation
- **Unprotected (Code 101)**: All 8 phases complete without detection

## Build Instructions

```bash
# Standard build
./utils/gobuild build tests_source/intel-driven/3e985e9e-8141-49d3-a23c-6c7f5e3282f5/
./utils/codesign sign build/3e985e9e-8141-49d3-a23c-6c7f5e3282f5/3e985e9e-8141-49d3-a23c-6c7f5e3282f5.exe

# Or manual build
cd tests_source/intel-driven/3e985e9e-8141-49d3-a23c-6c7f5e3282f5/
GOOS=windows GOARCH=amd64 go build -o ../../../build/3e985e9e-8141-49d3-a23c-6c7f5e3282f5/3e985e9e-8141-49d3-a23c-6c7f5e3282f5.exe 3e985e9e-8141-49d3-a23c-6c7f5e3282f5.go test_logger.go org_resolver.go es_config.go
```

## Threat Intelligence Sources

- Red Canary 2024 Threat Detection Report (macOS section)
- AMOS/Atomic Stealer MaaS analysis
- Banshee Stealer XProtect evasion research
- Cuckoo Stealer TCC manipulation documentation
- Elastic Security Labs macOS stealer analysis
