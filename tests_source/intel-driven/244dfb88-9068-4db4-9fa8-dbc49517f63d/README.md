# DPRK BlueNoroff Financial Sector Attack Chain

**Test Score**: **9.2/10**

## Overview

Simulates the complete DPRK/BlueNoroff (Lazarus subgroup) attack chain targeting macOS endpoints in the financial and cryptocurrency sectors. This 5-stage multi-stage test models techniques from five documented campaigns: RustBucket, Hidden Risk, TodoSwift, KANDYKORN, and BeaverTail. BlueNoroff is responsible for generating revenue for the DPRK regime through cryptocurrency theft, making this one of the most financially motivated APT groups operating today. The test covers the full killchain from initial access via Gatekeeper bypass through data exfiltration of crypto wallet data.

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Name |
|-------|--------|-----------|------|
| 1 | Initial Access / Defense Evasion | T1553.001 | Subvert Trust Controls: Gatekeeper Bypass |
| 2 | Persistence | T1543.004 | Create or Modify System Process: Launch Agent |
| 3 | Credential Access / Execution | T1059.002 | Command and Scripting Interpreter: AppleScript |
| 3 | Credential Access | T1555.001 | Credentials from Password Stores: Keychain |
| 3 | Credential Access | T1056.002 | Input Capture: GUI Input Capture |
| 4 | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| 4 | Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography |
| 4 | Command and Control | T1071.004 | Application Layer Protocol: DNS |
| 5 | Exfiltration | T1041 | Exfiltration Over C2 Channel |
| 5 | Exfiltration | T1567.002 | Exfiltration to Cloud Storage |
| 5 | Collection | T1560.001 | Archive Collected Data: Archive via Utility |

## Test Architecture

Multi-stage architecture with 5 separate signed stage binaries embedded in a single orchestrator. Each stage implements a distinct phase of the BlueNoroff killchain.

## Test Execution

```bash
# Build (5 stages + cleanup)
./tests_source/intel-driven/244dfb88-9068-4db4-9fa8-dbc49517f63d/build_all.sh --org sb

# Deploy single binary to target
scp build/244dfb88-9068-4db4-9fa8-dbc49517f63d/244dfb88-9068-4db4-9fa8-dbc49517f63d.exe target:C:\

# Execute
C:\244dfb88-9068-4db4-9fa8-dbc49517f63d.exe

# Cleanup
C:\F0\bluenoroff_cleanup.exe
```

## Expected Outcomes

- **Protected (Exit 126)**: EDR blocks at least one stage (file quarantine, execution prevention, or behavioral detection)
- **Unprotected (Exit 101)**: All 5 stages execute successfully -- complete BlueNoroff killchain succeeded
- **Error (Exit 999)**: Test prerequisites not met

## Stage Details

### Stage 1: Gatekeeper Bypass & Payload Delivery (T1553.001)
- Simulates curl-based download (no quarantine attribute)
- Creates fake notarized malware with hijacked Apple Developer ID metadata
- Simulates quarantine attribute removal (`xattr -d com.apple.quarantine`)
- Drops disguised crypto application payload

### Stage 2: LaunchAgent Persistence (T1543.004)
- Creates RustBucket LaunchAgent (`com.apple.systemupdate.plist`)
- Creates BeaverTail LaunchAgent (`com.avatar.update.wake.plist`)
- Modifies `.zshenv` for Hidden Risk persistence (bypasses Login Items notification)
- Simulates LaunchDaemon installation for root persistence

### Stage 3: Credential Harvesting (T1059.002, T1555.001, T1056.002)
- Simulates osascript fake password dialog
- Simulates Keychain dump via `security` CLI
- Extracts browser credentials (Chrome Safe Storage key, Login Data)
- Targets crypto wallet data (MetaMask, Exodus, Coinbase Wallet)
- Simulates TCC manipulation (`tccutil reset`)

### Stage 4: C2 Communication (T1071.001, T1573.002, T1071.004)
- Simulates Sliver mTLS C2 beacon on port 8888
- HTTPS fallback C2 with JSON beacon payload
- DNS-based C2 tunnel with base64-encoded subdomain queries
- Google Drive URL payload staging (TodoSwift pattern)

### Stage 5: Data Exfiltration (T1041, T1567.002, T1560.001)
- Archives collected data (AMOS "out.zip" pattern)
- Simulates AWS S3 exfiltration with hardcoded credentials (NotLockBit pattern)
- Simulates Google Drive exfiltration (TodoSwift pattern)
- HTTP POST exfiltration with hwid/wid/user identifiers

## Threat Intelligence Sources

- RustBucket (BlueNoroff/Lazarus): Multi-stage AppleScript -> Objective-C -> Rust
- Hidden Risk Campaign (Nov 2024, SentinelLabs): .zshenv persistence, notarized malware
- KANDYKORN: Full RAT targeting blockchain engineers via linkpc.net domains
- TodoSwift: SwiftUI dropper using Google Drive URLs
- BeaverTail: Qt-based credential stealer delivering InvisibleFerret Python backdoor
- macOS.NotLockBit: AWS S3 exfiltration with hardcoded credentials

## Files

| File | Purpose |
|------|---------|
| `244dfb88-9068-4db4-9fa8-dbc49517f63d.go` | Main orchestrator |
| `stage-T1553.001.go` | Stage 1: Gatekeeper Bypass |
| `stage-T1543.004.go` | Stage 2: LaunchAgent Persistence |
| `stage-T1059.002.go` | Stage 3: Credential Harvesting |
| `stage-T1071.001.go` | Stage 4: C2 Communication |
| `stage-T1041.go` | Stage 5: Data Exfiltration |
| `cleanup_utility.go` | Cleanup utility |
| `test_logger.go` | Schema v2.0 logging |
| `org_resolver.go` | Organization registry helper |
| `build_all.sh` | Build script (7-step) |
