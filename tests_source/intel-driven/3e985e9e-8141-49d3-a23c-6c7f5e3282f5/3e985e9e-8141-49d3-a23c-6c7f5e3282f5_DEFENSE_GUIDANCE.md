# Defense Guidance: AMOS/Banshee macOS Infostealer Credential Harvesting

## Executive Summary

This document provides comprehensive defense guidance for protecting against **AMOS (Atomic Stealer)**, **Banshee Stealer**, and **Cuckoo Stealer** -- the three dominant macOS infostealer families operating as Malware-as-a-Service (MaaS) platforms at $3,000/month. Red Canary documented a 400% increase in macOS threats from 2023 to 2024, with osascript identified as the single most abused execution mechanism on macOS. The attack chain encompasses 8 phases: credential phishing via fake system dialogs, password validation via dscl, Keychain extraction via Chainbreaker, multi-browser credential theft, cryptocurrency wallet enumeration, TCC database manipulation, XProtect-style XOR evasion, and data staging/exfiltration via HTTP POST.

| Field | Value |
|-------|-------|
| **Test ID** | 3e985e9e-8141-49d3-a23c-6c7f5e3282f5 |
| **Test Name** | AMOS/Banshee macOS Infostealer Credential Harvesting Simulation |
| **MITRE ATT&CK** | [T1059.002](https://attack.mitre.org/techniques/T1059/002/), [T1555.001](https://attack.mitre.org/techniques/T1555/001/), [T1056.002](https://attack.mitre.org/techniques/T1056/002/), [T1005](https://attack.mitre.org/techniques/T1005/), [T1560.001](https://attack.mitre.org/techniques/T1560/001/), [T1041](https://attack.mitre.org/techniques/T1041/), [T1027](https://attack.mitre.org/techniques/T1027/) |
| **Tactics** | Execution, Credential Access, Collection, Exfiltration, Defense Evasion |
| **Threat Actor** | AMOS (Atomic Stealer) / Banshee Stealer / Cuckoo Stealer |
| **Severity** | CRITICAL |
| **Test Score** | 9.3/10 |
| **Platform** | macOS |

---

## Threat Overview

### Attack Description

AMOS (Atomic Stealer), Banshee Stealer, and Cuckoo Stealer represent the industrialization of macOS credential theft. These MaaS platforms provide subscribers with turnkey infostealer capabilities including:

- **Fake password dialogs** via osascript with retry logic and dscl password validation
- **Keychain credential extraction** via Chainbreaker using the phished macOS password
- **Multi-browser credential theft** targeting 9+ browsers (Chrome, Firefox, Safari, Brave, Edge, Opera, Vivaldi, Chromium, Arc)
- **Cryptocurrency wallet enumeration** across 8 wallets (MetaMask, Coinbase, Exodus, Atomic, Electrum, Phantom, Trust Wallet, Bitwarden)
- **Apple Notes harvesting** for passwords stored in NoteStore.sqlite
- **TCC database manipulation** to clear consent decisions and force re-prompting
- **XProtect-style XOR string encryption** that evaded VirusTotal for 2+ months
- **HTTP POST exfiltration** with hardware/worker ID metadata matching C2 protocol

### Attack Flow

```
[1] osascript Credential Phishing (T1059.002, T1056.002)
    -> "display dialog" with "hidden answer" mimicking System Preferences
    -> Banshee variant retries up to 5 times
         |
         v
[2] dscl Credential Validation (T1059.002)
    -> dscl /Local/Default -authonly $USER <password>
    -> Universal validation step across all three stealers
         |
         v
[3] Keychain Credential Dumping (T1555.001)
    -> security list-keychains -d user
    -> Chainbreaker extraction (login.keychain-db, System.keychain, iCloud.keychain)
    -> Chrome Safe Storage key extraction for browser credential decryption
         |
         v
[4] Browser Credential Theft (T1005)
    -> Login Data, Cookies, key4.db across 9 browsers
    -> Safari cookie restoration for session hijacking (AMOS feature)
    -> Apple Notes (NoteStore.sqlite) extraction
         |
         v
[5] Cryptocurrency Wallet Targeting (T1005)
    -> MetaMask, Coinbase, Exodus, Atomic, Electrum, Phantom, Trust Wallet, Bitwarden
    -> Browser extension Local Extension Settings and app data directories
         |
         v
[6] TCC Database Reset (Cuckoo Pattern)
    -> tccutil reset AppleEvents
    -> Clears consent decisions, forces re-prompting for Automation access
         |
         v
[7] XProtect XOR String Encryption (T1027)
    -> Banshee adopted Apple's own XProtect string encryption algorithm
    -> Evaded VirusTotal for 2+ months by encrypting AV signature targets
         |
         v
[8] Data Staging and Exfiltration (T1560.001, T1041)
    -> Creates "out.zip" archive (~48.5 MB, 67 files)
    -> HTTP POST multipart/form-data with hwid/wid/user metadata
    -> Targets MaaS C2 infrastructure
```

---

## MITRE ATT&CK Mapping

### Technique-to-Mitigation Matrix

| Technique | Name | Mitigations |
|-----------|------|-------------|
| T1059.002 | Command and Scripting Interpreter: AppleScript | [M1042](https://attack.mitre.org/mitigations/M1042/) Disable or Remove Feature, [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1049](https://attack.mitre.org/mitigations/M1049/) Antivirus/Antimalware |
| T1555.001 | Credentials from Password Stores: Keychain | [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies, [M1026](https://attack.mitre.org/mitigations/M1026/) Privileged Account Management |
| T1056.002 | Input Capture: GUI Input Capture | [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1017](https://attack.mitre.org/mitigations/M1017/) User Training |
| T1005 | Data from Local System | [M1057](https://attack.mitre.org/mitigations/M1057/) Data Loss Prevention, [M1041](https://attack.mitre.org/mitigations/M1041/) Encrypt Sensitive Information |
| T1560.001 | Archive Collected Data: Archive via Utility | [M1047](https://attack.mitre.org/mitigations/M1047/) Audit |
| T1041 | Exfiltration Over C2 Channel | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1030](https://attack.mitre.org/mitigations/M1030/) Network Segmentation |
| T1027 | Obfuscated Files or Information | [M1049](https://attack.mitre.org/mitigations/M1049/) Antivirus/Antimalware, [M1040](https://attack.mitre.org/mitigations/M1040/) Behavior Prevention on Endpoint |

### Detection Priority Matrix

| Priority | Technique | Detection Confidence | Rationale |
|----------|-----------|---------------------|-----------|
| P1 | T1059.002 + T1056.002 | CRITICAL | osascript credential phishing is the initial access vector; high-fidelity detection |
| P1 | T1555.001 | CRITICAL | Keychain extraction represents actual credential compromise |
| P2 | T1005 (Browser) | HIGH | Multi-browser credential access is highly indicative |
| P2 | T1005 (Wallet) | HIGH | Cryptocurrency wallet access causes direct financial loss |
| P3 | T1560.001 | HIGH | Data staging precedes exfiltration; last chance to prevent data loss |
| P3 | T1041 | HIGH | Exfiltration detection; recovery-focused at this stage |
| P4 | T1027 | MEDIUM | XOR obfuscation harder to detect; behavioral analysis preferred |

---

## Detection Rules

### KQL Queries (Microsoft Sentinel/Defender)

Detection queries are available in `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_detections.kql` covering 13 queries:

1. **osascript Credential Phishing Detection** (T1059.002, T1056.002) - Critical
2. **dscl Credential Validation Detection** (T1059.002) - Critical
3. **Keychain Access and Credential Dumping** (T1555.001) - Critical
4. **Browser Credential Database Access** (T1005) - High
5. **Cryptocurrency Wallet Enumeration** (T1005) - High
6. **TCC Database Manipulation** (T1059.002) - High
7. **Apple Notes Database Access** (T1005) - Medium
8. **Data Staging and Archive Creation** (T1560.001) - High
9. **HTTP POST Exfiltration with Stealer Metadata** (T1041) - Critical
10. **Hidden Directory Credential Cache (Cuckoo)** (T1059.002) - Critical
11. **Combined Behavioral Detection - Full Chain** (T1059.002, T1555.001, T1005) - Critical
12. **dscl User Enumeration** (T1059.002, T1087.001) - Medium
13. **Keychain File Direct Access** (T1555.001) - Critical

### Sigma Rules

Detection rules are available in `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_sigma_rules.yml` covering 13 rules:

| Rule ID | Title | Level |
|---------|-------|-------|
| 3e985e9e-sigma-001 | macOS osascript Credential Phishing Dialog | Critical |
| 3e985e9e-sigma-002 | macOS dscl Credential Validation via authonly | Critical |
| 3e985e9e-sigma-003 | macOS Keychain Credential Extraction Commands | Critical |
| 3e985e9e-sigma-004 | macOS Multi-Browser Credential Database File Access | High |
| 3e985e9e-sigma-005 | macOS Cryptocurrency Wallet Extension Directory Enumeration | High |
| 3e985e9e-sigma-006 | macOS TCC Database Reset via tccutil | High |
| 3e985e9e-sigma-007 | macOS Apple Notes Database Access by Non-Apple Process | High |
| 3e985e9e-sigma-008 | macOS Exfiltration Archive Creation (out.zip Pattern) | High |
| 3e985e9e-sigma-009 | macOS HTTP POST Exfiltration with Stealer Metadata Fields | Critical |
| 3e985e9e-sigma-010 | macOS Cuckoo Stealer Hidden Directory Credential Cache | Critical |
| 3e985e9e-sigma-011 | macOS Keychain Database Direct File Read | Critical |
| 3e985e9e-sigma-012 | macOS dscl Local User Account Enumeration | Medium |
| 3e985e9e-sigma-013 | macOS Infostealer Full Kill Chain Correlation | Critical |

### LimaCharlie D&R Rules

Detection rules are available in `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_dr_rules.yaml` covering 12 rules:

| Rule Name | Event Type | Confidence |
|-----------|------------|------------|
| macos-osascript-credential-phishing | NEW_PROCESS | Critical |
| macos-dscl-credential-validation | NEW_PROCESS | Critical |
| macos-keychain-credential-extraction | NEW_PROCESS | High |
| macos-chainbreaker-execution | NEW_PROCESS | Critical |
| macos-keychain-db-direct-access | FILE_GET_REP | High |
| macos-browser-credential-database-access | FILE_GET_REP | High |
| macos-crypto-wallet-data-access | FILE_GET_REP | High |
| macos-tcc-database-reset | NEW_PROCESS | High |
| macos-apple-notes-database-access | FILE_GET_REP | Medium |
| macos-exfil-archive-creation | FILE_CREATE | High |
| macos-cuckoo-pwdat-credential-cache | FILE_CREATE | Critical |
| macos-dscl-user-enumeration | NEW_PROCESS | Medium |

### YARA Rules

Detection rules are available in `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_rules.yar` covering 9 rules:

| Rule Name | Targets | Confidence |
|-----------|---------|------------|
| AMOS_Banshee_OsascriptPhishing_MacOS | AppleScript credential phishing patterns | High |
| AMOS_Banshee_DsclValidation_MacOS | dscl validation in Mach-O binaries | High |
| AMOS_Banshee_KeychainTheft_MacOS | Keychain extraction strings | High |
| AMOS_Banshee_MultiBrowserTheft_MacOS | Multi-browser credential database references | High |
| AMOS_Banshee_CryptoWalletTheft_MacOS | Cryptocurrency wallet extension IDs | High |
| AMOS_Banshee_XORObfuscation_MacOS | XProtect-style XOR obfuscation patterns | Medium |
| AMOS_Banshee_ExfilPayload_MacOS | Exfiltration archive with stealer metadata | High |
| AMOS_Banshee_CombinedIndicators_MacOS | Multi-phase infostealer binary | Critical |
| Cuckoo_Stealer_HiddenDirectory_MacOS | .local-UUID/pw.dat credential caching | High |

---

## Hardening Guidance

### Quick Reference: Key Hardening Actions

| Priority | Action | Mitigation | Impact |
|----------|--------|-----------|--------|
| P1 | Restrict osascript execution via MDM profile | M1038 | Medium - may affect legitimate AppleScript workflows |
| P1 | Enable Keychain Access Notifications | M1027 | Low - user awareness enhancement |
| P1 | Deploy EDR with macOS behavioral detection | M1049 | Low - requires agent deployment |
| P2 | Restrict dscl to admin accounts | M1026 | Low - standard users rarely need dscl |
| P2 | Protect browser credential databases | M1041 | Low - filesystem permission hardening |
| P2 | Configure TCC policy via MDM | M1054 | Low - centralized permission management |
| P3 | Network egress filtering for HTTP POST | M1031 | Medium - requires proxy infrastructure |
| P3 | Monitor archive creation in user directories | M1047 | Low - audit logging only |

### Hardening Scripts

Platform-specific hardening scripts are provided:

| Script | Platform | Purpose |
|--------|----------|---------|
| `3e985e9e..._hardening.ps1` | Windows | Cross-platform guidance for mixed environments |
| `3e985e9e..._hardening_macos.sh` | macOS | Primary target platform hardening |
| `3e985e9e..._hardening_linux.sh` | Linux | Equivalent protections for Linux endpoints |

### Detailed Hardening: osascript Execution Restriction

**MITRE Mitigation:** [M1038](https://attack.mitre.org/mitigations/M1038/) - Execution Prevention

**Applicable Techniques:** T1059.002, T1056.002

**Implementation:**

| Setting | Value |
|---------|-------|
| **Location** | MDM Configuration Profile |
| **Mechanism** | Application Management / Launch Agent restrictions |
| **Impact Level** | Medium |

**MDM Profile (Jamf/Kandji/Mosyle):**

Restrict osascript execution to approved applications only:

```xml
<key>com.apple.applicationaccess</key>
<dict>
    <key>restrictedApplicationPaths</key>
    <array>
        <string>/usr/bin/osascript</string>
    </array>
</dict>
```

**Verification:**
```bash
# Verify osascript restrictions are applied
profiles list -output stdout-xml | grep -A5 "applicationaccess"
```

**Considerations:**
- **Potential Impacts:** May break legitimate automation workflows using osascript
- **Compatibility:** Requires MDM enrollment; works with Jamf, Kandji, Mosyle, Microsoft Intune
- **Testing:** Test in audit mode first; identify legitimate osascript usage before blocking

### Detailed Hardening: Keychain Access Protection

**MITRE Mitigation:** [M1027](https://attack.mitre.org/mitigations/M1027/) - Password Policies

**Applicable Techniques:** T1555.001

**Implementation:**

| Setting | Value |
|---------|-------|
| **Location** | Keychain Access preferences + MDM |
| **Mechanism** | Keychain auto-lock + access notifications |
| **Impact Level** | Low |

**Commands:**
```bash
# Set keychain to auto-lock after 5 minutes of inactivity
security set-keychain-settings -l -u -t 300 ~/Library/Keychains/login.keychain-db

# Require password confirmation for keychain access
security set-keychain-settings -l ~/Library/Keychains/login.keychain-db
```

**Verification:**
```bash
security show-keychain-info ~/Library/Keychains/login.keychain-db
```

### Detailed Hardening: Browser Credential Database Protection

**MITRE Mitigation:** [M1041](https://attack.mitre.org/mitigations/M1041/) - Encrypt Sensitive Information

**Applicable Techniques:** T1005

**Implementation:**

```bash
# Set restrictive permissions on Chrome Login Data
chmod 600 ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data
chmod 600 ~/Library/Application\ Support/Google/Chrome/Default/Cookies

# Monitor access to browser credential files
log stream --predicate 'eventMessage contains "Login Data"' --info
```

**Considerations:**
- Browsers need read/write access to their own credential databases
- Use file integrity monitoring rather than strict permissions
- Deploy endpoint DLP to detect bulk credential database reads

### Detailed Hardening: Network Egress Filtering

**MITRE Mitigation:** [M1031](https://attack.mitre.org/mitigations/M1031/) - Network Intrusion Prevention

**Applicable Techniques:** T1041

**Implementation:**

```bash
# Block non-browser HTTP POST to suspicious destinations
# Deploy via pf.conf or application firewall

# Enable application firewall
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Enable stealth mode
/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# Block all incoming connections for unsigned apps
/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off
```

**Considerations:**
- Application firewall controls incoming connections; egress filtering requires proxy
- Deploy HTTPS inspection proxy for deep packet inspection of outbound traffic
- Monitor for multipart/form-data POST requests from non-browser processes

---

## Incident Response Playbook

### Quick Reference

| Field | Value |
|-------|-------|
| **Test ID** | 3e985e9e-8141-49d3-a23c-6c7f5e3282f5 |
| **Test Name** | AMOS/Banshee macOS Infostealer Credential Harvesting |
| **MITRE ATT&CK** | T1059.002, T1555.001, T1056.002, T1005, T1560.001, T1041, T1027 |
| **Severity** | Critical |
| **Estimated Response Time** | 2-4 hours (containment), 24-48 hours (full response) |

---

### 1. Detection Triggers

#### Alert Conditions

| Detection Name | Trigger Criteria | Confidence | Priority |
|----------------|------------------|------------|----------|
| osascript Credential Phishing | osascript + "display dialog" + "hidden answer" + password keyword | Critical | P1 |
| dscl Credential Validation | dscl -authonly from non-system process | Critical | P1 |
| Keychain Credential Extraction | security command with credential extraction flags | Critical | P1 |
| Multi-Browser Credential Access | Non-browser process accessing 3+ browser credential databases | High | P2 |
| Cryptocurrency Wallet Access | Non-browser process accessing 2+ wallet extension directories | High | P2 |
| Exfiltration Archive Creation | out.zip or similar archive created by non-standard process | High | P2 |
| TCC Database Reset | tccutil reset command execution | High | P3 |
| Cuckoo Credential Cache | pw.dat file in .local-UUID directory | Critical | P1 |

#### Initial Triage Questions

1. Is this a known F0RT1KA test execution or unexpected activity?
2. What user account is associated with the osascript/dscl execution?
3. Was the user prompted for their password recently (potential real credential capture)?
4. What is the timeline -- has keychain extraction or browser access already occurred?
5. Are there any outbound HTTP POST connections from the host?

---

### 2. Containment

#### Immediate Actions (First 15 minutes)

- [ ] **Isolate affected Mac from the network**
  ```bash
  # Disable all network interfaces
  sudo networksetup -setairportpower en0 off
  sudo networksetup -setnetworkserviceenabled "Ethernet" off

  # Or use MDM to push network isolation profile
  ```

- [ ] **Terminate malicious processes**
  ```bash
  # Kill osascript processes
  sudo killall osascript 2>/dev/null

  # Kill any suspicious processes accessing keychain
  sudo killall chainbreaker 2>/dev/null

  # List and kill processes accessing credential stores
  lsof +D ~/Library/Application\ Support/Google/Chrome/Default/ 2>/dev/null | grep -v "Chrome"
  ```

- [ ] **Preserve volatile evidence**
  ```bash
  # Create evidence directory
  sudo mkdir -p /var/ir_evidence/$(date +%Y%m%d)

  # Capture running processes
  ps aux > /var/ir_evidence/$(date +%Y%m%d)/processes.txt

  # Capture network connections
  netstat -an > /var/ir_evidence/$(date +%Y%m%d)/netstat.txt
  lsof -i > /var/ir_evidence/$(date +%Y%m%d)/network_connections.txt

  # Capture open files
  lsof > /var/ir_evidence/$(date +%Y%m%d)/open_files.txt
  ```

- [ ] **Revoke captured credentials immediately**
  ```bash
  # Force password reset for affected user
  # Coordinate with IT helpdesk for immediate credential rotation

  # Revoke browser sessions
  # Chrome: chrome://settings/security -> Sign out everywhere
  # Safari: Preferences -> Privacy -> Manage Website Data -> Remove All
  ```

---

### 3. Evidence Collection

#### Critical Artifacts

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Unified log (osascript) | System log | `log show --predicate 'process == "osascript"' --last 24h > /var/ir_evidence/osascript_log.txt` |
| Unified log (security) | System log | `log show --predicate 'process == "security"' --last 24h > /var/ir_evidence/security_log.txt` |
| Unified log (dscl) | System log | `log show --predicate 'process == "dscl"' --last 24h > /var/ir_evidence/dscl_log.txt` |
| TCC database | ~/Library/Application Support/com.apple.TCC/ | `sudo cp ~/Library/Application\ Support/com.apple.TCC/TCC.db /var/ir_evidence/` |
| Launch agents | ~/Library/LaunchAgents/ | `cp -R ~/Library/LaunchAgents/ /var/ir_evidence/launch_agents/` |
| Credential cache | .local-*/pw.dat | `find ~ -name "pw.dat" -path "*/.local-*" -exec cp {} /var/ir_evidence/ \;` |
| Staging archives | out.zip, data.zip | `find ~ /tmp -name "out.zip" -o -name "data.zip" 2>/dev/null \| xargs -I{} cp {} /var/ir_evidence/` |
| Quarantine events | com.apple.quarantine | `xattr -l ~/Downloads/* 2>/dev/null > /var/ir_evidence/quarantine_attrs.txt` |

#### Memory Acquisition
```bash
# Using osxpmem (if available)
sudo ./osxpmem -o /var/ir_evidence/memory.raw

# Or using macOS built-in (limited)
sudo vmmap -resident $(pgrep -f "suspicious_process") > /var/ir_evidence/vmmap.txt
```

#### Timeline Generation
```bash
# Export unified logs for timeline analysis
log show --last 24h --style syslog > /var/ir_evidence/unified_log_24h.txt

# Export FSEvents for file system timeline
find /.fseventsd -name "*.gz" -mtime -1 -exec cp {} /var/ir_evidence/fsevents/ \;

# Export login/logout events
last -100 > /var/ir_evidence/login_history.txt
```

---

### 4. Eradication

#### File Removal (AFTER evidence collection)
```bash
# Remove credential cache files
find ~ -path "*/.local-*/pw.dat" -delete 2>/dev/null
find ~ -name ".credentials_cache" -delete 2>/dev/null

# Remove staging archives
find ~ /tmp -name "out.zip" -delete 2>/dev/null

# Remove any dropped AppleScript artifacts
find ~ /tmp -name "*.applescript" -newer /var/ir_evidence/timeline_start -delete 2>/dev/null
```

#### Keychain Security Reset
```bash
# Reset keychain password (forces re-authentication)
security set-keychain-password ~/Library/Keychains/login.keychain-db

# Lock all keychains immediately
security lock-keychain -a
```

#### Browser Credential Rotation
```bash
# Clear Chrome saved passwords (recommend user action in browser)
# Clear Firefox saved passwords
# Revoke all active browser sessions
# Rotate any passwords stored in Apple Notes
```

#### TCC Database Verification
```bash
# Check TCC database for unauthorized entries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access WHERE service='kTCCServiceAppleEvents';"

# Reset TCC if tampering detected
tccutil reset AppleEvents
```

---

### 5. Recovery

#### System Restoration Checklist

- [ ] Verify all credential cache and staging files removed
- [ ] All user passwords rotated (macOS login, iCloud, browser-stored)
- [ ] All cryptocurrency wallet seed phrases regenerated / funds moved to new wallets
- [ ] Apple Notes reviewed for any stored passwords (moved to password manager)
- [ ] Browser sessions invalidated across all 9 targeted browsers
- [ ] TCC database verified clean
- [ ] Network connectivity restored (after validation)
- [ ] EDR agent verified operational

#### Validation Commands
```bash
# Verify no credential cache files remain
find ~ -name "pw.dat" -path "*/.local-*" 2>/dev/null  # Should return empty

# Verify no staging archives remain
find ~ /tmp -name "out.zip" -o -name "data.zip" 2>/dev/null  # Should return empty

# Verify keychain is locked
security show-keychain-info ~/Library/Keychains/login.keychain-db

# Verify macOS security controls active
csrutil status                           # SIP should be enabled
spctl --status                           # Gatekeeper should be enabled
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate  # Firewall should be on
```

---

### 6. Post-Incident

#### Lessons Learned Questions

1. How was the initial infection vector delivered (DMG, PKG, direct download)?
2. Was the user prompted with a fake password dialog? Did they enter their password?
3. How long was the stealer active before detection?
4. Which detection rule triggered first?
5. What data was potentially exfiltrated (keychain, browsers, wallets, notes)?
6. Were any cryptocurrency funds stolen?

#### Recommended Improvements

| Area | Recommendation | Priority |
|------|----------------|----------|
| Prevention | Deploy MDM policy restricting osascript execution | Critical |
| Prevention | Enable macOS Gatekeeper in strict mode | High |
| Prevention | Block unsigned/notarized DMG mounts via MDM | High |
| Detection | Deploy endpoint telemetry monitoring keychain access patterns | Critical |
| Detection | Implement behavioral detection for multi-browser credential access | High |
| Detection | Monitor for archive creation in user/temp directories | Medium |
| Response | Create automated credential rotation playbook | High |
| Response | Pre-position cryptocurrency wallet transfer procedures | High |
| Training | User awareness training on fake system dialogs | Medium |
| Architecture | Deploy enterprise password manager (reduce credential store surface) | Medium |

---

## References

- [MITRE ATT&CK - T1059.002 AppleScript](https://attack.mitre.org/techniques/T1059/002/)
- [MITRE ATT&CK - T1555.001 Keychain](https://attack.mitre.org/techniques/T1555/001/)
- [MITRE ATT&CK - T1056.002 GUI Input Capture](https://attack.mitre.org/techniques/T1056/002/)
- [MITRE ATT&CK - T1005 Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK - T1560.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)
- [MITRE ATT&CK - T1041 Exfiltration Over C2](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK - T1027 Obfuscated Files](https://attack.mitre.org/techniques/T1027/)
- [Red Canary 2024 Threat Detection Report - macOS](https://redcanary.com/threat-detection-report/)
- [Elastic Security Labs - AMOS Stealer Analysis](https://www.elastic.co/security-labs/)
- [SentinelOne - Banshee Stealer XProtect Evasion](https://www.sentinelone.com/)
- [Kandji - Cuckoo Stealer Analysis](https://www.kandji.io/)

---

## File Index

| File | Content |
|------|---------|
| `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_detections.kql` | 13 KQL queries for Microsoft Sentinel/Defender |
| `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_sigma_rules.yml` | 13 Sigma rules for SIEM-agnostic detection |
| `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_dr_rules.yaml` | 12 LimaCharlie D&R rules |
| `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_rules.yar` | 9 YARA rules for file scanning |
| `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_elastic_rules.ndjson` | Elasticsearch detection rules |
| `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_hardening.ps1` | Windows hardening script (cross-platform guidance) |
| `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_hardening_macos.sh` | macOS hardening script (primary platform) |
| `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_hardening_linux.sh` | Linux hardening script |
| `3e985e9e-8141-49d3-a23c-6c7f5e3282f5_DEFENSE_GUIDANCE.md` | This comprehensive defense guidance document |
