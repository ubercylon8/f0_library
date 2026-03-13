# Defense Guidance: DPRK BlueNoroff Financial Sector Attack Chain

## Executive Summary

This document provides comprehensive defense guidance for protecting against the **DPRK BlueNoroff Financial Sector Attack Chain**, a multi-stage killchain targeting macOS endpoints in the financial and cryptocurrency sectors. BlueNoroff is a subgroup of the Lazarus Group tasked with generating revenue for the DPRK regime through attacks on financial institutions, cryptocurrency exchanges, and blockchain companies.

| Field | Value |
|-------|-------|
| **Test ID** | 244dfb88-9068-4db4-9fa8-dbc49517f63d |
| **Test Name** | DPRK BlueNoroff Financial Sector Attack Chain |
| **MITRE ATT&CK** | T1553.001, T1543.004, T1059.002, T1555.001, T1056.002, T1071.001, T1573.002, T1071.004, T1041, T1567.002, T1560.001 |
| **Tactics** | Initial Access, Persistence, Credential Access, Command and Control, Exfiltration, Defense Evasion, Collection |
| **Threat Actor** | BlueNoroff/Lazarus (DPRK) |
| **Severity** | CRITICAL |
| **Test Score** | 9.2/10 |
| **Target Platform** | macOS (primary), with cross-platform network-level defenses |
| **Campaigns Modeled** | RustBucket, Hidden Risk, KANDYKORN, TodoSwift, BeaverTail |

---

## Threat Overview

### Attack Description

This test simulates the complete BlueNoroff attack chain across five documented campaigns:

- **RustBucket** (2023-2024): Multi-stage dropper chain (AppleScript -> Objective-C -> Rust) with LaunchAgent persistence at `com.apple.systemupdate`
- **Hidden Risk** (November 2024, SentinelLabs): Abuses `~/.zshenv` for stealth persistence that bypasses macOS Ventura's Login Items notification; uses notarized malware signed with a hijacked Apple Developer ID ("Avantis Regtech Private Limited", team ID 2S8XHJ7948)
- **KANDYKORN** (2023, Elastic Security Labs): Full RAT targeting blockchain engineers using `linkpc.net` dynamic DNS domains for C2
- **TodoSwift** (2024): Swift/SwiftUI dropper leveraging Google Drive URLs for payload delivery and data exfiltration
- **BeaverTail** (2024, Unit 42): Qt framework-based credential stealer delivering InvisibleFerret Python backdoor, targeting crypto developers via fake job interviews

### Attack Flow

```
[Stage 1] Gatekeeper Bypass & Payload Delivery (T1553.001)
    - curl-based download bypasses com.apple.quarantine attribute
    - Notarized malware with hijacked Apple Developer ID
    - xattr -d com.apple.quarantine removes Gatekeeper check
    - Disguised as cryptocurrency trading application
    |
    v
[Stage 2] LaunchAgent Persistence (T1543.004)
    - com.apple.systemupdate.plist LaunchAgent (RustBucket pattern)
    - com.avatar.update.wake.plist LaunchAgent (BeaverTail/InvisibleFerret)
    - ~/.zshenv modification (Hidden Risk -- bypasses Login Items notification)
    - com.apple.security.updateagent LaunchDaemon (root-level persistence)
    |
    v
[Stage 3] Credential Harvesting (T1059.002, T1555.001, T1056.002)
    - osascript fake password dialog (shared AMOS/Banshee/BlueNoroff pattern)
    - dscl -authonly credential validation
    - Keychain dump via security CLI (dump-keychain, find-generic-password)
    - Browser credential extraction (Chrome Login Data + Safe Storage key)
    - Crypto wallet theft: MetaMask vault, Exodus seed, Coinbase Wallet recovery
    - TCC manipulation via tccutil reset
    |
    v
[Stage 4] Multi-Protocol C2 (T1071.001, T1573.002, T1071.004)
    - Sliver mTLS beacon (port 8888, beacon.linkpc.net)
    - HTTPS fallback C2 (app.linkpc.net, cloud.dnx.capital, swissborg.blog)
    - DNS tunneling with base64-encoded subdomain queries (update.linkpc.net)
    - Google Drive payload staging (TodoSwift pattern)
    |
    v
[Stage 5] Financial Data Exfiltration (T1041, T1567.002, T1560.001)
    - Archive compression using AMOS "out.zip" naming pattern (T1560.001)
    - AWS S3 exfiltration with hardcoded credentials (macOS.NotLockBit pattern)
    - Google Drive exfiltration via OAuth token (TodoSwift pattern)
    - HTTP POST exfiltration with hwid/wid/user metadata identifiers
```

---

## MITRE ATT&CK Mapping with Mitigations

### Technique-to-Mitigation Matrix

| Technique | Name | Tactic | Applicable Mitigations |
|-----------|------|--------|----------------------|
| [T1553.001](https://attack.mitre.org/techniques/T1553/001/) | Gatekeeper Bypass | Defense Evasion | [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1017](https://attack.mitre.org/mitigations/M1017/) User Training, [M1045](https://attack.mitre.org/mitigations/M1045/) Code Signing |
| [T1543.004](https://attack.mitre.org/techniques/T1543/004/) | Launch Agent | Persistence | [M1022](https://attack.mitre.org/mitigations/M1022/) Restrict File and Directory Permissions, [M1033](https://attack.mitre.org/mitigations/M1033/) Limit Software Installation, [M1047](https://attack.mitre.org/mitigations/M1047/) Audit |
| [T1059.002](https://attack.mitre.org/techniques/T1059/002/) | AppleScript | Execution | [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1042](https://attack.mitre.org/mitigations/M1042/) Disable or Remove Feature, [M1049](https://attack.mitre.org/mitigations/M1049/) Antivirus/Antimalware |
| [T1555.001](https://attack.mitre.org/techniques/T1555/001/) | Keychain | Credential Access | [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies, [M1026](https://attack.mitre.org/mitigations/M1026/) Privileged Account Management |
| [T1056.002](https://attack.mitre.org/techniques/T1056/002/) | GUI Input Capture | Credential Access | [M1017](https://attack.mitre.org/mitigations/M1017/) User Training |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | C2 | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1037](https://attack.mitre.org/mitigations/M1037/) Filter Network Traffic |
| [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Asymmetric Cryptography | C2 | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1020](https://attack.mitre.org/mitigations/M1020/) SSL/TLS Inspection |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | C2 | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1037](https://attack.mitre.org/mitigations/M1037/) Filter Network Traffic |
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 | Exfiltration | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1057](https://attack.mitre.org/mitigations/M1057/) Data Loss Prevention |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Exfiltration | [M1021](https://attack.mitre.org/mitigations/M1021/) Restrict Web-Based Content |
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Collection | [M1047](https://attack.mitre.org/mitigations/M1047/) Audit |

### Defense-in-Depth Layers

| Layer | Defense Controls | Techniques Addressed |
|-------|-----------------|---------------------|
| **Perimeter / DNS** | DNS sinkhole for linkpc.net, dnx.capital, swissborg.blog; block port 8888 outbound | T1071.001, T1071.004, T1573.002 |
| **Endpoint - Gatekeeper** | SIP enabled, Gatekeeper enforced, quarantine attribute monitoring | T1553.001 |
| **Endpoint - Persistence** | LaunchAgent/LaunchDaemon monitoring, .zshenv file integrity | T1543.004 |
| **Endpoint - Credential** | Keychain access monitoring, osascript restriction, TCC enforcement | T1059.002, T1555.001, T1056.002 |
| **Network - Exfiltration** | DLP for archive uploads, cloud storage access control (CASB), AWS API monitoring | T1041, T1567.002, T1560.001 |
| **User Awareness** | Training on fake cryptocurrency applications, social engineering via job interviews | T1056.002, T1553.001 |

---

## Detection Strategy

### Detection Priority Matrix

| Detection Layer | Priority | Confidence | Rationale |
|-----------------|----------|------------|-----------|
| DNS C2 Indicators (linkpc.net) | P1 | CRITICAL | High-fidelity DPRK BlueNoroff/KANDYKORN indicator; linkpc.net is a dynamic DNS provider heavily abused by Lazarus Group |
| LaunchAgent Persistence with com.apple.* label | P1 | HIGH | Non-Apple processes creating com.apple.* plist files is inherently suspicious; campaign-specific labels known |
| osascript Credential Phishing (display dialog + hidden answer) | P1 | HIGH | Technique-inherent behavior shared by AMOS, Banshee, and BlueNoroff stealers |
| Keychain Credential Dumping (security CLI) | P2 | HIGH | Common across all macOS credential stealers; few legitimate use cases for bulk dump |
| .zshenv Modification by Non-Editor | P2 | HIGH | Rarely modified by applications; Hidden Risk campaign signature |
| Crypto Wallet Data Access by Non-Browser | P2 | HIGH | Non-browser process accessing MetaMask/Exodus/Coinbase extension storage is anomalous |
| Gatekeeper Bypass (xattr quarantine removal) | P2 | HIGH | xattr -d com.apple.quarantine from non-user-initiated context is suspicious |
| Cloud Storage Exfiltration (S3/Google Drive) | P3 | MEDIUM | Requires context filtering; legitimate cloud usage must be baselined |
| DNS Tunneling Patterns (long subdomain labels) | P3 | MEDIUM | Volume and entropy-based detection; requires tuning |
| Archive Creation in Staging Directories | P3 | MEDIUM | Common operation; suspicious when combined with credential staging artifacts |

### Detection Files Reference

| File | Purpose | Format | Rule Count |
|------|---------|--------|------------|
| `244dfb88-9068-4db4-9fa8-dbc49517f63d_detections.kql` | Microsoft Sentinel/Defender queries | KQL | 16 queries |
| `244dfb88-9068-4db4-9fa8-dbc49517f63d_rules.yar` | File and memory content detection | YARA | 10 rules |
| `244dfb88-9068-4db4-9fa8-dbc49517f63d_dr_rules.yaml` | LimaCharlie D&R rules | YAML | 7 rules |
| `244dfb88-9068-4db4-9fa8-dbc49517f63d_sigma_rules.yml` | Platform-agnostic detection | Sigma | 13 rules |
| `244dfb88-9068-4db4-9fa8-dbc49517f63d_elastic_rules.ndjson` | Elastic Security SIEM rules | NDJSON | 10 rules |

### Key Detection Concepts

All detection rules in the files above follow the **Technique-Focused Detection Principle**: they detect the underlying macOS attack technique behaviors, NOT the F0RT1KA testing framework. They will catch real-world attackers using the same persistence, credential theft, C2, and exfiltration techniques with their own custom tooling.

**What the rules detect (technique artifacts):**
- osascript execution with `display dialog` and `hidden answer` parameters
- `security` CLI used with `dump-keychain`, `find-generic-password`, `find-internet-password`
- Plist file creation in `~/Library/LaunchAgents/` or `/Library/LaunchDaemons/` with `com.apple.*` labels by non-Apple processes
- `.zshenv` file modification by non-editor processes
- DNS queries to `*.linkpc.net`, `*.dnx.capital`, `*.swissborg.blog`
- `xattr -d com.apple.quarantine` execution
- Outbound connections on port 8888 from non-browser processes
- Archive creation followed by cloud upload activity

**What the rules do NOT detect (test framework artifacts):**
- F0RT1KA binary names, UUIDs, or paths (`/tmp/F0/`, `c:\F0\`)
- Test orchestrator patterns or stage binary naming
- Test logging JSON files or execution metadata

---

## Hardening Guidance

### Overview

Hardening scripts are provided for three platforms to address the BlueNoroff attack chain in mixed environments. Since BlueNoroff primarily targets macOS, the macOS script is the most comprehensive.

| Script | Platform | Focus Areas |
|--------|----------|-------------|
| `244dfb88-9068-4db4-9fa8-dbc49517f63d_hardening.ps1` | Windows | DNS/network-level C2 blocking, Credential Guard, audit logging, cloud exfiltration monitoring |
| `244dfb88-9068-4db4-9fa8-dbc49517f63d_hardening_macos.sh` | macOS | Gatekeeper enforcement, LaunchAgent monitoring, .zshenv protection, Keychain hardening, osascript restriction, C2 domain blocking, crypto wallet protection |
| `244dfb88-9068-4db4-9fa8-dbc49517f63d_hardening_linux.sh` | Linux | DNS blocking, network egress filtering, credential store hardening, audit logging, cron/systemd persistence monitoring |

All scripts support three modes:
- **apply** -- Apply hardening settings (default)
- **undo** -- Revert hardening settings
- **check** -- Verify current hardening status

### macOS-Specific Hardening (Primary Target Platform)

#### 1. Gatekeeper & Code Signing Enforcement (T1553.001)

| Setting | Value |
|---------|-------|
| **Mitigation** | [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1045](https://attack.mitre.org/mitigations/M1045/) Code Signing |
| **SIP (System Integrity Protection)** | Must be enabled (csrutil enable in Recovery Mode) |
| **Gatekeeper** | Must be enabled (spctl --master-enable) |
| **Quarantine Enforcement** | LSQuarantine must not be disabled |
| **Impact** | Low -- standard macOS security posture |

**Verification:**
```bash
csrutil status           # Should show "enabled"
spctl --status           # Should show "assessments enabled"
```

**User Training:** Educate users (especially blockchain engineers and crypto developers) to NEVER run `xattr -cr` on downloaded applications. This is the primary social engineering vector that BlueNoroff uses to bypass Gatekeeper.

#### 2. LaunchAgent/LaunchDaemon Monitoring (T1543.004)

| Setting | Value |
|---------|-------|
| **Mitigation** | [M1022](https://attack.mitre.org/mitigations/M1022/) Restrict File and Directory Permissions |
| **Monitor Paths** | `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/` |
| **Alert On** | New plist files with `com.apple.*` labels from non-Apple processes |
| **Known Malicious Labels** | `com.apple.systemupdate`, `com.avatar.update.wake`, `com.apple.security.updateagent` |
| **Impact** | Low -- monitoring only |

**Protection Script Excerpt:**
```bash
# Immutable flag on LaunchAgents directory (prevents unauthorized additions)
# WARNING: Also prevents legitimate software from adding agents
sudo chflags uchg ~/Library/LaunchAgents/
# To undo: sudo chflags nouchg ~/Library/LaunchAgents/
```

#### 3. .zshenv File Protection (T1543.004 - Hidden Risk)

| Setting | Value |
|---------|-------|
| **Mitigation** | [M1022](https://attack.mitre.org/mitigations/M1022/) Restrict File and Directory Permissions |
| **Critical Insight** | `.zshenv` executes for EVERY zsh session and does NOT trigger macOS Ventura Login Items notification |
| **Protection** | Set immutable flag, monitor for modifications, audit contents regularly |
| **Impact** | Medium -- may affect legitimate shell customization |

**Protection:**
```bash
# If .zshenv is not needed, create an empty one with immutable flag
touch ~/.zshenv
chflags uchg ~/.zshenv
# To undo: chflags nouchg ~/.zshenv
```

#### 4. osascript Restriction (T1059.002, T1056.002)

| Setting | Value |
|---------|-------|
| **Mitigation** | [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1042](https://attack.mitre.org/mitigations/M1042/) Disable or Remove Feature |
| **TCC Enforcement** | Require explicit Accessibility and AppleEvents permissions |
| **MDM Configuration** | Deploy a profile restricting osascript to approved applications |
| **Impact** | Medium -- may affect automation workflows that use AppleScript |

#### 5. Keychain Access Hardening (T1555.001)

| Setting | Value |
|---------|-------|
| **Mitigation** | [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies, [M1026](https://attack.mitre.org/mitigations/M1026/) Privileged Account Management |
| **Lock Timeout** | Set Keychain auto-lock to 5 minutes of inactivity |
| **Require Password** | Keychain should require password for each access (not "Always Allow") |
| **Impact** | Medium -- users prompted more frequently for Keychain password |

**Configuration:**
```bash
# Set Keychain to lock after 5 minutes
security set-keychain-settings -t 300 -l ~/Library/Keychains/login.keychain-db
```

#### 6. C2 Domain Blocking (T1071.001, T1071.004)

| Setting | Value |
|---------|-------|
| **Mitigation** | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1037](https://attack.mitre.org/mitigations/M1037/) Filter Network Traffic |
| **Block Domains** | `linkpc.net`, `dnx.capital`, `swissborg.blog`, `on-offx.com`, `tokenview.xyz` |
| **Block Port** | Outbound TCP 8888 (Sliver mTLS default) |
| **Impact** | Low -- these are known malicious or abused domains |

#### 7. Crypto Wallet Protection

| Setting | Value |
|---------|-------|
| **Targets** | MetaMask, Exodus, Coinbase Wallet browser extensions |
| **Protection** | File integrity monitoring on wallet data directories |
| **Alert On** | Non-browser process accessing extension Local Storage paths |
| **Impact** | Low -- monitoring only |

**Key Paths to Monitor:**
```
~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn  (MetaMask)
~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad  (Coinbase Wallet)
~/Library/Application Support/Exodus/exodus.wallet
```

### Cross-Platform Network Hardening

These controls apply to all platforms (Windows, macOS, Linux) to block BlueNoroff C2 infrastructure at the network level.

#### DNS-Level Blocking

Add the following domains to your DNS sinkhole, firewall blocklist, or threat intelligence feed:

| Domain | Associated Campaign | Confidence |
|--------|---------------------|------------|
| `*.linkpc.net` | KANDYKORN, Hidden Risk, Sliver C2 | CRITICAL |
| `*.dnx.capital` | RustBucket | HIGH |
| `*.swissborg.blog` | KANDYKORN | HIGH |
| `*.on-offx.com` | BlueNoroff general infrastructure | HIGH |
| `*.tokenview.xyz` | BlueNoroff financial targeting | MEDIUM |

#### Port-Level Blocking

| Port | Protocol | Direction | Rationale |
|------|----------|-----------|-----------|
| 8888 | TCP | Outbound | Sliver C2 mTLS default port |

#### Cloud Storage Monitoring

| Service | Indicator | Priority |
|---------|-----------|----------|
| AWS S3 | Non-approved process uploading to S3 buckets | HIGH |
| Google Drive | Non-browser process using googleapis.com/upload/drive | HIGH |
| Google Drive | Direct download links (`drive.google.com/uc?export=download`) from non-browser | MEDIUM |

---

## Incident Response Playbook

### Quick Reference

| Field | Value |
|-------|-------|
| **Test ID** | 244dfb88-9068-4db4-9fa8-dbc49517f63d |
| **Test Name** | DPRK BlueNoroff Financial Sector Attack Chain |
| **MITRE ATT&CK** | T1553.001, T1543.004, T1059.002, T1555.001, T1056.002, T1071.001, T1573.002, T1071.004, T1041, T1567.002, T1560.001 |
| **Severity** | Critical |
| **Estimated Response Time** | 2-4 hours |
| **Primary Indicators** | LaunchAgent plists with com.apple.* labels, .zshenv modification, Keychain dump activity, DNS queries to linkpc.net |

---

### 1. Detection Triggers

#### Alert Conditions

| Detection Name | Trigger Criteria | Confidence | Priority |
|----------------|------------------|------------|----------|
| BlueNoroff C2 DNS | DNS query to `*.linkpc.net` or `*.dnx.capital` | Critical | P1 |
| LaunchAgent Masquerade | `com.apple.*` plist created by non-Apple process in LaunchAgents | High | P1 |
| osascript Credential Phishing | `osascript` with `display dialog` and `hidden answer` | High | P1 |
| Keychain Credential Dump | `security dump-keychain` or `find-generic-password -g` | High | P2 |
| .zshenv Persistence | `~/.zshenv` modified by non-editor process | High | P2 |
| Crypto Wallet Access | Non-browser access to MetaMask/Exodus/Coinbase extension paths | High | P2 |
| Gatekeeper Bypass | `xattr -d com.apple.quarantine` execution | High | P2 |
| Sliver mTLS Port | Outbound TCP connection to port 8888 from non-browser | Medium | P3 |

#### Initial Triage Questions

1. Is this activity from a known F0RT1KA security test execution or unexpected?
2. Is the affected endpoint used by a blockchain engineer, crypto developer, or financial sector employee? (BlueNoroff targets these roles specifically)
3. What is the scope -- single host or multiple hosts showing indicators?
4. Has the user recently installed any cryptocurrency-related applications or attended a job interview?
5. What is the timeline -- when did the first indicator appear?

---

### 2. Containment

#### Immediate Actions (First 15 minutes)

- [ ] **Isolate the affected Mac**
  ```bash
  # Block all outbound network traffic (except management)
  sudo pfctl -E
  echo "block out all" | sudo pfctl -f -

  # Alternative: disable Wi-Fi and Ethernet
  networksetup -setairportpower en0 off
  ```

- [ ] **Terminate suspicious processes**
  ```bash
  # Kill osascript processes (credential phishing)
  pkill -9 osascript

  # Kill any processes connecting to known C2 domains
  lsof -i | grep -iE "linkpc|dnx\.capital|swissborg" | awk '{print $2}' | xargs kill -9 2>/dev/null

  # Kill processes on port 8888 (Sliver mTLS)
  lsof -i :8888 | awk 'NR>1 {print $2}' | xargs kill -9 2>/dev/null
  ```

- [ ] **Unload malicious LaunchAgents immediately**
  ```bash
  launchctl unload ~/Library/LaunchAgents/com.apple.systemupdate.plist 2>/dev/null
  launchctl unload ~/Library/LaunchAgents/com.avatar.update.wake.plist 2>/dev/null
  sudo launchctl unload /Library/LaunchDaemons/com.apple.security.updateagent.plist 2>/dev/null
  ```

- [ ] **Preserve volatile evidence**
  ```bash
  mkdir -p /tmp/ir_evidence_$(date +%Y%m%d)
  IR_DIR="/tmp/ir_evidence_$(date +%Y%m%d)"

  # Capture running processes with full command lines
  ps auxww > "$IR_DIR/processes_$(date +%Y%m%d_%H%M%S).txt"

  # Capture network connections
  lsof -i -n -P > "$IR_DIR/connections_$(date +%Y%m%d_%H%M%S).txt"
  netstat -anv > "$IR_DIR/netstat_$(date +%Y%m%d_%H%M%S).txt"

  # Capture LaunchAgents and LaunchDaemons
  ls -la ~/Library/LaunchAgents/ > "$IR_DIR/user_launchagents.txt"
  ls -la /Library/LaunchAgents/ > "$IR_DIR/system_launchagents.txt" 2>/dev/null
  sudo ls -la /Library/LaunchDaemons/ > "$IR_DIR/launchdaemons.txt" 2>/dev/null

  # Capture .zshenv contents
  cat ~/.zshenv > "$IR_DIR/zshenv_contents.txt" 2>/dev/null

  # Capture DNS cache
  sudo dscacheutil -cachedump > "$IR_DIR/dns_cache.txt" 2>/dev/null
  ```

---

### 3. Evidence Collection

#### Critical Artifacts

| Artifact | Location | Collection Command | Priority |
|----------|----------|-------------------|----------|
| LaunchAgent plists | `~/Library/LaunchAgents/` | `cp -r ~/Library/LaunchAgents/ $IR_DIR/launchagents/` | P1 |
| LaunchDaemon plists | `/Library/LaunchDaemons/` | `sudo cp -r /Library/LaunchDaemons/ $IR_DIR/launchdaemons/` | P1 |
| .zshenv file | `~/.zshenv` | `cp ~/.zshenv $IR_DIR/zshenv_copy` | P1 |
| .zshenv backup | `~/.zshenv.bak` | `cp ~/.zshenv.bak $IR_DIR/zshenv_backup` | P2 |
| Keychain databases | `~/Library/Keychains/` | `cp -r ~/Library/Keychains/ $IR_DIR/keychains/` | P1 |
| Hidden payloads | `/Users/Shared/.system/`, `/Users/Shared/.invisible_ferret/` | `cp -r /Users/Shared/.[a-z]* $IR_DIR/shared_hidden/` | P1 |
| Root persistence | `/Library/Application Support/.security/` | `sudo cp -r "/Library/Application Support/.security/" $IR_DIR/` | P1 |
| DNS resolution log | System unified log | `log show --predicate 'subsystem == "com.apple.mdnsresponder"' --last 4h > $IR_DIR/dns_log.txt` | P2 |
| System log | Unified log | `log show --last 4h > $IR_DIR/unified_log.txt` | P2 |
| Chrome Login Data | `~/Library/Application Support/Google/Chrome/Default/Login Data` | `cp "$src" $IR_DIR/` | P2 |
| MetaMask vault | Chrome extension storage | See crypto wallet paths above | P2 |
| Exodus wallet | `~/Library/Application Support/Exodus/` | `cp -r "$src" $IR_DIR/` | P2 |

#### Memory Acquisition

```bash
# Using osxpmem (if available)
sudo ./osxpmem -o $IR_DIR/memory.aff4

# Alternative: capture process memory for suspicious PIDs
lldb -p <PID> -o "process save-core $IR_DIR/proc_<PID>.core" -o "quit"
```

#### Timeline Generation

```bash
# Export unified log for timeline analysis
log show --last 24h --style json > $IR_DIR/unified_log_24h.json

# Export specific security-relevant subsystems
log show --predicate 'subsystem == "com.apple.securityd" OR subsystem == "com.apple.xpc"' --last 24h > $IR_DIR/security_log.txt

# List recently modified files
find / -mtime -1 -type f 2>/dev/null > $IR_DIR/recently_modified_files.txt
```

---

### 4. Eradication

#### Remove Persistence Mechanisms

```bash
# Remove BlueNoroff LaunchAgents (AFTER evidence collection)
rm -f ~/Library/LaunchAgents/com.apple.systemupdate.plist
rm -f ~/Library/LaunchAgents/com.avatar.update.wake.plist
sudo rm -f /Library/LaunchDaemons/com.apple.security.updateagent.plist

# Restore .zshenv from backup or remove
if [[ -f ~/.zshenv.bak ]]; then
    cp ~/.zshenv.bak ~/.zshenv
else
    rm -f ~/.zshenv
fi
```

#### Remove Hidden Payloads

```bash
# Remove hidden payload directories
rm -rf /Users/Shared/.system/
rm -rf /Users/Shared/.invisible_ferret/
sudo rm -rf "/Library/Application Support/.security/"

# Remove any staging directories
rm -rf /tmp/credential_staging/
rm -rf /tmp/c2_simulation/
rm -rf /tmp/exfil_staging/
```

#### Credential Rotation (CRITICAL for BlueNoroff)

Since BlueNoroff targets cryptocurrency assets, credential rotation is essential:

```
1. Reset macOS user password immediately
2. Reset Keychain password (create new login keychain)
3. Change all browser-saved passwords (especially crypto exchange accounts)
4. Rotate MetaMask wallet seed phrase (transfer funds to new wallet)
5. Rotate Exodus wallet seed phrase
6. Rotate Coinbase Wallet recovery phrase
7. Revoke all active API keys for crypto exchanges
8. Enable 2FA on all crypto accounts (hardware key preferred)
9. Revoke any Apple Developer ID sessions
10. Rotate Chrome Safe Storage encryption
```

#### Network Cleanup

```bash
# Flush DNS cache
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Block C2 domains in local hosts file (temporary measure)
echo "0.0.0.0 linkpc.net" | sudo tee -a /etc/hosts
echo "0.0.0.0 dnx.capital" | sudo tee -a /etc/hosts
echo "0.0.0.0 swissborg.blog" | sudo tee -a /etc/hosts
```

---

### 5. Recovery

#### System Restoration Checklist

- [ ] Verify all malicious LaunchAgents/LaunchDaemons removed
- [ ] Verify .zshenv is clean or absent
- [ ] Verify no hidden payloads in /Users/Shared/
- [ ] Verify no persistence in /Library/Application Support/
- [ ] Restore network connectivity (remove pfctl rules)
- [ ] Apply hardening script (`sudo ./244dfb88_hardening_macos.sh apply`)
- [ ] Install or update EDR agent
- [ ] Re-enable network after validation

#### Validation Commands

```bash
# Verify no persistence remains
echo "--- LaunchAgent Check ---"
launchctl list | grep -iE "apple\.system|avatar|security\.update"
echo "--- .zshenv Check ---"
cat ~/.zshenv 2>/dev/null || echo ".zshenv does not exist"
echo "--- LaunchAgents Directory ---"
ls -la ~/Library/LaunchAgents/
echo "--- LaunchDaemons Directory ---"
sudo ls -la /Library/LaunchDaemons/
echo "--- Hidden Directories in /Users/Shared ---"
ls -la /Users/Shared/.[a-z]* 2>/dev/null || echo "No hidden dirs"

# Verify network connections clean
echo "--- Network Check ---"
lsof -i | grep -iE "linkpc|8888|dnx\.capital"
nslookup beacon.linkpc.net  # Should fail or return sinkhole

# Verify Keychain integrity
echo "--- Keychain Check ---"
security list-keychains
```

---

### 6. Post-Incident

#### Lessons Learned Questions

1. How was the attack initially detected? Which detection rule fired first?
2. What was the detection-to-containment time? Was it within the 15-minute target?
3. Was the user a high-value target (blockchain engineer, crypto developer, financial analyst)?
4. How did the initial payload arrive -- social engineering, fake application, job interview?
5. Were any cryptocurrency funds actually transferred before containment?
6. What detection gaps were identified during the investigation?
7. Were the hardening scripts deployed before or after the incident?

#### Recommended Improvements

| Area | Recommendation | Priority | Effort |
|------|----------------|----------|--------|
| **Detection** | Deploy EDR with macOS-specific LaunchAgent and .zshenv monitoring | Critical | Medium |
| **Detection** | Add DNS sinkhole for linkpc.net and related dynamic DNS providers | Critical | Low |
| **Detection** | Monitor osascript execution with behavioral rules | High | Low |
| **Prevention** | Deploy MDM profile restricting osascript to approved applications | High | Medium |
| **Prevention** | Implement file integrity monitoring on LaunchAgent directories | High | Medium |
| **Prevention** | Block outbound port 8888 at network firewall | High | Low |
| **Response** | Pre-stage memory acquisition tools on macOS endpoints | Medium | Low |
| **Response** | Create automated containment script for macOS isolation | Medium | Medium |
| **User Training** | Targeted training for crypto/blockchain teams on DPRK social engineering | High | Medium |
| **Architecture** | Implement CASB to control cloud storage uploads from endpoints | Medium | High |

---

## References

### MITRE ATT&CK

- [T1553.001 - Subvert Trust Controls: Gatekeeper Bypass](https://attack.mitre.org/techniques/T1553/001/)
- [T1543.004 - Create or Modify System Process: Launch Agent](https://attack.mitre.org/techniques/T1543/004/)
- [T1059.002 - Command and Scripting Interpreter: AppleScript](https://attack.mitre.org/techniques/T1059/002/)
- [T1555.001 - Credentials from Password Stores: Keychain](https://attack.mitre.org/techniques/T1555/001/)
- [T1056.002 - Input Capture: GUI Input Capture](https://attack.mitre.org/techniques/T1056/002/)
- [T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [T1573.002 - Encrypted Channel: Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002/)
- [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [T1560.001 - Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)

### Threat Intelligence

- [SentinelLabs - BlueNoroff Hidden Risk Campaign (November 2024)](https://www.sentinelone.com/labs/bluenoroff-hidden-risk/)
- [Jamf Threat Labs - RustBucket Analysis](https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/)
- [Elastic Security Labs - KANDYKORN Analysis](https://www.elastic.co/security-labs/elastic-catches-dprk-passing-out-kandykorn)
- [Unit 42 - BeaverTail and InvisibleFerret](https://unit42.paloaltonetworks.com/north-korean-threat-actors-luring-tech-job-seekers-as-fake-recruiters/)
- [SentinelOne - macOS.NotLockBit Analysis](https://www.sentinelone.com/blog/macos-notlockbit-evolving-macos-threat/)

### Mitigations

- [M1031 - Network Intrusion Prevention](https://attack.mitre.org/mitigations/M1031/)
- [M1037 - Filter Network Traffic](https://attack.mitre.org/mitigations/M1037/)
- [M1038 - Execution Prevention](https://attack.mitre.org/mitigations/M1038/)
- [M1022 - Restrict File and Directory Permissions](https://attack.mitre.org/mitigations/M1022/)
- [M1045 - Code Signing](https://attack.mitre.org/mitigations/M1045/)
- [M1027 - Password Policies](https://attack.mitre.org/mitigations/M1027/)
- [M1017 - User Training](https://attack.mitre.org/mitigations/M1017/)
- [M1057 - Data Loss Prevention](https://attack.mitre.org/mitigations/M1057/)
