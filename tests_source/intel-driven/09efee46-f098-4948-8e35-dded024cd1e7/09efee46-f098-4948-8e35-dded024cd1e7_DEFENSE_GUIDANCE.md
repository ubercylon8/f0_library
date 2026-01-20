# Defense Guidance: Sliver C2 Client Detection

## Executive Summary

This document provides comprehensive defense guidance for protecting against the **Sliver C2 Client Detection** test. Sliver is a legitimate open-source, cross-platform adversary emulation/red team framework that can be abused by threat actors for command and control operations. This test validates endpoint security capabilities to detect and prevent C2 framework deployments.

| Field | Value |
|-------|-------|
| **Test ID** | 09efee46-f098-4948-8e35-dded024cd1e7 |
| **Test Name** | Sliver C2 Client Detection |
| **MITRE ATT&CK** | [T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/) |
| **Tactic** | Command and Control (TA0011) |
| **Severity** | HIGH |
| **Test Score** | 7.5/10 |

---

## Threat Overview

### Attack Description

The Sliver C2 framework represents a significant threat to enterprise security. Unlike traditional malware, Sliver:

- **Is open-source and actively maintained** - Available on GitHub with regular updates
- **Supports multiple C2 protocols** - HTTP, HTTPS, DNS, mTLS, TCP
- **Cross-platform** - Compiled in Go, runs on Windows, Linux, macOS
- **Used by both red teams and threat actors** - Legitimate tool abused for malicious purposes
- **Feature-rich** - Lateral movement, process injection, credential harvesting

### Attack Flow

```
Real-World Attack Chain:

[1] Initial Access (Phishing, Exploit, etc.)
    |
    v
[2] Drop Sliver implant to user-writable directory
    (%TEMP%, %APPDATA%, Downloads, etc.)
    |
    v
[3] Execute Sliver implant
    |
    v
[4] Establish C2 communication (mTLS, HTTPS, DNS, WireGuard)
    |
    v
[5] Receive operator commands
    |
    v
[6] Execute post-exploitation modules
```

### Real-World Context

Sliver has been observed in use by:

- **APT groups** - Used as an alternative to Cobalt Strike after increased detection
- **Ransomware operators** - Employed for initial access and lateral movement
- **Red teams** - Legitimate security testing tool
- **Criminal threat actors** - Free alternative to commercial C2 frameworks

---

## MITRE ATT&CK Mapping

### Technique Details

| Field | Value |
|-------|-------|
| **Technique ID** | T1219 |
| **Technique Name** | Remote Access Software |
| **Tactic** | Command and Control (TA0011) |
| **Platforms** | Windows, Linux, macOS |
| **Permissions Required** | User |
| **Data Sources** | Process, Network Traffic, File |

### Applicable Mitigations

| M-Code | Mitigation | Implementation |
|--------|------------|----------------|
| **M1042** | Disable or Remove Feature or Program | Disable unnecessary remote access capabilities |
| **M1038** | Execution Prevention | Block untrusted executables via AppLocker/WDAC |
| **M1037** | Filter Network Traffic | Block known C2 domains and suspicious outbound traffic |
| **M1031** | Network Intrusion Prevention | Deploy NIDS with C2 framework signatures |

---

## Detection Strategy

### Detection Priority Matrix

| Detection Layer | Priority | Confidence | Notes |
|-----------------|----------|------------|-------|
| File Signature Detection | P1 | HIGH | Known Sliver binary signatures |
| Behavioral Analysis | P1 | HIGH | C2 tool execution patterns |
| Process Creation Monitoring | P2 | MEDIUM-HIGH | Suspicious process chains |
| Network Connection Analysis | P2 | MEDIUM | C2 beaconing patterns |
| File System Monitoring | P2 | MEDIUM | File drops in suspicious locations |

### Detection Files

| File | Purpose | Format |
|------|---------|--------|
| `09efee46-f098-4948-8e35-dded024cd1e7_detections.kql` | Microsoft Sentinel/Defender queries | KQL |
| `09efee46-f098-4948-8e35-dded024cd1e7_rules.yar` | File/memory detection | YARA |
| `09efee46-f098-4948-8e35-dded024cd1e7_dr_rules.yaml` | LimaCharlie D&R rules | YAML |

---

## Detection Rules Summary

### KQL Queries (Microsoft Sentinel/Defender)

#### 1. Sliver C2 Client Binary Detection
**Confidence:** HIGH | **Severity:** Critical

Detects Sliver C2 client binary execution or file creation based on known signatures and behavioral patterns.

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "sliver_client.exe"
    or FileName matches regex @"(?i)sliver.*\.exe"
    or ProcessCommandLine has_any ("sliver", "--mtls", "--wg", "--dns", "--http")
```

#### 2. C2 Framework Binary Drop Detection
**Confidence:** HIGH | **Severity:** High

Detects file creation of known C2 framework binaries in monitored directories.

#### 3. Suspicious Go Binary Execution
**Confidence:** MEDIUM | **Severity:** Medium

Detects Go-compiled binaries with C2 framework characteristics.

#### 4. C2 Beaconing Pattern Detection
**Confidence:** MEDIUM-HIGH | **Severity:** High

Detects network beaconing patterns consistent with C2 communication.

#### 5. Combined Behavioral Detection
**Confidence:** HIGH | **Severity:** Critical

Correlates multiple indicators for high-confidence C2 detection.

### YARA Rules

| Rule Name | Purpose | Confidence |
|-----------|---------|------------|
| `Sliver_C2_Client_Generic` | Generic Sliver client detection | HIGH |
| `Sliver_Implant_Strings` | Sliver-specific string patterns | HIGH |
| `Go_C2_Framework_Generic` | Go-compiled C2 frameworks | MEDIUM |
| `C2_Framework_Network_Strings` | Common C2 network indicators | MEDIUM |
| `Sliver_PDB_Artifact` | Sliver build artifacts | HIGH |

### LimaCharlie D&R Rules

| Rule Name | Trigger | Confidence |
|-----------|---------|------------|
| `sliver-c2-client-execution` | NEW_PROCESS matching Sliver patterns | HIGH |
| `c2-binary-file-drop` | FILE_CREATE in monitored paths | HIGH |
| `suspicious-go-binary` | Go binary characteristics | MEDIUM |
| `c2-network-beaconing` | Periodic network connections | MEDIUM |

---

## Hardening Guidance

### Quick Implementation

Run the provided PowerShell hardening script with Administrator privileges:

```powershell
# Apply all hardening settings
.\09efee46-f098-4948-8e35-dded024cd1e7_hardening.ps1

# Preview changes without applying
.\09efee46-f098-4948-8e35-dded024cd1e7_hardening.ps1 -WhatIf

# Revert changes
.\09efee46-f098-4948-8e35-dded024cd1e7_hardening.ps1 -Undo
```

### Hardening Components

#### 1. Application Allowlisting (M1038)

**Purpose:** Prevent unauthorized executable from running

**Implementation:**
```powershell
# Enable Windows Defender Application Control (WDAC)
# Or AppLocker for environments without WDAC support

# Block executables from common attacker drop locations
$blockPaths = @(
    "$env:TEMP\*",
    "$env:APPDATA\*",
    "$env:LOCALAPPDATA\Temp\*",
    "$env:USERPROFILE\Downloads\*",
    "$env:PUBLIC\*"
)
foreach ($path in $blockPaths) {
    New-AppLockerPolicy -RuleType Path -Deny -Path $path
}
```

**Key Controls:**
- Block executables from user-writable directories (%TEMP%, %APPDATA%, Downloads)
- Allow only signed, trusted applications
- Implement deny-by-default policies

#### 2. Network Filtering (M1037)

**Purpose:** Block C2 communications

**Implementation:**
```powershell
# Block common C2 ports (adjust based on your environment)
New-NetFirewallRule -DisplayName "Block Sliver mTLS" -Direction Outbound -Action Block -Protocol TCP -RemotePort 8888

# Enable outbound connection logging
Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True
```

**Key Controls:**
- Monitor and restrict outbound connections
- Block connections to known malicious infrastructure
- Implement web filtering/proxy inspection

#### 3. Endpoint Detection (M1031)

**Purpose:** Detect C2 activity at the endpoint

**Key Controls:**
- Enable EDR with behavioral analysis
- Configure signature updates for C2 frameworks
- Monitor process creation with command line logging

#### 4. File System Monitoring

**Purpose:** Detect and quarantine malicious binaries

```powershell
# Enable Windows Defender Real-Time Protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable cloud-delivered protection
Set-MpPreference -MAPSReporting Advanced

# Enable signature updates
Update-MpSignature
```

### GPO Deployment

For enterprise deployment via Group Policy:

**Computer Configuration > Windows Settings > Security Settings:**

| Setting | Path | Value |
|---------|------|-------|
| Application Control | Software Restriction Policies | Block unsigned executables |
| Firewall | Windows Firewall | Log blocked connections |
| Defender | Real-Time Protection | Enabled |

---

## Incident Response Playbook

### Quick Reference

| Field | Value |
|-------|-------|
| **Test ID** | 09efee46-f098-4948-8e35-dded024cd1e7 |
| **MITRE ATT&CK** | T1219 |
| **Severity** | HIGH |
| **Estimated Response Time** | 30-60 minutes |

### 1. Detection Triggers

| Alert Name | Trigger Criteria | Priority |
|------------|------------------|----------|
| Sliver Binary Detection | Known Sliver signatures detected | P1 |
| C2 Tool Execution | C2 framework binary executed | P1 |
| Suspicious Binary in User-Writable Dir | File creation in %TEMP%, %APPDATA%, Downloads | P2 |
| Go Binary with C2 Patterns | Behavioral indicators present | P2 |

### 2. Initial Triage (First 5 minutes)

- [ ] **Verify alert is not a scheduled test** (check for F0RT1KA framework indicators)
- [ ] **Determine scope** - Single host or multiple?
- [ ] **Identify user context** - What account executed the binary?
- [ ] **Check timeline** - When did activity begin?

**Triage Questions:**
1. Is this a scheduled security test or authorized red team exercise?
2. What directory was the binary dropped to? (Common: %TEMP%, %APPDATA%, Downloads)
3. What is the parent process that dropped/executed the binary?
4. Are there any network connections from the process (check for C2 beaconing)?

### 3. Containment (15-30 minutes)

#### Immediate Actions

- [ ] **Isolate affected host(s)**
```powershell
# Network isolation via Windows Firewall
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# Or use EDR isolation capability if available
```

- [ ] **Terminate malicious processes**
```powershell
# Kill Sliver client process by name
Get-Process | Where-Object {$_.ProcessName -match "sliver"} | Stop-Process -Force

# Kill suspicious processes from user-writable locations
$suspiciousPaths = @("*\AppData\*", "*\Temp\*", "*\Downloads\*", "*\Public\*")
foreach ($path in $suspiciousPaths) {
    Get-Process | Where-Object {$_.Path -like $path -and $_.ProcessName -notmatch "(chrome|firefox|edge)"} | Stop-Process -Force
}
```

- [ ] **Quarantine the binary**
```powershell
# Move binary to quarantine folder for analysis
$quarantine = "C:\IR\Quarantine\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $quarantine -ItemType Directory -Force

# Quarantine from common attacker drop locations (adjust path as needed)
$suspectedPath = "C:\Users\$env:USERNAME\AppData\Local\Temp\sliver_client.exe"
if (Test-Path $suspectedPath) {
    Move-Item -Path $suspectedPath -Destination $quarantine -Force
}
```

- [ ] **Preserve volatile evidence**
```powershell
# Create IR folder
$irPath = "C:\IR\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $irPath -ItemType Directory -Force

# Capture running processes
Get-Process | Export-Csv "$irPath\processes.csv" -NoTypeInformation

# Capture network connections
Get-NetTCPConnection | Export-Csv "$irPath\connections.csv" -NoTypeInformation

# Capture DNS cache
Get-DnsClientCache | Export-Csv "$irPath\dns_cache.csv" -NoTypeInformation
```

### 4. Evidence Collection

#### Critical Artifacts

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Sliver binary | User-writable dirs (%TEMP%, %APPDATA%) | `Copy-Item "$env:TEMP\sliver*" "C:\IR\artifacts\"` |
| Process memory | Memory | `procdump -ma <pid> C:\IR\` |
| Event logs | System | `wevtutil epl Security C:\IR\Security.evtx` |
| Prefetch files | `C:\Windows\Prefetch\` | `Copy-Item "C:\Windows\Prefetch\SLIVER*" "C:\IR\Prefetch\"` |
| Network logs | Firewall | `Copy-Item %SystemRoot%\System32\LogFiles\Firewall\* C:\IR\` |

#### Timeline Generation
```powershell
# Export relevant event logs
$logs = @("Security", "System", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational")
foreach ($log in $logs) {
    try {
        wevtutil epl $log "C:\IR\$($log -replace '/','-').evtx"
    } catch {
        Write-Warning "Could not export $log"
    }
}

# Query process creation events
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4688
    StartTime = (Get-Date).AddHours(-24)
} | Where-Object { $_.Message -match "sliver" } | Export-Csv "C:\IR\process_events.csv" -NoTypeInformation
```

### 5. Eradication

#### File Removal
```powershell
# Remove attack artifacts (AFTER evidence collection)
# Search common attacker drop locations
$searchPaths = @("$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA", "$env:USERPROFILE\Downloads", "$env:PUBLIC")
foreach ($path in $searchPaths) {
    Remove-Item -Path "$path\sliver*" -Force -ErrorAction SilentlyContinue
}

# Remove any persistence mechanisms
# Check scheduled tasks
Get-ScheduledTask | Where-Object {$_.Actions.Execute -like "*sliver*"} | Unregister-ScheduledTask -Confirm:$false

# Check services
Get-Service | Where-Object {$_.BinaryPathName -like "*sliver*"} | Stop-Service -Force
```

#### Verify Removal
```powershell
# Verify binaries are removed from common locations
$searchPaths = @("$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA", "$env:USERPROFILE\Downloads")
foreach ($path in $searchPaths) {
    Get-ChildItem -Path $path -Filter "sliver*" -ErrorAction SilentlyContinue  # Should return nothing
}

# Verify no persistence
Get-ScheduledTask | Where-Object {$_.Actions.Execute -like "*sliver*"}
Get-Service | Where-Object {$_.BinaryPathName -like "*sliver*"}
```

### 6. Recovery

#### System Restoration Checklist

- [ ] Verify all malicious artifacts removed
- [ ] Confirm no persistence mechanisms remain
- [ ] Validate security controls are functioning
- [ ] Re-enable network connectivity
- [ ] Update security signatures

#### Validation Commands
```powershell
# Verify Defender is functional
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureLastUpdated

# Verify no suspicious processes from user-writable directories
$suspiciousPaths = @("*\AppData\*", "*\Temp\*", "*\Downloads\*", "*\Public\*")
foreach ($path in $suspiciousPaths) {
    Get-Process | Where-Object {$_.Path -like $path} | Select-Object ProcessName, Path
}

# Verify no suspicious network connections
Get-NetTCPConnection | Where-Object {$_.OwningProcess -ne 0 -and $_.State -eq "Established"} |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
```

### 7. Post-Incident

#### Lessons Learned Questions

1. How was the C2 tool detected? (Which detection rule triggered?)
2. What was the detection-to-containment time?
3. How did the binary get onto the system?
4. What would have prevented this attack?

#### Recommended Improvements

| Area | Recommendation | Priority |
|------|----------------|----------|
| Detection | Deploy YARA rules for C2 framework detection | HIGH |
| Prevention | Implement application allowlisting | HIGH |
| Prevention | Block outbound connections to untrusted destinations | MEDIUM |
| Monitoring | Enable process creation with command line logging | HIGH |
| Response | Pre-stage IR collection scripts | MEDIUM |

---

## Detection Testing

### Validation Steps

1. **Deploy detection rules** to your SIEM/EDR
2. **Run F0RT1KA test** on a monitored endpoint
3. **Verify alerts fire** within expected timeframes
4. **Tune false positives** based on your environment

### Expected Alert Timeline

| Phase | Expected Alert | Timing |
|-------|----------------|--------|
| Binary Drop | File creation in user-writable directory | Immediate |
| File Detection | Signature/heuristic alert on Sliver binary | Within seconds |
| Process Execution | NEW_PROCESS event with C2 characteristics | If file not quarantined |
| C2 Communication | Network beaconing to external IP | After execution |
| Command Line Detection | Sliver-specific arguments (--mtls, --wg, --dns) | At execution |

---

## References

### MITRE ATT&CK
- [T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [M1042 - Disable or Remove Feature or Program](https://attack.mitre.org/mitigations/M1042/)
- [M1038 - Execution Prevention](https://attack.mitre.org/mitigations/M1038/)
- [M1037 - Filter Network Traffic](https://attack.mitre.org/mitigations/M1037/)
- [M1031 - Network Intrusion Prevention](https://attack.mitre.org/mitigations/M1031/)

### Technical Documentation
- [Sliver C2 Framework GitHub](https://github.com/BishopFox/sliver)
- [Sliver Documentation](https://sliver.sh/docs)

### Industry Research
- [Microsoft: Threat Actor Behavior - Sliver](https://www.microsoft.com/security/blog/)
- [CISA Alert on C2 Frameworks](https://www.cisa.gov/)

---

## Files Included

| File | Description |
|------|-------------|
| `09efee46-f098-4948-8e35-dded024cd1e7_DEFENSE_GUIDANCE.md` | This comprehensive defense document |
| `09efee46-f098-4948-8e35-dded024cd1e7_detections.kql` | KQL queries for Microsoft Sentinel/Defender |
| `09efee46-f098-4948-8e35-dded024cd1e7_rules.yar` | YARA rules for file/memory detection |
| `09efee46-f098-4948-8e35-dded024cd1e7_dr_rules.yaml` | LimaCharlie D&R rules |
| `09efee46-f098-4948-8e35-dded024cd1e7_hardening.ps1` | PowerShell hardening script |

---

*Generated by F0RT1KA Defense Guidance Builder*
*Date: 2025-12-07*
