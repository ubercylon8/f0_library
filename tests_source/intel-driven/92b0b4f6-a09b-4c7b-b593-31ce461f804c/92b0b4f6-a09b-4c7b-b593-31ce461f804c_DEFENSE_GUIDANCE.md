# Defense Guidance: APT42 TAMECAT Fileless Backdoor with Browser Credential Theft

## Executive Summary

This document provides comprehensive defense guidance for protecting against **APT42 TAMECAT**, a fileless backdoor deployed by Iranian state-sponsored threat actors (also tracked as Magic Hound, Educated Manticore, and UNC788). The attack chain encompasses five stages: initial access via malicious LNK files with VBScript WMI enumeration, in-memory PowerShell execution via conhost headless chain, dual persistence mechanisms (Registry Run key and UserInitMprLogonScript), browser credential theft targeting Chrome/Edge databases with DPAPI decryption, and multi-channel data exfiltration via Telegram Bot API, FTP, and HTTPS POST.

This guide covers detection rules (KQL, Sigma, LimaCharlie D&R, YARA, Elastic Security), hardening scripts (Windows, Linux, macOS), and a complete incident response playbook.

| Field | Value |
|-------|-------|
| **Test ID** | 92b0b4f6-a09b-4c7b-b593-31ce461f804c |
| **Test Name** | APT42 TAMECAT Fileless Backdoor with Browser Credential Theft |
| **MITRE ATT&CK** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1059.005](https://attack.mitre.org/techniques/T1059/005/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/), [T1037.001](https://attack.mitre.org/techniques/T1037/001/), [T1555.003](https://attack.mitre.org/techniques/T1555/003/), [T1102](https://attack.mitre.org/techniques/T1102/) |
| **Tactics** | Execution, Persistence, Credential Access, Command and Control, Exfiltration |
| **Threat Actor** | APT42 / Magic Hound / Educated Manticore / UNC788 |
| **Severity** | CRITICAL |
| **Test Score** | 9.4/10 |
| **Target Platform** | Windows endpoints |
| **Financial Sector Relevance** | High -- targets browser-stored credentials for banking, trading, and treasury platforms |

---

## Threat Overview

### Attack Description

APT42 is an Iranian state-sponsored cyber espionage group operating under the Islamic Revolutionary Guard Corps Intelligence Organization (IRGC-IO). The group specifically targets organizations in the financial, government, defense, and academic sectors. The TAMECAT fileless backdoor represents their evolved tradecraft:

- **Malicious LNK files** delivered via spearphishing or WebDAV, disguised as PDF documents
- **VBScript-based WMI enumeration** of antivirus products and Windows Defender status before payload deployment
- **In-memory PowerShell execution** via `conhost.exe --headless` chain to evade console-based and ETW detection
- **Dual persistence** via Registry Run key ("Renovation" -- a documented APT42 IOC) and `UserInitMprLogonScript`
- **Browser credential theft** targeting Chrome and Edge Login Data SQLite databases, Edge remote debugging port (9222), and DPAPI decryption via `CryptUnprotectData`
- **Multi-channel exfiltration** via Telegram Bot API (`api.telegram.org/bot*/sendMessage`), FTP port 21, and HTTPS POST to external data collection endpoints

### Attack Flow

```
[1] Initial Access: Malicious LNK File
    Important_Document.pdf.lnk
    -> Target: cscript.exe //Nologo //T:15 update_check.vbs
    -> MS-SHLLINK binary format with TrackerDataBlock
         |
         v
[2] VBScript WMI AV Enumeration (T1059.005)
    -> winmgmts:\\.\root\SecurityCenter2 -> AntiVirusProduct
    -> winmgmts:\\.\root\Microsoft\Windows\Defender -> MSFT_MpComputerStatus
    -> winmgmts:\\.\root\cimv2 -> Win32_ComputerSystem, Win32_OperatingSystem
         |
         v
[3] TAMECAT PowerShell Backdoor (T1059.001) -- Fileless
    -> conhost.exe --headless powershell.exe -EncodedCommand <UTF-16LE-base64>
    -> Environment fingerprinting (hostname, domain, PSVersion, CLR)
    -> AMSI detection check (GetAssemblies, amsi DLL)
    -> Defender process enumeration (MsMpEng, MsSense, SenseIR, SenseCncProxy)
    -> Network interface enumeration (Get-NetIPAddress)
    -> Beacon marker file (tamecat_beacon.dat)
    -> Secondary IEX (Invoke-Expression) in-memory pattern
         |
         v
[4] Dual Persistence Mechanisms (T1547.001, T1037.001)
    -> HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Renovation
       = cscript.exe //Nologo //B "c:\F0\update_check.vbs"
    -> HKCU\Environment\UserInitMprLogonScript
       = c:\F0\update_check.vbs
    -> Read-back verification (detects silent EDR removal)
    -> HKLM used in SYSTEM context (machine-wide persistence)
         |
         v
[5] Browser Credential Theft (T1555.003)
    -> Edge: msedge.exe --remote-debugging-port=9222 --headless
    -> Chrome: Copy %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
    -> Edge: Copy %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
    -> DPAPI: CryptUnprotectData (crypt32.dll) with Chrome "v10" encrypted_value prefix
    -> Runs.dll: 4KB chunk staging for exfiltration (runs_staging\chunk_NNN.dat)
         |
         v
[6] Multi-Channel Exfiltration (T1102, T1048)
    -> DNS resolution: api.telegram.org
    -> HTTPS GET: api.telegram.org/bot{token}/getMe
    -> HTTPS POST: api.telegram.org/bot{token}/sendMessage (JSON body)
    -> FTP: Staging artifacts, port 21 connectivity test
    -> HTTPS POST: httpbin.org/post (JSON exfil simulation)
```

---

## MITRE ATT&CK Mapping

### Technique-to-Mitigation Matrix

| Technique | Name | Tactic | Applicable Mitigations |
|-----------|------|--------|----------------------|
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | Execution | [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1017](https://attack.mitre.org/mitigations/M1017/) User Training, [M1040](https://attack.mitre.org/mitigations/M1040/) Behavior Prevention on Endpoint |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | VBScript | Execution | [M1042](https://attack.mitre.org/mitigations/M1042/) Disable or Remove Feature, [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1049](https://attack.mitre.org/mitigations/M1049/) Antivirus/Antimalware |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution | [M1042](https://attack.mitre.org/mitigations/M1042/) Disable or Remove Feature, [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1045](https://attack.mitre.org/mitigations/M1045/) Code Signing, [M1049](https://attack.mitre.org/mitigations/M1049/) Antivirus/Antimalware |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys | Persistence | [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | Logon Script (Windows) | Persistence | [M1024](https://attack.mitre.org/mitigations/M1024/) Restrict Registry Permissions |
| [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Credentials from Web Browsers | Credential Access | [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies |
| [T1102](https://attack.mitre.org/techniques/T1102/) | Web Service | Command and Control | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1021](https://attack.mitre.org/mitigations/M1021/) Restrict Web-Based Content |

### Mitigation Implementation Priority

| Priority | Mitigation | Techniques Covered | Effort | Impact |
|----------|-----------|-------------------|--------|--------|
| P1 | Enable ASR rules for script interpreter blocking | T1204.002, T1059.005 | Low | High |
| P1 | Block Telegram API at network perimeter | T1102 | Low | High |
| P1 | Deploy UserInitMprLogonScript monitoring | T1037.001 | Low | Critical |
| P2 | Enable PowerShell Script Block Logging and Transcription | T1059.001 | Medium | High |
| P2 | Restrict browser credential database access via WDAC | T1555.003 | Medium | High |
| P2 | Block FTP outbound from workstations | T1048 | Low | Medium |
| P3 | Deploy enterprise password manager | T1555.003 | High | High |
| P3 | Enable Constrained Language Mode for PowerShell | T1059.001 | Medium | Medium |
| P3 | Deploy WDAC/AppLocker for unsigned code prevention | T1204.002, T1059.001 | High | Critical |

---

## Detection Rules Summary

### Detection Artifacts Provided

| File | Format | Count | Purpose |
|------|--------|-------|---------|
| `*_detections.kql` | KQL (Microsoft Sentinel/Defender) | 15 queries | Microsoft security platform detection |
| `*_sigma_rules.yml` | Sigma | 11 rules | Platform-agnostic, portable detection |
| `*_dr_rules.yaml` | LimaCharlie D&R | 7 rules | LimaCharlie EDR detection and response |
| `*_rules.yar` | YARA | 8 rules | File and memory pattern matching |
| `*_elastic_rules.ndjson` | Elastic Security | See file | Elastic SIEM detection rules |

### Detection Priority Matrix

| Priority | Detection | Technique | Confidence | False Positive Rate |
|----------|-----------|-----------|------------|---------------------|
| P1 | Conhost headless PowerShell chain | T1059.001 | Critical | Very Low |
| P1 | UserInitMprLogonScript modification | T1037.001 | Critical | Very Low |
| P1 | Telegram API from non-Telegram process | T1102 | Critical | Low |
| P1 | Browser credential database access by non-browser | T1555.003 | Critical | Low |
| P2 | Encoded PowerShell from script interpreter parent | T1059.001 | High | Low |
| P2 | Registry Run key with script interpreter target | T1547.001 | High | Medium |
| P2 | Browser remote debugging port activation | T1555.003 | High | Medium |
| P2 | CryptUnprotectData DPAPI from suspicious process | T1555.003 | High | Medium |
| P3 | VBScript WMI AV enumeration | T1059.005 | High | Medium |
| P3 | LNK file creation by non-standard process | T1204.002 | Medium | Medium |
| P3 | FTP outbound from workstation | T1048 | High | Medium |
| P3 | HTTPS POST to external data collection endpoints | T1102 | Medium | Medium |
| P4 | Multi-indicator kill chain correlation (3+ indicators) | Multiple | Critical | Very Low |
| P4 | Dual persistence mechanism correlation | T1547.001 + T1037.001 | Critical | Very Low |
| P4 | PowerShell Script Block Logging TAMECAT indicators | T1059.001 | High | Low |

---

## Hardening Guidance

### Quick Wins (Immediate Actions)

Three hardening scripts are provided for comprehensive cross-platform protection:

#### Windows (Primary -- this test targets Windows)

```powershell
# Apply all hardening settings
.\92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening.ps1

# Preview changes without applying
.\92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening.ps1 -WhatIf

# Revert all changes
.\92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening.ps1 -Undo
```

#### Linux (Cross-platform defense-in-depth)

```bash
# Apply hardening
sudo ./92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening_linux.sh apply

# Check status
sudo ./92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening_linux.sh check

# Revert changes
sudo ./92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening_linux.sh undo
```

#### macOS (Cross-platform defense-in-depth)

```bash
# Apply hardening
sudo ./92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening_macos.sh apply

# Check status
sudo ./92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening_macos.sh check

# Revert changes
sudo ./92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening_macos.sh undo
```

### Hardening Details by Technique

#### 1. Block Script Interpreters via ASR Rules (T1204.002, T1059.005)

**MITRE Mitigation:** [M1038](https://attack.mitre.org/mitigations/M1038/) - Execution Prevention

| Setting | Value |
|---------|-------|
| **ASR Rule GUID** | `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` |
| **Description** | Block execution of potentially obfuscated scripts |
| **Impact Level** | Medium -- may affect legitimate admin VBScript tools |

```powershell
# Enable ASR rule
Set-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC `
    -AttackSurfaceReductionRules_Actions Enabled

# Additional: Block WMI-spawned processes
Set-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b `
    -AttackSurfaceReductionRules_Actions Enabled
```

**Group Policy Path:**
```
Computer Configuration > Administrative Templates > Windows Components
    > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard
    > Attack Surface Reduction > Configure Attack Surface Reduction rules
```

**Verification:**
```powershell
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
```

**Rollback:**
```powershell
Set-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC `
    -AttackSurfaceReductionRules_Actions Disabled
```

#### 2. PowerShell Hardening (T1059.001)

**MITRE Mitigation:** [M1042](https://attack.mitre.org/mitigations/M1042/) - Disable or Remove Feature

| Setting | Value |
|---------|-------|
| **Script Block Logging** | Enabled |
| **Transcription** | Enabled, output to `C:\PSTranscripts` |
| **Impact Level** | Low -- logging only, no operational disruption |

```
Group Policy Path:
Computer Configuration > Administrative Templates > Windows Components
    > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled
    > Windows PowerShell > Turn on PowerShell Transcription = Enabled
```

**Registry Implementation:**
```
Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
Name: EnableScriptBlockLogging
Type: REG_DWORD
Value: 1

Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
Name: EnableTranscripting
Type: REG_DWORD
Value: 1
```

**Considerations:**
- Script Block Logging generates Windows Event ID 4104
- Transcription logs may consume disk space on active systems
- Consider centralized log collection via Windows Event Forwarding (WEF)

#### 3. UserInitMprLogonScript Lockdown (T1037.001)

**MITRE Mitigation:** [M1024](https://attack.mitre.org/mitigations/M1024/) - Restrict Registry Permissions

| Setting | Value |
|---------|-------|
| **Registry Key** | `HKCU\Environment\UserInitMprLogonScript` |
| **Action** | Remove existing value, audit future modifications |
| **Impact Level** | Low -- this value is rarely used legitimately |

```powershell
# Remove any existing malicious value
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f 2>$null

# Group Policy to block legacy logon scripts:
# Computer Configuration > Admin Templates > System > Logon
#   > Do not process the legacy run list = Enabled
```

**Considerations:**
- UserInitMprLogonScript executes before the desktop loads at every logon
- Legitimate enterprise use is extremely rare (GPO logon scripts use different mechanism)
- Monitor with Windows Event ID 13 (Sysmon registry value set)

#### 4. Network Exfiltration Prevention (T1102, T1048)

**MITRE Mitigation:** [M1031](https://attack.mitre.org/mitigations/M1031/) - Network Intrusion Prevention

| Control | Implementation |
|---------|---------------|
| **Block Telegram API** | Firewall rules blocking 149.154.160.0/20 and 91.108.0.0/16 subnets |
| **Block FTP Outbound** | Firewall rule blocking TCP port 21 from workstations |
| **Block External Data Services** | Web proxy/CASB blocking known paste/webhook/requestbin services |

```powershell
# Block Telegram API subnets
New-NetFirewallRule -DisplayName "Block Telegram API (APT42 C2)" `
    -Direction Outbound `
    -RemoteAddress 149.154.160.0/20,91.108.4.0/22,91.108.8.0/22,91.108.12.0/22,91.108.16.0/22,91.108.20.0/22,91.108.56.0/22 `
    -Action Block

# Block FTP outbound
New-NetFirewallRule -DisplayName "Block FTP Outbound" `
    -Direction Outbound -Protocol TCP -RemotePort 21 `
    -Action Block
```

**Considerations:**
- Verify Telegram desktop client is not required for business use before blocking
- FTP blocking may impact legacy file transfer workflows
- Implement at proxy/firewall level for comprehensive coverage

#### 5. Browser Credential Protection (T1555.003)

**MITRE Mitigation:** [M1027](https://attack.mitre.org/mitigations/M1027/) - Password Policies

| Control | Implementation |
|---------|---------------|
| **Enterprise Password Manager** | Deploy 1Password, LastPass, or Bitwarden enterprise |
| **Browser Policy** | Disable Chrome/Edge built-in password manager via GPO |
| **WDAC Rule** | Block non-browser processes from accessing `Login Data` files |

```
Group Policy (Chrome):
Computer Configuration > Administrative Templates > Google Chrome > Password Manager
    > Enable saving passwords to the password manager = Disabled

Group Policy (Edge):
Computer Configuration > Administrative Templates > Microsoft Edge > Password Manager
    > Enable saving passwords to the password manager = Disabled
```

**WDAC Supplemental Policy (Advanced):**
```xml
<!-- Block non-browser access to Login Data via file integrity monitoring -->
<!-- Deploy via Microsoft Endpoint Manager or direct WDAC policy -->
```

#### 6. Windows Defender Configuration (T1059.001, T1059.005)

**MITRE Mitigation:** [M1049](https://attack.mitre.org/mitigations/M1049/) - Antivirus/Antimalware

```powershell
# Ensure core protections are enabled
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableScriptScanning $false
```

#### 7. Audit Policy Configuration (T1547.001, T1555.003)

```powershell
# Enable registry auditing (for Run key and Environment key detection)
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Enable file system auditing (for browser credential access detection)
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Enable process creation auditing (for conhost/powershell chain detection)
auditpol /set /subcategory:"Process Creation" /success:enable

# Enable command line in process creation events (Event 4688)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 1 /f
```

---

## Incident Response Playbook

### Quick Reference

| Field | Value |
|-------|-------|
| **Test ID** | 92b0b4f6-a09b-4c7b-b593-31ce461f804c |
| **Test Name** | APT42 TAMECAT Fileless Backdoor with Browser Credential Theft |
| **MITRE ATT&CK** | T1204.002, T1059.001, T1059.005, T1547.001, T1037.001, T1555.003, T1102 |
| **Severity** | Critical |
| **Estimated Response Time** | 2-4 hours (containment), 8-24 hours (full investigation) |
| **IR Team Composition** | SOC Analyst, Endpoint Forensics, Network Forensics, Identity/IAM |

---

### 1. Detection Triggers

#### Alert Conditions

| Detection Name | Trigger Criteria | Confidence | Priority |
|----------------|------------------|------------|----------|
| Conhost Headless PowerShell | conhost.exe --headless spawning powershell.exe | Critical | P1 |
| UserInitMprLogonScript Modification | Registry value set on Environment\UserInitMprLogonScript | Critical | P1 |
| Telegram C2 Communication | Non-Telegram process resolving/connecting to api.telegram.org | Critical | P1 |
| Browser Credential Database Access | Non-browser process reading Chrome/Edge Login Data files | Critical | P1 |
| Encoded PowerShell from Script Parent | -EncodedCommand from cscript/wscript/conhost parent process | High | P2 |
| Dual Persistence Correlation | Run key + UserInitMprLogonScript on same host within 1 hour | Critical | P1 |
| Kill Chain Correlation | 3+ indicators on same host within 4 hours | Critical | P1 |

#### Initial Triage Questions

1. Is this a known test execution (F0RT1KA test run) or unexpected activity?
2. What is the scope -- single host, multiple hosts, or domain-wide?
3. What user account is associated? Is it a privileged account?
4. What is the timeline -- when did the first indicator appear?
5. Has the Telegram API connection been successful (data may have been exfiltrated)?
6. Are browser-stored credentials for financial applications present on the affected host?
7. Has the attacker established persistence (check Run keys and UserInitMprLogonScript)?

---

### 2. Containment (First 15 Minutes)

- [ ] **Isolate affected host(s) from network**
  ```powershell
  # Network isolation via Windows Firewall (preserve EDR connectivity)
  netsh advfirewall set allprofiles state on
  netsh advfirewall firewall add rule name="IR-Block-All-Outbound" dir=out action=block
  netsh advfirewall firewall add rule name="IR-Allow-EDR" dir=out remoteip=<EDR-cloud-IPs> action=allow
  netsh advfirewall firewall add rule name="IR-Allow-DNS" dir=out remoteport=53 protocol=udp action=allow
  ```

- [ ] **Terminate suspicious processes immediately**
  ```powershell
  # Kill TAMECAT execution chain processes
  Get-Process -Name "conhost" -ErrorAction SilentlyContinue | Where-Object {
      $_.StartInfo.Arguments -like "*headless*"
  } | Stop-Process -Force

  Stop-Process -Name "cscript" -Force -ErrorAction SilentlyContinue
  Stop-Process -Name "wscript" -Force -ErrorAction SilentlyContinue

  # Kill any PowerShell with encoded command (review before killing in production)
  Get-WmiObject Win32_Process -Filter "Name='powershell.exe'" |
      Where-Object { $_.CommandLine -like "*EncodedCommand*" } |
      ForEach-Object { $_.Terminate() }
  ```

- [ ] **Preserve volatile evidence before remediation**
  ```powershell
  # Create IR evidence directory
  $irDir = "C:\IR\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
  New-Item -ItemType Directory -Path $irDir -Force

  # Capture running processes with command lines
  Get-WmiObject Win32_Process | Select-Object ProcessId, Name, CommandLine, ParentProcessId,
      CreationDate, ExecutablePath |
      Export-Csv "$irDir\processes.csv" -NoTypeInformation

  # Capture network connections
  Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
      State, OwningProcess, CreationTime |
      Export-Csv "$irDir\connections.csv" -NoTypeInformation

  # Capture DNS cache
  Get-DnsClientCache | Export-Csv "$irDir\dns_cache.csv" -NoTypeInformation

  # Export persistence registry keys
  reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "$irDir\hkcu_run.reg" /y
  reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" "$irDir\hklm_run.reg" /y
  reg query "HKCU\Environment" > "$irDir\hkcu_environment.txt" 2>&1
  reg query "HKLM\Environment" > "$irDir\hklm_environment.txt" 2>&1

  # Capture scheduled tasks
  Get-ScheduledTask | Export-Csv "$irDir\scheduled_tasks.csv" -NoTypeInformation

  # Capture recent file modifications
  Get-ChildItem C:\Users -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) } |
      Select-Object FullName, Length, LastWriteTime, CreationTime |
      Export-Csv "$irDir\recent_files.csv" -NoTypeInformation
  ```

---

### 3. Evidence Collection

#### Critical Artifacts

| Artifact | Location | Collection Command | Priority |
|----------|----------|-------------------|----------|
| Run key persistence | `HKCU\...\CurrentVersion\Run` | `reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" C:\IR\run.reg` | Critical |
| Logon script persistence | `HKCU\Environment` | `reg query "HKCU\Environment" > C:\IR\env.txt` | Critical |
| PowerShell event logs | Windows Event Log | `wevtutil epl Microsoft-Windows-PowerShell/Operational C:\IR\PS.evtx` | Critical |
| Script Block Logging | Windows Event Log | `wevtutil epl Microsoft-Windows-PowerShell/Operational C:\IR\SBL.evtx` | Critical |
| AMSI events | Windows Defender Log | `wevtutil epl "Microsoft-Windows-Windows Defender/Operational" C:\IR\Defender.evtx` | High |
| Sysmon events | Sysmon Log | `wevtutil epl Microsoft-Windows-Sysmon/Operational C:\IR\Sysmon.evtx` | High |
| Security events | Security Event Log | `wevtutil epl Security C:\IR\Security.evtx` | High |
| Browser credential access | Prefetch | `Copy-Item "C:\Windows\Prefetch\*" C:\IR\Prefetch\ -Recurse` | High |
| Network connections | Memory | `Get-NetTCPConnection \| Export-Csv C:\IR\tcp.csv` | High |
| TAMECAT beacon marker | `c:\F0\tamecat_beacon.dat` | `Copy-Item "c:\F0\tamecat_beacon.dat" C:\IR\ -ErrorAction SilentlyContinue` | Medium |
| VBScript artifacts | `c:\F0\update_check.vbs` | `Copy-Item "c:\F0\update_check.vbs" C:\IR\ -ErrorAction SilentlyContinue` | Medium |
| AV enumeration results | `c:\F0\av_enum_results.txt` | `Copy-Item "c:\F0\av_enum_results.txt" C:\IR\ -ErrorAction SilentlyContinue` | Medium |
| Exfil channel results | `c:\F0\exfil_channel_results.json` | `Copy-Item "c:\F0\exfil_channel_results.json" C:\IR\ -ErrorAction SilentlyContinue` | Medium |

#### Memory Acquisition

```powershell
# Using WinPMEM (if available)
.\winpmem_mini_x64.exe C:\IR\memory.raw

# Using DumpIt (if available)
.\DumpIt.exe /OUTPUT C:\IR\memory.dmp
```

#### Timeline Generation

```powershell
# Export all critical event logs for timeline analysis
$logs = @(
    "Security",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational"
)
foreach ($log in $logs) {
    $safeName = $log -replace '[/\\]', '-'
    wevtutil epl $log "C:\IR\$safeName.evtx" 2>$null
}
```

---

### 4. Eradication

#### Remove Persistence Mechanisms

```powershell
# Remove Registry Run key persistence ("Renovation" value)
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Renovation" /f 2>$null
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Renovation" /f 2>$null

# Remove UserInitMprLogonScript
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f 2>$null
reg delete "HKLM\Environment" /v "UserInitMprLogonScript" /f 2>$null

# Verify removal
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Renovation" 2>&1
reg query "HKCU\Environment" /v "UserInitMprLogonScript" 2>&1
```

#### Remove Attack Artifacts

```powershell
# Remove TAMECAT staging artifacts (AFTER evidence collection)
$artifacts = @(
    "c:\F0\tamecat_beacon.dat",
    "c:\F0\tamecat_output.txt",
    "c:\F0\tamecat_iex_marker.txt",
    "c:\F0\update_check.vbs",
    "c:\F0\Important_Document.pdf.lnk",
    "c:\F0\av_enum_results.txt",
    "c:\F0\vbs_av_enum_output.txt",
    "c:\F0\browser_cred_results.txt",
    "c:\F0\exfil_channel_results.json",
    "c:\F0\chrome_login_data_copy.db",
    "c:\F0\edge_login_data_copy.db"
)

foreach ($artifact in $artifacts) {
    if (Test-Path $artifact) {
        Remove-Item $artifact -Force -ErrorAction SilentlyContinue
        Write-Host "Removed: $artifact"
    }
}

# Remove staging directories
Remove-Item "c:\F0\runs_staging" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "c:\F0\ftp_staging" -Recurse -Force -ErrorAction SilentlyContinue
```

---

### 5. Recovery

#### System Restoration Checklist

- [ ] Verify all persistence mechanisms removed (Run key "Renovation", UserInitMprLogonScript)
- [ ] Verify no TAMECAT beacon or staging artifacts remain on disk
- [ ] Reset all browser-stored passwords for the affected user
- [ ] Rotate credentials for any financial platforms accessed through the browser
- [ ] Re-enable network connectivity (after validation)
- [ ] Apply hardening script to prevent recurrence
- [ ] Monitor for re-compromise indicators for 72 hours minimum

#### Validation Commands

```powershell
# Verify clean state
Get-ChildItem "c:\F0\" -ErrorAction SilentlyContinue  # Should be empty or not exist

# Verify no persistence remains
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Renovation" 2>&1 | Select-String "ERROR"
reg query "HKCU\Environment" /v "UserInitMprLogonScript" 2>&1 | Select-String "ERROR"

# Verify no suspicious PowerShell processes
Get-Process powershell -ErrorAction SilentlyContinue |
    Select-Object Id, StartTime, @{N='CmdLine';E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}}

# Verify no Telegram DNS resolution in cache
Get-DnsClientCache | Where-Object { $_.Entry -like "*telegram*" }

# Verify firewall rules are blocking exfiltration channels
Get-NetFirewallRule -DisplayName "*Telegram*" -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName "*FTP*" -ErrorAction SilentlyContinue
```

---

### 6. Post-Incident

#### Lessons Learned Questions

1. How was the attack detected? Which rule/alert triggered first?
2. What was the detection-to-containment time? Was it under the 15-minute target?
3. Which attack stage was the attack stopped at? Could it have been stopped earlier?
4. Were browser-stored credentials for financial applications compromised?
5. Was any data successfully exfiltrated via Telegram or other channels?
6. What detection gaps were identified during the investigation?
7. Were the hardening recommendations from this guide already in place?

#### Recommended Post-Incident Improvements

| Area | Recommendation | Priority |
|------|----------------|----------|
| Detection | Deploy conhost headless PowerShell detection rule across all endpoints | Critical |
| Detection | Enable PowerShell Script Block Logging organization-wide | High |
| Detection | Implement kill chain correlation rule (3+ indicators = auto-escalate) | High |
| Prevention | Block UserInitMprLogonScript via Group Policy (Do not process legacy run list) | Critical |
| Prevention | Block Telegram API at network perimeter (proxy + firewall) | High |
| Prevention | Deploy enterprise password manager, disable browser credential storage | High |
| Prevention | Enable ASR rules for script interpreter blocking organization-wide | High |
| Prevention | Block FTP outbound from all workstation subnets at firewall | Medium |
| Response | Create automated containment playbook for APT42 indicators | Medium |
| Response | Pre-stage IR evidence collection scripts on all endpoints | Medium |
| Identity | Implement MFA for all financial platform accounts | Critical |
| Identity | Rotate all credentials stored in affected browsers | Critical |

---

## Cross-Platform Hardening Summary

While this test specifically targets Windows, the underlying attack techniques have direct equivalents on Linux and macOS. The provided hardening scripts address cross-platform defense:

| Attack Technique | Windows Hardening | Linux Equivalent | macOS Equivalent |
|-----------------|------------------|-----------------|-----------------|
| VBScript/PowerShell execution | ASR rules, Script Block Logging | Restrict bash/python/perl permissions, auditd | Restrict osascript, enable Endpoint Security |
| Registry persistence | Monitor Run keys, block UserInitMprLogonScript | Monitor cron/systemd, protect rc.local | Monitor LaunchAgents/LaunchDaemons |
| Browser credential theft | WDAC, browser GPO | File permissions on ~/.config/chromium | File permissions on ~/Library/Application Support |
| Telegram C2 | Windows Firewall rules | iptables/nftables rules | pf firewall rules |
| FTP exfiltration | Block outbound port 21 | iptables/nftables rules | pf firewall rules |
| DPAPI decryption | Monitor CryptUnprotectData API calls | Monitor gnome-keyring/kwallet access | Monitor Keychain access |

---

## References

- [MITRE ATT&CK - APT42 Group Profile](https://attack.mitre.org/groups/G1024/)
- [Mandiant - APT42: Crooked Charms, Cons, and Compromises](https://www.mandiant.com/resources/blog/apt42-charms-cons-compromises)
- [Volexity - TAMECAT Backdoor Analysis](https://www.volexity.com/)
- [Microsoft MSTIC - Magic Hound / Phosphorus Threat Intelligence](https://www.microsoft.com/en-us/security/blog/)
- [Google TAG - APT42 Campaign Operations](https://blog.google/threat-analysis-group/)
- [CISA - Iranian State-Sponsored Actors Conduct Credential Harvesting](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Microsoft - Attack Surface Reduction Rules Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [MITRE ATT&CK - T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK - T1037.001 Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [MITRE ATT&CK - T1555.003 Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK - T1102 Web Service](https://attack.mitre.org/techniques/T1102/)
