# Defense Guidance: APT33 Tickler Backdoor DLL Sideloading

## Executive Summary

This document provides comprehensive defense guidance for protecting against **APT33 Tickler**, a sophisticated backdoor leveraging DLL sideloading, dual persistence mechanisms, binary masquerading, and Azure-hosted C2 infrastructure. APT33 (Peach Sandstorm) specifically targets defense, satellite, and oil & gas sectors.

| Field | Value |
|-------|-------|
| **Test ID** | 13c2d073-8e33-4fca-ab27-68f20c408ce9 |
| **Test Name** | APT33 Tickler Backdoor DLL Sideloading |
| **MITRE ATT&CK** | [T1566.001](https://attack.mitre.org/techniques/T1566/001/), [T1574.002](https://attack.mitre.org/techniques/T1574/002/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/), [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1036](https://attack.mitre.org/techniques/T1036/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| **Tactics** | Initial Access, Persistence, Defense Evasion, Command and Control |
| **Threat Actor** | APT33 / Elfin / Peach Sandstorm / Refined Kitten |
| **Severity** | HIGH |
| **Test Score** | 8.7/10 |

---

## Threat Overview

### Attack Description

APT33 (tracked by Microsoft as Peach Sandstorm) has evolved from simple spearphishing to sophisticated multi-stage attacks. The Tickler backdoor uses DLL sideloading via renamed Microsoft binaries, dual persistence through registry Run keys and scheduled tasks, and communicates with Azure-hosted C2 infrastructure on non-standard HTTP ports (808/880).

### Attack Flow

```
[1] Spearphishing Attachment (T1566.001)
    -> Q3_Financial_Report_2025.pdf.zip (double extension)
    -> Contains: Microsoft.SharePoint.NativeMessaging.exe + DLLs + decoy
         |
         v
[2] DLL Side-Loading (T1574.002)
    -> Renamed notepad.exe as Microsoft.SharePoint.NativeMessaging.exe
    -> Loads msvcp140.dll and vcruntime140.dll from same directory
         |
         v
[3] Registry Run Key Persistence (T1547.001)
    -> HKCU or HKLM ...\Run\SharePoint = path\to\backdoor.exe
    -> SYSTEM vs user context detection
         |
         v
[4] Scheduled Task Persistence (T1053.005)
    -> MicrosoftSharePointSync task with ONLOGON trigger
    -> HIGHEST run level for redundant persistence
         |
         v
[5] Binary Masquerading (T1036)
    -> SharePoint.exe copy executing from non-standard path
    -> Version info mismatch (original name vs file name)
         |
         v
[6] Web Protocols C2 (T1071.001)
    -> HTTP POST to ports 808 and 880
    -> Base64-encoded system fingerprint
    -> User-Agent: Microsoft SharePoint/16.0
```

---

## MITRE ATT&CK Mapping

### Technique-to-Mitigation Matrix

| Technique | Name | Mitigations |
|-----------|------|-------------|
| T1566.001 | Spearphishing Attachment | [M1049](https://attack.mitre.org/mitigations/M1049/) Antivirus/Antimalware, [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1017](https://attack.mitre.org/mitigations/M1017/) User Training |
| T1574.002 | DLL Side-Loading | [M1013](https://attack.mitre.org/mitigations/M1013/) Application Developer Guidance, [M1051](https://attack.mitre.org/mitigations/M1051/) Update Software |
| T1547.001 | Registry Run Keys | [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention |
| T1053.005 | Scheduled Task | [M1026](https://attack.mitre.org/mitigations/M1026/) Privileged Account Management, [M1028](https://attack.mitre.org/mitigations/M1028/) Operating System Configuration |
| T1036 | Masquerading | [M1045](https://attack.mitre.org/mitigations/M1045/) Code Signing, [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention |
| T1071.001 | Web Protocols | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1030](https://attack.mitre.org/mitigations/M1030/) Network Segmentation |

---

## Detection Rules Summary

### Detection Artifacts Provided

| File | Format | Count | Purpose |
|------|--------|-------|---------|
| `*_detections.kql` | KQL (Sentinel/Defender) | 12 queries | Microsoft security platform detection |
| `*_sigma_rules.yml` | Sigma | 9 rules | Platform-agnostic detection |
| `*_dr_rules.yaml` | LimaCharlie D&R | 7 rules | LimaCharlie EDR detection and response |
| `*_rules.yar` | YARA | See file | File/memory pattern matching |

### Detection Priority Matrix

| Priority | Detection | Technique | Confidence | False Positive Rate |
|----------|-----------|-----------|------------|---------------------|
| P1 | SharePoint-themed registry persistence | T1547.001+T1036 | Critical | Very Low |
| P1 | Combined DLL sideloading + SharePoint persistence | Multi | Critical | Very Low |
| P1 | DLL sideloading from non-standard path | T1574.002 | High | Low |
| P2 | SharePoint-themed scheduled task | T1053.005 | High | Low |
| P2 | SharePoint binary masquerading | T1036 | High | Low |
| P2 | HTTP traffic on ports 808/880 | T1071.001 | High | Medium |
| P3 | Spoofed SharePoint User-Agent | T1071.001 | High | Low |
| P3 | Double extension archive | T1566.001 | Medium | Medium |
| P3 | Elevated ONLOGON scheduled task | T1053.005 | Medium | Medium |
| P4 | ZIP extraction to user directory | T1566.001 | Medium | High |

---

## Hardening Guidance

### Quick Wins (Immediate Actions)

Run the provided hardening script:

```powershell
# Apply all hardening settings
.\13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening.ps1

# Preview changes without applying
.\13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening.ps1 -WhatIf

# Revert all changes
.\13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening.ps1 -Undo
```

### 1. Block DLL Sideloading

**MITRE Mitigation:** [M1013](https://attack.mitre.org/mitigations/M1013/) - Application Developer Guidance

- Deploy WDAC/AppLocker policies to only allow DLL loading from trusted paths
- Enable "DLL Safe Search Mode" via registry:
  ```
  Path: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
  Name: SafeDllSearchMode
  Type: REG_DWORD
  Value: 1
  ```

### 2. Restrict Scheduled Task Creation

**MITRE Mitigation:** [M1026](https://attack.mitre.org/mitigations/M1026/) - Privileged Account Management

- Restrict schtasks.exe execution to administrators only via WDAC
- Monitor Event ID 4698 (scheduled task created) in Security log
- Block creation of tasks with HIGHEST run level from non-admin processes

### 3. Block Non-Standard HTTP Ports

**MITRE Mitigation:** [M1031](https://attack.mitre.org/mitigations/M1031/) - Network Intrusion Prevention

```powershell
# Block outbound connections on Tickler C2 ports
New-NetFirewallRule -DisplayName "Block Port 808 Outbound" -Direction Outbound -Protocol TCP -RemotePort 808 -Action Block
New-NetFirewallRule -DisplayName "Block Port 880 Outbound" -Direction Outbound -Protocol TCP -RemotePort 880 -Action Block
```

### 4. Enable Code Signing Enforcement

**MITRE Mitigation:** [M1045](https://attack.mitre.org/mitigations/M1045/) - Code Signing

- Deploy WDAC policies requiring valid signatures for executables
- Block execution of binaries with version info mismatches (original name != file name)
- Restrict execution from user-writable directories

---

## Incident Response Playbook

### Quick Reference

| Field | Value |
|-------|-------|
| **Test ID** | 13c2d073-8e33-4fca-ab27-68f20c408ce9 |
| **Test Name** | APT33 Tickler Backdoor DLL Sideloading |
| **MITRE ATT&CK** | T1566.001, T1574.002, T1547.001, T1053.005, T1036, T1071.001 |
| **Severity** | High |
| **Estimated Response Time** | 2-4 hours |

### 1. Detection Triggers

| Detection Name | Trigger Criteria | Confidence | Priority |
|----------------|------------------|------------|----------|
| DLL Sideloading | VC++ DLLs loaded from non-standard path | High | P1 |
| SharePoint Registry Persistence | Run key with SharePoint name/path | Critical | P1 |
| SharePoint Scheduled Task | schtasks /Create with SharePoint reference | High | P2 |
| Binary Masquerading | SharePoint-named binary from user directory | High | P2 |
| Non-Standard Port C2 | Outbound TCP 808/880 | High | P2 |
| Combined Correlation | DLL sideloading + persistence on same host | Critical | P1 |

### 2. Containment (First 15 Minutes)

- [ ] **Isolate affected host(s)**
  ```powershell
  netsh advfirewall set allprofiles state on
  netsh advfirewall firewall add rule name="IR-Block-Outbound" dir=out action=block
  ```

- [ ] **Terminate suspicious processes**
  ```powershell
  Get-Process | Where-Object { $_.Path -like "*SharePoint*" -and $_.Path -notlike "*Program Files*" } | Stop-Process -Force
  ```

- [ ] **Preserve volatile evidence**
  ```powershell
  Get-Process | Export-Csv "C:\IR\processes.csv"
  Get-NetTCPConnection | Export-Csv "C:\IR\connections.csv"
  reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "C:\IR\hkcu_run.reg"
  reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "C:\IR\hklm_run.reg"
  schtasks /query /fo CSV > "C:\IR\scheduled_tasks.csv"
  ```

### 3. Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Run key persistence | `HKCU/HKLM\...\Run\SharePoint` | `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"` |
| Scheduled task | `MicrosoftSharePointSync` | `schtasks /query /tn MicrosoftSharePointSync /fo LIST /v` |
| Sideloaded DLLs | User directories | `Get-ChildItem -Recurse -Filter "msvcp140.dll" C:\Users\` |
| Masqueraded binaries | User directories | `Get-ChildItem -Recurse -Filter "SharePoint*.exe" C:\Users\` |
| Spearphishing archive | Downloads | `Get-ChildItem -Recurse -Filter "*.pdf.zip" C:\Users\` |
| C2 staging data | `c:\F0\c2_staging\` | `Copy-Item c:\F0\c2_staging\ C:\IR\ -Recurse` |
| Event logs | Security, Sysmon | `wevtutil epl Security C:\IR\Security.evtx` |

### 4. Eradication

```powershell
# Remove registry Run key persistence
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SharePoint" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SharePoint" /f

# Remove scheduled task
schtasks /delete /tn "MicrosoftSharePointSync" /f

# Remove masqueraded binaries and sideloaded DLLs
Remove-Item "c:\Users\fortika-test\tickler_extract\*" -Recurse -Force -ErrorAction SilentlyContinue

# Remove C2 staging data
Remove-Item "c:\F0\c2_staging\*" -Recurse -Force -ErrorAction SilentlyContinue
```

### 5. Recovery

- [ ] Verify all persistence mechanisms removed
- [ ] Scan for additional masqueraded binaries
- [ ] Re-enable network connectivity after validation
- [ ] Apply hardening script to prevent recurrence
- [ ] Monitor for re-compromise indicators for 72 hours

### 6. Post-Incident Recommendations

| Area | Recommendation | Priority |
|------|----------------|----------|
| Detection | Deploy DLL sideloading detection rules | Critical |
| Detection | Monitor scheduled task creation events (4698) | High |
| Prevention | Enable WDAC/AppLocker to restrict DLL loading paths | High |
| Prevention | Block outbound ports 808/880 at firewall | High |
| Prevention | Restrict schtasks.exe to administrators | Medium |
| Prevention | Deploy email gateway filtering for double-extension archives | High |
| Response | Create automated containment playbook for APT33 indicators | Medium |

---

## Cross-Platform Hardening

This test targets Windows endpoints, but equivalent hardening scripts are provided for Linux and macOS environments to address the same attack technique categories using platform-native controls.

| Platform | Script | Key Controls |
|----------|--------|-------------|
| **Windows** | `*_hardening.ps1` | DLL SafeSearchMode, CWDIllegalInDllSearch, ASR rules (6), C2 port firewall blocks (TCP 808/880), registry/task audit policies, Defender hardening |
| **Linux** | `*_hardening_linux.sh` | LD_PRELOAD/LD_LIBRARY_PATH protection, cron/systemd persistence auditing, iptables/nftables C2 port blocking, auditd execve monitoring, /tmp noexec |
| **macOS** | `*_hardening_macos.sh` | SIP/Gatekeeper enforcement, DYLD_INSERT_LIBRARIES protection, LaunchAgent/LaunchDaemon hardening, pf firewall C2 port blocking, eslogger monitoring |

### Usage

```bash
# Windows
.\13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening.ps1          # Apply
.\13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening.ps1 -Undo    # Revert
.\13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening.ps1 -WhatIf  # Preview

# Linux
sudo ./13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening_linux.sh           # Apply
sudo ./13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening_linux.sh --undo    # Revert
sudo ./13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening_linux.sh --dry-run # Preview

# macOS
sudo ./13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening_macos.sh           # Apply
sudo ./13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening_macos.sh --undo    # Revert
sudo ./13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening_macos.sh --dry-run # Preview
```

---

## Defense Artifacts Inventory

| File | Format | Description |
|------|--------|-------------|
| `13c2d073-8e33-4fca-ab27-68f20c408ce9_detections.kql` | KQL | 12 detection queries for Microsoft Sentinel/Defender |
| `13c2d073-8e33-4fca-ab27-68f20c408ce9_sigma_rules.yml` | Sigma | Platform-agnostic detection rules |
| `13c2d073-8e33-4fca-ab27-68f20c408ce9_elastic_rules.ndjson` | NDJSON | Elasticsearch/Kibana detection rules |
| `13c2d073-8e33-4fca-ab27-68f20c408ce9_dr_rules.yaml` | YAML | LimaCharlie D&R rules (file format) |
| `13c2d073-8e33-4fca-ab27-68f20c408ce9_rules.yar` | YARA | File/memory pattern matching rules |
| `13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening.ps1` | PowerShell | Windows hardening script with -Undo/-WhatIf |
| `13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening_linux.sh` | Bash | Linux hardening script with --undo/--dry-run |
| `13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening_macos.sh` | Bash | macOS hardening script with --undo/--dry-run |
| `13c2d073-8e33-4fca-ab27-68f20c408ce9_DEFENSE_GUIDANCE.md` | Markdown | This document -- consolidated defense guidance |

---

## References

- [MITRE ATT&CK - APT33](https://attack.mitre.org/groups/G0064/)
- [Microsoft - Peach Sandstorm Tickler Malware](https://www.microsoft.com/en-us/security/blog/2024/08/28/peach-sandstorm-deploys-new-custom-tickler-malware-in-long-running-intelligence-gathering-operations/)
- [FBI/CISA Advisory AA24-241a](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [MITRE ATT&CK - DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK - Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK - Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK - Masquerading](https://attack.mitre.org/techniques/T1036/)
- [MITRE ATT&CK - Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft - Attack Surface Reduction Rules](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
