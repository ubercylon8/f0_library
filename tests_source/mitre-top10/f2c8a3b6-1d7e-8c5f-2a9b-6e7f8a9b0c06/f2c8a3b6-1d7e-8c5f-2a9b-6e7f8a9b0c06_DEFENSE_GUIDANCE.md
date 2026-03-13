# Defense Guidance: LOLBIN Download Detection

## Executive Summary

This document provides comprehensive defense guidance for protecting against **Living Off The Land Binary (LOLBIN) download techniques**. Adversaries abuse legitimate Windows binaries (certutil, bitsadmin, curl, PowerShell) to download malicious payloads, bypassing application whitelisting since these are signed Microsoft executables.

| Field | Value |
|-------|-------|
| **Test ID** | f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06 |
| **Test Name** | LOLBIN Download Detection |
| **MITRE ATT&CK** | [T1105](https://attack.mitre.org/techniques/T1105/) - Ingress Tool Transfer, [T1059.001](https://attack.mitre.org/techniques/T1059/001/) - PowerShell |
| **Tactics** | Command and Control, Execution |
| **Severity** | HIGH |
| **Test Score** | 8.0/10 |

---

## Threat Overview

### Attack Description

LOLBIN download techniques are among the most prevalent attacker behaviors observed in real-world intrusions. Every major APT group, ransomware operator, and initial access broker uses native Windows binaries to download second-stage payloads, tools, and scripts. These techniques are effective because:

- **Binaries are signed by Microsoft** -- whitelisting and code signing policies allow them
- **Binaries are present on every Windows installation** -- no attacker tools needed
- **Network traffic appears normal** -- HTTP/HTTPS from legitimate system binaries
- **Multiple fallback options** -- if one method is blocked, attackers switch to another

### Download Methods Tested

| # | Method | Binary | Command Pattern | Prevalence |
|---|--------|--------|----------------|------------|
| 1 | certutil URL cache | certutil.exe | `certutil -urlcache -split -f <url> <output>` | Very High |
| 2 | BITS transfer | bitsadmin.exe | `bitsadmin /transfer <job> /download <url> <output>` | High |
| 3 | PowerShell IWR | powershell.exe | `Invoke-WebRequest -Uri <url> -OutFile <output>` | Very High |
| 4 | PowerShell WebClient | powershell.exe | `(New-Object Net.WebClient).DownloadFile(<url>, <output>)` | Very High |
| 5 | Windows curl | curl.exe | `curl.exe -o <output> <url>` | Medium |

---

## MITRE ATT&CK Mapping

### Technique-to-Mitigation Matrix

| Technique | Name | Mitigations |
|-----------|------|-------------|
| T1105 | Ingress Tool Transfer | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1037](https://attack.mitre.org/mitigations/M1037/) Filter Network Traffic |
| T1059.001 | PowerShell | [M1042](https://attack.mitre.org/mitigations/M1042/) Disable or Remove Feature, [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention, [M1049](https://attack.mitre.org/mitigations/M1049/) Antivirus/Antimalware |

---

## Detection Rules Summary

### Detection Artifacts Provided

| File | Format | Count | Purpose |
|------|--------|-------|---------|
| `*_detections.kql` | KQL (Sentinel/Defender) | 8 queries | Microsoft security platform detection |
| `*_sigma_rules.yml` | Sigma | See file | Platform-agnostic detection |
| `*_dr_rules.yaml` | LimaCharlie D&R | See file | LimaCharlie EDR detection and response |
| `*_rules.yar` | YARA | See file | File/memory pattern matching |

### Detection Priority Matrix

| Priority | Detection | Technique | Confidence | False Positive Rate |
|----------|-----------|-----------|------------|---------------------|
| P1 | Multiple LOLBINs downloading in sequence | T1105 | Critical | Very Low |
| P1 | certutil URL cache download | T1105 | High | Low |
| P1 | BITS job for external download | T1105 | High | Low |
| P2 | PowerShell download cradle | T1059.001 | High | Medium |
| P2 | Network connections from LOLBIN processes | T1105 | High | Medium |
| P3 | curl.exe to suspicious locations | T1105 | Medium | Medium |
| P3 | Files created by LOLBIN processes | T1105 | Medium | Medium |

---

## Hardening Guidance

### Quick Wins (Immediate Actions)

Run the provided hardening script:

```powershell
# Apply all hardening settings
.\f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening.ps1

# Preview changes
.\f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening.ps1 -WhatIf

# Revert changes
.\f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening.ps1 -Undo
```

### 1. Block Certutil Download Capability

**MITRE Mitigation:** [M1038](https://attack.mitre.org/mitigations/M1038/) - Execution Prevention

Certutil is rarely needed for downloads in production environments:

```powershell
# ASR Rule: Block process creations originating from PSExec and WMI commands
Set-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled

# AppLocker: Restrict certutil to admin-only usage
# Deploy via Group Policy
```

### 2. Restrict BITS Job Creation

**MITRE Mitigation:** [M1037](https://attack.mitre.org/mitigations/M1037/) - Filter Network Traffic

```powershell
# Monitor BITS jobs
Get-BitsTransfer -AllUsers | Format-Table DisplayName, JobState, TransferType

# Remove suspicious BITS jobs
Get-BitsTransfer -AllUsers | Where-Object { $_.DisplayName -notlike "*Windows*" } | Remove-BitsTransfer
```

### 3. Enable PowerShell Logging

**MITRE Mitigation:** [M1042](https://attack.mitre.org/mitigations/M1042/) - Disable or Remove Feature

```
Group Policy Path:
Computer Configuration > Administrative Templates > Windows Components
    > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled
    > Windows PowerShell > Turn on PowerShell Transcription = Enabled
```

### 4. Deploy Web Proxy with TLS Inspection

**MITRE Mitigation:** [M1031](https://attack.mitre.org/mitigations/M1031/) - Network Intrusion Prevention

- Force all HTTP/HTTPS traffic through a web proxy
- Block direct internet access from workstations for certutil.exe, bitsadmin.exe
- Implement TLS inspection for download content analysis

---

## Incident Response Playbook

### Quick Reference

| Field | Value |
|-------|-------|
| **Test ID** | f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06 |
| **Test Name** | LOLBIN Download Detection |
| **MITRE ATT&CK** | T1105, T1059.001 |
| **Severity** | High |
| **Estimated Response Time** | 1-2 hours |

### 1. Detection Triggers

| Detection Name | Trigger Criteria | Confidence | Priority |
|----------------|------------------|------------|----------|
| Certutil URL Cache | certutil.exe with -urlcache flag | High | P1 |
| BITSAdmin Transfer | bitsadmin.exe with /transfer to external URL | High | P1 |
| PowerShell Download | IWR/WebClient download commands | High | P2 |
| Multiple LOLBIN Sequence | 2+ LOLBINs downloading within 10 minutes | Critical | P1 |
| LOLBIN Network Connection | Outbound from certutil/bitsadmin | High | P2 |

### 2. Containment (First 15 Minutes)

- [ ] **Identify downloaded files**
  ```powershell
  # Check recently created files in common staging locations
  Get-ChildItem C:\Users\*\Downloads,C:\Users\*\AppData,C:\Temp,C:\Windows\Temp -Recurse -File |
      Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-2) } |
      Select-Object FullName, Length, CreationTime
  ```

- [ ] **Terminate download processes**
  ```powershell
  Stop-Process -Name "certutil" -Force -ErrorAction SilentlyContinue
  Stop-Process -Name "bitsadmin" -Force -ErrorAction SilentlyContinue
  Get-BitsTransfer -AllUsers | Remove-BitsTransfer
  ```

- [ ] **Clean certutil cache**
  ```powershell
  certutil -urlcache * delete
  ```

### 3. Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| BITS jobs | BITS database | `Get-BitsTransfer -AllUsers \| Export-Csv C:\IR\bits.csv` |
| Certutil cache | Certutil cache | `certutil -urlcache * > C:\IR\certutil_cache.txt` |
| Downloaded files | Various | Check user Temp, Downloads, AppData |
| Process creation logs | Event Log | `wevtutil epl Security C:\IR\Security.evtx` |
| PowerShell logs | Event Log | `wevtutil epl Microsoft-Windows-PowerShell/Operational C:\IR\PS.evtx` |

### 4. Eradication

```powershell
# Remove downloaded files (AFTER evidence collection)
# Identify and remove based on investigation findings

# Clear BITS transfer history
Get-BitsTransfer -AllUsers | Remove-BitsTransfer

# Clear certutil URL cache
certutil -urlcache * delete
```

### 5. Post-Incident Recommendations

| Area | Recommendation | Priority |
|------|----------------|----------|
| Detection | Deploy certutil download monitoring across all endpoints | Critical |
| Detection | Enable PowerShell Script Block Logging organization-wide | High |
| Prevention | Restrict certutil.exe/bitsadmin.exe via AppLocker to admins only | High |
| Prevention | Deploy web proxy forcing all HTTP through inspection | High |
| Prevention | Block direct internet for LOLBINs via Windows Firewall | Medium |
| Response | Automate BITS job monitoring and alerting | Medium |

---

## Cross-Platform Hardening

While LOLBIN techniques are Windows-specific, equivalent download tool abuse exists on Linux and macOS. Cross-platform hardening scripts address the same ingress tool transfer techniques using platform-native controls.

| Platform | Script | Key Controls |
|----------|--------|-------------|
| **Windows** | `*_hardening.ps1` | PowerShell logging (ScriptBlock, Module, Transcription), certutil/bitsadmin firewall blocks, ASR rules (5), BITS event logging, Defender network protection |
| **Linux** | `*_hardening_linux.sh` | auditd rules for curl/wget/nc/python/perl, /tmp file integrity monitoring with noexec, outbound connection restrictions, PowerShell Core logging, network logging |
| **macOS** | `*_hardening_macos.sh` | eslogger endpoint monitoring, application firewall + stealth mode, Gatekeeper/SIP enforcement, download tool restrictions (Santa), LuLu/Little Snitch, PowerShell Core logging |

### Usage

```bash
# Windows
.\f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening.ps1          # Apply
.\f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening.ps1 -Undo    # Revert
.\f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening.ps1 -WhatIf  # Preview

# Linux
sudo ./f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening_linux.sh           # Apply
sudo ./f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening_linux.sh --undo    # Revert
sudo ./f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening_linux.sh --dry-run # Preview

# macOS
sudo ./f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening_macos.sh           # Apply
sudo ./f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening_macos.sh --undo    # Revert
sudo ./f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening_macos.sh --dry-run # Preview
```

---

## Defense Artifacts Inventory

| File | Format | Description |
|------|--------|-------------|
| `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_detections.kql` | KQL | 8 detection queries for Microsoft Sentinel/Defender |
| `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_sigma_rules.yml` | Sigma | Platform-agnostic detection rules |
| `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_elastic_rules.ndjson` | NDJSON | Elasticsearch/Kibana detection rules |
| `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_dr_rules.yaml` | YAML | LimaCharlie D&R rules (file format) |
| `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_rules.yar` | YARA | File/memory pattern matching rules |
| `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening.ps1` | PowerShell | Windows hardening script with -Undo/-WhatIf |
| `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening_linux.sh` | Bash | Linux hardening script with --undo/--dry-run |
| `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening_macos.sh` | Bash | macOS hardening script with --undo/--dry-run |
| `f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_DEFENSE_GUIDANCE.md` | Markdown | This document -- consolidated defense guidance |

---

## References

- [MITRE ATT&CK T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Red Canary Threat Detection Report - Certutil](https://redcanary.com/threat-detection-report/)
- [Microsoft - Attack Surface Reduction Rules](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft - PowerShell Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
