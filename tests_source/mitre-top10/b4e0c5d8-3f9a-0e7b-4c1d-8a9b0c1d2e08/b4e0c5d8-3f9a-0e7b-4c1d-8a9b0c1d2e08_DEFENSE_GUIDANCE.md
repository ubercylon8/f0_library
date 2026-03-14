# Defense Guidance: Ransomware Encryption (Safe Mode)

## Executive Summary

This test simulates core ransomware behaviors — mass file rename operations, AES-256 key generation,
and ransom note creation — against a Windows endpoint. The techniques exercised (T1486 Data Encrypted
for Impact and T1491.001 Internal Defacement) are the terminal impact phase of virtually every modern
ransomware campaign. A result of 101 (Unprotected) means the endpoint's behavioral controls failed to
interrupt the kill chain before files were altered. Priority actions are: enable and tune Windows
Defender Controlled Folder Access, deploy Attack Surface Reduction rules that restrict file extension
manipulation, and ensure behavioral monitoring of rapid mass rename syscalls is active at the EDR
sensor level.

---

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08 |
| **Test Name** | Ransomware Encryption (Safe Mode) |
| **MITRE ATT\&CK** | [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) · [T1491.001 — Internal Defacement](https://attack.mitre.org/techniques/T1491/001/) |
| **Tactic** | Impact |
| **Severity** | Critical |
| **Threat Actor** | Generic ransomware tradecraft (observed in LockBit, BlackCat/ALPHV, Hive, Clop, Royal, SafePay) |
| **Subcategory** | Ransomware |
| **Test Score** | 8.5 / 10 |

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|----------------------|
| [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) | Impact | M1040 — Behavior Prevention on Endpoint · M1053 — Data Backup · M1038 — Execution Prevention |
| [T1491.001 — Internal Defacement](https://attack.mitre.org/techniques/T1491/001/) | Impact | M1053 — Data Backup · M1040 — Behavior Prevention on Endpoint |

### Technique Detail

**T1486 — Data Encrypted for Impact**
Adversaries encrypt files on a system to interrupt availability. In ransomware campaigns this is the
primary monetization action. The test simulates this by generating a valid AES-256 key, then
renaming a batch of documents with an unknown extension (`.f0rtika`), triggering the same filesystem
syscalls (NtSetInformationFile / MoveFile) that real ransomware uses. Detection depends on either
behavioral heuristics (mass rename/extension change rate) or file-content entropy analysis.

**T1491.001 — Internal Defacement**
Adversaries modify visual content on internal systems to intimidate or distract defenders. In
ransomware this manifests as ransom note files (`README.txt`, `HOW_TO_DECRYPT.txt`, etc.) dropped
in every affected directory. The test creates `README_F0RTIKA.txt` in the user profile root,
exercising file-creation monitoring and keyword-based content detection.

---

## Hardening Recommendations

### Quick Wins (Immediate — Low Operational Impact)

1. **Enable Controlled Folder Access (CFA)**
   Turn on Windows Defender Controlled Folder Access via Group Policy or Intune. This blocks any
   process not on the allow-list from writing to protected folders (Documents, Desktop, Pictures,
   etc.) without requiring EDR behavioural tuning.
   `Set-MpPreference -EnableControlledFolderAccess Enabled`

2. **Enable ASR rule: Block credential stealing from LSASS**
   While not directly ransomware-specific, enabling all production-ready ASR rules raises the overall
   attack cost and is a prerequisite for a strong ASR baseline.

3. **Enable ASR rule: Use advanced protection against ransomware**
   GUID `c1db55ab-c21a-4637-bb3f-a12568109d35` — specifically targets rapid file operations
   characteristic of ransomware. Set to Block mode.

4. **Enable ASR rule: Block executable content from email/webmail**
   GUID `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` — limits initial delivery vectors.

5. **Audit and restrict Windows Script Host (WSH)**
   Ransomware frequently uses WSH/VBScript loaders. Disable or restrict via registry if not
   operationally required.

6. **Configure tamper protection**
   Ensure `Set-MpPreference -DisableTamperProtection $false` so ransomware cannot disable Defender
   before launching the encryption phase.

### Medium-Term (1–2 Weeks — Moderate Effort)

1. **Deploy file-extension allow-listing at the EDR sensor**
   Work with your EDR vendor to create a behavioral rule that fires when any single process performs
   more than 10 file renames with extension changes within 30 seconds. This threshold catches
   ransomware while having near-zero false positives in practice.

2. **Implement protected document folders via Controlled Folder Access + custom folders**
   Add business-critical paths (shares, project directories, finance folders) to the CFA protected
   list beyond the defaults.

3. **Enable VSS shadow copy protection**
   Apply Group Policy to restrict `vssadmin.exe`, `wmic.exe shadowcopy delete`, and `bcdedit.exe`
   invocations by non-SYSTEM processes. Ransomware routinely deletes shadow copies (T1490) before or
   during encryption.
   ```
   AppLocker / WDAC deny rules targeting:
     - vssadmin.exe delete shadows
     - wmic shadowcopy delete
     - bcdedit /set {default} recoveryenabled No
   ```

4. **Deploy Microsoft MAPS / cloud-delivered protection at highest level**
   `Set-MpPreference -MAPSReporting Advanced -CloudBlockLevel High`
   Cloud-delivered protection provides near-real-time signature updates and can block novel
   ransomware variants within seconds of first-seen telemetry.

5. **Harden backup infrastructure**
   Ensure backup agents run under a dedicated service account that cannot be compromised by an
   endpoint user token. Offline/immutable backup copies (Azure Backup soft-delete, tape, or S3
   Object Lock) are the definitive recovery mitigation against ransomware (M1053).

6. **Enable audit logging for file system operations**
   Enable "Audit Object Access — File System" in Advanced Audit Policy and configure SACL on
   high-value directories. This feeds SIEM/EDR with the rename event stream needed for detection.

7. **Network segmentation — limit SMB lateral spread**
   Block inbound SMB (TCP 445) between workstations at the host firewall layer to contain
   network-aware ransomware from spreading to adjacent endpoints after initial compromise.

### Strategic (1–3 Months — Requires Planning)

1. **Deploy Windows Defender Application Control (WDAC) policy**
   A managed code integrity policy in Enforced mode (replacing older AppLocker) is the strongest
   execution prevention control (M1038). It blocks unsigned or untrusted binaries from running,
   stopping ransomware that arrives as a novel PE.

2. **Implement privileged access workstations (PAWs) for IT administrators**
   Human-operated ransomware campaigns compromise admin credentials before deploying encryption.
   PAWs isolate privileged sessions from internet-facing risk.

3. **Zero-trust file share segmentation**
   Replace open SMB shares with identity-aware file access (SharePoint, OneDrive with sensitivity
   labels, or Zero Trust Network Access) so a compromised endpoint cannot enumerate and encrypt
   network shares.

4. **Ransomware-specific incident response retainer**
   Establish a relationship with an IR firm and pre-negotiate services so response time from
   detection to containment is measured in minutes, not hours.

5. **Regular offline backup validation**
   Schedule quarterly restoration drills from offline backups to verify Recovery Time Objective (RTO)
   is achievable. Tested backups are the primary business continuity control against ransomware.

---

## Cross-Platform Hardening Scripts

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08_hardening.ps1` | PowerShell — CFA, ASR, Defender, audit policy, VSS protection. Supports -Undo and -WhatIf. |

> Note: This test targets Windows endpoints only. Linux and macOS scripts are not generated for this
> test UUID.

---

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| Mass File Extension Change | Single process renames >10 files with extension change within 30 s | High | P1 |
| Ransom Note File Created | File creation matching `README*.txt`, `HOW_TO*.txt`, `DECRYPT*.txt` in user profile path | High | P1 |
| AES Crypto API Usage + File Write Burst | `CryptGenKey` / `BCryptGenerateSymmetricKey` followed by high-rate `NtWriteFile` | High | P1 |
| Unknown Extension Proliferation | Files with non-standard extension appearing in >3 directories in <60 s | Medium | P2 |
| VSS/Shadow Copy Deletion Attempt | `vssadmin delete shadows` or `wmic shadowcopy delete` process creation | High | P1 |
| Defender Tamper Attempt | Registry write to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` | High | P1 |

---

### Containment (First 15 Minutes)

- [ ] Isolate the affected host immediately — disconnect from network (wired and wireless)
  ```powershell
  # Emergency network isolation via Windows Firewall
  netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
  ```
- [ ] Disable the affected user account in Active Directory / Entra ID
  ```powershell
  Disable-ADAccount -Identity <username>
  # Or via Entra ID:
  Update-MgUser -UserId <UPN> -AccountEnabled:$false
  ```
- [ ] Identify and suspend the offending process
  ```powershell
  Get-Process | Where-Object { $_.Modules.FileName -like "*suspicious*" } | Stop-Process -Force
  ```
- [ ] Snapshot the disk image (if VM) before any remediation changes
- [ ] Revoke active authentication tokens for the compromised account
  ```powershell
  # Entra ID: revoke all refresh tokens
  Revoke-MgUserSignInSession -UserId <UPN>
  ```
- [ ] Alert SOC / CISO and activate ransomware IR runbook

---

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|--------------------|
| Security event log | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | `wevtutil epl Security C:\IR\Security.evtx` |
| System event log | `%SystemRoot%\System32\winevt\Logs\System.evtx` | `wevtutil epl System C:\IR\System.evtx` |
| Sysmon operational log | `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | `wevtutil epl Microsoft-Windows-Sysmon/Operational C:\IR\Sysmon.evtx` |
| Windows Defender log | `%ProgramData%\Microsoft\Windows Defender\Support\MPLog-*.log` | `Copy-Item "$env:ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log" C:\IR\` |
| Prefetch files | `C:\Windows\Prefetch\` | `Copy-Item C:\Windows\Prefetch\*.pf C:\IR\Prefetch\` |
| MFT snapshot | NTFS Master File Table | `.\MFTECmd.exe -f $Volume --csv C:\IR\MFT\` |
| Process creation events | Windows Security Event ID 4688 | `Get-WinEvent -LogName Security -FilterHashtable @{Id=4688} | Export-Csv C:\IR\ProcessCreation.csv` |
| File rename events | Sysmon Event ID 11 (FileCreate) / ID 2 (FileCreateTime) | `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{Id=11} | Export-Csv C:\IR\FileEvents.csv` |
| Network connections at time of incident | `netstat -anob` | `netstat -anob > C:\IR\netstat.txt` |
| Running processes snapshot | Task Manager / WMIC | `Get-Process | Select Name,Id,Path,StartTime | Export-Csv C:\IR\Processes.csv` |
| Loaded drivers | — | `driverquery /v > C:\IR\Drivers.txt` |

---

### Eradication

> Perform AFTER evidence collection is complete and verified.

- [ ] Remove all files with unknown/ransomware extension in affected directories
  ```powershell
  # After confirming these are test/ransomware artifacts — adjust extension as needed
  Get-ChildItem -Path C:\Users -Recurse -Filter "*.f0rtika" | Remove-Item -Force
  ```
- [ ] Remove ransom note files
  ```powershell
  Get-ChildItem -Path C:\Users -Recurse -Filter "README*.txt" | Select FullName
  # Review list then remove confirmed artifacts
  ```
- [ ] Identify and remove persistence mechanisms (registry run keys, scheduled tasks, services)
  ```powershell
  # Check common persistence locations
  Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
  Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
  Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select TaskName,TaskPath
  Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped' }
  ```
- [ ] Rebuild or reimage if encryption was genuine (not a test scenario)
- [ ] Reset credentials for any accounts that were active on the host during the incident

---

### Recovery

- [ ] Verify all ransomware-dropped artifacts have been removed (second independent review)
- [ ] Restore from last known-good offline backup if any user data was genuinely impacted
- [ ] Re-enable Controlled Folder Access and confirm it is in Block mode
  ```powershell
  Set-MpPreference -EnableControlledFolderAccess Enabled
  Get-MpPreference | Select EnableControlledFolderAccess
  ```
- [ ] Re-enable network connectivity incrementally (test connectivity before full restoration)
- [ ] Re-enable user accounts only after credential reset and MFA re-enrollment
- [ ] Monitor endpoint for 48 hours post-recovery for reinfection indicators
- [ ] Verify backup integrity — confirm the restoration set was not itself encrypted

---

### Post-Incident Review

1. How was the attack detected — behavioral rule, user report, or post-hoc log review?
2. What was the detection-to-containment elapsed time? Target: < 15 minutes.
3. Were Controlled Folder Access and ASR rules active at time of incident?
4. Was the initial access vector identified (phishing, RDP brute-force, supply chain)?
5. Did the adversary delete VSS shadow copies before encryption?
6. What data, if any, was exfiltrated before encryption (double-extortion)?
7. Were offline backups intact and restoration time within RTO targets?
8. What single control, if in place, would have broken the kill chain earliest?

---

## References

| Resource | URL |
|----------|-----|
| MITRE ATT&CK T1486 — Data Encrypted for Impact | https://attack.mitre.org/techniques/T1486/ |
| MITRE ATT&CK T1491.001 — Internal Defacement | https://attack.mitre.org/techniques/T1491/001/ |
| MITRE M1040 — Behavior Prevention on Endpoint | https://attack.mitre.org/mitigations/M1040/ |
| MITRE M1053 — Data Backup | https://attack.mitre.org/mitigations/M1053/ |
| MITRE M1038 — Execution Prevention | https://attack.mitre.org/mitigations/M1038/ |
| CISA StopRansomware Guide | https://www.cisa.gov/stopransomware |
| CISA MS-ISAC Ransomware Guide | https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf |
| Microsoft ASR Rules Reference | https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference |
| Microsoft Controlled Folder Access | https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/controlled-folders |
| CIS Benchmark — Windows 11 v3.0 | https://www.cisecurity.org/benchmark/microsoft_windows_desktop |
| Microsoft Incident Response Ransomware Playbook | https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-ransomware |
