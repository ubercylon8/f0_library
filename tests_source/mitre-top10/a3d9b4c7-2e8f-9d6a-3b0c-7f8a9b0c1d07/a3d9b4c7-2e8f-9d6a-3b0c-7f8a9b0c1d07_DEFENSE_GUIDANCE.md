# Defense Guidance: Pre-Encryption File Enumeration

## Executive Summary

Pre-encryption file enumeration is a critical phase in ransomware and advanced threat actor operations. Before initiating encryption, adversaries perform systematic reconnaissance to identify high-value file types, estimate data volume, and generate ordered target lists. This behavior spans three MITRE ATT&CK techniques: file and directory discovery (T1083), automated collection (T1119), and system information discovery via tools such as Seatbelt (T1082).

The core risk is that native Windows commands (`cmd.exe /c dir /s /b`) and open-source offensive tools (GhostPack Seatbelt) are difficult to block outright — defense must rely on behavioral detection of enumeration velocity and patterns rather than binary blocking alone. Priority actions are enabling file system audit logging, deploying behavioral detection rules for bulk enumeration, and restricting execution of known offensive reconnaissance tools via application control policy.

---

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07 |
| **Test Name** | Pre-Encryption File Enumeration |
| **MITRE ATT&CK** | [T1083](https://attack.mitre.org/techniques/T1083/) — File and Directory Discovery; [T1119](https://attack.mitre.org/techniques/T1119/) — Automated Collection; [T1082](https://attack.mitre.org/techniques/T1082/) — System Information Discovery |
| **Tactics** | Discovery, Collection |
| **Severity** | High |
| **Threat Actor** | Ransomware operators broadly (Conti, BlackCat/ALPHV, LockBit, REvil); APT groups performing pre-exfiltration reconnaissance |
| **Subcategory** | Discovery |
| **Tags** | file-enumeration, system-info, automated-collection, pre-ransomware, seatbelt |

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|------------------------|
| [T1083](https://attack.mitre.org/techniques/T1083/) — File and Directory Discovery | Discovery | No direct technical mitigation exists; detection and least-privilege access controls are primary defenses |
| [T1119](https://attack.mitre.org/techniques/T1119/) — Automated Collection | Collection | M1041 — Encrypt Sensitive Information; M1029 — Remote Data Storage |
| [T1082](https://attack.mitre.org/techniques/T1082/) — System Information Discovery | Discovery | M1028 — Operating System Configuration; no direct block mitigation |

### Mitigation Detail

**M1041 — Encrypt Sensitive Information**
Encrypt sensitive data at rest using BitLocker (full-volume) and EFS (per-file). Even if a threat actor enumerates and reads file metadata, encryption prevents them from assessing content value and complicates ransomware target selection for data exfiltration before encryption.

**M1029 — Remote Data Storage**
Store sensitive data on remote, access-controlled repositories (SharePoint, OneDrive with DLP policies, or file servers with strict ACLs). This limits the blast radius of local file enumeration and concentrates high-value data behind network access controls that can be monitored and throttled.

**M1028 — Operating System Configuration**
Apply OS hardening to reduce system information exposure: restrict WMI access, limit `systeminfo` output to authorized users, configure registry ACLs to prevent enumeration of sensitive keys.

---

## Hardening Recommendations

### Quick Wins (Immediate — Low Operational Impact)

1. **Enable Object Access Auditing** — Turn on Success+Failure auditing for File System object access in Advanced Audit Policy. This generates Event ID 4663 for every file open, enabling detection of bulk enumeration velocity.
2. **Enable Process Creation Auditing with Command Lines** — Audit Policy → Detailed Tracking → Audit Process Creation (Success). Enable `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1` to capture full command-line arguments, making `dir /s /b` enumeration visible in Event ID 4688.
3. **Deploy Windows Defender ASR Rule: Block executable files from running unless they meet prevalence, age, or trusted list criteria** (GUID `01443614-cd74-433a-b99e-2ecdc07bfc25`) — This rule significantly constrains the execution of dropped offensive tools like Seatbelt that lack widespread prevalence.
4. **Add Seatbelt and GhostPack tool hashes to Microsoft Defender custom block indicators** — Use Security Center > Settings > Indicators > File to block known Seatbelt hashes. Obtain current hashes from the GhostPack release page.
5. **Configure Windows Defender PUA (Potentially Unwanted Application) protection in Block mode** — Seatbelt is flagged as a PUA/HackTool by Defender. `Set-MpPreference -PUAProtection Enabled`.

### Medium-Term (1–2 Weeks — Moderate Planning Required)

1. **Deploy AppLocker or WDAC rules** to restrict execution of unsigned or low-prevalence executables. A WDAC policy enforcing "publisher + file name + version" rules prevents Seatbelt from executing even if dropped to disk, because it is unsigned or signed by an untrusted publisher.
2. **Implement folder-level read ACL auditing on sensitive directories** — Apply SACL (System ACL) entries to directories containing financial documents, databases, and backup files. Trigger alerts on bulk SACL hits (>50 files in 60 seconds from a single process).
3. **Restrict `cmd.exe` and `powershell.exe` spawned by non-interactive parent processes** — Many ransomware enumeration chains involve `cmd.exe` spawned by the initial payload. Alert on `cmd.exe /c dir /s /b` spawned by processes outside standard admin tooling.
4. **Enable Microsoft Defender for Endpoint (MDE) Tamper Protection** — Ensures ASR rules, real-time protection, and behavioral blocking cannot be disabled by the threat actor during the enumeration phase.
5. **Deploy Controlled Folder Access (CFA)** — Protect Documents, Desktop, and custom sensitive directories. CFA blocks write access from untrusted processes and can trigger alerts on enumeration-followed-by-write-attempt sequences typical of ransomware.
6. **Implement file classification with Microsoft Purview Information Protection** — Apply sensitivity labels to documents matching ransomware-targeted extensions. Labeled files generate richer telemetry in Defender for Endpoint when enumerated or accessed in bulk.

### Strategic (1–3 Months — Architecture and Policy Planning)

1. **Implement Zero Trust file access model** — Move sensitive documents to SharePoint/OneDrive with Conditional Access policies. Require device compliance + MFA for document access. Network-accessible shares are primary ransomware targets; cloud-based access dramatically reduces local enumeration success.
2. **Deploy a Data Loss Prevention (DLP) solution** — Microsoft Purview DLP or a third-party solution can alert on bulk file access patterns (accessing >100 files with targeted extensions in under 5 minutes) from a single endpoint. This provides pre-encryption detection independent of signature-based tools.
3. **Deploy a Deception/Honeypot layer** — Place canary files (disguised as high-value documents: `employee_salaries_2025.xlsx`, `database_backup.bak`) in commonly enumerated locations. Any process opening these files triggers an immediate high-confidence alert that is not subject to false positives. Solutions: Attivo Networks, Specter, or custom canary tokens.
4. **Integrate EDR telemetry with SIEM for behavioral baselining** — Establish a normal file access velocity baseline per user and per process. Alert on >3 standard deviations of file system activity for any single process in a rolling 5-minute window.
5. **Implement a backup architecture resistant to enumeration-aided ransomware** — Immutable backups (Azure Blob Storage with WORM policy, Veeam with immutability, or AWS S3 Object Lock) ensure that even successful encryption can be fully recovered. Offline air-gapped backups prevent encryption of backup targets discovered during enumeration.

---

## Cross-Platform Hardening Scripts

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07_hardening.ps1` | PowerShell with -Undo support — configures ASR, audit policy, CFA, PUA protection, and AppLocker |

---

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| Recursive directory enumeration | `cmd.exe` with args `/s /b` against user profile or document directories | Medium | P2 |
| Bulk file access velocity | >100 distinct file opens in 60 seconds by a single non-system process (Event ID 4663) | High | P1 |
| Seatbelt binary execution | Process creation of `Seatbelt.exe` OR process with command line containing `-group=all`, `WindowsCredentialFiles`, `WindowsVault`, `InterestingFiles` | High | P1 |
| GhostPack tool hash match | File hash matches known Seatbelt/GhostPack release hashes (Defender alert) | High | P1 |
| Target list file creation | A process writes a file containing a list of file paths with pipe-delimited sizes in a temp/working directory | Medium | P2 |
| Extension-pattern enumeration burst | Multiple `dir /b *.docx`, `dir /b *.xlsx`, `dir /b *.pdf` commands issued within 30 seconds | High | P2 |
| PUA/HackTool detection | Windows Defender raises `HackTool:MSIL/Seatbelt` or similar PUA alert | High | P1 |

### Containment (First 15 Minutes)

- [ ] Isolate the affected endpoint from the network immediately (MDE: `Isolate device` action, or physical network disconnect)
- [ ] Terminate the enumeration process if still running:
  ```powershell
  # Identify and kill the enumeration process
  Get-Process | Where-Object { $_.MainWindowTitle -eq "" -and $_.CPU -gt 10 } | Select Id, Name, CPU, StartTime
  Stop-Process -Id <PID> -Force
  ```
- [ ] Preserve volatile evidence BEFORE any remediation (process list, network connections, open file handles):
  ```powershell
  # Capture volatile state
  Get-Process | Export-Csv C:\IR\processes_$(Get-Date -Format yyyyMMdd_HHmmss).csv
  Get-NetTCPConnection | Export-Csv C:\IR\connections_$(Get-Date -Format yyyyMMdd_HHmmss).csv
  ```
- [ ] Verify whether encryption has begun: check for `.locked`, `.encrypted`, or ransom note files in user directories
  ```powershell
  Get-ChildItem -Path C:\Users -Recurse -Include "*.locked","*DECRYPT*","*RANSOM*" -ErrorAction SilentlyContinue
  ```
- [ ] Snapshot or preserve the Seatbelt binary if present (for forensic hash comparison):
  ```powershell
  Get-FileHash -Path "C:\path\to\Seatbelt.exe" -Algorithm SHA256
  Copy-Item "C:\path\to\Seatbelt.exe" "C:\IR\Seatbelt_evidence.exe"
  ```

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|--------------------|
| Security event log (file access) | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | `wevtutil epl Security C:\IR\Security.evtx` |
| System event log | `%SystemRoot%\System32\winevt\Logs\System.evtx` | `wevtutil epl System C:\IR\System.evtx` |
| Windows Defender operational log | `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx` | `wevtutil epl "Microsoft-Windows-Windows Defender/Operational" C:\IR\Defender.evtx` |
| MDE investigation package | Microsoft Security Center | Download via MDE portal: Devices > [hostname] > Collect investigation package |
| Prefetch files (executed tools) | `%SystemRoot%\Prefetch\` | `Copy-Item C:\Windows\Prefetch\SEATBELT* C:\IR\` |
| Target list file (if created) | Varies (working directory of malware) | `Copy-Item <path>\target_list.txt C:\IR\target_list_evidence.txt` |
| Enumeration output file | Varies (working directory) | `Copy-Item <path>\dir_enumeration_output.txt C:\IR\` |
| MFT (Master File Table) snapshot | Disk-level | `Copy-Item \\.\C: C:\IR\mft.bin` (requires raw disk tools) |
| Running processes at time of alert | Memory | `Get-Process | Export-Csv C:\IR\processes.csv` |
| Scheduled tasks (persistence check) | Registry/Task Scheduler | `schtasks /query /fo LIST /v > C:\IR\scheduled_tasks.txt` |
| Autorun locations (persistence check) | Registry | `reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run C:\IR\run_keys.reg` |

### Investigation Steps

1. **Identify patient zero and initial access vector** — Review Event ID 4624 (logon) and 4648 (explicit credential logon) in the Security log around the time of first enumeration. Correlate with email gateway logs if phishing is suspected.
2. **Determine enumeration scope** — Parse the target list file (if captured) to understand which directories were surveyed. Check `dir_enumeration_output.txt` artifacts.
3. **Assess Seatbelt execution output** — If `seatbelt_groupall_output.txt` or `seatbelt_credentials_output.txt` was found, review for credential harvesting (DPAPI master keys, Windows Vault, browser credentials).
4. **Check for lateral movement indicators** — Successful Seatbelt enumeration (`-group=all`) provides network share, ARP, and DNS cache data to the attacker. Review Event ID 4648 and SMB access logs on adjacent systems.
5. **Determine if encryption has begun** — Check for file extension changes and shadow copy deletion (`vssadmin delete shadows`, Event ID 4688 with `vssadmin` or `wmic shadowcopy delete`).

### Eradication

- [ ] Remove the threat actor binary and any dropped tools (AFTER forensic copy is secured)
  ```powershell
  Remove-Item "C:\path\to\Seatbelt.exe" -Force
  Remove-Item "C:\path\to\target_list.txt" -Force
  ```
- [ ] Remove any persistence mechanisms identified during investigation:
  ```powershell
  # Check and clean scheduled tasks
  Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | Format-List
  # Check registry Run keys
  Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  ```
- [ ] Reset credentials for any accounts whose credential stores were accessed by Seatbelt (Windows Vault, Windows Credential Files)
- [ ] Rotate any service account passwords, API keys, or certificates stored in Windows Credential Manager on the affected host
- [ ] Verify Windows Defender real-time protection and ASR rules are active and not tampered:
  ```powershell
  Get-MpComputerStatus | Select RealTimeProtectionEnabled, AMRunningMode, AntispywareEnabled
  Get-MpPreference | Select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
  ```

### Recovery

- [ ] Verify all enumeration artifacts and threat actor tooling have been removed
- [ ] Re-enable any security controls that were disabled during the attack
- [ ] Restore any modified configurations from known-good baselines
- [ ] Validate ACLs on sensitive directories have not been modified
- [ ] Reconnect isolated endpoint to the network only after above steps are confirmed
- [ ] Monitor for 72 hours post-recovery for signs of re-infection or lateral movement attempts
- [ ] Verify backup integrity and test restore capability for affected directories

### Post-Incident

1. How was the initial detection made — was it signature-based (Seatbelt hash), behavioral (bulk enumeration), or manual investigation? What was the detection-to-containment time?
2. Were any credentials from Windows Vault or Credential Manager successfully retrieved by the attacker before containment? What downstream systems are at risk?
3. Was encryption initiated? If yes, how many files were affected and were backups intact?
4. What controls from the hardening recommendations were NOT in place that would have detected or blocked this activity earlier?
5. Should Controlled Folder Access be enabled for the directories that were enumerated?
6. Should canary/honeypot files be deployed to enable earlier, higher-confidence detection?

---

## Technical Behavior Reference

The test simulates three distinct behavioral patterns that defenders should understand:

**Pattern 1: Native Windows Enumeration (`dir /s /b`)**
Uses `cmd.exe /c dir /s /b <path>` to recursively list all files. This is a completely legitimate Windows command that cannot be blocked without breaking normal operations. Detection must be behavioral: alert on process ancestry (what spawned `cmd.exe`?), command-line arguments (`/s /b` against user-data directories), and execution velocity (repeated invocations within seconds of each other).

**Pattern 2: Extension-Based Filtering**
Issues multiple `dir /b *.<ext>` commands for each targeted extension (.docx, .xlsx, .pdf, .db, .sql, .bak, etc.). The behavioral signature is: a single parent process issuing 15+ `cmd.exe` child processes within 60 seconds, each with a different file extension wildcard pattern. This is not consistent with any legitimate administrative activity.

**Pattern 3: Seatbelt Enumeration (`-group=all`)**
Seatbelt is a well-known GhostPack tool. It performs 60+ enumeration checks including credential store access (Windows Vault, DPAPI keys), security configuration enumeration (AppLocker, Defender, Firewall), network reconnaissance (ARP cache, DNS cache, shares), and browser credential extraction. Defender flags Seatbelt as `HackTool:MSIL/Seatbelt`. Any occurrence of this binary should be treated as a high-confidence indicator of compromise.

---

## References

- [MITRE ATT&CK T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE ATT&CK T1119 — Automated Collection](https://attack.mitre.org/techniques/T1119/)
- [MITRE ATT&CK T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE ATT&CK M1041 — Encrypt Sensitive Information](https://attack.mitre.org/mitigations/M1041/)
- [MITRE ATT&CK M1029 — Remote Data Storage](https://attack.mitre.org/mitigations/M1029/)
- [MITRE ATT&CK M1028 — Operating System Configuration](https://attack.mitre.org/mitigations/M1028/)
- [GhostPack Seatbelt — GitHub](https://github.com/GhostPack/Seatbelt)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)
- [CISA Alert AA21-265A — Conti Ransomware TTPs](https://www.cisa.gov/uscert/ncas/alerts/aa21-265a)
- [Microsoft WDAC Policy Wizard](https://webapp-wdac-wizard.azurewebsites.net/)
- [CIS Benchmark for Windows 10/11 — Section 9 (Windows Defender)](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft ASR Rules Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft Controlled Folder Access Documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/controlled-folders)
- [Microsoft Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
