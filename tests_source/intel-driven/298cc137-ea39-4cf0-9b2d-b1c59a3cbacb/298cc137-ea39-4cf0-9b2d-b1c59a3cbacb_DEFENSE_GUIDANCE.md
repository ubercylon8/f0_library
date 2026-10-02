# Defense Guidance: LockBit 3.0 Double Extortion Kill Chain (SB-PC-2026-001)

## Executive Summary

This document provides defense, hardening, and incident-response guidance for the LockBit 3.0 double-extortion kill chain defined by Superintendencia de Bancos supervisory package **SB-PC-2026-001 (Arquetipo A — Ransomware con doble extorsión)** for the Dominican financial sector. It is written for financial-institution CISOs, SOC leads, and infrastructure security teams who must demonstrate — under continuous testing — that a single compromised workstation cannot be converted into a full double-extortion event.

LockBit 3.0 (LockBit Black) remains the most prolific ransomware-as-a-service operation targeting financial institutions globally (CISA AA23-075A / AA23-165A). Its affiliate playbook is deliberately unspectacular: it wins by abusing **built-in Windows tooling and legitimate administration primitives** — PowerShell, `sc.exe`, `Set-MpPreference`, `rundll32 comsvcs.dll`, `reg.exe save`, ADMIN$ shares, rclone/MEGA for exfiltration, and `vssadmin`/`bcdedit`/`wevtutil` for recovery inhibition — rather than exotic exploits. Every stage of the emulated kill chain below is something your institution already has the native capability to prevent or detect; the question this test answers is whether those capabilities are actually configured.

**Key findings the kill chain evaluates:**

1. **Defense degradation is the opening move.** Before touching data, LockBit disables Defender real-time monitoring, stops security services (`WinDefend`, `WdNisSvc`, `Sense`, `EventLog`), and writes the `DisableAntiSpyware` policy value. If Tamper Protection and service ACLs are not enforced, the entire downstream sensor stack goes blind in seconds.
2. **Credential access is one LOLBin away.** `rundll32.exe comsvcs.dll, MiniDump <lsass_pid> dump.dmp full` and `reg.exe save HKLM\SAM` are the documented LockBit credential primitives. LSA Protection (RunAsPPL) and Credential Guard break the first; SeBackupPrivilege auditing and restricted SAM ACLs expose the second.
3. **Lateral movement rides administrative shares.** LockBit copies payloads to `ADMIN$` of file/database servers. SMB signing enforcement, admin-share restrictions, and workstation-to-server segmentation collapse this stage.
4. **Exfiltration precedes encryption (double extortion).** Data is staged, archived, and pushed to cloud storage with rclone-style tooling *before* any file is encrypted. Egress filtering and exfil-tool execution control are the only chances to prevent the regulatory-reportable data breach even if encryption later fails.
5. **Impact is designed to be unrecoverable.** Mass AES encryption is paired with shadow-copy deletion, boot-recovery tampering, and event-log clearing. Controlled Folder Access, ASR ransomware rules, protected/immutable backups, and forwarded logs are the difference between an incident and a catastrophe.

**Priority recommendations:** enable Defender Tamper Protection tenant-wide; enforce RunAsPPL + Credential Guard on all endpoints and servers; deploy the ASR rule set (LSASS credential stealing, ransomware protection, obfuscated scripts, PSExec/WMI process creation); enable PowerShell Script Block Logging with central forwarding; require SMB signing and disable legacy admin shares on workstations; enforce egress filtering with explicit cloud-storage exfil tooling blocks; and enable Controlled Folder Access with ransomware canaries. The companion script `298cc137-ea39-4cf0-9b2d-b1c59a3cbacb_hardening.ps1` implements the endpoint-local subset of these controls idempotently with full rollback.

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | 298cc137-ea39-4cf0-9b2d-b1c59a3cbacb |
| **Test Name** | LockBit 3.0 Double Extortion Kill Chain (SB-PC-2026-001) |
| **MITRE ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1112](https://attack.mitre.org/techniques/T1112/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1570](https://attack.mitre.org/techniques/T1570/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1486](https://attack.mitre.org/techniques/T1486/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1070.001](https://attack.mitre.org/techniques/T1070/001/) |
| **Severity** | Critical |
| **Threat Actor** | LockBit 3.0 (LockBit Black RaaS) |
| **Subcategory** | Ransomware / Double Extortion |
| **Platform** | Windows endpoint |
| **Regulatory Context** | SB-PC-2026-001 — Superintendencia de Bancos (República Dominicana) continuous-testing package, Arquetipo A |

### Emulated Kill Chain (as implemented in the test)

| Stage | Objective (SB-PC-2026-001) | Simulated Behaviors |
|-------|---------------------------|---------------------|
| 1 | Ejecución y degradación de defensas | PowerShell recon with `-ExecutionPolicy Bypass` (AV enumeration via `root\SecurityCenter2`); `sc.exe stop`/`config start= disabled` on `WinDefend`, `WdNisSvc`, `Sense`, `EventLog`; `Set-MpPreference -DisableRealtimeMonitoring $true`; `HKLM\...\Windows Defender\DisableAntiSpyware=1` write |
| 2 | Acceso a credenciales privilegiadas | `OpenProcess(lsass, PROCESS_VM_READ)`; `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> lsass.dmp full`; `reg.exe save HKLM\SAM sam.save` |
| 3 | Movimiento lateral y propagación | `net use \\host\ADMIN$` session; tool drop into `ADMIN$\Temp` (SMB write) |
| 4 | Exfiltración previa al cifrado | PII staging (~2 MB CSVs), `Compress-Archive`, HTTP POST with `rclone/v1.61.1` User-Agent and cloud-upload headers (`X-Remote-Path: /stolen_data/customers/`, Bearer token) |
| 5 | Impacto por cifrado y bloqueo de recuperación | Mass AES-256 encryption with `.lockbit` extension; `Restore-My-Files.txt` ransom note; `vssadmin delete shadows`, `bcdedit /set ... recoveryenabled no` (wbadmin catalog deletion documented as the real-world third primitive); `wevtutil cl` log clearing |

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|------------------------|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — PowerShell | Execution | [M1042](https://attack.mitre.org/mitigations/M1042/) Disable/Remove Feature, [M1045](https://attack.mitre.org/mitigations/M1045/) Code Signing, [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention (AppLocker/WDAC/Constrained Language Mode) |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) — Disable or Modify Tools | Defense Evasion | [M1018](https://attack.mitre.org/mitigations/M1018/) User Account Management, [M1022](https://attack.mitre.org/mitigations/M1022/) Restrict File and Directory Permissions (service ACLs), [M1024](https://attack.mitre.org/mitigations/M1024/) Restrict Registry Permissions, [M1047](https://attack.mitre.org/mitigations/M1047/) Audit, [M1054](https://attack.mitre.org/mitigations/M1054/) Software Configuration (Tamper Protection) |
| [T1112](https://attack.mitre.org/techniques/T1112/) — Modify Registry | Defense Evasion | [M1024](https://attack.mitre.org/mitigations/M1024/) Restrict Registry Permissions, [M1047](https://attack.mitre.org/mitigations/M1047/) Audit |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) — LSASS Memory | Credential Access | [M1043](https://attack.mitre.org/mitigations/M1043/) Credential Access Protection (Credential Guard), [M1028](https://attack.mitre.org/mitigations/M1028/) Operating System Configuration (RunAsPPL), [M1025](https://attack.mitre.org/mitigations/M1025/) Privileged Process Integrity, [M1026](https://attack.mitre.org/mitigations/M1026/) Privileged Account Management, [M1040](https://attack.mitre.org/mitigations/M1040/) Behavior Prevention on Endpoint (ASR LSASS rule) |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) — Security Account Manager | Credential Access | [M1026](https://attack.mitre.org/mitigations/M1026/) Privileged Account Management, [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies (LSA secrets hardening), [M1022](https://attack.mitre.org/mitigations/M1022/) Restrict File and Directory Permissions (SAM ACL / RestrictRemoteSAM), [M1047](https://attack.mitre.org/mitigations/M1047/) Audit (Sensitive Privilege Use) |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) — SMB/Windows Admin Shares | Lateral Movement | [M1030](https://attack.mitre.org/mitigations/M1030/) Network Segmentation, [M1035](https://attack.mitre.org/mitigations/M1035/) Limit Access to Resource Over Network, [M1037](https://attack.mitre.org/mitigations/M1037/) Filter Network Traffic, [M1026](https://attack.mitre.org/mitigations/M1026/) Privileged Account Management, [M1042](https://attack.mitre.org/mitigations/M1042/) Disable or Remove Feature (admin shares) |
| [T1570](https://attack.mitre.org/techniques/T1570/) — Lateral Tool Transfer | Lateral Movement | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1037](https://attack.mitre.org/mitigations/M1037/) Filter Network Traffic, [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) — Exfiltration to Cloud Storage | Exfiltration | [M1021](https://attack.mitre.org/mitigations/M1021/) Restrict Web-Based Content, [M1037](https://attack.mitre.org/mitigations/M1037/) Filter Network Traffic (egress filtering), [M1020](https://attack.mitre.org/mitigations/M1020/) SSL/TLS Inspection |
| [T1486](https://attack.mitre.org/techniques/T1486/) — Data Encrypted for Impact | Impact | [M1040](https://attack.mitre.org/mitigations/M1040/) Behavior Prevention on Endpoint (ASR ransomware rule, Controlled Folder Access), [M1053](https://attack.mitre.org/mitigations/M1053/) Data Backup, [M1041](https://attack.mitre.org/mitigations/M1041/) Encrypt Sensitive Information |
| [T1490](https://attack.mitre.org/techniques/T1490/) — Inhibit System Recovery | Impact | [M1028](https://attack.mitre.org/mitigations/M1028/) Operating System Configuration, [M1053](https://attack.mitre.org/mitigations/M1053/) Data Backup (offline/immutable), [M1041](https://attack.mitre.org/mitigations/M1041/) Encrypt Sensitive Information, [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention (restrict vssadmin/wbadmin/bcdedit) |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) — Clear Windows Event Logs | Defense Evasion | [M1022](https://attack.mitre.org/mitigations/M1022/) Restrict File and Directory Permissions, [M1029](https://attack.mitre.org/mitigations/M1029/) Remote Data Storage (log forwarding), [M1047](https://attack.mitre.org/mitigations/M1047/) Audit (1102 alerting) |

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact)

1. **Enable PowerShell Script Block Logging + Module Logging** via GPO (`Computer Config → Admin Templates → Windows Components → Windows PowerShell`): *Turn on PowerShell Script Block Logging*, *Turn on Module Logging* (`*`). Ships 4104/4103 events — the single highest-value telemetry source for stage 1 and stage 4 (`Compress-Archive`) behavior. Implemented in the companion script.
2. **Verify Defender Tamper Protection is ON tenant-wide** (Microsoft Defender portal → Settings → Endpoints → Advanced features). Tamper Protection is what actually blocks `Set-MpPreference -DisableRealtimeMonitoring`, `DisableAntiSpyware`, and `sc stop WinDefend` from an elevated attacker. The companion script audits and alerts if it is off (it cannot be enabled by script — it must be set in the portal/Intune).
3. **Enforce Defender real-time, behavior, script (AMSI), and IOAV scanning** and delete any `DisableAntiSpyware` policy value. Implemented in the companion script.
4. **Set execution policy to RemoteSigned** (LocalMachine) and audit for `-ExecutionPolicy Bypass` command lines. Low prevention value alone, but raises the bar and generates policy-violation evidence.
5. **Enable process command-line auditing** (`ProcessCreationIncludeCmdLine_Enabled=1` + Audit Process Creation) — required to see `rundll32 comsvcs.dll MiniDump`, `vssadmin delete shadows`, `wevtutil cl` in 4688 events.
6. **Enable Sensitive Privilege Use auditing** — fires on `reg.exe save HKLM\SAM` (SeBackupPrivilege) even when it succeeds.
7. **Enable core ASR rules in Block mode** (staged via Audit first if needed):
   - `9e6c4e1f-7d60-472a-bbaa-a39f66977d63` — Block credential stealing from LSASS (breaks stage 2 outright)
   - `c1db55ab-c21a-4637-bb3f-a12568109d35` — Use advanced protection against ransomware (stage 5)
   - `5beb7efe-fd9a-4556-801d-275e5ffc04cc` — Block execution of potentially obfuscated scripts (stage 1)
   - `d1e49aac-8f56-4280-b9ba-993a6d77406c` — Block process creations originating from PSExec and WMI commands (stage 3 execution follow-on)
   - `e6db77e5-3df2-4cf1-b95a-636979351e5b` — Block persistence through WMI event subscription
   All implemented in the companion script.
8. **Alert on Security event 1102 (log cleared) and System 104 (EventLog service cleared)** — `wevtutil cl` is the pre-impact signature; forwarding must be in place first so the alert survives the clear.

### Medium-Term (1–2 Weeks — Medium Impact)

1. **Enable LSA Protection (RunAsPPL=1)** on all endpoints/servers (reboot required; pilot against legacy auth plugins first — see MS guidance on the `RunAsPPLBoot` audit mode). Combined with the ASR LSASS rule, this reduces stage 2 to handle-denial events. Implemented in the companion script.
2. **Enable Credential Guard (VBS + LsaCfgFlags=1, UEFI lock=2)** on supported hardware (UEFI, Secure Boot, IOMMU). Protects domain credentials even if LSASS memory is read. Optional in the companion script (`-EnableCredentialGuard`).
3. **Harden SAM/LSA**: `RestrictRemoteSAM` SDDL (`O:BAG:BAD:(A;;RC;;;BA)`), `LmCompatibilityLevel=5`, `NoLMHash=1`, `disabledomaincreds=1` on servers that do not need cached logons. Implemented in the companion script.
4. **SMB controls**: require SMB signing on client and server (`RequireSecuritySignature=1`), disable SMBv1, and disable workstation admin shares (`AutoShareWks=0`) where management tooling permits — LockBit's `ADMIN$` copy primitive depends on them. Restrict inbound 445 on workstations to management subnets via Windows Firewall. Implemented in the companion script (share suppression is opt-in via `-DisableAdminShares`; subnet restriction via `-AllowedSMBSubnet`).
5. **Egress filtering**: default-deny outbound from servers and teller/back-office segments to the internet; allowlist required destinations through the proxy. Block/alert on exfil-tool execution (`rclone.exe`, `megacmd`, `MEGAsync`, `winscp`, `filezilla`) via AppLocker deny rules for standard users, and alert on rclone/MEGA User-Agents and domains at the proxy. The companion script deploys an AppLocker policy (audit mode by default, `-AppLockerMode Enforce` to block) covering exfil tools plus recovery/log-tamper LOLBins (`vssadmin`, `wbadmin`, `bcdedit`, `wevtutil`) for non-admin users.
6. **Controlled Folder Access in Block mode** with protected folders covering shares holding customer data, plus deployed ransomware canaries with write-auditing SACLs. Implemented in the companion script (`-EnableCFA` / canaries on by default).
7. **Centralize log forwarding (WEF/Winlogbeat/Splunk UF)** for Security, System, PowerShell/Operational, and Defender channels so `wevtutil cl` cannot destroy evidence. The companion script can configure a source-initiated WEF subscription manager (`-SubscriptionManagerUrl`) and enlarges/hardens local logs.
8. **Protect security services** with restrictive service ACLs (deny stop/change to non-SYSTEM) on `WinDefend`, `WdNisSvc`, `Sense`, `EventLog`, and enforce their start types. Implemented in the companion script with original SDDLs backed up for rollback.

### Strategic (1–3 Months — Requires Planning)

1. **WDAC or enforced AppLocker application control** on all endpoints: allow only signed/approved binaries; blocks unsigned stage payloads, renamed rclone, and LOLBin abuse paths that ASR cannot cover (e.g., `rundll32 comsvcs.dll MiniDump` — pair with the LSASS ASR rule). Start in audit, enforce per-ring.
2. **Tiered administration + privileged access workstations (PAWs)**: no domain-admin logon to endpoints; LAPS for local admin; kills the credential-reuse path from stage 2 into stage 3.
3. **Network segmentation between workstation, server, and core banking segments** with host-firewall default-deny east-west; a workstation should never reach `ADMIN$` on a server directly.
4. **Immutable/offline backups** (air-gap, WORM, or object-lock) for core banking, file, and backup infrastructure itself — the only control that survives successful `vssadmin`/`wbadmin` tampering. Test restoration quarterly; document RTO/RPO for the SB.
5. **DLP + cloud-app governance (CASB)**: classify customer PII, alert/block bulk archive creation followed by upload, and block unsanctioned cloud storage (MEGA, rclone-reachable endpoints) at the network layer.
6. **Deception grid**: canary credentials (honeytokens in LSASS-reachable stores), canary file shares, and decoy documents wired to P1 alerts — high-fidelity, near-zero false positives.
7. **Regular adversary-emulation validation**: rerun this SB-PC-2026-001 kill chain (and sibling archetypes) after every control change; track stage-level block rates as the board-level KPI for ransomware readiness.

## Hardening Scripts

> **Note:** Only scripts for the test's target platform(s) are included. This is a Windows-endpoint test — no Linux/macOS scripts are provided.

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `298cc137-ea39-4cf0-9b2d-b1c59a3cbacb_hardening.ps1` | Idempotent PowerShell hardening with `-WhatIf` preview and `-Undo` rollback (state captured in `%ProgramData%\EndpointBaselineHardening`) |

The script is production-ready and tool-agnostic: it contains **no references to the test, its paths, or its binaries** — every control targets the underlying technique (service ACLs, ASR, RunAsPPL, SMB policy, AppLocker LOLBin rules, log forwarding, canaries), so it protects against any actor using the same playbook.

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| Defender RTP tampering | PowerShell 4104 / 4688 containing `Set-MpPreference` with `-DisableRealtimeMonitoring`, `-DisableBehaviorMonitoring`, `-DisableScriptScanning`; or registry write to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` | High | P1 |
| Security-service stop/disable | 4688: `sc.exe (stop|config)` against `WinDefend`, `WdNisSvc`, `Sense`, `EventLog`; System 7036 stop events for these services not tied to patching | High | P1 |
| Recon PowerShell | 4688: `powershell.exe -ExecutionPolicy Bypass` from non-management parent; 4104 with `SecurityCenter2` + `AntiVirusProduct` | Medium | P2 |
| LSASS memory access | Sysmon EID 10 (GrantedAccess 0x1010/0x1FFFFF) to `lsass.exe` from non-approved binary; 4688: `rundll32.exe` with `comsvcs.dll` and `MiniDump`; ASR LSASS block event (Defender 1121/1122, rule `9e6c4e1f…`) | High | P1 |
| SAM hive extraction | 4688: `reg.exe save HKLM\SAM`; 4674/4663 Sensitive Privilege Use (SeBackupPrivilege) by unusual account; new file `sam.save`/`*.sam` in temp dirs | High | P1 |
| ADMIN$ lateral session | Security 4624 type 3 + 5140/5145 to `ADMIN$` from workstation sources; 4688: `net use \\*\ADMIN$`; new file write under `ADMIN$\Temp` | Medium-High | P2 |
| Lateral tool drop | Sysmon EID 11 file create in `\\*\ADMIN$\Temp\*.exe`; unsigned binary appearing on server within minutes of 5145 | High | P1 |
| Cloud exfil tooling | Proxy/DNS: `rclone/*` User-Agent, MEGA/unsanctioned storage domains; process execution of `rclone.exe`, `megacmd.exe` (AppLocker 8003/8004); large outbound POST from a server/workstation with no business proxy path | High | P2 |
| Bulk staging + archive | 4104/4688: `Compress-Archive` over user/share directories; rapid creation of multi-MB `.zip`/`.7z` in temp followed by network egress | Medium | P2 |
| Mass encryption | High file-rename velocity to uniform extension (`.lockbit`); entropy spike on writes; `Restore-My-Files.txt` creation; canary file modification (Security 4663 on canary paths); CFA block events (Defender 1123/1124) | High | P1 |
| Recovery inhibition | 4688: `vssadmin delete shadows`, `vssadmin resize shadowstorage`, `wbadmin delete catalog`/`delete systemstatebackup`, `bcdedit` with `recoveryenabled no` / `bootstatuspolicy ignoreallfailures` | High | P1 |
| Event-log clearing | Security 1102, System 104 (EventLog); 4688: `wevtutil cl` | High | P1 |

### Containment (First 15 Minutes)

- [ ] **Isolate affected host(s)** — MDE: `Invoke-MdeMachineIsolate` / Defender portal *Isolate device*; or cut the NIC while preserving RAM:
  ```powershell
  Disable-NetAdapter -Name "*" -Confirm:$false   # last resort, local console only
  ```
- [ ] **Block lateral spread** — temporarily deny inbound SMB on at-risk servers:
  ```powershell
  New-NetFirewallRule -DisplayName "IR-BLOCK-SMB-IN" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block
  ```
- [ ] **Suspend the attacker account(s)** identified in 4624/5140/5145 telemetry:
  ```powershell
  Disable-ADAccount -Identity <samAccountName>
  ```
- [ ] **Kill malicious processes** (only after volatile capture below, if time permits):
  ```powershell
  Get-Process | Where-Object {$_.Path -match 'rundll32|powershell'} | Stop-Process -Force
  ```
- [ ] **Preserve volatile evidence before reboot**: running processes, network connections, logon sessions:
  ```powershell
  Get-Process | Export-Clixml C:\IR\processes.xml
  Get-NetTCPConnection | Export-Csv C:\IR\netconn.csv
  qwinsta > C:\IR\sessions.txt
  ```

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Security log | System | `wevtutil epl Security C:\IR\Security.evtx` |
| System log | System | `wevtutil epl System C:\IR\System.evtx` |
| PowerShell Operational | Microsoft-Windows-PowerShell/Operational | `wevtutil epl Microsoft-Windows-PowerShell/Operational C:\IR\PS-Operational.evtx` |
| Defender Operational | Microsoft-Windows-Windows Defender/Operational | `wevtutil epl Microsoft-Windows-Windows Defender/Operational C:\IR\Defender.evtx` |
| Sysmon (if deployed) | Microsoft-Windows-Sysmon/Operational | `wevtutil epl Microsoft-Windows-Sysmon/Operational C:\IR\Sysmon.evtx` |
| SMB file-access audit | Security 5140/5145 subset | `wevtutil qe Security /q:"*[System[(EventID=5140 or EventID=5145)]]" /f:text > C:\IR\smb-access.txt` |
| Scheduled tasks / persistence | System | `schtasks /query /v /fo csv > C:\IR\tasks.csv; Get-CimInstance Win32_StartupCommand \| Export-Csv C:\IR\startup.csv` |
| Shadow copy inventory | System | `vssadmin list shadows > C:\IR\shadows.txt; vssadmin list providers >> C:\IR\shadows.txt` |
| Memory image (if credential theft suspected) | RAM | `winpmem` / MAGNET RAM Capture to external media |
| Ransom note(s) + encrypted samples | Affected dirs | Copy (do not open) one `.lockbit` sample + note to IR media |
| Recent prefetch / AmCache | System | `copy C:\Windows\Prefetch\*.pf C:\IR\prefetch\` |

### Eradication

- Remove attacker tooling and lateral-transfer payloads (AFTER evidence collection):
  ```powershell
  Get-ChildItem \\<server>\ADMIN$\Temp -Include *.exe -Recurse | Remove-Item -Force
  ```
- Clean registry tampering and restore Defender policy state:
  ```powershell
  Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -ErrorAction SilentlyContinue
  Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false
  ```
- Restore security services to proper start type and start them:
  ```powershell
  Set-Service WinDefend,WdNisSvc,Sense -StartupType Automatic
  Start-Service WinDefend,WdNisSvc,Sense,EventLog
  ```
- Remove persistence: audit services (`Get-CimInstance Win32_Service | ? PathName -notmatch 'system32|program files'`), run keys, scheduled tasks created in the incident window.
- **Reset all credentials that touched affected hosts** (KRBTGT twice if domain controllers or Tier-0 assets were reachable; LAPS-rotate local admins).

### Recovery

- [ ] Verify no `.lockbit`/ransom artifacts remain; confirm encryption scope from canary + file-server telemetry.
- [ ] Restore encrypted data from **offline/immutable backups** — never trust on-host shadow copies (`vssadmin list shadows` to confirm scope of T1490 damage).
- [ ] Repair boot configuration if tampered: `bcdedit /set {current} recoveryenabled yes`, `reagentc /enable`.
- [ ] Re-enable/repair security controls; run the companion hardening script to re-baseline, then verify with a control rerun of the emulation.
- [ ] Confirm log forwarding resumes (check WEF source: `wecutil es` on collector; verify events arrive post-recovery).
- [ ] Reconnect to network in a monitored VLAN; observe for 48–72 h before full rejoin.
- [ ] **Regulatory notification**: evaluate SB (Superintendencia de Bancos) incident-reporting obligations and data-breach notification duties given the confirmed exfiltration stage.

### Post-Incident

1. How was the attack detected — which stage, which control, which event ID? Which stages produced NO alert?
2. What was detection-to-response time at each stage (goal: P1 trigger → containment < 15 min)?
3. What would have prevented this stage outright (map back to the Quick Wins / Medium-Term tables)?
4. Were backups immutable and restorable — time to restore a representative dataset?
5. Did forwarded logs survive the `wevtutil cl` attempt — was Security 1102 received centrally?
6. Which hardening-script controls would have flipped the test from 101 (unprotected) to 126 (prevented), and what is the rollout plan/date for each?

## References

- MITRE ATT&CK techniques: [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1112](https://attack.mitre.org/techniques/T1112/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1570](https://attack.mitre.org/techniques/T1570/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1486](https://attack.mitre.org/techniques/T1486/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- CISA #StopRansomware: [LockBit 3.0 (AA23-075A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a), [LockBit update (AA23-165A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a)
- Microsoft: [LSA Protection / RunAsPPL](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection), [Credential Guard](https://learn.microsoft.com/windows/security/identity-protection/credential-guard/), [ASR rules reference](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference), [Controlled Folder Access](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/controlled-folders), [Tamper Protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
- CIS Benchmarks: Microsoft Windows 11 Enterprise — Sections 2.3 (Security Options), 17 (Advanced Audit Policy), 18.9 (Administrative Templates: Defender, PowerShell, SMB, Event Log)
- Superintendencia de Bancos (RD): SB-PC-2026-001 continuous-testing package (internal supervisory document)
