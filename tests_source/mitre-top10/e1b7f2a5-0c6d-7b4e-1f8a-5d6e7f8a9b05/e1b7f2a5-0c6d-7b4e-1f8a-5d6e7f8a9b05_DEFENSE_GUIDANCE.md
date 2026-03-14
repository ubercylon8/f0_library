# Defense Guidance: System Recovery Inhibition (Safe Mode)

## Executive Summary

T1490 (Inhibit System Recovery) is the defining final preparation step executed by virtually every modern ransomware family before payload deployment. Attackers use built-in Windows administration tools — vssadmin.exe, bcdedit.exe, wbadmin.exe, and wmic.exe — to silently destroy Volume Shadow Copies, disable Windows Recovery Environment, and erase backup catalogs. Once these recovery anchors are gone, victims have no path to self-recovery without paying the ransom or restoring from an offline backup.

The key defensive insight is that these binaries are legitimate system tools that have almost no valid non-administrative, non-automated use case for deleting recovery data. Any process invoking them with destructive arguments outside a documented change window should be treated as a high-confidence ransomware indicator.

Priority actions: enable VSS protected-process enforcement (Windows Server 2022+ / Windows 11), deploy ASR rule for credential theft from LSASS, apply WDAC rules restricting volume shadow administration to managed processes, and ensure immutable or offline backup copies exist that cannot be reached from an internet-connected endpoint.

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05 |
| **Test Name** | System Recovery Inhibition (Safe Mode) |
| **MITRE ATT&CK** | [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) |
| **Tactic** | Impact |
| **Severity** | Critical |
| **Threat Actor** | Ransomware-generic (LockBit, Conti, REvil, Ryuk, BlackCat/ALPHV, BlackBasta, Hive, Royal, Play) |
| **Affected Platform** | Windows (all versions with VSS) |
| **Test Mode** | Safe / Read-Only |

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|----------------------|
| [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) | Impact | M1053 — Data Backup; M1028 — Operating System Configuration; M1024 — Restrict Registry Permissions; M1018 — User Account Management |

### Mitigation Details

| M-Code | Name | Relevance to T1490 |
|--------|------|--------------------|
| M1053 | Data Backup | Offline/immutable backups are the primary recovery control when shadow copies are destroyed |
| M1028 | Operating System Configuration | Restricting vssadmin, bcdedit, wbadmin via WDAC, AppLocker, or attack surface reduction rules |
| M1024 | Restrict Registry Permissions | Protecting the BCD store (HKLM\BCD00000000) from unauthorized modification |
| M1018 | User Account Management | Limiting which accounts can execute shadow copy administration and BCD modification |

## What the Test Reveals

The test exercises the exact reconnaissance path a ransomware operator uses before issuing destructive commands:

1. Confirms vssadmin.exe, bcdedit.exe, and wbadmin.exe are present and executable from the current context.
2. Runs read-only queries (`vssadmin list shadows`, `bcdedit /enum`, `wbadmin get versions`) to enumerate recovery posture.
3. Documents the destructive follow-on commands the operator would issue (not executed by the test).

**If the test returns exit code 101 (Unprotected):** All three recovery tools are accessible with no EDR intervention. The endpoint is fully exposed to T1490. A ransomware process running as admin would have unobstructed access to destroy every local recovery path within seconds.

**If the test returns exit code 126 (Protected):** The EDR blocked at least one read-only query, demonstrating behavioral monitoring of recovery tool access.

## Hardening Recommendations

### Quick Wins (Immediate — Low Operational Impact)

1. **Enable VSS protection auditing** — Create an audit rule for any process spawning vssadmin.exe, bcdedit.exe, or wbadmin.exe from a non-system parent. This produces telemetry with zero operational disruption.
2. **Set VSS writer protection via registry** — On Windows Server 2022 and Windows 11 22H2+, enable the `VSSProtection` feature flag that prevents non-VSS-framework processes from deleting shadow copies.
3. **Enforce audit logging for Volume Shadow Copy Service events** — Ensure the Application event log retains VSS event IDs 8193, 8194, 8228, and 8229. Set the log to 50 MB minimum and enable forwarding to SIEM.
4. **Apply the Microsoft recommended block rule for wmic.exe** — Add a WDAC deny rule for `wmic shadowcopy delete` argument pattern. The WDAC Wizard generates this without code-signing infrastructure.
5. **Enable Attack Surface Reduction rule: Block credential stealing from LSASS** — While targeting a different technique, ASR deployment validates that the Defender ASR engine is active, a prerequisite for several recovery-focused ASR improvements coming in future Windows builds.

### Medium-Term (1–2 Weeks — Moderate Implementation Effort)

1. **Deploy WDAC policy restricting shadow copy administration** — Author a supplemental WDAC policy that limits execution of vssadmin.exe, wbadmin.exe, and bcdedit.exe to code-signed processes in the managed software catalog. Use audit mode for two weeks before enforcement.
2. **Configure Windows Defender Controlled Folder Access** — Enable CFA for system recovery directories: `%SystemDrive%\System Volume Information`, `%SystemRoot%\System32\config\BCD-Template`. This blocks untrusted processes from writing to these locations.
3. **Implement PowerShell Constrained Language Mode** — Prevents PowerShell-based shadow deletion wrappers (`Get-WmiObject Win32_Shadowcopy | Remove-WmiObject`) that bypass command-line-based detections.
4. **Create a dedicated backup service account with MFA** — Revoke backup-operator rights from general admin accounts. Require Privileged Identity Management (PIM) or PAM elevation with MFA to access backup administration. Log all elevations.
5. **Enable Windows Event Forwarding for process creation events (Event ID 4688)** — Ensure process command-line auditing is enabled (`Audit Process Creation` = Success + Failure; `Include command line in process creation events` = Enabled via GPO). Forward to central SIEM.
6. **Segment backup infrastructure** — Ensure backup agents run on a separate VLAN that is not reachable from production endpoints. Backup targets should only accept push connections from the backup server, never pull from endpoints.

### Strategic (1–3 Months — Requires Architecture Planning)

1. **Implement immutable backup snapshots** — Transition primary backups to an immutable storage tier (Azure Immutable Blob Storage with WORM lock, AWS S3 Object Lock, or Veeam immutability mode). Immutability must survive the loss of all domain admin credentials.
2. **Deploy Microsoft's Protected Users group and credential guard** — Reduces lateral movement capability that ransomware operators use to elevate to Domain Admin before running recovery inhibition at scale across the environment.
3. **Adopt the 3-2-1-1-0 backup rule** — 3 copies, 2 media types, 1 offsite, 1 offline/air-gapped, 0 backup errors verified by automated restore testing monthly.
4. **Pilot Microsoft Pluton or equivalent TPM-backed BCD integrity measurement** — On compatible hardware (Surface, newer OEM designs), enable Secure Boot with measured boot and remote attestation. Unauthorized bcdedit changes will be detected at pre-OS layer.
5. **Conduct tabletop exercise for ransomware recovery scenario** — Validate that the incident response plan covers the specific case where all local shadow copies and backup catalogs are destroyed. Measure actual RTO/RPO against the offline backup tier.

## Windows Hardening Script

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05_hardening.ps1` | PowerShell with -Undo support — hardens VSS, bcdedit, wbadmin access controls, audit policy, and CFA |

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| Shadow Copy Deletion Attempt | vssadmin.exe spawned with `delete` in command line | Critical | P1 |
| BCD Recovery Disabled | bcdedit.exe spawned with `recoveryenabled No` | Critical | P1 |
| Backup Catalog Destruction | wbadmin.exe spawned with `delete catalog` or `delete systemstatebackup` | Critical | P1 |
| WMI Shadow Delete | wmic.exe spawned with `shadowcopy` and `delete` arguments | Critical | P1 |
| VSS Service Stopped | Service Control Manager Event 7036 — VSS service state change to Stopped | High | P1 |
| Abnormal vssadmin Parent | vssadmin.exe, bcdedit.exe, or wbadmin.exe spawned by cmd.exe, PowerShell, or a non-system process | High | P2 |
| Shadow Storage Resize | vssadmin.exe spawned with `resize shadowstorage` and small maxsize value | High | P2 |
| Recovery Tool Read-Only Recon | vssadmin `list shadows`, bcdedit `/enum`, or wbadmin `get versions` from non-admin tooling parent | Medium | P3 |

### Containment (First 15 Minutes)

- [ ] Isolate the affected host from the network at the switch/EDR level — **do not shut down** (preserves volatile memory for forensics).
- [ ] Confirm whether shadow copies still exist: `vssadmin list shadows` from a trusted admin workstation via PSRemoting.
- [ ] Suspend the process tree of the suspicious parent process (do not terminate — preserve handle/memory state for forensics).
- [ ] Revoke the credential token of any user account seen in the process execution chain — force Kerberos ticket invalidation: `klist purge` and reset the password from a clean admin station.
- [ ] Block lateral movement: quarantine the host in EDR, apply network micro-segmentation ACL to cut all SMB/RPC/WMI outbound from the host.
- [ ] Alert backup infrastructure team — verify that backup targets are not currently mounted or accessible from the affected host.

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|--------------------|
| Security event log | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | `wevtutil epl Security C:\IR\Security.evtx` |
| Application event log (VSS events) | `%SystemRoot%\System32\winevt\Logs\Application.evtx` | `wevtutil epl Application C:\IR\Application.evtx` |
| System event log | `%SystemRoot%\System32\winevt\Logs\System.evtx` | `wevtutil epl System C:\IR\System.evtx` |
| Current shadow copy inventory | Volume Shadow Copy Service | `vssadmin list shadows > C:\IR\shadows_current.txt` |
| BCD current configuration | Boot Configuration Data | `bcdedit /enum all > C:\IR\bcd_current.txt` |
| Running processes snapshot | Process list | `Get-Process | Select-Object Id,Name,Path,StartTime | Export-Csv C:\IR\processes.csv -NoTypeInformation` |
| Process tree with command lines | WMI | `Get-WmiObject Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Export-Csv C:\IR\process_tree.csv -NoTypeInformation` |
| Network connections | TCP/IP stack | `netstat -ano > C:\IR\netstat.txt` |
| Scheduled tasks | Task Scheduler | `schtasks /query /fo CSV /v > C:\IR\scheduled_tasks.csv` |
| Registry persistence keys | Registry | `reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run C:\IR\run_keys.reg` |
| Memory dump (if possible) | RAM | `procdump -ma <suspicious_pid> C:\IR\memdump.dmp` (Sysinternals ProcDump) |
| EDR telemetry export | EDR console | Export process tree for affected host covering T-60 minutes to T+0 |
| Prefetch files | `%SystemRoot%\Prefetch\` | `xcopy /S /E %SystemRoot%\Prefetch C:\IR\Prefetch\` |

### Eradication

Perform eradication steps only AFTER evidence collection is complete and verified:

- [ ] Terminate the ransomware/loader process if still running.
- [ ] Remove persistence mechanisms:
  - Scheduled tasks created by the attacker: `schtasks /delete /tn <name> /f`
  - Registry run keys: `reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v <name> /f`
  - Malicious services: `sc.exe stop <service> && sc.exe delete <service>`
- [ ] Remove dropper binaries and payloads from disk (document hash and path before deletion).
- [ ] Restore BCD recovery settings if modified:
  - `bcdedit /set {default} recoveryenabled Yes`
  - `bcdedit /deletevalue {default} bootstatuspolicy`
- [ ] Restore VSS shadow copies from backup if deleted (shadow copies themselves cannot be recreated retroactively — restore from offline backup tier).
- [ ] Reset credentials for all accounts observed in the process execution chain, including service accounts.
- [ ] Rotate any API keys, certificates, or secrets accessible from the compromised host.

### Recovery

- [ ] Verify all identified attacker artifacts have been removed (re-run file system scan with updated IOC list).
- [ ] Re-enable Windows Recovery Environment if it was disabled: `reagentc /enable`
- [ ] Verify VSS is running and shadow copy schedule is active: `vssadmin list shadows`; `Get-ScheduledTask | Where-Object TaskName -like "*Shadow*"`
- [ ] Re-enable any security controls that were temporarily suspended during IR.
- [ ] Apply outstanding Windows patches (ransomware often exploits unpatched vulnerabilities for initial access or privilege escalation).
- [ ] Reconnect the host to the network only after clean bill of health from EDR and IR team sign-off.
- [ ] Restore data from offline immutable backup if encryption occurred.
- [ ] Verify backup restore integrity with automated hash validation.

### Post-Incident Analysis

1. How was the attack initially detected — was it the EDR, the SIEM alert, or a user report?
2. What was the time delta between first malicious process creation and detection?
3. How many shadow copies existed at the time of the incident, and were any deleted?
4. Was the attacker operating from a domain admin credential, a local admin, or a service account?
5. What was the lateral movement path from initial access to the affected host?
6. Were backup targets accessible from the affected host at the time of the attack?
7. What changes to the hardening baseline would have blocked this specific attack path?
8. Update threat hunt queries to sweep all other endpoints for the same IOCs retroactively.

## References

- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK M1053 — Data Backup](https://attack.mitre.org/mitigations/M1053/)
- [MITRE ATT&CK M1028 — Operating System Configuration](https://attack.mitre.org/mitigations/M1028/)
- [MITRE ATT&CK M1024 — Restrict Registry Permissions](https://attack.mitre.org/mitigations/M1024/)
- [MITRE ATT&CK M1018 — User Account Management](https://attack.mitre.org/mitigations/M1018/)
- [Microsoft Security Blog — Ransomware Shadow Copy Deletion](https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)
- [CISA Ransomware Guide — Backup and Recovery Best Practices](https://www.cisa.gov/stopransomware/ransomware-guide)
- [CIS Benchmark for Windows — Section 18.9 (Windows Defender / Attack Surface Reduction)](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft WDAC Wizard — Supplemental Policy Authoring](https://webapp-wdac-wizard.azurewebsites.net/)
- [Microsoft Volume Shadow Copy Service Documentation](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [BCDEdit Command Reference](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options)
- [NSA/CISA Joint Advisory — Ransomware Trends](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a)
