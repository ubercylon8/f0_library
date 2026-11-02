# Defense Guidance: Qilin (Agenda) BYOVD EDR-Killer & svchost Injection Chain

## Executive Summary

Qilin's reported EDR-killer chain combines security-product discovery, DLL side-loading, vulnerable signed drivers, security-process termination, injection into trusted-looking processes, credential access, recovery inhibition, and encryption. The defensive priority is to stop the chain **before a driver load or injection succeeds**, while retaining independent telemetry outside the endpoint security agent.

Highest priorities:

1. Enforce the current Microsoft vulnerable-driver blocklist through App Control for Business (WDAC), with memory integrity/HVCI and an explicit driver allowlist where feasible.
2. Enable endpoint behavioral controls for vulnerable-driver writes, LSASS access, copied system tools, injection, and ransomware. Validate Microsoft Defender ASR rules in audit/pilot rings before broad enforcement.
3. Protect LSASS with LSA protection (PPL) and Credential Guard after plug-in, hardware, and recovery testing.
4. Deploy user-mode and kernel application control to prevent unapproved DLLs and drivers; do not rely on signatures alone because BYOVD abuses validly signed drivers.
5. Stream EDR, CodeIntegrity, process, service, and authentication telemetry off-host. Alert on security-agent health gaps and driver/service changes, not only malware signatures.
6. Maintain tested, immutable/offline backups and a ransomware containment plan.

The bundled PowerShell script applies a conservative local baseline. It enables the built-in vulnerable-driver blocklist, selected ASR policy rules, LSA audit mode, process command-line and PowerShell Script Block logging, and Controlled Folder Access audit mode. Higher-impact LSA, Credential Guard, memory-integrity, and Controlled Folder Access enforcement requires explicit switches. It does not install or replace a WDAC policy and does not change third-party EDR settings.

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | `8f68dda1-94be-430f-8f35-d8af3f9b5d2e` |
| **Test Name** | Qilin (Agenda): BYOVD EDR-Killer & svchost Injection Chain |
| **MITRE ATT&CK** | [T1518.001](https://attack.mitre.org/techniques/T1518/001/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1211](https://attack.mitre.org/techniques/T1211/), [T1055](https://attack.mitre.org/techniques/T1055/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1486](https://attack.mitre.org/techniques/T1486/) |
| **Severity** | Critical |
| **Threat Actor** | Qilin (Agenda) |
| **Platform** | Windows endpoint |
| **Tactics** | Discovery, defense evasion, credential access, impact |

Cisco Talos describes a malicious `msimg32.dll` that is likely side-loaded by a legitimate application, decrypts an EDR-killer component, uses `rwdrv.sys` for physical-memory access and `hlpdrv.sys` for process termination, and unregisters monitoring callbacks before terminating security processes. A valid signature therefore does not make a driver safe. See [Cisco Talos: Qilin EDR killer](https://blog.talosintelligence.com/qilin-edr-killer/), with supporting reporting from [The Hacker News](https://thehackernews.com/2026/04/qilin-and-warlock-ransomware-use.html) and [Cybersecurity News](https://cybersecuritynews.com/qilin-ransomware-kill-edr/).

### Simulation Boundary

The Go implementation is a detection harness, not a working Qilin payload:

- Discovery uses `root/SecurityCenter2`, `tasklist`, `sc query`, and operating-system CIM queries. A test-owned host calls `LoadLibraryW` on a copied Microsoft `msimg32.dll`; no malicious forwarding DLL is reproduced.
- A real `rwdrv.sys` asset is exposed only for signature inspection and removed before load attempts. Subsequent service and `NtLoadDriver` operations use nonfunctional stand-ins. Kernel callback removal is represented only in JSON.
- Injection targets a test-owned process named `svchost.exe` and loads a renamed Microsoft `version.dll`; production Windows services are not injected.
- LSASS is opened with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` after a `SeDebugPrivilege` attempt, but no memory read or dump occurs.
- Only synthetic files are encrypted. `vssadmin` and `bcdedit` target nonexistent identifiers and are designed to fail harmlessly.
- Security-product termination targets test-owned stand-ins, not production EDR processes. There is no external egress.

Defenses below address the **real attack techniques**, not filenames, paths, hashes, or other harness artifacts. Successful harness execution is not evidence that a real vulnerable driver could load or that an EDR bypass would succeed.

## MITRE ATT&CK Mapping

Mitigations reduce likelihood or impact; none is a complete substitute for detection and response. T1211 is named **Exploitation for Stealth** in the current ATT&CK knowledge base.

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|------------------------|
| [T1518.001 — Security Software Discovery](https://attack.mitre.org/techniques/T1518/001/) | Discovery | No easy preventive mitigation; use **M1047 — Audit** for discovery telemetry and **M1038 — Execution Prevention** against unauthorized parent tooling. |
| [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/) | Discovery | No easy preventive mitigation; use **M1047 — Audit**, plus application control and least privilege to reduce follow-on execution. |
| [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) | Defense Evasion | **M1040 — Behavior Prevention on Endpoint**, **M1049 — Antivirus/Antimalware**, **M1038 — Execution Prevention**, **M1026 — Privileged Account Management**, **M1022 — Restrict File and Directory Permissions**, **M1025 — Privileged Process Integrity**. |
| [T1211 — Exploitation for Stealth](https://attack.mitre.org/techniques/T1211/) | Defense Evasion | **M1051 — Update Software**, **M1050 — Exploit Protection**, **M1048 — Application Isolation and Sandboxing**, **M1019 — Threat Intelligence Program**. |
| [T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/) | Defense Evasion, Privilege Escalation | **M1040 — Behavior Prevention on Endpoint**, **M1026 — Privileged Account Management**, **M1025 — Privileged Process Integrity**; **M1044 — Restrict Library Loading** for the DLL variant. |
| [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) | Credential Access | **M1040 — Behavior Prevention on Endpoint**, **M1043 — Credential Access Protection**, **M1025 — Privileged Process Integrity**, **M1026 — Privileged Account Management**, **M1027 — Password Policies**, **M1028 — Operating System Configuration**. |
| [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) | Impact | **M1053 — Data Backup**, **M1038 — Execution Prevention**, **M1040 — Behavior Prevention on Endpoint**, **M1026 — Privileged Account Management**. |
| [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) | Impact | **M1040 — Behavior Prevention on Endpoint**, **M1053 — Data Backup**, **M1022 — Restrict File and Directory Permissions**, **M1038 — Execution Prevention**. |

Supporting behaviors in the source also justify [T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/) controls (**M1044**, **M1038**, **M1022**) and kernel-service creation monitoring associated with [T1543.003 — Windows Service](https://attack.mitre.org/techniques/T1543/003/). They are defense-relevant context, not additions to the test's declared technique list.

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact)

1. **Enable and verify the Microsoft vulnerable-driver blocklist.** On supported Windows 11 systems, confirm **Windows Security → Device security → Core isolation → Microsoft vulnerable driver blocklist** is on. Keep Windows updated because the OS-delivered list is serviced through Windows Update. The supplied script sets `VulnerableDriverBlocklistEnable=1`; reboot and verify operational state rather than treating the registry value alone as proof.
2. **Enable the vulnerable-signed-driver ASR rule in a pilot.** Rule GUID `56a863a9-875e-4185-98a7-b882c64b5ce5` blocks applications from writing known vulnerable signed drivers. It does **not** stop an already-present driver from loading; pair it with the blocklist/WDAC. Start in audit mode where compatibility is uncertain.
3. **Protect LSASS.** Enable the LSASS credential-theft ASR rule (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) in a small ring, inventory LSA plug-ins, and use LSA audit mode (`AuditLevel=8`) before enforcing PPL. Check CodeIntegrity events 3065/3066 during audit and 3033/3063 after enforcement.
4. **Turn on security-product self-protection using supported management consoles.** For Microsoft Defender, manage Tamper Protection through Intune, the Microsoft Defender portal, or Configuration Manager as appropriate; do not treat a local registry edit as a supported substitute. For other EDR products, use the vendor's current tamper/self-protection and uninstall-protection controls. This guide makes no claim about a CrowdStrike-specific setting.
5. **Increase independent visibility.** Enable Security event 4688 with command lines, PowerShell event 4104, CodeIntegrity Operational, and EDR process/module telemetry. Forward events to a remote SIEM with restricted retention administration. Treat sensitive command lines and script content according to organizational privacy policy.
6. **Audit ransomware controls before enforcement.** Enable Controlled Folder Access in audit mode and advanced ransomware ASR in audit mode where application compatibility is unknown. Review Defender events 1123/1124 (CFA) and 1121/1122 (ASR block/audit), then enforce with narrow, documented exclusions.
7. **Remove routine administrative rights.** Use separate admin accounts, tiered administration, unique local administrator passwords, and just-enough/just-in-time elevation. A non-elevated user should not possess `SeLoadDriverPrivilege` or broad `SeDebugPrivilege`.

### Medium-Term (1–2 Weeks — Medium Impact)

1. **Deploy the latest WDAC vulnerable-driver blocklist in audit mode.** Download the current policy and refresh tool from [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules). Use the supplied audit-only binary first; do not hand-author a one-driver deny rule and assume it covers BYOVD.
   - Rename the selected policy to `SiPolicy.p7b`, copy it to `%windir%\System32\CodeIntegrity`, and refresh policies with Microsoft's tool.
   - Confirm CodeIntegrity event **3099** identifies the intended policy. Review CodeIntegrity **3077** (audit) and **3076** (enforcement) driver-block events and application-control events in the AppLocker/MSI and Script logs where relevant.
   - Reboot before declaring protection effective, especially when a driver was already loaded.
   - For an enforced deployment, retain the prior policy and a tested rollback procedure. The Microsoft blocklist package contains Allow All rules; when merging with an allowlist base policy, follow Microsoft's deny-policy guidance and remove those Allow All rules rather than accidentally weakening the base policy.
2. **Establish driver governance.** Maintain an inventory of publisher, signer, hash, version, source, owner, business purpose, and approval date for every non-inbox driver. Block unapproved new kernel services, prohibit users from installing drivers, remove unused drivers with vendor-supported methods, and expedite vendor updates. Require emergency change review for drivers added outside normal servicing.
3. **Enforce memory integrity/HVCI and Credential Guard in compatible rings.** Validate Secure Boot, VBS hardware support, drivers, smart-card/cryptographic plug-ins, virtualization, and recovery procedures first. Prefer configuration without UEFI lock for remotely managed pilots so rollback remains possible; consider UEFI lock only after stability and physical-recovery procedures are proven.
4. **Control DLL side-loading and injection.** Deploy WDAC user-mode code integrity with managed-installer/publisher rules for approved applications and DLLs. Remove user write access to application directories and avoid executing privileged applications from user-writable locations. Keep `SafeDllSearchMode` enabled, but recognize that it does not eliminate application-directory side-loading. Enable the copied/impersonated-system-tool ASR rule (`c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb`) and Office injection ASR (`75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84`) after application testing.
5. **Harden EDR administration.** Restrict service-control permissions, agent uninstall rights, policy-exclusion changes, and sensor-management roles. Alert on unexpected service stop/disable events and gaps in heartbeat or event forwarding. Keep security-agent binaries and drivers under vendor-supported self-protection; do not apply ad hoc service ACLs that could break updates or recovery.
6. **Add cross-process and module telemetry.** Deploy Sysmon or equivalent EDR telemetry with a reviewed configuration: Event ID **6** (driver load), **7** (image load; disabled by default and potentially noisy), **8** (CreateRemoteThread), **10** (ProcessAccess), **11** (file create), **12–14** (registry), and **1** (process create). Tune rather than enabling unbounded image/process-access collection. Correlate `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` behavior where the EDR exposes it.
7. **Protect recovery.** Use separate backup identities, immutable or offline copies, MFA on backup administration, and restrictions on `vssadmin`, `wbadmin`, `bcdedit`, `diskshadow`, and backup APIs through application control where operationally feasible. Test file and bare-metal restoration.

### Strategic (1–3 Months — Requires Planning)

1. **Adopt explicit allowlisting for kernel and user-mode code.** Build WDAC base and supplemental policies from a managed installer or a known-good reference fleet. Use publisher rules where practical and file rules for high-risk drivers. Run audit and enforced pilot rings, maintain break-glass recovery media, and measure policy drift.
2. **Create a driver allow/deny lifecycle.** Require security review for new kernel drivers, track Microsoft vulnerable-driver intelligence and vendor advisories, submit suspicious drivers to Microsoft, and rehearse emergency revocation/blocklist deployment. Prefer removing or updating a vulnerable driver over permanent exclusions.
3. **Deploy secured-core and virtualization-based protections.** Standardize on Secure Boot, TPM, supported processors, HVCI, Credential Guard, and LSA PPL with UEFI lock where operational maturity supports it. Measure boot, authentication, hardware, and application compatibility.
4. **Reduce credential blast radius.** Implement tiered administration, Windows LAPS, restricted admin logon, Credential Guard, remote credential guard where appropriate, and rapid enterprise-wide credential reset procedures. Restrict NTLM where feasible after dependency analysis.
5. **Engineer ransomware-resistant recovery.** Segregate production and backup control planes, use immutable/offline repositories, enforce separate administrative identities, and run recurring restoration exercises with recovery-time and recovery-point objectives.
6. **Build an independent security-health control plane.** Monitor sensor heartbeat, policy version, service state, exclusion changes, kernel-driver inventory, and telemetry freshness from a platform whose failure does not depend on the same local agent.

## Hardening Scripts

Only the Windows hardening script is supplied because the test targets Windows endpoints.

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `8f68dda1-94be-430f-8f35-d8af3f9b5d2e_hardening.ps1` | Idempotent, administrator-only baseline with `-WhatIf`, `-Undo`, original-state rollback, and opt-in high-impact controls. |

Run from an elevated Windows PowerShell 5.1+ or PowerShell 7+ session after reviewing the guide and testing in a pilot:

```powershell
# Preview the conservative baseline without changing anything
.\8f68dda1-94be-430f-8f35-d8af3f9b5d2e_hardening.ps1 -WhatIf

# Apply the baseline: driver blocklist, selected ASR block rules,
# LSA audit, telemetry, SafeDllSearchMode, and CFA audit mode
.\8f68dda1-94be-430f-8f35-d8af3f9b5d2e_hardening.ps1

# After compatibility review, opt in to additional enforcement
.\8f68dda1-94be-430f-8f35-d8af3f9b5d2e_hardening.ps1 -EnforceLSAProtection -EnforceControlledFolderAccess

# Only after VBS, driver, authentication, and recovery validation
.\8f68dda1-94be-430f-8f35-d8af3f9b5d2e_hardening.ps1 -EnableCredentialGuard -EnableMemoryIntegrity

# Preview or perform rollback of settings changed by this script
.\8f68dda1-94be-430f-8f35-d8af3f9b5d2e_hardening.ps1 -Undo -WhatIf
.\8f68dda1-94be-430f-8f35-d8af3f9b5d2e_hardening.ps1 -Undo
```

Important operating notes:

- ASR and Controlled Folder Access are Microsoft Defender Antivirus features. If Defender is disabled or in passive mode because another antivirus/EDR is active, configuring these settings does not establish active protection. Use the incumbent product's supported behavioral controls instead; the script reports this condition and never modifies third-party sensors.
- The script configures policy-registry equivalents for standalone/pilot use. On centrally managed devices, prefer Intune, Group Policy, Configuration Manager, or the Defender security-settings management path and avoid conflicting local policy.
- LSA enforcement uses `RunAsPPL=2` (without UEFI lock) and requires Windows 11 22H2 or later plus reboot. Audit first. Credential Guard and memory integrity also require reboot and compatible hardware/drivers.
- The script enables the built-in blocklist, not a downloaded WDAC policy. It does not overwrite `SiPolicy.p7b`, create AppLocker rules, or add broad exclusions.
- `-Undo` restores only values recorded by the script. It does not disable protections that predated the run, revert centrally managed policy, remove UEFI variables, or roll back a separately deployed WDAC policy.

## Detection and Monitoring Procedures

### High-Value Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| Vulnerable-driver write or load | ASR vulnerable-driver event; Sysmon driver load with a blocklisted hash/signer; CodeIntegrity 3076/3077; new `.sys` followed by kernel-service creation | High when correlated | P1 |
| Security-defense impairment | Unexpected EDR service stop/disable/crash, sensor heartbeat loss, policy/exclusion change, CodeIntegrity setting change, or security-process handle/termination attempt | High with no approved change | P1 |
| LSASS credential access | Unexpected ProcessAccess to LSASS with VM read/all-access rights; ASR LSASS event; memory-dump file creation or dump API sequence | High for non-approved processes | P1 |
| Cross-process injection | CreateRemoteThread/Sysmon 8, remote writable allocation plus memory write and thread start, or unexpected DLL load into a Windows service process | High with API sequence | P1 |
| DLL side-load | Application loads a same-named system DLL from its non-system directory; signed application loads an unsigned/untrusted DLL from a user-writable path | Medium; High with subsequent discovery/driver activity | P2 |
| Kernel-service creation | Security 4697, System 7045, or service registry creation whose service type is kernel driver and whose binary is new/unapproved | Medium; High outside change window | P1/P2 |
| Security/system discovery burst | One parent runs SecurityCenter2 AV queries, process/service enumeration, and OS CIM queries in quick succession | Medium; correlate with later stages | P2/P3 |
| Recovery inhibition | `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit ... recoveryenabled no`, `diskshadow` deletion, or VSS snapshot deletion by an unapproved process | High outside backup administration | P1 |
| Ransomware behavior | Rapid create/write/rename/delete bursts across document paths, ransom-note creation, CFA/ASR ransomware events, or multiple hosts showing the same behavior | High | P1 |

Useful triage commands (run from an approved administrative shell; scope time ranges to the incident):

```powershell
# New process command lines
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-2)} |
  Select-Object TimeCreated, Message

# PowerShell Script Block content (may contain sensitive data)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddHours(-2)} |
  Select-Object TimeCreated, Message

# Code Integrity policy and block activity
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 200 |
  Where-Object Id -in 3033,3063,3065,3066,3076,3077,3089,3099 |
  Select-Object TimeCreated, Id, Message

# Service installations and state changes
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036,7040,7045; StartTime=(Get-Date).AddHours(-2)} |
  Select-Object TimeCreated, Id, ProviderName, Message

# Defender ASR/CFA activity, when Defender is the active provider
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 300 |
  Where-Object Id -in 1121,1122,1123,1124,5007 |
  Select-Object TimeCreated, Id, Message

# Configured versus running VBS/Credential Guard state
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning,CodeIntegrityPolicyEnforcementStatus

# Driver inventory for offline comparison and approval review
Get-CimInstance Win32_SystemDriver |
  Select-Object Name,DisplayName,State,StartMode,PathName
```

For environments with Sysmon, query its Operational log for IDs 1, 6, 7, 8, 10, 11, and 12–14. An LSASS access event alone is not proof of dumping; validate access rights, source process/signer, subsequent file/memory activity, and approved administrative activity.

## Incident Response Playbook

### Containment (First 15 Minutes)

- [ ] Declare P1 for credible BYOVD, EDR termination, LSASS dumping, or multi-host encryption. Start an incident timeline and preserve the original alert/telemetry.
- [ ] Isolate affected hosts using the EDR/network containment capability; keep them powered on when safe for volatile acquisition. Segment adjacent backup and administration systems.
- [ ] Disable or restrict implicated accounts and sessions from an independent management plane. If credentials were exposed, plan enterprise-wide resets rather than changing only one local password.
- [ ] Do not reboot, uninstall security software, delete drivers/services, or run cleanup before evidence capture unless continued encryption or safety requires it.
- [ ] If active encryption is spreading, prioritize network isolation, share access revocation, backup-control-plane protection, and suspension of the suspected deployment/lateral-movement account.
- [ ] Identify other endpoints with the same driver, signer, service, module-load, or command-line telemetry. Treat security-agent silence as a potential compromise indicator.

### Evidence Collection

Create the evidence directory on trusted responder media or an approved collection share, not on a suspected attacker-writable path. Record hashes and chain of custody. The examples below use `E:\IR\<hostname>` as responder-media placeholders.

| Artifact | Location | Collection Command |
|----------|----------|--------------------|
| Volatile system/process/network state | Live host | `Get-Date; whoami /all; Get-Process \| Sort-Object StartTime; Get-NetTCPConnection; Get-CimInstance Win32_SystemDriver \| Export-Clixml E:\IR\$env:COMPUTERNAME\drivers.xml` |
| Security log | `C:\Windows\System32\winevt\Logs\Security.evtx` | `wevtutil epl Security E:\IR\%COMPUTERNAME%\Security.evtx` |
| System log | System event log | `wevtutil epl System E:\IR\%COMPUTERNAME%\System.evtx` |
| CodeIntegrity | CodeIntegrity Operational | `wevtutil epl Microsoft-Windows-CodeIntegrity/Operational E:\IR\%COMPUTERNAME%\CodeIntegrity.evtx` |
| PowerShell | PowerShell Operational | `wevtutil epl Microsoft-Windows-PowerShell/Operational E:\IR\%COMPUTERNAME%\PowerShell.evtx` |
| Sysmon, if installed | Sysmon Operational | `wevtutil epl Microsoft-Windows-Sysmon/Operational E:\IR\%COMPUTERNAME%\Sysmon.evtx` |
| Defender, if active | Defender Operational | `wevtutil epl Microsoft-Windows-Windows Defender/Operational E:\IR\%COMPUTERNAME%\Defender.evtx` |
| Service/driver configuration | Registry | `reg export "HKLM\SYSTEM\CurrentControlSet\Services" E:\IR\%COMPUTERNAME%\Services.reg /y` |
| VBS and code-integrity configuration | Registry/CIM | `reg export "HKLM\SYSTEM\CurrentControlSet\Control\CI" E:\IR\%COMPUTERNAME%\CI.reg /y` and save `Win32_DeviceGuard` output |
| Suspicious files | Driver, DLL, executable, ransom note paths identified by telemetry | Copy read-only to evidence media; calculate `Get-FileHash -Algorithm SHA256`; preserve original timestamps and Zone.Identifier where present |

A raw LSASS or full-memory image can contain credentials and highly sensitive data. Acquire only under the incident plan, encrypt it, restrict access, and document transfer/destruction. If a kernel driver executed, memory acquisition by trusted specialists is strongly preferred; user-mode cleanup cannot establish kernel integrity.

### Eradication

1. Determine initial access and persistence before removing isolated artifacts; otherwise reinfection is likely.
2. Remove unapproved driver registrations and files only after acquisition, using vendor-supported removal/update procedures. Check driver stores, services, Run keys, scheduled tasks, WMI persistence, and sideloaded application directories indicated by evidence.
3. Revoke unauthorized exclusions, policy changes, service ACL changes, and newly privileged accounts. Restore security policy from a known-good central source.
4. Reset credentials exposed on affected hosts, including cached domain/admin credentials and service accounts; revoke active tokens/tickets as appropriate.
5. **If a malicious/vulnerable driver obtained kernel execution, security services were disabled, or kernel callbacks/objects were altered, rebuild from trusted media.** Do not declare the host clean based only on file deletion or a subsequent antivirus scan.
6. Reimage or restore using a known-good OS and approved driver set, then patch and reapply WDAC/EDR policy before reconnection.

### Recovery

- [ ] Verify driver and service inventories against a known-good baseline; confirm no unapproved kernel services or side-loaded modules remain.
- [ ] Confirm EDR sensor health, self-protection, policy version, heartbeat, and off-host telemetry for a sustained observation period.
- [ ] Verify WDAC policy activation (CodeIntegrity 3099), vulnerable-driver blocklist, LSA PPL (WinInit 12), Credential Guard (WinInit 13 and DeviceGuard CIM), and VBS/HVCI state.
- [ ] Confirm Windows recovery and backup services are healthy; restore data from clean immutable/offline backups after malware eradication.
- [ ] Scan restored data and validate business integrity before returning it to production.
- [ ] Reconnect in stages, monitor closely for recurrence, and rotate any remaining potentially exposed secrets.

### Post-Incident

1. Which control first detected or blocked the chain: application control, driver blocklist, ASR, EDR behavior, SIEM correlation, or user report?
2. What were detection, isolation, credential-reset, and recovery times?
3. Did any security-agent or telemetry gap delay detection? Was independent telemetry available?
4. Was the driver already present, newly written, or loaded through an approved service/change? Why was it trusted?
5. Were DLL and driver policies actually enforced after reboot, or only configured?
6. Did backups remain available and meet restoration objectives?
7. What policy, inventory, detection, or exercise must change before closure?

## References

### Threat Intelligence

- [Cisco Talos — Qilin EDR killer infection chain, 2026-04-02](https://blog.talosintelligence.com/qilin-edr-killer/)
- [The Hacker News — Qilin and Warlock ransomware use EDR killer](https://thehackernews.com/2026/04/qilin-and-warlock-ransomware-use.html)
- [Cybersecurity News — Qilin ransomware EDR-killer reporting](https://cybersecuritynews.com/qilin-ransomware-kill-edr/)

### Microsoft Control Guidance

- [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
- [App Control for Business (WDAC) overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac)
- [Enable virtualization-based protection of code integrity](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Configure Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure)
- [Attack Surface Reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Configure Controlled Folder Access](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure)
- [Command-line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Microsoft Security Baselines and CIS Microsoft Windows Benchmarks: apply the current version for the deployed OS through the organization's change-control process; do not mix settings from different OS releases without validation.

### MITRE ATT&CK

- Technique pages linked in the mapping table and [Enterprise Mitigations](https://attack.mitre.org/mitigations/enterprise/)
- [M1040 — Behavior Prevention on Endpoint](https://attack.mitre.org/mitigations/M1040/)
- [M1043 — Credential Access Protection](https://attack.mitre.org/mitigations/M1043/)
- [M1044 — Restrict Library Loading](https://attack.mitre.org/mitigations/M1044/)
- [M1053 — Data Backup](https://attack.mitre.org/mitigations/M1053/)
- [M1038 — Execution Prevention](https://attack.mitre.org/mitigations/M1038/)
- [M1050 — Exploit Protection](https://attack.mitre.org/mitigations/M1050/)
- [M1051 — Update Software](https://attack.mitre.org/mitigations/M1051/)
- [M1025 — Privileged Process Integrity](https://attack.mitre.org/mitigations/M1025/)
- [M1026 — Privileged Account Management](https://attack.mitre.org/mitigations/M1026/)
