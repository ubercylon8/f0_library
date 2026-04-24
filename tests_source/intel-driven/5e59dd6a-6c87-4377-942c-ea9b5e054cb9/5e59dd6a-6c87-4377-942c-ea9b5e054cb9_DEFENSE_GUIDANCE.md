# Defense Guidance: BlueHammer Early-Stage Behavioral Pattern

## Executive Summary

BlueHammer (Nightmare-Eclipse, 2026) is a Windows Defender TOCTOU exploit that chains three
novel primitives to obtain a read handle on the SAM database from user space, enabling offline
credential decryption and SYSTEM-level code execution without any vulnerability in a third-party
driver. The primitives exercised in this F0RT1KA test — Cloud Files sync-root registration,
batch-oplock issue, and VSS device enumeration plus transacted file open — are the observable
API surface that appears in telemetry **before** the damaging credential-access phases begin.

If an EDR detects and blocks any of these three early-stage primitives, it disrupts the entire
kill chain. If all three pass undetected, the attacker has established the preconditions for a
TOCTOU race that leaks the SAM hive handle.

Priority recommendations:
1. Enforce Tamper Protection and LSA RunAsPPL — they are the last line of defense if the
   oplock-based Defender freeze succeeds.
2. Alert on `CfRegisterSyncRoot` calls from non-vendor sync clients.
3. Alert on `FSCTL_REQUEST_BATCH_OPLOCK` outside of Storage/Backup process contexts.
4. Alert on `CreateFileTransactedW` combined with prior VSS device-object enumeration.
5. Rotate all local account credentials on any host where this or a similar test exits 101.

---

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | 5e59dd6a-6c87-4377-942c-ea9b5e054cb9 |
| **Test Name** | BlueHammer Early-Stage Behavioral Pattern |
| **Threat Actor** | Nightmare-Eclipse |
| **Source** | https://github.com/Nightmare-Eclipse/BlueHammer |
| **MITRE ATT&CK** | [T1211](https://attack.mitre.org/techniques/T1211/) — Exploitation for Defense Evasion |
| | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) — Impair Defenses: Disable or Modify Tools |
| **Tactics** | Defense Evasion |
| **Severity** | High |
| **Target** | windows-endpoint |
| **Complexity** | Medium |

---

## The Real BlueHammer Threat Chain

This section documents the full Nightmare-Eclipse kill chain for reference. Only phases 1-3 are
exercised by this test. Phases 4-6 are **never executed** and are described here purely to give
defenders context on what the early-phase detection wins actually prevent.

### Phase 1 — Cloud Files Sync-Root Hijack (Scanner Intercept Setup)

The attacker registers a fake Cloud Files sync provider on a chosen directory using
`CfRegisterSyncRoot` with a crafted provider identity. A `CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS`
callback is registered via `CfConnectSyncRoot`. Windows Defender, on encountering a placeholder
file inside this root, must request hydration through the registered callback — handing the
attacker code control over the timing of Defender's scan completion for files in that tree.

### Phase 2 — Batch Oplock Freeze (Scanner Stall)

The attacker issues `FSCTL_REQUEST_BATCH_OPLOCK` on a Defender update-definition file (e.g.,
`mpasbase.vdm`). A batch oplock grants the holder exclusive cached access; any attempt by another
process to open the file breaks the oplock and unblocks the holder. This freezes Defender's
scan-update path for the duration the attacker holds the oplock — creating a window for the
TOCTOU race in phase 4.

### Phase 3 — VSS Recon + Transacted-Open Staging (TOCTOU Setup)

The attacker enumerates the NT Object Manager `\Device` namespace using `NtOpenDirectoryObject`
and `NtQueryDirectoryObject` to identify `HarddiskVolumeShadowCopy*` device objects. This
establishes the VSS snapshot path that hosts a frozen copy of the SAM hive. A Kernel Transaction
Manager (KTM) transaction is created via `CreateTransaction`; `CreateFileTransactedW` is then
used to open a file transactionally — staging the mechanism used in phase 4.

### Phase 4 — TOCTOU Race (SAM Handle Leak) [OUT OF SCOPE — not exercised]

While Defender is frozen (phase 2 oplock held), the attacker races `CreateFileTransactedW`
against `mpasbase.vdm` on the VSS snapshot path. Because the scan is frozen and the KTM
transaction bypasses certain access-check revalidations on the snapshot handle, this returns
a file handle that, when the transaction is aborted, retargets to the SAM hive within the
snapshot — leaking a read handle to `\Windows\System32\Config\SAM` without ever calling
`RegOpenKey` or `NtOpenKey` on the live hive.

### Phase 5 — Offline SAM Parsing (Credential Decryption) [OUT OF SCOPE — not exercised]

The leaked SAM handle is passed to `OROpenHiveByHandle` (Offline Registry, `offreg.dll`).
The LSA boot key is reconstructed from `SYSTEM\CurrentControlSet\Control\Lsa` subkeys
(JD/Skew1/GBG/Data). The SAM account password encryption key is decrypted with AES-128-CBC.
NTLM hashes for all local accounts are decrypted. No live registry keys are read after the
initial VSS snap enumeration.

### Phase 6 — Credential Theft and SYSTEM Shell [OUT OF SCOPE — not exercised]

`samlib.dll!SamiChangePasswordUser` is called to change a local administrator password.
Token duplication with `SE_TCB_NAME` and `SE_ASSIGNPRIMARYTOKEN_NAME` is performed.
A new service is created that spawns a `cmd.exe` in `LocalSystem` context. The attacker
now has an interactive SYSTEM shell with no driver exploit and no reboot required.

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|----------------------|
| [T1211](https://attack.mitre.org/techniques/T1211/) — Exploitation for Defense Evasion | Defense Evasion | M1048 — Application Isolation and Sandboxing; M1050 — Exploit Protection; M1051 — Update Software |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) — Impair Defenses: Disable or Modify Tools | Defense Evasion | M1022 — Restrict File and Directory Permissions; M1024 — Restrict Registry Permissions; M1047 — Audit; M1038 — Execution Prevention; M1018 — User Account Management |

---

## Technique-Focused Detection Strategy

These detection patterns target the underlying technique class, not any specific tool or test
framework. They apply to BlueHammer and any derivative that reuses the same primitive sequence.

### Cloud Files API Abuse (Stage 1)

**What to monitor:** `CfRegisterSyncRoot` and `CfConnectSyncRoot` calls from processes that are
not recognized sync-client binaries (OneDrive, Google Drive, Dropbox, iCloud, corporate DLP
agents). The key signal is a provider identity string that is not part of the system's legitimate
sync client set, combined with a `CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS` callback registration.

**Secondary signal:** File-write events producing known AV test strings (EICAR) inside a newly
registered sync root from a non-vendor process. The combination of sync-root registration and
EICAR drop in the same directory tree from the same PID is a high-confidence signal.

**Process context:** Any process outside `%ProgramFiles%` issuing `CfRegisterSyncRoot`
should be considered anomalous on managed endpoints. The Cloud Files API is not used by
typical enterprise applications.

### Batch Oplock Scanner-Stall Pattern (Stage 2)

**What to monitor:** `FSCTL_REQUEST_BATCH_OPLOCK` (IOCTL code `0x00090018`) issued by a
process that is not a recognized storage, backup, or file-system filter driver service.
Specifically: a `DeviceIoControl` call with this control code from a user-mode process running
outside `%SystemRoot%`, `%ProgramFiles%`, or a process signed by a known backup vendor.

**Amplifying context:** The presence of an overlapped I/O pattern (`FILE_FLAG_OVERLAPPED`)
combined with a batch oplock request and a multi-second wait indicates deliberate scanner
stall intent rather than legitimate cached I/O management.

**Platform note:** `FSCTL_REQUEST_BATCH_OPLOCK` is used legitimately by SQL Server, some
antivirus engines, and file-system filter drivers. Correlate against process lineage and
signing context before alerting. The high-fidelity variant is: non-system-signed process +
batch oplock + file on a path known to host Defender update definitions
(`%ProgramData%\Microsoft\Windows Defender\Definition Updates\*`).

### VSS Enumeration Plus Transacted-File-Open (Stage 3)

**What to monitor:** `NtOpenDirectoryObject` calls targeting the `\Device` namespace from
a user-mode process that is not a VSS writer, backup agent, or volume management service.
The call is normal for administrators but unusual from non-elevated arbitrary processes.

**High-confidence compound:** `NtOpenDirectoryObject(\Device)` followed within the same
process lifetime by `CreateFileTransactedW` (ktmw32.dll) is a near-unique behavioral
fingerprint for the BlueHammer TOCTOU setup sequence. `CreateFileTransactedW` is used
almost exclusively by installers and corporate DLP agents in normal enterprise environments.
A non-installer process calling it is intrinsically suspicious.

**File target escalation:** If the `CreateFileTransactedW` target path is inside a
`HarddiskVolumeShadowCopy` device path, this transitions from suspicious to critical —
it represents an active TOCTOU race attempt against a snapshot and should trigger immediate
host isolation.

---

## Hardening Recommendations

### Quick Wins (Immediate — Low Operational Impact)

1. **Enable Defender Tamper Protection** — Prevents registry-level and process-level
   modification of Defender settings. This is a UI toggle (Windows Security > Virus
   and threat protection > Manage settings > Tamper protection) or Intune policy
   (`TamperProtection = 5`). Without it, phases 1-2 can surgically disable Defender
   scanning before the oplock is even needed.

2. **Enable LSA RunAsPPL (Protected Process Light)** — Forces `lsass.exe` to run as
   a Protected Process, preventing user-mode credential extraction via `OpenProcess` +
   `ReadProcessMemory`. Even if BlueHammer's SAM offline parse succeeds (phase 5),
   RunAsPPL limits what can be done with the recovered hashes against live processes.
   Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 2` (requires reboot).

3. **Enable Credential Guard** — Virtualizes the LSA secrets store using
   VBS/Hyper-V, preventing pass-the-hash with recovered NTLM hashes even if the
   offline SAM parse succeeds. Requires UEFI Secure Boot + VBS-capable hardware.

4. **Enable Attack Surface Reduction rule: Block credential stealing from LSASS**
   (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0`) — Blocks `OpenProcess` calls targeting
   `lsass.exe` from most process contexts. Complements RunAsPPL.

5. **Enable ASR rule: Block process creations from PSExec and WMI commands**
   (`d1e49aac-8f56-4280-b9ba-993a6d77406c`) — Blocks the service-creation SYSTEM
   shell that BlueHammer phase 6 depends on.

6. **Review local administrator accounts** — Disable the built-in Administrator
   account where not required. Limit the local administrator group membership. The
   SAM-leak payoff is only useful if there is a privileged local account whose
   hash or password can be leveraged. Reducing local admin account count reduces
   the attack's practical return.

### Medium-Term (1-2 Weeks — Requires Change Management)

7. **Restrict Cloud Files API access via AppLocker/WDAC** — Create an application
   control rule that prevents `cldapi.dll` from being loaded by processes outside
   of approved sync-client paths. This directly blocks phase 1. WDAC policy snippet:
   block any process not in the authorized publisher allowlist from loading
   `cldapi.dll` via `FilePublisherCondition`.

8. **Enable Windows Defender Exploit Guard: ASR rule for Kernel Transaction Manager
   abuse** — As of Windows 11 22H2, Microsoft has backported restrictions on
   `CreateFileTransactedW` against snapshot paths. Ensure KB5021255 and later
   cumulative updates are installed; these patch the specific TOCTOU window
   BlueHammer exploits in phase 4.

9. **Audit and restrict VSS writer permissions** — Review `vssadmin list writers`
   and ensure only authorized services (SQL, Exchange, system writers) have VSS
   writer registration. Unauthenticated VSS snapshot enumeration
   (`NtOpenDirectoryObject`) cannot be blocked at the OS level for standard users,
   but alerts can be configured via audit policy on object access to the `\Device`
   namespace (requires kernel auditing via ETW/WFP providers or an EDR that
   instruments NT Object Manager calls).

10. **Enable LSASS audit logging** — Set
    `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe`
    `AuditLevel = dword:00000008` to log all access to `lsass.exe`. This surfaces
    any process that opens LSASS regardless of RunAsPPL.

11. **Deploy Windows Defender Credential Guard with hardware binding** — On
    hardware supporting IOMMU (VT-d/AMD-Vi), enable Credential Guard with UEFI
    lock so it cannot be disabled via registry without a firmware change.

### Strategic (1-3 Months — Architecture or Policy Change Required)

12. **Enforce privileged access workstations (PAWs) for local administrator use** —
    If local admin credentials are only used from dedicated admin hosts, a TOCTOU
    SAM leak on a workstation yields credentials with no lateral-movement value
    in a properly tiered AD environment.

13. **Implement LAPS (Local Administrator Password Solution)** — Randomize local
    administrator passwords per machine with 30-day or shorter rotation. This limits
    the blast radius of a successful SAM offline parse: the recovered hash is valid
    for only one host and has a bounded validity window.

14. **Transition to Windows Hello for Business or FIDO2** — Eliminates NTLM
    hashes for primary credentials entirely on enrolled devices. If there are no
    NTLM hashes for privileged accounts in the SAM database, the entire
    BlueHammer phase 5-6 chain is a no-op.

15. **Deploy an EDR with Cloud Files API instrumentation** — Confirm your EDR
    vendor's coverage of `CfRegisterSyncRoot` events. Not all EDRs instrument
    the Cloud Files minifilter callbacks; this is a detection gap for a relatively
    new attack surface.

---

## Hardening Scripts

> Only the Windows hardening script is included. This test targets windows-endpoint exclusively.

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `5e59dd6a-6c87-4377-942c-ea9b5e054cb9_hardening.ps1` | PowerShell; applies LSA RunAsPPL, Tamper Protection check, ASR rules for credential access, LSASS audit, and Defender exploit-guard settings. Supports -Undo and -WhatIf. |

---

## Incident Response Playbook

### Detection Triggers

| Detection Name | Triggering Criteria | Confidence | Priority |
|----------------|---------------------|------------|----------|
| Cloud Files — Non-Vendor Sync Root Registration | Process outside known sync-client paths calls `CfRegisterSyncRoot` | High | P2 |
| Cloud Files + EICAR Compound | Same process registers sync root AND drops EICAR in that tree | Critical | P1 |
| Batch Oplock by Non-System Process | `DeviceIoControl(0x00090018)` from non-system-signed process | Medium | P2 |
| Batch Oplock on Defender Definition Path | Above, where target file path is under `%ProgramData%\Microsoft\Windows Defender\Definition Updates` | Critical | P1 |
| VSS Enum + Transacted Open Compound | `NtOpenDirectoryObject(\Device)` + `CreateFileTransactedW` in same process | High | P1 |
| Transacted Open Targeting VSS Path | `CreateFileTransactedW` target path contains `HarddiskVolumeShadowCopy` | Critical | P1 |
| LSASS Access from Non-System Process | Non-system process opens `lsass.exe` with `PROCESS_VM_READ` | High | P1 |

### Containment (First 15 Minutes)

- [ ] Identify the process tree of the alerting process: `Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq <pid> } | Select-Object ProcessId, ParentProcessId, Name, CommandLine`
- [ ] Capture process memory image before killing: `procdump.exe -ma <pid> C:\IR\<pid>.dmp`
- [ ] Kill the alerting process: `Stop-Process -Id <pid> -Force`
- [ ] Isolate the host from the network (via EDR console or `netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound`)
- [ ] If a Cloud Files sync root was registered, forcibly unregister: `CfUnregisterSyncRoot` equivalent via registry — remove `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\<provider-id>` entries
- [ ] Revoke all active logon sessions for the executing user account: `quser /server:<hostname>` then `logoff <session-id>`

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|--------------------|
| Security event log | System | `wevtutil epl Security C:\IR\Security.evtx` |
| System event log | System | `wevtutil epl System C:\IR\System.evtx` |
| Windows Defender operational log | System | `wevtutil epl "Microsoft-Windows-Windows Defender/Operational" C:\IR\Defender.evtx` |
| Cloud Files filter log (cldapi) | ETW provider | `logman start cldapi -p {3913A5B9-D3F0-4B75-9EA9-CEB07BFD0B7B} 0xFFFFFFFF -o C:\IR\cldapi.etl -ets` |
| VSS writer state | System | `vssadmin list writers > C:\IR\vss_writers.txt` |
| VSS snapshot list | System | `vssadmin list shadows > C:\IR\vss_shadows.txt` |
| Running processes and loaded modules | System | `Get-Process | ForEach-Object { $_ | Select-Object Id, Name, Path, @{n='Modules';e={$_.Modules.FileName -join ';'}} } | Export-Csv C:\IR\processes.csv` |
| Prefetch files (execution history) | `C:\Windows\Prefetch\` | `Copy-Item C:\Windows\Prefetch\* C:\IR\Prefetch\ -Recurse` |
| Registry: LSA settings | Registry | `reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" C:\IR\lsa_settings.reg` |
| Registry: Cloud Files sync roots | Registry | `reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager" C:\IR\syncroots.reg` |
| SAM hive (for hash comparison) | `%SystemRoot%\System32\config\` | `Copy-Item \\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\IR\SAM.bak` (use existing VSS snap if available) |
| SYSTEM hive (for boot-key reconstruction) | `%SystemRoot%\System32\config\` | `Copy-Item \\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\IR\SYSTEM.bak` |
| Defender scan logs | `%ProgramData%\Microsoft\Windows Defender\Support\` | `Copy-Item "%ProgramData%\Microsoft\Windows Defender\Support\MPLog*.log" C:\IR\` |

### Eradication

- [ ] Remove any sync-root registrations left by the attacker process: audit `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager` and remove non-vendor entries
- [ ] Delete any files dropped by the attacker process in user-writable directories (check `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, and any identified sync-root directory)
- [ ] Revoke and re-issue any certificates used by the attacker binary (check signing metadata from process memory dump)
- [ ] Verify VSS snapshot integrity: enumerate all snapshots with `vssadmin list shadows` and delete attacker-created snapshots: `vssadmin delete shadows /shadow={<guid>} /quiet`
- [ ] Remove any scheduled tasks or services created during the session: `Get-ScheduledTask | Where-Object { $_.Date -gt (Get-Date).AddHours(-2) }` and `Get-Service | Where-Object { $_.StartType -eq 'Automatic' }` — cross-reference against baseline
- [ ] AFTER evidence collection: rotate all local account passwords on the affected host (see Credential Rotation below)

### Credential Rotation (Mandatory if Exit Code 101 or Phases 4-6 Cannot Be Ruled Out)

The BlueHammer end-state is the full set of NTLM hashes for all local accounts in the SAM
database. If the attacker had sufficient time to complete phases 4-5 (which takes seconds
once the oplock is held), the following credentials must be considered compromised:

- [ ] All local user account passwords on the affected host — rotate immediately
- [ ] Built-in Administrator account password (if enabled)
- [ ] Any domain account whose credentials were cached (DPAPI-protected) on the host
- [ ] Service accounts running processes on the host that have stored credentials in LSA secrets
- [ ] Any password reused across multiple systems that matches a local account on this host

**Rotation commands:**
```powershell
# Rotate a specific local account password
net user <accountname> <newpassword>

# Rotate the built-in Administrator password
net user Administrator (New-Guid).ToString().Replace('-','').Substring(0,20)

# Disable the built-in Administrator if not needed
net user Administrator /active:no

# Force all domain cached credential invalidation (requires domain connectivity)
klist purge -li 0x3e7
```

**LAPS:** If LAPS is deployed, force an immediate rotation cycle:
```powershell
Reset-LapsPassword -ComputerName <hostname>
```

### Recovery

- [ ] Verify all attacker artifacts removed (sync roots, scheduled tasks, services, dropped files)
- [ ] Re-validate Tamper Protection is enabled on the recovered host
- [ ] Re-validate RunAsPPL is set and lsass.exe is listed as a PPL in Task Manager (Details > Columns > Protection)
- [ ] Re-enable any Defender components that were modified during the incident
- [ ] Reconnect host to the network only after credential rotation and artifact verification are complete
- [ ] Re-run the F0RT1KA test (exit code 126 expected) to confirm the host is now protected

### Post-Incident Review

1. Was the Cloud Files sync-root registration event logged before any other detection fired? If not, the EDR lacks Cloud Files API instrumentation — raise with the vendor.
2. Was the batch oplock IoControl event visible in telemetry? Many EDRs do not instrument `DeviceIoControl` at the FSCTL level for user-mode callers.
3. Did any alert fire before the VSS enumeration stage? If detection only occurred at stage 3, consider whether stage 1 or 2 alone would have been sufficient to stop a faster real-world attacker.
4. What was the time between first detectable telemetry event and analyst triage? The BlueHammer full chain completes in under 30 seconds on a warm system. Detection-to-containment latency is the critical metric.
5. Were there any EICAR quarantine events that were not promoted to a P1 incident? EICAR quarantine alone, without the sync-root context, would not signal BlueHammer — ensure the compound detection rule exists.
6. What was the source of initial access? BlueHammer requires user-mode code execution as a standard or medium-integrity process. The prerequisite is always prior code execution — identify it.

---

## References

| Resource | URL |
|----------|-----|
| BlueHammer PoC | https://github.com/Nightmare-Eclipse/BlueHammer |
| T1211 — Exploitation for Defense Evasion | https://attack.mitre.org/techniques/T1211/ |
| T1562.001 — Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |
| M1050 — Exploit Protection | https://attack.mitre.org/mitigations/M1050/ |
| M1048 — Application Isolation and Sandboxing | https://attack.mitre.org/mitigations/M1048/ |
| M1047 — Audit | https://attack.mitre.org/mitigations/M1047/ |
| M1038 — Execution Prevention | https://attack.mitre.org/mitigations/M1038/ |
| M1022 — Restrict File and Directory Permissions | https://attack.mitre.org/mitigations/M1022/ |
| M1024 — Restrict Registry Permissions | https://attack.mitre.org/mitigations/M1024/ |
| CfRegisterSyncRoot API | https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfregistersyncroot |
| CfConnectSyncRoot API | https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfconnectsyncroot |
| FSCTL_REQUEST_BATCH_OPLOCK | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_batch_oplock |
| CreateFileTransactedW API | https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiletransactedw |
| LSA RunAsPPL configuration | https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection |
| Windows Defender Credential Guard | https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure |
| Attack Surface Reduction rules reference | https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference |
| LAPS overview | https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview |
| KB5021255 (TOCTOU fix) | https://support.microsoft.com/en-us/topic/december-13-2022-kb5021255 |
| Microsoft Security Baseline (Windows 11) | https://www.microsoft.com/en-us/download/details.aspx?id=55319 |
| CIS Benchmark for Windows 11 | https://www.cisecurity.org/benchmark/microsoft_windows_desktop |
