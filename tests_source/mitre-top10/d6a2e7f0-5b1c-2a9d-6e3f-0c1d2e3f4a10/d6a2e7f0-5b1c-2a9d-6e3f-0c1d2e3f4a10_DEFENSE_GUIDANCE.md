# Defense Guidance: Security Service Stop Simulation

## Executive Summary

Adversaries frequently disable or stop security services as a prerequisite to ransomware deployment, lateral movement, or data exfiltration. This test evaluates an endpoint's resilience against two closely related MITRE ATT&CK techniques: **T1489 — Service Stop** and **T1562.001 — Impair Defenses: Disable or Modify Tools**. Both techniques are consistently present in major ransomware kill chains (LockBit, Conti, REvil, BlackCat/ALPHV) and are exploited specifically to blind defensive tooling before payload execution.

Priority actions: enable Windows Defender Tamper Protection, deploy Attack Surface Reduction rules targeting service control abuse, configure Protected Process Light (PPL) for security service processes, and implement audit policy rules that alert on bulk service query and control sequences from non-SYSTEM processes.

---

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10 |
| **Test Name** | Security Service Stop Simulation |
| **MITRE ATT&CK** | [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489/) · [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactics** | Impact, Defense Evasion |
| **Severity** | High |
| **Threat Actor** | N/A (technique is cross-actor — LockBit, Conti, REvil, BlackCat/ALPHV, Lazarus) |
| **Platform** | Windows Endpoint |
| **Subcategory** | defense-evasion |
| **Tags** | service-stop, defender-tampering, security-service, impair-defenses, sc.exe, taskkill, netexec, smb |

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Description | Applicable Mitigations |
|-----------|--------|-------------|----------------------|
| [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489/) | Impact | Adversaries stop or disable services on a system to render those services unavailable to users — particularly backup and security services — to facilitate ransomware execution or disrupt recovery | M1030 — Network Segmentation · M1022 — Restrict File and Directory Permissions · M1024 — Restrict Registry Permissions · M1018 — User Account Management |
| [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) | Defense Evasion | Adversaries disable or modify security tools to avoid detection — targeting AV/EDR services, Windows Defender, and security center components — before executing follow-on payloads | M1038 — Execution Prevention · M1054 — Software Configuration · M1018 — User Account Management · M1024 — Restrict Registry Permissions |

### Mitigation Detail

| M-Code | Name | Relevance to This Test |
|--------|------|----------------------|
| **M1018** | User Account Management | Restrict which accounts can issue `sc stop`, `sc delete`, and `sc create` commands. Enforce least privilege so standard user processes cannot interact with the Service Control Manager for security-relevant services. |
| **M1022** | Restrict File and Directory Permissions | Lock down SCM write access. Limit which processes can modify service binaries and registration entries. |
| **M1024** | Restrict Registry Permissions | Security service configuration lives under `HKLM\SYSTEM\CurrentControlSet\Services\<name>`. Restrict write permissions to SYSTEM only. |
| **M1030** | Network Segmentation | Block or alert on SMB (TCP/445) connections originating from non-management hosts. Prevents NetExec-style lateral service enumeration. |
| **M1038** | Execution Prevention | Use WDAC or AppLocker to block execution of known offensive tools (e.g., NetExec/nxc.exe) and restrict which processes may invoke `sc.exe` or `taskkill.exe` outside of trusted management paths. |
| **M1054** | Software Configuration | Enable Windows Defender Tamper Protection. This is the single most impactful control — it prevents modification, disable, or stop of WinDefend, MsMpEng, and related security services even by local administrators. |

---

## Attack Technique Analysis

### T1489 — Service Stop

**What the test does:** The test creates a dedicated test service (`F0RTIKA_TestSvc`), stops it via `sc.exe stop`, then deletes it via `sc.exe delete`. It also queries the status of four high-value security services (WinDefend, wscsvc, VSS, wbengine) to simulate the reconnaissance step attackers perform before deciding which services to disable.

**Real-world adversary pattern:**
- Ransomware families use batch scripts or PowerShell loops to iterate over a hardcoded list of 50–200 services and stop each one.
- Common targets: `WinDefend`, `wscsvc`, `MsMpSvc`, `VSS`, `wbengine`, `SQLSERVERAGENT`, `MSSQLSERVER`, backup agent services.
- Commands observed in the wild: `sc stop <name>`, `net stop <name> /y`, `taskkill /f /im <process>`, WMI `Win32_Service.StopService()`.

**Why it matters:** Stopping VSS and wbengine prevents shadow copy-based recovery after ransomware encryption. Stopping WinDefend removes real-time protection. Stopping wscsvc hides security health alerts from the user.

### T1562.001 — Impair Defenses: Disable or Modify Tools

**What the test does:** The test checks whether `taskkill.exe` is accessible (a prerequisite for process-kill chains), and optionally executes NetExec (`nxc.exe`) with `--services` against localhost to simulate SMB-based remote service enumeration — a common lateral movement prerequisite.

**Real-world adversary pattern:**
- Disable Defender via registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1`
- Stop via `sc stop WinDefend` (blocked by Tamper Protection on modern Windows)
- Kill AV processes: `taskkill /f /im MsMpEng.exe`
- Use BYOVD (Bring Your Own Vulnerable Driver) to kill PPL-protected processes
- Remote service control via SMB using stolen credentials (NetExec pattern)

---

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact on Operations)

1. **Enable Windows Defender Tamper Protection** — Prevents any process, including SYSTEM, from stopping WinDefend, disabling real-time protection, or modifying Defender policy. Enables via Intune or registry under `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 5`.
2. **Set WinDefend service start type to Automatic (Protected)** — Ensures Defender restarts even if a stop attempt partially succeeds before PPL kicks in.
3. **Enable Enhanced audit policy for Object Access and Process Creation** — Captures all `sc.exe` and `taskkill.exe` invocations with full command lines (requires `Audit Process Creation` + `Include command line in process creation events` GPO setting).
4. **Restrict taskkill.exe via AppLocker/WDAC publisher rule** — Allow execution only from `%WINDIR%\System32\` signed by Microsoft; block execution from arbitrary working directories.
5. **Block NetExec/offensive tool known hashes** via Windows Defender controlled folder access and hash-based custom indicators in Defender for Endpoint.

### Medium-Term (1–2 Weeks — Medium Planning Required)

1. **Deploy Attack Surface Reduction (ASR) rules** — Specifically:
   - Rule `d4f940ab-401b-4efc-aadc-ad5f3c50688a` — Block process creations originating from PSExec and WMI commands (limits remote service control).
   - Rule `e6db77e5-3df2-4cf1-b95a-636979351e5b` — Block persistence through WMI event subscription.
2. **Harden SCM (Service Control Manager) DACL** — Remove `SC_MANAGER_ALL_ACCESS` from the `Users` group in SCM DACL. Allow `SERVICE_QUERY_STATUS` read-only for standard users; restrict write operations to `SYSTEM` and explicit admin accounts only.
3. **Restrict SMB lateral movement** — Deploy Windows Firewall rules blocking outbound and inbound TCP/445 between endpoints (allow only to/from designated management jump hosts and domain controllers).
4. **Enable Credential Guard and LSA PPL** — Prevents credential theft from LSASS, which attackers use to obtain tokens for remote service control via NetExec.
5. **Audit and restrict who can register new services** — Apply a GPO-based software restriction preventing `sc.exe create` except from `NT AUTHORITY\SYSTEM` and specific admin accounts.

### Strategic (1–3 Months — Architecture-Level Changes)

1. **Deploy Windows Defender Application Control (WDAC) in enforced mode** — Prevent unsigned or untrusted binaries (such as downloaded NetExec builds) from executing anywhere on the endpoint.
2. **Implement Privileged Access Workstations (PAW)** — Tier-0 and Tier-1 admin operations should originate only from hardened, monitored management workstations that have explicit allow-listed service control capabilities.
3. **Deploy Microsoft Defender for Endpoint (MDE) with Tamper Protection in Intune** — Provides cloud-backed enforcement of Tamper Protection that cannot be bypassed via local registry edits even with local admin rights.
4. **Enable Protected Process Light (PPL) for third-party AV/EDR** — Requires AV vendors to sign their service processes as PPL; prevents even admins from terminating the security service process without a kernel-level exploit.
5. **Integrate SIEM correlation rules for service kill chain detection** — Alert on: (a) 3+ distinct security service queries within 60 seconds from the same PID, (b) `sc stop` or `net stop` issued against any service whose name matches a known security service list.

---

## Cross-Platform Hardening Scripts

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10_hardening.ps1` | PowerShell with -Undo and -WhatIf support; hardens SCM DACL, Tamper Protection, ASR rules, audit policy, and firewall |

> Note: T1489 and T1562.001 are Windows-centric techniques relying on the Windows Service Control Manager, `sc.exe`, and Windows Defender. Linux and macOS hardening scripts are not applicable for this specific test; equivalent coverage on those platforms requires systemd service protection and AV process watchdog configuration addressed separately.

---

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| Bulk Security Service Query | 3+ `sc query` calls targeting WinDefend/wscsvc/VSS/wbengine within 60s from a single non-SYSTEM process | High | P2 |
| Service Stop — Security Service | `sc stop` or `net stop` against WinDefend, wscsvc, MsMpSvc, or wbengine | High | P1 |
| New Service Created Then Immediately Stopped | `sc create` followed by `sc stop` on same service within 30s | Medium | P3 |
| taskkill.exe Invoked by Non-Admin Process | `taskkill.exe` spawned from a process running as a standard user or with unusual parent | Medium | P3 |
| NetExec / nxc.exe Execution | Process creation event where image name is `nxc.exe` or SHA1 matches known NetExec builds | High | P1 |
| SMB Service Enumeration from Endpoint | Outbound TCP/445 with DCERPC `svcctl` service enumeration RPC call from non-management host | High | P2 |
| Tamper Protection Alert | Windows Security Center event ID 5013 (Tamper Protection blocked change) | High | P1 |

### Containment (First 15 Minutes)

- [ ] **Isolate the affected host** from the network — use MDE "Isolate device" action or remove from switch port. Preserve localhost-only connectivity for IR tooling.
- [ ] **Identify the process tree** — find the parent PID that spawned `sc.exe` / `taskkill.exe`. Check if the parent is an interactive shell, a scheduled task, or a remote session.
- [ ] **Suspend (do not kill)** the parent process to freeze attacker state for forensics: `Get-Process -Id <PID> | Suspend-Process`
- [ ] **Preserve memory** of the suspicious process before any remediation: `procdump.exe -ma <PID> C:\IR\<PID>_memdump.dmp`
- [ ] **Check if WinDefend is still running**: `sc query WinDefend` — if STOPPED, re-enable immediately via `sc start WinDefend` and verify Tamper Protection status.
- [ ] **Verify shadow copies are intact**: `vssadmin list shadows` — if none exist, the attacker may have already executed a ransomware payload.

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Security Event Log | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | `wevtutil epl Security C:\IR\Security.evtx` |
| System Event Log | `%SystemRoot%\System32\winevt\Logs\System.evtx` | `wevtutil epl System C:\IR\System.evtx` |
| Application Event Log | `%SystemRoot%\System32\winevt\Logs\Application.evtx` | `wevtutil epl Application C:\IR\Application.evtx` |
| Prefetch (sc.exe, taskkill.exe, nxc.exe) | `%SystemRoot%\Prefetch\` | `Copy-Item C:\Windows\Prefetch\SC*.pf C:\IR\` |
| Services registry hive | `HKLM\SYSTEM\CurrentControlSet\Services` | `reg export HKLM\SYSTEM\CurrentControlSet\Services C:\IR\Services.reg` |
| Running processes snapshot | Memory | `Get-Process | Export-Csv C:\IR\processes.csv` |
| Network connections snapshot | Memory | `netstat -ano > C:\IR\netstat.txt` |
| Scheduled tasks | `%SystemRoot%\System32\Tasks\` | `schtasks /query /fo CSV /v > C:\IR\tasks.csv` |
| Recent PowerShell command history | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | `Copy-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" C:\IR\` |
| MDE Alert timeline | Microsoft 365 Defender portal | Export via `https://security.microsoft.com` → Incidents |

### Eradication

Perform AFTER evidence collection is confirmed complete.

1. **Remove any unrecognized services** registered during the incident:
   - `sc query type= all state= all | findstr SERVICE_NAME`
   - Cross-reference against known-good baseline; delete unknown entries with `sc delete <name>`
2. **Restore Defender Tamper Protection** if it was disabled:
   - `Set-MpPreference -DisableTamperProtection $false` (requires MDE cloud or admin)
   - Verify: `Get-MpComputerStatus | Select-Object IsTamperProtected`
3. **Remove dropped binaries** associated with offensive tooling (e.g., `nxc.exe`, any unknown `.exe` in temp or user-writable paths):
   - Scan with: `Get-ChildItem C:\Users -Recurse -Include *.exe | Get-AuthenticodeSignature | Where-Object {$_.Status -ne "Valid"}`
4. **Re-enable any stopped security services** and verify startup type:
   - `sc config WinDefend start= auto && sc start WinDefend`
   - `sc config wscsvc start= auto && sc start wscsvc`
   - `sc config VSS start= demand` (VSS is demand-start by design)
5. **Reset SCM DACL** to default if it was modified — apply hardening script with `-Undo` first, then re-apply hardened baseline.
6. **Rotate credentials** for any account seen issuing service control commands or authenticated via SMB during the incident window.

### Recovery

- [ ] Verify all attack artifacts removed (unknown services, dropped binaries)
- [ ] Confirm WinDefend, wscsvc, and VSS services are running at correct startup type
- [ ] Re-enable Tamper Protection and validate via `Get-MpComputerStatus`
- [ ] Restore any modified audit policy settings using `auditpol /restore`
- [ ] Create a fresh VSS snapshot after confirming clean state: `vssadmin create shadow /for=C:`
- [ ] Reconnect host to network only after clean-state verification
- [ ] Apply the hardening script (`_hardening.ps1`) on the recovered host before returning to production
- [ ] Verify ASR rules are active: `Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids`

### Post-Incident Review

1. How was the activity first detected — SIEM alert, EDR alert, or manual observation? What was the detection-to-response time?
2. Was Tamper Protection enabled at the time? If not, what process removed it and when?
3. Did the attacker successfully stop any security service, or were all stop attempts blocked?
4. Were any VSS snapshots deleted? What is the earliest clean recovery point?
5. What privilege level did the attacker process run at — local admin, domain admin, SYSTEM?
6. How did the attacker obtain the privilege required to issue service control commands?
7. What architectural control would have prevented this entirely (e.g., WDAC policy, PAW enforcement, MDE P2 with Tamper Protection)?

---

## References

- [MITRE ATT&CK T1489 — Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE M1054 — Software Configuration (Tamper Protection)](https://attack.mitre.org/mitigations/M1054/)
- [MITRE M1018 — User Account Management](https://attack.mitre.org/mitigations/M1018/)
- [MITRE M1038 — Execution Prevention](https://attack.mitre.org/mitigations/M1038/)
- [MITRE M1022 — Restrict File and Directory Permissions](https://attack.mitre.org/mitigations/M1022/)
- [MITRE M1024 — Restrict Registry Permissions](https://attack.mitre.org/mitigations/M1024/)
- [MITRE M1030 — Network Segmentation](https://attack.mitre.org/mitigations/M1030/)
- [Microsoft — Protect security settings with Tamper Protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
- [Microsoft — Attack Surface Reduction rules reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft — Service Control Manager security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [CIS Benchmark — Windows Server 2022, Section 2.3.9 (Network Access)](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [CISA Advisory AA23-165A — LockBit 3.0 Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a)
- [CISA Advisory AA21-265A — Conti Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a)
- [NSA/CISA Cybersecurity Advisory — BlackCat/ALPHV Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a)
- [NetExec GitHub Repository](https://github.com/Pennyw0rth/NetExec)
- [Microsoft Security Blog — Service Stop in Ransomware Kill Chains](https://www.microsoft.com/en-us/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/)
