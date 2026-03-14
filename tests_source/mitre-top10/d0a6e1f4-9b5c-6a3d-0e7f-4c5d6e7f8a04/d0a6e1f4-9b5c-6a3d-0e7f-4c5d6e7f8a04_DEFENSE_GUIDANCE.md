# Defense Guidance: WMI Execution Simulation

## Executive Summary

Windows Management Instrumentation (WMI) is one of the most frequently abused built-in Windows capabilities in modern threat actor campaigns. Because WMI is a legitimate administrative interface present on every Windows system, attacks using it blend naturally with authorized activity, making detection and prevention significantly harder than for tooling that is obviously foreign to the environment.

This test exercises T1047 (WMI execution and enumeration via `wmic.exe`) and T1546.003 (WMI Event Subscription persistence inspection). Successful execution of these patterns without EDR intervention indicates that the endpoint lacks adequate WMI telemetry, process-creation monitoring, or behavioral analytics. Priority actions are: deploy Attack Surface Reduction rule 9e6c4e1f (Block process creations originating from PSExec and WMI commands), enable WMI activity logging, and restrict WMI namespace access via DCOM security policy.

---

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04 |
| **Test Name** | WMI Execution Simulation |
| **MITRE ATT&CK** | [T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) · [T1546.003 — WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/) |
| **Tactics** | Execution, Persistence |
| **Severity** | High |
| **Threat Actor** | N/A (technique broadly used by APT29, Lazarus, FIN7, ransomware operators) |
| **Subcategory** | execution |
| **Tags** | wmi, wmic, event-subscription, lateral-tool-transfer, process-creation, stealthy |

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|----------------------|
| T1047 — Windows Management Instrumentation | Execution | M1026 — Privileged Account Management · M1040 — Behavior Prevention on Endpoint · M1018 — User Account Management |
| T1546.003 — Event Triggered Execution: WMI Event Subscription | Persistence | M1026 — Privileged Account Management · M1040 — Behavior Prevention on Endpoint · M1018 — User Account Management · M1038 — Execution Prevention |

### Mitigation Details

**M1026 — Privileged Account Management**
Prevent adversaries from using high-privilege accounts to interact with WMI. Non-administrative users should not have remote DCOM/WMI access. Restrict membership in the local Administrators and DCOM Launch/Activation groups. Use dedicated service accounts with least-privilege for any legitimate WMI-dependent software.

**M1040 — Behavior Prevention on Endpoint**
Deploy an EDR product with behavioral analytics capable of detecting `wmiprvse.exe` spawning unusual child processes, `Win32_Process.Create` method calls, and WMI event subscription creation. Microsoft Defender for Endpoint's attack surface reduction rules directly address WMI process-creation patterns.

**M1018 — User Account Management**
Limit which accounts can perform remote WMI operations. Modify DCOM security settings (Component Services > My Computer > Properties > COM Security) to deny remote activation to non-administrative accounts. Use `WMI Control` (wmimgmt.msc) to restrict namespace permissions on `ROOT\CIMV2` and related namespaces.

**M1038 — Execution Prevention**
Use application control (WDAC/AppLocker) to prevent execution of `wmic.exe` by users who do not require it. `wmic.exe` was deprecated in Windows 11 22H2; where operationally feasible, disable or remove it entirely on endpoints that do not require it.

---

## Hardening Recommendations

### Quick Wins (Immediate — Low Operational Impact)

1. **Enable ASR rule: Block process creations originating from PSExec and WMI commands** (GUID `9e6c4e1f-11b8-4807-94a6-deeb567a5490`) — set to Audit first, then Block after validating no false positives with legitimate admin tooling.
2. **Enable WMI activity logging** — turn on the `Microsoft-Windows-WMI-Activity/Operational` event log (Event ID 5857, 5858, 5859, 5860, 5861). This is disabled by default on many systems.
3. **Enable Security audit for Object Access** and **Process Creation** audit subcategories to capture `wmic.exe` command-line arguments in Security Event Log (Event ID 4688 with command-line logging enabled).
4. **Configure Windows Event Forwarding (WEF)** to ship WMI activity, Security, and Sysmon logs to a central SIEM.
5. **Deploy Sysmon** with a configuration that includes `WmiEvent` and `ProcessCreate` rules for `wmic.exe` and `wmiprvse.exe` (Sysmon Event IDs 19, 20, 21 for WMI event subscription activity).

### Medium-Term (1–2 Weeks — Moderate Operational Impact)

1. **Restrict DCOM remote access** — in Component Services (`dcomcnfg`), under My Computer > Properties > COM Security, remove remote access permissions for standard user accounts and limit remote activation to Administrators only.
2. **Harden WMI namespace permissions** — open `wmimgmt.msc`, navigate to `ROOT\CIMV2`, and remove the `Everyone` / `NETWORK` ACE. Retain only `Administrators` and service accounts that legitimately require WMI.
3. **Transition off wmic.exe** — audit which processes and scripts still invoke `wmic.exe`; migrate to PowerShell `Get-WmiObject` / `Get-CimInstance` (which produce richer telemetry) or direct API calls. Once migrated, block `wmic.exe` via WDAC.
4. **Enable AppLocker / WDAC for wmic.exe** — create a deny rule for `wmic.exe` for all non-administrative standard users.
5. **Audit existing WMI event subscriptions** — run `Get-WMIObject -Namespace root\subscription -Class __EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` on all managed endpoints. Any unexpected subscriptions should be investigated immediately as T1546.003 persistence.
6. **Enable Protected Event Logging** — configure `EnableScriptBlockLogging` and `EnableTranscription` in PowerShell Group Policy and enable `Protected Event Logging` (Group Policy: `Computer Configuration > Administrative Templates > Windows Components > Event Logging`) to protect log integrity.

### Strategic (1–3 Months — Requires Planning)

1. **Deploy Microsoft Defender for Endpoint (MDE) with full behavioral prevention** — MDE's AMSI integration and behavioral engine detect `Win32_Process.Create` calls, WMI lateral movement, and event subscription abuse. Ensure the security profile is set to `Block` rather than `Audit` for WMI-related rules.
2. **Implement Zero-Trust for administrative interfaces** — require Privileged Access Workstations (PAWs) for all WMI-dependent administrative tasks. Block general-purpose endpoints from initiating outbound DCOM/RPC (TCP 135 + dynamic high ports) to server tiers.
3. **Network segmentation for RPC/DCOM** — deploy host-based or network firewall rules that restrict TCP port 135 and the DCOM dynamic port range (49152–65535) to only authorized management systems, eliminating the remote WMI lateral movement surface.
4. **Deploy a deception platform** — place WMI honeypot subscriptions (`__EventFilter` with distinctive names) that alert on any process that deletes or modifies them, providing high-confidence detection of WMI persistence tampering.
5. **Enforce LAPS and tiered credential model** — prevent credential reuse that enables remote WMI execution across tiers. Local Administrator Password Solution (LAPS) ensures each endpoint has a unique local admin credential, eliminating the pass-the-hash / pass-the-ticket lateral movement via DCOM/WMI.

---

## Hardening Scripts

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04_hardening.ps1` | PowerShell — ASR, Defender, audit policy, WMI namespace restrictions, wmic.exe control; supports `-Undo` and `-WhatIf` |

---

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| WMI Process Creation via wmic.exe | `wmic.exe` process with arguments containing `process call create` | High | P1 |
| wmiprvse.exe Spawning Unusual Child | `wmiprvse.exe` as parent of any process other than `mofcomp.exe`, `scrcons.exe` (known legitimate) | High | P1 |
| WMI Shadow Copy Enumeration | `wmic.exe` with `shadowcopy` in command line | High | P1 |
| WMI Event Subscription Creation | Security event 4703 or WMI-Activity/Operational 5861 — `__EventFilter`, `__EventConsumer`, or `__FilterToConsumerBinding` creation | High | P1 |
| Remote WMI / DCOM Lateral Movement | Outbound TCP 135 from workstation-class endpoints, followed by WMI activity on the destination | Medium | P2 |
| WMI Namespace Enumeration | Multiple rapid `ROOT\CIMV2` queries from a non-administrative user context | Medium | P2 |

### Containment (First 15 Minutes)

- [ ] **Isolate the endpoint** — use EDR console to network-isolate the affected host; preserve memory before isolation if ransomware activity is suspected.
- [ ] **Kill suspicious wmiprvse.exe children** — terminate any process spawned under `wmiprvse.exe` that is not part of a known-good administrative baseline.
- [ ] **Stop outbound DCOM/RPC** — if remote WMI lateral movement is suspected, block TCP 135 and 49152-65535 on the affected host's firewall: `netsh advfirewall firewall add rule name="IR-Block-DCOM" dir=out protocol=tcp remoteport=135 action=block`.
- [ ] **Invalidate any credentials present on the host** — if lateral movement via WMI is confirmed, rotate all accounts whose credentials were cached on the affected system (run `klist purge`, reset AD accounts).
- [ ] **Preserve volatile evidence** — capture process list, network connections, and WMI subscription state before any remediation.

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Security Event Log | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | `wevtutil epl Security C:\IR\Security.evtx` |
| WMI Activity Log | `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx` | `wevtutil epl "Microsoft-Windows-WMI-Activity/Operational" C:\IR\WMI-Activity.evtx` |
| Sysmon Log | `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | `wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\IR\Sysmon.evtx` |
| WMI Repository | `%SystemRoot%\System32\wbem\Repository\` | `robocopy "%SystemRoot%\System32\wbem\Repository" C:\IR\WMI-Repo /E` |
| WMI Event Subscriptions | WMI namespace | `Get-WMIObject -Namespace root\subscription -Class __EventFilter \| Export-Csv C:\IR\WMI-EventFilters.csv` |
| WMI Event Consumers | WMI namespace | `Get-WMIObject -Namespace root\subscription -Class __EventConsumer \| Export-Csv C:\IR\WMI-EventConsumers.csv` |
| WMI FilterToConsumer Bindings | WMI namespace | `Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding \| Export-Csv C:\IR\WMI-Bindings.csv` |
| Running Processes (snapshot) | Memory | `Get-Process \| Select-Object Id,Name,Path,CommandLine \| Export-Csv C:\IR\Processes.csv` |
| Network Connections (snapshot) | Memory | `netstat -bano > C:\IR\netstat.txt` |

### Eradication

**After completing evidence collection:**

1. **Remove malicious WMI event subscriptions** (if T1546.003 persistence found):
   ```powershell
   # Remove by name — replace <FilterName> with actual name found in evidence
   Get-WMIObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq "<FilterName>" } | Remove-WMIObject
   Get-WMIObject -Namespace root\subscription -Class __EventConsumer | Where-Object { $_.Name -eq "<ConsumerName>" } | Remove-WMIObject
   Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*<FilterName>*" } | Remove-WMIObject
   ```
2. **Remove any scripts or binaries dropped by WMI-spawned processes** — examine the command-line arguments captured in WMI activity logs for file paths, then delete them.
3. **Purge WMI repository if corrupted or heavily abused** — only as a last resort: `winmgmt /resetrepository` (requires a reboot and may impact legitimate WMI-dependent applications).
4. **Remove scheduled tasks** that may have been created as secondary persistence by the same actor.
5. **Reset credentials** of all accounts used in or exposed by the attack chain.

### Recovery

- [ ] Verify all malicious WMI subscriptions have been removed (re-run evidence collection queries)
- [ ] Confirm no suspicious processes are running under `wmiprvse.exe`
- [ ] Restore any modified Group Policy / registry settings to secure baseline
- [ ] Re-enable and verify all ASR rules are in Block mode
- [ ] Re-enable WMI activity logging if it was disrupted during the incident
- [ ] Reconnect endpoint to the network after isolation
- [ ] Monitor the host for 24–48 hours post-recovery for signs of re-infection

### Post-Incident Analysis

1. Was the WMI activity detected by existing controls before this test/incident was reported?
2. What was the time between initial WMI execution and detection-to-response?
3. Were WMI event subscriptions found that pre-dated this incident (indicating prior persistent access)?
4. What legitimate applications or administrative tooling use WMI on affected systems — are those now covered by updated detection baselines?
5. Which hardening steps from the Quick Wins list were not yet implemented at time of incident?
6. Were credentials exposed that could enable lateral movement — has a full credential rotation been performed?

---

## References

- [MITRE ATT&CK T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK T1546.003 — WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
- [MITRE M1026 — Privileged Account Management](https://attack.mitre.org/mitigations/M1026/)
- [MITRE M1040 — Behavior Prevention on Endpoint](https://attack.mitre.org/mitigations/M1040/)
- [MITRE M1018 — User Account Management](https://attack.mitre.org/mitigations/M1018/)
- [MITRE M1038 — Execution Prevention](https://attack.mitre.org/mitigations/M1038/)
- [Microsoft — Attack Surface Reduction Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft — Block process creations originating from PSExec and WMI commands (ASR GUID 9e6c4e1f)](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#block-process-creations-originating-from-psexec-and-wmi-commands)
- [Microsoft — Configure WMI Namespace Security](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setting-namespace-security-with-the-wmi-control)
- [CISA Advisory — WMI Persistence (AA22-011A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-011a)
- [CIS Benchmark for Windows — Section 18.9.47 (ASR rules)](https://www.cisecurity.org/cis-benchmarks/)
- [Detecting WMI Abuse — SANS ISC](https://www.sans.org/blog/detecting-wmi-abuse/)
- [Red Canary Threat Detection Report — WMI](https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/)
- [FireEye/Mandiant — Dissecting One of APT29's Fileless WMI and PowerShell Backdoors](https://www.mandiant.com/resources/blog/dissecting-one-of-apt29s-fileless-wmi-and-powershell-backdoors)
