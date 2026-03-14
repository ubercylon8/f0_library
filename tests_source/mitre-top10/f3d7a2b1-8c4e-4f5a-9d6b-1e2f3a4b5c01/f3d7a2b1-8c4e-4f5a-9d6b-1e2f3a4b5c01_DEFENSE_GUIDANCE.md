# Defense Guidance: PowerShell Execution & AMSI Detection

## Executive Summary

PowerShell (T1059.001) is consistently among the most observed techniques in real-world intrusions, appearing in the toolkits of ransomware operators, APT groups, and commodity malware alike. Coupled with deobfuscation/decoding techniques (T1140), attackers use encoded commands, download cradles, and hidden-window invocations to evade command-line inspection tools and bypass the Antimalware Scan Interface (AMSI). This test exposes four distinct execution patterns that indicate whether endpoint controls are correctly configured.

Key findings and priority recommendations:

1. Enable PowerShell Constrained Language Mode (CLM) via WDAC — this is the single highest-impact control.
2. Enable Script Block Logging (Event ID 4104) and Module Logging — these decode obfuscation at the point of execution.
3. Enforce AMSI provider registration and monitor for tampering with AMSI-related registry keys.
4. Deploy ASR rule `d4f940ab-401b-4efc-aadc-ad5f3c50688a` (Block Office applications from creating child processes) and related PowerShell execution rules.
5. Restrict PowerShell to signed scripts via execution policy backed by WDAC (execution policy alone is trivially bypassed).

---

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01 |
| **Test Name** | PowerShell Execution & AMSI Detection |
| **MITRE ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — PowerShell; [T1140](https://attack.mitre.org/techniques/T1140/) — Deobfuscate/Decode Files or Information |
| **Tactics** | Execution, Defense Evasion |
| **Severity** | High |
| **Threat Actor** | N/A (technique is universal — used by APT29, Lazarus, FIN7, ransomware operators) |
| **Test Score** | 7.5/10 |

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|------------------------|
| T1059.001 — Command and Scripting Interpreter: PowerShell | Execution | M1042 — Disable or Remove Feature or Program; M1045 — Code Signing; M1026 — Privileged Account Management; M1038 — Execution Prevention |
| T1140 — Deobfuscate/Decode Files or Information | Defense Evasion | M1049 — Antivirus/Antimalware; M1040 — Behavior Prevention on Endpoint |

### Mitigation Detail

| M-Code | Name | Relevance to This Test |
|--------|------|------------------------|
| M1042 | Disable or Remove Feature or Program | Remove or constrain PowerShell v2 (lacks AMSI/logging); disable WMI remoting if unused |
| M1045 | Code Signing | Enforce AllSigned execution policy backed by WDAC; require scripts to carry valid Authenticode signatures |
| M1026 | Privileged Account Management | Restrict which accounts may execute PowerShell with -ExecutionPolicy Bypass; enforce JEA for administrative tasks |
| M1038 | Execution Prevention | WDAC/AppLocker to block unsigned PowerShell scripts; block powershell.exe from untrusted paths |
| M1049 | Antivirus/Antimalware | Ensure AMSI provider is registered and active; keep AV signatures current; enable real-time protection |
| M1040 | Behavior Prevention on Endpoint | EDR behavioral rules to detect -EncodedCommand, -WindowStyle Hidden, download cradle strings; AMSI content scanning |

---

## Hardening Recommendations

### Quick Wins (Immediate — Low Effort, High Return)

1. **Enable PowerShell Script Block Logging** — Group Policy: `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging`. Set to Enabled. This decodes base64 and obfuscated content at the point of execution and writes it to Event ID 4104.
2. **Enable PowerShell Module Logging** — Set `Turn on Module Logging` to Enabled with `*` as the module name. Captures all pipeline activity in Event ID 4103.
3. **Enable PowerShell Transcription** — Write full transcript to a centralized share. Provides human-readable record of all PowerShell activity.
4. **Disable PowerShell v2** — `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`. PowerShell v2 bypasses AMSI and all modern logging.
5. **Verify AMSI health** — Confirm `HKLM\SOFTWARE\Microsoft\AMSI\Providers` is populated and not modified. Audit with Get-MpComputerStatus.
6. **Enable Windows Defender Real-Time Protection** — Ensure `Set-MpPreference -DisableRealtimeMonitoring $false` is set and protected against tampering.

### Medium-Term (1–2 Weeks — Policy/Configuration Changes)

1. **Deploy Attack Surface Reduction (ASR) rules** — Enable the following rules in Audit mode first, then Block:
   - `d4f940ab-401b-4efc-aadc-ad5f3c50688a` — Block Office applications from creating child processes
   - `3b576869-a4ec-4529-8536-b80a7769e899` — Block Office applications from creating executable content
   - `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` — Block executable content from email/webmail
   - `e6db77e5-3df2-4cf1-b95a-636979351e5b` — Block persistence through WMI event subscription
2. **Restrict PowerShell execution policy via GPO** — Set `Restricted` or `AllSigned` at machine scope via GPO. Pair with WDAC to prevent -ExecutionPolicy Bypass overrides.
3. **Implement PowerShell Constrained Language Mode (CLM)** — Use WDAC policies to enforce CLM on untrusted code. CLM prevents .NET reflection calls used for AMSI bypasses.
4. **Enable Protected Event Logging** — Encrypt PowerShell event log entries so they cannot be tampered with. GPO: `Turn on PowerShell Script Block Logging` with `Log script block invocation start / stop events`.
5. **Monitor AMSI registry keys for tampering** — Alert on writes to `HKLM\SOFTWARE\Microsoft\AMSI\` and `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`.
6. **Configure Process Creation Auditing** — Ensure `Audit Process Creation` is set to Success and that `Include command line in process creation events` (GPO) is enabled. This populates Event ID 4688 with full command line.

### Strategic (1–3 Months — Requires Planning)

1. **Deploy Windows Defender Application Control (WDAC)** — Author and deploy a policy that enforces code integrity for PowerShell. Use WDAC Audit mode for 2–4 weeks before enforcement. This is the definitive control for preventing unsigned script execution.
2. **Implement Just Enough Administration (JEA)** — Replace interactive privileged PowerShell sessions with constrained JEA endpoints. Limits blast radius when credentials are compromised.
3. **Adopt a tiered PAM model** — Prevent credential reuse across trust zones; use Privileged Access Workstations (PAWs) for all administrative PowerShell usage.
4. **Deploy centralized PowerShell log aggregation** — Forward Event IDs 4103, 4104, 4688, 1 (Sysmon process creation) to SIEM. Build detection analytics on PowerShell -EncodedCommand, -WindowStyle Hidden, download cradle patterns, and AMSI bypass strings.
5. **Evaluate application allowlisting** — AppLocker or WDAC publisher rules to restrict which binaries may call powershell.exe as a parent.

---

## Cross-Platform Hardening Scripts

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01_hardening.ps1` | PowerShell script — enables logging, disables PS v2, configures Defender/AMSI, ASR rules, audit policy. Supports -Undo and -WhatIf. |

> Note: This test targets Windows endpoints only. Linux and macOS hardening scripts are not generated for this test.

---

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| PowerShell Encoded Command | Process creation: `powershell.exe` with `-EncodedCommand` or `-enc` argument | High | P2 |
| PowerShell Hidden Window | Process creation: `powershell.exe` with `-WindowStyle Hidden` | High | P2 |
| PowerShell Execution Policy Bypass | Command line contains `-ExecutionPolicy Bypass` or `-ep bypass` | Medium | P2 |
| Download Cradle Pattern | Script block log (4104) contains `Net.WebClient`, `DownloadString`, `IEX`, `Invoke-Expression` | High | P1 |
| AMSI Bypass String Detected | Script block log (4104) contains `AmsiScanBuffer`, `amsiInitFailed`, `AmsiUtils`, `[Ref].Assembly.GetType` | High | P1 |
| AMSI Provider Registry Modification | Registry write to `HKLM\SOFTWARE\Microsoft\AMSI\Providers` | High | P1 |
| PowerShell v2 Invocation | Process creation: `powershell.exe -Version 2` | High | P2 |
| Suspicious PS Parent Process | `powershell.exe` spawned by `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe` | High | P1 |

### Containment (First 15 Minutes)

- [ ] Identify the affected host via SIEM alert or EDR telemetry. Note hostname, username, process tree, and command line.
- [ ] Isolate the host at the network level via EDR (LiveResponse network isolation) or VLAN change — prevent lateral movement and C2 callbacks.
- [ ] Terminate the suspicious PowerShell process if still running: `Stop-Process -Id <PID> -Force`
- [ ] If a download cradle was observed, immediately null-route the destination IP/domain at the perimeter.
- [ ] Disable the affected user account if credential compromise is suspected: `Disable-ADAccount -Identity <username>`
- [ ] Preserve volatile memory if possible before isolation: use EDR memory acquisition or `procdump.exe -ma <PID>`.

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|--------------------|
| Security event log | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | `wevtutil epl Security C:\IR\Security.evtx` |
| PowerShell Operational log | `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx` | `wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\IR\PSOperational.evtx` |
| Script block log entries | Event ID 4104 in PS Operational log | `Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" | Export-Csv C:\IR\ScriptBlocks.csv` |
| Process creation log | Security log, Event ID 4688 | `wevtutil qe Security "/q:*[System[EventID=4688]]" /f:text > C:\IR\ProcessCreation.txt` |
| Prefetch files | `C:\Windows\Prefetch\POWERSHELL.EXE-*.pf` | `Copy-Item C:\Windows\Prefetch\POWERSHELL* C:\IR\Prefetch\` |
| Sysmon log (if deployed) | `Microsoft-Windows-Sysmon/Operational` | `wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\IR\Sysmon.evtx` |
| PowerShell transcript | `%USERPROFILE%\Documents\` (if transcription enabled) | `Get-ChildItem -Path $env:USERPROFILE\Documents -Filter "*.txt" -Recurse | Copy-Item -Destination C:\IR\Transcripts\` |
| Scheduled tasks | `C:\Windows\System32\Tasks\` | `schtasks /query /fo LIST /v > C:\IR\ScheduledTasks.txt` |
| Run keys | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" C:\IR\RunKey.reg` |
| AMSI provider registry | `HKLM\SOFTWARE\Microsoft\AMSI` | `reg export "HKLM\SOFTWARE\Microsoft\AMSI" C:\IR\AMSI.reg` |

### Investigation Steps

1. Review PowerShell script block log (Event 4104) — the decoded content of all obfuscated commands appears here regardless of encoding.
2. Decode any base64 payload found in Event 4688 command line: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<string>'))`.
3. Identify all files written or modified during the PowerShell session using EDR file telemetry or `C:\IR\Sysmon.evtx` (Event ID 11).
4. Determine whether any network connections were made (Event ID 3 in Sysmon, or EDR network telemetry) — download cradle patterns produce outbound HTTP/HTTPS connections.
5. Check for persistence: review scheduled tasks, Run keys, WMI subscriptions, and service installations created within the investigation timeframe.
6. Determine the initial vector — what spawned the PowerShell process? Check parent process in Event 4688 or Sysmon Event 1.
7. If AMSI bypass strings were present, check whether Defender/AV was disabled or AMSI patched in memory: `Get-MpComputerStatus`, inspect `HKLM\SOFTWARE\Microsoft\AMSI\Providers`.

### Eradication

- Remove any persistence mechanisms identified during investigation (scheduled tasks, Run keys, WMI subscriptions, services) — document each before removal.
- If AMSI was tampered with (registry modification or in-memory patch), restore affected system from known-good image.
- Delete any payloads downloaded or staged by the PowerShell session.
- Re-enable any security controls that were disabled (Defender real-time protection, AMSI providers).
- Reset credentials for the affected account and any accounts whose credentials were accessible from the compromised session.

### Recovery

- [ ] Verify all attack artifacts removed (files, registry keys, scheduled tasks, services).
- [ ] Confirm Defender real-time protection is active: `Get-MpComputerStatus | Select RealTimeProtectionEnabled`.
- [ ] Confirm AMSI providers are intact: `Get-ChildItem HKLM:\SOFTWARE\Microsoft\AMSI\Providers`.
- [ ] Confirm PowerShell v2 is disabled: `Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`.
- [ ] Confirm Script Block Logging is enabled: check GPO or `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`.
- [ ] Confirm ASR rules are active: `Get-MpPreference | Select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions`.
- [ ] Reconnect host to network after verification.
- [ ] Monitor host for 72 hours post-recovery for re-infection indicators.

### Post-Incident

1. How was the attack first detected — EDR alert, SIEM rule, script block log, or user report? Was detection timely?
2. What was detection-to-containment time? Target is under 15 minutes for active execution.
3. Was PowerShell Script Block Logging enabled prior to the incident? If not, the decoded payload may be unrecoverable.
4. Was AMSI functioning correctly at the time of the incident? Were any bypass strings found in script block logs?
5. What would have prevented this — WDAC Constrained Language Mode, execution policy enforcement, or blocking the initial access vector?
6. Update detection rules and threat hunt queries based on specific patterns observed.

---

## References

- [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1140 — Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [MITRE M1042 — Disable or Remove Feature or Program](https://attack.mitre.org/mitigations/M1042/)
- [MITRE M1045 — Code Signing](https://attack.mitre.org/mitigations/M1045/)
- [MITRE M1026 — Privileged Account Management](https://attack.mitre.org/mitigations/M1026/)
- [MITRE M1038 — Execution Prevention](https://attack.mitre.org/mitigations/M1038/)
- [MITRE M1049 — Antivirus/Antimalware](https://attack.mitre.org/mitigations/M1049/)
- [MITRE M1040 — Behavior Prevention on Endpoint](https://attack.mitre.org/mitigations/M1040/)
- [Microsoft: PowerShell Security Features](https://learn.microsoft.com/en-us/powershell/scripting/learn/security-features)
- [Microsoft: AMSI Developer Guide](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [Microsoft: Windows Defender Application Control (WDAC)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/)
- [Microsoft: Attack Surface Reduction Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [CIS Benchmark: Windows 11 — Section 18.9.91 (Windows PowerShell)](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [NSA/CISA: Keeping PowerShell: Security Measures to Use and Embrace](https://media.defense.gov/2022/Jun/22/2003021689/-1/-1/1/CSI_KEEPING_POWERSHELL_SECURITY_MEASURES_TO_USE_AND_EMBRACE_20220622.PDF)
- [CISA SCuBA M365 Security Baseline](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project)
