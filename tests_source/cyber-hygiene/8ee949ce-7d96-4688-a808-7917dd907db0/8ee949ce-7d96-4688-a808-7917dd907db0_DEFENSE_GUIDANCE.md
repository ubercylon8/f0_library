# Defense Guidance: Cyber-Hygiene Bundle (Sophos Intercept X Edition)

**Guidance date:** 2026-11-03  
**Target:** Windows endpoints and servers managed by Sophos Intercept X

## Executive Summary

This bundle is a **read-only configuration assessment**, not an exploit or attack simulation. It inspects selected local Windows settings, Sophos service health, and a readable Sophos executable version. It does not test whether an attack is blocked, whether Sophos prevention rules work, or whether logs reach a SIEM.

Priorities are:

1. Restore unhealthy Sophos services through the normal support/change process and validate tamper protection, prevention policy, and cloud check-in in **Sophos Central**.
2. Deploy PowerShell, audit, account, credential-protection, network, and print settings through **Group Policy, Intune, or another approved central baseline**, with role-specific pilots.
3. Remove SMBv1 and legacy name-resolution dependencies only after compatibility testing. Do not disable printing on servers or change LAPS policy merely to make a check pass.
4. Forward and protect security telemetry, then validate prevention and detection with separately authorized exercises.

The accompanying PowerShell script is an optional documentation artifact. It is deliberately limited to reversible PowerShell logging and Point and Print policy values. It does not manage Sophos Central, Defender ASR, services, LAPS, account lockout, SMB, Credential Guard, or network protocols.

## Threat Overview

| Field | Value |
|---|---|
| **Test ID** | 8ee949ce-7d96-4688-a808-7917dd907db0 |
| **Test Name** | Cyber-Hygiene Bundle (Sophos Intercept X Edition) |
| **Category / Subcategory** | cyber-hygiene / baseline |
| **Severity** | High |
| **Platform** | windows-endpoint; several checks also apply to Windows servers |
| **Threat Actor** | N/A — baseline assessment |
| **Primary ATT&CK Techniques** | T1562.001, T1003.001, T1059.001, T1021.002, T1110, T1557.001, T1572, T1078.003, T1569.002, T1547.012, T1078, T1136, T1098 |
| **Additional shared-check mappings** | T1059 (Process Creation auditing), T1562.002 (Audit Policy Change auditing) |

## Scope and Interpretation

### Local evidence collected by the assessment

- **Sophos local health:** `Sophos Endpoint Defense Service` and `Sophos MCS Agent` running state/start mode, plus a readable executable version at known installation paths.
- **Credential protection:** LSASS Protected Process Light, Credential Guard, and Virtualization-Based Security policy values.
- **PowerShell:** script block logging, module logging, transcription, and the Constrained Language policy marker.
- **SMB/network:** SMBv1 driver state, server/client signing, server encryption, null-session restriction, LLMNR, NetBIOS over TCP/IP, WPAD override, and the IPv6 `DisabledComponents` mask.
- **Print:** spooler state and three Point and Print policy values.
- **Identity and telemetry:** LAPS policy markers, nine advanced audit subcategories, local account lockout/password values, and password complexity.

“Local” describes the **evidence source**, not a recommendation to configure each machine manually. Registry policy values can originate from GPO, MDM, security tooling, or manual configuration. Confirm the resulting policy with `gpresult` or the organization’s MDM reporting before changing it.

### Evidence that requires central management

The following controls intentionally remain **unknown/not evaluated** without central evidence:

| Control | Required evidence and remediation owner |
|---|---|
| **CH-SOP-004 — Sophos Prevention Policy** | Export or inspect the effective computer/server policy in Sophos Central. Validate prevention, behavioral, exploit, and credential-theft protections for the device’s actual policy group. Sophos Central administrators own remediation. |
| **CH-SOP-005 — Sophos Recent Cloud Check-in** | Compare endpoint `lastSeenAt` with the organization’s approved threshold. Investigate network, proxy, device, and management-agent causes; a stale check-in alone is not proof of compromise. |
| **CH-SOP-006 — Sophos Tamper Protection** | Verify `tamperProtectionEnabled=true` on tamper-capable endpoints in Sophos Central. Recover tamper state centrally; do not bypass tamper protection locally. |

### Important limitations

- **CH-SOP-003 proves only that a local version string is readable.** It does not establish that the installed Sophos version is current or supported.
- A registry flag is not proof that the security feature is operational. Validate runtime state, event logs, hardware/firmware prerequisites, and centralized policy where applicable.
- The spooler check is intentionally inconclusive on servers until an approved print role is confirmed. **Do not stop or disable Print Spooler blindly on servers, domain controllers, print servers, or application hosts.**
- LAPS is applicable only to appropriately domain- or Entra-joined devices. Do not disable LAPS on servers to resolve a finding; use a documented server policy and exceptions where necessary.
- The Point and Print checks reduce driver-installation risk but do not prove that malicious print processors or every spooler exploit are prevented.
- The IPv6 registry check is a narrow policy marker, not proof that application-level command-and-control tunneling is blocked. Do not disable IPv6 wholesale as a response.
- This is a targeted baseline sample. **It is not a complete CIS Benchmark assessment, a certification, or evidence of compliance with every CIS, Microsoft, or Sophos recommendation.**

## MITRE ATT&CK Mapping

Mitigations below are relevant technique-level options, not claims that the bundle validates each mitigation.

| Technique | Tactic | Applicable Mitigations |
|---|---|---|
| [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) | Defense Evasion | M1018 — User Account Management; M1024 — Restrict Registry Permissions; M1047 — Audit |
| [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) | Credential Access | M1043 — Credential Access Protection; M1028 — Operating System Configuration; M1026 — Privileged Account Management |
| [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Execution | M1038 — Execution Prevention; M1045 — Code Signing; M1047 — Audit |
| [T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) | Lateral Movement | M1035 — Limit Access to Resource Over Network; M1030 — Network Segmentation; M1026 — Privileged Account Management |
| [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | Credential Access | M1036 — Account Use Policies; M1027 — Password Policies; M1032 — Multi-Factor Authentication |
| [T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/) | Credential Access | M1042 — Disable or Remove Feature or Program; M1037 — Filter Network Traffic; M1035 — Limit Access to Resource Over Network |
| [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/) | Command and Control | M1037 — Filter Network Traffic; M1031 — Network Intrusion Prevention; M1030 — Network Segmentation |
| [T1078.003 — Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/) | Defense Evasion, Persistence, Privilege Escalation, Initial Access | M1036 — Account Use Policies; M1027 — Password Policies; M1026 — Privileged Account Management |
| [T1569.002 — System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/) | Execution, Persistence, Privilege Escalation | M1040 — Behavior Prevention on Endpoint; M1026 — Privileged Account Management; M1047 — Audit |
| [T1547.012 — Boot or Logon Autostart Execution: Print Processors](https://attack.mitre.org/techniques/T1547/012/) | Persistence, Privilege Escalation | M1051 — Update Software; M1022 — Restrict File and Directory Permissions; M1026 — Privileged Account Management |
| [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Defense Evasion, Persistence, Privilege Escalation, Initial Access | M1018 — User Account Management; M1026 — Privileged Account Management; M1032 — Multi-Factor Authentication |
| [T1136 — Create Account](https://attack.mitre.org/techniques/T1136/) | Persistence | M1018 — User Account Management; M1026 — Privileged Account Management; M1047 — Audit |
| [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) | Persistence, Privilege Escalation | M1018 — User Account Management; M1026 — Privileged Account Management; M1032 — Multi-Factor Authentication |
| [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | Execution | M1047 — Audit; M1038 — Execution Prevention |
| [T1562.002 — Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/) | Defense Evasion | M1047 — Audit; M1018 — User Account Management; M1024 — Restrict Registry Permissions |

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact)

1. **Triage Sophos health without weakening protection.** If either assessed Sophos service is stopped or not automatic, follow the Sophos support/change process, inspect endpoint and Central events, and restore normal operation. Do not disable tamper protection or remove the agent as a first-line fix.
2. **Enable PowerShell telemetry centrally.** Use GPO/MDM for Script Block Logging and Module Logging; configure module names explicitly (`*` where approved). If transcription is enabled, use a secured central output path, restrictive ACLs, retention controls, and a process for sensitive command content.
3. **Set the assessed audit subcategories through Advanced Audit Policy.** Require Logon success/failure, Logoff success, Account Lockout failure, Special Logon success, Process Creation success, Audit Policy Change success, User Account Management success/failure, Computer Account Management success, and Security Group Management success. Check for legacy audit-policy conflicts and confirm event delivery.
4. **Apply the Point and Print restrictions.** Require administrator approval for driver installation and retain installation/update warnings. Pilot print workflows before broad deployment; do not disable the spooler as part of this quick win.
5. **Review account policy centrally.** This baseline expects lockout threshold 1–5, duration at least 15 minutes or administrator-unlock/“Never,” observation window at least 15 minutes, minimum password length at least 14, and complexity enabled. Assess denial-of-service and service-account impacts before tightening lockout policy.

### Medium-Term (1–2 Weeks — Medium Impact)

1. **Pilot LSASS PPL, Credential Guard, and VBS by hardware/application group.** Use supported Microsoft deployment guidance. Start without UEFI lock where rollback risk must be reduced, validate drivers and authentication compatibility, reboot through change control, and verify operational state rather than only registry values.
2. **Remove legacy SMB safely.** Inventory SMBv1 dependencies, then disable/remove SMBv1 and verify the client driver is disabled after reboot. Stage required SMB client/server signing, null-session restrictions, and encryption where appropriate. Test NAS devices, scanners, legacy applications, clustering, and cross-forest access first.
3. **Reduce name-resolution and relay exposure.** Disable LLMNR and NetBIOS over TCP/IP after DHCP/legacy-application testing. Replace uncontrolled WPAD use with an explicit managed proxy policy; validate WinHTTP and application behavior before setting the WPAD override. SMB signing is a complementary relay control, not a replacement for network segmentation.
4. **Review transition-protocol policy without breaking IPv6.** Inventory required tunnel technologies and preserve unrelated `DisabledComponents` bits. If the organization adopts this bundle’s `0x21` requirement, pilot its tunnel-interface and IPv4-preference effects. Use egress controls and network detection for protocol tunneling; the registry value alone is insufficient.
5. **Deploy Windows LAPS centrally.** Select the approved Entra ID or Active Directory backup mode, unique per-device passwords, appropriate rotation, and tightly controlled password-read permissions. Plan legacy LAPS migration rather than running two unmanaged implementations. Use role-specific server policies and documented exceptions.
6. **Use application control for PowerShell Constrained Language.** Deploy and pilot WDAC or AppLocker; do not set `__PSLockdownPolicy` manually as a substitute. Application control and constrained language should not break administrative tooling.

### Strategic (1–3 Months — Requires Planning)

1. **Adopt tiered administration and strong authentication.** Remove routine administrative use of shared/local accounts, use MFA where supported, prefer managed service accounts, and restrict administrative SMB/RDP/WinRM paths by host and network zone.
2. **Establish policy-as-evidence workflows.** Continuously collect approved, read-only Sophos Central policy/check-in/tamper evidence and correlate it with local endpoint results. Protect API credentials and keep them out of scripts and result files.
3. **Centralize and protect telemetry.** Forward Security, PowerShell Operational, Sophos, and relevant network logs to tamper-resistant storage. Monitor log gaps, unexpected audit changes, and clock/collection failures.
4. **Separate endpoint and server baselines.** Maintain approved print roles, server LAPS coverage, hardware-specific credential protections, and legacy-protocol exceptions with expiry dates and compensating controls.
5. **Validate effectiveness separately.** Use authorized prevention/detection exercises to establish that Sophos and Windows controls stop or reveal the behaviors of interest; do not infer effectiveness from this read-only assessment.

## Hardening Scripts

Only the target platform’s script is included. The test itself never executes this script.

| Platform | Script | Description |
|---|---|---|
| Windows | `8ee949ce-7d96-4688-a808-7917dd907db0_hardening.ps1` | Idempotent local PowerShell logging and Point and Print policy settings with `-WhatIf`, prior-value capture, and `-Undo` |

Preview and apply only in an approved pilot:

```powershell
.\8ee949ce-7d96-4688-a808-7917dd907db0_hardening.ps1 -WhatIf
.\8ee949ce-7d96-4688-a808-7917dd907db0_hardening.ps1
```

Preview or perform rollback:

```powershell
.\8ee949ce-7d96-4688-a808-7917dd907db0_hardening.ps1 -Undo -WhatIf
.\8ee949ce-7d96-4688-a808-7917dd907db0_hardening.ps1 -Undo
```

The script stores original values under `%ProgramData%\SecurityBaseline\SophosWindowsBaseline`. `-Undo` restores only values previously changed and recorded by the script; pre-existing compliant values are left alone. Empty registry keys may remain after rollback. In a managed environment, prefer central policy and treat local script changes as temporary exceptions that must be reconciled with GPO/MDM.

## Incident Response Playbook

These triggers are for suspected security incidents, not automatic responses to a failed hygiene check.

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|---|---|---|---|
| Sophos defense impairment | Unexpected Sophos service stop/start-mode change, tamper protection disabled, or Central tamper alert | High when correlated with Central telemetry | P1 |
| Sophos management loss | Endpoint exceeds approved Central check-in threshold; local MCS Agent unhealthy | Medium; investigate operational causes | P2 |
| LSASS credential access | Unauthorized LSASS handle/memory access, dump file creation, or credential-theft alert | High | P1 |
| Suspicious PowerShell | PowerShell 4104/module telemetry with obfuscation, suspicious download, credential access, or defense changes | Medium–High with context | P2 |
| SMB/service lateral movement | New remote service plus admin-share access, Security 4624/5140/5145, or System 7045 | High when correlated | P1 |
| Account/persistence changes | Unexpected account creation, reset, enablement, or privileged-group change (for example 4720, 4724, 4725, 4732) | Medium–High | P2 |
| Logging impairment | Security 4719 audit-policy change or 1102 audit-log clear without approved change | High | P1 |
| Print exploitation/persistence | Unexpected spooler child process, driver installation, or print-processor change | High | P1 |

### Containment (First 15 Minutes)

- [ ] Open an incident and record timestamps, affected hosts, users, source IPs, and the evidence supporting containment.
- [ ] Isolate affected hosts using Sophos Central or approved network controls; preserve management access needed by responders.
- [ ] Disable or restrict implicated accounts and revoke active sessions where supported. Reset exposed credentials using a clean administrative host.
- [ ] Block confirmed malicious infrastructure and unauthorized remote-service creation; do not indiscriminately disable Sophos, printing, LAPS, or all SMB.
- [ ] Preserve volatile evidence before reboot, service restoration, registry rollback, or agent reinstall.

### Evidence Collection

Create a case-specific, access-controlled directory such as `C:\IR\<case-id>` and record collection times and operators.

| Artifact | Location | Example collection command |
|---|---|---|
| Security log | Windows Event Log | `wevtutil epl Security C:\IR\case-id\Security.evtx` |
| System log / service events | Windows Event Log | `wevtutil epl System C:\IR\case-id\System.evtx` |
| PowerShell operational log | Windows Event Log | `wevtutil epl Microsoft-Windows-PowerShell/Operational C:\IR\case-id\PowerShell-Operational.evtx` |
| Effective audit policy | Local policy | `auditpol /get /category:* /r > C:\IR\case-id\audit-policy.csv` |
| Local account policy | Local policy | `net accounts > C:\IR\case-id\net-accounts.txt` |
| Sophos service state | WMI/CIM | `Get-CimInstance Win32_Service -Filter "Name='Sophos Endpoint Defense Service' OR Name='Sophos MCS Agent'" | Export-Clixml C:\IR\case-id\sophos-services.xml` |
| Sophos central evidence | Sophos Central | Export effective policy, tamper state, last check-in, alerts, and relevant endpoint events with timestamps. |
| Relevant registry policy | HKLM policy/system hives | Export only case-relevant keys with `reg export`; protect the resulting files as sensitive configuration evidence. |

Memory acquisition should be performed only by trained responders under the incident plan. Avoid creating LSASS dumps solely for evidence collection because they can contain credentials.

### Eradication

- Remove confirmed malicious services, print processors/drivers, accounts, tasks, and unauthorized tools **after evidence collection**.
- Reverse unauthorized registry, audit-policy, or security-policy changes through approved central configuration where possible.
- Reinstall or repair Sophos only through the supported process if tampering or corruption is confirmed; verify tamper protection before reconnecting.
- Patch applicable Windows and Sophos vulnerabilities and remove unauthorized legacy-protocol exceptions.
- Rotate credentials with potential exposure, prioritizing privileged and interactively logged-on accounts.

### Recovery

- [ ] Confirm Sophos services run with automatic start, Central check-in resumes, tamper protection is enabled, and the effective prevention policy is correct.
- [ ] Validate effective GPO/MDM settings and audit collection; do not rely solely on registry values.
- [ ] Confirm required business functions, including approved server print roles, SMB dependencies, LAPS recovery, and administrative access.
- [ ] Monitor the host and related accounts for recurrence before returning to normal alerting levels.
- [ ] Reconnect the host only after containment and eradication evidence is reviewed.

### Post-Incident

1. Which local or central signal first identified the issue, and was any required evidence marked unknown?
2. What were detection, containment, credential-reset, and recovery times?
3. Which prevention or configuration control would have stopped the behavior, and was it actually operational?
4. Did an emergency change create print, authentication, SMB, LAPS, or application downtime?
5. Are exceptions documented, approved, compensated, and assigned an expiry date?

## References

- MITRE ATT&CK technique and mitigation links are included in the mapping table.
- [Sophos Central documentation](https://docs.sophos.com/central/Customer/help/en-us/index.html)
- [Microsoft: Configure additional LSA protection](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Microsoft: Credential Guard overview](https://learn.microsoft.com/windows/security/identity-protection/credential-guard/)
- [Microsoft: PowerShell logging in Windows](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Microsoft: SMB signing](https://learn.microsoft.com/windows-server/storage/file-server/smb-signing)
- [Microsoft: Detect, enable, and disable SMBv1, SMBv2, and SMBv3](https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Microsoft: Windows LAPS overview](https://learn.microsoft.com/windows-server/identity/laps/laps-overview)
- [Microsoft: KB5005652 — Point and Print default driver installation behavior](https://support.microsoft.com/help/5005652)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — use the applicable full benchmark for a separate, comprehensive assessment; this bundle does not claim CIS completeness.
