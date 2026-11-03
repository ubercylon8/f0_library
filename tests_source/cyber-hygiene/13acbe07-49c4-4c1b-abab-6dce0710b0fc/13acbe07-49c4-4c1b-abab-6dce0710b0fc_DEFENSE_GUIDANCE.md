# Defense Guidance: Cyber-Hygiene Bundle (SentinelOne Singularity Edition)

**Date:** 2026-11-03  
**Platform:** Windows endpoints and Windows Servers  
**Purpose:** Remediate selected local Windows and centrally managed SentinelOne control gaps identified by the read-only baseline assessment.

## Executive Summary

This bundle evaluates 41 controls covering SentinelOne agent health, credential protection, PowerShell logging, SMB and name-resolution hardening, print security, Windows LAPS, audit policy, and account policy. It does not execute the associated attack techniques and does not remediate settings.

Priorities are:

1. Restore SentinelOne service health and verify effective prevention, anti-tampering, connectivity, and detection-engine policy in the Singularity management console.
2. Protect credentials with LSASS Protected Process Light (PPL), Credential Guard, unique LAPS-managed local administrator passwords, and appropriately scoped administrative access.
3. Enable security telemetry and preserve it in a protected central log platform.
4. Remove legacy protocol exposure only after compatibility testing, with special review for SMB, NetBIOS, IPv6 transition technologies, and printing dependencies.

The companion PowerShell script is a **documentation artifact**. The assessment never runs it. It supports `-WhatIf` and `-Undo`, records prior local values, and deliberately excludes SentinelOne policy, Defender/ASR, account policy, LAPS, and Print Spooler service changes.

## Scope and Evidence Model

A local pass is not proof of central compliance, and a central policy object is not proof that an endpoint received or applied it.

| Evidence class | Controls | Interpretation |
|---|---|---|
| Local registry, CIM/WMI, service, file-version, `auditpol`, `net accounts`, and `secedit` evidence | CH-LSS, CH-PWS, CH-SMB, CH-NET, CH-LAP, CH-PRT, CH-AUD, CH-LOK, CH-S1-001, CH-S1-002 | Observed local state at collection time. Registry policy may require a reboot, may differ from runtime state, and may later be overwritten by GPO or MDM. |
| `central_sentinelone_api_required` | CH-S1-003 through CH-S1-006 | **Unknown, not failed.** The local agent cannot establish the effective account/site/group policy. Collect read-only central host and effective-policy evidence before remediation. |
| Local version evidence | CH-S1-002 | Confirms only that a version string is readable at a known installation path. It makes no claim that the version is current, supported, or centrally approved. |
| Server print-role context | CH-PRT-001 | A running spooler on a server is **Unknown** pending role validation, not automatically a failure. |

**Compliance limitation:** These are selected hygiene checks, not a complete CIS Benchmark, Microsoft security baseline, SentinelOne policy audit, or certification assessment. Do not report “CIS compliant” or equivalent solely from this bundle. Use the applicable OS/role-specific benchmark and central policy review for broader coverage.

## Threat Overview

| Field | Value |
|---|---|
| **Test ID** | 13acbe07-49c4-4c1b-abab-6dce0710b0fc |
| **Test Name** | Cyber-Hygiene Bundle (SentinelOne Singularity Edition) |
| **Severity** | High |
| **Threat Actor** | N/A — technique-oriented baseline |
| **Target** | `windows-endpoint`; server-specific cautions below also apply |
| **Primary risk** | Security-control tampering, credential theft and reuse, script execution, lateral movement, protocol abuse, privilege escalation, and persistence |

## MITRE ATT&CK Mapping

The source metadata and shared checks produce the following mapping. Mitigations are relevant ATT&CK mitigations, not guarantees of prevention.

| Technique | Tactic | Selected mitigations |
|---|---|---|
| [T1562.001 — Impair Defenses](https://attack.mitre.org/techniques/T1562/001/) | Defense Evasion | M1018 — User Account Management; M1022/M1024 — Restrict File/Directory and Registry Permissions; M1047 — Audit |
| [T1562.002 — Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/) | Defense Evasion | M1047 — Audit; M1022/M1024 — Restrict configuration permissions |
| [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) | Credential Access | M1043 — Credential Access Protection; M1026 — Privileged Account Management; M1028 — Operating System Configuration |
| [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) and [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | Execution | M1026 — Privileged Account Management; M1038 — Execution Prevention; M1047 — Audit |
| [T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) | Lateral Movement | M1030 — Network Segmentation; M1035 — Limit Access to Resource Over Network; M1037 — Filter Network Traffic |
| [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | Credential Access | M1036 — Account Use Policies; M1027 — Password Policies; M1032 — Multi-factor Authentication |
| [T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/) | Credential Access | M1037 — Filter Network Traffic; M1030 — Network Segmentation; M1042 — Disable or Remove Feature or Program |
| [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/) | Command and Control | M1037 — Filter Network Traffic; M1031 — Network Intrusion Prevention; M1030 — Network Segmentation |
| [T1078.003 — Local Accounts](https://attack.mitre.org/techniques/T1078/003/) and [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Defense Evasion, Persistence, Privilege Escalation, Initial Access | M1018 — User Account Management; M1026 — Privileged Account Management; M1027 — Password Policies; M1032 — MFA |
| [T1569.002 — Service Execution](https://attack.mitre.org/techniques/T1569/002/) | Execution | M1026 — Privileged Account Management; M1018 — User Account Management; M1047 — Audit |
| [T1547.012 — Print Processors](https://attack.mitre.org/techniques/T1547/012/) | Persistence, Privilege Escalation | M1026 — Privileged Account Management; M1047 — Audit; M1051 — Update Software |
| [T1136 — Create Account](https://attack.mitre.org/techniques/T1136/) | Persistence | M1026 — Privileged Account Management; M1028 — Operating System Configuration; M1030 — Network Segmentation |
| [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) | Persistence, Privilege Escalation | M1018 — User Account Management; M1026 — Privileged Account Management; M1032 — MFA |

## Control Remediation Matrix

### SentinelOne: separate local health from central policy

| Control | Evidence and finding | Remediation plane and action |
|---|---|---|
| CH-S1-001 Agent Service | Local `SentinelAgent` state and automatic start | Investigate stopped, missing, or non-automatic service through the endpoint owner and SentinelOne support procedures. Do not stop, restart, reinstall, or alter anti-tampered components automatically. Confirm recovery in the console. |
| CH-S1-002 Agent Version | Local file version only | Reconcile with central inventory and the organization’s supported-version policy. Upgrade through an approved SentinelOne deployment process; local readability is not a currency check. |
| CH-S1-003 Prevention Mode | Central evidence required; always Unknown locally | In Singularity, verify the endpoint’s effective group/site/account policy has agent prevention active and is not detect-only. Review inherited policy and overrides before changing anything. |
| CH-S1-004 Recent Cloud Check-in | Central evidence required; always Unknown locally | Verify `networkStatus` and `lastActiveDate` against the organization’s threshold. Investigate network, proxy, firewall, service, and decommissioning causes. A running local service does not prove cloud connectivity. |
| CH-S1-005 Anti-Tampering | Central evidence required; always Unknown locally | Verify anti-tampering is enabled in the effective policy. Investigate gaps and unauthorized tamper events; do not weaken anti-tampering to make routine changes. |
| CH-S1-006 Detection Engines | Central evidence required; always Unknown locally | Verify the organization-approved detection engines are enabled in the effective policy. Engine availability and names vary by license/version; use current authenticated SentinelOne documentation. |

Use a read-only API token or console role for evidence collection. Record endpoint ID, policy scope, inheritance, collection time, and console/API response. Apply changes centrally to a pilot group, verify endpoint receipt and behavior, then broaden deployment. The companion script makes **no SentinelOne changes**.

### Windows baseline

| Controls | Recommended state | Plane, validation, and operational caution |
|---|---|---|
| CH-LSS-001–003 | `RunAsPPL` 1 or 2; Credential Guard enabled; VBS enabled | Prefer GPO/Intune. Test hardware, drivers, virtualization, authentication, and management tools. Reboot and verify `Win32_DeviceGuard.SecurityServicesRunning`; a registry pass alone is not runtime proof. The script uses Credential Guard **without UEFI lock** (`LsaCfgFlags=2`) to preserve remote rollback. |
| CH-PWS-001–003 | Script block, module, and transcription logging enabled | Deploy centrally, size event/log retention, restrict read access, and forward logs securely. Logs and transcripts can contain credentials or other sensitive content; consider Protected Event Logging and avoid broad user access. |
| CH-PWS-004 | `__PSLockdownPolicy=4` | Test administrative scripts, installers, remote management, and application dependencies. Treat Constrained Language Mode as part of a WDAC/AppLocker design, not a standalone security boundary. |
| CH-SMB-001 | SMBv1 driver disabled or feature absent | Inventory legacy dependencies first. Remove/disable SMBv1 through approved OS feature management; the script only disables an existing driver registration and does not uninstall features. |
| CH-SMB-002–003 | SMB server and client signing required | Prefer central policy and audit third-party SMB devices. Required signing can block unsigned or guest-access workflows; do not weaken signing as a compatibility workaround. |
| CH-SMB-004 | SMB server encryption enabled | Test SMB 3.x support and performance before enforcement. Older/third-party clients may not support encryption. |
| CH-SMB-005 | Null-session access restricted | Validate legacy applications and anonymous share dependencies; replace them rather than broadly permitting null sessions. |
| CH-NET-001–003 | LLMNR disabled; NetBIOS over TCP/IP disabled on IP-enabled adapters; `WpadOverride=1` | Confirm DNS suffix/search configuration and legacy name-resolution dependencies. Use explicit, authenticated proxy configuration where required. `WpadOverride` is only one local signal; also review WinINet/per-user and network proxy behavior. |
| CH-NET-004 | `DisabledComponents` includes both `0x01` and `0x20` | Review DirectAccess, VPN, transition technologies, and IPv6 routing. This does **not** disable native IPv6 and should not be replaced with a blanket `0xFF` setting. |
| CH-LAP-001 | Windows LAPS or approved legacy LAPS enabled where applicable | Remediate through AD GPO or Intune after selecting the correct backup directory, preparing AD schema/permissions or Entra settings, and validating retrieval/rotation. Do not enable, disable, or change LAPS blindly on servers. Domain controllers and DSRM backup require separate review. The script makes no LAPS changes. |
| CH-PRT-001 | Spooler absent/disabled only when no documented print role requires it | Inventory local printing, print servers, RDS, application rendering, scanning, and domain-controller needs. Obtain role-owner approval before stopping or disabling the service. A running server spooler is not automatically noncompliant. The script never stops or disables it. |
| CH-PRT-002–004 | Driver installation restricted to administrators; install/update prompts enabled | Apply Point and Print restrictions after testing approved printer-driver deployment and user workflows. Keep Windows and print drivers patched. |
| CH-AUD-001–009 | Required success/failure auditing for logon, lockout, process, policy, account, and group events | Prefer Advanced Audit Policy GPO; local `auditpol` changes can be overwritten. Size and centrally protect Security logs. Process command-line auditing and retention require separate privacy/capacity review. |
| CH-LOK-001–005 | Lockout threshold 1–5; duration and observation window at least 15 minutes; minimum length at least 14; complexity enabled | Set through the correct domain or local security policy. On a domain controller, local tools can affect domain-wide policy. Assess denial-of-service and service-account risk before tightening lockout. Use current organizational password guidance; complexity does not replace MFA or compromised-password controls. The script makes no account-policy changes. |

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact)

1. Investigate failed local SentinelAgent health and collect the four central Unknown controls rather than treating them as passes or failures.
2. Enable PowerShell and required Windows audit logging on a pilot group; verify event generation, retention, access control, and central forwarding.
3. Enable Point and Print restrictions and LSASS PPL after application/driver validation.
4. Review local administrators, unauthorized accounts/groups, and repeated authentication failures using central identity and SentinelOne telemetry.

### Medium-Term (1–2 Weeks — Medium Impact)

1. Deploy Credential Guard/VBS, SMB signing, and audit policy through versioned GPO/Intune rings; verify effective runtime state after reboot.
2. Inventory and retire SMBv1, LLMNR, NetBIOS, WPAD, and unused IPv6 tunnel dependencies. Use network controls to limit poisoning, relay, and tunneling paths.
3. Implement Windows LAPS centrally with tested help-desk retrieval, rotation, and break-glass procedures.
4. Document print roles and disable the spooler only on approved non-printing systems.

### Strategic (1–3 Months — Requires Planning)

1. Adopt role-specific Microsoft security baselines and separately assess the applicable CIS Benchmark; reconcile conflicts rather than stacking settings blindly.
2. Implement tiered administration, privileged access workstations, MFA, and application control/JEA to reduce reusable credentials and unrestricted script execution.
3. Establish continuous central SentinelOne effective-policy and check-in monitoring, configuration drift alerts, and protected log retention.
4. Segment administrative SMB and management pathways and restrict egress to approved proxy/tunnel infrastructure.

## Hardening Script

| Platform | Script | Description |
|---|---|---|
| Windows | `13acbe07-49c4-4c1b-abab-6dce0710b0fc_hardening.ps1` | Selected local registry, NetBIOS, and advanced-audit hardening with `-WhatIf`, `-Undo`, original-state backup, and drift protection |

Run only after review and pilot testing, from an elevated Windows PowerShell 5.1+ session:

```powershell
# Preview local changes; no configuration or rollback-state writes.
.\13acbe07-49c4-4c1b-abab-6dce0710b0fc_hardening.ps1 -WhatIf

# Apply selected local settings.
.\13acbe07-49c4-4c1b-abab-6dce0710b0fc_hardening.ps1

# Preview or perform rollback of recorded values.
.\13acbe07-49c4-4c1b-abab-6dce0710b0fc_hardening.ps1 -Undo -WhatIf
.\13acbe07-49c4-4c1b-abab-6dce0710b0fc_hardening.ps1 -Undo
```

Rollback state defaults to `%ProgramData%\SentinelOneWindowsBaseline\state.json`. Re-running Apply retains the original baseline rather than overwriting it. Undo restores only recorded values that still match the script-applied state; it skips later third-party changes and reports them. Undo does not reverse central policy, reboot-dependent runtime state, or settings outside the script. Back up the state file with the host’s normal protected configuration backups.

The script intentionally does **not** configure Defender or Defender ASR, change SentinelOne, change LAPS/account policy, or stop/disable printing. Those actions require the central and role-specific processes above.

## Incident Response Playbook

A failed hygiene check alone is not evidence of compromise. Escalate when a gap coincides with tamper alerts, unexplained policy changes, suspicious authentication, malicious detections, or unexpected services/accounts.

### Detection Triggers

| Trigger | Criteria | Confidence | Priority |
|---|---|---|---|
| SentinelOne tamper or loss of prevention | Agent/service disabled unexpectedly, anti-tamper alert, or effective mode changed without approval | High | P1 |
| Credential access | Suspicious LSASS access/dump behavior or SentinelOne credential-theft detection | High | P1 |
| Audit impairment | Unexpected `auditpol` change, Event Log interruption, or central logging gap | Medium/High | P2 |
| Account abuse | Unexpected account/group creation or modification, repeated lockouts, or local administrator reuse | Medium/High | P1/P2 |
| Protocol abuse | LLMNR/NBT-NS poisoning, unsigned SMB relay, unexpected tunnel, or spooler/print-processor alert | Medium/High | P1/P2 |

### Containment (First 15 Minutes)

- [ ] Use SentinelOne network isolation for a suspected compromised host; do not isolate a critical server without invoking the approved availability procedure.
- [ ] Preserve the console detection, effective policy, policy-change history, and relevant endpoint telemetry.
- [ ] Disable or revoke suspected compromised credentials through the identity owner; do not reset evidence-rich accounts before coordination.
- [ ] Block identified malicious destinations or relay paths at approved network controls.

### Evidence Collection

Create an authorized evidence directory and record UTC collection time. Example commands:

```powershell
New-Item -ItemType Directory -Path C:\IR -Force
wevtutil epl Security C:\IR\Security.evtx
wevtutil epl System C:\IR\System.evtx
wevtutil epl Microsoft-Windows-PowerShell/Operational C:\IR\PowerShell-Operational.evtx
auditpol /get /category:* /r > C:\IR\auditpol.csv
Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName |
    Export-Csv -NoTypeInformation C:\IR\services.csv
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select-Object SecurityServicesConfigured,SecurityServicesRunning |
    Export-Clixml C:\IR\deviceguard.xml
```

Also collect SentinelOne console detection details, agent connectivity/last-active evidence, effective policy and inheritance, and management audit logs. Protect logs because PowerShell content and command lines may contain secrets or personal data.

### Eradication

- Remove unauthorized accounts, group membership, services, print processors, tunnels, and policy changes only after evidence collection and owner validation.
- Reimage or restore from a known-good source when credential theft, kernel tampering, or persistent SYSTEM compromise cannot be confidently removed.
- Restore security settings through the authoritative central policy rather than relying only on local edits.

### Recovery

- [ ] Verify SentinelOne prevention, anti-tampering, engines, and cloud check-in centrally.
- [ ] Verify local/runtime credential protections and required audit events after reboot.
- [ ] Rotate exposed credentials and LAPS-managed passwords using approved procedures.
- [ ] Monitor authentication, SMB, PowerShell, account, and service activity before reconnecting normally.

### Post-Incident

1. Identify the initial access, control gap, and central/local policy drift that enabled the activity.
2. Measure detection, isolation, credential revocation, and recovery times.
3. Add the affected role to a pilot hardening ring and validate that remediation does not create availability or logging gaps.

## References

- MITRE ATT&CK technique and mitigation links in the mapping above.
- [Microsoft: Configure Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure)
- [Microsoft: Credential Guard considerations and known issues](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues)
- [Microsoft: PowerShell logging on Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Microsoft: Windows LAPS policy settings](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings)
- [Microsoft: Control SMB signing behavior](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Microsoft: SMB security hardening](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)
- [Microsoft: Windows Server 2025 security baselines](https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-security-baselines)
- SentinelOne Singularity management console, authenticated product documentation, and SentinelOne Support for current policy-engine names, API fields, agent recovery, and supported deployment practices.
