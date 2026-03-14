# Defense Guidance: RDP Lateral Movement Simulation

## Executive Summary

Remote Desktop Protocol (RDP) lateral movement is one of the most prevalent techniques used by ransomware operators, APT groups, and opportunistic attackers to traverse compromised networks. This test covers two closely related technique areas: active use of RDP for lateral movement (T1021.001) and manipulation of the Windows Credential Manager to store or harvest RDP credentials (T1555.004).

The highest-priority actions are enforcing Network Level Authentication (NLA) on all RDP endpoints, restricting RDP access to named jump hosts via firewall policy, auditing and restricting cmdkey usage through AppLocker or WDAC, and deploying behavioral detections for the native reconnaissance commands (qwinsta, sc query TermService, reg query Terminal Server keys) that precede RDP-based movement.

---

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03 |
| **Test Name** | RDP Lateral Movement Simulation |
| **MITRE ATT&CK** | [T1021.001 — Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/) and [T1555.004 — Credentials from Password Stores: Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004/) |
| **Tactics** | Lateral Movement, Credential Access |
| **Severity** | High |
| **Threat Actor** | N/A (generic; technique is universally used by ransomware groups, APT29, Lazarus, FIN7, and others) |
| **Subcategory** | lateral-movement |
| **Test Score** | 8.0/10 |

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|------------------------|
| T1021.001 — Remote Services: Remote Desktop Protocol | Lateral Movement | M1035 — Limit Access to Resource Over Network; M1030 — Network Segmentation; M1028 — Operating System Configuration; M1047 — Audit; M1026 — Privileged Account Management |
| T1555.004 — Credentials from Password Stores: Windows Credential Manager | Credential Access | M1042 — Disable or Remove Feature or Program; M1027 — Password Policies; M1026 — Privileged Account Management; M1054 — Software Configuration |

### Mitigation Summaries

**M1035 — Limit Access to Resource Over Network**
Restrict RDP (TCP/3389) inbound connections using host-based Windows Firewall rules and network-level ACLs. Only named jump hosts or privileged access workstations (PAWs) should be permitted to initiate RDP connections to production systems. Block lateral RDP (workstation-to-workstation) entirely at the firewall layer.

**M1030 — Network Segmentation**
Place servers and workstations in separate VLANs or network segments with inter-segment firewall rules that deny RDP unless explicitly approved. East-west RDP traversal between workstations is rarely legitimate and should be denied by default.

**M1028 — Operating System Configuration**
Enforce NLA (Network Level Authentication) on all RDP listeners. Disable RDP on systems that do not require it. Change the default RDP port only as a defense-in-depth measure (not a primary control). Enable restricted admin mode for RDP sessions to prevent credential delegation.

**M1047 — Audit**
Regularly audit which accounts are members of the Remote Desktop Users group. Review systems where RDP is enabled and validate business justification. Audit Windows Credential Manager contents for unexpected stored credentials.

**M1026 — Privileged Account Management**
Prevent administrators from using domain admin accounts for routine RDP sessions. Enforce tiered administration (Tier 0/1/2) so that domain admin credentials are never cached on workstations or member servers that could be reached via RDP.

**M1042 — Disable or Remove Feature or Program**
Disable the Windows Credential Manager's ability to store domain credentials where not operationally required. Consider restricting `cmdkey.exe` access via AppLocker or WDAC publisher or path rules.

**M1027 — Password Policies**
Enforce strong, unique passwords for all accounts with RDP access. Implement account lockout policies to deter brute-force attacks against the RDP listener.

**M1054 — Software Configuration**
Configure RDP to use TLS 1.2 or later. Disable deprecated encryption modes (Classic RDP encryption). Enable CredSSP for NLA enforcement. Consider deploying Microsoft RD Gateway to proxy and audit all RDP connections.

---

## Hardening Recommendations

### Quick Wins (Immediate — Low Operational Impact)

1. Enable NLA on all Windows endpoints via GPO (`Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require use of specific security layer for remote (RDP) connections` — set to SSL/TLS and `Require NLA`).
2. Restrict Remote Desktop Users group membership: remove standard users; document all members.
3. Enable Windows Firewall rules to block inbound RDP from unauthorized source IP ranges.
4. Enable audit logging for Logon/Logoff (Event IDs 4624, 4625, 4634) and Object Access for Credential Manager (Event ID 5379, 5380, 5381, 5382).
5. Enable "Audit Logon Events" and "Audit Account Logon Events" via Advanced Audit Policy to capture RDP logons (Logon Type 10).

### Medium-Term (1–2 Weeks — Moderate Planning Required)

1. Deploy AppLocker or WDAC rules to restrict execution of known RDP offensive tools (SharpRDP, mstsc with automated credential injection) and restrict `cmdkey.exe` to approved administrative processes.
2. Configure Microsoft Defender for Endpoint (MDE) Attack Surface Reduction rules relevant to credential access and lateral movement.
3. Deploy an RD Gateway or equivalent PAM solution so all RDP sessions pass through a centralized proxy with session recording.
4. Implement network-level controls to block workstation-to-workstation RDP (TCP/3389 and alternate ports) at the switch/VLAN layer.
5. Enable Windows Defender Credential Guard to protect domain credentials from being harvested from LSASS — this also reduces credential exposure via RDP session delegation.
6. Review all scheduled tasks and services that store credentials in Windows Credential Manager; remove unnecessary stored credentials.

### Strategic (1–3 Months — Architecture or Policy Changes Required)

1. Implement Privileged Access Workstations (PAWs) and tiered administration to ensure domain admin credentials are never exposed on systems reachable via lateral RDP.
2. Deploy a Privileged Access Management (PAM) solution (e.g., CyberArk, BeyondTrust, Microsoft PIM) that issues time-limited credentials for RDP access and records sessions.
3. Enforce Just-in-Time (JIT) access for RDP: disable the RDP listener by default and enable it only for approved maintenance windows via PAM automation.
4. Migrate workload management to modern remote management protocols (WinRM/PowerShell Remoting with constrained endpoints, SSH) where RDP is not operationally required.
5. Deploy Azure AD / Entra ID Conditional Access policies requiring MFA before RDP access via Azure AD-joined or hybrid-joined devices.

---

## Cross-Platform Hardening Scripts

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03_hardening.ps1` | PowerShell — NLA, firewall, audit policy, Credential Guard, AppLocker. Supports `-Undo` and `-WhatIf`. |

---

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| RDP Reconnaisance — TermService Query | `sc.exe` with arguments `query TermService` spawned by non-SYSTEM, non-SCM parent | Medium | P2 |
| RDP Registry Enumeration | `reg.exe` querying `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` or `RDP-Tcp` keys outside of standard tooling | High | P2 |
| RDP Session Enumeration | `qwinsta.exe` or `query session` executed by non-admin user or from unexpected parent process | High | P2 |
| Credential Manager Manipulation | `cmdkey.exe /add` or `cmdkey.exe /generic` executed by any interactive user or automated process | High | P1 |
| SharpRDP Binary Detection | File write or process creation for `SharpRDP.exe` or hash/signature match against known SharpRDP builds | Critical | P1 |
| Suspicious RDP Logon | Event ID 4624 Logon Type 10 from non-PAW/jump host source IP | High | P1 |
| Credential Manager Access Event | Event IDs 5379, 5381, 5382 — Credential Manager credentials read | Medium | P2 |

### Containment (First 15 Minutes)

- [ ] Isolate the affected endpoint from the network (revoke network access via NAC, disable switch port, or quarantine via EDR).
- [ ] Terminate any active RDP sessions from the affected host: `query session /server:<hostname>` then `logoff <sessionid> /server:<hostname>`.
- [ ] If `cmdkey.exe` created persistent credentials, remove them: `cmdkey /delete:<target>` for each entry listed by `cmdkey /list`.
- [ ] Block outbound RDP (TCP/3389) from the affected host at the host firewall level.
- [ ] Suspend or disable the user account associated with the suspicious RDP session.
- [ ] Preserve volatile evidence (running process list, network connections, logged-on sessions) before any remediation.

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Security event log | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | `wevtutil epl Security C:\IR\Security.evtx` |
| System event log | `%SystemRoot%\System32\winevt\Logs\System.evtx` | `wevtutil epl System C:\IR\System.evtx` |
| RDS event log | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | `wevtutil epl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" C:\IR\RDS_LSM.evtx` |
| RDP-Tcp event log | `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | `wevtutil epl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" C:\IR\RDS_RCM.evtx` |
| Active RDP sessions | Memory | `query session` and `qwinsta` output saved to file |
| Stored Credential Manager entries | DPAPI vault | `cmdkey /list > C:\IR\credential_manager.txt` |
| RDP registry configuration | Registry | `reg export "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" C:\IR\rdp_config.reg` |
| Running processes | Memory | `Get-Process | Export-Csv C:\IR\processes.csv` |
| Network connections | Memory | `netstat -anob > C:\IR\netstat.txt` |
| Prefetch for RDP tools | `%SystemRoot%\Prefetch\` | Copy `QWINSTA.EXE-*.pf`, `CMDKEY.EXE-*.pf`, `SHARPRDP.EXE-*.pf` |
| PowerShell history | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Copy file |

### Eradication

Perform AFTER evidence collection is complete and signed off.

- [ ] Remove SharpRDP.exe and any copies from disk (search entire volume): `Get-ChildItem -Path C:\ -Filter SharpRDP.exe -Recurse -ErrorAction SilentlyContinue`.
- [ ] Clear unauthorized Credential Manager entries: `cmdkey /delete:<target>` for each entry identified during evidence collection.
- [ ] Revoke and rotate credentials for any account that authenticated via the suspicious RDP session.
- [ ] Remove the attacker's user account or any backdoor accounts added during the intrusion.
- [ ] Review and clean up any scheduled tasks, services, or registry run keys added during the intrusion.
- [ ] Re-image the affected system if the intrusion scope cannot be fully bounded.

### Recovery

- [ ] Verify all attack artifacts have been removed (SharpRDP, unauthorized credentials, persistence mechanisms).
- [ ] Restore RDP configuration to hardened baseline (NLA enabled, firewall rules applied).
- [ ] Re-enable security controls if temporarily disabled during investigation.
- [ ] Reset passwords for all accounts that were active on the compromised system.
- [ ] Validate NLA requirement is enforced on the restored system before reconnecting to production network.
- [ ] Reconnect the system to the network with monitoring in enhanced mode for 72 hours.
- [ ] Validate EDR agent is healthy and telemetry is flowing.

### Post-Incident Review

1. How was the initial detection made — EDR alert, SIEM correlation, or manual investigation?
2. What was the detection-to-containment time? Target: under 1 hour for P1 alerts.
3. Was RDP the initial access vector or was it used for lateral movement after initial compromise via another vector?
4. Were credentials obtained from Windows Credential Manager used for subsequent movement? Which accounts were affected?
5. Were NLA and firewall restrictions in place on the affected system? If not, why not?
6. Would MFA enforcement on the RDP listener (via RD Gateway or NPS extension) have prevented this incident?
7. What detection gaps allowed the reconnaissance phase (qwinsta, reg query) to go undetected?
8. Update detection rules based on IOCs and TTPs observed in this incident.

---

## References

- [MITRE ATT&CK T1021.001 — Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK T1555.004 — Credentials from Password Stores: Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004/)
- [MITRE M1035 — Limit Access to Resource Over Network](https://attack.mitre.org/mitigations/M1035/)
- [MITRE M1030 — Network Segmentation](https://attack.mitre.org/mitigations/M1030/)
- [MITRE M1028 — Operating System Configuration](https://attack.mitre.org/mitigations/M1028/)
- [MITRE M1042 — Disable or Remove Feature or Program](https://attack.mitre.org/mitigations/M1042/)
- [MITRE M1026 — Privileged Account Management](https://attack.mitre.org/mitigations/M1026/)
- [MITRE M1047 — Audit](https://attack.mitre.org/mitigations/M1047/)
- [CIS Benchmark for Windows — Section 18.9.65 (Remote Desktop Services)](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Security Baseline — Remote Desktop Services hardening](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [CISA Advisory — Top Routinely Exploited Vulnerabilities (RDP abuse)](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Microsoft Docs — Protect Remote Desktop credentials with Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [NSA Cybersecurity Advisory — Mitigating Recent RDP Vulnerabilities](https://media.defense.gov/2018/Oct/12/2002049453/-1/-1/0/CSA_MICROSOFT_RDP.pdf)
