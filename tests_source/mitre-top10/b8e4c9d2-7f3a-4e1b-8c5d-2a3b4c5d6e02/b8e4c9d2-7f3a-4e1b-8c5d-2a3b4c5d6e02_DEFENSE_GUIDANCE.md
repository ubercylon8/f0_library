# Defense Guidance: Local Account Enumeration

## Executive Summary

This test simulates a three-technique attack chain that adversaries routinely execute during post-initial-access reconnaissance: local account discovery via native Windows binaries (net.exe, wmic.exe, whoami.exe), valid local account abuse (T1078.003), and Kerberoasting/AS-REP roasting via Rubeus (T1558.003). Because the first four techniques use built-in Windows executables, behavioral detection is essential — signature-based controls alone are insufficient.

Priority recommendations: (1) enable and tune Windows Defender ASR rules and command-line audit logging to capture net.exe/wmic.exe enumeration patterns; (2) enforce Kerberos AES-only encryption and enable Kerberos pre-authentication for all accounts; (3) restrict local administrator account proliferation and enforce least-privilege through LAPS and tiered administration; (4) deploy behavioral analytics to baseline and alert on anomalous enumeration command sequences.

---

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02 |
| **Test Name** | Local Account Enumeration |
| **MITRE ATT&CK** | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) · [T1087.001](https://attack.mitre.org/techniques/T1087/001/) · [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| **Tactics** | Defense Evasion, Discovery, Credential Access, Persistence, Privilege Escalation, Initial Access |
| **Severity** | Medium (test-platform rating) / High (real-world impact) |
| **Threat Actor** | N/A (broadly observed across APT29, FIN6, Scattered Spider, and commodity ransomware operators) |
| **Platform** | Windows Endpoint (domain-joined or standalone) |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Tactic(s) | Applicable Mitigations |
|-----------|---------------|-----------|------------------------|
| T1087 — Account Discovery | .001 Local Account | Discovery | M1028 — Operating System Configuration, M1033 — Limit Software Installation, M1018 — User Account Management |
| T1078 — Valid Accounts | .003 Local Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access | M1026 — Privileged Account Management, M1027 — Password Policies, M1032 — Multi-Factor Authentication, M1017 — User Training |
| T1558 — Steal or Forge Kerberos Tickets | .003 Kerberoasting | Credential Access | M1041 — Encrypt Sensitive Information, M1027 — Password Policies, M1026 — Privileged Account Management |

### Mitigation Detail

| M-Code | Mitigation Name | Relevance to This Test |
|--------|-----------------|------------------------|
| M1026 | Privileged Account Management | Limit local admin accounts; use LAPS for unique per-machine passwords; tier administrative access |
| M1027 | Password Policies | Enforce strong, unique passwords for service accounts; use MSAs/gMSAs to eliminate static SPN passwords |
| M1028 | Operating System Configuration | Disable WMIC remote access; restrict net.exe via AppLocker/WDAC where feasible |
| M1032 | Multi-Factor Authentication | Require MFA for local administrator and privileged accounts to limit the blast radius of credential theft |
| M1033 | Limit Software Installation | Block execution of unsigned or unknown binaries (Rubeus) via application control policies |
| M1041 | Encrypt Sensitive Information | Enforce AES256 Kerberos encryption; disable RC4 (ARCFOUR/DES) on all accounts and the domain |
| M1017 | User Training | Awareness of phishing and social engineering that enables initial compromise leading to enumeration |
| M1018 | User Account Management | Minimize the number of accounts with SPNs; audit SPN assignments; enable pre-authentication on all accounts |

---

## Hardening Recommendations

### Quick Wins (Immediate — Low Operational Impact)

1. Enable Process Creation audit policy with command-line logging (`Audit Process Creation` + `Include command line in process creation events` registry key).
2. Enable Kerberos pre-authentication on all user accounts (remove `DONT_REQ_PREAUTH` flag) to eliminate AS-REP roasting vectors.
3. Disable RC4 Kerberos encryption (ARCFOUR/DES) domain-wide via Group Policy (`Network security: Configure encryption types allowed for Kerberos`).
4. Audit all accounts with Service Principal Names (SPNs) assigned; remove SPNs from accounts that do not require them.
5. Enable the `Audit Kerberos Service Ticket Operations` and `Audit Kerberos Authentication Service` policies under Advanced Audit Policy Configuration.
6. Ensure WMIC remote access is restricted (`winmgmt` ACL) for non-administrative users.

### Medium-Term (1–2 Weeks — Moderate Planning Required)

1. Deploy Microsoft LAPS (Windows LAPS for Windows 11/Server 2022 or legacy LAPS) to randomize local administrator passwords across all endpoints, eliminating lateral movement via shared local admin credentials.
2. Enforce application control (AppLocker or WDAC) to block unsigned executables from user-writable locations (Downloads, %TEMP%, %APPDATA%) — this catches Rubeus and similar tools.
3. Enable Windows Defender ASR rule `Block abuse of exploited vulnerable signed drivers` and review all available ASR rules against your environment's application baseline.
4. Implement a Managed Service Account (MSA) or Group Managed Service Account (gMSA) migration plan for service accounts with SPNs — gMSA passwords rotate automatically (120-day default), making Kerberoasting offline attacks impractical.
5. Deploy a SIEM alert for anomalous enumeration command sequences: multiple invocations of net.exe, wmic.exe, or whoami.exe within a short window from a non-administrative user context.
6. Enforce MFA for all local administrator and privileged accounts using Windows Hello for Business or smart cards.

### Strategic (1–3 Months — Requires Architecture Planning)

1. Implement Active Directory tiered administration model (Tier 0/1/2) to prevent lateral movement from workstation-level account compromise to domain controllers.
2. Migrate all service accounts to gMSAs — this eliminates the attack surface for Kerberoasting entirely for those accounts.
3. Deploy Microsoft Privileged Identity Management (PIM) or CyberArk/BeyondTrust PAM solution for just-in-time local administrator access, removing standing privileged accounts from endpoints.
4. Implement Credential Guard on all Windows 10/11 endpoints to protect LSASS and prevent credential extraction from memory.
5. Deploy AD honeypot accounts (canary accounts) with SPNs and no real access — any Kerberoasting attempt against them triggers an immediate high-fidelity alert.
6. Establish a formal SPN review process integrated with the AD account lifecycle; decommission SPNs when service accounts are retired.

---

## Cross-Platform Hardening Scripts

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02_hardening.ps1` | PowerShell — audit policy, Kerberos encryption, AppLocker baselines, LAPS check, ASR rules. Supports `-Undo` and `-WhatIf`. |

> Linux and macOS hardening scripts are not applicable for this Windows-endpoint-only test. The techniques (local Windows account enumeration, Kerberos ticket abuse) are specific to the Windows/AD ecosystem.

---

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| Local Account Enumeration — Native Tools | `net.exe` or `wmic.exe` spawned with user/localgroup/useraccount arguments from a non-admin, non-IT process | Medium | P2 |
| Whoami Recon | `whoami.exe /all` executed from unexpected parent process (Office, browser, scripting host) | Medium | P2 |
| Offensive Tool Dropped | Rubeus.exe or matching hash written to disk | High | P1 |
| Rubeus Process Execution | Process creation for Rubeus.exe or known Rubeus command-line patterns | High | P1 |
| Kerberoasting Activity | Multiple TGS-REQ requests for different SPNs within 60 seconds from single source | High | P1 |
| AS-REP Roasting Activity | AS-REQ without pre-authentication data for multiple accounts from single source | High | P1 |
| RC4 Kerberos TGS | TGS ticket issued using RC4 encryption type (etype 23) — indicates Kerberoasting preparation | Medium | P2 |
| Anomalous Enumeration Sequence | Three or more of: net user, net localgroup, whoami /all, wmic useraccount — within 120 seconds | High | P1 |

### Containment (First 15 Minutes)

- [ ] Isolate the affected endpoint from the network (disable network adapter or apply firewall quarantine policy via EDR)
- [ ] Terminate any running Rubeus.exe or unknown processes from non-standard directories
- [ ] Preserve volatile memory: `winpmem.exe -o C:\IR\memory.dmp` (if available)
- [ ] Preserve active logon sessions: `qwinsta /server:localhost > C:\IR\sessions.txt`
- [ ] Check for lateral movement indicators: review other endpoints for the same user account's recent logons via DC Security logs (Event ID 4624)
- [ ] Reset the password of any account that was actively used during the session if compromise is suspected
- [ ] If Kerberoasting confirmed: immediately reset passwords for all service accounts with SPNs (prioritize those with RC4-encrypted tickets)

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|--------------------|
| Security event log | System | `wevtutil epl Security C:\IR\Security.evtx` |
| System event log | System | `wevtutil epl System C:\IR\System.evtx` |
| PowerShell operational log | System | `wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\IR\PS-Operational.evtx` |
| Process creation events | Security log | Filter Event ID 4688 for net.exe, wmic.exe, whoami.exe, Rubeus.exe |
| Kerberos service ticket events | DC Security log | Filter Event ID 4769 on domain controller for RC4 etype 23 requests |
| AS-REP roast events | DC Security log | Filter Event ID 4768 where Pre-Auth Type = 0 |
| Prefetch files | `C:\Windows\Prefetch\` | `xcopy C:\Windows\Prefetch\*.pf C:\IR\Prefetch\ /Y` |
| Shimcache / Amcache | Registry | `reg export HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache C:\IR\shimcache.reg` |
| Network connections at time of incident | Memory | `netstat -anob > C:\IR\netstat.txt` |
| File system artifacts | C:\F0\ (test staging dir) | `xcopy C:\F0\ C:\IR\F0_artifacts\ /E /Y /H` (if staging dir exists) |

### Eradication

- [ ] Remove any dropped offensive tool binaries (e.g., Rubeus.exe) from all locations on the endpoint (AFTER evidence collection)
- [ ] Remove hash output files (hashes.txt, kerberoast output) from the filesystem
- [ ] Rotate passwords for all accounts that were enumerated (visible in net user / net localgroup output) if breach is confirmed
- [ ] Rotate passwords for ALL service accounts with SPNs if Kerberoasting was confirmed (treat all SPN-bearing account hashes as compromised)
- [ ] Review and revoke any suspicious Kerberos tickets: `klist purge` on affected systems; consider issuing a krbtgt double-reset if Golden Ticket is suspected
- [ ] Remove any unauthorized SPN assignments identified during investigation
- [ ] Audit all local administrator group memberships and remove unauthorized accounts

### Recovery

- [ ] Verify all malicious artifacts removed (Rubeus.exe, hash files, output files)
- [ ] Confirm service account passwords have been reset and gMSA migration plan is in progress
- [ ] Re-enable any security controls that were modified or disabled during the incident
- [ ] Verify LAPS is functioning and local admin passwords are unique across endpoints
- [ ] Confirm Kerberos AES-only policy is applied domain-wide
- [ ] Re-enable the affected endpoint's network connectivity after confirming clean state
- [ ] Monitor the endpoint and domain controller logs for 72 hours post-recovery for recurrence
- [ ] Validate that ASR rules and audit policies are active and configured correctly

### Post-Incident Review

1. How was the initial compromise achieved? (phishing, credential stuffing, prior lateral movement?)
2. What was the time between initial compromise and detection of enumeration activity?
3. Were any enumeration commands (net.exe, wmic.exe) flagged by the SIEM during the incident? If not, why not?
4. Were any Kerberoast/AS-REP roast requests detected by domain controller monitoring?
5. Were service account passwords strong enough to resist offline cracking during the window between compromise and reset?
6. What controls would have prevented the initial access that enabled the attacker to run enumeration tools?
7. Were LAPS passwords unique at the time of compromise? Did shared local admin passwords enable lateral movement?
8. Action items: (a) deploy gMSAs for all SPN accounts, (b) enforce RC4 disable policy, (c) tune SIEM rules based on gaps identified.

---

## References

- [MITRE ATT&CK T1087.001 — Account Discovery: Local Account](https://attack.mitre.org/techniques/T1087/001/)
- [MITRE ATT&CK T1078.003 — Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- [MITRE ATT&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE M1026 — Privileged Account Management](https://attack.mitre.org/mitigations/M1026/)
- [MITRE M1027 — Password Policies](https://attack.mitre.org/mitigations/M1027/)
- [MITRE M1028 — Operating System Configuration](https://attack.mitre.org/mitigations/M1028/)
- [MITRE M1033 — Limit Software Installation](https://attack.mitre.org/mitigations/M1033/)
- [MITRE M1041 — Encrypt Sensitive Information](https://attack.mitre.org/mitigations/M1041/)
- [MITRE M1018 — User Account Management](https://attack.mitre.org/mitigations/M1018/)
- [Microsoft LAPS Documentation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [Microsoft — Group Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [CIS Benchmark for Windows 10/11](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [NSA/CISA — Top 10 Cybersecurity Misconfigurations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a)
- [CISA Advisory AA22-279A — Top Routinely Exploited Vulnerabilities](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-279a)
- [Sean Metcalf — Kerberoasting Without Mimikatz](https://adsecurity.org/?p=2293)
- [Harmj0y — Roasting AS-REPs](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
- [Microsoft Security Baseline — Windows 11](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
