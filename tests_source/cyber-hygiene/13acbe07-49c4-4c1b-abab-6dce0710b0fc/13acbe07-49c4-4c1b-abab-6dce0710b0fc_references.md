# References & Sources

## Primary Source

The user-provided requirements that initiated this read-only Windows and SentinelOne cyber-hygiene assessment.

| Field | Value |
|-------|-------|
| **Title** | User-provided cyber-hygiene requirements — SentinelOne Singularity edition |
| **Author/Organization** | User-provided F0RT1KA requirements briefing |
| **Date Published** | 2026-11-03 |
| **Document Type** | verbal-briefing |
| **URL** | Not available |

## Supporting Resources

These resources provide product and hardening context. They do not imply that this 41-control bundle is a complete assessment against any external benchmark.

| # | Title | Type | URL |
|---|-------|------|-----|
| 1 | SentinelOne Singularity Platform | Official vendor product overview | https://www.sentinelone.com/platform/ |
| 2 | SentinelOne Management API documentation | Official vendor documentation available inside authenticated customer consoles | Not publicly linked; access through the SentinelOne management console |
| 3 | Microsoft security baselines guide | Official platform hardening documentation | https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines |
| 4 | CIS Benchmarks | General hardening-benchmark reference only; no CIS certification or complete-profile claim | https://www.cisecurity.org/cis-benchmarks |
| 5 | F0RT1KA Rubric v2.1: Signal Quality + Execution Context + Operational Hygiene | Active scoring specification used for the 8.5/10 assessment; no lab execution is claimed | `docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md` in the F0RT1KA repository |

SentinelOne prevention mode, network/check-in state, anti-tampering, detection engines, and effective account/site/group policy require central evidence. The Go binary does not retrieve that evidence and performs no SentinelOne API network calls.

## MITRE ATT&CK References

The mappings identify defensive risk areas assessed by configuration controls; the bundle does not execute these techniques.

| Technique | Name | URL |
|-----------|------|-----|
| T1562.001 | Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |
| T1003.001 | OS Credential Dumping: LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ |
| T1110 | Brute Force | https://attack.mitre.org/techniques/T1110/ |
| T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | https://attack.mitre.org/techniques/T1557/001/ |
| T1572 | Protocol Tunneling | https://attack.mitre.org/techniques/T1572/ |
| T1078.003 | Valid Accounts: Local Accounts | https://attack.mitre.org/techniques/T1078/003/ |
| T1569.002 | System Services: Service Execution | https://attack.mitre.org/techniques/T1569/002/ |
| T1547.012 | Boot or Logon Autostart Execution: Print Processors | https://attack.mitre.org/techniques/T1547/012/ |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078/ |
| T1136 | Create Account | https://attack.mitre.org/techniques/T1136/ |
| T1098 | Account Manipulation | https://attack.mitre.org/techniques/T1098/ |

## Related Advisories & News

No campaign, threat-actor advisory, CVE, or incident report was supplied. This is a baseline cyber-hygiene bundle, so no advisory attribution is claimed.
