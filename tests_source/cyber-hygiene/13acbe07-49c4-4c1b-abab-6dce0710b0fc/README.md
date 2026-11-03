# Cyber-Hygiene Bundle (SentinelOne Singularity Edition)

**Test Score**: **8.5/10**

Active rubric: **v2.1**. The safety gate passes by source inspection: output is confined to approved directories, the temporary `secedit` export is deleted, and an enforced 10-minute watchdog logs and terminates with exit 102. No lab execution is claimed; Telemetry Signal Quality remains capped at 1.5/2.0.

## Overview

This Windows cyber-hygiene bundle evaluates **41 controls**: 35 shared Windows baseline checks and six SentinelOne Singularity checks. It is a read-only posture assessment, not an attack simulation. It inspects local registry policy, services, file versions, network-protocol settings, audit policy, account policy, endpoint role, and SentinelOne agent health to identify configuration gaps relevant to defense evasion, credential access, execution, lateral movement, command and control, persistence, and privilege escalation.

The bundle does not attempt credential dumping, PowerShell execution of attacker payloads, SMB relay, password guessing, account creation, service execution, or defense impairment. Its MITRE mappings describe the risk areas informed by each configuration check, not techniques performed by the binary.

SentinelOne local service and version evidence is deliberately separated from central policy. Prevention mode, recent cloud check-in, anti-tampering, and detection-engine controls are emitted as `UNKNOWN` by the Go binary. ProjectAchilles (PA) may resolve those controls only from read-only central host and effective account/site/group policy evidence; a running local service alone is never sufficient evidence of protection.

This is not a complete CIS Benchmark assessment and does not establish CIS certification or full compliance with any external framework.

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique name | Related assessment area |
|--------|-----------|----------------|-------------------------|
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | SentinelOne service health, prevention, anti-tampering, and detection policy |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | LSASS Protected Process Light, Credential Guard, and VBS policy |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Script block, module, transcription, and constrained-language policy |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | SMBv1, signing, encryption, and null-session restrictions |
| Credential Access | T1110 | Brute Force | Lockout, password, and account-lockout audit policy |
| Credential Access | T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | LLMNR, NetBIOS over TCP/IP, and WPAD hardening |
| Command and Control | T1572 | Protocol Tunneling | IPv6 tunnel-interface policy |
| Persistence; Privilege Escalation | T1078.003 | Valid Accounts: Local Accounts | Windows LAPS or legacy LAPS configuration |
| Execution | T1569.002 | System Services: Service Execution | Print Spooler service state and start mode |
| Privilege Escalation | T1547.012 | Boot or Logon Autostart Execution: Print Processors | Print driver and Point and Print restrictions |
| Defense Evasion | T1078 | Valid Accounts | Logon, logoff, and special-logon auditing |
| Persistence | T1136 | Create Account | User and computer account-management auditing |
| Persistence | T1098 | Account Manipulation | Security group-management auditing |

## Test Execution

The single-binary test runs one in-process validation phase. It discovers endpoint context, evaluates all controls without short-circuiting, writes one result per control to `bundle_results.json`, and writes Schema v2.0 execution logs.

For the most complete local evidence, run from an elevated Windows prompt. Running without elevation can make privileged registry, service, audit, or account-policy queries return `UNKNOWN`; it does not turn an unreadable setting into a pass or fail.

```powershell
C:\F0\13acbe07-49c4-4c1b-abab-6dce0710b0fc.exe
```

Outputs are written to `C:\F0`:

- `bundle_results.json` — bundle schema 1.1, endpoint context, aggregate status, and 41 control records.
- `test_execution_log.json` — Schema v2.0 result and execution context.
- `test_execution_log.txt` — human-readable execution log.

The execution context declares and the Go process enforces a 600,000 ms (10 minute) assessment timeout. On expiry, the watchdog records an error, marks the phase failed, saves the execution log with exit reason `Assessment watchdog expired`, and terminates with exit 102. Shared PowerShell and command helpers also enforce individual 30-second query deadlines.

The Go binary makes no SentinelOne API calls and has no network-egress routine. Local PowerShell/CIM, `auditpol`, `net accounts`, `secedit`, service, registry, and file-version queries provide evidence. The password-complexity INF is written as `C:\F0\f0_cyberhygiene_secedit.inf` and deleted by deferred cleanup after the check. Direct Elasticsearch export is disabled in the checked-in configuration.

## Expected Outcomes

### Per-control status

| Status | Control exit code | Meaning |
|--------|-------------------|---------|
| `PASS` | 126 | Observed evidence meets the stated baseline condition. This is a compliance pass, not proof that an attack was blocked. |
| `FAIL` | 101 | Observed evidence violates the stated baseline condition. This is a compliance failure, not a completed attack. |
| `UNKNOWN` | 0 | Evidence is unavailable, unreadable, or requires central management data; no compliance verdict is inferred. |
| `NOT_APPLICABLE` | 0 | The control does not apply to the discovered endpoint context, such as LAPS on a non-domain/non-Entra-joined device. |
| `ERROR`, `SKIPPED`, `NOT_EVALUATED` | 999 / 0 / 0 | Reserved result states handled by the shared finalizer; they are not evidence of protection or exposure. |

### Aggregate result

| Bundle outcome | Execution / compliance status | Overall exit code |
|----------------|-------------------------------|-------------------|
| At least one evaluated control failed | `completed` or `partial` / `non_compliant` | 101 |
| No failures, but at least one skipped, unknown, error, or not-evaluated control | `partial` / `incomplete` | 999 |
| At least one evaluated control, no failures, and no incomplete states | `completed` / `compliant` | 126 |
| No controls evaluated as pass or fail | `error` / `not_assessed` | 999 |
| Panic or failure to write bundle results | Execution error | 999 |
| Ten-minute assessment watchdog expired | Phase logged as failed; execution log saved with timeout reason | 102 |

`NOT_APPLICABLE` does not by itself make an assessment incomplete. A compliant aggregate may therefore include not-applicable controls, but never unknown or failed controls. The generic Schema v2.0 logger may label exit 126 as `protected` and 101 as `unprotected`; for this cyber-hygiene bundle, the authoritative meanings are **compliant** and **non_compliant**, respectively.

The bundle does not emit 105 or 127 as quarantine outcomes. Exit 102 is reserved for the overall assessment watchdog; an individual helper-query timeout becomes a control-level `UNKNOWN` and feeds the aggregate rules above.

## Build Instructions

From the repository root:

```bash
./utils/gobuild build tests_source/cyber-hygiene/13acbe07-49c4-4c1b-abab-6dce0710b0fc/
./utils/codesign sign build/13acbe07-49c4-4c1b-abab-6dce0710b0fc/13acbe07-49c4-4c1b-abab-6dce0710b0fc.exe
```

The expected signed binary is approximately 5.6 MB (Tier green).

## References

See [`13acbe07-49c4-4c1b-abab-6dce0710b0fc_references.md`](13acbe07-49c4-4c1b-abab-6dce0710b0fc_references.md) for source provenance and official vendor/MITRE references. See [`13acbe07-49c4-4c1b-abab-6dce0710b0fc_info.md`](13acbe07-49c4-4c1b-abab-6dce0710b0fc_info.md) for the full control catalog, evidence model, and outcome details.
