# Cyber-Hygiene Bundle (Sophos Intercept X Edition)

**Test Score**: **8.5/10**

**Test UUID**: `8ee949ce-7d96-4688-a808-7917dd907db0`  
**Rubric**: v2.1  
**Platform**: Windows endpoints and servers  
**Severity**: High  
**Subcategory**: `baseline`

## Overview

This single-binary cyber-hygiene bundle evaluates 41 controls: 35 shared Windows baseline controls and six Sophos Intercept X controls. It checks local configuration and service evidence for defenses associated with credential theft, PowerShell abuse, SMB lateral movement, network poisoning, account attacks, service execution, and persistence.

This is a read-only security configuration assessment, not an attack simulation. It does not execute the mapped techniques, create accounts or services, change security policy, drop attack payloads, or make network connections. The password-complexity check temporarily exports security policy to `C:\F0\f0_cyberhygiene_secedit.inf` with `secedit` and removes that file. Results show whether specific evidence met this bundle's policy; they do not establish full CIS Benchmark certification or prove that an endpoint is secure against every attack.

## Included Controls

| Control family | Count | Scope |
|---|---:|---|
| Sophos Local Agent Health | 3 | Endpoint Defense and MCS Agent service state/start mode; readable local endpoint version |
| Sophos Central Policy | 3 | Effective prevention policy, recent cloud check-in, and tamper protection; central evidence required |
| LSASS Protection | 3 | Protected Process Light, Credential Guard policy, Virtualization-Based Security policy |
| PowerShell Security | 4 | Script Block Logging, Module Logging, transcription, Constrained Language policy |
| SMB Hardening | 5 | SMBv1, server/client signing, server encryption, null-session restriction |
| Network Protocol Hardening | 4 | LLMNR, NetBIOS over TCP/IP, WPAD override, IPv6 tunnel interfaces |
| Print Spooler Hardening | 4 | Spooler service state, printer-driver installation restriction, Point and Print prompts |
| Local Administrator Password Solution | 1 | Windows LAPS or legacy LAPS on domain/Entra-joined devices |
| Windows Audit Logging | 9 | Logon/logoff, lockout, special logon, process creation, policy change, account/group management |
| Account Policy | 5 | Lockout threshold/duration/window, minimum password length, password complexity |
| **Total** | **41** | **35 Windows baseline + 6 Sophos controls** |

## MITRE ATT&CK Mapping

The mappings identify the attack techniques each configuration is intended to mitigate or make observable; they are not claims that the bundle performs those techniques.

| Tactic | Technique | Assessment relevance |
|---|---|---|
| Defense Evasion | **T1562.001** — Impair Defenses: Disable or Modify Tools | Sophos service health, prevention policy, check-in, and tamper protection |
| Credential Access | **T1003.001** — OS Credential Dumping: LSASS Memory | LSASS PPL, Credential Guard, and VBS policy |
| Execution | **T1059.001** — Command and Scripting Interpreter: PowerShell | PowerShell logging, transcription, and Constrained Language policy |
| Lateral Movement | **T1021.002** — Remote Services: SMB/Windows Admin Shares | SMBv1, signing, encryption, and null-session controls |
| Credential Access | **T1110** — Brute Force | Account lockout, password policy, and Account Lockout auditing |
| Credential Access | **T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | LLMNR, NetBIOS, and WPAD hardening |
| Command and Control | **T1572** — Protocol Tunneling | IPv6 tunnel-interface policy |
| Persistence, Privilege Escalation | **T1078.003** — Valid Accounts: Local Accounts | LAPS configuration for local administrator credential management |
| Execution | **T1569.002** — System Services: Service Execution | Print Spooler service exposure |
| Privilege Escalation | **T1547.012** — Boot or Logon Autostart Execution: Print Processors | Printer-driver and Point and Print restrictions |
| Defense Evasion | **T1078** — Valid Accounts | Logon, logoff, and Special Logon auditing |
| Persistence | **T1136** — Create Account | User and Computer Account Management auditing |
| Persistence | **T1098** — Account Manipulation | Security Group Management auditing |

## Test Execution

1. Discovers endpoint context: OS product/build, workstation or server role, architecture, and domain/Entra join state.
2. Initializes logging and starts an enforced 10-minute assessment watchdog; expiry is logged and exits 102.
3. Runs the 35 shared Windows baseline checks using local registry reads, CIM queries, `auditpol`, `net accounts`, and a temporary `secedit` security-policy export confined to `C:\F0` and removed after use.
4. Runs three local Sophos checks and creates three central-policy controls. Control status is finalized before its console line is printed.
5. Finalizes aggregate counts, execution status, compliance status, and overall exit code.
6. Writes per-control bundle results and Schema v2.0 execution logs under `C:\F0`.

### Local and central evidence are separate

- **CH-SOP-001 through CH-SOP-003** use endpoint-local service or executable-version evidence.
- **CH-SOP-004 through CH-SOP-006** are always `UNKNOWN` in the standalone Go binary because they require Sophos Central evidence.
- ProjectAchilles central evaluation must use evidence for the specific endpoint. It must not infer an endpoint's effective prevention policy, check-in state, or tamper protection from tenant-wide data alone.
- A readable local Sophos version is evidence of presence only; this bundle makes no version-currency claim.

## Expected Outcomes

### Per-control status

| Status | Meaning | Per-control code |
|---|---|---:|
| `PASS` | Observed evidence meets the control's expected value | 126 |
| `FAIL` | Evaluated evidence does not meet the expected value | 101 |
| `UNKNOWN` | Evidence is unavailable, inaccessible, or requires central management data | 0 |
| `NOT_APPLICABLE` | The control does not apply to the discovered endpoint context | 0 |
| `ERROR`, `SKIPPED`, `NOT_EVALUATED` | No compliance conclusion is available for the stated reason | 999 / 0 / 0 |

A per-control 126 is a compliance mapping, not evidence that an EDR blocked an attack. A per-control 101 is a failed hygiene requirement, not evidence that an attack succeeded.

### Bundle outcome

| Overall code | Compliance / execution | Meaning |
|---:|---|---|
| 101 | `non_compliant`; `completed` or `partial` | At least one evaluated control failed. Incomplete controls, if any, remain separately counted. |
| 126 | `compliant`; `completed` | Every evaluated control passed and no control is incomplete. Not reachable from the standalone binary while the three central controls remain `UNKNOWN`. |
| 999 | `incomplete`; `partial` | No failures were found, but one or more controls are unknown, skipped, errored, or not evaluated. |
| 999 | `not_assessed`; `error` | No control produced a pass/fail evaluation, or result/log generation failed. |
| 102 | Watchdog timeout | The assessment exceeded 10 minutes. The watchdog saves an execution log with the timeout reason and exits; no compliance conclusion should be inferred. |

The bundle itself does not emit 105 or 127 quarantine codes. An external runner may report its own execution failure; that must not be converted into a compliance finding without evidence.

## Lab Verification

A 2026-11-03 run on the `win` lab with Sophos Intercept X reached all 41 expected controls in 3.420 seconds:

| PASS | FAIL | UNKNOWN | NOT_APPLICABLE | Overall |
|---:|---:|---:|---:|---|
| 13 | 24 | 3 | 1 | 101 — `non_compliant`, `partial` |

The three `UNKNOWN` results were the central-only Sophos controls; LAPS was `NOT_APPLICABLE` on the non-domain/non-Entra-joined workstation. No controls were skipped, errored, or left unevaluated. The execution log passed the corrected worktree Schema v2.0 validator. Artifacts are retained in `staging/8ee949ce-7d96-4688-a808-7917dd907db0/` under execution ID `6a3a0808-82c4-44d0-8812-625da64640a7`.

## Requirements

- Windows 11, Windows Server 2022, or Windows Server 2025. Legacy OS profiles are intentionally excluded.
- PowerShell and local CIM/WMI support for service, adapter, and endpoint-context queries.
- `auditpol`, `net`, and `secedit` available for the corresponding baseline checks.
- Elevated execution is recommended for complete registry and security-policy evidence. Access failures produce `UNKNOWN` where the implementation cannot make a reliable determination.
- Sophos Intercept X for the Sophos-specific controls. The Go binary does not accept Sophos Central credentials and performs no Sophos API calls.

## Build Instructions

From the repository root:

```bash
./utils/gobuild build tests_source/cyber-hygiene/8ee949ce-7d96-4688-a808-7917dd907db0/
./utils/codesign sign build/8ee949ce-7d96-4688-a808-7917dd907db0/8ee949ce-7d96-4688-a808-7917dd907db0.exe
```

The signed binary is approximately 5.6 MB (Tier green).

## Usage and Output

Run the signed executable on the target Windows endpoint, preferably elevated:

```powershell
.\8ee949ce-7d96-4688-a808-7917dd907db0.exe
```

Output files:

- `C:\F0\bundle_results.json` — Schema 1.1 per-control results, evidence, counts, applicability, execution status, and compliance status.
- `C:\F0\test_execution_log.json` — Schema v2.0 execution log and metadata.
- `C:\F0\test_execution_log.txt` — Human-readable execution log.

## References

See [`8ee949ce-7d96-4688-a808-7917dd907db0_references.md`](8ee949ce-7d96-4688-a808-7917dd907db0_references.md) for source provenance, lab evidence, Sophos documentation, Microsoft references, and official MITRE ATT&CK mappings.
