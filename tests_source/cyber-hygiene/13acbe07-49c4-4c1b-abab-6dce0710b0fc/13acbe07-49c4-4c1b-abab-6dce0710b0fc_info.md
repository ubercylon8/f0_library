# Cyber-Hygiene Bundle (SentinelOne Singularity Edition)

## Test Information

**Test ID**: 13acbe07-49c4-4c1b-abab-6dce0710b0fc  
**Test Name**: Cyber-Hygiene Bundle (SentinelOne Singularity Edition)  
**Category**: cyber-hygiene  
**Subcategory**: baseline  
**Severity**: High  
**Platform**: Windows endpoint  
**Complexity**: Medium  
**Architecture**: Standard single binary; independent in-process controls  
**MITRE ATT&CK**: T1562.001, T1003.001, T1059.001, T1021.002, T1110, T1557.001, T1572, T1078.003, T1569.002, T1547.012, T1078, T1136, T1098  
**Tags**: cyber-hygiene, sentinelone, singularity, edr, hardening, compliance, bundle

## Description

This bundle assesses 41 Windows and SentinelOne configuration controls without simulating an attack. Thirty-five shared Windows baseline controls cover credential protections, PowerShell logging and language policy, SMB and network-protocol hardening, LAPS, Print Spooler exposure, security auditing, and local account policy. Six SentinelOne controls distinguish locally observable agent health from centrally managed protection policy.

Local service health and readable file-version evidence do not prove that prevention, anti-tampering, or detection engines are effective. The Go binary therefore returns `UNKNOWN` for SentinelOne prevention mode, recent cloud check-in, anti-tampering, and detection engines. PA can resolve these controls only when read-only SentinelOne central evidence establishes the effective account/site/group policy and current host state. Policy resolution must be conservative; a running `SentinelAgent` service cannot substitute for central evidence.

The assessment reports endpoint-specific compliance and completeness. It does not claim full CIS Benchmark coverage, CIS certification, or proof that every mapped ATT&CK technique would be prevented.

## Test Score: 8.5/10

Active rubric: **v2.1**. The Tier 1 safety gate now passes by source inspection. The `secedit` export is confined to `C:\F0` and deferred for deletion, and a `time.AfterFunc` watchdog enforces the 10-minute assessment deadline by logging the timeout and exiting 102. The score matches Go `TestMetadata`; no metadata alignment is needed. No lab execution is claimed.

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| Tier 1 — Safety Gate | **PASS** | Result/log writes and the temporary INF are confined to `C:\F0`; the INF has deferred cleanup. Real system targets are queried read-only, helper commands have deadlines, no network egress is present, and the assessment watchdog terminates a hung run with exit 102. |
| 2a — API Fidelity | 2.2/2.5 | Direct Windows registry and file APIs plus constrained local CIM/service queries collect the required production evidence accurately. Some checks use PowerShell, `auditpol`, `net accounts`, and `secedit` rather than direct APIs, preventing full credit. This is posture-validation fidelity, not an adversary API-chain claim. |
| 2b — Identifier Fidelity | 1.4/1.5 | Real HKLM paths, value names, service names, audit categories, account keys, and SentinelOne installation paths are used. Runtime endpoint role and join discovery improve applicability; no sandbox identifiers are involved. |
| 2c — Telemetry Signal Quality | 1.5/2.0 | Structured per-control evidence, explicit sensor/consumer mapping, and bundled behavioral rule artifacts provide clear audit signals. The no-lab hard cap applies: no end-to-end execution log or all-control lab result is claimed. Tenant rule firing is not scored. |
| 2d — Execution-Context Fidelity | 0.5/1.0 | Context-independent read-only assessment is appropriate. Endpoint role and join state affect applicability and privileged read failures degrade to `UNKNOWN`, but the test does not branch into distinct user/admin/SYSTEM behavior. |
| 3a — Schema & Metadata | 1.0/1.0 | Schema v2.0 `InitLogger`, full metadata, organization execution context, rubric v2.1, and the reported signed-binary build are present; score metadata agrees with this card. |
| 3b — Documentation Completeness | 1.0/1.0 | README, info card with v2.1 breakdown, references, official ATT&CK mappings, and consistent numeric score formatting are present. |
| 3c — Logging & Plumbing | 0.4/0.5 | Bundle fan-out and JSON/text execution logs are present, including watchdog logging. No pre/post system snapshots are produced. |
| 3d — Operational Hygiene | 0.5/0.5 | Approximately 5.6 MB signed single binary, no separate stage binaries, documented 10-minute budget, enforced watchdog, 30-second helper deadlines, and direct terminal exits. |
| **Total** | **8.5/10** | **Realism 5.6/7.0 + Structure 2.9/3.0; Advanced.** |

**Key strengths**:

- Forty-one independently evaluated controls do not short-circuit after a failure.
- Local observations and central-policy requirements are separate evidence domains.
- Unknown, not-applicable, failed, timeout, and execution-error states remain distinct.
- Endpoint role and domain/Entra join state inform LAPS and Print Spooler applicability.
- The enforced watchdog, confined temporary export, and direct terminal exits satisfy the inspected operational safety requirements.
- The Go binary performs no attack simulation and contains no network-egress routine.

**Improvement opportunities**:

- Run and retain representative end-to-end lab evidence to satisfy the final telemetry criterion and lift the 1.5/2.0 cap.
- Add pre/post system snapshots for full logging-and-plumbing credit.
- Exercise standard-user, elevated, workstation, server, domain-joined, Entra-joined, and PA-enriched scenarios without treating central unknowns as failures.
- Keep formal parser validation and lab firing separate: artifact validity contributes to test quality, while tenant firing is a defense audit.

## Technical Details

### Execution Flow

1. **Initialize and discover context**
   - Resolve organization identity and create a unique execution ID.
   - Capture hostname, OS product/version/build, architecture, workstation/server role, domain join, and Entra join state.
   - `F0_OS_ROLE` can explicitly override the discovered OS role; an invalid override is recorded as context error.

2. **Evaluate 35 shared Windows baseline controls**
   - Read HKLM policy values through the Windows registry API.
   - Use local PowerShell/CIM for service, adapter, and file-version evidence.
   - Query audit categories with `auditpol /get /r` and account policy with `net accounts`.
   - Export security policy with `secedit` for password complexity. The INF is confined to `C:\F0` and removed by deferred cleanup after the check.

3. **Evaluate six SentinelOne controls**
   - Query `SentinelAgent` state and start mode.
   - Read a local file version from the known `SentinelAgent.exe` or `SentinelStaticEngine.exe` paths.
   - Emit four central-policy controls as `UNKNOWN`; the Go binary does not call the SentinelOne Management API.

4. **Finalize and persist**
   - Normalize each control's status and exit code.
   - Count pass, fail, unknown, error, skipped, not-applicable, and not-evaluated states.
   - Derive execution status, compliance status, assessment completeness, and aggregate exit code.
   - Write `bundle_results.json`, `test_execution_log.json`, and `test_execution_log.txt` under `C:\F0`.

### Control Catalog

The source implements **41 controls**, not 40: 35 shared Windows controls plus six SentinelOne controls.

#### Credential, PowerShell, SMB, network, and LAPS controls

| Control | Name | Pass condition | ATT&CK |
|---------|------|----------------|--------|
| CH-LSS-001 | LSASS Protected Process Light | `RunAsPPL` is 1 or 2 | T1003.001 |
| CH-LSS-002 | Credential Guard Policy | `LsaCfgFlags` is 1 or 2 | T1003.001 |
| CH-LSS-003 | Virtualization-Based Security Policy | `EnableVirtualizationBasedSecurity = 1` | T1003.001 |
| CH-PWS-001 | PowerShell Script Block Logging | `EnableScriptBlockLogging = 1` | T1059.001 |
| CH-PWS-002 | PowerShell Module Logging | `EnableModuleLogging = 1` | T1059.001 |
| CH-PWS-003 | PowerShell Transcription | `EnableTranscripting = 1` | T1059.001 |
| CH-PWS-004 | PowerShell Constrained Language Policy | `__PSLockdownPolicy = 4` | T1059.001 |
| CH-SMB-001 | SMBv1 Disabled | `mrxsmb10 Start = 4`, or the driver is absent | T1021.002 |
| CH-SMB-002 | SMB Server Signing Required | Server `RequireSecuritySignature = 1` | T1021.002 |
| CH-SMB-003 | SMB Client Signing Required | Client `RequireSecuritySignature = 1` | T1021.002 |
| CH-SMB-004 | SMB Server Encryption Policy | `EncryptData = 1` | T1021.002 |
| CH-SMB-005 | SMB Null Session Restriction | `RestrictNullSessAccess = 1` | T1021.002 |
| CH-NET-001 | LLMNR Disabled | `EnableMulticast = 0` | T1557.001 |
| CH-NET-002 | NetBIOS over TCP/IP Disabled | `TcpipNetbiosOptions = 2` on every IP-enabled adapter | T1557.001 |
| CH-NET-003 | WPAD Override Enabled | `WpadOverride = 1` | T1557.001 |
| CH-NET-004 | IPv6 Tunnel Interfaces Disabled | `DisabledComponents` has any `0x21` bit set (`value & 0x21 != 0`) | T1572 |
| CH-LAP-001 | LAPS Configured | Windows LAPS `BackupDirectory > 0` or legacy `AdmPwdEnabled = 1`; not applicable when neither domain- nor Entra-joined | T1078.003 |

#### Print Spooler controls

| Control | Name | Pass condition | ATT&CK |
|---------|------|----------------|--------|
| CH-PRT-001 | Print Spooler Service | Service absent, or not running and disabled; a running spooler on a server remains `UNKNOWN` pending approval of its print role | T1569.002 |
| CH-PRT-002 | Printer Driver Installation Restricted | `RestrictDriverInstallationToAdministrators = 1` | T1547.012 |
| CH-PRT-003 | Point and Print Installation Warning | `NoWarningNoElevationOnInstall = 0` | T1547.012 |
| CH-PRT-004 | Point and Print Update Prompt | `UpdatePromptSettings = 0` | T1547.012 |

#### Windows audit controls

| Control | Name | Required audit mode | ATT&CK annotation in shared evaluator |
|---------|------|---------------------|----------------------------------------|
| CH-AUD-001 | Audit Logon | Success and Failure | T1078 |
| CH-AUD-002 | Audit Logoff | Success | T1078 |
| CH-AUD-003 | Audit Account Lockout | Failure | T1110 |
| CH-AUD-004 | Audit Special Logon | Success | T1078 |
| CH-AUD-005 | Audit Process Creation | Success | T1059 |
| CH-AUD-006 | Audit Policy Change | Success | T1562.002 |
| CH-AUD-007 | Audit User Account Management | Success and Failure | T1136 |
| CH-AUD-008 | Audit Computer Account Management | Success | T1136 |
| CH-AUD-009 | Audit Security Group Management | Success | T1098 |

`T1059` and `T1562.002` are annotations on shared evaluators; they are not additional entries in this bundle's declared `TestMetadata` technique list.

#### Account-policy controls

| Control | Name | Pass condition | ATT&CK |
|---------|------|----------------|--------|
| CH-LOK-001 | Account Lockout Threshold | 1 through 5, inclusive | T1110 |
| CH-LOK-002 | Account Lockout Duration | At least 15 minutes, or `Never` | T1110 |
| CH-LOK-003 | Reset Account Lockout Counter | Observation window of at least 15 minutes | T1110 |
| CH-LOK-004 | Minimum Password Length | At least 14 characters | T1110 |
| CH-LOK-005 | Password Complexity | Exported `PasswordComplexity = 1` | T1110 |

#### SentinelOne controls

| Control | Name | Evidence and pass condition | ATT&CK |
|---------|------|-----------------------------|--------|
| CH-S1-001 | SentinelOne Agent Service | Local `SentinelAgent` is `Running` with `Auto` start | T1562.001 |
| CH-S1-002 | SentinelOne Agent Version Detected | A non-empty readable file version at either known installation path; this makes no version-currency claim | T1562.001 |
| CH-S1-003 | SentinelOne Prevention Mode | Go result is `UNKNOWN`; central evidence must show an active agent and effective `mitigationMode` that is not detect-only | T1562.001 |
| CH-S1-004 | SentinelOne Recent Cloud Check-in | Go result is `UNKNOWN`; central `networkStatus=connected` and `lastActiveDate` within the configured threshold are required | T1562.001 |
| CH-S1-005 | SentinelOne Anti-Tampering | Go result is `UNKNOWN`; effective account/site/group policy must show `antiTamperingOn=true` | T1562.001 |
| CH-S1-006 | SentinelOne Detection Engines | Go result is `UNKNOWN`; effective central policy must show the required detection engines enabled | T1562.001 |

### Evidence and Outcome Integrity

- Registry values that are absent generally produce `FAIL` where the baseline requires explicit configuration; registry access errors produce `UNKNOWN`.
- SMBv1 is the deliberate exception: an absent `mrxsmb10` driver is compliant because the legacy driver is not installed.
- NetBIOS with no IP-enabled adapters is `NOT_APPLICABLE`; an unexpected query response is `UNKNOWN`.
- A local SentinelOne version missing from both known paths is `UNKNOWN`, not proof that the agent is absent or out of date.
- The four central-policy controls never become `PASS` or `FAIL` inside this Go binary.
- Control exit 126 means baseline pass; control exit 101 means baseline fail. These codes do not describe attack prevention or attack success in this bundle.

### Execution Context and Operational Budget

The controls are primarily configuration checks and do not emulate a user-context or SYSTEM-context attack chain. Elevated execution provides the broadest local visibility. The logger records username and an admin check, while the shared context discovery records endpoint role and join state. Access denials become unknown evidence rather than being reinterpreted as compliant or non-compliant.

- **Overall timeout**: 600,000 ms (10 minutes), both recorded in execution configuration and enforced by `time.AfterFunc`.
- **Watchdog outcome**: logs an error, marks phase 1 failed, saves the log with `Assessment watchdog expired`, and calls `os.Exit(102)`.
- **Helper deadline**: 30 seconds per shared PowerShell or command invocation.
- **Binary budget**: approximately 5.6 MB signed, Tier green; there are no separate stage binaries.
- **Network**: no egress routine in the Go binary; central enrichment is external to it.
- **Artifacts**: results, logs, and the password-complexity INF are confined to `C:\F0`; the INF has deferred deletion after the check.
- **Phase logging**: one-based phase numbers are converted to zero-based slice indices in `LogPhaseEnd` and `LogPhaseError`.

## Detection Opportunity Audit

This bundle produces **audit and posture evidence**, not adversary behavior. The following ten evidence surfaces are opportunities for execution auditing and compliance analytics; they are not claims that an EDR should block the read-only assessment. Bundled KQL, Sigma, YARA, and LimaCharlie rules address real SentinelOne tampering behavior rather than flagging this read-only validator.

| # | Control surface | Observable activity / evidence | Sensor or consumer | Pattern to monitor |
|---|-----------------|--------------------------------|--------------------|--------------------|
| 1 | LSASS, PowerShell, SMB, network, LAPS, and print policy | HKLM registry reads of named policy values | Registry auditing/EDR; F0 result consumer | Unexpected principal reading policies at scale; correlate process identity with baseline results |
| 2 | Service health | Local `powershell.exe` running CIM queries for `Win32_Service` | Sysmon/EDR process telemetry; CIM/WMI auditing | Query targets `SentinelAgent` or `Spooler`; retain state/start-mode evidence |
| 3 | Network adapters | CIM query for `Win32_NetworkAdapterConfiguration` | CIM/WMI auditing; F0 result consumer | IP-enabled adapters with NetBIOS not explicitly disabled |
| 4 | Agent file version | Local file metadata query for SentinelOne executables | File/registry telemetry where available; F0 result consumer | Version present but no inference of currency or prevention effectiveness |
| 5 | Audit policy | Nine `auditpol /get /r` queries | Sysmon/EDR process creation; Windows audit-policy telemetry | Correlate query results with required Success/Failure modes |
| 6 | Account policy | `net accounts` query | Sysmon/EDR process creation; F0 result consumer | Lockout/password values outside stated ranges |
| 7 | Password complexity | `powershell.exe` launches `secedit /export` and reads the INF under `C:\F0` | Process and file telemetry; F0 result consumer | Correlate the confined temporary INF with the validator; normal completion removes it |
| 8 | Endpoint applicability | Local OS role and domain/Entra join discovery | F0 `endpoint_context`; PA analytics | LAPS and spooler decisions interpreted using endpoint role and join state |
| 9 | Central SentinelOne policy | PA-ingested central host and effective-policy evidence | SentinelOne Management API via PA, not the Go binary | Account/site/group effective policy and host state; missing evidence remains unknown |
| 10 | Bundle health | Per-control statuses, evidence source, observed timestamp, and aggregate completeness | Elasticsearch/PA | Alert on failed critical controls and stale/incomplete assessments separately |

## Expected Results

### Compliant assessment (aggregate code 126)

Every evaluated control passes, at least one control is evaluated, and there are no unknown, skipped, error, or not-evaluated controls. Not-applicable controls may be present. This means the defined baseline passed; it is not a guarantee against the mapped ATT&CK techniques.

### Non-compliant assessment (aggregate code 101)

One or more controls fail. If incomplete states are also present, execution is `partial`; otherwise it is `completed`. Compliance is `non_compliant` in either case. Individual pass/fail records remain available for remediation prioritization.

### Incomplete assessment (aggregate code 999)

No control failed, but at least one control is unknown, skipped, error, or not evaluated. Execution is `partial` and compliance is `incomplete`. In the standalone Go binary, the four SentinelOne central-policy controls normally make the aggregate incomplete even when every locally evaluated control passes.

### Not assessed or execution error (aggregate code 999)

If no control reaches pass or fail, execution is `error` and compliance is `not_assessed`. Panics and bundle-result write failures also exit 999. These outcomes must not be counted as compliant, protected, or exposed.

### Assessment timeout (aggregate code 102)

If the 10-minute watchdog expires, it logs the timeout, marks phase 1 failed, saves the Schema v2.0 log, and terminates with 102. This is an execution timeout, not a compliance pass or fail. An individual 30-second helper timeout instead produces control-level `UNKNOWN` and follows the normal aggregation rules.

### Other codes

- **105 / 127**: quarantine codes supported by the generic logger, not emitted as control or aggregate compliance verdicts here.
- **Control code 0**: unknown, skipped, not-applicable, or not-evaluated; inspect `status`, `applicability`, `details`, and `evidence_source` rather than treating 0 as success.

## References

See [`13acbe07-49c4-4c1b-abab-6dce0710b0fc_references.md`](13acbe07-49c4-4c1b-abab-6dce0710b0fc_references.md) for full source provenance, supporting resources, and official ATT&CK mappings.
