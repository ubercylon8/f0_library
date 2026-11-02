# Qilin (Agenda): BYOVD EDR-Killer & svchost Injection Chain

**Test Score**: **8.7/10**

## Overview

This five-stage Windows test emulates the observable post-compromise chain described in Cisco Talos's April 2026 analysis of Qilin (Agenda): security-product discovery and `msimg32.dll` side-load-shaped activity, BYOVD defense impairment, DLL injection into an `svchost.exe`-named process, an LSASS access attempt, recovery-inhibition commands, and synthetic-data encryption. Its purpose is to expose native API, process, service, file, and command-line signals across the chain while keeping destructive operations on test-owned targets.

The implementation deliberately does **not** load a real vulnerable driver, modify kernel callbacks, terminate production security software, inject into a production `svchost.exe`, read LSASS memory, encrypt user data, delete real shadow copies, change real boot configuration, or make network connections. The real `rwdrv.sys` asset is dropped only for signature observation and is deleted before any service or native-load attempt. All five objectives are attempted independently, so an early block does not suppress later detection opportunities.

**Validation status:** **LAB VALIDATED** on 2026-11-02 against Sophos Intercept X on `win`. All five stages executed with no skipped controls; overall exit **126 (PREVENTED)** and Schema v2.0 validation passed. Go metadata and this document use the final **8.7/10** rubric v2.1 score. Native KQL/EQL/Sigma engine validators remain unavailable.

## Lab Evidence

| Stage | Result | Evidence |
|---|---|---|
| 1 — Discovery & Side-Load | Success (0) | Read-only discovery and the benign `msimg32.dll` image load completed. |
| 2 — BYOVD EDR-Killer | Success (0) | Both nonfunctional services were created and deleted; both `NtLoadDriver` calls returned `0xC0000130` (`STATUS_INVALID_IMAGE_NOT_MZ`) as designed. Three test-owned security-process stand-ins were terminated. Sophos separately logged `RWEverything Driver` for the real `rwdrv.sys` drop. |
| 3 — svchost Injection | **Blocked (126)** | Launching the test-owned `svchost.exe` returned Windows error 5 before remote-memory APIs executed. Sophos System Protection event 42 identified `Evade_22a (T1036.005)`. |
| 4 — LSASS Access | **Blocked (126)** | `OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION)` returned `ERROR_ACCESS_DENIED` in elevated SeDebug context; no LSASS memory was read. |
| 5 — Minimal Impact | Success (0) | Five synthetic files were encrypted; recovery commands failed only against nonexistent targets. |

The final run completed in approximately 43 seconds. `bundle_results.json` records five controls: two blocked, three successful, zero skipped. Sophos services remained running, both Qilin driver services were absent after cleanup, and pre-existing lab files were restored. Evidence is staged under `staging/8f68dda1-94be-430f-8f35-d8af3f9b5d2e/`, including `sophos_application_events.txt`.

## MITRE ATT&CK Mapping

| Tactic | Technique | Name | Stage |
|---|---|---|---|
| Discovery | T1518.001 | Software Discovery: Security Software Discovery | 1 |
| Discovery | T1082 | System Information Discovery | 1 |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | 2 |
| Defense Evasion | T1211 | Exploitation for Defense Evasion | 2 |
| Defense Evasion | T1055 | Process Injection | 3 |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | 4 |
| Impact | T1490 | Inhibit System Recovery | 5 |
| Impact | T1486 | Data Encrypted for Impact | 5 |

Stage 1 also records supporting T1574.002-shaped DLL side-load telemetry, and stage 2 records supporting T1543.003-shaped service-creation telemetry; neither is added to the declared metadata technique set.

## Test Execution

1. **Security Discovery & Side-Load — T1518.001/T1082:** performs read-only SecurityCenter2, process, service, and operating-system discovery. A test-owned `FoxitPDFReader.exe` loads a renamed, genuine Microsoft `msimg32.dll` with `LoadLibraryW` and then releases it with `FreeLibrary`.
2. **BYOVD EDR-Killer — T1562.001/T1211:** drops and observes the real `rwdrv.sys`, deletes it, writes nonfunctional `rwdrv.sys`/`hlpdrv.sys` stand-ins, creates and deletes test-owned kernel-service entries, attempts `SeLoadDriverPrivilege` plus `NtLoadDriver`, records 320 simulated callback removals in sandbox JSON, probes the guaranteed-nonfunctional `\\.\hlpdrv_f0_nonfunctional` device while logging the emulated IOCTL identifier `0x2222008`, and calls `NtTerminateProcess` only on test-owned security-process stand-ins. No device IOCTL is sent.
3. **svchost Process Injection — T1055:** starts a test-owned `svchost.exe`, then uses `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread(LoadLibraryW)` to load a renamed, genuine Microsoft `version.dll` as `pwndll.dll`.
4. **LSASS Access Attempt — T1003.001:** enables `SeDebugPrivilege` where available and requests `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` on the real LSASS process. A granted handle is closed immediately; no memory read or dump occurs.
5. **Minimal Impact — T1490/T1486:** encrypts five synthetic files with AES-256-GCM, adds `.qilin` names and a recovery note, and invokes `vssadmin`/`bcdedit` only against nonexistent GUID targets so the commands fail harmlessly.

The orchestrator extracts gzip-compressed, signed stage binaries into `C:\F0`, captures each stage's output, checks for quarantine, applies per-stage timeouts, and continues to later objectives after extraction failures, blocks, or errors. It writes `test_execution_log.json`, `bundle_results.json`, per-stage output files, and pre/post system snapshots.

## Expected Outcomes

- **Protected:** positive quarantine or prevention evidence in any stage produces overall exit **126**. Per-stage 105/126/127 results identify the blocked objective; later independent stages are still attempted.
- **Unprotected:** all five objectives complete without prevention, producing overall exit **101**. Successful stage exit 0 is normalized to 101 in `bundle_results.json`.
- **Test error:** extraction failures, inconclusive OS denials, missing prerequisites, or non-protection failures produce **999** unless another stage has positive block evidence, in which case the orchestrator's any-blocked rule takes precedence.
- **Watchdog timeout:** a stage timeout is logged as stage exit **102** and handled as an error by the orchestrator; it is not represented as an overall 102 result.
- **Observed outcome:** the final Sophos lab run produced stage exits 0/0/126/126/0 and overall **126**, matching the per-stage evidence above.

## Safety and Fidelity Boundaries

- All test-created files are confined to `C:\F0` or `c:\Users\fortika-test`; production enumeration and LSASS access are read-only or handle-only.
- Service creation/deletion applies only to unique `qilin_rwdrv_f0` and `qilin_hlpdrv_f0` entries backed by nonfunctional test-owned files. Privilege changes apply only to the current process token.
- Callback removal is represented by a sandbox JSON registry, not kernel modification. EDR process names are used only for test-owned executables.
- Normal stage returns use deferred cleanup. The orchestrator also deletes both test driver services, terminates only exact test-owned descendant paths, removes the Qilin sandbox, and deletes stand-in/driver files after stages 2 and 3 and during finalization, covering forced watchdog exits.
- The malicious `msimg32.dll` forwarding/loader logic, SEH/VEH obfuscation, user-mode hook and ETW bypasses, patched `pwndll.dll`, LSASS dump, and real encryption/recovery impact are intentionally not reproduced.

## Operational Notes

- **Orchestrator size:** 11,043,664 bytes (10.5 MiB), Yellow tier and below the v2.1 25 MB threshold.
- **Stage sizes:** all signed stages are approximately 3.2–3.4 MB after ordinary Go symbol/debug stripping, satisfying the every-stage-below-5-MB criterion. Gzip remains mandatory; no packer is used.
- **Configured stage budgets:** 180s / 360s / 240s / 180s / 180s for stages 1–5, within a 1,200,000 ms orchestrator execution configuration. These are source-configured ceilings, not observed runtimes.
- **Watchdogs:** `exec.CommandContext` enforces every stage budget. Timeout output is captured and logged, and remaining stages continue.

## Build Instructions

Run from the repository root. The multi-stage script builds and signs each stage, verifies signatures, gzip-compresses the signed stages, embeds them in the orchestrator, and signs the orchestrator:

```bash
./tests_source/intel-driven/8f68dda1-94be-430f-8f35-d8af3f9b5d2e/build_all.sh
```

Optional organization dual-signing:

```bash
./tests_source/intel-driven/8f68dda1-94be-430f-8f35-d8af3f9b5d2e/build_all.sh --org <org-identifier>
```

Output: `build/8f68dda1-94be-430f-8f35-d8af3f9b5d2e/8f68dda1-94be-430f-8f35-d8af3f9b5d2e.exe`.

See [`8f68dda1-94be-430f-8f35-d8af3f9b5d2e_info.md`](8f68dda1-94be-430f-8f35-d8af3f9b5d2e_info.md) for the complete v2.1 scorecard, Detection Opportunity Audit, execution-context analysis, watchdog semantics, safety deviations, and operational-hygiene review. Source provenance is in [`8f68dda1-94be-430f-8f35-d8af3f9b5d2e_references.md`](8f68dda1-94be-430f-8f35-d8af3f9b5d2e_references.md).
