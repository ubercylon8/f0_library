# Qilin (Agenda): BYOVD EDR-Killer & svchost Injection Chain

## Test Information

| Field | Value |
|---|---|
| Test ID | `8f68dda1-94be-430f-8f35-d8af3f9b5d2e` |
| Test Name | Qilin (Agenda): BYOVD EDR-Killer & svchost Injection Chain |
| Category | intel-driven |
| Subcategory | ransomware |
| Platform | windows-endpoint (amd64) |
| Severity | Critical |
| Complexity | High |
| Architecture | Five independent stages in one signed orchestrator |
| Threat Actor | Qilin (Agenda) |
| MITRE ATT&CK | T1518.001, T1082, T1562.001, T1211, T1055, T1003.001, T1490, T1486 |
| Tactics | discovery, defense-evasion, credential-access, impact |
| Rubric | v2.1 — Signal Quality + Execution Context + Operational Hygiene |
| Validation Status | Lab validated 2026-11-02 on `win` with Sophos Intercept X; all five stages reached |
| Primary Source | [Cisco Talos — Qilin EDR killer infection chain](https://blog.talosintelligence.com/qilin-edr-killer/), 2026-04-02 |

## Description

This test evaluates whether endpoint controls can observe a Qilin-inspired chain that combines security discovery, DLL side-load-shaped execution, vulnerable-driver defense impairment, remote DLL injection, LSASS access, recovery inhibition, and data encryption. Its principal value is the pre-impact defense-evasion chain rather than a full ransomware payload.

Five separately executable stages are signed, gzip-compressed, embedded, and independently attempted. The test preserves useful native primitives—`LoadLibraryW`, `AdjustTokenPrivileges`, `NtLoadDriver`, `CreateFile`, `NtTerminateProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, and LSASS `OpenProcess`—while substituting nonfunctional drivers, test-owned processes, benign Microsoft DLLs, and synthetic documents for harmful targets. The hlpdrv device open targets a guaranteed-nonfunctional name and logs the emulated IOCTL identifier without calling `DeviceIoControl`. It has no network-egress path.

## Test Score: 8.7/10

This is the final **rubric v2.1** assessment after source review, local rule validation, and an all-stage Sophos lab run on 2026-11-02. Go metadata declares the same 8.7 score and omits the incompatible legacy breakdown. Realism is **5.7/7.0** and Structure is **3.0/3.0**. The total, Realism, Structure, and lab-execution ship requirements are met. Native KQL/EQL/Sigma engine validation remains optional follow-up work, not a lab-evidence gap.

### Score Breakdown

| Tier | Criterion | Score | Detailed justification |
|---|---|---:|---|
| 1 | Safety Gate | **PASS — design and lab cleanup verified** | Writes are confined to `LOG_DIR`/`ARTIFACT_DIR`; there is no network egress. The real driver is deleted before load attempts, callback mutation is JSON-only, injection and termination target test-owned processes, LSASS is opened without a read, and recovery commands target nonexistent GUIDs. Services and privileges are confined to test-owned entries and the current token. Normal returns have deferred cleanup and every stage has an outer watchdog. The orchestrator also deletes test driver services, terminates only exact test-owned descendant paths, removes the Qilin sandbox, and deletes stand-in/driver files after relevant stages and finalization, covering forced-kill paths. Post-run checks found both Qilin services absent, Sophos healthy, and original lab artifacts restored. |
| 2a | API Fidelity (0–2.5) | **1.7** | The core native chains are present: side-load `LoadLibraryW`/`FreeLibrary`; service create/query plus `OpenProcessToken` → `LookupPrivilegeValue` → `AdjustTokenPrivileges` → `NtLoadDriver`; a `CreateFile` absence probe; `OpenProcess(PROCESS_TERMINATE)`/`NtTerminateProcess`; `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread(LoadLibraryW)` → `WaitForSingleObject`/`GetExitCodeThread`; LSASS `OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION)`; and real file encryption plus `vssadmin`/`bcdedit`. Exact-chain credit is withheld because no functional vulnerable driver or kernel callback operation occurs, no device IOCTL is sent, the malicious loader and patched DLL are absent, LSASS is not read, discovery is command-issued, and recovery commands intentionally fail. |
| 2b | Identifier Fidelity (0–1.5) | **1.5** | Uses accurate production identifiers: `root/SecurityCenter2`, `AntiVirusProduct`, `Win32_OperatingSystem`, `msimg32.dll`, `rwdrv.sys`, `hlpdrv.sys`, IOCTL `0x2222008`, `SeLoadDriverPrivilege`, `SeDebugPrivilege`, `lsass.exe`, `MsMpEng.exe`, `CSFalconService.exe`, `CrowdStrike.exe`, `svchost.exe`, `pwndll.dll`, `vssadmin.exe`, and `bcdedit.exe`. Runtime Toolhelp enumeration resolves the real LSASS PID. Sandbox artifacts retain adversary/target names while service names are explicitly test-owned; the device probe deliberately substitutes `\\.\hlpdrv_f0_nonfunctional` for the production device name. |
| 2c | Telemetry Signal Quality (0–2.0) | **2.0** | Criterion 1, signal richness: **met** across process, image-load, file, service, privilege, native-driver, process-access, remote-thread, and command-line surfaces. Criterion 2, sensor mapping: **met** by the Detection Opportunity Audit. Criterion 3, rule-artifact validity: **met**; all five formats are bundled, YAML/NDJSON parse successfully, and YARA compiles and matches the exact driver. Criterion 4, all-stage lab execution: **met**; the final `test_execution_log.json` has `exitReason`, all five stages have success/blocked outcomes rather than skipped, and Schema v2.0 validation passes. Sophos System Protection event 42 corroborates `RWEverything Driver` and `Evade_22a (T1036.005)` detections. Native KQL/EQL/Sigma engine validators remain unavailable but do not reduce the empirical lab result. |
| 2d | Execution-Context Fidelity (0–1.0) | **0.5** | `isAdmin()` and `isSystemContext()` are evaluated at runtime, and `enablePrivilege` handles privilege denial without crashing. Elevated context is required for meaningful SeLoadDriver/SeDebug outcomes. However, context is used mainly to distinguish positive prevention from baseline denial; behavior does not branch into distinct user/admin/SYSTEM emulation paths. Cross-context execution has not been lab-tested. |
| 3a | Schema & Metadata (0–1.0) | **1.0** | Schema v2.0 `InitLogger`, complete metadata header, technique/tactic/tags fields, generated execution UUID, organization UUID resolution, `RubricVersion: "v2.1"`, and a signed build path are present. Local digest verification passed and the F0RT1KA certificate was confirmed in the target's trusted root store before execution. The score is aligned with this document and the incompatible legacy breakdown is omitted. |
| 3b | Documentation Completeness (0–1.0) | **1.0** | README, this info card with an explicit v2.1 breakdown and Detection Opportunity Audit, and the references file are present. Official technique/sub-technique IDs are mapped and the required score formats are used. |
| 3c | Logging & Plumbing (0–0.5) | **0.5** | Schema v2.0 logger, shared stage logging, stdout/stderr capture, per-stage `bundle_results.json` fan-out, `test_execution_log.json`/`.txt`, and pre/post `<uuid>_system_snapshot_{pre,post}.json` are implemented. Snapshots include system information and CSFalconService/WinDefend/Sense plus Sophos Endpoint Defense/File Scanner/MCS service query output, covering the current lab sensor stack. |
| 3d | Operational Hygiene (0–0.5) | **0.5** | Orchestrator 10.5 MiB: **0.1** (<25 MB). Every signed stage is approximately 3.2–3.4 MB: **0.1** (<5 MB each). Documented per-stage budgets: **0.1**. Outer watchdog on every stage: **0.1**. Finalization completed within 30 seconds in the lab, including the 2-second finalization sleep: **0.1**. |
|  | **Total** | **8.7/10** | **Realism:** 1.7 + 1.5 + 2.0 + 0.5 = **5.7/7.0**. **Structure:** 1.0 + 1.0 + 0.5 + 0.5 = **3.0/3.0**. **Range:** Advanced; all-stage lab validated. |

### Go Metadata Alignment

The orchestrator sets `Score: 8.7`, leaves `ScoreBreakdown` nil/omitted, and retains `RubricVersion: "v2.1"`. The detailed v2.1 breakdown remains in this info card because the legacy five-field structure cannot represent the v2.1 dimensions. Rule artifacts and all-stage lab execution are validated.

### Key Strengths

- Five independent objectives preserve downstream detection opportunities even when an earlier stage is quarantined, blocked, or fails.
- Strong native API coverage and accurate Qilin/security-product identifiers provide multiple sensor-visible primitives without shelling out for the injection or termination chains.
- Harmful targets are replaced deliberately: the real driver is signature-observation-only, driver load attempts use invalid stand-ins, and process injection/termination never targets production processes.
- Structured logs, per-stage output, bundle fan-out, pre/post snapshots, quarantine checks, and explicit error-versus-block classification support ProjectAchilles ingestion.
- Every stage has a configured outer deadline, and stage output/extraction failures do not halt the remaining objectives.

### Improvement Opportunities

- Where available, add native KQL/EQL/Sigma engine validation to the completed YAML/NDJSON/YARA checks and validate the same stages against a CrowdStrike-protected host for cross-EDR comparison.
- Add meaningful user/admin/SYSTEM behavior branches rather than using context only for denial attribution, then test all three contexts.
- Add an orchestrator-wide hang guard around unbounded snapshot/discovery subprocess calls if deployment evidence shows they can stall.

## Technical Details

### Attack Flow

#### Stage 1 — Security Discovery & Side-Load (T1518.001/T1082)

1. Executes read-only `powershell.exe` CIM queries for `root/SecurityCenter2:AntiVirusProduct` and `Win32_OperatingSystem`, plus `tasklist.exe /fo csv` and `sc.exe query type= service`.
2. Writes discovery output to `C:\F0\qilin_security_discovery.json` and logs command output.
3. Copies the current signed stage binary to a sandbox `FoxitPDFReader.exe` and genuine `C:\Windows\System32\msimg32.dll` beside it.
4. Launches the test-owned host with `--sideload-host`; the child resolves and calls `LoadLibraryW` on the local `msimg32.dll`, writes a success marker, sleeps 750 ms, and calls `FreeLibrary`.
5. Checks positive launch/quarantine evidence and the marker, then removes the sandbox and marker on normal returns.

**Fidelity deviation:** this reproduces the image-load shape but not Qilin's malicious forwarding DLL, in-memory payload decryption, SEH/VEH control flow, hash-based API resolution, user-mode hook neutralization, or ETW suppression.

#### Stage 2 — BYOVD EDR-Killer (T1562.001/T1211)

1. Drops the embedded real `rwdrv.sys` in `C:\F0`, waits three seconds, and checks whether it survived or was quarantined. It then deletes that asset before any load operation.
2. Writes 4,096-byte nonfunctional `rwdrv.sys` and `hlpdrv.sys` images beginning with `MZ`.
3. Deletes any pre-existing test-owned service names, creates `qilin_rwdrv_f0` and `qilin_hlpdrv_f0` as demand-start kernel services, queries them for corroboration, and deletes created entries during normal cleanup. The orchestrator also requests deletion of both names after stage 2 and during finalization, including after a stage timeout.
4. Attempts to enable `SeLoadDriverPrivilege` on the current token and calls `NtLoadDriver` with each test-owned service registry path. Expected invalid-image statuses are success for telemetry execution; an unexpected successful load triggers `NtUnloadDriver` and an error.
5. Generates 320 process/thread/image-load callback records covering real security-vendor names and marks them inactive only in `ARTIFACT_DIR\Qilin\callback_registry.json`.
6. Attempts `CreateFile(GENERIC_READ|GENERIC_WRITE, OPEN_EXISTING)` on the guaranteed-nonfunctional `\\.\hlpdrv_f0_nonfunctional` device and logs the emulated `0x2222008` IOCTL identifier on absence. If a handle unexpectedly exists, it closes the handle and logs an error; it never sends `DeviceIoControl`.
7. Copies itself to `MsMpEng.exe`, `CSFalconService.exe`, and `CrowdStrike.exe` in `C:\F0`, starts each with `--standin`, opens only that PID with `PROCESS_TERMINATE`, and calls `NtTerminateProcess`.

**Fidelity deviation:** no real vulnerable driver is loaded, no physical memory is accessed, no kernel callback is unregistered, and no production security process is terminated. Most callback/device activity is therefore a simulation or absence probe rather than the complete Qilin kernel chain.

#### Stage 3 — Test-Owned svchost DLL Injection (T1055)

1. Creates a test-owned `svchost.exe` and copies genuine `C:\Windows\System32\version.dll` as `pwndll.dll` in the injection sandbox.
2. Starts the stand-in with `--injection-target` and opens only that child PID with `PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`.
3. Resolves `LoadLibraryW`, writes the UTF-16 `pwndll.dll` path with `VirtualAllocEx(MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)` and `WriteProcessMemory`.
4. Calls `CreateRemoteThread(LoadLibraryW, remotePath)`, waits up to 10 seconds, and corroborates a nonzero, non-259 thread exit value as the loaded module handle.
5. Closes handles, frees remote memory, terminates/waits for the test-owned target, and removes the sandbox on normal returns.

**Fidelity deviation:** the remote thread and module-load telemetry are real, but the target is not a production Windows service host and the loaded DLL is a benign renamed Microsoft library rather than Qilin's patched payload.

#### Stage 4 — LSASS Access Attempt (T1003.001)

1. Records elevated context and attempts `OpenProcessToken` → `LookupPrivilegeValue(SeDebugPrivilege)` → `AdjustTokenPrivileges` on the current process.
2. Resolves `lsass.exe` through `CreateToolhelp32Snapshot`, `Process32First`, and `Process32Next`.
3. Calls `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)` against LSASS. A granted handle is closed immediately.
4. `ERROR_ACCESS_DENIED` counts as prevention only in an elevated context where SeDebugPrivilege was successfully enabled; baseline denials are inconclusive errors.

**Fidelity deviation:** there is no `ReadProcessMemory`, MiniDump, credential parsing, or credential material output. This is an access-request primitive, not an LSASS dump.

#### Stage 5 — Minimal Impact (T1490/T1486)

1. Verifies that the impact sandbox remains beneath `ARTIFACT_DIR`, then creates five synthetic documents containing repeated explicit synthetic content.
2. Generates a random 256-bit key and per-file GCM nonce, writes AES-256-GCM ciphertext with a `.qilin` suffix, deletes only the synthetic plaintext, and writes a synthetic recovery note.
3. Runs `vssadmin.exe delete shadows` for a nonexistent volume GUID and `bcdedit.exe /set {00000000-0000-0000-0000-000000000000} recoveryenabled no` for a nonexistent boot entry.
4. Removes the impact sandbox on normal returns.

**Fidelity deviation:** encryption is real only for synthetic decoys. The recovery commands preserve command-line telemetry but cannot modify real shadow copies or boot configuration. AES-256-GCM is an implementation choice, not a claim that the complete Qilin encryptor algorithm or key schedule has been reproduced.

### Key Indicators

- **Processes:** PowerShell CIM queries, `tasklist`, `sc query/create/delete`, test-owned Foxit/svchost/security-product names, `vssadmin`, and `bcdedit`.
- **Image loads:** `msimg32.dll` from a non-System32 sandbox and `pwndll.dll` loaded through a remote `LoadLibraryW` thread.
- **Files:** `rwdrv.sys`, `hlpdrv.sys`, callback registry JSON, security-process stand-ins, discovery/marker/output files, and `.qilin` ciphertext.
- **Services/registry:** creation, query, and deletion of two uniquely named kernel-service entries and native registry-path construction for `NtLoadDriver`.
- **Privileges/process access:** SeLoadDriverPrivilege, SeDebugPrivilege, process termination of stand-ins, cross-process memory writes/thread creation, and LSASS VM-read access request.
- **Network:** none; there is no egress primitive.

## Detection Opportunity Audit

The audit below defines **16 candidate detection points** and maps each implemented primitive to an appropriate sensor and rule pattern. All five detection formats are bundled and locally validated. The Sophos lab run supplies execution and vendor-event evidence; only rows explicitly marked in the Lab Evidence section are claimed as observed detections or preventions. Other telemetry availability depends on audit policy and product configuration.

| # | Stage | Primitive | Sensor / telemetry surface | Candidate rule pattern and observability boundary |
|---:|---|---|---|---|
| 1 | 1 | SecurityCenter2 AV query | Sysmon/process telemetry; WMI/CIM or EDR query telemetry | PowerShell command line containing `root/SecurityCenter2` and `AntiVirusProduct`; correlate with the following discovery burst. |
| 2 | 1 | Process/service/OS enumeration | Sysmon Event ID 1 or equivalent process events | `tasklist.exe /fo csv`, `sc.exe query`, and `Win32_OperatingSystem` CIM query from the same short-lived parent chain. |
| 3 | 1 | Test-owned Foxit host and `msimg32.dll` load | Sysmon EID 1/7; file EID 11; EDR image-load | `FoxitPDFReader.exe` outside its normal installation path loading `msimg32.dll` outside `System32`; genuine Microsoft signature does not remove the path anomaly. |
| 4 | 2 | Real `rwdrv.sys` drop | Sysmon EID 11; AV content/signature; YARA file scan | Creation of `rwdrv.sys` by the stage process, followed by quarantine or deletion. Static-signature firing is expected to be sensor/policy dependent, not assumed. |
| 5 | 2 | Nonfunctional driver drops | Sysmon EID 11; EDR file creation | Two `.sys` files written into `C:\F0` immediately after removal of the real `rwdrv.sys`; distinguish signature observation from the invalid stand-ins. |
| 6 | 2 | Kernel-service create/query/delete | Windows System 7045/Security 4697 where enabled; Sysmon EID 1; EDR service/registry | `sc.exe create` with `type= kernel`, `start= demand`, and service names `qilin_rwdrv_f0`/`qilin_hlpdrv_f0`; correlate later deletes. |
| 7 | 2 | SeLoadDriverPrivilege adjustment | Windows Security 4703/token-privilege ETW; EDR token telemetry | `AdjustTokenPrivileges` enabling SeLoadDriverPrivilege immediately before native driver-load attempts. Standard Sysmon alone is insufficient for this primitive. |
| 8 | 2 | `NtLoadDriver` on test-owned service paths | EDR native-call/kernel telemetry; Sysmon EID 6 only if a driver actually loads | Native load referencing `CurrentControlSet\Services\qilin_*`; invalid-image NTSTATUS is expected, so a driver-loaded event is **not** expected. |
| 9 | 2 | 320 simulated callback removals | Sysmon/file EID 11; EDR JSON content inspection | Creation of `callback_registry.json` containing hundreds of security-vendor driver names and process/thread/image-load entries. This detects the simulation artifact, not a real kernel callback removal. |
| 10 | 2 | Nonfunctional hlpdrv-device probe / logged `0x2222008` | EDR device-access telemetry; structured F0 log | Open of `\\.\hlpdrv_f0_nonfunctional`, with the emulated termination IOCTL identifier recorded in the stage log. No IOCTL is sent and no production hlpdrv device is accessed, so this is a bounded simulation signal rather than real kernel IOCTL telemetry. |
| 11 | 2 | Test-owned EDR-process termination | Sysmon EID 10/5; EDR process-access/termination | `OpenProcess(PROCESS_TERMINATE)` followed by `NtTerminateProcess` where source and target share the stage binary lineage and target names mimic security products. |
| 12 | 3 | Remote allocation and memory write | Sysmon EID 10; EDR memory telemetry | Source opens its test-owned svchost child for VM operation/write, allocates RW memory, and writes a DLL path. Target name alone must not be treated as production svchost. |
| 13 | 3 | `CreateRemoteThread(LoadLibraryW)` and DLL load | Sysmon EID 8/7; EDR thread/image-load | Remote thread start resolving to LoadLibraryW followed by `pwndll.dll` load from the injection sandbox; correlate with the preceding VM write. |
| 14 | 4 | SeDebugPrivilege plus LSASS access request | Windows Security 4703/token ETW; Sysmon EID 10; EDR credential-access | SeDebugPrivilege enable followed by access to real `lsass.exe` requesting `PROCESS_VM_READ`. Detection must not require an actual memory read, which this test never performs. |
| 15 | 5 | Synthetic `.qilin` encryption | Sysmon EID 11/23/26; EDR ransomware behavior | Rapid create/write/delete sequence for five documents, ciphertext with `.qilin` suffix, and `README-RECOVER.txt`, all beneath the test sandbox. |
| 16 | 5 | Recovery-inhibition commands | Sysmon EID 1; EDR command-line/D&R | `vssadmin delete shadows` and `bcdedit ... recoveryenabled no` in the same impact stage. Match command intent even though the nonexistent GUIDs make both operations fail harmlessly. |

### Telemetry Signal Quality — Criterion Status

1. **Signal richness: met by inspection.** The API call graph supplies named signals across several independent telemetry surfaces; simulation-only rows are explicitly bounded above.
2. **Sensor mapping: met.** Every stage is cross-referenced to concrete sensor types and candidate rule patterns.
3. **Rule-artifact validity: met.** KQL, YARA, Sigma, Elastic EQL, and LimaCharlie D&R files are bundled. Sigma/LimaCharlie YAML and Elastic NDJSON parse successfully; YARA compiles and the exact-hash rule matches `rwdrv.sys`. KQL/EQL/Sigma received syntax-focused/manual review because their native engine validators are unavailable.
4. **Lab execution verified: met.** The final `test_execution_log.json` contains `exitReason`, and `bundle_results.json` records all five stages as success or blocked with zero skipped. The final JSON passes Schema v2.0 validation. No Lab-Bound Observability exception is needed because every stage was attempted.

Accordingly, 2c is **2.0/2.0**. Tenant rule firing remains separate from test quality; the Lab Evidence below records only observed vendor events and OS outcomes.

## Lab Evidence — 2026-11-02, `win`, Sophos Intercept X

The final run executed as `jimx` (administrator) on Windows 11 build 26200.9457. Sophos Endpoint Defense, File Scanner, MCS Agent, MCS Client, and Device Encryption services were running before and after the test. Windows Defender and Sense were stopped. Overall exit was **126 (PREVENTED)** in approximately 44 seconds.

| Stage | Outcome | Evidence |
|---|---|---|
| 1 — Discovery & Side-Load | Success (0) | Read-only discovery completed and the benign `msimg32.dll` image-load marker was produced. |
| 2 — BYOVD EDR-Killer | Success (0) | Real `rwdrv.sys` survived the three-second observation window and was deleted before load operations. Sophos System Protection event 42 subsequently identified it as `RWEverything Driver`. Both test kernel services were created and deleted. Both `NtLoadDriver` calls returned `0xC0000130` (`STATUS_INVALID_IMAGE_NOT_MZ`), the intended safe rejection. Three test-owned stand-ins were terminated; stage metrics were 9 success, 0 blocked, 0 error. |
| 3 — svchost Injection | **Blocked (126)** | Starting the test-owned `svchost.exe` returned Windows error 5 before `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, or `CreateRemoteThread` executed. Sophos System Protection event 42 identified the target as `Evade_22a (T1036.005)`. |
| 4 — LSASS Access | **Blocked (126)** | `OpenProcess` against LSASS PID 748 returned `ERROR_ACCESS_DENIED` with administrator context and SeDebugPrivilege enabled. No handle was granted and no memory was read. |
| 5 — Minimal Impact | Success (0) | Five synthetic files were encrypted with no denial/failure; `vssadmin` and `bcdedit` returned only their designed nonexistent-target failures. |

`bundle_results.json` records **five controls: two blocked, three succeeded, zero skipped**. Final structured messages use Schema-compatible levels and pass the repository's Schema v2.0 validator. Sophos event evidence is retained in `staging/8f68dda1-94be-430f-8f35-d8af3f9b5d2e/sophos_application_events.txt`.

Cleanup verification: both `qilin_rwdrv_f0` and `qilin_hlpdrv_f0` were absent, Sophos services remained running, test-owned descendants and sandbox artifacts were removed, and pre-existing lab logs and driver files were restored.

## Execution-Context Fidelity

The primary emulation context is an **elevated post-compromise administrator or SYSTEM process**, especially for service creation, SeLoadDriverPrivilege, SeDebugPrivilege, and LSASS access. Stages 1, 3, and 5 contain primitives that can execute in a standard-user context, while stage 2's service/native-load objectives and stage 4's privileged LSASS request may be denied as baseline OS behavior.

The source detects admin/SYSTEM state using `net session` and `USERNAME`, opens the current process token, and checks `ERROR_NOT_ALL_ASSIGNED`. These checks prevent a standard-user access denial from being mislabeled as EDR prevention. They do **not** create separate user-context and elevated-context attack branches, so 2d remains 0.5. No user/admin/SYSTEM lab matrix has been run.

## Stage Timeout Budgets and Watchdog Behavior

The orchestrator configures a 1,200,000 ms (20-minute) execution envelope. Sequential per-stage ceilings total 19 minutes, leaving approximately one minute for extraction, fixed sleeps, snapshots, and finalization. Values below are source-configured maxima, not observed durations.

| Stage | Technique | Configured budget | Operations covered by the budget |
|---|---|---:|---|
| 1 | T1518.001/T1082 | **180 s** | Four discovery commands, file copies, child launch, 3-second observation sleep, 750 ms loaded interval, marker check |
| 2 | T1562.001/T1211 | **360 s** | Driver observation, service operations, privilege/native-load calls, callback JSON generation, device probe, three stand-in lifecycles |
| 3 | T1055 | **240 s** | Target launch, cross-process allocation/write/thread, 10-second remote-thread wait, cleanup |
| 4 | T1003.001 | **180 s** | Privilege adjustment, Toolhelp process discovery, LSASS open/close |
| 5 | T1490/T1486 | **180 s** | Synthetic file generation/encryption, two fail-harmless recovery commands, cleanup |

For each stage, `context.WithTimeout` and `exec.CommandContext` bound `cmd.Run()`. On deadline expiry, the orchestrator logs `Stage <n> watchdog timeout after <budget>`, records process exit 102 with `watchdog timeout`, captures output, and marks that stage as an error. Later stages are still attempted. If no stage has positive block evidence, the final result is 999; any positive block takes precedence and produces overall 126. The implementation does not emit a literal `unexpected_hang` bundle status.

A watchdog kill terminates the stage process, so its deferred cleanup cannot be relied on for that path. The orchestrator therefore deletes both test driver services, terminates only exact test-owned descendant paths, removes the Qilin sandbox, and deletes stand-in/driver files after stages 2 and 3 and again during finalization. Normal finalization writes post-state, merges persisted stage messages, logs and bundles results, sleeps two seconds, and calls `Endpoint.Stop`; panic finalization uses the same cleanup/finalization path. The final lab run completed finalization within the 30-second criterion.

## Operational Hygiene and Binary Size Justification

- **Orchestrator:** 11,043,664 bytes (10.5 MiB), Yellow tier, satisfying the v2.1 <25 MB threshold.
- **Why this size is justified:** five independently executable signed Go stages carry native injection/BYOVD code and the shared Schema v2.0 logger; the BYOVD stage also embeds the real 18,688-byte `rwdrv.sys` signature-observation asset. Keeping the stages independent preserves detection coverage when one objective is blocked.
- **Compression/signing:** `build_all.sh` uses ordinary Go `-ldflags="-s -w"` symbol/debug stripping, signs and verifies each stage, applies mandatory `gzip -9`, embeds the compressed stages, and signs/verifies the orchestrator. No packer is used; extracted stages remain signed.
- **Stage-size criterion met:** all signed stages are approximately 3.2–3.4 MB, below the 5 MB threshold. Size was measured after compilation and before gzip embedding, with Authenticode signing and verification completing successfully.
- **Output hygiene:** stage stdout/stderr is both streamed and captured to `C:\F0\<stage>_output.txt`; extraction errors continue; pre/post snapshots and bundle fan-out are written on normal finalization.
- **Signing verification:** local digest verification passed for every stage and the orchestrator. The F0RT1KA certificate was found in the target's LocalMachine Root store before deployment. Windows `Get-AuthenticodeSignature` also reported the known self-signed basic-constraints warning; this was recorded rather than misclassified as a detection.

## Expected Results

| Scenario | Stage / overall result | Interpretation |
|---|---|---|
| All stages return 0 | Stage 0 normalized to 101 in bundles; overall **101** | Objectives completed without positive prevention; not the observed lab outcome |
| Stage binary disappears before launch | Stage **105**, overall **126** | `os.Stat` supplies quarantine evidence |
| Protection refuses a fresh stage/operation | Stage **126**, overall **126** | Numeric Windows/NTSTATUS evidence and context checks support a block |
| Stage is quarantined during execution | Stage **127**, overall **126** | Recognized as protection by the orchestrator; later stages continue |
| Stage exceeds its budget | Stage **102**, then overall **999** unless any other stage blocks | Watchdog timeout is an execution error, not a protection claim |
| Extraction, prerequisite, or inconclusive OS failure | Stage **999**, overall **999** unless any other stage blocks | Ambiguous/benign failures are not mapped to prevention |
| One stage blocks and another errors | Overall **126** | The orchestrator's any-blocked branch has priority; inspect per-stage bundles |

Positive evidence is required for 105/126/127. Access denied in a non-elevated context or after a failed privilege assignment is treated as inconclusive, not as an EDR block.

## References

See [`8f68dda1-94be-430f-8f35-d8af3f9b5d2e_references.md`](8f68dda1-94be-430f-8f35-d8af3f9b5d2e_references.md) for full source provenance, supporting reporting, the local design brief, and official MITRE ATT&CK mappings.
