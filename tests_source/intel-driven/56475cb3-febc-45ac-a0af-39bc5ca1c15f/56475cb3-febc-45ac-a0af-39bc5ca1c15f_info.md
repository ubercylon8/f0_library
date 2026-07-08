# 3CX 3CXDesktopApp Cascading Supply-Chain Compromise

## Test Information

**Test ID**: 56475cb3-febc-45ac-a0af-39bc5ca1c15f
**Test Name**: 3CX 3CXDesktopApp Cascading Supply-Chain Compromise
**Category**: intel-driven / supply-chain
**Severity**: Critical
**Complexity**: Medium
**Threat Actor**: Lazarus / UNC4736 (DPRK)
**MITRE ATT&CK**: T1195.002, T1574.002, T1497, T1027.003, T1071.001, T1555.003
**Architecture**: Multi-stage (orchestrator + 4 gzip-embedded, individually-signed stage binaries)
**Rubric version**: v2.1 (tiered, realism-first; signal-quality-not-tenant-defense)

## Description

In March 2023, Mandiant and CrowdStrike disclosed that the 3CX VoIP desktop client (`3CXDesktopApp`) had been trojanized in a supply-chain attack ultimately traced back to **UNC4736 (Lazarus Group, DPRK)**. The compromise was notable as the first publicly documented instance of a supply-chain attack *cascading* into a second one: a trojanized build of Trading Technologies' X_TRADER software (an earlier North Korean supply-chain compromise) infected a 3CX employee's workstation, and the stolen credentials/access were used to trojanize 3CX's own build pipeline. The resulting malicious `3CXDesktopApp.exe` — a validly, legitimately signed binary — side-loaded a malicious `d3dcompiler_47.dll`, which in turn loaded shellcode appended to a bundled `ffmpeg.dll`. The implant fingerprinted the host for VM/sandbox artifacts, stayed dormant for roughly 7 days, then fetched icon (`.ico`) files from `raw.githubusercontent.com/IconStorages/images` and read an AES-encrypted C2 configuration hidden in bytes appended after the legitimate icon image (documented in detail by Volexity as the "Iconic" incident). Later-stage payloads (including the ICONIC/Gopuram-family stealer) harvested browser credential stores.

This test reproduces the **observable primitives** of that kill chain end-to-end as a 4-stage orchestrated simulation, with every destructive, credential-touching, or truly-C2-capable element replaced by a safe stand-in:

- **Stage 1 (T1574.002)** — the "trusted signed vendor app" role is played by a copy of our own F0RT1KA-signed stage binary (written as `3CXDesktopApp.exe`, Authenticode signature preserved by the byte copy) in a user-writable `ARTIFACT_DIR` app path. Real, benign, Microsoft-signed system DLLs are planted beside it under the real side-load companion names (`d3dcompiler_47.dll` copied verbatim; `winmm.dll` copied as `ffmpeg.dll`), and the signed parent is relaunched in a host mode where it `LoadLibrary`s those companions **from its own directory** — emitting a genuine image-load event (signed `3CXDesktopApp.exe` loading a companion DLL from a user-writable path). The suspicious property is the path and loader identity, not the DLL contents, so no malicious code is ever loaded.
- **Stage 2 (T1497)** — read-only VM/sandbox fingerprinting (BIOS/disk/guest-service registry keys, CPU count, `GetTickCount64` uptime, domain-join inference) and a logged-but-compressed 7-day dormancy.
- **Stage 3 (T1027.003 + T1071.001)** — a real, benign DNS lookup and HTTPS GET shaped exactly like the IOC URL (`raw.githubusercontent.com/IconStorages/images/main/icon0.ico`), producing authentic TLS/DNS egress telemetry with the response body discarded and never used. The steganographic second stage is materialized locally: a real on-disk `.ico` with a valid `ICONDIR`/`ICONDIRENTRY` header and AES-256-CBC ciphertext appended after the legitimate icon image, then decoded (parse header → locate appended region → AES-decrypt) into a benign JSON C2 descriptor that lists real reported 3CX C2 domains (never contacted).
- **Stage 4 (T1555.003 + T1217)** — decoy Chrome/Edge/Brave/Firefox credential/history stores are pre-staged under `ARTIFACT_DIR` in the exact real relative path layout, then enumerated and copied into a collection buffer — exercising the ICONIC stealer's rapid multi-browser access pattern against decoys only. Real profile paths (`%LOCALAPPDATA%`/`%APPDATA%`) are logged as discovery targets (T1217) but never opened.

## Test Score: 7.6/10

### Score Breakdown (Rubric v2.1)

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `ARTIFACT_DIR` (`c:\Users\fortika-test`) or `LOG_DIR` (`C:\F0`). No write/delete/lock/reparse intent against real system targets. The real-system reads are `os.ReadFile` on `C:\Windows\System32\d3dcompiler_47.dll` and `winmm.dll` (read-only), which Stage 1 then `LoadLibrary`s from a user-writable path — both are Microsoft's own signed, benign DLLs (no malicious module is ever loaded). No COM activation, service creation, driver load, or token/privilege manipulation. Network egress is real but benign: DNS + HTTPS GET to `raw.githubusercontent.com` (a real, legitimate GitHub CDN host, not attacker infrastructure), response body discarded and never used as a payload or C2 channel — consistent with this repo's established pattern for T1071.001 stages (see e.g. `e5472cd5-c799-4b07-b455-8c02665ca4cf`). Stage 1/4 decoys are cleaned up via `os.RemoveAll` on the success path; **note** — on an error/quarantine exit the decoy cleanup step is skipped (flagged below, does not disqualify: decoys never leave the sandboxed `ARTIFACT_DIR` and contain only benign sentinel content). |
| **2a** | API Fidelity (0–2.5) | **2.0** | Stage 1 now emits a **genuine** side-load image-load event: a F0RT1KA-signed `3CXDesktopApp.exe` (a copy of the signed stage binary) calls `syscall.LoadLibrary` on real companion DLLs planted in its own user-writable directory (`d3dcompiler_47.dll`, `ffmpeg.dll`), so `DeviceImageLoadEvents`/Sysmon EID 7 fire by construction — matching the real trojanized `3CXDesktopApp.exe` behavior (a signed vendor process loading a companion DLL from a non-standard path), the only difference being the loaded DLL is Microsoft's own benign binary rather than a payload. Stage 2 (registry `QUERY_VALUE` reads + `GetTickCount64`) and Stage 3 (real `net.LookupHost` + `http.Client.Do` + manual `ICONDIR`/`ICONDIRENTRY` binary parsing + `crypto/aes`/`crypto/cipher` CBC) closely match the documented PoC API surface. The remaining dock is Stage 4, which abstracts the real ICONIC mechanism (SQLite query against `Login Data` + DPAPI `CryptUnprotectData` decrypt) down to a plain file copy — documented under Improvement Opportunities. |
| **2b** | Identifier Fidelity (0–1.5) | **1.2** | Identifiers are hard-coded but highly accurate: real side-load filenames (`3CXDesktopApp.exe`, `d3dcompiler_47.dll`, `ffmpeg.dll`), the real IOC URL path (`IconStorages/images/main/icon0.ico`), a realistic `User-Agent` (`3CXDesktopApp/18.12.416`), the real reported 3CX C2 domains (`msstorageazure.azureedge.net`, `azureonlinestorage.azurefd.net`, `officeaddons.azureedge.net`) embedded in the benign decoded descriptor, and the exact real relative browser-store paths (`Google\Chrome\User Data\Default\Login Data`, `Mozilla\Firefox\Profiles\...\key4.db`, etc.). Not runtime-extracted from the live system (no dynamic real-target discovery), which caps this below the 1.5 ceiling. |
| **2c** | Telemetry Signal Quality (0–2.0) | **1.3** (capped ≤1.5 — no lab run yet) | Criterion 1 (signal richness) ✅ — every stage emits an identifiable signal in its native telemetry surface (image/file-drop events, registry reads, DNS/TLS egress, AES-decrypt of appended ICO data, rapid multi-browser file reads). Criterion 2 (sensor mapping) ✅ — see Detection Opportunity Audit below; `56475cb3-febc-45ac-a0af-39bc5ca1c15f_detections.kql` (6 queries) and `56475cb3-febc-45ac-a0af-39bc5ca1c15f_rules.yar` (4 rules) are cross-referenced per primitive. Criterion 3 (rule-artifact validity) **mostly met** — all 5 supported rule formats are present (`_detections.kql`, `_rules.yar`, `_sigma_rules.yml`, `_elastic_rules.ndjson`, `_dr_rules.yaml`) and are well-formed on manual review (correct KQL/Sentinel Advanced Hunting, YARA, Sigma, Elastic EQL, and LimaCharlie D&R syntax); the only gap is that they were not run through an automated linter/YARA compiler in this session. Criterion 4 (lab execution) ❌ — not yet run end-to-end on an instrumented sensor stack; no `bundle_results.json`/`test_execution_log.json` lab artifacts exist yet. Per the v2.1 hard cap, this sub-score cannot exceed 1.5 until lab execution is verified; scored below the cap given criterion 3's partial state and criterion 4 being fully unmet (as opposed to met-via-documented-exception). |
| **2d** | Execution-Context Fidelity (0–1.0) | **0.5** | The test does not branch behavior by execution context (no `IsAdmin()`/SYSTEM detection gating any stage), but this is genuinely acceptable here: every primitive (registry `QUERY_VALUE` reads, file writes under user-owned `ARTIFACT_DIR`/`LOG_DIR`, process launch, HTTPS GET) works identically and realistically under standard-user, admin, or SYSTEM context — matching the real 3CX/ICONIC chain, which also runs entirely in whatever context the desktop app/user session provides and never attempts privilege escalation. No context-dependent crash or unrealistic-telemetry risk identified. |
| **3a** | Schema & Metadata (0–1.0) | **1.0** | Schema v2.0 `InitLogger` with full `TestMetadata` (`RubricVersion: "v2.1"`) + `ExecutionContext` using `orgInfo.UUID` (not a short name). Metadata header complete in the main `.go` file. Stage and orchestrator binaries dual-signed via `build_all.sh`'s standard 8-step sequence. |
| **3b** | Documentation Completeness (0–1.0) | **1.0** | README + this info card (with Score Breakdown table) + `56475cb3-febc-45ac-a0af-39bc5ca1c15f_references.md` all present. Score format validated against `utils/validate-score-format.sh` conventions. MITRE mapping cites official technique + sub-technique IDs for all 6 techniques. |
| **3c** | Logging & Plumbing (0–0.5) | **0.25** | `test_logger.go` v2.0 + per-stage `WriteStageBundleResults()` fan-out to `bundle_results.json` are wired in the orchestrator. No pre/post `56475cb3-febc-45ac-a0af-39bc5ca1c15f_system_snapshot_{pre,post}.json` (Defender status, AV exclusions, hotfixes) are captured — consistent with the fact that this snapshot pattern is not yet implemented anywhere in this repo (including `sample_tests/multistage_template/`), not a regression specific to this test. |
| **3d** | Operational Hygiene (0–0.5) | **0.35** | Orchestrator **13.62 MB** ✅ (< 25 MB Yellow-tier ceiling; see Size Justification below). Stage binaries: T1574.002 (3.39 MB), T1497 (3.19 MB), T1555.003 (3.21 MB) are all comfortably < 5 MB; **T1027.003 measures 7.65 MB unsigned/uncompressed** (exceeds the 5 MB per-stage guideline) because it statically links `net/http` + `crypto/tls` — partial credit only for this row. Per-stage execution-time budgets are now documented below ✅. No watchdog goroutine (`time.AfterFunc` or equivalent) wraps any stage's `cmd.Run()` in the orchestrator, and Stage 3's only internal timeout is the 6s `http.Client.Timeout` on its HTTPS GET — a genuinely hung stage (e.g., a stalled DNS resolution with no OS-level timeout) could block the orchestrator indefinitely ❌. In normal operation `Endpoint.Stop()` follows the final `SaveLog()` immediately with no artificial delay ✅. |
| | **Total** | **7.6 / 10** | Realism: 5.0 / 7.0 (API 2.0, Identifier 1.2, Telemetry 1.3, Exec-Context 0.5). Structure: 2.6 / 3.0. **Good** tier (6.0–7.9). Computed total now meets the v2.1 ship gates (Realism ≥ 5.0, Total ≥ 7.5) on test-property grounds — but the telemetry-signal-quality sub-score (2c) remains capped pending the lab detonation (below), which is the outstanding item to confirm the now-guaranteed image-load and the other stage signals actually fire on an instrumented sensor stack. |

### Stage Timeout Budgets (v2.1 §3d Operational Hygiene)

No watchdog currently enforces these — they are the *expected* per-stage runtimes under normal (non-hung) execution, useful for sizing a future watchdog and for PA timeout configuration.

| Stage | Technique | Expected runtime | Dominant cost |
|---|---|---|---|
| 0 | Binary extraction (all 4 stages) | ~2 s | Gzip decompression + `os.WriteFile` + 1.5 s quarantine-detection sleep per stage |
| 1 | T1574.002 | ~8 s | 3 s post-stage detection sleep + 4 s post-launch reaction window + process kill/wait |
| 2 | T1497 | ~3 s | Fixed 3 s compressed-dormancy sleep (registry/uptime/domain checks are near-instant) |
| 3 | T1027.003 / T1071.001 | ~8–10 s | HTTPS GET (bounded by 6 s `http.Client.Timeout`) + 2 s detection-window sleep + AES decode (near-instant) |
| 4 | T1555.003 | ~2 s | 2 s post-staging detection sleep; decoy I/O is near-instant |

Total unprotected end-to-end runtime: **~25–35 s** (includes 2 s inter-stage pauses ×3), well within the `medium` complexity band (30 s–5 min).

## Size Justification

Final orchestrator size: **13.62 MB (14,282,576 bytes) — Yellow tier (10–25 MB)**.

This is normal and expected for a gzip-embedded, 4-stage Go multi-stage test:

- The orchestrator embeds **4 standalone, individually F0RT1KA-signed stage PEs** (`T1574.002`, `T1497`, `T1027.003`, `T1555.003`), each a full Go-runtime binary in its own right — Go's static runtime linking means every embedded stage carries its own ~2 MB+ baseline regardless of how small the stage-specific logic is.
- Stage `T1027.003` additionally statically links `net/http` + `crypto/tls` (for the real DNS+HTTPS egress to `raw.githubusercontent.com` that produces genuine TLS/DNS telemetry) and `crypto/aes`/`crypto/cipher` (for the AES-256-CBC stego decode) — this stage alone is ~7.65 MB unsigned before compression, the largest of the four.
- Gzip compression (`build_all.sh` step 4, `gzip -9`) is wired and reduces the embedded payload by roughly 35%, consistent with the CLAUDE.md-documented pattern.
- This sits well under the ~20 MB reference implementation for 6-stage tests (`tests_source/intel-driven/13c2d073-8e33-4fca-ab27-68f20c408ce9/`), and far under the 25 MB Yellow ceiling.

No refactor is required. If future work wants to shrink further, the highest-leverage change is trimming `net/http`'s transitive dependency surface in stage 3 (e.g., a minimal raw-TLS DNS+GET implementation instead of the full `net/http` client), but this is not necessary at the current size.

## Technical Details

### Attack Flow

1. **Phase 0 — Stage Binary Extraction**: The orchestrator (playing 3CXDesktopApp's role as the trusted, F0RT1KA-signed "vendor app") decompresses and writes all 4 gzip-embedded stage binaries to `C:\F0`, verifying each survives a 1.5 s quarantine-detection window via `os.Stat`.
2. **Stage 1 — DLL Side-Loading (T1574.002)**: Copies this F0RT1KA-signed stage binary to `ARTIFACT_DIR\3CXDesktopApp\app\3CXDesktopApp.exe` (the signed-parent stand-in, Authenticode signature preserved), plants real Microsoft-signed system DLLs beside it under the companion names (`C:\Windows\System32\d3dcompiler_47.dll` copied verbatim; `winmm.dll` copied as `ffmpeg.dll` — both valid, loadable, benign PEs in the wrong path), waits 3 s for a protection reaction and checks for quarantine via `os.Stat`, then relaunches the signed parent with `--sideload-host` so it calls `syscall.LoadLibrary` on the planted companions from its own directory (`cmd.Dir = appDir`) — emitting the genuine side-load image-load event. The child's load results are captured and logged; an OS-emitted "access is denied" on the load or a planted DLL disappearing during the load is classified as a block (Rule 8), otherwise the staged directory is cleaned up.
3. **Stage 2 — Sandbox/Dormancy Evasion (T1497)**: Read-only registry queries for BIOS/disk/guest-service VM artifacts (`HARDWARE\DESCRIPTION\System\BIOS`, `SYSTEM\CurrentControlSet\Services\Disk\Enum`, `VBoxGuest`/`vmtools`/`vmci` service keys), `runtime.NumCPU()`, `kernel32!GetTickCount64` uptime, and `USERDNSDOMAIN`/`USERDOMAIN` domain-join inference. Logs the intended 604,800 s (7-day) dormancy, sleeps 3 s.
4. **Stage 3 — Steganographic C2 Config (T1027.003 + T1071.001)**: Real `net.LookupHost("raw.githubusercontent.com")` DNS lookup, then a real HTTPS GET (`User-Agent: 3CXDesktopApp/18.12.416`) to `https://raw.githubusercontent.com/IconStorages/images/main/icon0.ico` — body discarded after 4096 bytes. Builds a real `.ico` locally (valid `ICONDIR`/`ICONDIRENTRY` + 64 bytes of icon pixel data) with AES-256-CBC ciphertext of a benign JSON descriptor appended after the legitimate icon region, writes it to `LOG_DIR\stego\icon0.ico`, waits 2 s, reads it back, parses the header to locate the appended region, AES-decrypts it, and writes the decoded benign config to `LOG_DIR\stego\decoded_config.json`.
5. **Stage 4 — Credentials from Web Browsers (T1555.003 + T1217)**: Logs the real canonical browser credential-store paths (`%LOCALAPPDATA%\...`) as discovery targets (never opened), then pre-stages 9 decoy files (Chrome `Login Data`/`Web Data`/`History`/`Cookies`, Edge `Login Data`/`History`, Brave `Login Data`, Firefox `logins.json`/`key4.db`) under `ARTIFACT_DIR\browser_profiles\` in the real relative layout. Waits 2 s, then enumerates and reads all 9 decoys into `LOG_DIR\collection\`, mirroring the ICONIC stealer's rapid cross-browser access pattern. Cleans up both the decoy tree and the collection buffer on completion.

### Key Indicators

- File system changes: `3CXDesktopApp.exe` + `d3dcompiler_47.dll` + `ffmpeg.dll` dropped together in a non-`Program Files` path; `.ico` file with data trailing past its declared icon-image region; 9 browser-credential-store-named files created outside a real browser's own write path
- Process creation events: signed stand-in binary launched with `cmd.Dir` set to its own artifact directory (not its install location)
- Network communications: DNS resolution + HTTPS GET to `raw.githubusercontent.com` for a `.ico` resource, from a non-browser process, with a desktop-app-shaped `User-Agent`
- Registry access: sequential reads of BIOS/disk-enum/hypervisor-guest-service keys by a non-`C:\Windows` process
- File access patterns: rapid sequential reads of `Login Data`/`Web Data`/`Cookies`/`logins.json`/`key4.db` across 4 different browser vendor directories by a single process

## Detection Opportunities

6 distinct detection points, each mapped to a rule artifact bundled with this test:

1. **Signed vendor app side-loading a non-system DLL** (T1574.002) — `56475cb3-febc-45ac-a0af-39bc5ca1c15f_detections.kql` Query 1 (`DeviceImageLoadEvents` filtered to `d3dcompiler_47.dll`/`ffmpeg.dll` loaded from a user-writable path) and `56475cb3-febc-45ac-a0af-39bc5ca1c15f_rules.yar` rule `ThreeCX_Sideload_Companion_DLL_Names`.
2. **Generic signed-binary side-load from its own writable directory** (T1574.002) — KQL Query 2, a broader hunt for any code-signed EXE loading a non-Microsoft DLL from the same writable folder it runs from.
3. **Steganographic ICO retrieval / appended high-entropy payload** (T1027.003 / T1071.001) — KQL Query 3 (`.ico` fetch from `raw.githubusercontent.com`/GitHub CDNs by a non-browser process) and YARA rule `ICO_Steganography_Appended_Encrypted_Payload` (flags an ICO file meaningfully larger than its declared icon-image region).
4. **Non-browser process reading multiple browser credential stores** (T1555.003 / T1217) — KQL Query 4 (cross-browser-family file access correlation) and YARA rule `Browser_Credential_Store_Stealer_Targets` (references 3+ browser-family paths plus a login/key-store filename).
5. **Sandbox/VM fingerprinting via registry firmware reads** (T1497) — KQL Query 5 and YARA rule `Sandbox_Evasion_Fingerprint_Strings`.
6. **Multi-stage correlation** (T1195.002 + T1574.002 + T1555.003) — KQL Query 6 joins a side-load event and a credential-store access event on the same device within a 30-minute window, surfacing the full cascading-chain pattern as a single high-confidence detection.

## Expected Results

### Unprotected System (Code 101)

All 4 stages complete: signed stand-in launched with side-load-shaped companions present, sandbox/dormancy checks logged, ICO stego config decoded, and decoy browser stores collected. `Endpoint.Unprotected` (101) — the endpoint has no effective detection across any stage of the kill chain.

### Protected System

- **Code 105** (`Endpoint.FileQuarantinedOnExtraction`): A stage binary or a staged artifact (e.g., the side-load companion DLLs, the stego `.ico`, or a decoy credential store) is confirmed removed via `os.Stat` after being written — positive quarantine evidence.
- **Code 126** (`Endpoint.ExecutionPrevented`): A protection layer blocks execution at a specific stage (an OS-emitted access denial on an operation that normally succeeds in this context) — the orchestrator reports exactly which stage (1–4) was blocked and how many stages completed before interception.
- **Code 999** (`Endpoint.UnexpectedTestError`): A prerequisite wasn't met or an ambiguous/benign failure occurred (e.g., `ARTIFACT_DIR` not provisioned, offline-lab DNS/HTTPS failure) — never classified as a block per Bug Prevention Rule 8.

## Improvement Opportunities (score < 9.0)

- **Confirm Stage 1's DLL-load telemetry in a lab run.** Stage 1 now forces a real load — the signed `3CXDesktopApp.exe` copy calls `syscall.LoadLibrary` on the planted `d3dcompiler_47.dll`/`ffmpeg.dll` from its own directory, so an image-load event fires by construction. The remaining verification is to confirm on an instrumented sensor stack (the `win` lab) that `DeviceImageLoadEvents`/Sysmon EID 7 actually records these loads with the expected path and signer fields, which would clear criterion 4 and uncap the 2c telemetry-signal-quality sub-score. A deeper future refinement would be a host with a static import-table dependency (requires a mingw/cgo build toolchain not currently available) for passive search-order resolution rather than an explicit `LoadLibrary`.
- **Lift Stage 4 API fidelity** by exercising a SQLite-shaped read (`SELECT` against the decoy `Login Data` file structure) and/or a DPAPI `CryptUnprotectData` call against a decoy blob, rather than a plain file copy — this would move Stage 4 closer to the real ICONIC mechanism and lift 2a.
- **Run this test end-to-end on an instrumented sensor stack** (LimaCharlie + Defender + Sysmon per the framework's lab convention) to clear the 2c Telemetry Signal Quality lab-execution criterion and remove the 1.5/2.0 cap.
- **Add a per-stage watchdog goroutine** (`time.AfterFunc`) around each `cmd.Run()` in the orchestrator, sized to the documented budgets above, to close the 3d Operational Hygiene gap and harden against a genuinely hung stage.
- **Add pre/post system snapshots** (`56475cb3-febc-45ac-a0af-39bc5ca1c15f_system_snapshot_{pre,post}.json`: Defender status, AV exclusions, hotfixes) to close the 3c Logging & Plumbing gap.
- **Expand rule-format coverage** beyond KQL + YARA to include Sigma, Elastic EQL, and LimaCharlie D&R for broader sensor-stack applicability, and validate all rule artifacts with `yara -c` / `sigma-cli validate` / `yamllint` in a session with those tools available.
- **Reduce Stage 3's binary size** below 5 MB if feasible without losing the real `net/http`+`crypto/tls` egress fidelity that produces genuine TLS/DNS telemetry (not required to ship — current size is justified).

## References

See [`56475cb3-febc-45ac-a0af-39bc5ca1c15f_references.md`](56475cb3-febc-45ac-a0af-39bc5ca1c15f_references.md) for full source provenance, supporting resources, and related advisories.
