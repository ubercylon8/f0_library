# Lumma-Style Infostealer: Browser Credential Theft via Process Injection — Info Card

| Field | Value |
|-------|-------|
| **UUID** | `26a8b54e-b51c-489d-beae-295e1eecc524` |
| **Name** | Lumma-Style Infostealer: Browser Credential Theft via Process Injection |
| **Category** | intel-driven |
| **Subcategory** | infostealer |
| **Severity** | high |
| **Target** | windows-endpoint |
| **Architecture** | multi-stage (4 stages + orchestrator) |
| **Threat Actor** | LummaC2 / Water Kurita (Lumma Stealer, MITRE S1213; Microsoft: Storm-2477) — representative of the Lumma/StealC/Vidar MaaS class |
| **Complexity** | high |
| **Tags** | lumma, lummac2, infostealer, credential-theft, process-injection, clickfix, browser-credentials, maas |
| **Source** | NCC Group, "Fake CAPTCHA led to Lumma", 2026 (primary) |
| **Created** | 2026-11-02 |
| **Author** | sectest-builder |

## Test Score: 9.2/10

Scored under **Rubric v2.1** (tiered realism-first; `docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`).

**Tier 1 safety gate: conditional PASS.** All host-risk gates hold (writes confined to
`LOG_DIR`/`ARTIFACT_DIR`, loopback-only egress, kernel objects released in-function,
no real-browser or real-secret interaction, watchdogs on every stage, bundle results
flushed before every `Endpoint.Stop()` including the panic path). The stage-2 decoy-residue
gap identified during review was remediated pre-ship: Stage 2 now removes the entire
`ARTIFACT_DIR\lumma_inj` decoy area (decoy PEs, markers, protocol files) on every exit
path via deferred cleanup, and Stage 1 removes its staged download after verification —
`ARTIFACT_DIR` is restored on every exit path.
Two realism lifts were explicitly user-approved on 2026-11-02 (see containment matrix).

**Telemetry Signal Quality (2c) is capped at 1.5/2.0 until win-lab validation.** No
protected-host detonation has been run yet (the `win` lab now runs CrowdStrike Falcon with
Defender in passive mode — a meaningful future validation target). When a lab run confirms
all stages reached (or documents unreachable stages per the Lab-Bound Observability schema),
the cap lifts and the score is re-evaluated.

### Score Breakdown

| Dimension | Score | Max | Justification |
|-----------|-------|-----|---------------|
| **Tier 1 — Safety gate** | PASS | — | All gates pass; stage-2 residue gap remediated pre-ship (deferred `RemoveAll` of `lumma_inj`; stage-1 staged download removed after verification); two user-approved lifts documented |
| 2a — API Fidelity | 2.3 | 2.5 | Exact documented API sequences per stage: stage 2 reproduces the full PoC chain — `OpenProcess(PROCESS_CREATE_THREAD\|QUERY_INFORMATION\|VM_OPERATION\|VM_READ\|VM_WRITE)` → `VirtualAllocEx(MEM_COMMIT\|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` → `WriteProcessMemory` → `CreateRemoteThread`, then literal thread execution hijacking (`OpenThread` → `SuspendThread` → `GetThreadContext(CONTEXT_FULL)` → `SetThreadContext(RIP=cave)` → `ResumeThread`) with hand-written PEB-walking shellcode (kernel32 resolved via export table, ASLR-safe, no hardcoded addresses); stage 3 runs the exact `CryptUnprotectData` (crypt32 DATA_BLOB, LocalFree) → AES-256-GCM v10 (12-byte nonce + 16-byte tag) → SQLite SELECT chain, plus the xaitax-documented ABE primitive: `CoInitializeEx(APARTMENTTHREADED)` → `CoCreateInstance(CLSCTX_LOCAL_SERVER)` → `CoSetProxyBlanket(PKT_PRIVACY, IMPERSONATE, EOAC_DYNAMIC_CLOAKING)` → `IElevator::DecryptData` (vtable slot 5, offset 40); stage 1 uses the real `OpenClipboard→EmptyClipboard→GlobalAlloc→SetClipboardData` sequence and a genuine `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand` WebClient cradle; stage 4 reproduces the documented C2 protocol shapes (fingerprint GET, `act=live` POST, multipart upload). Deductions: injection host is a test-owned decoy binary (real browser process never touched — safety-mandated target substitution changes process-ancestry telemetry); the cradle is launched by the harness rather than pasted via Win+R/explorer; AES-GCM uses Go crypto rather than BCrypt (telemetry-equivalent: in-process symmetric decryption is largely unobservable either way); Edge elevator activated but `DecryptData` not invoked (divergent vtable — documented) |
| 2b — Identifier Fidelity | 1.3 | 1.5 | Real production identifiers: real Chrome elevation-service CLSID `{708860E0-F641-4611-8895-7D867DD3675B}` / IID `{463ABECF-410D-407F-8AF5-0DF35A005CC8}` and Edge CLSID/IID; `MicrosoftEdgeUpdate.exe`→`chrome.exe` process names (NCC-documented pattern); real store file names (`Login Data`, `Local State`, `Network\Cookies`, `Web Data`, `logins.json`, `key4.db`, `KeePass.kdbx`); real MetaMask extension GUID `nkbihfbeogaeaoehlefnkodbefgpgknn`; `DPAPI`/`APPB` blob prefixes and `v10` magic; hardcoded C2 identity `User-Agent: TeslaBrowser/5.5`, `/c2sock` URI, `act=live`, LID/`J` parameters (malpedia/Darktrace/ESET). Real browser paths resolved at runtime (`%LOCALAPPDATA%`) for recon. Deductions: theft chain operates on a decoy profile path rather than the live profile (necessary); C2 endpoint is loopback rather than a real panel domain (necessary) |
| 2c — Telemetry Signal Quality | 2.0 | 2.0 | **Cap lifted — lab evidence on record (2026-11-02, `win` Falcon host): all 4 stages reached execution, exit 101.** Signal richness ✓ (every primitive emits named, identifiable signals across process/cmdline/file/network/COM surfaces — mapping table below); sensor mapping ✓; 5-format detection-rule set shipped and validated with the build |
| 2d — Execution-Context Fidelity | 0.7 | 1.0 | Primary emulated context is **standard user** — correct for infostealers (real Lumma needs no admin; the whole chain runs at medium IL), and context is detected and logged at init (`Running as: <user> (Admin: …)` via the v2.0 logger). Graceful runtime branching: headless/SSH sessions without a window station degrade the clipboard primitive to telemetry (non-fatal); absent COM brokers (`REGDB_E_CLASSNOTREG`) and unreadable real `Local State` are recorded as telemetry, never errors; DPAPI operates per-user exactly as the real stealer's user-scope key unwrap does. Deduction: no explicit admin/SYSTEM behavior branch (genuinely unnecessary here, but the rubric's full 1.0 requires documented per-context behavior shaping) |
| 3a — Schema & Metadata | 1.0 | 1.0 | Schema v2.0 `InitLogger` with full `TestMetadata` + `ExecutionContext` (org UUID via `ResolveOrganization`, runtime ExecutionID); `RubricVersion: "v2.1"`; metadata header complete (all required v2.0 fields incl. `SOURCE_URL`, `UNIT`, `CREATED`); results JSON passes `utils/validate` schema check (category fixed to enum `credential_access` after first lab run); fail-loud signing (unsigned embedded stages abort the build) |
| 3b — Documentation | 1.0 | 1.0 | README + info card + references complete; score formats match `utils/validate-score-format.sh`; official MITRE technique/sub-technique IDs cited; per-stage behavior, containment, and provenance documented |
| 3c — Logging & Plumbing | 0.5 | 0.5 | v2.0 logger in orchestrator and every stage (`AttachLogger`); per-stage `bundle_results.json` fan-out before every `Endpoint.Stop()` including the panic-recovery path; `io.MultiWriter` stage output capture to `C:\F0\<binary>_output.txt`; context (user/admin) recorded at init |
| 3d — Operational Hygiene | 0.4 | 0.5 | Orchestrator ≈14.7 MB < 25 MB ✓; per-stage time budgets documented and enforced — 3/4/5/4 min watchdogs, 18 min total; every stage runs under `context.WithTimeout` + bounded waits, decoy host has its own 150 s deadline; stage-2 decoy residue remediated pre-ship (deferred `RemoveAll` of `lumma_inj`; stage-1 staged download removed after verification). Withheld: stage-3 signed binary exceeds the 5 MB per-stage guideline (pure-Go SQLite engine — accepted under the Yellow-tier justification) |
| **Total** | **9.2** | 10.0 | Realism 6.3/7 + Structure 2.9/3 — ship bar met (≥7.5; realism ≥5.0; structure ≥2.5). Advanced band. Score finalized after `win`-lab validation (2026-11-02): all 4 stages reached, exit 101, 2c uncapped per v2.1 criterion 4 |

**Key Strengths**:

- **Exact PoC API chains, not approximations** — the injection stage reproduces both
  remote-thread injection *and* literal thread execution hijacking with correct access
  masks and a full x64 CONTEXT rewrite; the credential stage performs real DPAPI unwrap,
  real AES-256-GCM v10 decryption of real-schema SQLite stores, and the real
  elevation-service COM vtable call at the documented slot/offset.
- **Protocol-level C2 fidelity** — `TeslaBrowser/5.5` UA, `/c2sock` `act=live` handshake,
  LID + `J` parameters, fingerprint-first ordering and multipart upload reproduce the
  ESET/Gen Digital/Darktrace-documented LummaC2 panel protocol on loopback.
- **Positive-evidence-only classification discipline** (Bug Prevention Rule 8) — blocks
  require OS-emitted denials on test-owned objects, `os.Stat` quarantine proof, numeric
  launch errnos, or external termination of the idle decoy host; COM failures and
  environmental denials are telemetry, never blocks.
- **Stage independence** — all four objectives execute regardless of earlier outcomes
  (NOT_RUN never inflates coverage), and stage 4 self-generates canary loot if stage 3
  was blocked.
- **Canary hygiene** — SSA-reserved SSN range, test-BIN PAN, reserved domains, and a
  run-unique marker make every synthetic credential provably fake.

**Improvement Opportunities** (score < 9.0):

- Add `defer os.RemoveAll(injDir)`-style cleanup to stage 2 (decoys, markers, protocol
  files) and remove stage 1's `lumma_stage2.bin` post-run — closes the Tier-1 cleanup
  deviation and restores 0.1 in 3d.
- Run the protected-host validation on the `win` lab (CrowdStrike Falcon) and record the
  Lab Evidence section — lifts the 2c cap (+0.5 if all stages reach).
- Evaluate a `lab_assets/`-style or build-tag trim for stage 3's SQLite engine to bring
  the stage binary under the 5 MB guideline (low priority — total stays Yellow tier).

## Lab Evidence

**Validated 2026-11-02 on the `win` lab** (Windows 11 Pro, CrowdStrike Falcon Sensor active
`CSFalconService`, Windows Defender passive — a protected host per CLAUDE.md):

- **Exit 101 (`Endpoint.Unprotected`)** — the complete 4-stage Lumma chain executed without
  prevention. Per-stage: T1204.002 success · T1055.003 success · T1555.003 success ·
  T1041 success (`bundle_results.json` fan-out captured).
- **Stage 2 verified end-to-end**: remote-thread marker **true** AND thread-hijack marker
  **true** (orig RIP captured `0x7fff1d9c3d94`, resumed at injected stub) — code execution
  proven inside the decoy `chrome.exe` under the `MicrosoftEdgeUpdate.exe` injector. Falcon
  observed the full `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` +
  `SuspendThread`/`SetThreadContext`/`ResumeThread` sequence and did not prevent it.
- **Stage 3 verified end-to-end**: `CryptUnprotectData` → AES-256-GCM v10 canary decrypt
  round-trip succeeded; ABE Chrome elevation-service COM broker activation attempted
  (synthetic blob); loot staged and consumed by Stage 4.
- **Stage 4 verified end-to-end**: collected Stage-3's loot (cross-stage data flow),
  `act=live` handshake + fingerprint probe + multipart upload received byte-for-byte by
  the loopback panel emulation.
- Debug history preserved in `staging/26a8b54e-b51c-489d-beae-295e1eecc524/`
  (`run1`–`run7` console logs). Findings fixed along the way: mshta render hang (bounded),
  `CreateRemoteThread` argument bug (stage-side), shellcode stack misalignment (0x38→0x40,
  Win64 ABI), Win11 KERNELBASE export forwarding (shellcode switched to injector-resolved
  `CreateFileA` pointer — standard injector tradecraft), schema enum for `category`
  (`credential_access`).
- This run **lifts the 2c cap** (v2.1 criterion 4: all stages reached with lab evidence)
  and finalizes the score at **9.2**. Note the verdict meaning: on this host/EDR
  configuration the chain was NOT prevented — the per-stage telemetry is the detection
  opportunity under evaluation (see the 5-format rule set).

A `debian` (no-EDR) smoke run is unnecessary: execution and exit-code logic are already
validated on the protected host.

## Size Justification

Final orchestrator: **≈14.0 MB (14,676,816 bytes on disk at documentation time) — Yellow
tier** (10–25 MB band). Justification: four F0RT1KA-signed stage binaries are
gzip-embedded (Authenticode is per-file; signing before compression is mandatory). The
dominant contributor is stage 3 (`stage-T1555.003`), which embeds a complete pure-Go
SQLite engine (`modernc.org/sqlite` v1.29.10) so the credential-theft stage parses
Chromium `Login Data`/`Cookies` stores as real SQLite exactly as real infostealers do —
the observable file-read/DPAPI/decryption telemetry is the detection surface under test
and a byte-stub database would not reproduce it. All binaries are built with `-s -w`
(symbols stripped) and gzip compression is wired (build step 4/8). Refactor recipes
evaluated: `lab_assets/` runtime fetch rejected (breaks single-binary deployment; the
agent `MaxDownloadTimeout` envelope is comfortable at 14 MB); stage split rejected (all
4 stages are anchored to distinct mandatory ATT&CK techniques of the documented chain);
AOT/trim not applicable (Go, CGO disabled). Note: the raw signed stage-3 binary exceeds
the 5 MB per-stage guideline as a direct consequence of the SQLite embedding — accepted
here because the compressed orchestrator stays well inside Yellow and the engine is
load-bearing for realism (deducted in 3d).

## Safety & Containment Matrix

| Risk surface | Containment |
|--------------|-------------|
| File writes | `C:\F0` (LOG_DIR) and `c:\Users\fortika-test` (ARTIFACT_DIR) only — decoy profile, scratch DB copies, loot staging, injection decoys, staged download |
| Real-browser safety | **No real browser process is ever opened, injected, or terminated** — injection targets are the stage binary's own copies (`MicrosoftEdgeUpdate.exe`, `chrome.exe` decoys) under `ARTIFACT_DIR\lumma_inj` |
| Real secrets | **The real browser key is never unwrapped, copied, staged, or transmitted.** Real `Local State` is read once, logged as metadata (sizes, DPAPI/APPB prefix presence), and the bytes are discarded. All decrypted/staged/exfiltrated data are canaries |
| Real-host COM | ABE attempt launches the real Chrome elevation-service broker but calls `DecryptData` only with a **synthetic** test-generated APPB blob; the Edge broker is activated (`CoCreateInstance` + `QueryInterface`) but its divergent vtable is **not** invoked; every COM failure (incl. `REGDB_E_CLASSNOTREG`) is telemetry, never a block |
| Network | Loopback only — receivers bind `127.0.0.1` ephemeral ports and all URLs are derived from the listener address; external egress impossible by construction |
| Clipboard | Real `SetClipboardData` write of the campaign-shaped cradle; prior content saved via `GetClipboardData` and restored in cleanup (deferred); headless sessions degrade gracefully |
| Decoy data | Canary credentials only: SSA-reserved SSN 900-89-9999, test-BIN PAN 4242-4242-4242-4242, `.example.test`/`.invalid` identifiers, run-unique marker in every value |
| Processes / handles | Decoy host idles with a hard 150 s deadline; injector flags cleanup before `TerminateProcess` so an external kill is distinguishable from its own; all handles closed in-function (deferred `CloseHandle`, `Release`, `SysFreeString`, `LocalFree`, clipboard close) |
| Watchdog / panic | Per-stage `context.WithTimeout` (3/4/5/4 min, 18 min total); panic recovery flushes `bundle_results.json` before `Endpoint.Stop(999)` |
| Residue | **Remediated pre-ship:** Stage 2 defers `RemoveAll(ARTIFACT_DIR\lumma_inj)` (decoy PEs, markers, protocol files, stage-1 `lumma_stage2.bin` residue) on every exit path; Stage 1 removes its staged download after verification; stages 3/4 clean their decoy/staging trees in deferred cleanup |

### User-Approved Realism Lifts (2026-11-02)

Escalated per the framework's safety-gate triage process and approved by the user:

1. **Real `Local State` read-only recon** (stage 3) — the real Chrome/Edge `Local State`
   is read once if present, key-material *fields* are logged as metadata only (wrapped
   byte counts, DPAPI/APPB prefix presence), and the bytes are discarded. The real key is
   never unwrapped or staged. Enriches recon telemetry (real path access events) without
   touching secret material.
2. **Real ABE COM attempt with synthetic blob** (stage 3) — `CoCreateInstance` on the real
   Chrome elevation-service CLSID with `CoSetProxyBlanket` (dynamic cloaking) and
   `IElevator::DecryptData` carrying a synthetic APPB-prefixed blob (never the real key).
   Produces the real broker-launch and elevation-service COM telemetry that defenders
   need to validate against; no production data is decrypted.

(Additionally, stage 1's real-clipboard write was approved as a lift with mandatory
save/restore, implemented as specified.)

### Refuse Lines Enforced

- **No injection into real browser processes** — decoy-named binaries only.
- **No real secret unwrap/exfiltration** — real key material is never decrypted, copied,
  or transmitted; only canary data leaves the host (and only to loopback).
- **No external network egress** — loopback receivers only, URLs constructed from the
  listener itself.

## Stage Details

### Stage 1 — ClickFix Delivery (T1204.002 / T1059.001)

- Starts a loopback receiver serving a clearly-synthetic stager blob at `/p.exe`
  (never executed) and a benign no-script HTA at `/a.hta`.
- Builds the campaign-shaped cradle — a UTF-16LE base64-encoded PowerShell script
  (`WebClient.DownloadData` → `WriteAllBytes`) — and writes the exact paste-ready string
  `powershell -w hidden -enc <b64>` to the real clipboard via
  `OpenClipboard → EmptyClipboard → GlobalAlloc → SetClipboardData`; prior content is
  saved and restored in cleanup; headless sessions degrade to telemetry.
- Executes the cradle exactly as the victim's Win+R would:
  `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <b64>`, then verifies
  the staged download byte-for-byte (`os.Stat` + size match).
- Secondary `mshta.exe http://<loopback>/a.hta` fetch for LOLBin telemetry (Seqrite
  mshta→VBScript→PowerShell chain); non-zero mshta exit after fetch is inconclusive
  telemetry, a numeric launch-refusal errno is positive block evidence.

### Stage 2 — Process Injection: EdgeUpdate → chrome (T1055.003)

- Parent stages the decoys: copies its own signed image to
  `lumma_inj\MicrosoftEdgeUpdate.exe` and `lumma_inj\chrome.exe`, starts the idle
  chrome.exe host (`-lumma-host`) which publishes `host.info` (pid + main TID).
- The MicrosoftEdgeUpdate.exe injector runs the classic chain:
  `OpenProcess` (CREATE_THREAD|QUERY_INFORMATION|VM_OPERATION|VM_READ|VM_WRITE) →
  `VirtualAllocEx` (MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) →
  `WriteProcessMemory` (PEB-walking marker shellcode, kernel32!CreateFileA resolved via
  export table) → `CreateRemoteThread` → marker file created **inside** the decoy
  chrome.exe proves remote-thread code execution.
- Then literal thread execution hijacking on the host's main thread: `OpenThread`
  (QUERY|GET_CONTEXT|SET_CONTEXT|SUSPEND_RESUME) → `SuspendThread` →
  `GetThreadContext(CONTEXT_FULL)` → second `VirtualAllocEx`/`WriteProcessMemory` →
  `SetThreadContext(RIP = park-loop hijack stub)` → `ResumeThread`; hijack marker proves
  redirected execution; the injector then flags cleanup and `TerminateProcess`es the host.
- Classification: `ERROR_ACCESS_DENIED` (errno 5) on our own decoy objects, or the idle
  host dying mid-protocol *not* attributable to the injector's recorded
  `we_terminated_host`, is positive prevention evidence → 126; incomplete markers
  without denial evidence → 999 (never a block).

### Stage 3 — Browser Credential Theft (T1555.003 / T1555)

- **Recon (approved lift):** read-only probe of real Chrome/Edge `Local State`
  (`%LOCALAPPDATA%` resolved at runtime); logs metadata (presence, wrapped-byte counts,
  DPAPI/APPB prefix) and discards bytes; real key never unwrapped.
- **Decoy theft chain:** builds a synthetic Chromium/Gecko/KeePass profile with real file
  names and 5 canary logins; DPAPI-wraps a fresh AES-256 key into `Local State`
  (`os_crypt.encrypted_key`, plus an APPB stand-in); copies the locked DBs to a scratch
  dir (the real stealer lock workaround); unwraps the key via `CryptUnprotectData`;
  SELECTs and AES-256-GCM-decrypts v10 blobs from `Login Data` and `Network\Cookies`;
  canary round-trip verified (`F0RT1KA-CANARY` markers must decrypt).
- **Wholesale collection:** `KeePass.kdbx` (real magic bytes), Gecko `logins.json` +
  `key4.db`, MetaMask-GUID wallet dir and 2FA extension dir copied to
  `lumma_staging\loot`; decrypted-credentials manifest written for stage 4.
- **ABE attempt (approved lift):** real Chrome elevation-service broker activation with
  `CoSetProxyBlanket` dynamic cloaking and `IElevator::DecryptData` (vtable slot 5,
  offset 40) on a synthetic APPB blob; Edge broker activation only (divergent vtable,
  method not invoked). All COM outcomes are telemetry.

### Stage 4 — Collection & Exfiltration over C2 (T1041 / T1005 / T1071.001)

- Collects stage 3's loot if present, else self-generates an equivalent canary harvest
  (stage independence).
- Archives the loot **in memory** (`archive/zip`) — matching Lumma's in-memory upload
  archive.
- Emulates the LummaC2 panel on loopback and runs the documented sequence with
  `User-Agent: TeslaBrowser/5.5`: fingerprint GET probe (`/fp?id=<LID>&b=chrome`,
  Gen Digital Remus ordering) → `POST /c2sock` handshake `act=live&lid=<LID>&j=2`
  (ESET) → multipart upload POST with `lid`/`hwid`/`os`/`b` fields and the archive.
- Byte-counted classification: all archive bytes received → success; explicit
  connection-reset/forcibly-closed denial → 126; anything else → 999. Loot staging is
  removed in cleanup after exfil.

## Telemetry Signal Mapping

| Stage | Primitive | Expected sensor events |
|-------|-----------|------------------------|
| 1 | `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand` | Sysmon EID 1 (command line, `-enc` + `-WindowStyle Hidden`), AMSI scan, PowerShell 4104 script-block |
| 1 | WebClient `DownloadData` in encoded script | PowerShell 4104, proxy/IDS URL fetch telemetry |
| 1 | `mshta.exe http://…/a.hta` | Sysmon EID 1 (canonical LOLBin signature), EID 3 network |
| 1 | Clipboard API sequence from a console process | ETW/instrumented clipboard monitoring (OpenClipboard/SetClipboardData callers) |
| 2 | Self-copy as `MicrosoftEdgeUpdate.exe` + `chrome.exe` in user profile | Sysmon EID 11 (file create, browser-named PEs in non-standard path), EID 1 |
| 2 | `VirtualAllocEx(RWX)` + `WriteProcessMemory` + `CreateRemoteThread` into chrome-named process | Sysmon EID 8 (CreateRemoteThread), EID 10 (ProcessAccess with VM_WRITE\|VM_OPERATION), EDR injection behavioral engines |
| 2 | `OpenThread`/`Suspend`/`Get/SetThreadContext`/`Resume` hijack sequence | Sysmon EID 8/10, EDR thread-hijack behavioral detection |
| 3 | Read of `Local State` + copy of `Login Data`/`Cookies` | Sysmon EID 11/10 (browser-store access from non-browser process), EDR file-read telemetry on credential stores |
| 3 | `CryptUnprotectData` on browser key material | DPAPI instrumentation/ETW, EDR credential-access behavior |
| 3 | SQLite SELECT on `logins`/`cookies` tables | File-read telemetry on copied stores |
| 3 | `CoCreateInstance` of Chrome elevation-service CLSID from non-browser parent | Sysmon EID 1 (`elevation_service.exe` launch with anomalous parent), COM/ETW telemetry, EDR ABE detections |
| 3 | `KeePass.kdbx` / `key4.db` / wallet+2FA extension dir collection | Sysmon EID 11 (staging writes), EID 10 (sensitive-file access) |
| 4 | In-memory zip + multipart POST with `TeslaBrowser/5.5` UA | Sysmon EID 3 (network connection), proxy/IDS UA and `act=live` C2 signatures, byte-volume anomaly |
| 4 | `POST /c2sock` `act=live` handshake, LID/`J` params | Known LummaC2 protocol signatures (ESET-documented indicators) |

## Key Indicators

- **File system**: browser-named PE drops in `…\lumma_inj\`; `Login Data`/`Local State`/
  `Cookies`/`Web Data`/`logins.json`/`key4.db`/`KeePass.kdbx` reads and staging copies;
  marker files proving in-process code execution; `credentials.json` harvest manifest.
- **Process**: encoded hidden PowerShell; `mshta.exe` http fetch; remote thread + thread
  hijack into a chrome-named process; `elevation_service.exe` spawned by a non-browser
  parent.
- **Network** (loopback in this test; shapes match real egress): `TeslaBrowser/5.5`
  UA on `/fp`, `/c2sock` (`act=live`, `lid`, `j`), and multipart `/upload` POSTs.
- **COM**: Chrome elevator CLSID `{708860E0-F641-4611-8895-7D867DD3675B}` activation
  with dynamic-cloaking proxy blanket; vtable slot-5 `DecryptData` call.
- **No registry modifications** are performed by this test.

## Detection Opportunities

14 distinct detection points:

1. Encoded + hidden PowerShell command line (`-enc` with `-w hidden`/`-WindowStyle Hidden`).
2. PowerShell `WebClient`/`DownloadData` download cradle in script-block logging/AMSI.
3. `mshta.exe` invoked with an `http://` URL (LOLBin).
4. Clipboard write of a shell command from a non-interactive/console process.
5. Browser-named PE files (`MicrosoftEdgeUpdate.exe`, `chrome.exe`) created outside
   browser install directories.
6. Classic remote-thread injection chain (`VirtualAllocEx` RWX → `WriteProcessMemory` →
   `CreateRemoteThread`) targeting a chrome-named process.
7. Thread execution hijacking signature (`SuspendThread` + `SetThreadContext` RIP rewrite
   + `ResumeThread`).
8. Cross-process access to `Login Data`/`Cookies`/`Local State` from non-browser processes.
9. `CryptUnprotectData` invoked on browser key material by a non-browser process.
10. Chrome elevation-service COM activation (`CoCreateInstance` on the elevator CLSID)
    from an unexpected parent; `elevation_service.exe` anomalous launch.
11. `IElevator::DecryptData` invocation (ABE bypass primitive; proxy blanket with dynamic
    cloaking).
12. Wholesale reads of `KeePass.kdbx` / `key4.db` / `logins.json` / wallet+2FA extension
    directories followed by staging writes.
13. Archive creation from credential-store paths followed immediately by multipart upload.
14. LummaC2 protocol identity: `TeslaBrowser/5.5` UA, `/c2sock` with `act=live`, LID/`J`
    parameters, fingerprint-probe-then-upload ordering.

## Expected Results

### Unprotected System (Code 101)

All four stages complete: clipboard poisoned and restored, encoded cradle stages the
loopback download, mshta fetch succeeds; both injections verified by markers inside the
decoy chrome.exe; canary logins/cookies DPAPI+AES-GCM-decrypted and loot staged; ABE
broker activation attempted; harvest zipped and fully received by the loopback C2
emulation.

### Protected System

- **Code 126**: positive prevention evidence in any stage — launcher refusal errno on
  `powershell.exe`/`mshta.exe`/stage binaries, `ERROR_ACCESS_DENIED` on the test's own
  decoy process/thread handles, external termination of the idle decoy chrome.exe
  mid-protocol, or an explicit reset on the exfil transfer.
- **Code 105/127**: a stage binary quarantined on extraction or execution
  (`os.Stat` evidence).

### Test Error (Code 999)

Prerequisite failures or inconclusive outcomes — extraction failure (aborts), missing
markers without denial evidence, crypto-chain inconclusiveness, failed loopback binds,
watchdog timeouts (3/4/5/4 min per stage). Ambiguous failures are NEVER mapped to a
block code (Bug Prevention Rule 8).

Per-stage outcomes fan out to `C:\F0\bundle_results.json` (one row per stage) for
Elasticsearch/ProjectAchilles ingestion.

## Execution

```bash
# Build (dev machine):
cd tests_source/intel-driven/26a8b54e-b51c-489d-beae-295e1eecc524 && ./build_all.sh

# Deploy (Windows lab, SSH alias `win`):
scp build/26a8b54e-b51c-489d-beae-295e1eecc524/26a8b54e-b51c-489d-beae-295e1eecc524.exe win:'c:/F0/'
ssh win 'cmd /v:on /c "c:\F0\26a8b54e-b51c-489d-beae-295e1eecc524.exe & echo EXIT_CODE: !ERRORLEVEL!"'
```

Runs in standard-user context (no admin required — matches real infostealer operation).
Watchdog budget: 18 minutes total.

## References

See [`26a8b54e-b51c-489d-beae-295e1eecc524_references.md`](26a8b54e-b51c-489d-beae-295e1eecc524_references.md)
for full source provenance (primary: NCC Group 2026), the eleven supporting sources, and
MITRE ATT&CK technique references.
