# LOLBIN Download Detection

## Test Information

**Test ID**: f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06
**Test Name**: LOLBIN Download Detection
**Category**: Command and Control / Ingress Tool Transfer
**Severity**: High
**MITRE ATT&CK**: T1105, T1059.001

## Description

This test evaluates endpoint protection against Living Off The Land Binary (LOLBIN) download techniques. Adversaries frequently abuse native Windows binaries to download malicious payloads, tools, and second-stage components. This technique bypasses application whitelisting since the binaries are legitimate, signed Microsoft executables.

The test simulates realistic attacker behavior by using five common LOLBIN download patterns that appear in real-world intrusions, including APT campaigns and ransomware operations. Each pattern is tested independently to provide granular detection visibility.

## Test Score: 8.0/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **2.0** | Five exact canonical LOLBIN ingress invocations: certutil -urlcache -split -f, bitsadmin /transfer <job> /download /priority FOREGROUND, PowerShell Invoke-WebRequest + WebClient.DownloadFile cradles with -ExecutionPolicy Bypass, curl --fail -o. These ARE the adversary primitives — no abstraction loss. No download→execute linkage (intentional safety bound). |
| **2b** | Identifier Fidelity (0–1.5) | **0.9** | Real system-binary paths and flags; retrieval target is a stable benign public file (GitHub raw) — URL-reputation coverage against attacker-style hosts is future work (documented). bitsadmin job name is plausible but generic. |
| **2c** | Telemetry Signal Quality (0–2) | **2.0** | Highest in suite — EMPIRICALLY verified 2026-11-03: Sophos Intercept X blocked certutil.exe at process creation (fork/exec Access is denied), the other four LOLBINs genuinely downloaded; exit 126 PARTIAL PROTECTION from positive evidence. Signal richness ✅ (process creation + network + file-write surfaces). Sensor mapping ✅. Rule artifacts parse ✅. |
| **2d** | Execution-Context Fidelity (0–1) | **0.5** | User-context operations throughout (context-independence is genuinely desirable for ingress tests) — no context branching. |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 11 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **8.0 / 10** | Realism: 5.40 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 126 — certutil BLOCKED by Sophos at process creation (positive evidence); bitsadmin/IWR/WebClient/curl downloaded successfully.** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.

**Key Strengths**:
- Tests 5 distinct LOLBIN download methods commonly abused by threat actors
- Uses actual native Windows binaries with real-world command patterns
- Provides granular results per download method
- Safe execution with benign download target and automatic cleanup
- Comprehensive logging including raw command output capture

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Creates target directory `c:\F0`
   - Initializes comprehensive logging
   - Verifies test environment

2. **Phase 2: Network Connectivity Check**
   - Validates internet access to test endpoint
   - Uses HTTP HEAD request to minimize bandwidth
   - Falls back to alternate URL if primary unavailable

3. **Phase 3: LOLBIN Download Tests**
   - **certutil.exe**: Uses `-urlcache -split -f` flags to download and cache file
   - **bitsadmin.exe**: Creates background transfer job with `/transfer` command
   - **PowerShell IWR**: Uses `Invoke-WebRequest` cmdlet with `-UseBasicParsing`
   - **PowerShell WebClient**: Uses .NET `System.Net.WebClient.DownloadFile()` method
   - **curl.exe**: Windows 10+ native curl with `-o` output flag

4. **Phase 4: Final Assessment**
   - Aggregates results across all patterns
   - Generates summary report
   - Determines protection status
   - Performs cleanup

### Key Indicators

- **Process Creation**: certutil.exe, bitsadmin.exe, powershell.exe, curl.exe
- **Command Line Patterns**:
  - `certutil` with `-urlcache`, `-split`, `-f` flags
  - `bitsadmin` with `/transfer` subcommand
  - `powershell` with `Invoke-WebRequest` or `WebClient`
  - `curl.exe` with `-o` flag and external URL
- **File System Activity**: New files created in `c:\F0` directory
- **Network Activity**: HTTP GET requests to external URLs

## Detection Opportunities

1. **Process Execution Monitoring**
   - certutil.exe spawned by unexpected parent process
   - bitsadmin.exe with /transfer command
   - PowerShell with download-related cmdlets
   - curl.exe downloading to suspicious locations

2. **Command Line Analysis**
   - certutil -urlcache patterns (very suspicious outside admin context)
   - bitsadmin /transfer to external URLs
   - PowerShell download cradles (IWR, WebClient)
   - curl.exe with -o flag to local paths

3. **Network Connections**
   - Connections from certutil.exe, bitsadmin.exe (unusual)
   - PowerShell outbound HTTPS connections
   - curl.exe to non-update URLs

4. **File System Events**
   - Files created by LOLBIN processes in non-standard locations
   - Rapid sequence of file downloads from same source

5. **Behavioral Correlation**
   - Multiple download binaries used in sequence
   - Download activity followed by execution attempts
   - Files downloaded to temp or writable directories

## Expected Results

### Unprotected System (Code 101)
- All 5 LOLBIN download patterns execute successfully
- Downloaded files persist on disk without quarantine
- No security alerts or blocks generated
- Test summary shows 0 blocked, 5 successful

### Protected System (Enhanced Detection)

- **Code 126 (Execution Prevented)**: EDR blocks LOLBIN commands before download completes. Common with behavior-based detection that flags certutil/bitsadmin download patterns.

- **Code 105 (File Quarantined)**: Downloads complete but files are immediately quarantined by AV/EDR file system monitoring. Indicates reactive rather than proactive protection.

- **Partial Protection**: Some patterns blocked while others succeed. Indicates gaps in detection coverage that should be addressed.

### Error Conditions

- **Code 999**: Network unavailable - test cannot complete
- **Code 1**: All tests skipped due to missing binaries or other errors

## References

- [MITRE ATT&CK T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Microsoft: Detecting LOLBIN Activity](https://docs.microsoft.com/en-us/security/)
- [Red Canary: Certutil Detection](https://redcanary.com/threat-detection-report/)

## Improvement Opportunities

- Add wget.exe pattern for systems with wget installed
- Include PowerShell `Start-BitsTransfer` cmdlet
- Add curl with `--output` alternate flag
- Test rundll32.exe with javascript: protocol
- Include mshta.exe HTA download pattern

## Size Justification

The compiled orchestrator is ~15 MB (Yellow tier, 10–25 MB): it is a single Go binary with the standard F0RT1KA telemetry stack (Schema v2.0 logger, org resolver, per-child output capture for five LOLBIN executions). No .NET runtime or external payloads are embedded; size is dominated by Go runtime + logging infrastructure, not by simulation bulk.

## Realism constraints

- **Retrieval target**: downloads use `https://raw.githubusercontent.com/torvalds/linux/master/README` (guaranteed-reachable benign content). URL-reputation controls treat well-known benign domains differently from attacker-controlled hosts — full URL-reputation coverage requires a controlled random-looking host on owned infrastructure (future work).
- **Download → execute linkage**: T1105's danger is delivering a payload that then executes; this test stops at retrieval of a benign text file (intentional safety bound).
