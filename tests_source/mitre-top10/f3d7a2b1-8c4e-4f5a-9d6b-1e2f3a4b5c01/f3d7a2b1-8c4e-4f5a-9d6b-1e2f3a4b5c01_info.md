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

## Test Score: 7.5/10

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.0/3.0** | Uses actual PowerShell command patterns observed in real attacks. Base64 encoding, download cradle, and hidden window patterns mirror real-world TTPs. AMSI bypass patterns are authentic strings found in actual bypass techniques. |
| **Technical Sophistication** | **2.0/3.0** | Implements multiple distinct detection patterns. Tests both command-line argument detection and content-based AMSI scanning. Native test without external dependencies. |
| **Safety Mechanisms** | **2.0/2.0** | Excellent safety profile - all commands create harmless marker files only. No actual network connections, no code execution beyond file creation. AMSI patterns are tested via string detection, not actual bypass execution. Automatic cleanup of test artifacts. |
| **Detection Opportunities** | **1.0/1.0** | Provides 4+ distinct detection points: process creation monitoring, command-line argument analysis, AMSI integration, script block logging, and behavioral file creation patterns. |
| **Logging & Observability** | **0.5/1.0** | Full Schema v2.0 logging with JSON/text output. Phase tracking, process execution logging, file operation logging. Some room for improvement in detailed timing metrics. |

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
   - Execute simulated download cradle (creates marker file)
   - Pattern: `$marker = "..."; $marker | Out-File -FilePath "c:\F0\marker_download.txt"`
   - Detection: Script content, behavioral analysis

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

If the test binary is quarantined:
- EDR/AV detected the test binary
- This indicates signature-based or heuristic detection
- Test did not fully execute

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
