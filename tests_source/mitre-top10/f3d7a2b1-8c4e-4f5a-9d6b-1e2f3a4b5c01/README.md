# PowerShell Execution & AMSI Detection

**Test Score**: **7.5/10**

## Overview

This test evaluates endpoint protection capabilities against common PowerShell-based attack patterns. It simulates real-world techniques used by threat actors including base64-encoded command execution, download cradle patterns, hidden window execution, and AMSI bypass indicator detection. All test patterns are designed to be safe - they only create harmless marker files.

## MITRE ATT&CK Mapping

- **Tactic**: Execution, Defense Evasion
- **Technique**: T1059.001 - Command and Scripting Interpreter: PowerShell
- **Technique**: T1140 - Deobfuscate/Decode Files or Information

## Test Patterns

### 1. Base64 Encoded Command (-enc)
Tests detection of PowerShell's `-EncodedCommand` parameter, commonly used by attackers to obfuscate malicious commands.

### 2. Download Cradle Pattern
Simulates the `IEX (New-Object Net.WebClient).DownloadString()` pattern commonly used for initial access and payload delivery. The test creates a marker file instead of downloading actual content.

### 3. Hidden Window Execution
Tests detection of `-WindowStyle Hidden` parameter used to hide PowerShell execution from users.

### 4. AMSI Bypass Pattern Detection
Checks if EDR/AV detects common AMSI bypass indicator strings:
- `AmsiScanBuffer`
- `amsiInitFailed`
- `[Ref].Assembly.GetType`
- `System.Management.Automation.AmsiUtils`

## Safety Measures

- All commands create harmless marker files only
- No actual network connections or downloads
- AMSI patterns are logged for detection, not executed as bypasses
- Automatic cleanup of test artifacts

## Test Execution

Single-binary deployment - no external dependencies required.

```bash
# Build
./utils/gobuild build tests_source/mitre-top10/f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01/

# Sign
./utils/codesign sign build/f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01/f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01.exe
```

## Expected Outcomes

### Protected (Exit Code 126)
EDR/AV blocks at least one of the PowerShell attack patterns:
- Blocks base64 encoded command execution
- Detects download cradle pattern
- Prevents hidden window execution
- Detects AMSI bypass patterns

### Unprotected (Exit Code 101)
All attack patterns execute successfully:
- Base64 commands run without detection
- Download cradle pattern succeeds
- Hidden window execution completes
- No AMSI pattern detection

### Script Quarantined (Exit Code 105)
Security product quarantines the test binary or scripts before execution.

### PowerShell Unavailable (Exit Code 999)
PowerShell is not available on the target system (prerequisites not met).

## Detection Opportunities

1. **Process Creation**: Monitor `powershell.exe` with `-EncodedCommand` or `-enc` flags
2. **Command Line Arguments**: Detect `-WindowStyle Hidden` or `-NonInteractive` flags
3. **Script Block Logging**: Enable PowerShell script block logging for visibility
4. **AMSI Integration**: Ensure AMSI is enabled and functioning
5. **Behavioral Analysis**: Detect rapid file creation in `c:\F0` directory

## Files Created

- `c:\F0\marker_encoded.txt` - Base64 test marker
- `c:\F0\marker_download.txt` - Download cradle test marker
- `c:\F0\marker_hidden.txt` - Hidden window test marker
- `c:\F0\amsi_pattern_results.txt` - AMSI detection results
- `c:\F0\test_summary.txt` - Complete test summary
- `c:\F0\test_execution_log.json` - Schema v2.0 compliant execution log
- `c:\F0\test_execution_log.txt` - Human-readable execution log

## References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1140](https://attack.mitre.org/techniques/T1140/)
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/learn/security-features)
- [AMSI Overview](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
