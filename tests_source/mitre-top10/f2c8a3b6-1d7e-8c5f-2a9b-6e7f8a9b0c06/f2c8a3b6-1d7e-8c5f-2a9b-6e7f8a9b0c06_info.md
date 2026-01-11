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

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.5/3.0** | Uses actual Windows LOLBINs (certutil, bitsadmin, curl, PowerShell) with real command-line patterns seen in production attacks |
| **Technical Sophistication** | **2.0/3.0** | Multiple distinct download methods, proper stdout/stderr capture, comprehensive error handling |
| **Safety Mechanisms** | **2.0/2.0** | Only downloads benign robots.txt, no execution of downloaded content, automatic cleanup, all files to whitelisted directory |
| **Detection Opportunities** | **1.0/1.0** | 5 distinct detection points - one for each LOLBIN pattern, plus network IOC opportunities |
| **Logging & Observability** | **0.5/1.0** | Full Schema v2.0 logging, phase tracking, process execution logs, output capture to files |

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
