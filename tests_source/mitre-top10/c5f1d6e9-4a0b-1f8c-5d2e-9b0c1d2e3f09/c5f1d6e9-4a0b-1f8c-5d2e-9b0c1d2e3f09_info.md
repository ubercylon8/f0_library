# Webshell Post-Exploitation Simulation

## Test Information

**Test ID**: c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09
**Test Name**: Webshell Post-Exploitation Simulation
**Category**: MITRE Top 10 / Initial Access
**Severity**: High
**MITRE ATT&CK**: T1190, T1059.003

## Description

This test simulates the POST-EXPLOITATION phase that occurs after a webshell has been successfully deployed on a compromised web server. Webshells are a critical component in many real-world intrusions, providing attackers with persistent remote access to compromised systems.

The test focuses on two key behaviors:

1. **Reconnaissance Command Execution**: Webshells typically execute a series of discovery commands immediately after deployment to enumerate the compromised system, identify privileges, map the network, and locate security software.

2. **C2 Callback**: Many webshells beacon back to attacker-controlled infrastructure to confirm successful deployment and exfiltrate collected data.

This test does NOT deploy an actual webshell - it simulates the behavior that would occur AFTER deployment to evaluate whether security controls can detect webshell-like activity patterns.

## Test Score: 7.5/10

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.5/3.0** | Uses authentic reconnaissance commands (whoami /all, systeminfo, netstat -an) that mirror real webshell TTPs. C2 callback simulates actual beacon behavior. Command sequence matches observed attack patterns. |
| **Technical Sophistication** | **2.0/3.0** | Implements 6 distinct reconnaissance commands plus HTTP POST C2 callback. Native test without embedded binaries. Includes realistic timing delays between commands. |
| **Safety Mechanisms** | **1.5/2.0** | All commands are read-only reconnaissance (no system modifications). C2 endpoint uses safe public service (httpbin.org). No actual webshell deployment or persistence. Small deduction for network dependency. |
| **Detection Opportunities** | **1.0/1.0** | Provides 7+ distinct detection points: 6 reconnaissance commands (each a detection opportunity) plus C2 callback. Multiple process creation events, command-line patterns, and network activity. |
| **Logging & Observability** | **0.5/1.0** | Full Schema v2.0 logging with JSON/text output. Process execution logging, file operation tracking, phase tracking. Room for improvement in detailed timing and per-command metrics. |

### Key Strengths

1. **High Real-World Relevance**: Webshells are consistently used in APT and financially-motivated attacks, making this test highly relevant
2. **Multiple Detection Points**: 7+ distinct detection opportunities across recon commands and C2 activity
3. **Native Implementation**: No embedded binaries or external tools - uses only Windows built-in commands
4. **Safe Design**: Read-only commands with harmless C2 endpoint - no risk to target system
5. **Authentic Patterns**: Command selection and sequence mirrors real threat actor behavior
6. **C2 Simulation**: Tests network egress controls in addition to endpoint detection

### Improvement Opportunities

1. Could add PowerShell-based reconnaissance patterns
2. Could simulate file upload/download via webshell
3. Could add directory traversal reconnaissance patterns
4. Could include credential harvesting command simulation

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Create target directory `c:\F0`
   - Initialize Schema v2.0 logging
   - Prepare command execution environment

2. **Phase 2: Reconnaissance Commands**
   - Execute: `whoami /all` (user context enumeration)
   - Execute: `hostname` (system identification)
   - Execute: `ipconfig /all` (network configuration)
   - Execute: `systeminfo` (full system information)
   - Execute: `netstat -an` (network connections)
   - Execute: `tasklist` (running processes)
   - Detection: Process creation, command-line arguments, behavioral patterns

3. **Phase 3: C2 Callback Simulation**
   - HTTP POST to https://httpbin.org/post
   - Payload includes: beacon identifier, hostname, test UUID
   - User-Agent: Standard browser string
   - Detection: Network egress, HTTP POST content, unusual destination

4. **Phase 4: Output and Assessment**
   - Write reconnaissance output to marker file
   - Generate test summary
   - Evaluate protection status
   - Cleanup test artifacts

### Key Indicators

**Process Creation:**
- cmd.exe executions from unusual parent processes
- Rapid succession of whoami, systeminfo, ipconfig commands
- netstat -an and tasklist in command chain

**Command Line Patterns:**
- `whoami /all` - Full user enumeration
- `systeminfo` - Detailed system information
- `ipconfig /all` - Complete network configuration
- `netstat -an` - All connections with numeric addresses
- `tasklist` - Process enumeration

**Network Activity:**
- HTTP POST to external IP/domain
- Beacon-like payload (identifier, hostname)
- Non-standard user-agent patterns

**File System:**
- Creation of output files in `c:\F0`
- Files containing system information

## Detection Opportunities

1. **Process Creation Monitoring**
   - Alert on reconnaissance command sequences
   - Monitor for rapid execution of multiple discovery commands
   - Track parent-child process relationships (e.g., w3wp.exe -> cmd.exe)

2. **Command Line Analysis**
   - Detect `/all` flags on whoami, ipconfig
   - Identify netstat with `-an` parameters
   - Flag systeminfo execution from web server context

3. **Behavioral Correlation**
   - Correlate multiple recon commands in short timeframe (<30 seconds)
   - Associate command execution with network callback
   - Track command chains typical of webshell activity

4. **Network Egress Monitoring**
   - Monitor HTTP POST to external endpoints
   - Inspect payload for reconnaissance data
   - Detect beacon-like patterns (periodic callbacks, identification data)

5. **Web Server Context**
   - Alert on cmd.exe spawned by IIS (w3wp.exe), Apache (httpd), etc.
   - Flag discovery commands from web application context
   - Correlate with web server access logs

6. **File System Activity**
   - Monitor for output files containing system information
   - Detect reconnaissance data staging

## Expected Results

### Unprotected System (Code 101)

When the system is unprotected:
- All six reconnaissance commands execute successfully
- C2 callback completes (HTTP 200 response)
- Reconnaissance output file created in `c:\F0`
- System information collected and (simulated) exfiltrated

### Protected System (Code 126)

When the system has active protection:
- One or more reconnaissance commands blocked
- OR C2 callback blocked by network security
- Blocking may occur via:
  - Process creation prevention
  - Command execution blocking
  - Network egress filtering
  - Behavioral detection

### Network Unavailable (Code 999)

When network is unavailable:
- C2 callback fails due to connectivity (not security)
- Reconnaissance commands may still succeed
- This is environmental, not a security result

## Build Instructions

```bash
# Build the test
cd /home/jimx/F0RT1KA/f0_library
./utils/gobuild build tests_source/mitre-top10/c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09/

# Sign the binary
./utils/codesign sign build/c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09/c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09.exe

# Or use combined build-sign command
/build-sign-test c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09
```

## References

- [MITRE ATT&CK T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1059.003 - Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [Microsoft Security Blog - Web Shell Attacks](https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/)
- [CISA Alert AA20-205A - Web Shells](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-205a)
- [NSA/ASD - Detect and Prevent Web Shell Malware](https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-11 | Initial release with 6 recon commands + C2 callback |
