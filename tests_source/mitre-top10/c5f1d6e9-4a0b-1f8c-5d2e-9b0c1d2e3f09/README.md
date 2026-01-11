# Webshell Post-Exploitation Simulation

**Test Score**: **7.5/10**

## Overview

This test simulates the POST-EXPLOITATION phase after a webshell has been deployed on a compromised system. It executes reconnaissance commands that webshells typically run to gather system information and attempts a C2 (Command and Control) callback to simulate data exfiltration. This test evaluates whether EDR/AV solutions can detect and block webshell-like activity patterns.

## MITRE ATT&CK Mapping

- **Tactic**: Initial Access, Execution
- **Technique**: T1190 - Exploit Public-Facing Application (post-exploitation phase)
- **Technique**: T1059.003 - Windows Command Shell

## Test Patterns

### Reconnaissance Commands

The test executes six common reconnaissance commands that webshells use for initial system enumeration:

1. **whoami /all** - User context enumeration (privileges, group memberships)
2. **hostname** - System identification for lateral movement planning
3. **ipconfig /all** - Network configuration (IPs, DNS, DHCP)
4. **systeminfo** - Full system information (OS, hotfixes, domain)
5. **netstat -an** - Active network connections and listening ports
6. **tasklist** - Running processes (identify security software)

### C2 Callback Simulation

Simulates a webshell beacon callback to a C2 server using httpbin.org as a safe test endpoint. This tests whether outbound HTTP POST requests with suspicious patterns are blocked.

## Safety Measures

- All reconnaissance commands are read-only (no system modifications)
- C2 endpoint uses httpbin.org (harmless public test service)
- No actual exploitation or webshell deployment
- No persistence mechanisms
- Automatic cleanup of test artifacts

## Test Execution

Single-binary deployment - no external dependencies required.

```bash
# Build
./utils/gobuild build tests_source/mitre-top10/c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09/

# Sign
./utils/codesign sign build/c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09/c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09.exe
```

## Expected Outcomes

### Protected (Exit Code 126)

EDR/AV blocks at least one of the following:
- Reconnaissance command execution (whoami, systeminfo, etc.)
- C2 callback attempt (outbound POST to external endpoint)

### Unprotected (Exit Code 101)

All attack patterns execute successfully:
- All reconnaissance commands complete
- C2 callback succeeds (outbound connection allowed)

### Network Unavailable (Exit Code 999)

C2 callback failed due to network issues (not security blocking):
- No internet connectivity
- Proxy configuration issues
- DNS resolution failure

### Test Error (Exit Code 1)

Test encountered an unexpected error during execution.

## Detection Opportunities

1. **Process Creation**: Monitor cmd.exe spawned by web server processes (w3wp.exe, httpd.exe)
2. **Command Line Analysis**: Detect rapid execution of reconnaissance commands
3. **Process Chains**: Identify unusual parent-child relationships
4. **Network Activity**: Monitor outbound HTTP POST requests with suspicious payloads
5. **Behavioral Analysis**: Correlate multiple recon commands in short timeframe
6. **File Creation**: Detect output files created in c:\F0 directory

## Files Created

- `c:\F0\webshell_recon_output.txt` - Collected reconnaissance data
- `c:\F0\test_summary.txt` - Test execution summary
- `c:\F0\test_execution_log.json` - Schema v2.0 compliant execution log
- `c:\F0\test_execution_log.txt` - Human-readable execution log

## References

- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1059.003](https://attack.mitre.org/techniques/T1059/003/)
- [Webshell Threat Research](https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/)
- [CISA Alert on Web Shells](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-205a)
