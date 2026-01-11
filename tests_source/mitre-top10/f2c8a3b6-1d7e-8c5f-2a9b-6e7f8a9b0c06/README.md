# LOLBIN Download Detection

**Test Score**: **8.0/10**

## Overview

This test evaluates EDR/AV detection capabilities against Living Off The Land Binary (LOLBIN) download techniques. It simulates adversary behavior using native Windows binaries to download files from the internet, a common initial access and tool transfer technique used by threat actors to avoid detection.

## MITRE ATT&CK Mapping

- **Tactic**: Command and Control, Execution
- **Technique**: T1105 - Ingress Tool Transfer
- **Sub-technique**: T1059.001 - Command and Scripting Interpreter: PowerShell

## Test Patterns

The test evaluates 5 distinct LOLBIN download patterns commonly used by attackers:

| Pattern | Binary | Command Example |
|---------|--------|-----------------|
| certutil URL cache | certutil.exe | `certutil -urlcache -split -f <url> <file>` |
| bitsadmin transfer | bitsadmin.exe | `bitsadmin /transfer job <url> <file>` |
| PowerShell IWR | powershell.exe | `Invoke-WebRequest -Uri <url> -OutFile <file>` |
| PowerShell WebClient | powershell.exe | `(New-Object Net.WebClient).DownloadFile()` |
| curl download | curl.exe | `curl.exe -o <file> <url>` |

## Test Execution

The test performs the following:

1. **Initialization**: Verifies target directory and network connectivity
2. **Network Check**: Confirms internet access to test endpoint (example.com)
3. **LOLBIN Tests**: Executes each download pattern sequentially
4. **Detection Check**: Monitors for EDR blocking or file quarantine
5. **Cleanup**: Removes all downloaded test files

## Expected Outcomes

- **Protected (Exit 126)**: EDR blocks LOLBIN download commands
- **Protected (Exit 105)**: Downloaded files are quarantined
- **Unprotected (Exit 101)**: Downloads succeed without detection
- **Error (Exit 999)**: Network unavailable or prerequisites not met

## Safety Mechanisms

- Only downloads benign content (robots.txt from example.com)
- No execution of downloaded content
- Automatic cleanup of all test artifacts
- All files dropped to whitelisted `c:\F0` directory

## Build Instructions

```bash
# Build single self-contained binary
./utils/gobuild build tests_source/mitre-top10/f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06/

# Sign the binary
./utils/codesign sign build/f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06/f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06.exe
```

## Detection Opportunities

Security teams should monitor for:

1. **certutil.exe** with `-urlcache` or `-split` flags
2. **bitsadmin.exe** with `/transfer` command
3. **PowerShell** with `Invoke-WebRequest` or `WebClient.DownloadFile`
4. **curl.exe** downloading to unusual locations
5. Multiple download binaries executing in sequence

## References

- [MITRE ATT&CK T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [LOLBAS Project - Living Off The Land Binaries](https://lolbas-project.github.io/)
