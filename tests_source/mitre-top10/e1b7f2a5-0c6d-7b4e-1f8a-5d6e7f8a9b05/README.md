# System Recovery Inhibition (Safe Mode)

**Test Score**: **8.0/10**

## Overview

This test evaluates EDR/AV detection capabilities against T1490 (Inhibit System Recovery) reconnaissance. It uses a SAFE MODE implementation that performs READ-ONLY checks only - no destructive operations are executed. The test verifies whether security controls can detect and block access to recovery tools commonly abused by ransomware.

## MITRE ATT&CK Mapping

- **Tactic**: Impact
- **Technique**: T1490 - Inhibit System Recovery
- **Description**: Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery

## Test Behavior (Safe Mode)

This test performs the following READ-ONLY operations:

1. **vssadmin.exe accessibility check** - Verifies tool exists
2. **vssadmin list shadows** - Read-only query (does NOT delete)
3. **bcdedit.exe accessibility check** - Verifies tool exists
4. **bcdedit /enum** - Read-only query (does NOT modify)
5. **wbadmin.exe accessibility check** - Verifies tool exists
6. **wbadmin get versions** - Read-only query (does NOT delete)
7. **Documentation** - Logs commands ransomware WOULD execute (never executed)

### Commands Documented But NOT Executed

The following commands are what ransomware typically executes. These are LOGGED for documentation purposes only:

```
vssadmin delete shadows /all /quiet
bcdedit /set {default} recoveryenabled No
wbadmin delete systemstatebackup -keepVersions:0
wbadmin delete catalog -quiet
wmic shadowcopy delete /nointeractive
```

## Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 126 | PROTECTED | EDR blocked read-only queries to recovery tools |
| 101 | UNPROTECTED | Recovery tools accessible - vulnerable to T1490 |
| 999 | ERROR | Prerequisites not met (admin privileges required) |

## Expected Outcomes

### Protected System (Exit Code 126)
- EDR detects and blocks read-only queries to vssadmin, bcdedit, or wbadmin
- Indicates behavioral monitoring of recovery tool access
- System would prevent ransomware recovery inhibition

### Unprotected System (Exit Code 101)
- All recovery tools are accessible and queryable
- No EDR intervention on tool access
- System is vulnerable to T1490 ransomware techniques

## Build Instructions

```bash
# Build single self-contained binary
cd tests_source/mitre-top10/e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05
GOOS=windows GOARCH=amd64 go build -o ../../../build/e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05/e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05.exe *.go

# Or use build utility from project root
./utils/gobuild build tests_source/mitre-top10/e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05/
./utils/codesign sign build/e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05/e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05.exe
```

## Deployment

```powershell
# Copy to target and execute (requires Administrator)
.\e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05.exe
```

## Safety Guarantees

This test is designed to be completely safe to run repeatedly:

- **NO shadow copy deletion** - Only `list shadows` is executed
- **NO boot config modification** - Only `/enum` is executed
- **NO backup deletion** - Only `get versions` is executed
- **All operations are read-only** - System state is never modified
- **Marker files only in c:\F0** - Test artifacts isolated

## Detection Opportunities

1. Process creation: vssadmin.exe, bcdedit.exe, wbadmin.exe
2. Command line monitoring for recovery tool arguments
3. WMI queries targeting Win32_ShadowCopy class
4. Registry access to BCD store
5. Event log monitoring (VSS events 8193, 8194)

## Files Created

| File | Location | Description |
|------|----------|-------------|
| recovery_inhibition_report.txt | c:\F0 | Comprehensive test report |
| t1490_test_started.txt | c:\F0 | Start marker |
| t1490_test_completed.txt | c:\F0 | Completion marker |
| test_execution_log.json | c:\F0 | Schema v2.0 JSON log |
| test_execution_log.txt | c:\F0 | Human-readable log |

## References

- [MITRE ATT&CK T1490](https://attack.mitre.org/techniques/T1490/)
- [Ransomware: Shadow Copy Deletion](https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)
- [Understanding Volume Shadow Copy Service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
