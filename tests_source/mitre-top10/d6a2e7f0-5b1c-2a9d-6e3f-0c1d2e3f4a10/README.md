# Security Service Stop Simulation

**Test Score**: **8.0/10**

## Overview

Simulates MITRE ATT&CK T1489 (Service Stop) and T1562.001 (Impair Defenses: Disable or Modify Tools) techniques to evaluate EDR detection of service control operations. This test uses **safe implementation patterns** - it only queries existing security services and creates/manages its own test service.

## MITRE ATT&CK Mapping

- **Tactic**: Impact, Defense Evasion
- **Technique**: T1489 - Service Stop
- **Technique**: T1562.001 - Impair Defenses: Disable or Modify Tools

## Safety Guarantees

This test implements multiple safety mechanisms:

1. **Query-Only for Real Services**: Security services (WinDefend, wscsvc, VSS, wbengine) are only queried - never stopped or modified
2. **Test Service Only**: Creates, stops, and deletes only the `F0RTIKA_TestSvc` test service
3. **Localhost-Only Network**: NetExec (if present) only connects to 127.0.0.1
4. **Dummy Credentials**: SMB enumeration uses credentials that will fail authentication
5. **Automatic Cleanup**: All test artifacts are cleaned up after execution

## Test Patterns Implemented

| Pattern | Command | Safety Level |
|---------|---------|--------------|
| Query WinDefend | `sc query WinDefend` | Query Only |
| Query wscsvc | `sc query wscsvc` | Query Only |
| Query VSS | `sc query VSS` | Query Only |
| Query wbengine | `sc query wbengine` | Query Only |
| Create test service | `sc create F0RTIKA_TestSvc...` | Own Service |
| Stop test service | `sc stop F0RTIKA_TestSvc` | Own Service |
| Delete test service | `sc delete F0RTIKA_TestSvc` | Own Service |
| Check taskkill | `taskkill /?` | Help Only |
| NetExec (optional) | `nxc smb 127.0.0.1 --services` | Localhost |

## NetExec Integration (Optional)

The test supports optional NetExec (nxc.exe) integration for testing SMB-based service enumeration detection.

### To Enable NetExec Testing:

1. Download NetExec from: https://github.com/Pennyw0rth/NetExec
2. Place `nxc.exe` in `c:\F0\tools\`
3. Re-run the test

### Without NetExec:

The test still runs all native service query patterns and test service operations.

## Expected Outcomes

### Protected System (Exit Code 126)
- EDR blocks service queries or service control operations
- NetExec execution is prevented
- Access denied errors returned for sc.exe commands

### Unprotected System (Exit Code 101)
- All service queries succeed
- Test service create/stop/delete operations complete
- NetExec (if present) executes without interference

### Insufficient Privileges (Exit Code 999)
- Test not running as Administrator
- Service operations require elevated privileges

## Build Instructions

```bash
# Build single binary
cd tests_source/mitre-top10/d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10
GOOS=windows GOARCH=amd64 go build -o ../../../build/d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10/d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10.exe *.go

# Or use the build utility
./utils/gobuild build tests_source/mitre-top10/d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10/

# Sign the binary
./utils/codesign sign build/d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10/d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10.exe
```

## Deployment

1. Copy `d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10.exe` to `c:\F0\`
2. (Optional) Copy `nxc.exe` to `c:\F0\tools\`
3. Run as Administrator: `c:\F0\d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10.exe`

## Detection Opportunities

1. **Service Query Patterns**: Multiple `sc query` commands for security services
2. **Service Creation**: Test service created with `sc create`
3. **Service Control**: Stop and delete operations on services
4. **Taskkill Access**: Process termination utility access check
5. **NetExec Execution**: Known offensive tool execution
6. **SMB Enumeration**: Service enumeration via SMB protocol

## Files Generated

| File | Purpose |
|------|---------|
| `c:\F0\test_execution_log.json` | Schema v2.0 compliant execution log |
| `c:\F0\test_execution_log.txt` | Human-readable log |
| `c:\F0\tools\nxc_output.txt` | NetExec output (if executed) |
| `c:\F0\tools\README.md` | NetExec placement instructions |

## References

- [MITRE ATT&CK T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK T1562.001 - Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)
- [NetExec GitHub](https://github.com/Pennyw0rth/NetExec)
