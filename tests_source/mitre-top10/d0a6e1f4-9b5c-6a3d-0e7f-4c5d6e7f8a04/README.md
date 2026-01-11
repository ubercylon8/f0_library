# WMI Execution Simulation

**Test Score**: **8.0/10**

## Overview

This test evaluates EDR/AV detection capabilities against Windows Management Instrumentation (WMI) abuse patterns commonly used by threat actors for execution, reconnaissance, and persistence. WMI is a stealthy technique that leverages built-in Windows functionality, making it difficult to distinguish from legitimate administrative activity.

## MITRE ATT&CK Mapping

- **Tactic**: Execution, Persistence
- **Technique**: T1047 - Windows Management Instrumentation
- **Sub-technique**: T1546.003 - Event Triggered Execution: WMI Event Subscription (read-only check)

## Test Patterns

1. **Process Enumeration**: `wmic process list brief` - Reconnaissance via WMI
2. **Process Creation**: `wmic process call create` - Execute commands via WMI
3. **Shadow Copy Enumeration**: `wmic shadowcopy list` - Pre-ransomware reconnaissance
4. **WMI Event Subscription Check**: Registry inspection for persistence artifacts
5. **wmiexec-Pro Placeholder**: Future support for advanced WMI tool testing

## Test Execution

This test simulates WMI abuse patterns to evaluate defensive capabilities:

- Uses native Windows `wmic.exe` commands
- Creates harmless marker files to verify execution
- Performs read-only checks on WMI event subscription registry
- Logs all operations for detection correlation

## Expected Outcomes

- **Protected (126)**: EDR blocks WMI process creation or enumeration patterns
- **Unprotected (101)**: WMI commands executed without detection
- **Error (999)**: WMI service unavailable or wmic.exe not found

## Build Instructions

```bash
# Build single self-contained binary
./utils/gobuild build tests_source/mitre-top10/d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04/

# Sign the binary
./utils/codesign sign build/d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04/d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04.exe
```

## wmiexec-Pro Integration (Optional)

To enable advanced WMI testing with wmiexec-Pro:

1. Place `wmiexec-Pro.py` in `c:\F0\tools\`
2. Ensure Python 3.x is available
3. See `tools/README.md` for detailed instructions

**Note**: Remote WMI execution via wmiexec-Pro requires manual operation and a network target.

## Detection Opportunities

1. **Process Creation**: wmic.exe spawning child processes
2. **WMI Provider Host**: wmiprvse.exe activity
3. **Network Traffic**: Port 135 (DCE/RPC) for remote WMI
4. **Registry Access**: WMI ESS registry key queries
5. **Command Line**: Suspicious wmic.exe arguments

## Safety Considerations

- All operations are local (no remote WMI execution)
- Only creates benign marker files
- WMI event subscription check is read-only
- No persistence mechanisms are deployed

## References

- [MITRE ATT&CK T1047](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK T1546.003](https://attack.mitre.org/techniques/T1546/003/)
- [wmiexec-Pro GitHub](https://github.com/XiaoliChan/wmiexec-Pro)
