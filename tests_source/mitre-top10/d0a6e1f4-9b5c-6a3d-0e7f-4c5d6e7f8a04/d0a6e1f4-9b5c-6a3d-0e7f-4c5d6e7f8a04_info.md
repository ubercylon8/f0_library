# WMI Execution Simulation

## Test Information

**Test ID**: d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04
**Test Name**: WMI Execution Simulation
**Category**: Execution / Persistence
**Severity**: High
**MITRE ATT&CK**: T1047, T1546.003

## Description

This security test evaluates endpoint detection and response (EDR) capabilities against Windows Management Instrumentation (WMI) abuse patterns. WMI is a powerful Windows administration interface that threat actors frequently abuse for execution, reconnaissance, and persistence due to its:

- **Native presence**: Available on all Windows systems without additional tools
- **Stealthiness**: Difficult to distinguish from legitimate administrative activity
- **Versatility**: Supports process execution, data queries, and event subscriptions
- **Remote capability**: Can execute commands on remote systems via DCOM

The test covers both native wmic.exe patterns and provides a placeholder for advanced testing with wmiexec-Pro, a Python-based WMI exploitation tool.

## Test Score: 8.0/10

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.5/3.0** | Uses real wmic.exe commands identical to actual attacks; includes placeholder for wmiexec-Pro which is used in real-world penetration testing; covers process creation and enumeration patterns seen in APT activity |
| **Technical Sophistication** | **2.0/3.0** | Multiple WMI patterns (enumeration, process creation, shadow copy queries); WMI event subscription registry inspection; extensible architecture for wmiexec-Pro integration |
| **Safety Mechanisms** | **2.0/2.0** | All operations are local only; marker file creation is benign; WMI event subscription check is read-only; no persistence deployed; no network operations |
| **Detection Opportunities** | **1.0/1.0** | 5+ distinct detection points: wmic.exe process creation, Win32_Process::Create calls, shadow copy enumeration, wmiprvse.exe child processes, registry access patterns |
| **Logging & Observability** | **0.5/1.0** | Full Schema v2.0 logging; stdout/stderr capture; process execution details; comprehensive summary generation |

### Key Strengths

- **Real Attack Patterns**: Uses the exact wmic.exe commands observed in real-world intrusions
- **Stealthy Technique Coverage**: Tests a technique that blends with legitimate Windows activity
- **Extensible Design**: Placeholder architecture allows integration of wmiexec-Pro for advanced testing
- **Multiple Detection Surfaces**: Covers process creation, enumeration, and persistence check patterns
- **Comprehensive Logging**: Detailed logging enables security team analysis

### Improvement Opportunities

- Integration of actual wmiexec-Pro execution when Python and tool are available
- Addition of WMI namespace enumeration patterns
- Inclusion of WMI-based lateral movement simulation (with proper safeguards)

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Verify WMI service (winmgmt) is running
   - Check wmic.exe availability
   - Create target directory c:\F0

2. **Phase 2: Process Enumeration (T1047)**
   - Execute: `wmic process list brief`
   - Saves process listing to file
   - Tests reconnaissance capability

3. **Phase 3: Process Creation (T1047)**
   - Execute: `wmic process call create "cmd.exe /c echo marker > c:\F0\wmi_marker.txt"`
   - Verifies execution by checking marker file
   - Tests execution capability via WMI

4. **Phase 4: Shadow Copy Enumeration (T1047)**
   - Execute: `wmic shadowcopy list brief`
   - Pre-ransomware reconnaissance pattern
   - Saves results to file

5. **Phase 5: WMI Event Subscription Check (T1546.003)**
   - Registry query: `HKLM\SOFTWARE\Microsoft\Wbem\ESS`
   - Registry query: `HKLM\SOFTWARE\Microsoft\WBEM\CIMOM`
   - Read-only inspection for persistence artifacts

6. **Phase 6: wmiexec-Pro Check (Placeholder)**
   - Checks for Python availability
   - Looks for wmiexec-Pro.py in c:\F0\tools\
   - Logs availability for manual testing

7. **Phase 7: Final Assessment**
   - Aggregate results from all phases
   - Generate comprehensive summary
   - Determine protection status

### Key Indicators

- **Process**: wmic.exe with suspicious arguments (process call create, shadowcopy list)
- **Network**: Port 135 (DCE/RPC) traffic for remote WMI operations
- **Process Tree**: wmiprvse.exe spawning child processes
- **Registry**: Access to WMI ESS and CIMOM registry keys
- **Command Line**: Base64 encoded WMI queries, remote hostname specifications

## Detection Opportunities

1. **wmic.exe Process Creation**
   - Monitor for wmic.exe spawning with suspicious arguments
   - Alert on: `process call create`, `shadowcopy`, `/node:` parameters
   - Parent process analysis (unusual parents)

2. **WMI Provider Host Activity**
   - wmiprvse.exe spawning child processes
   - Unusual process trees from WMI operations
   - Command execution patterns

3. **DCE/RPC Network Traffic**
   - Port 135 connections to other hosts
   - WMI-specific traffic patterns
   - DCOM activation

4. **Registry Access Patterns**
   - Queries to WMI event subscription paths
   - ESS namespace access
   - FilterToConsumerBinding artifacts

5. **Behavioral Patterns**
   - Sequential WMI operations (enumeration followed by execution)
   - Shadow copy enumeration (pre-ransomware indicator)
   - Process creation via WMI from unusual contexts

## Expected Results

### Unprotected System (Code 101)

When the system lacks WMI protection:
- All wmic.exe commands execute successfully
- Process enumeration returns system process list
- WMI process creation successfully spawns cmd.exe
- Marker file is created at c:\F0\wmi_marker.txt
- Shadow copy enumeration completes
- Test summary indicates UNPROTECTED status

### Protected System (Code 126)

When EDR/AV properly monitors WMI:
- wmic.exe process creation is blocked or terminated
- WMI Win32_Process::Create method is intercepted
- Command execution via WMI fails with access denied
- Test summary indicates PROTECTED status

### Service Unavailable (Code 999)

When prerequisites are not met:
- WMI service (winmgmt) is not running
- wmic.exe is not available (deprecated in newer Windows)
- Cannot perform WMI operations

## References

- [MITRE ATT&CK T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK T1546.003 - WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
- [XiaoliChan/wmiexec-Pro - GitHub](https://github.com/XiaoliChan/wmiexec-Pro)
- [Detecting WMI Abuse - SANS](https://www.sans.org/blog/detecting-wmi-abuse/)
- [WMI for Offense - Red Canary](https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/)

## wmiexec-Pro Integration

This test includes a placeholder for wmiexec-Pro integration. When the tool is available, it enables testing of:

- Impacket-style WMI execution patterns
- DCOM-based remote command execution
- Semi-interactive shell via WMI
- Stealthier WMI abuse patterns

To enable wmiexec-Pro testing:
1. Install Python 3.x on the target system
2. Place wmiexec-Pro.py in c:\F0\tools\
3. Follow the instructions in tools/README.md

**Note**: Remote WMI execution requires manual operation and should only be performed against authorized test targets.

## Behavioral Detection KQL (Optional)

```kql
// WMI Process Creation Detection
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where ProcessCommandLine has "wmic" and ProcessCommandLine has "process" and ProcessCommandLine has "call" and ProcessCommandLine has "create"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName

// WMI Shadow Copy Enumeration
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where ProcessCommandLine has "wmic" and ProcessCommandLine has "shadowcopy"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine

// WMI Provider Host Child Processes
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where InitiatingProcessFileName == "wmiprvse.exe"
| where FileName != "mofcomp.exe" // Exclude legitimate WMI operations
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
