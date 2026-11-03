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

## Test Score: 7.9/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **1.7** | Real wmic.exe invocations with canonical arguments (process list brief, process call create, shadowcopy list brief, os get /format:list) PLUS the modern wmic-less variant: PowerShell Invoke-CimMethod Win32_Process::Create and Get-CimInstance — the tradecraft used on Win11 24H2+ where wmic is removed. No direct IWbemServices COM calls. |
| **2b** | Identifier Fidelity (0–1.5) | **1.0** | Real WMI class/method identifiers (Win32_Process::Create, Win32_ComputerSystem); real service name (winmgmt). |
| **2c** | Telemetry Signal Quality (0–2) | **1.8** | Lab-verified 2026-11-03 (exit 101; wmic + CIM phases reached). Signal richness ✅ (wmic.exe + powershell.exe CIM + WmiPrvSE provider telemetry). Sensor mapping ✅. Rule artifacts parse ✅. wmiexec-Pro phase skipped per Lab-Bound Observability (tool absent). |
| **2d** | Execution-Context Fidelity (0–1) | **0.8** | Admin probe gates WMI-denial classification; wmic availability detected at runtime with CIM fallback branching (wmic-less hosts are first-class, not errors). |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 5.8 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **7.9 / 10** | Realism: 5.30 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 101 — wmic and Invoke-CimMethod process-creation both executed (marker files verified).** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.

### Lab-Bound Observability (v2.1 §2c criterion 4)

**Phases affected:** wmiexec-Pro remote WMI execution (Phase 6).

**Cause:** runtime-optional external tool not provided (`c:\F0\tools\`) and/or technique prerequisites not met on the lab host (documented in the phase log as explicit `skipped` — never counted as success or block). This is the designed degradation path for tool-optional tests, not a test deficiency: all native phases reached terminal status in the same run. Providing the tool (and, for Kerberos phases, a domain-joined host) re-enables the phase without rebuild.

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
- wmic.exe is not available (removed on Win11 24H2+): the test does NOT abort — wmic phases are skipped and the modern PowerShell `Invoke-CimMethod Win32_Process::Create` variant (plus `Get-CimInstance` recon) executes instead, which is the tradecraft used on wmic-less hosts
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
