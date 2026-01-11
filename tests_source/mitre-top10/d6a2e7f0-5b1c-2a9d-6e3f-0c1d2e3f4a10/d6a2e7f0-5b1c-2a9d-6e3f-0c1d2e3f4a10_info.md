# Security Service Stop Simulation

## Test Information

**Test ID**: d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10
**Test Name**: Security Service Stop Simulation
**Category**: MITRE Top 10 / Impact / Defense Evasion
**Severity**: High
**MITRE ATT&CK**: T1489, T1562.001

## Description

This test evaluates EDR/AV detection capabilities against service control operations commonly used by ransomware and threat actors to disable security services before executing their payloads. The test implements safe patterns by only querying real security services and performing actual service operations on a dedicated test service.

Service Stop (T1489) is a critical technique used by ransomware families including:
- **LockBit**: Stops backup services and security tools
- **Conti**: Disables VSS and security services
- **REvil**: Terminates AV processes and services
- **BlackCat/ALPHV**: Targets security service termination

## Test Score: 8.0/10

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.5/3.0** | Uses native Windows sc.exe, actual service operations, optional real red team tool (NetExec) |
| **Technical Sophistication** | **2.5/3.0** | Multi-phase service enumeration and control, SMB-based enumeration, multiple detection vectors |
| **Safety Mechanisms** | **2.0/2.0** | Query-only for real services, creates own test service, localhost-only network, automatic cleanup |
| **Detection Opportunities** | **0.5/1.0** | 6 distinct detection points: service queries, service control, process creation, tool execution |
| **Logging & Observability** | **0.5/1.0** | Full Schema v2.0 logging, JSON and text output, command output capture |

**Key Strengths**:
- Uses native Windows service control (sc.exe) - realistic TTP
- Optional real offensive tool (NetExec) for advanced testing
- Safe implementation - never stops real security services
- Multiple service query patterns for detection correlation
- Comprehensive logging with command output capture
- Single-binary deployment with optional tool integration

**Improvement Opportunities**:
- Could add WMI-based service enumeration
- Remote service control simulation (requires additional infrastructure)
- Process injection into service host

## Technical Details

### Attack Flow

1. **Phase 0: Prerequisites Check**
   - Verify Administrator privileges (required for service operations)
   - Exit with code 999 if not running elevated

2. **Phase 1: Setup and Component Extraction**
   - Create `c:\F0\tools\` directory
   - Create test service binary
   - Check for NetExec (nxc.exe) availability

3. **Phase 2: Security Service Query (Safe)**
   - Query WinDefend (Windows Defender)
   - Query wscsvc (Windows Security Center)
   - Query VSS (Volume Shadow Copy)
   - Query wbengine (Windows Backup Engine)
   - **Note**: Query-only, no stop commands issued

4. **Phase 3: Test Service Operations**
   - Create `F0RTIKA_TestSvc` service
   - Stop the test service
   - Delete the test service
   - Track if operations blocked by EDR

5. **Phase 4: Taskkill Access Check**
   - Verify taskkill.exe accessibility
   - Query-only (taskkill /?)

6. **Phase 5: NetExec SMB Enumeration (Optional)**
   - If nxc.exe present in `c:\F0\tools\`
   - Execute: `nxc smb 127.0.0.1 -u test -p test --services`
   - Localhost-only with dummy credentials

7. **Phase 6: Cleanup**
   - Remove test service if still exists
   - Remove test service binary
   - Preserve tools directory for reuse

### Key Indicators

**Process Creation:**
- `sc.exe query <service>`
- `sc.exe create F0RTIKA_TestSvc...`
- `sc.exe stop F0RTIKA_TestSvc`
- `sc.exe delete F0RTIKA_TestSvc`
- `taskkill.exe /?`
- `nxc.exe smb 127.0.0.1 --services` (if present)

**Service Operations:**
- Service enumeration for security-related services
- Test service lifecycle (create, stop, delete)

**Network Indicators (NetExec only):**
- SMB connection to 127.0.0.1:445
- Service enumeration over SMB

## Detection Opportunities

1. **Service Query Correlation**
   - Multiple sc query commands for security services in short time window
   - Behavioral pattern: WinDefend + wscsvc + VSS queries together
   - Command line analysis: service names associated with security

2. **Service Control Operations**
   - sc create with binPath parameter
   - sc stop operations
   - sc delete operations
   - Service control targeting newly created service

3. **Process Execution Chain**
   - Parent process spawning multiple sc.exe instances
   - Sequential service queries followed by service control

4. **Tool Execution**
   - NetExec/nxc.exe execution
   - Known offensive tool hash/signature
   - Command line containing `--services` flag

5. **SMB Activity**
   - Local SMB connections from suspicious process
   - Service enumeration via SMB protocol

6. **Behavioral Patterns**
   - Service enumeration followed by control operations
   - Multiple security service queries in sequence
   - Test service creation followed by immediate deletion

## Expected Results

### Unprotected System (Code 101)
- All service queries complete successfully
- Test service create/stop/delete operations succeed
- Taskkill accessible
- NetExec (if present) executes without blocking
- All security services return status (RUNNING/STOPPED)

### Protected System - Execution Prevented (Code 126)
- Service queries blocked with "Access Denied"
- Service creation prevented by EDR
- NetExec execution blocked
- Clear indication of security control intervention

### Error - Insufficient Privileges (Code 999)
- Test not running as Administrator
- Service operations fail due to privilege requirements
- Test exits early with clear error message

## References

- [MITRE ATT&CK T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [NetExec GitHub Repository](https://github.com/Pennyw0rth/NetExec)
- [Microsoft sc.exe Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query)
- [LockBit Ransomware Analysis](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a)
- [Conti Ransomware TTP Analysis](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a)

## Behavioral Detection Queries

For Microsoft Sentinel/Defender detection rules, see:
- Service enumeration: Multiple `sc query` for security service names
- Service control: `sc stop|delete` operations
- Tool execution: NetExec/nxc.exe process creation
- Correlation: Service queries followed by service control operations

## Enhancement Notes

**Version 1.0.0** (2025-01-11):
- Initial implementation with safe service query patterns
- Test service lifecycle (create/stop/delete)
- Optional NetExec integration for SMB enumeration testing
- Schema v2.0 compliant logging
- Comprehensive safety mechanisms
