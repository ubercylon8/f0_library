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

## Test Score: 8.2/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **1.7** | Real SCM lifecycle on the test's own service: sc create with a genuine service-protocol binary (snmptrap.exe) → sc start → poll to RUNNING → sc stop → re-query corroboration (Bug Prevention Rule 5 pattern implemented). Kill-list queries use sc query only. NetExec (the remote SMB form) is runtime-optional. Deduction: no remote/multi-host service stop. |
| **2b** | Identifier Fidelity (0–1.5) | **1.2** | Real service names in the kill list including the lab's LIVE EDR services (CSFalconService, Sophos Endpoint Defense Service, McsAgent/McsClient — some report NOT_FOUND by design); real SCM syntax (binPath=, type= own, start= demand). |
| **2c** | Telemetry Signal Quality (0–2) | **1.8** | Lab-verified 2026-11-03 (exit 101): full lifecycle create → RUNNING → stop → corroborated STOPPED; kill-list queries executed. Signal richness ✅ (SCM/service-control telemetry + tamper-protection surface). Sensor mapping ✅. Rule artifacts parse ✅. NetExec phase skipped per Lab-Bound Observability. |
| **2d** | Execution-Context Fidelity (0–1) | **0.9** | Strong context handling: hard admin prerequisite (999 abort), degraded-mode lifecycle when the service handshake fails (1053) — never counted as verified; tamper-protection evidence is never masked by own-service success. |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 5.9 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **8.2 / 10** | Realism: 5.60 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 101 — verified stop lifecycle (create → RUNNING → stop → re-query-corroborated).** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.

### Lab-Bound Observability (v2.1 §2c criterion 4)

**Phases affected:** NetExec SMB service enumeration (Phase 5).

**Cause:** runtime-optional external tool not provided (`c:\F0\tools\`) and/or technique prerequisites not met on the lab host (documented in the phase log as explicit `skipped` — never counted as success or block). This is the designed degradation path for tool-optional tests, not a test deficiency: all native phases reached terminal status in the same run. Providing the tool (and, for Kerberos phases, a domain-joined host) re-enables the phase without rebuild.

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
