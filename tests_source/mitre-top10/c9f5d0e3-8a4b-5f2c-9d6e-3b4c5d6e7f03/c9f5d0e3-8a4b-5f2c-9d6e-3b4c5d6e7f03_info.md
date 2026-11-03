# RDP Lateral Movement Simulation

## Test Information

**Test ID**: c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03
**Test Name**: RDP Lateral Movement Simulation
**Category**: Lateral Movement / Credential Access
**Severity**: High
**MITRE ATT&CK**: T1021.001, T1555.004

## Description

This test evaluates EDR/AV detection capabilities against Remote Desktop Protocol (RDP) lateral movement techniques. RDP is consistently ranked among the most frequently abused remote access methods by threat actors, ransomware operators, and advanced persistent threats (APTs) for lateral movement within compromised networks.

The test simulates both reconnaissance activities (service status checks, session enumeration) and credential manipulation patterns (cmdkey operations) that attackers use to prepare for and execute RDP-based lateral movement. Additionally, the test includes a placeholder for SharpRDP, a headless RDP command execution tool used by red teams and threat actors.

## Test Score: 7.9/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **1.5** | Real recon chain (sc query TermService, reg query of Terminal Server keys, qwinsta) plus the real cmdkey tradecraft (list discovery + /generic:TERMSRV/... staging + immediate delete). No RDP protocol implementation — SharpRDP is the executable form and is runtime-optional. |
| **2b** | Identifier Fidelity (0–1.5) | **1.2** | Real registry key paths (fDenyTSConnections, WinStations\RDP-Tcp\UserAuthentication, PortNumber), real service name (TermService), real credential namespace (TERMSRV/). Placeholder host/user values are generic. |
| **2c** | Telemetry Signal Quality (0–2) | **1.8** | Lab-verified 2026-11-03 (exit 101; native phases reached). Signal richness ✅ (sc.exe/reg.exe/qwinsta.exe/cmdkey.exe process + registry telemetry). Sensor mapping ✅. Rule artifacts parse ✅ (two YAML syntax bugs in _dr_rules.yaml fixed 2026-11-03). SharpRDP phase skipped per Lab-Bound Observability. |
| **2d** | Execution-Context Fidelity (0–1) | **0.8** | Admin probe gates denial classification; RDP-listener prerequisites (TermService running + fDenyTSConnections) gate the SharpRDP phase — doomed executions are skipped honestly. |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 5.9 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **7.9 / 10** | Realism: 5.30 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 101 — cmdkey /list + /generic:TERMSRV staging ran; SharpRDP skipped (tool absent, RDP prerequisites not met).** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.

### Lab-Bound Observability (v2.1 §2c criterion 4)

**Phases affected:** SharpRDP execution (Phase 6).

**Cause:** runtime-optional external tool not provided (`c:\F0\tools\`) and/or technique prerequisites not met on the lab host (documented in the phase log as explicit `skipped` — never counted as success or block). This is the designed degradation path for tool-optional tests, not a test deficiency: all native phases reached terminal status in the same run. Providing the tool (and, for Kerberos phases, a domain-joined host) re-enables the phase without rebuild.

**Key Strengths**:
- Real tool potential with SharpRDP integration (attacker-grade tooling)
- Uses actual cmdkey credential manipulation (T1555.004)
- Multiple native Windows commands for realistic reconnaissance
- Comprehensive safety mechanisms (local-only, immediate cleanup)
- 5+ distinct detection opportunities across phases

**Improvement Opportunities**:
- Could add network-level RDP connection simulation (mock connections)
- Integration with additional RDP tools (xfreerdp, rdesktop patterns)
- More extensive credential enumeration patterns

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Create target directory at c:\F0
   - Initialize logging and dropper

2. **Phase 2: RDP Service Status Check**
   - Execute: `sc query TermService`
   - Determine if RDP service is running
   - This is a prerequisite check for meaningful test results

3. **Phase 3: RDP Registry Configuration**
   - Query: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
   - Check fDenyTSConnections (RDP enabled/disabled)
   - Check UserAuthentication (NLA requirement)
   - Check PortNumber configuration

4. **Phase 4: Session Enumeration**
   - Execute: `qwinsta` (Query Session)
   - Enumerate active RDP sessions
   - Save output for analysis
   - Detection point for session reconnaissance

5. **Phase 5: Cmdkey Credential Manager Manipulation**
   - Execute: `cmdkey /add:TESTSERVER /user:testuser /pass:testpass123!`
   - Immediately execute: `cmdkey /delete:TESTSERVER`
   - Tests T1555.004 (Credentials from Password Stores)
   - Safe operation - no persistent credentials

6. **Phase 6: SharpRDP Execution (if present at runtime)**
   - Load SharpRDP.exe from c:\F0\tools\ at runtime (NOT embedded; skipped when RDP prerequisites are not met)
   - Check for quarantine on extraction
   - Execute: `SharpRDP computername=localhost command=whoami`
   - Safe local-only execution

7. **Phase 7: Final Assessment**
   - Generate summary report
   - Determine protection status
   - Clean up artifacts

### Key Indicators

- `sc.exe` querying TermService
- `reg.exe` accessing Terminal Server registry keys
- `qwinsta.exe` session enumeration
- `cmdkey.exe` with /add and /delete arguments
- `SharpRDP.exe` binary presence and execution
- Credential Manager registry access
- RDP-related registry key enumeration

## Detection Opportunities

1. **Service Query Detection**
   - Process: sc.exe
   - Arguments: query TermService
   - Detection: Service enumeration for remote services

2. **Registry Access Detection**
   - Process: reg.exe
   - Keys: Terminal Server, RDP-Tcp
   - Detection: Configuration reconnaissance

3. **Session Enumeration Detection**
   - Process: qwinsta.exe
   - Detection: RDP session reconnaissance
   - High-fidelity indicator in non-admin contexts

4. **Credential Manager Manipulation**
   - Process: cmdkey.exe
   - Arguments: /add, /delete
   - Detection: Credential storage manipulation (T1555.004)
   - High-value behavioral indicator

5. **Malicious Tool Detection**
   - File: SharpRDP.exe
   - Detection: Known offensive tool signature
   - Behavioral: RDP API calls without GUI

6. **Process Chain Analysis**
   - Parent: Test binary
   - Children: sc.exe, reg.exe, qwinsta.exe, cmdkey.exe, SharpRDP.exe
   - Detection: Suspicious process lineage

## Expected Results

### Unprotected System (Code 101)

- sc query TermService executes successfully
- Registry queries return configuration data
- qwinsta enumeration completes without blocking
- cmdkey credential manipulation succeeds
- SharpRDP executes (if present at runtime) without detection
- All patterns indicate unmonitored RDP reconnaissance

### Protected System (Enhanced Detection)

- **Code 105**: SharpRDP.exe quarantined immediately on file extraction
  - Indicates strong file-based AV/EDR detection
  - SharpRDP signature detection active

- **Code 126**: Execution prevention occurred
  - cmdkey manipulation blocked by behavioral controls
  - SharpRDP execution prevented by EDR
  - qwinsta enumeration blocked (less common)
  - Indicates active monitoring of lateral movement indicators

- **Code 999**: RDP service not running
  - Test incomplete due to missing prerequisites
  - TermService not available for testing

## References

- [MITRE ATT&CK - T1021.001: Remote Services - Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK - T1555.004: Credentials from Password Stores - Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004/)
- [SharpRDP - Headless RDP Tool](https://github.com/0xthirteen/SharpRDP)
- [Microsoft Documentation - Remote Desktop Services](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/)

## Tool Integration

### SharpRDP Placeholder

This test includes a placeholder for SharpRDP, a C# tool that enables headless RDP command execution without spawning a full graphical RDP session. This technique is highly valued by threat actors for:

- Stealthy command execution over RDP
- Bypassing interactive session requirements
- Reduced network footprint compared to full RDP sessions

See `tools/README.md` for instructions on obtaining SharpRDP (runtime-loaded from `c:\F0\tools\`, not embedded).

## Enhancement Notes

- v1.0.0 (2026-01-11): Initial release with native commands and SharpRDP placeholder
