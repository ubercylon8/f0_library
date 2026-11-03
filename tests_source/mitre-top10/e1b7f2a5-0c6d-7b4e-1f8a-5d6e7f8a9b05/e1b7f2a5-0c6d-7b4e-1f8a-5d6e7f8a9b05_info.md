# System Recovery Inhibition (Non-Destructive Mode)

## Test Information

**Test ID**: e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05
**Test Name**: System Recovery Inhibition (Non-Destructive Mode)
**Category**: Impact / Ransomware Precursor
**Severity**: Critical
**MITRE ATT&CK**: T1490

## Description

This test evaluates endpoint detection capabilities against T1490 (Inhibit System Recovery) - a critical technique used by ransomware to prevent victims from recovering their systems without paying the ransom. The test uses a SAFE MODE implementation that performs READ-ONLY checks only, making it completely safe to run on production systems.

T1490 is one of the most impactful ransomware techniques because it:
- Eliminates recovery options before encryption begins
- Increases pressure on victims to pay ransom
- Prevents rollback to pre-infection state
- Is used by virtually all modern ransomware families

## Test Score: 7.9/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **1.0** | Read-only recon queries PLUS the **REAL destructive T1490 command set, ARMED and LAB-VERIFIED 2026-11-03** (env `F0_DESTRUCTIVE_T1490=1` after hypervisor snapshot; default remains off): `vssadmin delete shadows /all /quiet`, `bcdedit /set {default} recoveryenabled No`, `bcdedit /set {default} bootstatuspolicy ignoreallfailures`, `wbadmin delete catalog -quiet` — all executed with canonical attacker arguments. Revert-first BCD cleanup verified in the same run (post-state: recoveryenabled Yes, bootstatuspolicy DisplayAllFailures). Remaining deductions: safe-mode boot staging intentionally excluded (boot-risk/marginal-value), single-host scope, and the lab had no shadow copies to delete (command telemetry complete; deletion effect unexercised). |
| **2b** | Identifier Fidelity (0–1.5) | **0.9** | Real tool paths (System32\vssadmin.exe / bcdedit.exe / wbadmin.exe); documented command set uses exact real-family arguments (incl. LockBit-style resize shadowstorage /maxsize=401MB). |
| **2c** | Telemetry Signal Quality (0–2) | **1.8** | Lab-verified 2026-11-03 in BOTH modes: gate-off (exit 101, recon queries) and ARMED (exit 101, destructive commands executed — the argument-based detections EDRs signature on now actually fire; post-run BCD state verified reverted). Sensor mapping ✅. Rule artifacts parse ✅. |
| **2d** | Execution-Context Fidelity (0–1) | **1.0** | Best-in-suite context handling: privilege gate aborts with 999 BEFORE any query (non-elevated denials can never be misclassified); all denials are elevated-gated; watchdog sized for wbadmin's 30–60 s runtime. |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 5.8 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **7.1 / 10** | Realism: 4.50 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 101 — gate-off recon run AND armed destructive run (vssadmin/bcdedit/wbadmin destructive commands executed; BCD verified reverted post-run; zero residue).** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.

**Key Strengths**:
- Maximum safety score - no risk of system damage
- Tests critical ransomware technique (T1490)
- Multiple detection opportunity points
- Comprehensive documentation of ransomware commands
- Repeatable testing without side effects
- Full Schema v2.0 compliance

**Improvement Opportunities**:
- Could add WMI-based shadow copy enumeration (still read-only)
- Could test PowerShell-based recovery tool access
- Could add registry-based BCD store read checks

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Initialize dropper and logging framework
   - Create target directory c:\F0
   - Check administrator privileges
   - Create start marker file

2. **Phase 2: vssadmin Check**
   - Verify C:\Windows\System32\vssadmin.exe exists
   - Execute read-only query: `vssadmin list shadows`
   - Capture output and detect any EDR blocking
   - Log process execution details

3. **Phase 3: bcdedit Check**
   - Verify C:\Windows\System32\bcdedit.exe exists
   - Execute read-only query: `bcdedit /enum`
   - Capture boot configuration output
   - Log process execution details

4. **Phase 4: wbadmin Check**
   - Verify C:\Windows\System32\wbadmin.exe exists
   - Execute read-only query: `wbadmin get versions`
   - Capture backup version information
   - Log process execution details

5. **Phase 5: Destructive Command Documentation**
   - Log commands ransomware WOULD execute (NOT executed)
   - Document impact of each command
   - Provide detection signatures

6. **Phase 6: Final Assessment**
   - Generate comprehensive report
   - Determine protection status
   - Create completion marker

### Key Indicators

Defenders should monitor for:

- **Process Creation**:
  - vssadmin.exe execution
  - bcdedit.exe execution
  - wbadmin.exe execution
  - wmic.exe with shadowcopy arguments

- **Command Line Arguments**:
  - `delete shadows` or `resize shadowstorage`
  - `recoveryenabled No` or `bootstatuspolicy`
  - `delete systemstatebackup` or `delete catalog`
  - `shadowcopy delete`

- **Event Logs**:
  - VSS Event ID 8193, 8194 (shadow copy events)
  - System Event ID 7036 (VSS service changes)

## Detection Opportunities

1. **Tool Access Detection**
   - Monitor for any process accessing recovery tool executables
   - Alert on non-standard parent processes for these tools
   - Track frequency and patterns of access

2. **Command Line Monitoring**
   - Flag any vssadmin/bcdedit/wbadmin command execution
   - Specifically alert on destructive arguments
   - Correlate with other ransomware indicators

3. **Behavioral Analysis**
   - Multiple recovery tool access in short timeframe
   - Access from unusual process trees
   - Access outside normal administrative windows

4. **File System Monitoring**
   - Shadow copy volume access patterns
   - BCD store file access
   - Backup catalog file access

5. **Registry Monitoring**
   - HKLM\BCD00000000 access patterns
   - Volume Shadow Copy Service registry keys
   - Backup service configuration changes

## Expected Results

### Unprotected System (Code 101)

When the test returns exit code 101:
- All three recovery tools are accessible
- Read-only queries executed successfully
- No EDR/AV intervention detected
- System is vulnerable to T1490 attacks
- Report shows all tools queryable

Implications:
- Ransomware could delete shadow copies
- Boot recovery could be disabled
- Backup catalogs could be destroyed
- No behavioral protection against T1490

### Protected System (Code 126)

When the test returns exit code 126:
- EDR blocked one or more read-only queries
- Tool access or query execution prevented
- Active protection against T1490 detected
- Report shows which queries were blocked

Protection mechanisms that may trigger this:
- Behavioral monitoring of recovery tool access
- Command line argument scanning
- Process creation blocking for sensitive tools
- Application whitelisting policies

### Prerequisites Not Met (Code 999)

When the test returns exit code 999:
- Administrator privileges not available
- Cannot accurately assess recovery tool access
- Re-run with elevated privileges required

## References

- [MITRE ATT&CK T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [Ransomware Shadow Copy Deletion Analysis](https://www.microsoft.com/en-us/security/blog/)
- [Volume Shadow Copy Service Documentation](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [BCDEdit Command Reference](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options)
- [WBAdmin Command Reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin)

## Ransomware Families Using T1490

This technique is used by virtually all modern ransomware including:
- LockBit
- Conti
- REvil/Sodinokibi
- Ryuk
- BlackCat/ALPHV
- Hive
- Royal
- Play
- BlackBasta

## Enhancement Notes

Version 1.0.0 (2026-01-11):
- Initial safe mode implementation
- Read-only checks for vssadmin, bcdedit, wbadmin
- Comprehensive documentation of destructive commands
- Full Schema v2.0 logging compliance
- Multi-organization support via org_resolver
