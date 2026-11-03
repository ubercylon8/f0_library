# Local Account Enumeration

## Test Information

**Test ID**: b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02
**Test Name**: Local Account Enumeration
**Category**: Credential Access / Account Discovery
**Severity**: High
**MITRE ATT&CK**: T1078.003, T1087.001, T1558.003

## Description

This security test simulates local account enumeration techniques that adversaries commonly use during reconnaissance and credential access phases of an attack. The test evaluates EDR detection capabilities against both native Windows enumeration commands and advanced Kerberos abuse tools (Rubeus).

The test covers three key MITRE ATT&CK techniques:
- **T1078.003 (Valid Accounts: Local Accounts)**: Understanding local account context
- **T1087.001 (Account Discovery: Local Account)**: Enumerating local users and groups
- **T1558.003 (Kerberoasting)**: Targeting service accounts for offline credential cracking

This combination reflects real-world attack patterns where adversaries first enumerate accounts using native tools, then escalate to Kerberos-based attacks for credential theft.

## Test Score: 8.0/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **1.5** | Real native enumeration binaries (net user, net localgroup administrators, whoami /all, wmic useraccount list brief) with exact attacker argument sets; real Rubeus CLI (kerberoast /outfile /opsec, asreproast /format:hashcat) when the tool is provided. No direct Win32 SAM/LSA API calls — process-creation tradecraft only. |
| **2b** | Identifier Fidelity (0–1.5) | **1.2** | Enumerates REAL local accounts/groups at runtime (net user output = live identifiers); real service/CLI flags. Rubeus phases gated on real domain-join detection. |
| **2c** | Telemetry Signal Quality (0–2) | **1.8** | Lab-verified 2026-11-03 (exit 101; native phases reached). Signal richness ✅ (net.exe/whoami.exe/wmic.exe process + WMI telemetry). Sensor mapping ✅. Rule artifacts parse ✅. Rubeus phases skipped per Lab-Bound Observability (tool absent + standalone host). |
| **2d** | Execution-Context Fidelity (0–1) | **0.9** | Runtime context detection: admin probe gates denial classification; domain-join detection gates the Kerberos phases with explicit skip logging (standalone hosts produce honest skips, not fake success). |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 5.8 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **8.0 / 10** | Realism: 5.40 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 101 — 2 native patterns succeeded; wmic benign-skipped; Rubeus phases skipped (no domain, no tool).** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.

### Lab-Bound Observability (v2.1 §2c criterion 4)

**Phases affected:** Rubeus kerberoast (Phase 6) and Rubeus asreproast (Phase 7).

**Cause:** runtime-optional external tool not provided (`c:\F0\tools\`) and/or technique prerequisites not met on the lab host (documented in the phase log as explicit `skipped` — never counted as success or block). This is the designed degradation path for tool-optional tests, not a test deficiency: all native phases reached terminal status in the same run. Providing the tool (and, for Kerberos phases, a domain-joined host) re-enables the phase without rebuild.

**Key Strengths**:
- Combines native Windows commands with real offensive tooling (Rubeus)
- Tests multiple ATT&CK techniques in a single execution
- Optional tool loading allows testing with or without Rubeus (runtime-loaded from `c:\F0\tools\` — not embedded)
- Domain-joined hosts are auto-detected: on standalone hosts the Rubeus phases skip explicitly; a failed kerberoast/asreproast run is classified as a benign operational failure (never as attack success, never as a block)
- Read-only operations ensure safety
- Comprehensive output capture for forensic analysis

**Improvement Opportunities**:
- Could add PowerShell-based enumeration (Get-LocalUser, Get-LocalGroupMember)
- Could implement additional Rubeus operations (tgtdeleg, s4u)
- Domain-joined environment testing for full Kerberoasting simulation

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Dropper initialization
   - Target directory creation (c:\F0)
   - Logger setup with Schema v2.0 compliance

2. **Phase 2: Net User Enumeration (T1087.001)**
   - Executes `net user` command
   - Captures list of all local user accounts
   - Output saved to `net_user_output.txt`

3. **Phase 3: Admin Group Enumeration (T1087.001)**
   - Executes `net localgroup administrators`
   - Identifies accounts with local admin privileges
   - Output saved to `net_localgroup_admins_output.txt`

4. **Phase 4: User Context Discovery (T1078.003)**
   - Executes `whoami /all`
   - Reveals current user privileges, group memberships, SIDs
   - Output saved to `whoami_all_output.txt`

5. **Phase 5: WMI Account Enumeration (T1087.001)**
   - Executes `wmic useraccount list brief`
   - Alternative enumeration method using WMI
   - Output saved to `wmic_useraccount_output.txt`

6. **Phase 6: Rubeus Kerberoasting (T1558.003) [Optional]**
   - Loads Rubeus.exe from `c:\F0\tools\` if available
   - Executes `Rubeus kerberoast /outfile:hashes.txt /opsec`
   - Requests TGS tickets for SPN-enabled accounts
   - Output saved to `rubeus_kerberoast_output.txt`

7. **Phase 7: Rubeus AS-REP Roasting (T1558.003) [Optional]**
   - Executes `Rubeus asreproast /format:hashcat`
   - Targets accounts without Kerberos pre-authentication
   - Output saved to `rubeus_asreproast_output.txt`

8. **Phase 8: Final Assessment**
   - Aggregates results across all phases
   - Generates comprehensive summary
   - Determines protection status based on blocked patterns

### Key Indicators

- **Process Creation**: net.exe, whoami.exe, wmic.exe, Rubeus.exe
- **Command Line Patterns**:
  - `net user`
  - `net localgroup administrators`
  - `whoami /all`
  - `wmic useraccount list brief`
  - `Rubeus kerberoast`
  - `Rubeus asreproast`
- **File System Activity**:
  - Creation of Rubeus.exe in c:\F0\
  - Output files in c:\F0\
  - Hash output files from Kerberoasting
- **Network Activity**:
  - Kerberos TGS-REQ requests (TCP 88)
  - AS-REQ requests without pre-authentication

## Detection Opportunities

1. **Native Command Monitoring**
   - net.exe spawned with 'user' or 'localgroup' arguments
   - whoami.exe with '/all' flag
   - wmic.exe querying useraccount class
   - Process tree analysis (parent process identification)

2. **Offensive Tool Detection**
   - Rubeus.exe file signature (hash-based)
   - Rubeus.exe behavioral signatures
   - Known command line patterns for Rubeus
   - Process creation from c:\F0\ directory

3. **Kerberos Activity Monitoring**
   - High volume of TGS-REQ requests in short time
   - TGS requests for rarely-used SPNs
   - AS-REQ without pre-authentication data
   - Kerberos ticket encryption type anomalies

4. **Command Line Analysis**
   - Pattern matching on enumeration commands
   - Frequency analysis of recon commands
   - Correlation of multiple enumeration methods

## Expected Results

### Unprotected System (Code 101)

- All native enumeration commands execute successfully
- Rubeus executes without quarantine (if available)
- Kerberoast/ASREProast operations complete
- Full output files generated in c:\F0\
- Summary shows 0 blocked patterns, 4-6 successful patterns

### Protected System (Enhanced Detection)

- **Code 105**: Rubeus.exe quarantined on extraction - AV detected offensive tool signature
- **Code 126**: One or more enumeration commands blocked - EDR detected suspicious patterns
  - Native command blocking indicates advanced behavioral detection
  - Rubeus execution blocking indicates process-level protection
- **Code 999**: Insufficient privileges or test error - prerequisites not met

## References

- [MITRE ATT&CK T1078.003 - Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- [MITRE ATT&CK T1087.001 - Account Discovery: Local Account](https://attack.mitre.org/techniques/T1087/001/)
- [MITRE ATT&CK T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Rubeus - GhostPack Kerberos Toolset](https://github.com/GhostPack/Rubeus)
- [Kerberoasting Detection](https://adsecurity.org/?p=2293)
- [AS-REP Roasting](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)

## Tool Placement

To enable Rubeus testing, place `Rubeus.exe` in `c:\F0\tools\` on the target system before running the test. See `tools/README.md` for detailed instructions on obtaining and placing Rubeus.

## Enhancement Notes

- **Version 1.0.0** (2026-01-11): Initial release with native enumeration and Rubeus placeholder
- Future versions may add:
  - PowerShell-based enumeration (Get-LocalUser)
  - Additional Rubeus operations (tgtdeleg, s4u, harvest)
  - Domain controller-aware Kerberoasting
  - LDAP-based enumeration
