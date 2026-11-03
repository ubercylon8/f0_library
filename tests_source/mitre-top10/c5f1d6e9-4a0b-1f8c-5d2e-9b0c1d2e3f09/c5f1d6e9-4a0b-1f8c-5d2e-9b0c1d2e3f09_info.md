# Webshell Post-Exploitation Simulation

## Test Information

**Test ID**: c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09
**Test Name**: Webshell Post-Exploitation Simulation
**Category**: MITRE Top 10 / Initial Access
**Severity**: High
**MITRE ATT&CK**: T1190, T1059.003

## Description

This test simulates the POST-EXPLOITATION phase that occurs after a webshell has been successfully deployed on a compromised web server. Webshells are a critical component in many real-world intrusions, providing attackers with persistent remote access to compromised systems.

The test focuses on two key behaviors:

1. **Reconnaissance Command Execution**: Webshells typically execute a series of discovery commands immediately after deployment to enumerate the compromised system, identify privileges, map the network, and locate security software.

2. **C2 Callback**: Many webshells beacon back to attacker-controlled infrastructure to confirm successful deployment and exfiltrate collected data.

This test does NOT deploy an actual webshell - it simulates the behavior that would occur AFTER deployment to evaluate whether security controls can detect webshell-like activity patterns.

## Test Score: 6.9/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **1.2** | Six real recon binaries (whoami /all, hostname, ipconfig /all, systeminfo, netstat -an, tasklist) in a realistic sequence plus a real TLS beacon POST. Main deduction: NO webshell exists — no script file is dropped and the recon runs as children of the test binary, not of a web-server worker (w3wp.exe → cmd.exe lineage is the defining webshell signal). Real-webshell variant deferred (needs lab web role). |
| **2b** | Identifier Fidelity (0–1.5) | **0.9** | Real recon command arguments; beacon target is a benign public service (httpbin.org) rather than an attacker-style endpoint. |
| **2c** | Telemetry Signal Quality (0–2) | **1.6** | Lab-verified 2026-11-03 (exit 101; 6/6 recon + beacon succeeded). Signal richness ✅ for the recon/beacon surfaces; the webshell-specific surfaces are absent by design. Sensor mapping ✅. Rule artifacts parse ✅. |
| **2d** | Execution-Context Fidelity (0–1) | **0.6** | Admin probe gates denial classification; recon commands are context-portable. Parent-process shape is unrealistic (documented). |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 11 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **6.9 / 10** | Realism: 4.30 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 101 — 6/6 reconnaissance commands and the TLS C2 beacon succeeded.** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.

### Key Strengths

1. **High Real-World Relevance**: Webshells are consistently used in APT and financially-motivated attacks, making this test highly relevant
2. **Multiple Detection Points**: 7+ distinct detection opportunities across recon commands and C2 activity
3. **Native Implementation**: No embedded binaries or external tools - uses only Windows built-in commands
4. **Safe Design**: Read-only commands with harmless C2 endpoint - no risk to target system
5. **Authentic Patterns**: Command selection and sequence mirrors real threat actor behavior
6. **C2 Simulation**: Tests network egress controls in addition to endpoint detection

### Improvement Opportunities

1. Could add PowerShell-based reconnaissance patterns
2. Could simulate file upload/download via webshell
3. Could add directory traversal reconnaissance patterns
4. Could include credential harvesting command simulation

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Create target directory `c:\F0`
   - Initialize Schema v2.0 logging
   - Prepare command execution environment

2. **Phase 2: Reconnaissance Commands**
   - Execute: `whoami /all` (user context enumeration)
   - Execute: `hostname` (system identification)
   - Execute: `ipconfig /all` (network configuration)
   - Execute: `systeminfo` (full system information)
   - Execute: `netstat -an` (network connections)
   - Execute: `tasklist` (running processes)
   - Detection: Process creation, command-line arguments, behavioral patterns

3. **Phase 3: C2 Callback Simulation**
   - HTTP POST to https://httpbin.org/post
   - Payload includes: beacon identifier, hostname, test UUID
   - User-Agent: Standard browser string
   - Detection: Network egress, HTTP POST content, unusual destination

4. **Phase 4: Output and Assessment**
   - Write reconnaissance output to marker file
   - Generate test summary
   - Evaluate protection status
   - Cleanup test artifacts

### Key Indicators

**Process Creation:**
- cmd.exe executions from unusual parent processes
- Rapid succession of whoami, systeminfo, ipconfig commands
- netstat -an and tasklist in command chain

**Command Line Patterns:**
- `whoami /all` - Full user enumeration
- `systeminfo` - Detailed system information
- `ipconfig /all` - Complete network configuration
- `netstat -an` - All connections with numeric addresses
- `tasklist` - Process enumeration

**Network Activity:**
- HTTP POST to external IP/domain
- Beacon-like payload (identifier, hostname)
- Non-standard user-agent patterns

**File System:**
- Creation of output files in `c:\F0`
- Files containing system information

## Detection Opportunities

1. **Process Creation Monitoring**
   - Alert on reconnaissance command sequences
   - Monitor for rapid execution of multiple discovery commands
   - Track parent-child process relationships (e.g., w3wp.exe -> cmd.exe)

2. **Command Line Analysis**
   - Detect `/all` flags on whoami, ipconfig
   - Identify netstat with `-an` parameters
   - Flag systeminfo execution from web server context

3. **Behavioral Correlation**
   - Correlate multiple recon commands in short timeframe (<30 seconds)
   - Associate command execution with network callback
   - Track command chains typical of webshell activity

4. **Network Egress Monitoring**
   - Monitor HTTP POST to external endpoints
   - Inspect payload for reconnaissance data
   - Detect beacon-like patterns (periodic callbacks, identification data)

5. **Web Server Context**
   - Alert on cmd.exe spawned by IIS (w3wp.exe), Apache (httpd), etc.
   - Flag discovery commands from web application context
   - Correlate with web server access logs

6. **File System Activity**
   - Monitor for output files containing system information
   - Detect reconnaissance data staging

## Expected Results

### Unprotected System (Code 101)

When the system is unprotected:
- All six reconnaissance commands execute successfully
- C2 callback completes (HTTP 200 response)
- Reconnaissance output file created in `c:\F0`
- System information collected and (simulated) exfiltrated

### Protected System (Code 126)

When the system has active protection:
- One or more reconnaissance commands blocked
- OR C2 callback blocked by network security
- Blocking may occur via:
  - Process creation prevention
  - Command execution blocking
  - Network egress filtering
  - Behavioral detection

### Network Unavailable (Code 999)

When network is unavailable:
- C2 callback fails due to connectivity (not security)
- Reconnaissance commands may still succeed
- This is environmental, not a security result

## Build Instructions

```bash
# Build the test
cd /home/jimx/F0RT1KA/f0_library
./utils/gobuild build tests_source/mitre-top10/c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09/

# Sign the binary
./utils/codesign sign build/c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09/c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09.exe

# Or use combined build-sign command
/build-sign-test c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09
```

## References

- [MITRE ATT&CK T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1059.003 - Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [Microsoft Security Blog - Web Shell Attacks](https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/)
- [CISA Alert AA20-205A - Web Shells](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-205a)
- [NSA/ASD - Detect and Prevent Web Shell Malware](https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-11 | Initial release with 6 recon commands + C2 callback |

## Size Justification

The compiled orchestrator is ~15 MB (Yellow tier, 10–25 MB): a single Go binary carrying the Schema v2.0 telemetry stack plus six child-process output captures and the TLS C2-beacon client. No .NET runtime or web-server components are embedded.

## Realism constraints

- **No webshell exists in this test**: no script file is dropped and no web-server worker process is exercised. Recon commands run as children of the test binary, so the defining `w3wp.exe -> cmd.exe` lineage is absent (future work; requires a lab web role).
- **C2 beacon** targets the benign public service httpbin.org; a controlled attacker-style endpoint would strengthen network detections.
- **T1190 mapping** denotes the attack stage the recon represents (post-exploitation after a hypothetical public-facing-app compromise), not an executed exploitation step.
