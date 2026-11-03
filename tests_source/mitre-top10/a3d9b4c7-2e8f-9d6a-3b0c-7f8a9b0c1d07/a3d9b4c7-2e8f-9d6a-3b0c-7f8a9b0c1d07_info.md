# Pre-Encryption File Enumeration

## Test Information

**Test ID**: a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07
**Test Name**: Pre-Encryption File Enumeration
**Category**: Discovery / Collection
**Severity**: High
**MITRE ATT&CK**: T1083, T1119, T1082

## Description

This test simulates pre-encryption reconnaissance behavior commonly observed in ransomware attacks. Modern ransomware operators perform extensive file discovery before initiating encryption to:

1. **Identify high-value targets**: Documents, databases, backups, and financial records
2. **Estimate attack scope**: Total file count and data volume for ransom calculation
3. **Prioritize encryption order**: Encrypt most valuable files first
4. **Avoid detection**: Understand system layout to avoid security tool directories

The test includes optional integration with **Seatbelt**, a comprehensive host security enumeration tool that performs 60+ security checks. When Seatbelt is available, the test evaluates EDR detection of advanced enumeration tooling.

## Test Score: 8.2/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **1.8** | Real cmd.exe dir /s /b recursive enumeration with 17 extension filters (exact pre-encryption recon form) plus Go filepath.Walk target-list generation. **UPGRADED 2026-11-03: REAL Seatbelt now EMBEDDED** (built from pinned source GhostPack@392171df, net472, 585 KB, sha256 ee09f12b…3800e; build-tag `seatbelt`, see build_all.sh) and executed with its canonical arguments (-group=all; WindowsCredentialFiles WindowsVault InterestingFiles). |
| **2b** | Identifier Fidelity (0–1.5) | **1.2** | Real user-profile directories enumerated at runtime (C:\Users\*\Documents, Desktop — live identifiers); realistic decoy document names; target extensions match real ransomware victim-file profiles. |
| **2c** | Telemetry Signal Quality (0–2) | **2.0** | **EMPIRICALLY verified 2026-11-03: Sophos Intercept X BLOCKED both embedded Seatbelt executions** (positive denial evidence; exit 126) — the tool's signals are demonstrably detectable. Native enumeration phases also reached with persisted output. Signal richness ✅, sensor mapping ✅, rule artifacts parse ✅. |
| **2d** | Execution-Context Fidelity (0–1) | **0.6** | Admin probe gates denial classification. Read-only enumeration is context-portable; no deeper branching. |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 5.9 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **7.7 / 10** | Realism: 5.10 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 126 — embedded Seatbelt extracted, executed, and BLOCKED by Sophos Intercept X on both invocations (positive evidence); native enumeration phases succeeded.** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.


### Key Strengths

- **Real Tool Integration**: Seatbelt provides 60+ real security checks commonly used by threat actors
- **Authentic Enumeration Patterns**: Uses actual ransomware reconnaissance techniques
- **Comprehensive Coverage**: Tests both native Windows enumeration and advanced tooling
- **Non-Whitelisted Path**: Test documents created in `c:\Users\fortika-test\test_documents\` (EDR detects operations)
- **Complete Safety**: Read-only operations, own test files, full cleanup

### Improvement Opportunities

- Could add WMI-based enumeration queries
- Could integrate additional enumeration tools (e.g., SharpShares)
- Could add network share enumeration patterns

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Initialize test environment
   - Create target directory structure
   - Verify prerequisites

2. **Phase 2: Test Document Creation**
   - Create test documents in `c:\Users\fortika-test\test_documents\`
   - Files include: financial_report_2024.docx, customer_database.db, quarterly_earnings.xlsx, backup_config.bak, etc.
   - Realistic filenames matching ransomware targets

3. **Phase 3: Recursive File Enumeration**
   - Execute `cmd /c dir /s /b` style enumeration
   - Capture all files in test directory recursively
   - Log file count and execution time
   - Save raw output to `dir_enumeration_output.txt`

4. **Phase 4: Extension-Based Filtering**
   - Filter files by ransomware-targeted extensions
   - Target extensions: .docx, .xlsx, .pdf, .db, .sql, .bak, .doc, .xls, .ppt, etc.
   - Log matching file count per extension

5. **Phase 5: Target List Generation**
   - Walk file system using Go's filepath.Walk
   - Generate target list with file paths and sizes
   - Format matches ransomware pre-encryption output
   - Save to `target_list.txt`

6. **Phase 6: Seatbelt -group=all** (PLACEHOLDER)
   - Load Seatbelt from `c:\F0\tools\Seatbelt.exe`
   - Execute comprehensive enumeration (60+ checks)
   - Capture output to `seatbelt_groupall_output.txt`
   - Detect quarantine or execution blocking

7. **Phase 7: Seatbelt Credential Checks** (PLACEHOLDER)
   - Execute Seatbelt WindowsCredentialFiles, WindowsVault, InterestingFiles
   - Target credential storage locations
   - Capture output to `seatbelt_credentials_output.txt`

8. **Phase 8: Final Assessment**
   - Generate enumeration summary
   - Determine protection status
   - Cleanup all test artifacts

### Key Indicators

- **Process Creation**: cmd.exe with /s /b flags for recursive listing
- **File Access Patterns**: Bulk file enumeration in short timeframe
- **Extension Filtering**: Multiple targeted extension searches
- **Target List File**: Creation of file listing with paths and sizes
- **Seatbelt Binary**: Known GhostPack tool signature
- **Seatbelt Arguments**: -group=all, WindowsCredentialFiles, etc.
- **High-Volume Queries**: Aggressive file system enumeration

### Target Extensions

The test filters for extensions commonly targeted by ransomware:

| Category | Extensions |
|----------|------------|
| Documents | .docx, .doc, .pdf, .txt |
| Spreadsheets | .xlsx, .xls, .csv |
| Presentations | .ppt, .pptx |
| Databases | .db, .sql, .mdb, .accdb, .sqlite |
| Backups | .bak |
| Data Files | .json, .xml |

## Detection Opportunities

1. **Process Execution Monitoring**
   - cmd.exe with recursive enumeration flags (/s /b)
   - High-frequency process creation for enumeration
   - Seatbelt.exe execution with any arguments

2. **File System Activity**
   - Bulk file access in non-user directories
   - Enumeration of multiple directories in rapid succession
   - Access to sensitive file locations (credential stores, backups)

3. **Behavioral Patterns**
   - Extension-based filtering (multiple dir commands with wildcards)
   - Target list file creation with file paths and sizes
   - Pre-encryption reconnaissance patterns

4. **Tool Detection**
   - Seatbelt.exe binary signature
   - GhostPack tool family indicators
   - Known offensive security tool hashes

5. **Network/System Queries**
   - WMI queries for system information
   - Registry access for security configuration
   - Credential store enumeration

## Expected Results

### Unprotected System (Code 101)

- All enumeration phases complete successfully
- Test documents enumerated without detection
- Target list file created with file paths and sizes
- Seatbelt executes without blocking (if available)
- No security alerts generated
- Pre-encryption reconnaissance successful

### Protected System (Enhanced Detection)

- **Code 105**: Seatbelt.exe quarantined on extraction by AV/EDR
- **Code 126**: EDR blocks aggressive enumeration patterns or Seatbelt execution
- **Code 999**: Test prerequisites not met (directory creation failed)

Specific detection trigger points:
- Recursive dir enumeration with bulk file access
- Extension-based filtering patterns
- Target list file creation
- Seatbelt binary detection
- Seatbelt execution blocking
- High-volume file system queries

## References

- [MITRE ATT&CK T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE ATT&CK T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)
- [MITRE ATT&CK T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [GhostPack Seatbelt Repository](https://github.com/GhostPack/Seatbelt)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)
- [Conti Ransomware TTPs](https://www.cisa.gov/uscert/ncas/alerts/aa21-265a)
- [BlackCat/ALPHV Ransomware Analysis](https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/)

## Seatbelt Tool Reference

Seatbelt is a C# project that performs numerous security-oriented host-survey safety checks. When executed with `-group=all`, it performs 60+ checks including:

- **User Checks**: CurrentUser, DomainInfo, LocalGroups, etc.
- **System Checks**: EnvironmentVariables, OSInfo, Processes, Services
- **Credential Checks**: WindowsCredentialFiles, WindowsVault, DPAPIMasterKeys
- **Security Checks**: AppLocker, Defender settings, Firewall rules
- **Browser Checks**: Chrome, Firefox, IE history and credentials
- **Network Checks**: DNS cache, Network shares, ARP cache

This comprehensive enumeration mirrors advanced threat actor reconnaissance.

## Enhancement Notes

**Version 1.0.0** (2026-01-11):
- Initial implementation with file enumeration patterns
- Seatbelt placeholder integration
- Schema v2.0 compliance
- 7+ detection opportunities
