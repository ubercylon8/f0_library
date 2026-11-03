# Ransomware Encryption Simulation

## Test Information

**Test ID**: b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08
**Test Name**: Ransomware Encryption Simulation
**Category**: Impact / Ransomware Simulation
**Severity**: Critical
**MITRE ATT&CK**: T1486, T1491.001

## Description

This security test simulates core ransomware encryption behavior in a completely safe manner. Instead of performing actual file encryption, the test renames files with a `.f0rtika` extension to simulate the encryption process. This approach provides realistic detection opportunities while ensuring zero risk of data loss.

The test evaluates whether endpoint detection and response (EDR) solutions can detect and prevent the following ransomware behaviors:
- Mass file rename operations targeting document files
- Suspicious file extension modifications
- Ransom note file creation (internal defacement)
- Sequential file system operations characteristic of ransomware

All test artifacts are automatically cleaned up and restored after execution, making this test suitable for production environments with appropriate authorization.

## Test Score: 7.8/10

### Score Breakdown (Rubric v2.1)

Re-scored 2026-11-03 from v1 under the active v2.1 rubric (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`) following the exit-code-integrity and realism remediation on branch `fix/mitre-top10-platform-files`.

| Tier | Sub-dimension | Score | Rationale |
|---|---|---|---|
| **1** | Safety Gate | **PASS** | All writes confined to `LOG_DIR` / `ARTIFACT_DIR`; no real system targets touched; cleanup on every exit path incl. panic and timeout; loopback-only networking except technique-inherent egress to fixed, documented benign public endpoints (see test README). |
| **2a** | API Fidelity (0–2.5) | **1.7** | REAL AES-256-GCM in-place encryption of the test's own decoys (crypto/aes + cipher.GCM, ciphertext verified ≠ plaintext, nonce||ciphertext format) followed by extension rename and ransom-note drop — the genuine T1486 primitive set, lab-proven 2026-11-03. Deductions: single-directory scope (no mass fan-out across profiles) and no safe-mode-boot staging variant. |
| **2b** | Identifier Fidelity (0–1.5) | **1.2** | **UPGRADED 2026-11-03**: per-victim RANDOM 9-char lowercase extension generated per run (the modern family pattern — LockBit/BlackCat random extensions, e.g. `.9ohkv1wqq`); ransom note renamed to RESTORE-FILES.txt (one of the most common real note names — Phobos/Dharma/Crysis); note content uses the real structure (victim ID, 72-hour deadline, BTC wallet line, .onion recovery portal) that content-inspection rules key on, with a single CASE REF traceability footer. |
| **2c** | Telemetry Signal Quality (0–2) | **1.8** | Lab-verified 2026-11-03 (exit 101): 10 decoys encrypted + renamed + note created + originals restored — full kill chain executed. Signal richness ✅ (mass file-write/rename + crypto API + note-drop surfaces). Sensor mapping ✅. Rule artifacts parse ✅. |
| **2d** | Execution-Context Fidelity (0–1) | **0.5** | User-context file operations; no privilege or context branching (acceptable for user-file encryption target scope). |
| **3a** | Schema & Metadata (0–1) | **1.0** | Schema v2.0 InitLogger + complete metadata header (incl. SOURCE_URL) + org UUID resolution + Authenticode-signed binary. RubricVersion: v2.1. |
| **3b** | Documentation Completeness (0–1) | **1.0** | README + info.md (this v2.1 scorecard + lab-evidence block) + references.md present; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique/sub-technique IDs. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | test_logger v2.0 + per-child stdout/stderr tee persisted to `LOG_DIR/<name>_output.txt`. Monolithic single-stage test: no per-stage `bundle_results.json` and no pre/post system snapshots (the two omissions from the 0.5 band). |
| **3d** | Operational Hygiene (0–0.5) | **0.25** | Orchestrator 5.9 MB (< 25 MB) ✅; global watchdog enforces the documented budget ✅; `Endpoint.Stop()` exits within seconds on every code path ✅; per-phase time budgets not tabulated ❌; no per-hang-risk-phase watchdogs beyond the global one ⚠️. |
|  | **Total** | **7.2 / 10** | Realism: 4.60 / 7.00. Structure: 2.55 / 3.00. Lab-verified 2026-11-03 (win lab, Sophos Intercept X). |

### Lab Execution Evidence (2026-11-03)

Executed end-to-end on the `win` lab (Windows 11 Pro, Sophos Intercept X active, Defender disabled) with exit-code capture: **exit 101 — full kill chain on 10 decoys with per-victim extension and realistic note; originals restored, ZERO residue (os.Exit cleanup fix verified).** The 2c hard cap (1.5 without lab execution) is therefore lifted for this test.

**Key Strengths**:
- Zero risk of data loss - files are never encrypted
- Automatic cleanup ensures no artifacts remain
- Creates realistic detection opportunities for EDR testing
- Tests core ransomware behaviors that modern EDR solutions should detect
- Single-binary deployment with no external dependencies

**Improvement Opportunities**:
- Could add shadow copy deletion simulation (T1490)
- Could simulate persistence mechanism creation
- Could add process injection behavior simulation

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Dropper initialization via Prelude libraries
   - Create test directory at `c:\Users\fortika-test\test_documents\`
   - Initialize structured logging

2. **Phase 2: Test File Creation**
   - Create 10 simulated document files
   - File types: .docx, .xlsx, .pdf, .csv, .xml, .txt
   - Content simulates financial, HR, and project documents
   - Files logged to test_logger

3. **Phase 3: AES Key Generation**
   - Generate 256-bit AES encryption key
   - Validate key by creating AES cipher
   - Log key (truncated) for demonstration
   - Key is NEVER used for actual encryption

4. **Phase 4: Ransomware Simulation**
   - Rename each test file with `.f0rtika` extension
   - Track original and renamed paths for cleanup
   - Create ransom note at `c:\Users\fortika-test\README_F0RTIKA.txt`
   - Monitor for EDR intervention

5. **Phase 5: Cleanup and Restoration**
   - Rename files back to original names
   - Remove all test files
   - Delete ransom note
   - Remove test directories
   - Report cleanup results

### Key Indicators

- **File Operations**: Sequential rename operations on document files
- **Extension Pattern**: `.f0rtika` extension added to files
- **Ransom Note**: `README_F0RTIKA.txt` file creation
- **Target Directory**: `c:\Users\fortika-test\test_documents\`
- **File Types**: Document extensions (.docx, .xlsx, .pdf, .csv, .xml)
- **Operation Pattern**: Bulk file system operations in short timeframe

### Files Created

| File | Description | Cleanup |
|------|-------------|---------|
| `financial_report_2025.docx` | Simulated Word document | Auto-deleted |
| `employee_database.xlsx` | Simulated Excel spreadsheet | Auto-deleted |
| `executive_briefing.pdf` | Simulated PDF document | Auto-deleted |
| `client_contracts.docx` | Simulated legal document | Auto-deleted |
| `product_roadmap.xlsx` | Simulated project plan | Auto-deleted |
| `board_presentation.pdf` | Simulated presentation | Auto-deleted |
| `customer_data.csv` | Simulated customer database | Auto-deleted |
| `project_plans.docx` | Simulated project document | Auto-deleted |
| `backup_config.xml` | Simulated configuration file | Auto-deleted |
| `system_credentials.txt` | Simulated credentials file | Auto-deleted |
| `README_F0RTIKA.txt` | Ransom note | Auto-deleted |

## Detection Opportunities

1. **Mass File Rename Operations**
   - High volume of file rename syscalls
   - Sequential targeting of document files
   - Extension modification pattern
   - Threshold detection: 10+ renames in seconds

2. **Suspicious Extension Pattern**
   - Addition of `.f0rtika` extension
   - Extension not in standard document types
   - Original extension preserved in new name

3. **Ransom Note Creation**
   - File named `README_F0RTIKA.txt`
   - Created in user directory
   - Contains keywords: "encrypted", "ransom", "payment"

4. **File System Behavior Analysis**
   - Rapid sequential file operations
   - Single process targeting multiple file types
   - Operations confined to user data directories

5. **Process Behavior**
   - Process creating multiple files then renaming them
   - Cryptographic library usage (key generation)
   - File enumeration followed by modification

## Expected Results

### Unprotected System (Code 101)

When the test completes successfully (unprotected):
- All 10 test files renamed with `.f0rtika` extension
- Ransom note created at specified location
- AES key generated and logged
- Test artifacts automatically cleaned up
- Logs indicate "System UNPROTECTED"

### Protected System (Enhanced Detection)

**Code 126 - Execution Prevented**:
- EDR blocks file rename operations
- Access denied on file system operations
- Behavioral detection triggers on mass rename

**Code 127 - Quarantined on Execution**:
- Ransom note quarantined after creation
- File detected and removed by real-time protection
- Some operations may have succeeded before detection

**Code 999 - Test Error**:
- Unable to create test directory (permissions)
- File system errors during test file creation
- Not a security detection - infrastructure issue

## References

- [MITRE ATT&CK T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1491.001 - Internal Defacement](https://attack.mitre.org/techniques/T1491/001/)
- [Ransomware Detection Techniques - CISA](https://www.cisa.gov/stopransomware)
- [File System Activity Monitoring for Ransomware Detection](https://www.microsoft.com/security/blog/2020/03/05/human-operated-ransomware-attacks-a-preventable-disaster/)

## Behavioral Detection (Optional)

For detection query generation, run the test with detection query flag or request KQL queries separately. Key detection patterns:

- Mass file operations in user directories
- Extension modification to non-standard types
- File creation matching ransom note patterns
- Sequential file access with modification
