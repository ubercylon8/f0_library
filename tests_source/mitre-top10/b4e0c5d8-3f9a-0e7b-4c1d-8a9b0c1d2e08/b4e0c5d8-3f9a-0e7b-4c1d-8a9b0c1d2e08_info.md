# Ransomware Encryption (Safe Mode)

## Test Information

**Test ID**: b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08
**Test Name**: Ransomware Encryption (Safe Mode)
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

## Test Score: 8.5/10

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.5/3.0** | Simulates realistic ransomware patterns including file targeting by extension, AES key generation, mass file operations, and ransom note creation. Uses actual file system operations that trigger real EDR heuristics. Does not simulate actual encryption or communicate with C2. |
| **Technical Sophistication** | **2.5/3.0** | Implements cryptographic key generation (AES-256), multi-phase attack simulation, file system operations targeting multiple document types, and comprehensive state tracking. Native implementation without external tools. |
| **Safety Mechanisms** | **2.0/2.0** | Full safety implementation: no actual encryption, only file rename operations, automatic cleanup and restoration, isolated test directory, defer-based cleanup even on errors/panics. Files remain fully readable throughout. |
| **Detection Opportunities** | **1.0/1.0** | Multiple distinct detection points: mass file operations, extension changes, ransom note creation, directory enumeration, file rename syscalls, suspicious file patterns. |
| **Logging & Observability** | **0.5/1.0** | Comprehensive test_logger with Schema v2.0, phase tracking, file operation logging, execution timing. Could be enhanced with more detailed syscall logging. |

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
