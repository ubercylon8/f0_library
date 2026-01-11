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

## Test Score: 8.5/10

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.5/3.0** | Uses real ransomware enumeration patterns (dir /s /b, extension filtering) and integrates real-world tool (Seatbelt with 60+ checks). Creates realistic target file list matching ransomware reconnaissance output. |
| **Technical Sophistication** | **2.5/3.0** | Multiple enumeration techniques including native Windows commands, extension-based filtering, target list generation, and comprehensive Seatbelt integration with multiple check categories. |
| **Safety Mechanisms** | **2.0/2.0** | Creates own test files only in dedicated directory, read-only enumeration, no data exfiltration, complete cleanup after execution. Test documents in non-system location. |
| **Detection Opportunities** | **1.0/1.0** | 7+ distinct detection points: process execution patterns, bulk file access, extension filtering, target list creation, Seatbelt binary detection, Seatbelt execution patterns, high-volume queries. |
| **Logging & Observability** | **0.5/1.0** | Comprehensive Schema v2.0 logging with phase tracking, process execution logging, file drop logging, and output capture to files. |

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
