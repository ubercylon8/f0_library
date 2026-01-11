# Pre-Encryption File Enumeration

**Test Score**: **8.5/10**

## Overview

This test simulates pre-encryption reconnaissance behavior commonly observed in ransomware attacks. It evaluates EDR/AV detection capabilities against file and directory discovery techniques used by threat actors to identify valuable targets before initiating encryption routines. The test includes optional Seatbelt integration for comprehensive host security enumeration with 60+ checks.

## MITRE ATT&CK Mapping

- **Tactic**: Discovery, Collection
- **Technique**: T1083 - File and Directory Discovery
- **Technique**: T1119 - Automated Collection
- **Technique**: T1082 - System Information Discovery (via Seatbelt)

## Test Execution

This test performs multiple phases of file enumeration:

1. **Test Document Creation**: Creates test documents in `c:\Users\fortika-test\test_documents\` with realistic filenames
2. **Recursive File Enumeration**: Uses `dir /s /b` style enumeration patterns
3. **Extension-Based Filtering**: Filters files by ransomware-targeted extensions (.docx, .xlsx, .pdf, .db, .sql, .bak)
4. **Target List Generation**: Creates a target list file simulating pre-encryption reconnaissance output
5. **Seatbelt -group=all** (PLACEHOLDER): Comprehensive host enumeration with 60+ security checks
6. **Seatbelt Credential Checks** (PLACEHOLDER): WindowsCredentialFiles, WindowsVault, InterestingFiles

## Seatbelt Integration

This test includes a **PLACEHOLDER** for Seatbelt (GhostPack/Seatbelt) - a comprehensive host security enumeration tool. Seatbelt must be placed in the `tools/` directory before running the test.

See `tools/README.md` for instructions on obtaining and installing Seatbelt.

## Expected Outcomes

- **Protected (Exit 105)**: Seatbelt.exe quarantined on extraction
- **Protected (Exit 126)**: EDR blocks aggressive enumeration or Seatbelt execution
- **Unprotected (Exit 101)**: Enumeration completed, target list created without detection
- **Error (Exit 999)**: Test directory creation failed or prerequisites not met

## Build Instructions

```bash
# Build the test binary
./utils/gobuild build tests_source/mitre-top10/a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07/

# Sign the binary
./utils/codesign sign build/a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07/a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07.exe

# Or use the build-sign-test skill
/build-sign-test a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07
```

## Deployment

1. Deploy the signed binary to `c:\F0\` on the target system
2. (Optional) Place Seatbelt.exe in `c:\F0\tools\` for comprehensive enumeration testing
3. Execute the test binary

```powershell
# On target system
c:\F0\a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07.exe
```

## Safety Features

- Creates own test files only (no modification of existing files)
- Read-only enumeration operations
- No exfiltration of discovered data
- Complete cleanup of all test artifacts after execution
- Test documents created in dedicated test directory (not system directories)

## Detection Opportunities

1. **Process Execution**: cmd.exe with recursive enumeration flags
2. **File System Activity**: Bulk file access patterns
3. **Extension Filtering**: Multiple extension-based searches
4. **Target List Creation**: Writing enumeration results to file
5. **Seatbelt Binary**: Known security tool signature detection
6. **Seatbelt Execution**: Security enumeration tool execution patterns
7. **High-Volume Queries**: Aggressive file system enumeration

## Files Created

| File | Location | Purpose |
|------|----------|---------|
| Test documents | `c:\Users\fortika-test\test_documents\` | Enumeration targets |
| `dir_enumeration_output.txt` | `c:\F0\` | Raw enumeration output |
| `target_list.txt` | `c:\F0\` | Pre-encryption target list |
| `seatbelt_groupall_output.txt` | `c:\F0\` | Seatbelt -group=all output |
| `seatbelt_credentials_output.txt` | `c:\F0\` | Seatbelt credential check output |
| `enumeration_summary.txt` | `c:\F0\` | Test summary |

## References

- [MITRE ATT&CK T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE ATT&CK T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)
- [MITRE ATT&CK T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [GhostPack Seatbelt](https://github.com/GhostPack/Seatbelt)
- [Ransomware Pre-Encryption Behavior Analysis](https://www.cisa.gov/stopransomware)
