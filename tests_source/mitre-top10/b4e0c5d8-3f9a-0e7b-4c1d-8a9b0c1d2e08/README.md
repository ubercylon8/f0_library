# Ransomware Encryption (Safe Mode)

**Test Score**: **8.5/10**

## Overview

This test simulates ransomware encryption behavior using a SAFE implementation that renames files with a `.f0rtika` extension instead of actually encrypting them. The test evaluates EDR capabilities to detect and prevent core ransomware behaviors including mass file operations, file extension modification, and ransom note creation. All test files are automatically restored after execution, making this completely safe for production environments.

## MITRE ATT&CK Mapping

- **Tactic**: Impact
- **Technique**: T1486 - Data Encrypted for Impact
- **Sub-technique**: T1491.001 - Internal Defacement (ransom note)

## Test Execution

The test simulates ransomware encryption behavior by:
1. Creating simulated document files (Word, Excel, PDF, CSV, XML)
2. Generating an AES-256 encryption key (logged but never used)
3. Renaming files with `.f0rtika` extension (simulates encryption)
4. Creating a ransom note in the test directory
5. Automatically cleaning up all artifacts

## Safety Features

- **NO actual encryption** - Files are only renamed, content remains intact
- **Self-created files only** - Never touches existing user data
- **Automatic cleanup** - All test artifacts removed after execution
- **Isolated directory** - Operations confined to `c:\Users\fortika-test\`
- **Reversible operations** - Files can be manually renamed back if needed

## Expected Outcomes

| Exit Code | Status | Description |
|-----------|--------|-------------|
| **126** | Protected | EDR blocks file rename or ransom note creation |
| **101** | Unprotected | Simulation completed, files renamed, ransom note created |
| **999** | Error | Test file creation failed |
| **127** | Quarantined | Ransom note quarantined after creation |

## Detection Opportunities

1. **Mass File Rename Operations** - Bulk file extension changes
2. **Suspicious Extension** - `.f0rtika` extension pattern
3. **Ransom Note Creation** - `README_F0RTIKA.txt` file creation
4. **File System Behavior** - Sequential file operations pattern
5. **Directory Targeting** - Operations in user documents path

## Build Instructions

```bash
# Standard build (from project root)
cd tests_source/mitre-top10/b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08
./build_all.sh --org sb

# Or use gobuild utility
./utils/gobuild build tests_source/mitre-top10/b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08/
./utils/codesign sign build/b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08/b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08.exe
```

## Files Created During Execution

| File | Location | Purpose |
|------|----------|---------|
| Test documents | `c:\Users\fortika-test\test_documents\` | Simulated target files |
| Ransom note | `c:\Users\fortika-test\README_F0RTIKA.txt` | Defacement artifact |
| Execution log | `c:\F0\test_execution_log.json` | Test results |

## References

- [MITRE ATT&CK T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1491.001 - Internal Defacement](https://attack.mitre.org/techniques/T1491/001/)
