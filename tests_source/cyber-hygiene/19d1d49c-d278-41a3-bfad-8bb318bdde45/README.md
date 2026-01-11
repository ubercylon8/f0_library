# Windows Audit Logging Configuration Validator

**Test Score**: **8.0/10**

## Overview

Validates that critical Windows audit logging categories are properly configured for incident detection and forensics. NSA/CISA's Top 10 Misconfigurations identifies "insufficient internal network monitoring" as a critical gap. This test verifies compliance with CIS Benchmark recommendations for Windows audit policy configuration.

## MITRE ATT&CK Mapping

This is a **defensive/cyber-hygiene** test that validates logging configurations which enable detection of virtually all attack techniques. Proper audit logging is foundational for:
- **Credential Attacks** (T1110, T1078) - Detected via Credential Validation and Logon auditing
- **Privilege Escalation** (T1068, T1134) - Detected via Sensitive Privilege Use and Special Logon auditing
- **Persistence** (T1098, T1136) - Detected via User Account Management and Security Group Management auditing
- **Execution** (T1059, T1204) - Detected via Process Creation and Command Line auditing
- **Defense Evasion** (T1562) - Detected via Security State Change auditing

## Configuration Checks

The test validates **9 critical audit subcategories**:

| # | Subcategory | Required Setting | CIS Reference |
|---|-------------|------------------|---------------|
| 1 | Credential Validation | Success and Failure | 17.1.1 |
| 2 | Security Group Management | Success | 17.2.5 |
| 3 | User Account Management | Success and Failure | 17.2.6 |
| 4 | Logon | Success and Failure | 17.5.1 |
| 5 | Special Logon | Success | 17.5.6 |
| 6 | Sensitive Privilege Use | Success and Failure | 17.7.1 |
| 7 | Security State Change | Success | 17.7.3 |
| 8 | Process Creation | Success | 17.8.1 |
| 9 | Command Line Auditing | Registry = 1 | 17.9.1 |

## Test Execution

This is a **read-only** configuration validation test. It does not modify any system settings.

```bash
# Build the test
./utils/gobuild build tests_source/cyber-hygiene/19d1d49c-d278-41a3-bfad-8bb318bdde45/

# Sign the test
./utils/codesign sign build/19d1d49c-d278-41a3-bfad-8bb318bdde45/19d1d49c-d278-41a3-bfad-8bb318bdde45.exe

# Deploy and execute on Windows target (requires Administrator)
```

## Expected Outcomes

| Exit Code | Status | Description |
|-----------|--------|-------------|
| **126** | COMPLIANT | All 9 audit categories properly configured |
| **101** | NON-COMPLIANT | One or more audit categories not properly configured |
| **999** | ERROR | Test error (insufficient privileges) |

## GPO Configuration Path

```
Computer Configuration > Windows Settings > Security Settings >
Advanced Audit Policy Configuration > Audit Policies
```

## References

- [NSA/CISA Top 10 Cybersecurity Misconfigurations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a)
- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Advanced Audit Policy Settings](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq)
