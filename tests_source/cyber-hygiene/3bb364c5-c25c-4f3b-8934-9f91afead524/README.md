# Account Lockout and Password Policy Validator

**Test Score**: **7.5/10**

## Overview

This cyber-hygiene test validates that Windows account lockout and password policies are properly configured according to CIS Level 1 benchmarks to prevent brute force attacks. Microsoft reports blocking 7,000 password attacks per second - proper account lockout policies are essential for defense.

## MITRE ATT&CK Mapping

- **Tactic**: Credential Access
- **Techniques**:
  - T1110 - Brute Force
  - T1110.001 - Password Guessing
  - T1110.003 - Password Spraying

## Test Execution

This is a **READ-ONLY** configuration validation test that:
1. Queries account lockout policies using `net accounts`
2. Queries password complexity using `secedit /export`
3. Validates 5 policy settings against CIS Level 1 thresholds
4. Reports compliance status and remediation guidance

### Policy Checks

| Check | Method | CIS L1 Compliant Value |
|-------|--------|------------------------|
| Lockout Threshold | `net accounts` | 1-5 attempts (0 = disabled = FAIL) |
| Lockout Duration | `net accounts` | >= 15 minutes |
| Reset Counter After | `net accounts` | >= 15 minutes |
| Minimum Password Length | `net accounts` | >= 14 characters |
| Password Complexity | `secedit export` | Enabled (1) |

## Expected Outcomes

- **126 (COMPLIANT/Protected)**: All 5 policy checks pass CIS Level 1 thresholds
- **101 (NON-COMPLIANT/Vulnerable)**: One or more policy checks fail
- **999 (Test Error)**: Insufficient privileges or query failure

## Prerequisites

- Windows operating system
- Administrator privileges (required to query account policies)

## Build Instructions

```bash
# Build single binary
./utils/gobuild build tests_source/cyber-hygiene/3bb364c5-c25c-4f3b-8934-9f91afead524/

# Sign the binary
./utils/codesign sign build/3bb364c5-c25c-4f3b-8934-9f91afead524/3bb364c5-c25c-4f3b-8934-9f91afead524.exe
```

## CIS Benchmark References

- CIS Controls v8: 5.2 (Use Unique Passwords), 6.3 (Require MFA for Remote Access)
- CIS Windows Benchmarks:
  - 1.1.1: Enforce password history
  - 1.1.4: Minimum password length
  - 1.1.5: Password complexity requirements
  - 1.2.1: Account lockout duration
  - 1.2.2: Account lockout threshold
  - 1.2.3: Reset account lockout counter

## Remediation

If the test reports NON-COMPLIANT, run the following commands as Administrator:

```cmd
net accounts /lockoutthreshold:5
net accounts /lockoutduration:15
net accounts /lockoutwindow:15
net accounts /minpwlen:14
```

For password complexity, use Group Policy:
1. Open `gpedit.msc`
2. Navigate to: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy
3. Enable "Password must meet complexity requirements"

## References

- [MITRE ATT&CK - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Security Blog - Password Attack Statistics](https://www.microsoft.com/security/blog/)
