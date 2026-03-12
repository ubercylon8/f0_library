# Cyber Hygiene - Configuration Validation Test Suite

This folder contains security tests that validate **endpoint and cloud identity security configurations** and hardening best practices. These tests evaluate whether security controls are properly configured rather than simulating attacks.

## Test Suite Overview

### Endpoint Tests

| # | UUID | Test Name | Techniques |
|---|------|-----------|------------|
| 1 | `05c39526-5374-419f-bf1e-68468400f3c6` | Local Administrator Password Solution (LAPS) Validator | T1078.003, T1021.002, T1550.002 |
| 2 | `19d1d49c-d278-41a3-bfad-8bb318bdde45` | Windows Audit Logging Configuration Validator | (defensive) |
| 3 | `3135f66e-2c50-45ea-9b38-63d78870d16b` | Attack Surface Reduction Rules Validator | T1059.001, T1059.005, T1055, T1566.001 |
| 4 | `35a4ea61-a8b0-4249-9d2a-80e56d6d22e8` | LSASS Protection Validator | T1003.001, T1003.002, T1550.002 |
| 5 | `38539d88-7446-48c0-990b-343d65b12538` | Network Protocol Hardening Validator | T1557.001, T1040, T1557 |
| 6 | `3bb364c5-c25c-4f3b-8934-9f91afead524` | Account Lockout and Password Policy Validator | T1110, T1110.001, T1110.003 |
| 7 | `67165014-0377-4300-8197-ab459bd9249b` | PowerShell Security and Logging Validator | T1059.001, T1027, T1140, T1105 |
| 8 | `742bf5df-ee2c-49ce-a477-1afbde3b6f2c` | Microsoft Defender Configuration Validator | T1562.001, T1562.004, T1070 |
| 9 | `b4b50f92-f19a-4aba-a119-6f0e26d54ba5` | SMB Protocol Hardening Validator | T1021.002, T1570, T1210, T1557 |
| 10 | `bac53a6e-dd97-4764-bb10-2ee605f24808` | CrowdStrike Falcon Configuration Validator | T1562.001, T1562.004, T1070 |
| 11 | `c6d2bdfc-ba48-4811-9f7f-8034855daed3` | Print Spooler Hardening Validator | T1547.012, T1569.002, T1068 |

### CIS Level 1 Bundles

| # | UUID | Test Name | Platform | Controls | Techniques |
|---|------|-----------|----------|----------|------------|
| 12 | `078f1409-9f7b-4492-bb35-3fd596e85ce0` | CIS Windows Endpoint Level 1 Hardening Bundle | Windows | 52 | T1110, T1078.001, T1557.001, T1003.001, T1562.001, T1059.001, T1021.001 |
| 13 | `602a5333-e9cf-4ddf-a132-a22aa7126447` | CIS Identity & Active Directory Level 1 Bundle | Windows | 28 | T1078.002, T1098.001, T1098.003, T1558.003, T1558.004, T1078.004, T1556.007 |
| 14 | `7f0d43e7-8a7b-48f3-9aff-cfa9703a51e8` | CIS Linux Endpoint Level 1 Hardening Bundle | Linux | 35 | T1562.001, T1021.004, T1548.001, T1059.004, T1070.002, T1543.002 |
| 15 | `6d63934b-963f-4e3b-83f5-8166e33eb6da` | CIS macOS Endpoint Level 1 Hardening Bundle | macOS | 22 | T1562.001, T1553.001, T1071.001, T1021.004, T1548.004 |

### Cloud Identity Tests

| # | UUID | Test Name | Techniques |
|---|------|-----------|------------|
| 16 | `4f484076-9816-4813-947e-b76bce3d3f83` | Entra ID Tenant Security Hygiene Bundle | T1078.004, T1556.007, T1110.001, T1098.003, T1098.001, T1566, T1528, T1562.008 |
| 17 | `7659eeba-f315-440e-9882-4aa015d68b27` | Identity Endpoint Posture Bundle | T1078.004, T1556.007, T1556.006, T1528, T1550.001, T1588.004, T1005, T1111 |

## Purpose

Unlike attack simulation tests, **Cyber Hygiene tests validate defensive configurations**:

- Check if security controls are enabled and properly configured
- Validate registry settings, group policies, and service configurations
- Validate cloud identity platform security (Entra ID / Microsoft 365)
- Report gaps in security posture without exploiting them
- Provide remediation guidance for identified issues

## Path Conventions

| Platform | Artifact Type | Path | Reason |
|----------|--------------|------|--------|
| Windows | Test binaries (.exe) | `c:\F0` | Whitelisted - allows execution |
| Windows | Log files | `c:\F0` | Standard location |
| Linux | Test binaries / logs | `/tmp/F0` | Standard location |
| macOS | Test binaries / logs | `/tmp/F0` | Standard location |

## Test Categories

### Credential Protection
- **LAPS Validator** - Validates local admin password randomization
- **LSASS Protection Validator** - Checks Credential Guard and PPL settings

### Endpoint Security
- **Microsoft Defender Configuration Validator** - Verifies Defender settings
- **CrowdStrike Falcon Configuration Validator** - Validates Falcon agent config
- **ASR Rules Validator** - Checks Attack Surface Reduction rules

### Network Hardening
- **SMB Protocol Hardening Validator** - SMBv1 disabled, signing enforced
- **Network Protocol Hardening Validator** - LLMNR, NBT-NS, mDNS settings

### Logging & Audit
- **Windows Audit Logging Validator** - Validates audit policy configuration
- **PowerShell Security Validator** - Script block logging, transcription

### Service Hardening
- **Print Spooler Hardening Validator** - PrintNightmare mitigations
- **Account Lockout Validator** - Password policy and lockout thresholds

### Cloud Identity
- **Entra ID Tenant Security Hygiene Bundle** - CISA SCuBA baseline validation for Entra ID (MFA, Conditional Access, PIM, guest access, app governance)
- **Identity Endpoint Posture Bundle** - Endpoint-level identity hardening (device join, WHfB, MDM enrollment, PRT protection, BitLocker escrow)

### CIS Level 1 Benchmarks
- **CIS Windows Endpoint L1 Bundle** - 52 CIS controls: password policy, account management, network auth, credential protection, firewall, audit logging, endpoint protection (7 validators, multi-binary)
- **CIS Identity & AD L1 Bundle** - 28 CIS controls: privileged accounts, service accounts, auth hardening, AD infrastructure, group policy, Entra ID (6 validators, single-binary)
- **CIS Linux Endpoint L1 Bundle** - 35 CIS controls: filesystem, services, network, audit, SSH, access control, system maintenance (7 validators, multi-binary)
- **CIS macOS Endpoint L1 Bundle** - 22 CIS controls: system preferences, audit, network, access control, endpoint protection (5 validators, multi-binary)

## Build Instructions

```bash
# Build all tests in this suite
for dir in tests_source/cyber-hygiene/*/; do
    ./utils/gobuild build "$dir"
done

# Sign all tests
./utils/codesign sign-all
```

## Expected Results

| Exit Code | Meaning |
|-----------|---------|
| 101 | Configuration gaps found (needs hardening) |
| 126 | All security controls properly configured |
| 999 | Test prerequisites not met |
