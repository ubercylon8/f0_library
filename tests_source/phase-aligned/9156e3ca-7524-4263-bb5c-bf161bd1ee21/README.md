# Pass-the-Hash Detection Test

**Test ID**: `9156e3ca-7524-4263-bb5c-bf161bd1ee21`

**MITRE ATT&CK**: T1550.002 - Pass the Hash

**Phase**: 7 - Lateral Movement

**Suite**: lateral-movement-readiness-2026-01

## Overview

This test validates detection capabilities for Pass-the-Hash (PTH) attacks, a technique where attackers use stolen NTLM password hashes to authenticate to systems without needing the plaintext password.

## What This Test Does

1. **NTLM Hash Pattern Simulation**: Creates artifacts matching PTH credential patterns
2. **LSASS Access Pattern**: Simulates LSA connections (what Mimikatz does)
3. **Network Logon Simulation**: Attempts LOGON32_LOGON_NEW_CREDENTIALS (Type 9) logon
4. **SMB Authentication Pattern**: Simulates Impacket-style SMB authentication
5. **Security Event Detection**: Checks for generated security events

## Detection Opportunities

| Event/Indicator | Source | Description |
|-----------------|--------|-------------|
| Event ID 4624 Type 9 | Security Log | NewCredentials logon (PTH indicator) |
| Event ID 4648 | Security Log | Explicit credential logon |
| LSASS Access | EDR/Sysmon | Process accessing LSASS memory |
| NTLM Authentication | Network | NTLM auth from unusual sources |

## Expected Outcomes

- **Exit 126 (Protected)**: PTH patterns blocked by Credential Guard, LSA Protection, or EDR
- **Exit 101 (Unprotected)**: PTH patterns succeeded without detection

## Remediation

If this test shows UNPROTECTED:
1. Enable Windows Credential Guard
2. Enable LSA Protection (RunAsPPL)
3. Audit NTLM usage with Group Policy
4. Monitor Event ID 4624 Type 9 logons
5. Deploy EDR with PTH detection

**Test Score**: **7.5/10**
