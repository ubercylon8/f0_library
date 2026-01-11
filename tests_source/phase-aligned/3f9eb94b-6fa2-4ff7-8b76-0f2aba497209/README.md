# Pass-the-Ticket Detection Test

**Test ID**: `3f9eb94b-6fa2-4ff7-8b76-0f2aba497209`

**MITRE ATT&CK**: T1550.003 - Pass the Ticket

**Phase**: 7 - Lateral Movement

**Suite**: lateral-movement-readiness-2026-01

## Overview

This test validates detection capabilities for Pass-the-Ticket attacks, where attackers inject stolen Kerberos tickets to authenticate.

## What This Test Does

1. **Ticket Enumeration**: Lists current cached Kerberos tickets
2. **Injection Simulation**: Tests LSA/Kerberos access patterns
3. **Artifact Creation**: Creates .kirbi simulation files

## Detection Opportunities

| Event/Indicator | Source | Description |
|-----------------|--------|-------------|
| Event ID 4768 | Security Log | TGT request anomalies |
| Event ID 4769 | Security Log | TGS request after injection |
| .kirbi files | File System | Ticket export artifacts |

## Expected Outcomes

- **Exit 126 (Protected)**: LSA access protected by Credential Guard
- **Exit 101 (Unprotected)**: Ticket injection possible

**Test Score**: **7.8/10**
