# AS-REP Roasting Detection Test

**Test ID**: `711cbe27-87d7-41ce-8eb7-a31ca311d876`

**MITRE ATT&CK**: T1558.004 - AS-REP Roasting

**Phase**: 7 - Lateral Movement

**Suite**: lateral-movement-readiness-2026-01

## Overview

This test validates detection capabilities for AS-REP Roasting attacks, where attackers request Kerberos AS-REP responses for accounts that have Kerberos pre-authentication disabled, then crack these offline.

## What This Test Does

1. **Pre-Auth Enumeration**: Searches for accounts with DONT_REQUIRE_PREAUTH flag
2. **AS-REP Request Simulation**: Simulates requests for accounts without pre-auth
3. **Artifact Creation**: Creates detection artifacts mimicking Rubeus/GetNPUsers output

## Detection Opportunities

| Event/Indicator | Source | Description |
|-----------------|--------|-------------|
| Event ID 4768 | Security Log | TGT request with PreAuthType=0 |
| Event ID 4771 | Security Log | Kerberos pre-authentication failure |
| LDAP Query | DC/EDR | Enumeration of userAccountControl |

## Expected Outcomes

- **Exit 126 (Protected)**: AS-REP Roasting patterns blocked or detected
- **Exit 101 (Unprotected)**: AS-REP Roasting patterns succeeded

## Remediation

If this test shows UNPROTECTED:
1. Audit and remove DONT_REQUIRE_PREAUTH flag
2. Monitor Event ID 4768 with PreAuthType=0
3. Enforce pre-authentication for all accounts
4. Implement strong passwords for necessary exceptions

**Test Score**: **7.5/10**
