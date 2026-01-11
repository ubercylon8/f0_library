# Kerberoasting Detection Test

**Test ID**: `6ded8b8c-046c-491f-bc7d-85bcc762fae7`

**MITRE ATT&CK**: T1558.003 - Kerberoasting

**Phase**: 7 - Lateral Movement

**Suite**: lateral-movement-readiness-2026-01

## Overview

This test validates detection capabilities for Kerberoasting attacks, where attackers request Kerberos TGS service tickets for accounts with Service Principal Names (SPNs) and crack them offline to obtain plaintext passwords.

## What This Test Does

1. **SPN Enumeration**: Searches Active Directory for accounts with SPNs (Rubeus/GetUserSPNs.py behavior)
2. **TGS Request Simulation**: Requests Kerberos service tickets for target SPNs
3. **Ticket Export Simulation**: Simulates ticket extraction for offline cracking
4. **Artifact Creation**: Creates detection artifacts mimicking Kerberoast output

## Detection Opportunities

| Event/Indicator | Source | Description |
|-----------------|--------|-------------|
| Event ID 4769 | Security Log | TGS request with encryption type 0x17 (RC4) |
| LDAP SPN Query | DC/EDR | High-volume SPN enumeration |
| Ticket Volume | EDR | Multiple TGS requests in short timeframe |

## Expected Outcomes

- **Exit 126 (Protected)**: Kerberoasting patterns blocked or detected
- **Exit 101 (Unprotected)**: Kerberoasting patterns succeeded without detection

## Remediation

If this test shows UNPROTECTED:
1. Monitor Event ID 4769 for RC4 encryption (0x17)
2. Implement Group Managed Service Accounts (gMSA)
3. Enforce AES256 for all service accounts
4. Deploy honeypot SPNs for detection
5. Regular password rotation for service accounts

**Test Score**: **7.8/10**
