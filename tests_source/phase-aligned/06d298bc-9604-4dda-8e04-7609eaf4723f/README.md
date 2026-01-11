# SMB Lateral Movement Detection Test

**Test ID**: `06d298bc-9604-4dda-8e04-7609eaf4723f`

**MITRE ATT&CK**: T1021.002 - SMB/Windows Admin Shares

**Phase**: 7 - Lateral Movement

**Suite**: lateral-movement-readiness-2026-01

## Overview

This test validates detection capabilities for SMB-based lateral movement, including PsExec-style service creation and admin share access.

## What This Test Does

1. **Admin Share Check**: Tests accessibility of C$, ADMIN$ shares
2. **Service Creation Simulation**: Simulates PsExec service creation pattern
3. **Artifact Creation**: Creates detection artifacts mimicking PsExec/smbexec

## Detection Opportunities

| Event/Indicator | Source | Description |
|-----------------|--------|-------------|
| Event ID 7045 | System Log | New service installed |
| Event ID 5145 | Security Log | Admin share access |
| Event ID 4624 Type 3 | Security Log | Network logon |

## Expected Outcomes

- **Exit 126 (Protected)**: Admin shares inaccessible, service creation blocked
- **Exit 101 (Unprotected)**: Lateral movement via SMB possible

**Test Score**: **7.8/10**
