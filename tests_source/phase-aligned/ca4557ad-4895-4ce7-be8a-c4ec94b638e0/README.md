# CrackMapExec Detection Test

**Test ID**: `ca4557ad-4895-4ce7-be8a-c4ec94b638e0`

**MITRE ATT&CK**: T1021.002, T1110.003 - SMB Lateral Movement, Password Spraying

**Phase**: 7 - Lateral Movement

**Suite**: lateral-movement-readiness-2026-01

## Overview

This multi-stage test validates detection capabilities for CrackMapExec/NetExec-style attacks, combining password spraying, share enumeration, and remote execution.

## What This Test Does

1. **Stage 1 - Password Spray**: Simulates SMB password spray behavior
2. **Stage 2 - Share Enumeration**: Tests share discovery patterns
3. **Stage 3 - WMI Execution**: Simulates wmiexec command execution
4. **Stage 4 - Artifacts**: Creates detection artifacts

## Detection Opportunities

| Event/Indicator | Source | Description |
|-----------------|--------|-------------|
| Event ID 4625 | Security Log | Multiple failed logons |
| Event ID 4740 | Security Log | Account lockout |
| Event ID 5145 | Security Log | Share access patterns |
| Event ID 4688 | Security Log | WMI process creation |

## Expected Outcomes

- **Exit 126 (Protected)**: 2+ stages blocked
- **Exit 101 (Unprotected)**: CME-style attacks possible

**Test Score**: **8.0/10**
