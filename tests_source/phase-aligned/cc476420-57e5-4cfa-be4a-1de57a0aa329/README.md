# WinRM Execution Detection Test

**Test ID**: `cc476420-57e5-4cfa-be4a-1de57a0aa329`

**MITRE ATT&CK**: T1021.006 - Windows Remote Management

**Phase**: 7 - Lateral Movement

**Suite**: lateral-movement-readiness-2026-01

## Overview

This test validates detection capabilities for WinRM-based lateral movement, including Evil-WinRM style connections and PowerShell remoting.

## What This Test Does

1. **WinRM Configuration Check**: Verifies WinRM service and listener status
2. **Connection Simulation**: Tests Evil-WinRM style session creation
3. **Artifact Creation**: Creates detection artifacts

## Detection Opportunities

| Event/Indicator | Source | Description |
|-----------------|--------|-------------|
| Event ID 91 | WinRM Log | Session start |
| Event ID 4648 | Security Log | Explicit credential logon |
| Port 5985/5986 | Network | WinRM connections |

## Expected Outcomes

- **Exit 126 (Protected)**: WinRM disabled or restricted
- **Exit 101 (Unprotected)**: WinRM lateral movement possible

**Test Score**: **7.5/10**
