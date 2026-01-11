# NTLM Relay Detection Test

**Test ID**: `1a5895fa-f9b2-4d35-a11b-b4c9e40373a0`

**MITRE ATT&CK**: T1557.001 - LLMNR/NBT-NS Poisoning

**Phase**: 7 - Lateral Movement

**Suite**: lateral-movement-readiness-2026-01

## Overview

This test validates detection and prevention of NTLM relay attacks, including LLMNR/NBT-NS poisoning (Responder) and credential relay (ntlmrelayx).

## What This Test Does

1. **Protocol Configuration Check**: Verifies LLMNR, NetBIOS, and SMB signing settings
2. **Poisoning Detection Simulation**: Tests for LLMNR/NBT-NS response behavior
3. **Artifact Creation**: Creates detection artifacts mimicking Responder output

## Detection Opportunities

| Event/Indicator | Source | Description |
|-----------------|--------|-------------|
| LLMNR Queries | Network | Multicast queries to 224.0.0.252 |
| SMB Traffic | Network | NTLM auth without prior DNS resolution |
| Event ID 4648 | Security Log | Explicit credential use |

## Expected Outcomes

- **Exit 126 (Protected)**: LLMNR/NBT-NS disabled, SMB signing required
- **Exit 101 (Unprotected)**: Relay-vulnerable configuration

**Test Score**: **7.8/10**
