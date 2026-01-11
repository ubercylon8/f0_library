# Kerberoasting Detection Test

## Test Information

| Field | Value |
|-------|-------|
| **Test ID** | 6ded8b8c-046c-491f-bc7d-85bcc762fae7 |
| **Test Name** | Kerberoasting Detection Test |
| **MITRE ATT&CK** | T1558.003 - Kerberoasting |
| **Tactic** | Credential Access |
| **Phase** | 7 - Lateral Movement |
| **Suite** | lateral-movement-readiness-2026-01 |
| **Created** | 2026-01-05 |
| **Version** | 1.0.0 |

## Description

Kerberoasting exploits the Kerberos authentication protocol by requesting service tickets for accounts with Service Principal Names (SPNs). These tickets are encrypted with the service account's password hash and can be cracked offline to obtain plaintext credentials.

## Test Score: 7.8/10

### Score Breakdown

| Criterion | Score |
|-----------|-------|
| **Real-World Accuracy** | **2.8/3.0** |
| **Technical Sophistication** | **2.5/3.0** |
| **Safety Mechanisms** | **1.5/2.0** |
| **Detection Opportunities** | **0.5/1.0** |
| **Logging & Observability** | **0.5/1.0** |

## Attack Simulation Details

### Phase 1: SPN Enumeration
- Queries Active Directory for user accounts with SPNs
- Simulates Rubeus/GetUserSPNs.py reconnaissance

### Phase 2: TGS Request Simulation
- Requests Kerberos TGS tickets for discovered SPNs
- Uses KerberosRequestorSecurityToken API
- Generates Event ID 4769

### Phase 3: Ticket Export Simulation
- Enumerates cached Kerberos tickets via klist
- Simulates ticket export for offline cracking

### Phase 4: Artifact Creation
- Creates files mimicking Rubeus output
- Includes simulated hashcat-format hashes

## Tools Simulated

| Tool | Technique | Description |
|------|-----------|-------------|
| Rubeus | kerberoast | Request and export service tickets |
| Impacket | GetUserSPNs.py | SPN enumeration and roasting |
| PowerSploit | Invoke-Kerberoast | PowerShell kerberoasting |

## Detection Requirements

### Windows Security Events
- **4769**: Kerberos TGS Request (with RC4 encryption = 0x17)
- **4768**: Kerberos TGT Request (pre-authentication)

### Key Indicators
- RC4 encryption in TGS requests (legacy/weak)
- High volume TGS requests from single source
- TGS requests for multiple SPNs rapidly
- Requests for SPNs without subsequent service access

## Protection Mechanisms

| Control | Description | Effectiveness |
|---------|-------------|---------------|
| AES-only Kerberos | Disable RC4 encryption | High |
| gMSA Accounts | Auto-rotating 240-char passwords | Very High |
| Honeypot SPNs | Fake SPNs for detection | Medium |
| Password Length | 25+ char service passwords | High |

## TIBER-EU Mapping

Maps to TIBER-EU Phase 7 credential access techniques.

## References

- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft: Kerberos Authentication](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
