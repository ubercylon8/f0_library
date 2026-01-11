# Phase-Aligned - DORA/TIBER-EU Pentest Readiness Test Suite

This folder contains security tests organized by **penetration testing phases** aligned with DORA (Digital Operational Resilience Act) and TIBER-EU (Threat Intelligence-Based Ethical Red Teaming) frameworks.

## Test Suite Overview

| # | UUID | Test Name | Technique | Phase |
|---|------|-----------|-----------|-------|
| 1 | `06d298bc-9604-4dda-8e04-7609eaf4723f` | SMB Lateral Movement Detection Test | T1021.002 | Lateral Movement |
| 2 | `1a5895fa-f9b2-4d35-a11b-b4c9e40373a0` | NTLM Relay Detection Test | T1557.001 | Credential Access |
| 3 | `3f9eb94b-6fa2-4ff7-8b76-0f2aba497209` | Pass-the-Ticket Detection Test | T1550.003 | Credential Access |
| 4 | `6ded8b8c-046c-491f-bc7d-85bcc762fae7` | Kerberoasting Detection Test | T1558.003 | Credential Access |
| 5 | `711cbe27-87d7-41ce-8eb7-a31ca311d876` | AS-REP Roasting Detection Test | T1558.004 | Credential Access |
| 6 | `9156e3ca-7524-4263-bb5c-bf161bd1ee21` | Pass-the-Hash Detection Test | T1550.002 | Credential Access |
| 7 | `ca4557ad-4895-4ce7-be8a-c4ec94b638e0` | CrackMapExec Detection Test | T1021.002, T1110.003 | Lateral Movement |
| 8 | `cc476420-57e5-4cfa-be4a-1de57a0aa329` | WinRM Execution Detection Test | T1021.006 | Lateral Movement |

## Purpose

Phase-Aligned tests support **DORA Article 25/26 compliance** and TIBER-EU threat-led penetration testing by:

- Validating detection capabilities for each pentest phase
- Generating evidence for regulatory compliance
- Identifying gaps before actual red team engagements
- Providing remediation roadmaps for detected gaps

## Pentest Phases Covered

### Credential Access
- **Kerberoasting** - Service ticket extraction for offline cracking
- **AS-REP Roasting** - Pre-authentication disabled account attacks
- **Pass-the-Hash** - NTLM hash reuse attacks
- **Pass-the-Ticket** - Kerberos ticket reuse attacks
- **NTLM Relay** - Authentication relay attacks

### Lateral Movement
- **SMB Lateral Movement** - PsExec-style remote execution
- **WinRM Execution** - PowerShell remoting abuse
- **CrackMapExec** - Multi-protocol lateral movement tool

## Path Conventions

| Artifact Type | Path | Reason |
|--------------|------|--------|
| Test binaries (.exe) | `c:\F0` | Whitelisted - allows execution |
| Embedded tools | `c:\F0` | Same as above |
| Log files | `c:\F0` | Standard location |

## DORA/TIBER-EU Alignment

| Framework | Article/Phase | Coverage |
|-----------|---------------|----------|
| DORA | Article 25 | ICT risk management testing |
| DORA | Article 26 | Threat-led penetration testing |
| TIBER-EU | Threat Intelligence | Technique selection |
| TIBER-EU | Red Team Testing | Attack simulation |
| TIBER-EU | Blue Team Assessment | Detection validation |

## Build Instructions

```bash
# Build all tests in this suite
for dir in tests_source/phase-aligned/*/; do
    ./utils/gobuild build "$dir"
done

# Sign all tests
./utils/codesign sign-all
```

## Suite Artifacts

When run as a complete suite, the following artifacts are generated:

| File | Purpose |
|------|---------|
| `*_coverage_matrix.md` | Technique coverage documentation |
| `*_gap_analysis.md` | Identified detection gaps |
| `*_metadata.json` | Dashboard visualization data |
| `*_dora_evidence.md` | DORA Article 25/26 compliance evidence |
| `*_remediation_roadmap.md` | Prioritized gap remediation |

## Expected Results

| Exit Code | Meaning |
|-----------|---------|
| 101 | Attack succeeded - detection gap identified |
| 105 | File/binary quarantined |
| 126 | Execution blocked - detection working |
| 999 | Test prerequisites not met |

## Related Documentation

- `pentesting/agentic_pentest.md` - DORA/TIBER-EU pentest methodology
- `pentesting/PENTEST_READINESS_GUIDE.md` - Pentest readiness builder usage
- Use `@agent-pentest-readiness-builder` for suite generation
