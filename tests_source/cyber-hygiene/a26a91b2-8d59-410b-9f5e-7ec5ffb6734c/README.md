# ISACA ITGC AD Identity Validation Bundle

**Test UUID**: `a26a91b2-8d59-410b-9f5e-7ec5ffb6734c`
**Test Score**: **8.5/10** (rubric v2.1 — pending lab verification)
**Subcategory**: `isaca-itgc-ad-identity`
**Target**: Active Directory (any domain-joined Windows host with RSAT)

## Overview

Validates 3 ISACA ITGCs that require Active Directory queries. Companion to the ISACA ITGC Windows Endpoint bundle (`db0738eb-...`); together they cover the on-prem identity ITGCs in the ISACA spec. Cloud identity (AM-006 MFA) lives in the Entra Tenant bundle (`4f484076-...`).

## Controls

| ITGC ID | Control | Evidence |
|---|---|---|
| **ITGC-AM-003** | Dormant Account Detection | Get-ADUser w/ lastLogonTimestamp ≥ N days (configurable via `ITGC_DORMANT_DAYS`, default 90); excludes service-account OU patterns. |
| **ITGC-AM-004** | Service Account Permissions Audit | SPN holders cross-referenced against privileged groups (Domain/Enterprise/Schema Admins, Account/Backup Operators) + password-never-expires flag. |
| **ITGC-NS-003** | LAPS Deployment Validation | Schema check (legacy `ms-Mcs-AdmPwd` OR Windows LAPS `msLAPS-Password`) + ≥80% computer-object coverage. |

## Output

- `c:\F0\bundle_results.json` — standard F0RT1KA fan-out for PA ingestion
- `c:\F0\itgc_evidence_ITGC-AM-003.json`, `...AM-004.json`, `...NS-003.json` — per-control auditor sidecars
- `c:\F0\itgc_audit_workpaper.json` — aggregated auditor evidence pack

## Prerequisites

- Windows host **domain-joined** to the AD forest you want to audit
- **RSAT ActiveDirectory PowerShell module** installed
- Network access to a domain controller (LDAP / AD Web Services)
- Read-only AD account (Domain Users is sufficient for most queries; for LAPS password reads, the account needs `Read ms-Mcs-AdmPwd` delegation OR `msLAPS-Password` permission on the relevant OUs — though this bundle only checks for **presence** of the attribute, not the password value)

The bundle is read-only; no AD modifications are made.

## Configuration

| Env Var | Default | Purpose |
|---|---|---|
| `ITGC_DORMANT_DAYS` | 90 | Days of inactivity threshold for AM-003 |

## Build & Deploy

```bash
cd tests_source/cyber-hygiene/a26a91b2-8d59-410b-9f5e-7ec5ffb6734c/
mkdir -p build/a26a91b2-8d59-410b-9f5e-7ec5ffb6734c/
GOOS=windows GOARCH=amd64 go build -o build/.../a26a91b2-...exe .

# from repo root, sign with F0RT1KA cert
../../../utils/codesign sign tests_source/cyber-hygiene/a26a91b2-.../build/a26a91b2-.../a26a91b2-...exe
```

## Architecture

Single-binary (vs. the Windows Endpoint bundle's multi-binary model). Reason: all three controls share an AD/LDAP session via `RunADCommand` (PowerShell `Import-Module ActiveDirectory`), and there's no quarantine-resilience benefit to splitting them since they're not invoking distinct attack-surface APIs.

## Framework Coverage

- **CISA 2024 ECO domain**: D5 (Protection of Information Assets)
- **COBIT 2019**: DSS05.04 Manage Identity and Logical Access
- **CIS Controls v8**: 5.2 (Unique Passwords), 5.3 (Disable Dormant), 5.4 (Restrict Admin)
- **MITRE ATT&CK**: T1078.001, T1078.002, T1078.003, T1558.003

## Companion Bundles

- `db0738eb-848e-442b-b43c-208029063fe9` — ISACA ITGC Windows Endpoint (31 controls)
- `4f484076-9816-4813-947e-b76bce3d3f83` — Entra Tenant (with ITGC-AM-006 MFA)

Together: 35/35 ITGCs from the ISACA spec.
