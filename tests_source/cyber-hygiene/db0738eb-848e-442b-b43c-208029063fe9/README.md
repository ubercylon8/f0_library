# ISACA ITGC Windows Endpoint Validation Bundle

**Test UUID**: `db0738eb-848e-442b-b43c-208029063fe9`
**Test Score**: **8.5/10** (rubric v2.1 — pending lab verification)
**Subcategory**: `isaca-itgc-windows`
**Target**: Windows 10/11, Windows Server 2019/2022

## Overview

Validates 31 IT General Controls (ITGCs) defined in the ISACA ITGC Validation Bundle for CISA-credentialed auditors. Each control produces auditor-ready JSON evidence (ITGC ID + CISA domain + COBIT 2019 objective + CIS v8 mapping + MITRE ATT&CK + actual values + manual residual procedures) plus an aggregated workpaper file.

The bundle implements 7 multi-binary validators (one per ITGC control family) for quarantine resilience — if AV/EDR quarantines one validator, the rest still execute.

## Status

**Phase 2.5b milestone (2026-04-25)**: **31 of 31 controls** implemented + signed multi-binary build pipeline verified (orchestrator + 7 validators signed with F0RT1KA cert, orchestrator 24 MB).

| Family | Controls in scope | Implemented | Status |
|---|---|---|---|
| Access Management (AM) | AM-001, AM-002, AM-005 | 3/3 | full |
| Change Management (CM) | CM-001..005 | 5/5 | full |
| Logging & Monitoring (LM) | LM-001..005 | 5/5 | full |
| Endpoint Protection (EP) | EP-001..006 | 6/6 | full |
| Backup & Recovery (BR) | BR-001..003 | 3/3 | full |
| Network Security (NS) | NS-001, NS-002, NS-004 | 3/3 | full |
| Governance & Policy (GV) | GV-001..006 | 6/6 | full |
| **TOTAL** | **31** | **31** | **full** |

> **Note** — AM-006 (MFA Enrollment) is in the companion `4f484076-...` Entra Tenant bundle. AM-003, AM-004, NS-003 (LAPS) are deferred to the planned AD Identity bundle (separate UUID, runs on DC/mgmt host with RSAT).

Companion bundles (planned):
- ISACA ITGC AD Identity Bundle (UUID TBD) — covers AM-001 (local admin inv), AM-003 (dormant accts), AM-004 (service accts), NS-003 (LAPS) on a DC / mgmt server
- AM-006 MFA Enrollment lifted into existing Entra ID Tenant bundle (`4f484076-...`)

## Output

Bundle writes three things to `c:\F0\`:

1. **`bundle_results.json`** — standard F0RT1KA per-control fan-out for PA ingestion
2. **`itgc_evidence_<control_id>.json`** — one per control, ISACA workpaper schema
3. **`itgc_audit_workpaper.json`** — aggregated auditor evidence pack with all 31 controls

## Framework Coverage

- **CISA 2024 ECO domains**: D2 (Governance), D4 (Operations & Resilience), D5 (Protection of Information Assets)
- **COBIT 2019 objectives**: APO13.01, BAI06.01, BAI09.01, DSS01.05, DSS04.01, DSS05.01-07
- **CIS Controls v8**: 1.1, 4.1, 4.3, 4.8, 5.2-5.4, 7.4, 8.2-8.11, 10.1-10.7, 11.2
- **MITRE ATT&CK**: T1078, T1110, T1078.001, T1562.001, T1562.004, T1059.001, T1021.001, T1490, T1486, T1003.001, T1070.001, T1070.006, T1053.005, T1210, T1021.006

## Build & Deploy

```bash
./build_all.sh                       # Build + sign all 7 validators + orchestrator
./build_all.sh --es <profile>        # With Elasticsearch direct export
```

Output: `build/db0738eb-.../db0738eb-....exe` (single-binary deployment, signed F0RT1KA).

## Prerequisites

- Windows 10/11, Windows Server 2019/2022
- Local Administrator or SYSTEM context (registry, audit policy, BitLocker, ASR rules)
- PowerShell 5.1+ (for Get-WinEvent, Get-ScheduledTask, w32tm queries)

## See also

- `db0738eb-848e-442b-b43c-208029063fe9_info.md` — control-level info card
- ISACA spec: `~/Downloads/ITGC_Validation_Bundle_ISACA_Auditors.xlsx`
