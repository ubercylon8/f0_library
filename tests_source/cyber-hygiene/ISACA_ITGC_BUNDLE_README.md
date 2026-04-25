# ISACA ITGC Validation Bundle Suite — F0RT1KA

A 3-bundle suite implementing all 35 controls in the ISACA ITGC Validation Bundle for CISA-credentialed auditors. Output is engineered for direct workpaper drop-in — auditors do not need to interpret raw F0RT1KA telemetry.

## Bundle map

| Bundle | UUID | Scope | Architecture | Where to run |
|---|---|---|---|---|
| **Windows Endpoint** | [`db0738eb-848e-442b-b43c-208029063fe9`](db0738eb-848e-442b-b43c-208029063fe9/) | 31 controls (AM/CM/LM/EP/BR/NS/GV) | Multi-binary (7 validators) | Each Windows endpoint, SYSTEM context |
| **AD Identity** | [`a26a91b2-8d59-410b-9f5e-7ec5ffb6734c`](a26a91b2-8d59-410b-9f5e-7ec5ffb6734c/) | 3 controls (AM-003, AM-004, NS-003) | Single-binary | A domain-joined host with RSAT (DC or mgmt server) |
| **Entra Tenant** *(extends existing bundle)* | [`4f484076-9816-4813-947e-b76bce3d3f83`](4f484076-9816-4813-947e-b76bce3d3f83/) | 1 ITGC control (AM-006) + the existing CISA SCuBA suite | Single-binary | Centrally — ProjectAchilles `MicrosoftGraphClient` |

**Total: 35 / 35 ITGCs from the ISACA spec.**

## Output (per bundle)

Each bundle writes three things to `c:\F0\` on the host that ran it:

1. **`bundle_results.json`** — F0RT1KA's standard per-control fan-out for ProjectAchilles ingestion. Each control becomes one document in `achilles-results-*` (or `f0rtika-results-*`) Elasticsearch indices.

2. **`itgc_evidence_<control_id>.json`** *(one per control)* — ISACA workpaper schema:
    ```json
    {
      "control_id": "ITGC-AM-001",
      "control_name": "Local Administrator Account Inventory",
      "status": "PASS|FAIL|SKIPPED",
      "severity": "critical",
      "cisa_domain": "D5: Protection of Information Assets",
      "cobit_objective": "DSS05.04 Manage Identity and Logical Access",
      "cis_v8_mapping": "CIS 5.4 Restrict Administrator Privileges",
      "mitre_attack": ["T1078"],
      "manual_residual": "Auditor verifies each enumerated member ...",
      "expected": "Approved-admin baseline membership only",
      "actual": "3 local admin member(s): Administrator, DOMAIN\\SvcAdmin, ...",
      "evidence": { /* control-specific structured evidence */ },
      "hostname": "host-01",
      "timestamp": "2026-04-25T17:42:00Z"
    }
    ```

3. **`itgc_audit_workpaper.json`** — aggregated auditor pack containing all the above + run metadata. Auditors download this single file and drop it into workpapers.

## Control matrix

See [`docs/ISACA_ITGC_CONTROL_MATRIX.md`](../../docs/ISACA_ITGC_CONTROL_MATRIX.md) for the full control_id → file:line traceability map (every ITGC ID with its source location).

## ProjectAchilles integration

| ISACA "agent module" | F0RT1KA implementation | PA-side action |
|---|---|---|
| `endpoint_config` (22 ctrls) | Windows Endpoint bundle, runs locally as SYSTEM | None — PA only ingests `bundle_results.json` |
| `identity_audit` (6 ctrls) | AD Identity bundle, runs on DC/mgmt host with RSAT | None — same ingestion path |
| `cloud_identity` (1 ctrl: AM-006 MFA) | Extension to existing Entra Tenant bundle, uses PA's `MicrosoftGraphClient` | **Add `UserAuthenticationMethod.Read.All` permission** to existing app registration (see `4f484076-.../<uuid>_info.md`) |
| `siem_integration` (3 ctrls) | Local `Get-WinEvent` queries inside Windows Endpoint bundle | None for v1. SIEM-mode (Splunk/Sentinel) deferred to v2 |
| `asset_discovery` (3 ctrls) | WMI queries inside Windows Endpoint bundle | None |

## Build & sign

Each bundle has its own `build_all.sh` (Endpoint) or simple `go build` + `utils/codesign sign` (AD/Entra). All produce F0RT1KA-signed PE binaries ready for Prelude deployment.

## Configuration env vars

| Env Var | Bundle | Default | Purpose |
|---|---|---|---|
| `ITGC_PATCH_SLA_DAYS` | Endpoint | 30 | CM-002 patch SLA window |
| `ITGC_DORMANT_DAYS` | AD Identity | 90 | AM-003 dormant-account threshold |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | Entra Tenant | — | Graph API service principal (existing — no new value needed) |

## Schema version

Schema v2.0 with ISACA extensions. `TestMetadata` carries:
- `IsacaControlIDs []string`
- `CisaDomains []string`
- `CobitObjectives []string`

These propagate to ProjectAchilles via `MetadataExtractor` (commit `0e3d9ad` in PA backends; both `backend/` and `backend-serverless/` trees).

## Provenance & references

- ISACA spec: `~/Downloads/ITGC_Validation_Bundle_ISACA_Auditors.xlsx`
- CISA 2024 ECO domains
- COBIT 2019 management objectives
- CIS Controls v8
- MITRE ATT&CK
