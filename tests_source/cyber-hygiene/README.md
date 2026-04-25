# Cyber Hygiene — Configuration Validation Bundle Suite

Configuration-validation tests that verify whether security controls are properly enabled and hardened, rather than simulating attacks. Output is **per-control evidence** suitable for compliance workpapers and SIEM ingestion.

**10 bundles** spanning endpoint baselines, CIS Level 1 benchmarks, cloud identity (CISA SCuBA), and a complete **35/35 ISACA ITGC** validation suite. Each bundle writes `bundle_results.json` (per-control fan-out for ProjectAchilles `achilles-results-*` indices); the ISACA bundles additionally write per-control workpaper evidence.

## Featured: ISACA ITGC Bundle Suite

Three bundles together provide complete coverage of the **ISACA ITGC Validation Bundle** for CISA-credentialed auditors (35/35 controls). See [`ISACA_ITGC_BUNDLE_README.md`](ISACA_ITGC_BUNDLE_README.md) and [`docs/ISACA_ITGC_CONTROL_MATRIX.md`](../../docs/ISACA_ITGC_CONTROL_MATRIX.md) for the full control-id → file:line traceability map.

| Bundle | UUID | Controls | Where to run |
|---|---|---:|---|
| Windows Endpoint | [`db0738eb-…208029063fe9`](db0738eb-848e-442b-b43c-208029063fe9/) | 31 | Each Windows endpoint, SYSTEM context |
| AD Identity | [`a26a91b2-…7ec5ffb6734c`](a26a91b2-8d59-410b-9f5e-7ec5ffb6734c/) | 3 | Domain-joined host with RSAT (DC or mgmt server) |
| Entra Tenant *(extends CISA SCuBA)* | [`4f484076-…b76bce3d3f83`](4f484076-9816-4813-947e-b76bce3d3f83/) | 1 | Centrally — PA `MicrosoftGraphClient` |

ITGC scope: **AM** (Access Management) ×6 · **CM** (Change Management) ×5 · **LM** (Log Management) ×5 · **EP** (Endpoint Protection) ×6 · **BR** (Backup & Recovery) ×3 · **NS** (Network Security) ×4 · **GV** (Governance) ×6.

---

## Bundle inventory

### Endpoint Baseline Bundles (multi-binary, quarantine-resilient)

These consolidate prior point-tests (LAPS, ASR, LSASS, SMB, etc.) into validator binaries. Each validator runs independently — if AV/EDR quarantines one, the rest still execute.

| UUID | Name | Target | Edition | Key Techniques |
|---|---|---|---|---|
| [`a3c923ae-…be6c2731a628`](a3c923ae-1a46-4b1f-b696-be6c2731a628/) | Cyber-Hygiene Bundle (Windows Defender Edition) | Windows Endpoint | Defender | T1562.001, T1003.001, T1059.001, T1110, T1547.001 |
| [`b2cd3532-…f7c10ef0d717`](b2cd3532-701d-4700-bbb2-f7c10ef0d717/) | Cyber-Hygiene Bundle (CrowdStrike Falcon Edition) | Windows Endpoint | CrowdStrike | T1562.001, T1003.001, T1059.001, T1110, T1547.001 |

### CIS Level 1 Benchmark Bundles

| UUID | Name | Target | Controls | Key Techniques |
|---|---|---|---:|---|
| [`078f1409-…3fd596e85ce0`](078f1409-9f7b-4492-bb35-3fd596e85ce0/) | CIS Windows Endpoint Level 1 Hardening Bundle | Windows | 52 | T1110, T1003.001, T1562.001, T1059.001 |
| [`7f0d43e7-…cfa9703a51e8`](7f0d43e7-8a7b-48f3-9aff-cfa9703a51e8/) | CIS Linux Endpoint Level 1 Hardening Bundle | Linux | 35 | T1562.001, T1059.004, T1543.002, T1070.002 |
| [`6d63934b-…8166e33eb6da`](6d63934b-963f-4e3b-83f5-8166e33eb6da/) | CIS macOS Endpoint Level 1 Hardening Bundle | macOS | 22 | T1562.001, T1553.001, T1071.001 |
| [`602a5333-…a22aa7126447`](602a5333-e9cf-4ddf-a132-a22aa7126447/) | CIS Identity & Active Directory Level 1 Bundle | Windows / AD / Entra | 28 | T1078.002, T1098.001, T1558.003, T1484.001 |

### Cloud & Endpoint Identity Bundles

| UUID | Name | Target | Standard | Key Techniques |
|---|---|---|---|---|
| [`4f484076-…b76bce3d3f83`](4f484076-9816-4813-947e-b76bce3d3f83/) | Entra ID Tenant Security Hygiene Bundle *(+ ITGC-AM-006)* | Entra ID / M365 | CISA SCuBA + ISACA | T1078.004, T1556.007, T1110.001, T1098.003 |
| [`7659eeba-…4aa015d68b27`](7659eeba-f315-440e-9882-4aa015d68b27/) | Identity Endpoint Posture Bundle | Windows Endpoint | endpoint identity | T1078.004, T1556.007, T1528, T1550.001 |

### ISACA ITGC Validation Bundles

| UUID | Name | Target | ITGC Coverage |
|---|---|---|---|
| [`db0738eb-…208029063fe9`](db0738eb-848e-442b-b43c-208029063fe9/) | ISACA ITGC Windows Endpoint Validation Bundle | Windows Endpoint | 31 controls (AM/CM/LM/EP/BR/NS/GV) |
| [`a26a91b2-…7ec5ffb6734c`](a26a91b2-8d59-410b-9f5e-7ec5ffb6734c/) | ISACA ITGC AD Identity Validation Bundle | AD / Windows Server | 3 controls (AM-003, AM-004, NS-003) |

---

## ISACA ITGC control coverage matrix

35 / 35 controls across three bundles. Auditors can drop the workpaper output (`itgc_audit_workpaper.json` per host) directly into evidence packs.

| Domain | Bundle | Controls |
|---|---|---|
| **AM** Access Management | Windows Endpoint | AM-001, AM-002, AM-005 |
| **AM** Access Management | AD Identity | AM-003, AM-004 |
| **AM** Access Management | Entra Tenant | AM-006 |
| **CM** Change Management | Windows Endpoint | CM-001 → CM-005 |
| **LM** Log Management | Windows Endpoint | LM-001 → LM-005 |
| **EP** Endpoint Protection | Windows Endpoint | EP-001 → EP-006 |
| **BR** Backup & Recovery | Windows Endpoint | BR-001, BR-002, BR-003 |
| **NS** Network Security | Windows Endpoint | NS-001, NS-002, NS-004 |
| **NS** Network Security | AD Identity | NS-003 |
| **GV** Governance | Windows Endpoint | GV-001 → GV-006 |

Standards mapped per control: **CISA 2024 ECO domains**, **COBIT 2019 management objectives**, **CIS Controls v8**, and **MITRE ATT&CK**. The schema fields are surfaced via `TestMetadata.IsacaControlIDs`, `CisaDomains`, `CobitObjectives` (Schema v2.0 ISACA extensions; propagated to PA via `MetadataExtractor`).

---

## Output schema

Every bundle writes to `LOG_DIR` on the host that ran it (`c:\F0\` Windows, `/tmp/F0/` Linux/macOS):

| File | Producer | Consumer |
|---|---|---|
| `bundle_results.json` | All bundles | ProjectAchilles ingestion → Elasticsearch `achilles-results-*` |
| `itgc_evidence_<control_id>.json` | ISACA bundles only — one per control | Audit workpaper |
| `itgc_audit_workpaper.json` | ISACA bundles only — aggregated | Auditor pack (single-file drop-in) |

Each control becomes one Elasticsearch document via `bundle_results.json` per-control fan-out (see `orchestrator_utils.go` / `check_utils.go` and [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md)).

## Path conventions

| Platform | Test binary / log | Reason |
|---|---|---|
| Windows | `c:\F0\` | LOG_DIR — whitelisted, allows execution |
| Linux | `/tmp/F0/` | LOG_DIR — standard collection point |
| macOS | `/tmp/F0/` | LOG_DIR — standard collection point |

Cyber-hygiene tests do **not** drop simulation artifacts (no decoy files, no encrypted targets) — they only read configuration state. There is no ARTIFACT_DIR usage.

## Configuration

Bundles read environment variables for site-specific thresholds and Graph API credentials (Entra Tenant only):

| Env Var | Bundle | Default | Purpose |
|---|---|---|---|
| `ITGC_PATCH_SLA_DAYS` | ISACA Windows Endpoint | `30` | CM-002 patch SLA window |
| `ITGC_DORMANT_DAYS` | ISACA AD Identity | `90` | AM-003 dormant-account threshold |
| `AZURE_TENANT_ID` | Entra Tenant / Identity & AD CIS L1 | — | Graph API service principal |
| `AZURE_CLIENT_ID` | Entra Tenant / Identity & AD CIS L1 | — | Graph API service principal |
| `AZURE_CLIENT_SECRET` | Entra Tenant / Identity & AD CIS L1 | — | Graph API service principal |

The Entra-bundle service principal needs read-only Graph permissions: `Policy.Read.All`, `Directory.Read.All`, `RoleManagement.Read.All`, `AuditLog.Read.All`, `Application.Read.All`, **and `UserAuthenticationMethod.Read.All`** (added for ITGC-AM-006).

## Build & sign

```bash
# Build all bundles
for dir in tests_source/cyber-hygiene/*/; do
    ./utils/gobuild build "$dir"
done

# Sign all binaries
./utils/codesign sign-all
```

The Windows Endpoint Baseline (`a3c923ae` / `b2cd3532`), Identity Endpoint Posture (`7659eeba`), and ISACA Windows Endpoint (`db0738eb`) bundles are **multi-binary** for quarantine resilience (see [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md)). Each uses its own `build_all.sh` to embed pre-signed validator binaries in the orchestrator. The Entra Tenant and AD Identity bundles are single-binary because their checks share a Graph or LDAP session.

## Expected results

| Exit Code | Meaning |
|---|---|
| **101** | Configuration gaps found — needs hardening |
| **126** | All checked controls properly configured |
| **999** | Test prerequisites not met (e.g., no Graph credentials, missing RSAT, non-domain-joined host) |

Per-control results inside `bundle_results.json` carry `status: "PASS" | "FAIL" | "SKIPPED"` with the actual observation, expected value, and structured evidence — the bundle's overall exit code is a roll-up of those statuses.

## Related documentation

- [ISACA ITGC bundle overview](ISACA_ITGC_BUNDLE_README.md)
- [Implementation guide (PDF)](IMPLEMENTATION_GUIDE.pdf) · [Markdown](IMPLEMENTATION_GUIDE.md)
- [Risk reduction analysis (PDF)](RISK_REDUCTION_ANALYSIS.pdf) · [Markdown](RISK_REDUCTION_ANALYSIS.md)
- [Bundle architecture (multi-binary)](../../docs/ARCHITECTURE.md)
- [Test results schema v2.0](../../docs/TEST_RESULTS_SCHEMA_GUIDE.md)
- [Top-level README](../../README.md)
