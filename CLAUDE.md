# CLAUDE.md

This file provides essential guidance to Claude Code when working with this repository.

## Overview
This is the F0RT1KA security testing framework - a specialized library for evaluating AV/EDR detection capabilities against various threat tactics and techniques. Tests are written in Go and mapped to the MITRE ATT&CK framework.

## Critical Development Rules (NEVER VIOLATE)

1. **ALL binaries MUST be dropped to the platform-specific LOG_DIR** - `c:\F0` (Windows) / `/tmp/F0` (Linux/macOS)
2. **Simulation artifacts MUST be created in the platform-specific ARTIFACT_DIR** - `c:\Users\fortika-test` (Windows) / `/home/fortika-test` (Linux) / `/Users/fortika-test` (macOS) — NOT whitelisted, allowing EDR to detect file operations
3. **ALL tests MUST be SINGLE-BINARY deployments** - Embed all dependencies using `//go:embed`
4. **ALL tests MUST implement comprehensive logging** - Use test_logger.go pattern
5. **ALL tests MUST capture embedded binary stdout/stderr to file** - Use `io.MultiWriter` for console + file output
6. **ALL tests MUST conform to Schema v2.0** - Use updated InitLogger signature with metadata and executionContext
7. **ALL tests MUST implement organization UUID support** - See Organization UUID Implementation section below
8. **ALL tests MUST include metadata header for ProjectAchilles ingestion** - See Test Metadata Header section
9. **NEVER hardcode exit codes** - Always evaluate actual results before determining exit code
10. **NEVER modify test_logger.go schema** - Schema must remain consistent across all tests
11. Tests simulate real attack techniques - handle with appropriate security measures
12. Map every test to specific MITRE ATT&CK techniques

## Autonomous Operations Mode

**This project operates in AUTONOMOUS MODE.** Claude Code should proceed without asking for confirmation on standard development operations.

### Why Autonomous Mode?

- **Git provides safety net** - All changes can be reverted via `git checkout` or `git reset`
- **Development velocity** - Security test development requires rapid iteration
- **Batch operations** - Building/signing multiple tests shouldn't require per-test approval

### Autonomous Actions (DO NOT ASK FOR PERMISSION)

1. **File operations** - Create, edit, delete files in the project
2. **Git operations** - Add, commit, push, branch, checkout
3. **Build operations** - Run gobuild, go build, go mod tidy
4. **Sign operations** - Run codesign, build_all.sh scripts
5. **Python scripts** - Run sync scripts, validation utilities
6. **Directory operations** - Create, move, copy, delete directories
7. **Test fixes** - Fix build errors, import issues, duplicate functions

### When TO Ask for Permission

Only ask when:
- **Destructive git operations** - `git push --force`, `git reset --hard` to remote
- **External service changes** - Modifying LimaCharlie production rules
- **Credential operations** - Anything involving certificates or signing keys
- **Ambiguous requirements** - User intent is unclear

### Commit Style

When committing, use conventional commit format and push without asking:
```bash
git add -A && git commit -m "fix: description" && git push
```

## Organization UUID Implementation (MANDATORY)

Every new test MUST include these components:

1. **Copy `org_resolver.go`** from `sample_tests/multistage_template/`
2. **Add UUID dependency** - `github.com/google/uuid v1.6.0` in go.mod, run `go mod tidy`
3. **Resolve organization** - `orgInfo := ResolveOrganization("")` in main()
4. **Set in ExecutionContext** - Use `orgInfo.UUID` (NOT short name)
5. **Use Schema v2.0 InitLogger** - `InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)`
6. **Include in build** - `go build -o out.exe main.go test_logger.go org_resolver.go`
7. **Avoid naming conflicts** - Do NOT name structs "Stage" (conflicts with test_logger.go)

Reference: `sample_tests/multistage_template/`

## Test Result Codes (Critical Reference)

- **101** (`Endpoint.Unprotected`) - Attack succeeded, system unprotected
- **105** (`Endpoint.FileQuarantinedOnExtraction`) - File quarantined
- **126** (`Endpoint.ExecutionPrevented`) - Execution blocked/prevented
- **999** (`Endpoint.UnexpectedTestError`) - Test error (prerequisites not met)

**Exit Code Logic:**
- Exit 126 = At least one critical protection layer worked
- Exit 101 = All critical protections bypassed
- Exit 999 = Test couldn't run (missing prerequisites)

## Test Results Schema v2.0 (MANDATORY COMPLIANCE)

ALL tests MUST use Schema v2.0. The InitLogger signature changed:

```go
// OLD (v1.x) - NO LONGER VALID
InitLogger(testID, testName string)

// NEW (v2.0) - REQUIRED
InitLogger(testID, testName string, metadata TestMetadata, executionContext ExecutionContext)
```

**Required fields:**
- `TestMetadata`: Version, Category, Severity, Techniques, Tactics, Score, **RubricVersion**, Tags
- `ExecutionContext`: ExecutionID (uuid), Organization (orgInfo.UUID), Environment, DeploymentType

**`RubricVersion` (active rubric: v2.1 — activated 2026-04-25):**
- `"v2.1"` = **active rubric**. Tiered realism-first with separated test-property vs. tenant-defense scoring: Safety gate (pass/fail) + Realism 0–7 (API fidelity 2.5 + identifier fidelity 1.5 + telemetry signal quality 2 + execution-context fidelity 1) + Structure 0–3 (schema 1 + docs 1 + logging 0.5 + operational hygiene 0.5). 2c is capped at 1.5 without lab evidence (criterion 4: all stages reached, or unreachable stages documented per Lab-Bound Observability schema). See `.claude/agents/sectest-documentation.md` and `docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`.
- `"v2"` = **legacy**. Tiered realism-first: Safety gate + Realism 0–7 (API fidelity 3 + identifier fidelity 2 + detection-rule firing 2) + Structure 0–3 (schema 1 + docs 1 + logging 1). Capped at 7.5 without lab-fired detection rules. Existing v2-scored tests are preserved at their v2 scores — not retroactively re-scored under v2.1 (per Decision 3 in v2.1 doc). See `docs/PROPOSED_RUBRIC_V2_REALISM_FIRST.md` (superseded).
- `"v1"` = **legacy**. Co-equal 5-dimension (Accuracy 3 + Sophistication 3 + Safety 2 + Detection 1 + Logging 1). Existing tests backfilled with `"v1"` on 2026-04-24 are preserved at their v1 scores.
- Empty string is treated as `"v1"` by downstream consumers.
- New tests built from the canonical template default to `"v2.1"`. Use `"v2"` or `"v1"` only when explicitly preserving a legacy score.

**Enforcement rules:**
1. DO NOT modify test_logger.go data structures
2. ALWAYS provide metadata and executionContext to InitLogger()
3. VALIDATE results before committing: `./utils/validate --all`
4. USE semantic versioning for test versions
5. MAP techniques to MITRE ATT&CK official IDs
6. GENERATE unique ExecutionIDs via UUID

Full guide: `docs/TEST_RESULTS_SCHEMA_GUIDE.md`

## Certificate Trust & Code Signing

**Certificate Location:**
- `signing-certs/F0RT1KA.pfx` - Private key (build machine only)
- `signing-certs/F0RT1KA.cer` - Public certificate (expires 2030-10-24)

**Organization Registry** (`signing-certs/organization-registry.json`):
- **sb** (Superintendency of Banks): `09b59276-9efb-4d3d-bbdd-4b4663ef0c42`
- **tpsgl** (Transact Pay): `b2f8dccb-6d23-492e-aa87-a0a8a6103189`
- **rga** (RG Associates): `9634119d-fa6b-42b8-9b9b-90ad8f22e482`

**Dual Signing (for ASR compatibility):**
```bash
/build-sign-test <test-uuid> sb      # Short name
/build-sign-test <test-uuid> tpsgl   # For tpsgl
/build-sign-test <test-uuid>         # F0RT1KA-only (recommended for new deployments)
```

Details: `docs/DUAL_SIGNING_STRATEGY.md`

## PowerShell Development Guidelines

All PowerShell scripts must:
- Include a function to check if running with admin privileges
- Implement automatic execution policy bypass functionality

## LimaCharlie D&R Rule Formatting

File format vs Web UI format differ significantly in indentation and wrapper structure. See `limacharlie-iac/README.md` for format details, examples, and common YAML errors.

## Build Utilities

### Build Tests
```bash
./utils/gobuild build tests_source/intel-driven/<uuid>/    # Intel-driven tests
./utils/gobuild build tests_source/cyber-hygiene/<uuid>/    # Cyber-hygiene tests
./utils/gobuild build-all                                   # Build all tests
```

### Sign Test Binaries
```bash
./utils/codesign sign build/<uuid>/<uuid>.exe   # Sign specific binary
./utils/codesign sign-all                        # Sign all binaries
```

### Check Windows Defender Protection
```powershell
powershell -ExecutionPolicy Bypass -File ./utils/Check-DefenderProtection.ps1
```

## Project Structure

```
tests_source/                 # All security tests
  ├── intel-driven/           # Tests from threat intelligence (APT reports, CVEs)
  │   └── <uuid>/             # Individual threat-based tests
  └── mitre-top10/            # MITRE ATT&CK top 10 technique tests
      └── <uuid>/             # Individual technique tests
sample_tests/                 # Reference implementations
  └── multistage_template/    # Multi-stage test reference
pentest_suites/               # Pentest readiness suite artifacts
rules/                        # Development guidelines
signing-certs/                # Code signing certificates
limacharlie-iac/              # LimaCharlie Infrastructure as Code
utils/                        # Build and signing utilities
```

### Test Categories

| Category | Location | Created By | Purpose |
|----------|----------|------------|---------|
| Cyber-Hygiene | `tests_source/cyber-hygiene/` | `@agent-sectest-builder` | Endpoint and cloud identity configuration validation |
| Intel-Driven | `tests_source/intel-driven/` | `@agent-sectest-builder` | Tests from threat intelligence, APT reports, CVEs |
| MITRE Top 10 | `tests_source/mitre-top10/` | `@agent-sectest-builder` | MITRE ATT&CK top 10 technique tests |

### Cyber-Hygiene Subcategories

| Subcategory | Purpose | Auth Required |
|-------------|---------|---------------|
| `baseline` | Endpoint OS hardening (Defender, ASR, LSASS, SMB, audit logging) | None (local registry/commands) |
| `identity-tenant` | Entra ID tenant security (CISA SCuBA baseline: MFA, CA, PIM, guest access) | Service principal via Graph API |
| `identity-endpoint` | Endpoint identity posture (device join, WHfB, MDM, PRT, BitLocker escrow) | None (local dsregcmd/registry) |

**Identity-tenant tests** require environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` pointing to a service principal with read-only Graph API permissions (Policy.Read.All, Directory.Read.All, RoleManagement.Read.All, AuditLog.Read.All, Application.Read.All).

## Bundle Results Protocol (Cyber-Hygiene Bundles)

Cyber-hygiene bundle tests write `c:\F0\bundle_results.json` for per-control granularity — each security control becomes an independent Elasticsearch document. Multi-stage intel-driven tests can also use `WriteStageBundleResults()` for per-stage ES fan-out.

Details: `docs/ARCHITECTURE.md` and `orchestrator_utils.go` / `check_utils.go` source code.

## Multi-Binary Bundle Architecture (Cyber-Hygiene)

Multi-binary bundles compile each validator as a separate embedded binary for quarantine resilience — if AV/EDR quarantines one validator, the rest still execute. Baseline (`a3c923ae`) and Identity Endpoint (`7659eeba`) use multi-binary; Identity Tenant (`4f484076`) stays single-binary (shared Graph API session).

Details: `docs/ARCHITECTURE.md`

## Required Files for Each Test

1. `<uuid>/` directory (use lowercase UUID)
2. `<uuid>.go` - Main test implementation
3. `test_logger.go` - Comprehensive logging module with Schema v2.0 support
4. `org_resolver.go` - Organization registry helper for UUID resolution
5. `README.md` - Brief overview
6. `<uuid>_info.md` - Detailed information card
7. `go.mod` - Module file with Prelude library dependencies
8. `<uuid>_references.md` - Source provenance and references (intel-driven/mitre-top10 only)
9. `build_all.sh` - Build script for tests with embedded components (if needed)

**Note**: Always copy `test_logger.go` and `org_resolver.go` from `sample_tests/` to ensure consistency.

## Test Metadata Header (MANDATORY for new tests)

Every test's main Go file (`<uuid>.go`) MUST include a metadata comment header. This header is the **load-bearing contract** between `f0_library` and ProjectAchilles' `MetadataExtractor` — PA parses this block at test-catalog ingestion time to populate test metadata (techniques, severity, target, threat actor, etc.) in its UI and API surface. A missing or malformed header causes silent field drops in PA (no error, just missing data in the frontend).

The sync script supports 3 test categories: `cyber-hygiene`, `intel-driven`, `mitre-top10`.

### 1. Include Metadata Header in Go File

The main test file (`<uuid>.go`) MUST include the metadata comment block:

```go
/*
ID: <uuid>
NAME: <Test Name>
TECHNIQUES: T1234, T1567.001
TACTICS: defense-evasion, execution
SEVERITY: high
TARGET: windows-endpoint, active-directory
COMPLEXITY: medium
THREAT_ACTOR: APT29
SUBCATEGORY: apt
TAGS: powershell, credential-theft, memory-patching
SOURCE_URL: https://www.microsoft.com/security/blog/2024/08/28/peach-sandstorm...
UNIT: response
CREATED: 2026-01-17
AUTHOR: sectest-builder
*/
```

**All v2.0 fields are required.** Legacy tests may rely on parser defaults, but new tests must populate every required field explicitly.

| Field | Required | Example Values |
|-------|----------|----------------|
| `ID` | Yes | Test UUID |
| `NAME` | Yes | Human-readable name |
| `TECHNIQUES` | Yes | `T1562.001, T1059.001` |
| `TACTICS` | Yes | `defense-evasion, execution` (kebab-case) |
| `SEVERITY` | Yes | `critical`, `high`, `medium`, `low`, `informational` |
| `TARGET` | Yes | `windows-endpoint`, `active-directory`, `cloud-aws` |
| `COMPLEXITY` | Yes | `low` (<30s), `medium` (30s-5min), `high` (>5min) |
| `THREAT_ACTOR` | Yes | `APT29`, `Lazarus`, `SafePay`, `N/A` |
| `SUBCATEGORY` | Yes | `ransomware`, `apt`, `c2`, `baseline`, `identity-tenant` |
| `TAGS` | Yes | `powershell, defender-evasion` |
| `SOURCE_URL` | No | URL of the primary threat intelligence source (or `N/A`) |
| `AUTHOR` | Yes | `sectest-builder` |

### 2. Propagate Schema Changes to ProjectAchilles

**ProjectAchilles (`~/F0RT1KA/ProjectAchilles/`) is the live consumer of this metadata header.** PA has two parallel backends (`backend/` and `backend-serverless/`) that BOTH parse the Go metadata header with identical `MetadataExtractor` classes. When adding a new metadata field (or changing an existing one's format), the following files MUST be updated **in both `backend/` and `backend-serverless/`** — the two trees are mirrors and drift causes silent bugs:

**PA propagation checklist** (repeat for both `backend/` and `backend-serverless/`):

1. `src/services/browser/metadataExtractor.ts` — Add the `header.match(/FIELD:\s*(.+)/i)` regex extraction.
2. `src/types/test.ts` — Add the field to the `TestMetadata` (and `TestDetails`) interface.
3. `src/services/browser/testIndexer.ts` — Wire the extracted field through the indexer pipeline.
4. `src/services/agent/test-catalog.service.ts` — Include the field in catalog persistence / lookup.
5. `src/services/browser/__tests__/metadataExtractor.test.ts` — Add a regex extraction test for the new field.

**Failure mode if skipped:** the Go header will still build and sign fine, the field will appear in the source file, but PA's UI and API will silently drop it. No error, no warning — just missing data in the frontend. Always verify PA propagation before declaring a schema change complete.

PA lives in a separate repo with a different review cycle, so sectest-builder does NOT auto-update PA. The validation skill produces a PA propagation checklist for the user to apply manually.

### 3. Legacy: LimaCharlie→ES Enrichment Pipeline (not in production)

The following sync flow is **retained for historical reference only** — no tenant currently consumes `f0rtika-results-*` indices or the `f0rtika-test-catalog` enrichment index. The live results pipeline is ProjectAchilles' own `achilles-results-*` (PA handles its own ingestion). The sync script and its Kibana enrich policy are preserved in the repo but are **not part of the test-build workflow**.

If you need to refresh the historical catalog for exploratory queries:

```bash
source .venv/bin/activate
python3 utils/sync-test-catalog-to-elasticsearch.py
```

Then in Kibana Dev Tools: `POST /_enrich/policy/f0rtika-test-enrichment/_execute`

ES field reference and historical query examples: `limacharlie-iac/ELASTICSEARCH-ENRICHMENT-GUIDE.md` (marked as not-in-production).

## Test Score Format Requirements (MANDATORY)

**README.md**: `**Test Score**: **9.2/10**` (colon OUTSIDE bold markers)

**info.md**: `## Test Score: 9.2/10` (level 2 header, plain text score)

Validate: `./utils/validate-score-format.sh [test-uuid]`

## Prerequisites

- **Prelude Libraries**: Must be set up in `preludeorg-libraries/` directory
- **Go 1.21+**: Required for building
- **Supported platforms**: Windows (primary), Linux, macOS

## Key Conventions

- Use `Endpoint.Say()` for console output
- Use `os.Stat()` for quarantine detection (see Bug Prevention Rules)
- Always clean up artifacts after test completion
- Follow MITRE ATT&CK mapping standards

## Cross-Platform Test Development

Tests can target Windows, Linux, or macOS. The platform is determined by the threat being simulated.

### Platform Constants

| Platform | `LOG_DIR` | `ARTIFACT_DIR` | Build Tag | Binary Extension |
|----------|-----------|----------------|-----------|-----------------|
| Windows | `C:\F0` | `c:\Users\fortika-test` | `//go:build windows` | `.exe` |
| Linux | `/tmp/F0` | `/home/fortika-test` | `//go:build linux` | (none) |
| macOS | `/tmp/F0` | `/Users/fortika-test` | `//go:build darwin` | (none) |

### Platform-Specific Logger Files

The `test_logger.go` shared code uses `LOG_DIR` and `ARTIFACT_DIR` constants defined in platform-specific files:

- `test_logger.go` — Shared logger code (NO build tag, NO platform imports)
- `test_logger_windows.go` — Windows constants + system info functions (`//go:build windows`)
- `test_logger_linux.go` — Linux constants + system info functions (`//go:build linux`)
- `test_logger_darwin.go` — macOS constants + system info functions (`//go:build darwin`)

When creating a new test, copy the shared `test_logger.go` AND the appropriate platform file from `sample_tests/multistage_template/`.

### Build Commands Per Platform

```bash
# Windows (default)
GOOS=windows GOARCH=amd64 go build -o test.exe main.go test_logger.go test_logger_windows.go org_resolver.go

# Linux
GOOS=linux GOARCH=amd64 go build -o test main.go test_logger.go test_logger_linux.go org_resolver.go

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o test main.go test_logger.go test_logger_darwin.go org_resolver.go
```

### Code Signing Per Platform

| Platform | Signing Method | Tool |
|----------|---------------|------|
| Windows | Authenticode (PFX) | `osslsigncode` / `utils/codesign` |
| Linux | N/A (signing skipped) | — |
| macOS | Ad-hoc codesign | `codesign -s -` |

### macOS Deployment

macOS binaries may be quarantined by Gatekeeper. Before execution:
```bash
xattr -cr /tmp/F0/<binary>
```

### go.mod Dependencies

- Windows tests: include `golang.org/x/sys` (for registry access)
- Linux/macOS tests: do NOT include `golang.org/x/sys` (not needed)

## Stdout/Stderr Capture Pattern (MANDATORY)

When executing embedded binaries, capture stdout/stderr to both console and file using `io.MultiWriter`. Output file naming: `LOG_DIR/<binary-name>_output.txt`. See `sample_tests/` for implementation pattern.

## Test Architecture Patterns

### Pattern 1: Standard Single-Binary (Most Tests)
- Single Go binary with embedded dependencies
- Use for tests with 1-2 techniques
- Reference: See `sample_tests/` for examples

### Pattern 2: Multi-Stage Architecture (3+ Techniques)
- Main orchestrator + separate signed stage binaries per technique
- Provides technique-level detection precision
- Use for complex killchain simulations
- Reference: `sample_tests/multistage_template/`

**Decision Guide:**
- 1-2 techniques -> Standard pattern
- 3+ techniques -> Multi-stage pattern

## Test Development Workflow

For building new tests, use the **sectest-builder agent**: `@agent-sectest-builder`

## Common Pitfalls to Avoid

- **DON'T** drop files outside `c:\F0`
- **DON'T** require multiple files for deployment
- **DON'T** hardcode exit codes (always evaluate results)
- **DON'T** skip logging implementation
- **DON'T** forget to sign stage binaries BEFORE embedding (multi-stage tests)
- **DO** embed all dependencies into single binary
- **DO** implement comprehensive logging
- **DO** evaluate protection effectiveness before choosing exit code
- **DO** clean up build artifacts after embedding
- **DO** use established test structure patterns

## Bug Prevention Rules (Lessons Learned)

These rules prevent recurring false-positive bugs found across multiple tests:

1. **NEVER inject blame keywords into `fmt.Errorf()` wrappers** — words like "access denied", "blocked", "prevented" in error messages poison `determineExitCode()` into returning exit 126 for ANY error, not just actual EDR blocks. Describe the operation, not the cause.
2. **Handle SYSTEM vs user context** — Tests on Prelude run as SYSTEM where HKCU maps to `HKU\.DEFAULT`. Detect with `isSystemContext()` and use HKLM for machine-wide operations.
3. **Use `os.Stat()` for quarantine detection** — `Endpoint.Quarantined()` has a path-doubling bug with absolute paths. Use `time.Sleep(3s)` + `os.Stat()` instead.
4. **Separate benign from critical metrics** — Track simulation steps and protection tests with separate counters. Exit code must reflect critical protection metrics only.
5. **Handle empty sc.exe output** — Tamper-protected services may return empty output on stop/config. Treat unclear results as "blocked".
6. **Use Windows service names, not display names** — `sc.exe` uses registry service names (e.g., `CSFalconService`), not display names (e.g., `CrowdStrike Falcon Sensor`).
7. **Use gzip compression for multi-stage embedded binaries** — Embed `.exe.gz` files and decompress in memory with `compress/gzip`. NEVER use UPX or runtime packers (they trigger EDR heuristic detections for packer entropy, poisoning test results).

## Binary Size Budget (MANDATORY for new tests)

The compiled test binary that gets distributed to agents has a size budget enforced by both transport and operational realities, not by an arbitrary preference.

**Why this matters:** Agents download the orchestrator over the public internet (often via Cloudflare tunnels in dev, customer firewalls in prod). The agent's download budget is `MaxDownloadTimeout` (default 5 minutes). A 50 MB binary on a 1 Mbps link consumes the entire budget; a 70 MB binary fails outright. Beyond download time, large binaries also slow code signing (Authenticode is per-file), bloat agent disk (`~/.projectachilles/builds/`), and create unnaturally large file drops that distort detection telemetry — real adversary loaders are typically 100 KB – 5 MB.

### Size Tiers

| Tier | Final orchestrator size | Required action |
|------|-------------------------|-----------------|
| 🟢 Green | **≤ 10 MB** | None. Typical Go-only multi-stage test sits here. |
| 🟡 Yellow | **10 – 25 MB** | Note in `<uuid>_info.md` why the size is justified (e.g., "embeds .NET runtime for in-process API calls — required to match adversary tradecraft"). |
| 🔴 Red | **25 – 50 MB** | Add an explicit `## Size Justification` section to `<uuid>_info.md`. Before accepting this tier, the build agent **must** evaluate whether the refactor recipes below would shrink the binary without losing realism. If they would, refactor. |
| ⛔ Forbidden | **> 50 MB** | Do not ship. The build skill will flag this and require a refactor. The only path forward is one of the recipes below. |

### Refactor Recipes (when binary exceeds budget)

These exist because most oversized binaries are oversized by accident — packaging defaults, not adversary fidelity.

**1. .NET self-contained → trimmed/AOT.** A `dotnet publish` self-contained build emits ~70 MB of runtime. Almost always over-engineered for security tests. Pick one:
   - `<PublishTrimmed>true</PublishTrimmed>` + `<TrimMode>full</TrimMode>` — typically reduces 70 MB → 15 MB.
   - `<PublishAot>true</PublishAot>` (AOT) — typically reduces 70 MB → 5 MB and removes the JIT side-channel that some EDRs alert on.
   - `<PublishSingleFile>true</PublishSingleFile>` with `<EnableCompressionInSingleFile>true</EnableCompressionInSingleFile>`.

**2. .NET framework-dependent.** If the target host has .NET runtime (most enterprise Windows endpoints do for Defender/Office), drop `--self-contained` and ship a 1–3 MB managed exe. Adds a runtime prerequisite to the test, but the test footprint matches reality more closely.

**3. Move bulk into `lab_assets/` with runtime fetch.** The orchestrator embeds only loader logic; bulk payloads live in `lab_assets/` and are fetched at runtime from a controlled URL. This is *more* realistic — real adversaries stage payloads, they don't ship a single 50 MB binary. See `tests_source/intel-driven/<uuid>/lab_assets/` for the existing pattern.

**4. Split a multi-stage test.** If 6 stages each at 8 MB sum to 48 MB, ask whether all 6 are load-bearing. Sometimes a stage was added speculatively and never anchored to a specific MITRE technique.

**5. Verify gzip compression is wired.** Multi-stage tests MUST use the gzip-embed pattern (see `build_all.sh` step 4). A skipped gzip step inflates the orchestrator by ~35%.

### Where the Limit Is Enforced

- **`sectest-builder` agent (Phase 1, Step 3):** Reads the produced binary's size and refuses to proceed past Forbidden, requires justification past Red.
- **`sectest-build-config` skill (final step):** Reports tier alongside the SHA1 hash. Yellow/Red tiers print the refactor recipes.
- **No CI hard-block:** Authors can override with explicit justification — the limit encodes preference, not impossibility, because some legitimate red-team scenarios genuinely need bulk.

### Anchor: Why "50 MB"?

The number aligns with the agent's `MaxDownloadTimeout` (5 min) at the slowest link Achilles is expected to support cleanly (~1.4 Mbps, accounting for TLS + Cloudflare overhead). Above 50 MB, you exit the supported envelope; the agent may or may not finish in time depending on network conditions, and the failure mode is ugly (`write binary: context deadline exceeded`).

## Multi-Stage Test Build Requirements (MANDATORY)

All multi-stage tests MUST use the modern 8-step `build_all.sh` pattern with org registry integration, dual signing, signature verification, **gzip compression**, and SHA1 hashing.

**Build sequence**: Build stages → Sign stages → **Compress with gzip** → Embed compressed stages in orchestrator → Sign orchestrator

**Gzip compression is MANDATORY** for all multi-stage tests. Stage binaries are gzip-compressed at build time and decompressed in memory during extraction. This reduces orchestrator size by ~35% (e.g., 31MB → 20MB) without triggering EDR heuristics. Files written to disk are normal signed PEs.

- Orchestrator embeds `.exe.gz` files (not `.exe`)
- Orchestrator imports `"compress/gzip"` and decompresses via `decompressGzip()` helper
- UPX and runtime packers are FORBIDDEN (they trigger EDR entropy/packer detections)

Reference implementation: `tests_source/intel-driven/13c2d073-8e33-4fca-ab27-68f20c408ce9/build_all.sh`

Details: `docs/MULTISTAGE_QUICK_REFERENCE.md`

## Github Repository Management

- Initialize and create a private repository on Github
- For all changes, additions and fixes, commit and create PRs when applicable

## Agent Selection Guide

| Need | Agent |
|------|-------|
| Test specific threat/technique | `@agent-sectest-builder` (orchestrates skills + sub-agents) |
| Validate TIBER-EU phase readiness (on-demand) | `@agent-pentest-readiness-builder` |
| Visualize attack flow (on-demand) | `@agent-attack-flow-diagram-builder` |
| Visualize kill chain | `@agent-kill-chain-diagram-builder` (mandatory for multi-stage tests) |
| Generate detection rules (standalone) | `@agent-sectest-detection-rules` |
| Generate defense guidance (standalone) | `@agent-sectest-defense-guidance` |
| Generate all defense artifacts (legacy) | `@agent-defense-guidance-builder` (delegates to above two) |
| Deploy & execute test on endpoint | `@agent-sectest-deploy-test` |

## Additional Documentation

- `docs/TEST_RESULTS_SCHEMA_GUIDE.md` - Schema v2.0 full guide
- `docs/ARCHITECTURE.md` - Multi-binary bundle architecture
- `docs/MULTISTAGE_QUICK_REFERENCE.md` - Multi-stage build reference
- `docs/DUAL_SIGNING_STRATEGY.md` - Code signing details
- `limacharlie-iac/ELASTICSEARCH-ENRICHMENT-GUIDE.md` - ES enrichment setup
- `limacharlie-iac/README.md` - Certificate deployment
- `sample_tests/multistage_template/` - Multi-stage test patterns
- `pentesting/agentic_pentest.md` - DORA/TIBER-EU pentest methodology
- `pentesting/PENTEST_READINESS_GUIDE.md` - Pentest readiness builder usage
- `rules/` - Development guidelines
