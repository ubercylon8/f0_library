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
8. **ALL tests MUST include metadata header for Elasticsearch enrichment** - See Elasticsearch Catalog Sync section
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
- `TestMetadata`: Version, Category, Severity, Techniques, Tactics, Score, Tags
- `ExecutionContext`: ExecutionID (uuid), Organization (orgInfo.UUID), Environment, DeploymentType

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

## Elasticsearch Catalog Sync (MANDATORY for new tests)

Test results in Elasticsearch are enriched with metadata from a catalog index. The sync script supports 3 test categories: `cyber-hygiene`, `intel-driven`, `mitre-top10`.

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

**All v2.0 fields are required.** The sync script provides sensible defaults for legacy tests.

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

### 2. Sync Catalog After Creating Test

```bash
source .venv/bin/activate
python3 utils/sync-test-catalog-to-elasticsearch.py
```

### 3. Re-execute Enrich Policy

In Kibana Dev Tools: `POST /_enrich/policy/f0rtika-test-enrichment/_execute`

ES field reference and example queries: `limacharlie-iac/ELASTICSEARCH-ENRICHMENT-GUIDE.md`

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
