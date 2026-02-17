# CLAUDE.md

This file provides essential guidance to Claude Code when working with this repository.

## Overview
This is the F0RT1KA security testing framework - a specialized library for evaluating AV/EDR detection capabilities against various threat tactics and techniques. Tests are written in Go and mapped to the MITRE ATT&CK framework.

## Critical Development Rules (NEVER VIOLATE)

1. **ALL binaries MUST be dropped to `c:\F0`** - Hard requirement for all tests
2. **Simulation artifacts (test documents, PDFs, etc.) MUST be created in `c:\Users\fortika-test`** - This path is NOT whitelisted, allowing EDR to detect file operations
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

**ALL tests MUST implement organization UUID support** for multi-org analytics and Elasticsearch tracking.

### Implementation Checklist

Every new test MUST include the following components:

1. **Copy org_resolver.go**
   ```bash
   # Copy from sample_tests/multistage_template/org_resolver.go
   # Use intel-driven/ for threat-based tests, phase-aligned/ for pentest readiness tests
   cp sample_tests/multistage_template/org_resolver.go tests_source/<category>/<uuid>/
   ```

2. **Add UUID dependency**
   - Import: `"github.com/google/uuid"`
   - Add to `go.mod`: `github.com/google/uuid v1.6.0`
   - Run: `go mod tidy`

3. **Resolve organization in main()**
   ```go
   // Resolve organization from registry (uses default if empty string)
   orgInfo := ResolveOrganization("")
   ```

4. **Set organization in ExecutionContext**
   ```go
   executionContext := ExecutionContext{
       ExecutionID:   uuid.New().String(),
       Organization:  orgInfo.UUID,  // MUST use orgInfo.UUID, not short name
       Environment:   "lab",
       DeploymentType: "manual",
       // ... other fields
   }
   ```

5. **Use Schema v2.0 InitLogger signature**
   ```go
   InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)
   ```

6. **Include org_resolver.go in build commands**
   ```bash
   # All go build commands must include org_resolver.go
   GOOS=windows GOARCH=amd64 go build -o output.exe main.go test_logger.go org_resolver.go
   ```

7. **Avoid naming conflicts**
   - DO NOT name structs "Stage" (conflicts with test_logger.go logging Stage)
   - Use alternatives: `KillchainStage`, `AttackStage`, `ExecutionStage`

### What This Enables

- ✅ Multi-organization support (sb, tpsgl, rga)
- ✅ Automatic organization resolution from registry
- ✅ Cross-organizational analytics in Elasticsearch
- ✅ Test execution attribution and tracking
- ✅ Batch correlation via ExecutionID
- ✅ Time-series analysis per organization

### Reference Implementation

See `sample_tests/multistage_template/` for complete reference implementation with:
- Correct org_resolver.go usage
- Proper UUID dependency setup
- Schema v2.0 compliance
- Organization resolution pattern

### Common Errors to Avoid

❌ **Missing org_resolver.go** - Test won't compile (undefined: ResolveOrganization)
❌ **Missing UUID dependency** - Test won't compile (undefined: uuid)
❌ **Using old InitLogger signature** - Missing metadata/executionContext parameters
❌ **Using short name instead of UUID** - Should be `orgInfo.UUID`, not `orgInfo.ShortName`
❌ **Naming struct "Stage"** - Conflicts with test_logger.go Stage struct
❌ **Forgetting org_resolver.go in build** - Compilation failure during build

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

**ALL tests MUST generate Schema v2.0 compliant JSON output** for analytics, dashboards, and time-series analysis.

### Schema Overview

The F0RT1KA Test Results Schema v2.0 provides:
- **Schema versioning** for backward compatibility tracking
- **Rich metadata** with MITRE ATT&CK mapping and test scoring
- **Execution context** for batch correlation and organization filtering
- **Computed outcomes** with automatic protection status calculation
- **Pre-computed metrics** for dashboard performance
- **ISO 8601 UTC timestamps** for time-series analysis

### Updated InitLogger Signature (BREAKING CHANGE)

The `InitLogger()` function signature has changed in v2.0:

```go
// OLD (v1.x) - NO LONGER VALID
InitLogger(testID, testName string)

// NEW (v2.0) - REQUIRED
InitLogger(testID, testName string, metadata TestMetadata, executionContext ExecutionContext)
```

### Required Metadata Structure

```go
import "github.com/google/uuid"

// Define test metadata
metadata := TestMetadata{
    Version:    "1.0.0",           // Test version (semantic versioning)
    Category:   "defense_evasion", // See schema for valid categories
    Severity:   "high",            // critical, high, medium, low, informational
    Techniques: []string{"T1562.001"}, // MITRE ATT&CK technique IDs
    Tactics:    []string{"defense-evasion"}, // MITRE ATT&CK tactic names (kebab-case)
    Score:      8.5,               // Optional: Test quality score (0-10)
    ScoreBreakdown: &ScoreBreakdown{ // Optional: Detailed scoring
        RealWorldAccuracy:       2.5,
        TechnicalSophistication: 3.0,
        SafetyMechanisms:        2.0,
        DetectionOpportunities:  0.5,
        LoggingObservability:    1.0,
    },
    Tags: []string{"memory-patching", "watchdog"}, // Optional tags
}

// Resolve organization info from registry (UUID or short name)
// The org_resolver.go helper automatically resolves organization identifiers
orgInfo := ResolveOrganization("") // Empty string uses default from registry

// Define execution context
executionContext := ExecutionContext{
    ExecutionID:  uuid.New().String(), // Generate unique UUID
    Organization: orgInfo.UUID,         // Organization UUID (for Elasticsearch analytics)
    Environment:  "lab",                // production, staging, lab, development, testing
    DeploymentType: "manual",           // Optional: manual, automated, cicd, scheduled, on-demand
    TriggeredBy:    "user@example.com", // Optional: who/what initiated
    Configuration: &ExecutionConfiguration{ // Optional
        TimeoutMs:         300000,
        CertificateMode:   "self-healing",
        MultiStageEnabled: false,
    },
}

// Initialize logger with v2.0 signature
InitLogger(testID, testName, metadata, executionContext)
```

**Organization Resolution:**
- `ResolveOrganization("")` - Uses default from registry (auto-detects single org)
- `ResolveOrganization("sb")` - Resolves short name to full org info with UUID
- `ResolveOrganization("09b59276-...")` - Resolves UUID to full org info
- Returns `OrganizationInfo` with UUID, ShortName, FullName, CertificateFile
- Gracefully degrades if registry not available (uses identifier as-is)

### Schema Validation

Validate test results before committing:

```bash
# Validate single result
./utils/validate test_execution_log.json

# Validate all results in build directory
./utils/validate --all

# Validate with verbose output
./utils/validate --all --verbose
```

Python validation:
```bash
python utils/validate_test_results.py build/test-uuid/test_execution_log.json
python utils/validate_test_results.py --all
```

### Schema Documentation

- **Schema file**: `test-results-schema-v2.0.json` - JSON Schema definition
- **Guide**: `TEST_RESULTS_SCHEMA_GUIDE.md` - Comprehensive usage guide
- **Validator**: `utils/validate_test_results.py` - Python validation script

### Schema Enforcement Rules

1. **DO NOT modify test_logger.go data structures** - Schema must remain consistent
2. **ALWAYS provide metadata and executionContext** to InitLogger()
3. **VALIDATE results before committing** - Use validation utilities
4. **USE semantic versioning** for test versions (metadata.Version)
5. **MAP techniques to MITRE ATT&CK** - Use official technique IDs
6. **GENERATE unique ExecutionIDs** - Use UUID for each test run

### Benefits for Analytics

- **Time-series trending**: Track protection rates over time
- **Cross-organizational comparison**: Compare security posture across orgs
- **Batch correlation**: Group tests run together via ExecutionID
- **Technique coverage**: Analyze ATT&CK coverage and detection rates
- **Performance metrics**: Pre-computed aggregations for fast dashboards

## Certificate Trust & Code Signing

F0RT1KA tests are signed with the F0RT1KA code signing certificate.

**Two Approaches:**

1. **LimaCharlie IaC (RECOMMENDED)** - Automated cert installation via D&R rules
   - See `limacharlie-iac/README.md` for deployment
   - Deploy: `./limacharlie-iac/scripts/deploy-cert-installer.sh <org-name>`

2. **Embedded cert_installer (LEGACY)** - Per-test certificate installation code
   - Use for non-LimaCharlie deployments

**Certificate Location:**
- `signing-certs/F0RT1KA.pfx` - Private key (build machine only)
- `signing-certs/F0RT1KA.cer` - Public certificate (expires 2030-10-24)

**Organization Registry:**

F0RT1KA uses a central organization registry (`signing-certs/organization-registry.json`) that maps organization UUIDs to certificates and display names:
- **sb** (Superintendency of Banks): `09b59276-9efb-4d3d-bbdd-4b4663ef0c42`
- **tpsgl** (Transact Pay): `b2f8dccb-6d23-492e-aa87-a0a8a6103189`
- **rga** (RG Associates): `9634119d-fa6b-42b8-9b9b-90ad8f22e482`

The registry provides dual-identifier support:
- Build scripts accept either UUID or short name (e.g., `--org sb` or `--org 09b59276-...`)
- Test code uses `org_resolver.go` to resolve identifiers at runtime
- Graceful degradation if registry not available
- Auto-detection for single-org deployments (set `autoDetectSingleOrg: true`)
- Default organization configurable via `defaultOrganization` field

**Dual Signing (for ASR compatibility):**
```bash
# Dual-sign with org cert + F0RT1KA (accepts UUID or short name)
/build-sign-test <test-uuid> sb                          # Short name
/build-sign-test <test-uuid> 09b59276-9efb-4d3d-bbdd-... # UUID
/build-sign-test <test-uuid> tpsgl                       # For tpsgl organization
/build-sign-test <test-uuid> rga                         # For rga organization

# F0RT1KA-only (recommended for new deployments)
/build-sign-test <test-uuid>
```

## PowerShell Development Guidelines

All PowerShell scripts must:
- Include a function to check if running with admin privileges
- Implement automatic execution policy bypass functionality

## LimaCharlie D&R Rule Formatting

When creating D&R rules for LimaCharlie, note the format differences between file-based and web UI deployment.

**File Format** (for `limacharlie dr add` or `config push`):
```yaml
rules:
  rule-name-here:
    detect:
      event: RECEIPT
      op: and
      rules:
        - op: contains
          path: event/FILE_PATH
          value: "c:\\F0"
    respond:
      - action: output
        name: my-output
```

**Web UI Format** (paste directly into detect/respond fields):

The web UI expects NO outer wrapper and NO leading indentation. List items (`-`) must start at column 0.

Detect field:
```yaml
event: RECEIPT
op: and
rules:
- op: contains
  path: event/FILE_PATH
  value: "c:\\F0"
- op: is
  path: event/ERROR
  value: 259
  not: true
```

Respond field:
```yaml
- action: output
  name: my-output
```

**Common YAML Errors:**
- `Operation missing 'op' field` - Usually wrong nesting level
- `bad indentation of a mapping entry` - List items (`-`) have leading spaces; remove them

**Key Differences:**
| Aspect | File Format | Web UI Format |
|--------|-------------|---------------|
| Outer wrapper | `rules: { name: { detect: ... } }` | None |
| Indentation | 2-space nested | List items at column 0 |
| Rule name | In YAML structure | Separate field in UI |

## Build Utilities

### Build Tests
```bash
# Build specific test (Windows/amd64 by default)
./utils/gobuild build tests_source/intel-driven/<uuid>/    # Intel-driven tests
./utils/gobuild build tests_source/phase-aligned/<uuid>/   # Phase-aligned tests

# Build all tests
./utils/gobuild build-all
```

### Sign Test Binaries
```bash
# Sign specific binary
./utils/codesign sign build/<uuid>/<uuid>.exe

# Sign all binaries
./utils/codesign sign-all
```

### Check Windows Defender Protection
```powershell
# Verify security posture (run as Administrator)
powershell -ExecutionPolicy Bypass -File ./utils/Check-DefenderProtection.ps1
```

## Project Structure

```
tests_source/                 # All security tests
  ├── intel-driven/           # Tests from threat intelligence (APT reports, CVEs)
  │   └── <uuid>/             # Individual threat-based tests
  └── phase-aligned/          # Tests organized by pentest phases (DORA/TIBER-EU)
      └── <uuid>/             # Phase-aligned suite tests
sample_tests/                 # Reference implementations
  └── multistage_template/    # Multi-stage test reference
pentest_suites/               # Pentest readiness suite artifacts
rules/                        # Development guidelines
signing-certs/                # Code signing certificates
limacharlie-iac/              # LimaCharlie Infrastructure as Code
  ├── payloads/               # PowerShell scripts and payloads
  ├── rules/                  # Detection & Response rules
  ├── scripts/                # Deployment automation
  └── README.md               # Deployment guide
utils/                        # Build and signing utilities
  ├── gobuild                 # Cross-platform test builder
  ├── codesign                # Code signing utility
  ├── Check-DefenderProtection.ps1  # Defender status checker
  ├── validate-attack-flow-html.sh  # Attack flow validator
  └── README.md               # Utility documentation
```

### Test Categories

| Category | Location | Created By | Purpose |
|----------|----------|------------|---------|
| Cyber-Hygiene | `tests_source/cyber-hygiene/` | `@agent-sectest-builder` | Endpoint and cloud identity configuration validation |
| Intel-Driven | `tests_source/intel-driven/` | `@agent-sectest-builder` | Tests from threat intelligence, APT reports, CVEs |
| Phase-Aligned | `tests_source/phase-aligned/` | `@agent-pentest-readiness-builder` | DORA/TIBER-EU pentest phase validation |

### Cyber-Hygiene Subcategories

The cyber-hygiene category uses subcategories to distinguish test domains:

| Subcategory | Purpose | Auth Required |
|-------------|---------|---------------|
| `baseline` | Endpoint OS hardening (Defender, ASR, LSASS, SMB, audit logging) | None (local registry/commands) |
| `identity-tenant` | Entra ID tenant security (CISA SCuBA baseline: MFA, CA, PIM, guest access) | Service principal via Graph API |
| `identity-endpoint` | Endpoint identity posture (device join, WHfB, MDM, PRT, BitLocker escrow) | None (local dsregcmd/registry) |

**Identity-tenant tests** require environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` pointing to a service principal with read-only Graph API permissions (Policy.Read.All, Directory.Read.All, RoleManagement.Read.All, AuditLog.Read.All, Application.Read.All).

## Bundle Results Protocol (Cyber-Hygiene Bundles)

Cyber-hygiene bundle tests write `c:\F0\bundle_results.json` alongside the standard `test_execution_log.json`. This provides **per-control granularity** — each security control (e.g., "Defender Real-Time Protection enabled") becomes an independent Elasticsearch document, enabling fine-grained compliance dashboards and trend analysis.

**Applies to**: cyber-hygiene bundle tests only. Intel-driven and phase-aligned tests use the standard single-document result path.

### BundleResults Schema

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Schema version (currently `"1.0"`) |
| `bundle_id` | string | Bundle test UUID |
| `bundle_name` | string | Human-readable bundle name |
| `bundle_category` | string | Always `"cyber-hygiene"` |
| `bundle_subcategory` | string | `"baseline"`, `"identity-tenant"`, or `"identity-endpoint"` |
| `execution_id` | string | Matches `ExecutionContext.ExecutionID` for correlation |
| `started_at` | string | ISO 8601 UTC timestamp |
| `completed_at` | string | ISO 8601 UTC timestamp |
| `overall_exit_code` | int | 126 (all compliant) or 101 (any non-compliant) |
| `total_controls` | int | Total number of controls evaluated |
| `passed_controls` | int | Number of compliant controls |
| `failed_controls` | int | Number of non-compliant controls |
| `controls` | array | Array of `ControlResult` objects |

### ControlResult Schema

| Field | Type | Description |
|-------|------|-------------|
| `control_id` | string | Stable ID, e.g., `"CH-DEF-001"` |
| `control_name` | string | Human-readable control name |
| `validator` | string | Parent validator module name |
| `exit_code` | int | 126 = compliant, 101 = non-compliant |
| `compliant` | bool | Whether the control passed |
| `severity` | string | `critical`, `high`, `medium`, `low` |
| `category` | string | `"cyber-hygiene"` |
| `subcategory` | string | `"baseline"`, `"identity-tenant"`, or `"identity-endpoint"` |
| `techniques` | []string | MITRE ATT&CK technique IDs |
| `tactics` | []string | MITRE ATT&CK tactic names (kebab-case) |
| `expected` | string | Expected configuration value |
| `actual` | string | Actual configuration value found |
| `details` | string | Additional context or remediation info |
| `skipped` | bool | Whether the control was skipped |
| `error_message` | string | Error message if skipped or failed to evaluate |

### Control ID Naming Convention

Control IDs use the format `CH-{CAT}-{NUM}` where `CAT` is a 3-letter uppercase prefix and `NUM` is zero-padded:

| Prefix | Validator | Controls |
|--------|-----------|----------|
| `DEF` | Defender Settings | 6 |
| `LSS` | LSASS Protection | 3 |
| `ASR` | Attack Surface Reduction | 8 |
| `SMB` | SMB Hardening | 5 |
| `PWS` | PowerShell Security | 4 |
| `NET` | Network Security | 4 |
| `AUD` | Audit Logging | 9 |
| `LOK` | Account Lockout | 5 |
| `LAP` | LAPS Configuration | 2 |
| `PRT` | Print Spooler | 2 |
| `IEP` | Identity Endpoint Posture | 22 |
| `ITN` | Identity Tenant (Entra ID) | 26 |

Total: 48 controls across 10 validators (baseline subcategory), 22 controls across 5 validators (identity-endpoint subcategory), 26 controls across 8 validators (identity-tenant subcategory).

### Implementation Functions

Bundle results are produced using helpers from `check_utils.go`:

- **`CollectControlResults(validatorName, category, subcategory string, checks []CheckResult) []ControlResult`** — Converts validator check results into per-control results with proper exit codes (126/101)
- **`WriteBundleResults(results *BundleResults) error`** — Serializes and writes `c:\F0\bundle_results.json`

### End-to-End Pipeline

1. **Test writes** `c:\F0\bundle_results.json` via `WriteBundleResults()`
2. **Agent reads** the file after test execution, validates `bundle_id == task.TestUUID`
3. **Agent reports** the bundle as an optional field in the task result payload
4. **Backend detects** `bundle_results.controls` in the result
5. **Backend fans out** each control into an independent ES document via `client.bulk()`
6. **ES documents** include `f0rtika.is_bundle_control: true` and per-control fields
7. **Composite test_uuid**: Each control document uses `<bundle-uuid>::<control-id>` as `test_uuid` (e.g., `a3c923ae-...::CH-DEF-001`). The `::` separator is unambiguous — split on it to recover bundle_id and control_id

### Reference Implementation

See `tests_source/cyber-hygiene/a3c923ae-1a46-4b1f-b696-be6c2731a628/` for the baseline bundle with 48 controls across 10 validators.

For the ingestion side, see ProjectAchilles: `backend/src/services/agent/results.service.ts` (`ingestBundleControls()`).

## Multi-Binary Bundle Architecture (Cyber-Hygiene)

Multi-binary bundles compile each validator as a **separate embedded binary**. If AV/EDR quarantines one validator, the rest still execute and report results — providing resilient compliance data even under active endpoint protection.

### Which Bundles Use Multi-Binary

| Bundle | UUID | Architecture | Validators | Controls |
|--------|------|-------------|------------|----------|
| Baseline (Windows Defender) | `a3c923ae` | **Multi-binary** | 10 | 48 |
| Identity Endpoint Posture | `7659eeba` | **Multi-binary** | 5 | 22 |
| Identity Tenant (Entra ID) | `4f484076` | Single-binary | 8 | 26 |

**Why identity-tenant stays single-binary**: Its validators query Microsoft Graph API via PowerShell — they share an authenticated Graph session established in `main()`. Splitting into separate processes would require each validator to authenticate independently, which is impractical.

### Runtime Flow

```
Orchestrator (signed, deployed by agent)
  ├── //go:embed validator-defender.exe   (signed before embedding)
  ├── //go:embed validator-lsass.exe
  └── ...

  1. Extract each validator to c:\F0\
  2. Sleep 1.5s for AV/EDR reaction time
  3. Check if quarantined (os.Stat — file still exists?)
  4. If quarantined → mark all that validator's controls as skipped
  5. If present → execute as subprocess, capture exit code
  6. Read validator's output JSON (c:\F0\vr_<name>.json)
  7. Merge all results into c:\F0\bundle_results.json
```

### File Structure (Multi-Binary Bundle)

| File | Role |
|------|------|
| `<uuid>.go` | Orchestrator — embeds signed validators, extract/execute/merge |
| `orchestrator_utils.go` | Orchestrator helpers: extract, quarantine check, execute, merge, BundleResults |
| `validator_<name>.go` | Standalone `main()` for one validator (uses `//go:build ignore`) |
| `checks_<name>.go` | Check functions for one validator (unchanged from single-binary) |
| `check_utils.go` | Shared types: CheckResult, ValidatorResult, PowerShell/format helpers |
| `validator_output.go` | ValidatorOutput struct + WriteValidatorOutput() for `vr_<name>.json` |
| `test_logger.go` | Schema v2.0 logging (orchestrator only) |
| `org_resolver.go` | Organization registry helper (orchestrator only) |
| `build_all.sh` | Sign-before-embed build workflow |

### Compilation Split

Go requires exactly one `main()` per binary. Files are split into two build groups:

| Build target | Files |
|---|---|
| **Validator binary** | `validator_<name>.go` + `checks_<name>.go` + `check_utils.go` + `validator_output.go` |
| **Orchestrator** | `<uuid>.go` + `orchestrator_utils.go` + `test_logger.go` + `org_resolver.go` + `es_config.go` |

Validator `.go` files use `//go:build ignore` so `go build .` (package mode) skips them; `build_all.sh` explicitly lists files for each validator.

### Validator Output Protocol

Each validator writes `c:\F0\vr_<name>.json` with:
```json
{
  "validator_name": "defender",
  "compliant": true,
  "exit_code": 126,
  "checks": [
    { "control_id": "CH-DEF-001", "name": "...", "passed": true, ... }
  ]
}
```

Then exits 126 (compliant) or 101 (non-compliant). The orchestrator reads these files and merges them into `bundle_results.json`.

### Build Script (build_all.sh) for Multi-Binary Bundles

The build_all.sh follows a 7-step sign-before-embed workflow:
1. Build N unsigned validator binaries
2. Sign each validator binary (BEFORE embedding)
3. Verify signatures
4. Build orchestrator (embeds SIGNED validators via `//go:embed`)
5. Sign orchestrator
6. Cleanup temporary validator binaries from source dir
7. Calculate SHA1 hashes

**Three signing modes** (auto-detected):
1. `projectachilles` — cert via `F0_SIGN_CERT_PATH` + `F0_SIGN_CERT_PASS_FILE` env vars
2. `f0library` — local `signing-certs/F0RT1KA.pfx`
3. `none` — unsigned (warning printed)

### Quarantine Resilience

When a validator binary is quarantined by AV/EDR:
- The orchestrator detects the missing file via `os.Stat()`
- All controls for that validator are marked `skipped: true` in `bundle_results.json`
- The `skipped_controls` count is reported in the bundle summary
- Other validators continue executing normally

## Required Files for Each Test

1. `<uuid>/` directory (use lowercase UUID)
2. `<uuid>.go` - Main test implementation
3. `test_logger.go` - Comprehensive logging module with Schema v2.0 support
4. `org_resolver.go` - Organization registry helper for UUID resolution
5. `README.md` - Brief overview
6. `<uuid>_info.md` - Detailed information card
7. `go.mod` - Module file with Prelude library dependencies
8. `build_all.sh` - Build script for tests with embedded components (if needed)

**Note**: Always copy `test_logger.go` and `org_resolver.go` from `sample_tests/` to ensure consistency.

## Elasticsearch Catalog Sync (MANDATORY for new tests)

Test results in Elasticsearch are enriched with metadata from a catalog index. The sync script supports 4 test categories: `cyber-hygiene`, `intel-driven`, `mitre-top10`, `phase-aligned`.

### 1. Include Metadata Header in Go File

The main test file (`<uuid>.go`) MUST include the metadata comment block. **Enhanced format (v2.0)** includes new taxonomy fields:

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
UNIT: response
CREATED: 2026-01-17
AUTHOR: sectest-builder
*/
```

**Field Reference:**

| Field | Required | Description | Example Values |
|-------|----------|-------------|----------------|
| `ID` | Yes | Test UUID | `eafce2fc-75fd-4c62-92dc-32cabe5cf206` |
| `NAME` | Yes | Human-readable name | `SafePay Ransomware Simulation` |
| `TECHNIQUES` | Yes | ATT&CK technique IDs | `T1562.001, T1059.001` |
| `TACTICS` | Yes | ATT&CK tactics (kebab-case) | `defense-evasion, execution` |
| `SEVERITY` | Yes | Impact level | `critical`, `high`, `medium`, `low`, `informational` |
| `TARGET` | Yes | Target platforms | `windows-endpoint`, `active-directory`, `cloud-aws` |
| `COMPLEXITY` | Yes | Execution complexity | `low` (<30s), `medium` (30s-5min), `high` (>5min) |
| `THREAT_ACTOR` | Yes | APT attribution | `APT29`, `Lazarus`, `SafePay`, `N/A` |
| `SUBCATEGORY` | Yes | Secondary classification | `ransomware`, `apt`, `c2`, `baseline`, `identity-tenant`, `identity-endpoint` |
| `TAGS` | Yes | Searchable keywords | `powershell, defender-evasion` |
| `AUTHOR` | Yes | Test creator | `sectest-builder` |

**All v2.0 fields are required.** The sync script provides sensible defaults (severity=medium, complexity=medium) for any legacy tests not yet updated.

### 2. Sync Catalog After Creating Test

After creating or updating a test, sync the catalog to Elasticsearch:

```bash
# Activate Python venv
source .venv/bin/activate

# Sync test catalog
python3 utils/sync-test-catalog-to-elasticsearch.py
```

### 3. Re-execute Enrich Policy

In Kibana Dev Tools, re-execute the enrich policy to pick up new tests:

```json
POST /_enrich/policy/f0rtika-test-enrichment/_execute
```

### Enriched Fields in Elasticsearch

After sync, RECEIPT events will have these fields under `f0rtika.*`:

| Field | Description |
|-------|-------------|
| `f0rtika.test_uuid` | Test identifier (extracted from FILE_PATH) |
| `f0rtika.test_name` | Human-readable test name |
| `f0rtika.category` | Test category (auto-derived from directory) |
| `f0rtika.subcategory` | Secondary classification |
| `f0rtika.techniques` | MITRE ATT&CK technique IDs |
| `f0rtika.tactics` | MITRE ATT&CK tactic names |
| `f0rtika.severity` | Impact level (critical/high/medium/low/informational) |
| `f0rtika.target` | Target platforms array |
| `f0rtika.complexity` | Execution complexity (low/medium/high) |
| `f0rtika.threat_actor` | APT group attribution |
| `f0rtika.tags` | Searchable keyword array |
| `f0rtika.score` | Test quality score (0-10) |
| `f0rtika.error_name` | Human-readable exit code (Unprotected, ExecutionPrevented, etc.) |
| `f0rtika.is_protected` | Boolean: was endpoint protected? |
| `f0rtika.bundle_id` | Bundle test UUID (only for bundle control documents) |
| `f0rtika.bundle_name` | Bundle human-readable name |
| `f0rtika.control_id` | Individual control ID (e.g., `CH-DEF-001`) |
| `f0rtika.control_validator` | Parent validator name |
| `f0rtika.is_bundle_control` | Boolean: true for fan-out bundle control documents |

**Example Queries:**
```
# All intel-driven ransomware tests
f0rtika.category: "intel-driven" AND f0rtika.subcategory: "ransomware"

# Tests targeting Active Directory
f0rtika.target: "active-directory"

# Unprotected critical severity tests
f0rtika.is_protected: false AND f0rtika.severity: "critical"

# Tests attributed to specific threat actor
f0rtika.threat_actor: "APT29"

# All identity hygiene tests (tenant + endpoint)
f0rtika.category: "cyber-hygiene" AND f0rtika.subcategory: "identity-*"

# Entra ID tenant security validation results
f0rtika.subcategory: "identity-tenant"

# All bundle control results
f0rtika.is_bundle_control: true

# Failed Defender controls across all endpoints
f0rtika.control_id: CH-DEF-* AND f0rtika.is_protected: false

# All controls from baseline bundle on a specific host
f0rtika.bundle_id: "a3c923ae*" AND routing.hostname: "WORKSTATION01"

# Non-compliant critical controls
f0rtika.is_bundle_control: true AND f0rtika.severity: "critical" AND f0rtika.is_protected: false
```

**See**: `limacharlie-iac/ELASTICSEARCH-ENRICHMENT-GUIDE.md` for full setup details.

## Test Score Format Requirements (MANDATORY)

**ALL tests MUST use the exact score format expected by the security-test-browser.**

The security-test-browser parses test documentation using specific regex patterns. Incorrect formatting will cause scores to not display in the web interface.

### README.md Score Format

```markdown
**Test Score**: **9.2/10**
```

**Critical Rules:**
- Colon OUTSIDE the bold markers: `**: **` (NOT `:**`)
- Score value MUST be bold: `**9.2/10**`
- Use period for decimals: `9.2` (NOT `9,2`)
- Format: `**Test Score**: **X.X/10**`

### info.md Score Format

The info.md file MUST include a level 2 header with the score:

```markdown
## Test Score: 9.2/10
```

**Critical Rules:**
- Use level 2 header: `##`
- Space after colon: `: `
- Score as plain text (no bold in header)
- Place BEFORE "Score Breakdown" section

**Complete info.md Score Section:**
```markdown
## Test Score: 9.2/10

### Score Breakdown

| Criterion | Score |
|-----------|-------|
| **Real-World Accuracy** | **2.8/3.0** |
| **Technical Sophistication** | **3.0/3.0** |
| **Safety Mechanisms** | **2.2/2.0** |
| **Detection Opportunities** | **0.7/1.0** |
| **Logging & Observability** | **1.5/1.5** |
```

### Score Validation

Before committing test documentation, validate the score format:

```bash
# Validate specific test
./utils/validate-score-format.sh <test-uuid>

# Validate all tests
./utils/validate-score-format.sh
```

The validation script checks:
- ✓ README.md has `**Test Score**: **X.X/10**` format
- ✓ info.md has `## Test Score: X.X/10` header
- ✓ Both files show the same score value
- ✓ Score breakdown table uses correct formatting

**Why This Matters:**
The security-test-browser backend (`metadataExtractor.ts`) uses these exact regex patterns to parse scores:
- README.md: `/\*\*Test Score\*\*:\s*\*\*(\d+(?:\.\d+)?)\/10\*\*/i`
- info.md: `/##\s*Test Score:\s*(\d+(?:\.\d+)?)\/10/i`

Deviation from these formats will cause scores to not appear in the browser interface.

## Prerequisites

- **Prelude Libraries**: Must be set up in `preludeorg-libraries/` directory
- **Go 1.21+**: Required for building
- **Windows Target**: Tests are Windows-specific

## Key Conventions

- Use `Endpoint.Say()` for console output
- Check `Endpoint.Quarantined()` after dropping binaries
- Always clean up artifacts after test completion
- Follow MITRE ATT&CK mapping standards

## Stdout/Stderr Capture Pattern (MANDATORY)

When executing embedded binaries, **ALWAYS** capture stdout/stderr to both console and file using `io.MultiWriter`. This preserves raw output for forensic analysis and debugging.

**Required imports:**
```go
import (
    "bytes"
    "io"
)
```

**Implementation pattern:**
```go
// Execute the binary and capture output to both console and file
cmd := exec.Command(binaryPath)

// Create buffer to capture output
var outputBuffer bytes.Buffer

// Use MultiWriter to write to both console and buffer
stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)

cmd.Stdout = stdoutMulti
cmd.Stderr = stderrMulti

err := cmd.Run()

// Save raw output to file in c:\F0
outputFilePath := filepath.Join(targetDir, "<binary-name>_output.txt")
if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
    LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save raw output: %v", writeErr))
} else {
    LogMessage("INFO", "Output Capture", fmt.Sprintf("Raw output saved to: %s (%d bytes)", outputFilePath, outputBuffer.Len()))
}
```

**Output file naming convention:** `c:\F0\<binary-name>_output.txt`

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
- 1-2 techniques → Standard pattern
- 3+ techniques → Multi-stage pattern

## Test Development Workflow

For building new tests, use the **sectest-builder agent**:
```
@agent-sectest-builder
```

The agent handles:
- Test implementation patterns
- Single-binary embedding
- Logging implementation
- Exit code logic
- Multi-stage architecture (when applicable)
- Test scoring
- Documentation generation

## Common Pitfalls to Avoid

❌ **DON'T** drop files outside `c:\F0`
❌ **DON'T** require multiple files for deployment
❌ **DON'T** hardcode exit codes (always evaluate results)
❌ **DON'T** skip logging implementation
❌ **DON'T** forget to sign stage binaries BEFORE embedding (multi-stage tests)

✅ **DO** embed all dependencies into single binary
✅ **DO** implement comprehensive logging
✅ **DO** evaluate protection effectiveness before choosing exit code
✅ **DO** clean up build artifacts after embedding
✅ **DO** use established test structure patterns

## Multi-Stage Test Build Requirements (MANDATORY)

**ALL multi-stage tests MUST use the modern build_all.sh pattern.**

### Modern build_all.sh Pattern (7-Step Process)

**Reference Implementation**: `tests_source/intel-driven/eafce2fc-75fd-4c62-92dc-32cabe5cf206/build_all.sh`

**REQUIRED Features:**
- ✅ **Organization registry integration** - Uses `utils/resolve_org.sh` helper
- ✅ **Command-line arguments** - `--org <identifier>` support (UUID or short name)
- ✅ **Dual signing** - org cert + F0RT1KA via `codesign sign-nested`
- ✅ **Signature verification** - Uses `osslsigncode verify` on all binaries
- ✅ **SHA1 hash reporting** - Calculates and displays hashes for all binaries
- ✅ **Automatic cleanup** - Removes temporary stage binaries from source directory
- ✅ **NO interactive prompts** - Fully automated, CI/CD ready
- ✅ **Professional output** - Step indicators, file sizes, deployment instructions

**7-Step Build Workflow:**
1. **Step 1/7**: Build stage binaries (unsigned)
2. **Step 2/7**: Build cleanup utility
3. **Step 3/7**: Dual-sign stage binaries + cleanup (org cert + F0RT1KA)
4. **Step 4/7**: Verify signatures with osslsigncode
5. **Step 5/7**: Build main orchestrator (embeds SIGNED stages via `//go:embed`)
6. **Step 6/7**: Dual-sign main orchestrator
7. **Step 7/7**: Calculate SHA1 hashes and cleanup temporary files

**Why This Matters:**
- **Multi-organization support** - Deployable across sb, tpsgl, rga organizations
- **ASR bypass** - Dual signing with org cert bypasses Application Guard
- **Binary integrity** - SHA1 hashes enable verification and audit trails
- **CI/CD ready** - No interactive prompts, fully automated
- **Professional** - Enterprise-grade build process

**Usage Examples:**
```bash
# Use default organization from registry
./build_all.sh

# Specify organization by short name
./build_all.sh --org sb
./build_all.sh --org tpsgl
./build_all.sh --org rga

# Specify organization by UUID
./build_all.sh --org 09b59276-9efb-4d3d-bbdd-4b4663ef0c42
```

**Legacy Pattern (DEPRECATED):**
The old pattern with:
- ❌ No organization support
- ❌ Single signing only (F0RT1KA)
- ❌ Interactive prompts ("Continue without signing? (y/n)")
- ❌ No signature verification
- ❌ No SHA1 hashing
- ❌ No cleanup

**Is NO LONGER ACCEPTABLE for new or updated tests.**

**When Creating/Updating Multi-Stage Tests:**
1. Copy `tests_source/intel-driven/eafce2fc-75fd-4c62-92dc-32cabe5cf206/build_all.sh` as template
2. Update `TEST_UUID` variable
3. Update `STAGES` array with your techniques
4. Update test name in header comment
5. Test with `./build_all.sh --org sb`

See `@agent-sectest-builder` configuration for complete template.

## Github Repository Management

- Initialize and create a private repository on Github
- For all changes, additions and fixes, commit and create PRs when applicable

## Complete Test Development Workflow (4-Agent Pipeline)

F0RT1KA provides a complete red-to-blue workflow using specialized agents:

1. **`@agent-sectest-builder`** - Creates individual attack simulation tests
   - Analyzes threat intelligence and builds Go-based security tests
   - Handles single-binary embedding, logging, scoring

2. **`@agent-pentest-readiness-builder`** - Creates phase-aligned test suites for DORA/TIBER-EU
   - Builds test suites organized by pentest phases (reconnaissance through exfiltration)
   - Generates readiness scores and compliance evidence
   - Produces gap analysis and remediation roadmaps
   - Supports results analysis workflow for post-execution reporting

3. **`@agent-attack-flow-diagram-builder`** - Visualizes the attack flow
   - Creates interactive HTML attack flow diagrams
   - Maps MITRE ATT&CK techniques visually

4. **`@agent-defense-guidance-builder`** - Creates defense documentation
   - Generates KQL detection queries for Microsoft Sentinel/Defender
   - Creates YARA rules for file/memory detection
   - Produces LimaCharlie D&R rules ready for deployment
   - Provides hardening scripts (PowerShell) and guidance
   - Includes incident response playbooks

**Agent Selection Guide:**
| Need | Agent |
|------|-------|
| Test specific threat/technique | `@agent-sectest-builder` |
| Validate TIBER-EU phase readiness | `@agent-pentest-readiness-builder` |
| Visualize attack flow | `@agent-attack-flow-diagram-builder` |
| Generate detection rules | `@agent-defense-guidance-builder` |

**Output Files from Pentest Readiness Agent:**
| File | Purpose |
|------|---------|
| `<suite-id>_coverage_matrix.md` | Technique coverage documentation |
| `<suite-id>_gap_analysis.md` | Identified detection gaps |
| `<suite-id>_metadata.json` | Dashboard visualization data |
| `<suite-id>_dora_evidence.md` | DORA Article 25/26 compliance evidence |
| `<suite-id>_remediation_roadmap.md` | Prioritized gap remediation |

**Output Files from Defense Guidance Agent:**
| File | Purpose |
|------|---------|
| `<uuid>_DEFENSE_GUIDANCE.md` | Comprehensive defense document |
| `<uuid>_detections.kql` | Microsoft Sentinel queries |
| `<uuid>_rules.yar` | YARA detection rules |
| `<uuid>_dr_rules.yaml` | LimaCharlie D&R rules |
| `<uuid>_hardening.ps1` | PowerShell hardening scripts |

## Additional Documentation

For detailed implementation guides, see:
- `limacharlie-iac/README.md` - Certificate deployment
- `DUAL_SIGNING_STRATEGY.md` - Code signing details
- `sample_tests/multistage_template/` - Multi-stage test patterns
- `pentesting/agentic_pentest.md` - DORA/TIBER-EU pentest methodology
- `pentesting/PENTEST_READINESS_GUIDE.md` - Pentest readiness builder usage guide
- `rules/` - Development guidelines
- Agent `@agent-sectest-builder` for individual test creation
- Agent `@agent-pentest-readiness-builder` for DORA/TIBER-EU readiness suites
- Agent `@agent-attack-flow-diagram-builder` for attack visualization
- Agent `@agent-defense-guidance-builder` for defense documentation
