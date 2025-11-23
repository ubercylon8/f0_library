# CLAUDE.md

This file provides essential guidance to Claude Code when working with this repository.

## Overview
This is the F0RT1KA security testing framework - a specialized library for evaluating AV/EDR detection capabilities against various threat tactics and techniques. Tests are written in Go and mapped to the MITRE ATT&CK framework.

## Critical Development Rules (NEVER VIOLATE)

1. **ALL binaries MUST be dropped to `c:\F0`** - Hard requirement for all tests
2. **ALL tests MUST be SINGLE-BINARY deployments** - Embed all dependencies using `//go:embed`
3. **ALL tests MUST implement comprehensive logging** - Use test_logger.go pattern
4. **ALL tests MUST conform to Schema v2.0** - Use updated InitLogger signature with metadata and executionContext
5. **ALL tests MUST implement organization UUID support** - See Organization UUID Implementation section below
6. **NEVER hardcode exit codes** - Always evaluate actual results before determining exit code
7. **NEVER modify test_logger.go schema** - Schema must remain consistent across all tests
8. Tests simulate real attack techniques - handle with appropriate security measures
9. Map every test to specific MITRE ATT&CK techniques

## Organization UUID Implementation (MANDATORY)

**ALL tests MUST implement organization UUID support** for multi-org analytics and Elasticsearch tracking.

### Implementation Checklist

Every new test MUST include the following components:

1. **Copy org_resolver.go**
   ```bash
   # Copy from sample_tests/multistage_template/org_resolver.go
   cp sample_tests/multistage_template/org_resolver.go tests_source/<uuid>/
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

## Build Utilities

### Build Tests
```bash
# Build specific test (Windows/amd64 by default)
./utils/gobuild build tests_source/<uuid>/

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
tests_source/         # New tests go here
sample_tests/         # Reference implementations
  ├── multistage_template/  # Multi-stage test reference
rules/                # Development guidelines
signing-certs/        # Code signing certificates
limacharlie-iac/      # LimaCharlie Infrastructure as Code
  ├── payloads/       # PowerShell scripts and payloads
  ├── rules/          # Detection & Response rules
  ├── scripts/        # Deployment automation
  └── README.md       # Deployment guide
utils/                # Build and signing utilities
  ├── gobuild         # Cross-platform test builder
  ├── codesign        # Code signing utility
  ├── Check-DefenderProtection.ps1  # Defender status checker
  ├── validate-attack-flow-html.sh  # Attack flow validator
  └── README.md       # Utility documentation
```

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

## Prerequisites

- **Prelude Libraries**: Must be set up in `preludeorg-libraries/` directory
- **Go 1.21+**: Required for building
- **Windows Target**: Tests are Windows-specific

## Key Conventions

- Use `Endpoint.Say()` for console output
- Check `Endpoint.Quarantined()` after dropping binaries
- Always clean up artifacts after test completion
- Follow MITRE ATT&CK mapping standards

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

## Github Repository Management

- Initialize and create a private repository on Github
- For all changes, additions and fixes, commit and create PRs when applicable

## Additional Documentation

For detailed implementation guides, see:
- `limacharlie-iac/README.md` - Certificate deployment
- `DUAL_SIGNING_STRATEGY.md` - Code signing details
- `sample_tests/multistage_template/` - Multi-stage test patterns
- `rules/` - Development guidelines
- Agent `@agent-sectest-builder` for test creation
