---
name: sectest-implementation
description: Implement F0RT1KA security test Go code including bug prevention rules, Schema v2.0 compliance, multi-stage architecture, templates, metadata headers, PowerShell requirements, stdout/stderr capture, and dual logging patterns.
---

# Security Test Implementation

This skill handles Phase 1 (continued) of security test creation: writing the Go source code, stage binaries, and embedded scripts. It assumes the `sectest-source-analysis` skill has already run and the orchestrator context contains uuid, techniques, platform, architecture, etc.

## Pre-Implementation: Read Framework Documentation

Before writing any code, ALWAYS read:
```
Read CLAUDE.md
Read sample_tests/multistage_template/README.md
Read docs/TEST_RESULTS_SCHEMA_GUIDE.md
```

Copy required shared files from `sample_tests/multistage_template/`:
- `test_logger.go` (shared logger — NO build tag)
- `test_logger_<platform>.go` (platform constants + system info)
- `org_resolver.go` (organization registry helper)

## Known Bug Prevention Rules (MANDATORY)

These rules address recurring bugs. Violating them causes **false positive exit codes**.

### Rule 1: NEVER Inject Blame Keywords Into Error Messages

Error wrappers must describe the operation that failed, NOT interpret WHY it failed. `determineExitCode()` pattern-matches on keywords — injecting them into `fmt.Errorf()` causes ANY error to be misclassified as "EDR blocked" (exit 126).

```go
// WRONG — poisons error with "access denied" regardless of actual error
return fmt.Errorf("registry access denied: %v (EDR blocked access)", err)

// CORRECT — neutral description, lets real Windows error strings drive exit code
return fmt.Errorf("failed to open registry key %s: %v", keyPath, err)
```

**Forbidden keywords in fmt.Errorf wrappers**: "access denied", "permission denied", "blocked", "prevented", "EDR", "quarantine". Only `determineExitCode()` should interpret these from ACTUAL OS error strings.

**CRITICAL**: The `determineExitCode()` default fallback MUST be `StageError` (999), NEVER `StageBlocked` (126).

### Rule 2: Handle SYSTEM vs User Execution Context

Tests on Prelude run as SYSTEM. HKCU maps to `HKU\.DEFAULT` which lacks user-specific keys.

```go
func isSystemContext() bool {
    username := os.Getenv("USERNAME")
    return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}

// Use HKLM for SYSTEM context, HKCU for user context
if isSystemContext() {
    // Use HKLM\Software\Microsoft\Windows\CurrentVersion\Run
} else {
    // Use HKCU\Software\Microsoft\Windows\CurrentVersion\Run
}
```

**schtasks.exe**: `/SC ONLOGON /RL HIGHEST` fails as SYSTEM. Use `/RU SYSTEM` instead when `isSystemContext()` returns true.

### Rule 3: Use os.Stat() for Quarantine Detection

`Endpoint.Quarantined()` has a path-doubling bug with absolute paths. Use direct `os.Stat()`:

```go
// WRONG — path doubling bug with absolute paths
if Endpoint.Quarantined(fmt.Sprintf("c:\\F0\\%s", stage.BinaryName), stage.BinaryData) {

// CORRECT — direct file existence check
time.Sleep(3 * time.Second) // Give EDR time to react
if _, err := os.Stat(filepath.Join("c:\\F0", stage.BinaryName)); os.IsNotExist(err) {
    // File was quarantined by EDR
}
```

### Rule 4: Separate Benign from Critical Metrics

Track simulation steps and protection tests with SEPARATE counters. Exit code must reflect CRITICAL metrics only:

```go
// CORRECT — separate counters
var svcTamperAttempts, svcTamperBlocked, svcTamperSucceeded int

// Exit code based on CRITICAL metrics only:
if svcTamperAttempts == 0 { return StageError }  // no EDR found
if svcTamperSucceeded == 0 { return StageBlocked } // all blocked
```

### Rule 5: Handle Silent/Empty Error Output

`sc.exe stop` on tamper-protected services may return empty output. Treat unclear results as "blocked".

### Rule 6: Use Windows Service Names, NOT Display Names

`sc.exe` uses registry service names (e.g., `CSFalconService`), NOT display names (e.g., `CrowdStrike Falcon Sensor`).

### Rule 7: Use Gzip Compression for Multi-Stage Embedded Binaries

ALWAYS compress stage binaries with gzip. NEVER use UPX or runtime packers (they trigger EDR heuristic detections).

```go
// CORRECT — embeds gzip-compressed PE
//go:embed TEMPLATE-UUID-T1134.001.exe.gz
var stage1Compressed []byte

func decompressGzip(compressed []byte) ([]byte, error) {
    reader, err := gzip.NewReader(bytes.NewReader(compressed))
    if err != nil { return nil, err }
    defer reader.Close()
    return io.ReadAll(reader)
}
```

### Rule 8: NEVER Default to StageBlocked in determineExitCode()

The safest default is "error/unknown" (999). A false "PROTECTED" verdict is worse than an "ERROR" verdict.

```go
func determineExitCode(err error) int {
    if err == nil { return StageSuccess }
    errStr := err.Error()
    if containsAny(errStr, []string{"access denied", "access is denied", "permission denied"}) {
        return StageBlocked
    }
    if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
        return StageQuarantined
    }
    if containsAny(errStr, []string{"not found", "does not exist", "no such"}) {
        return StageError
    }
    return StageError // CORRECT — unrecognized errors are test errors, not EDR actions
}
```

## Test Results Schema v2.0 Compliance

ALL tests MUST conform to Schema v2.0. The InitLogger signature:

```go
// REQUIRED — v2.0
InitLogger(testID, testName string, metadata TestMetadata, executionContext ExecutionContext)
```

### Required TestMetadata

```go
metadata := TestMetadata{
    Version:    "1.0.0",
    Category:   "ransomware",  // ransomware, data_exfiltration, privilege_escalation,
                                // defense_evasion, persistence, credential_access, etc.
    Severity:   "critical",    // critical, high, medium, low, informational
    Techniques: []string{"T1486", "T1490"},
    Tactics:    []string{"impact"},  // kebab-case
    Score:      8.5,
    ScoreBreakdown: &ScoreBreakdown{
        RealWorldAccuracy:       2.5,
        TechnicalSophistication: 3.0,
        SafetyMechanisms:        2.0,
        DetectionOpportunities:  0.5,
        LoggingObservability:    1.0,
    },
    Tags: []string{"encryption", "file-operations"},
}
```

### Required ExecutionContext

```go
orgInfo := ResolveOrganization("")

executionContext := ExecutionContext{
    ExecutionID:    uuid.New().String(),
    Organization:   orgInfo.UUID,
    Environment:    "lab",
    DeploymentType: "manual",
    Configuration: &ExecutionConfiguration{
        TimeoutMs:       300000,
        CertificateMode: "self-healing",
    },
}
```

## Metadata Header (MANDATORY)

Every test Go file MUST include this comment block for Elasticsearch enrichment:

```go
//go:build <platform>
// +build <platform>

/*
ID: <uuid>
NAME: <Test Name>
TECHNIQUES: T1234, T1567.001
TACTICS: defense-evasion, execution
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: APT29
SUBCATEGORY: apt
TAGS: powershell, credential-theft
SOURCE_URL: <source_url from context, or N/A if not available>
UNIT: response
CREATED: <USE TODAY'S DATE: YYYY-MM-DD>
AUTHOR: sectest-builder
*/
package main
```

**CRITICAL**: `CREATED` field MUST contain the **actual current date** when the agent creates the test. Never hardcode dates from examples.

## Architecture: Standard Single-Binary

For tests with 1-2 techniques:

```
tests_source/intel-driven/<uuid>/
├── <uuid>.go                    # Main test implementation
├── test_logger.go               # Shared logger (copy from sample_tests/)
├── test_logger_<platform>.go    # Platform logger (copy from sample_tests/)
├── org_resolver.go              # Org resolver (copy from sample_tests/)
├── go.mod                       # Dependencies
└── README.md                    # Overview (created by documentation agent)
```

### Standard Main File Template

```go
import (
    _ "embed"
    "fmt"
    "os"
    "path/filepath"
    "time"

    "github.com/google/uuid"
    cert_installer "github.com/preludeorg/libraries/go/tests/cert_installer"
    Dropper "github.com/preludeorg/libraries/go/tests/dropper"
    Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed helper_binary.exe
var helperBinary []byte

func extractEmbeddedComponents() error {
    targetDir := "c:\\F0"
    if err := os.MkdirAll(targetDir, 0755); err != nil {
        return fmt.Errorf("failed to create target directory: %v", err)
    }
    // Extract each embedded component to LOG_DIR
    // Log with LogFileDropped()
    return nil
}

func test() {
    // Initialize Schema v2.0 logger
    InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

    defer func() {
        if r := recover(); r != nil {
            LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
            SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
        }
    }()

    // Phase 1: Initialization (Dropper)
    // Phase 2: File Drop Operations (extract, quarantine check)
    // Phase 3: Attack Execution (technique-specific logic)
    // Determine outcome based on results
}

func main() {
    Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))

    // Pre-flight certificate check
    if err := cert_installer.EnsureCertificateInstalled(); err != nil {
        Endpoint.Say("FATAL: Certificate installation failed: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    // Extract embedded components
    if err := extractEmbeddedComponents(); err != nil {
        Endpoint.Say("FATAL: Failed to extract components: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    done := make(chan bool, 1)
    go func() { test(); done <- true }()

    timeout := 2 * time.Minute
    select {
    case <-done:
        Endpoint.Say("Test completed successfully")
    case <-time.After(timeout):
        Endpoint.Say("Test timed out after %v", timeout)
        if globalLog != nil {
            LogMessage("ERROR", "Test Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
            SaveLog(Endpoint.TimeoutExceeded, fmt.Sprintf("Test exceeded timeout of %v", timeout))
        }
        Endpoint.Stop(Endpoint.TimeoutExceeded)
    }
}
```

## Architecture: Multi-Stage (3+ Techniques)

For tests with 3+ techniques that execute sequentially.

### File Structure

```
tests_source/intel-driven/<uuid>/
├── <uuid>.go                    # Main orchestrator
├── stage-T<technique1>.go       # Stage 1 source
├── stage-T<technique2>.go       # Stage 2 source
├── stage-T<technique3>.go       # Stage 3 source
├── test_logger.go               # Shared logger
├── test_logger_<platform>.go    # Platform logger
├── org_resolver.go              # Org resolver
├── go.mod                       # Dependencies
└── build_all.sh                 # Build script (created by build-config skill)
```

### Stage Binary Naming

Format: `stage-T<technique-id>.go` (e.g., `stage-T1134.001.go`, `stage-T1055.001.go`)

### Main Orchestrator Key Patterns

```go
// Embed SIGNED, GZIP-COMPRESSED stage binaries
//go:embed <uuid>-T1134.001.exe.gz
var stage1Compressed []byte

// Define killchain
killchain := []Stage{
    {
        ID: 1, Name: "Access Token Manipulation",
        Technique: "T1134.001",
        BinaryName: fmt.Sprintf("%s-T1134.001.exe", TEST_UUID),
        BinaryData: stage1Compressed,
        Description: "Manipulate access tokens for privilege escalation",
    },
    // More stages...
}

// Initialize stage results for ES fan-out
stageResults := make([]StageBundleDef, len(killchain))
for i, stage := range killchain {
    stageResults[i] = StageBundleDef{
        Technique: stage.Technique,
        Name:      stage.Name,
        Severity:  metadata.Severity,
        Tactics:   metadata.Tactics,
        ExitCode:  0,
        Status:    "skipped",
    }
}
```

### Stage Binary Template

```go
const (
    TEST_UUID      = "your-uuid"
    TECHNIQUE_ID   = "T1134.001"
    TECHNIQUE_NAME = "Access Token Manipulation"
    STAGE_ID       = 1
)

func main() {
    AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

    if err := performTechnique(); err != nil {
        LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
        os.Exit(StageBlocked)
    }

    LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Technique completed")
    os.Exit(StageSuccess)
}

func performTechnique() error {
    // Return nil if successful (vulnerable)
    // Return error if blocked (protected)
}
```

### Multi-Stage Exit Code Logic

- **Stage binaries** return: 0 (success/vulnerable), 126 (blocked), 105 (quarantined), 999 (error)
- **Main orchestrator** evaluates: Any stage 126/105 → PROTECTED (exit 126). All stages 0 → VULNERABLE (exit 101)
- **MANDATORY**: Call `WriteStageBundleResults()` before every `Endpoint.Stop()` call

### Multi-Stage Per-Stage ES Fan-Out

Multi-stage tests MUST call `WriteStageBundleResults()` to produce per-stage Elasticsearch documents:

```go
// Update results as each stage completes
stageResults[idx].ExitCode = exitCode
stageResults[idx].Status = "blocked" // or "success" or "error"
stageResults[idx].Details = "description of what happened"

// Call before EVERY exit point
WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", subcategory, stageResults)
```

## PowerShell Script Requirements

All embedded PowerShell scripts must include:

```powershell
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Host "[!] Failed to bypass execution policy: $_" -ForegroundColor Red
        return $false
    }
}
```

Execute from Go with: `exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)`

## Stdout/Stderr Capture Pattern (MANDATORY)

When executing embedded binaries, capture stdout/stderr to both console and file:

```go
cmd := exec.Command(binaryPath)
var outputBuffer bytes.Buffer
stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
cmd.Stdout = stdoutMulti
cmd.Stderr = stderrMulti

startTime := time.Now()
err := cmd.Run()
executionDuration := time.Since(startTime)

// Save raw output to LOG_DIR
outputFilePath := filepath.Join(targetDir, "<binary-name>_output.txt")
os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644)
```

## Dual Logging Pattern (MANDATORY for Multi-Stage)

All stage binaries must use both stdout + structured logging:

```go
// When stage encounters an error
if err := performTechnique(); err != nil {
    fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)  // Stdout
    LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))  // Structured log
    LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
    os.Exit(StageBlocked)
}
```

Apply to ALL error paths: prerequisite checks, technique failures, network errors, config errors, resource access failures.

## Cyber-Hygiene Bundle Output

**When to use**: Only for cyber-hygiene category tests evaluating multiple independent security controls.

- Control ID convention: `CH-{CATEGORY}-{NUMBER}` (e.g., `CH-DEF-001`, `CH-ASR-003`)
- Single-binary bundles: Use `CollectControlResults()` + `WriteBundleResults()` from `check_utils.go`
- Multi-binary bundles: Each validator compiles separately for quarantine resilience

## Direct Elasticsearch Export

ES export is a **build-time option** configured via `./build_all.sh --org <org> --es <profile>`. Do NOT ask about it during implementation.

## Test Exit Codes Reference

| Code | Constant | Meaning |
|------|----------|---------|
| 101 | `Endpoint.Unprotected` | Attack succeeded, system unprotected |
| 105 | `Endpoint.FileQuarantinedOnExtraction` | File quarantined before execution |
| 126 | `Endpoint.ExecutionPrevented` | Execution blocked by EDR |
| 127 | `Endpoint.FileQuarantinedOnExecution` | File caught during execution |
| 999 | `Endpoint.UnexpectedTestError` | Test error (prerequisites not met) |
| 102 | `Endpoint.TimeoutExceeded` | Timeout |

## Source-Built vs External Binaries

- **Source-built**: Have `.go` source in test directory → compiled by `build_all.sh`, never uploaded manually
- **External**: Third-party tools with no `.go` source → must be uploaded before building

## Implementation Checklist

Before proceeding to `sectest-build-config` skill:

- [ ] All `.go` files created in `tests_source/intel-driven/<uuid>/`
- [ ] `test_logger.go` and `test_logger_<platform>.go` copied from `sample_tests/`
- [ ] `org_resolver.go` copied from `sample_tests/`
- [ ] Metadata header with all v2.0 fields included
- [ ] Schema v2.0 `InitLogger()` call with metadata + executionContext
- [ ] Bug prevention rules 1-8 followed
- [ ] No unused imports
- [ ] For multi-stage: all `stage-T*.go` files created
- [ ] For multi-stage: `WriteStageBundleResults()` before every exit point
- [ ] For multi-stage: `decompressGzip()` helper included
- [ ] Dual logging in all stage binaries (stdout + structured)
