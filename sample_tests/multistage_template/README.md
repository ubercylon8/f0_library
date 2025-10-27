# Multi-Stage Test Template

**F0RT1KA Security Testing Framework**

This template provides a standardized structure for creating multi-stage attack chain tests where each ATT&CK technique is implemented as a separate signed binary.

## Overview

**Use this template when your test involves 3+ distinct ATT&CK techniques** that execute sequentially in a killchain order.

### Benefits

✅ **Technique-Level Detection Precision** - Know exactly which technique triggered EDR
✅ **Isolation of Detection Points** - Only the specific technique binary gets quarantined
✅ **Real-World Accuracy** - Models actual multi-stage attack chains
✅ **Forensic Value** - Logs show exact point where protection activated
✅ **Modular Testing** - Individual techniques can be run standalone

## Template Files

```
multistage_template/
├── TEMPLATE-UUID.go          # Main orchestrator (customize for your test)
├── stage-template.go          # Stage binary template (copy for each technique)
├── test_logger.go             # Enhanced logging (copy as-is)
├── go.mod                     # Module dependencies (update module name)
├── build_all.sh               # Build script (customize for your stages)
└── README.md                  # This file
```

## Quick Start

### 1. Copy Template

```bash
# Create new test directory
cp -r sample_tests/multistage_template/ tests_source/abc123-privilege-escalation/
cd tests_source/abc123-privilege-escalation/
```

### 2. Rename Main Orchestrator

```bash
mv TEMPLATE-UUID.go abc123.go
```

### 3. Create Stage Binaries

Copy `stage-template.go` once for each technique:

```bash
cp stage-template.go stage-T1134.001.go  # Token Manipulation
cp stage-template.go stage-T1055.001.go  # Process Injection
cp stage-template.go stage-T1003.001.go  # Credential Dump
```

### 4. Customize Files

#### Edit `abc123.go` (Main Orchestrator)

```go
const (
    TEST_UUID = "abc123"  // Your test UUID
    TEST_NAME = "Privilege Escalation Killchain"  // Your test name
)

// Update embedded binaries
//go:embed abc123-T1134.001.exe
var stage1Binary []byte

//go:embed abc123-T1055.001.exe
var stage2Binary []byte

//go:embed abc123-T1003.001.exe
var stage3Binary []byte

// Define your killchain
killchain := []Stage{
    {
        ID:          1,
        Name:        "Access Token Manipulation",
        Technique:   "T1134.001",
        BinaryName:  "abc123-T1134.001.exe",
        BinaryData:  stage1Binary,
        Description: "Manipulate access tokens for privilege escalation",
    },
    // ... add more stages
}
```

#### Edit Each Stage Binary

For example, `stage-T1134.001.go`:

```go
const (
    TEST_UUID      = "abc123"
    TECHNIQUE_ID   = "T1134.001"
    TECHNIQUE_NAME = "Access Token Manipulation"
    STAGE_ID       = 1
)

func performTechnique() error {
    // Implement your technique here
    // Return nil if successful, error if blocked

    // Example: Token manipulation
    token, err := getProcessToken()
    if err != nil {
        return fmt.Errorf("token access denied: %v", err)
    }

    err = adjustTokenPrivileges(token, SE_DEBUG_NAME)
    if err != nil {
        return fmt.Errorf("privilege elevation denied: %v", err)
    }

    return nil  // Success
}
```

#### Edit `build_all.sh`

```bash
TEST_UUID="abc123"

declare -a STAGES=(
    "T1134.001:stage-T1134.001"
    "T1055.001:stage-T1055.001"
    "T1003.001:stage-T1003.001"
)
```

#### Edit `go.mod`

```go
module abc123  // Your test UUID

go 1.21

require (
    github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
    golang.org/x/sys v0.15.0
)

replace github.com/preludeorg/libraries/go/tests/endpoint => ../../preludeorg-libraries/go/tests/endpoint
```

### 5. Implement Techniques

Edit each `stage-T*.go` file and implement the `performTechnique()` function:

- **Return `nil`** if technique succeeds (system vulnerable)
- **Return `error`** if technique is blocked (system protected)

### 6. Build and Sign

```bash
chmod +x build_all.sh
./build_all.sh
```

**Build Process:**
1. Builds unsigned stage binaries
2. **Signs stage binaries** (critical - before embedding)
3. Verifies signatures
4. Builds main orchestrator (embeds signed stages)
5. Signs main orchestrator
6. Cleans up temporary files

**Output:** `build/abc123/abc123.exe` (single deployable binary)

### 7. Test

```powershell
# Deploy to Windows target
scp build/abc123/abc123.exe target-host:C:\

# Execute test
C:\abc123.exe
```

## Exit Code Logic

### Stage Exit Codes (Stage Binaries)

```go
const (
    StageSuccess     = 0    // Technique executed successfully
    StageBlocked     = 126  // Technique blocked by EDR
    StageQuarantined = 105  // Binary quarantined
    StageError       = 999  // Prerequisites not met
)
```

**Stage Implementation:**

```go
func performTechnique() error {
    // Try to execute technique
    if err := attemptAttack(); err != nil {
        return err  // Blocked - returns 126
    }
    return nil  // Success - returns 0
}
```

### Main Orchestrator Logic

```go
for _, stage := range killchain {
    exitCode := executeStage(stage)

    if exitCode == 126 || exitCode == 105 {
        // EDR blocked this stage - system protected
        Endpoint.Stop(Endpoint.ExecutionPrevented)  // Exit 126
    } else if exitCode != 0 {
        // Stage error
        Endpoint.Stop(Endpoint.UnexpectedTestError)  // Exit 999
    }
    // Continue to next stage
}

// All stages succeeded - system vulnerable
Endpoint.Stop(Endpoint.Unprotected)  // Exit 101
```

## Execution Flow

```
Main Orchestrator (abc123.exe) starts:

Phase 0: Extract Stage Binaries
  → Extracts abc123-T1134.001.exe (signed) to C:\F0\
  → Extracts abc123-T1055.001.exe (signed) to C:\F0\
  → Extracts abc123-T1003.001.exe (signed) to C:\F0\

Stage 1: Execute T1134.001 (Token Manipulation)
  → Windows validates signature ✓
  → Executes technique
  → EDR allows → Exit 0 (continue)

Stage 2: Execute T1055.001 (Process Injection)
  → Windows validates signature ✓
  → Executes technique
  → EDR BLOCKS → Exit 126 (stop here)

Main Orchestrator:
  → Stage 2 returned 126 (blocked)
  → Logs: "EDR blocked at stage 2: T1055.001"
  → Final result: PROTECTED
  → Exit 126
```

## Log Output

### JSON Log (`C:\F0\test_execution_log.json`)

```json
{
  "testId": "abc123",
  "testName": "Privilege Escalation Killchain",
  "isMultiStage": true,
  "stages": [
    {
      "stageId": 1,
      "technique": "T1134.001",
      "name": "Access Token Manipulation",
      "status": "success",
      "durationMs": 1200,
      "exitCode": 0
    },
    {
      "stageId": 2,
      "technique": "T1055.001",
      "name": "Process Injection",
      "status": "blocked",
      "durationMs": 800,
      "exitCode": 126,
      "blockedBy": "WriteProcessMemory denied"
    }
  ],
  "blockedAtStage": 2,
  "blockedTechnique": "T1055.001",
  "result": "PROTECTED",
  "exitCode": 126
}
```

### Console Output

```
=================================================================
Stage 2/3: Process Injection
Technique: T1055.001
Description: Inject malicious DLL into target process
=================================================================

    ✓ Stage 2 completed successfully

=================================================================
FINAL EVALUATION: Stage 2 Blocked
=================================================================

✅ RESULT: PROTECTED

EDR successfully blocked the attack at stage 2:
  • Technique: T1055.001
  • Stage: Process Injection
  • Exit Code: 126

Attack Chain Interrupted:
  • Completed Stages: 1/3
  • Blocked Stage: 2 (T1055.001)
  • Remaining Stages: 1 (not executed)

Security Status: ENDPOINT IS SECURE
=================================================================
```

## File Structure After Build

```
tests_source/abc123-privilege-escalation/
├── abc123.go                  # Main orchestrator
├── stage-T1134.001.go         # Stage 1 source
├── stage-T1055.001.go         # Stage 2 source
├── stage-T1003.001.go         # Stage 3 source
├── test_logger.go             # Logging module
├── go.mod                     # Module file
├── build_all.sh               # Build script
└── README.md                  # Documentation

build/abc123/
└── abc123.exe                 # Single deployable binary (2-5MB)

Temporary files (auto-cleaned):
  abc123-T1134.001.exe        # Deleted after embedding
  abc123-T1055.001.exe        # Deleted after embedding
  abc123-T1003.001.exe        # Deleted after embedding
```

## Common Patterns

### Pattern 1: Sequential Privilege Escalation

```go
killchain := []Stage{
    {1, "Token Theft", "T1134.001", ...},
    {2, "Process Injection", "T1055.001", ...},
    {3, "Credential Dump", "T1003.001", ...},
}
```

### Pattern 2: Lateral Movement Chain

```go
killchain := []Stage{
    {1, "Remote Service", "T1021.002", ...},
    {2, "Admin Share", "T1077", ...},
    {3, "Remote Execution", "T1569.002", ...},
}
```

### Pattern 3: Data Exfiltration Chain

```go
killchain := []Stage{
    {1, "Data Staging", "T1074.001", ...},
    {2, "Data Compression", "T1560.001", ...},
    {3, "Exfiltration", "T1041", ...},
}
```

## Troubleshooting

### Build Fails: "file not found"

**Problem:** Stage binary not found during embedding
**Solution:** Ensure stage binaries are built BEFORE main orchestrator

```bash
# Check if stage binaries exist
ls -la *-T*.exe

# If missing, build them first
GOOS=windows GOARCH=amd64 go build -o abc123-T1134.001.exe stage-T1134.001.go test_logger.go
```

### Signature Verification Fails

**Problem:** osslsigncode verify fails
**Solution:** Check signing certificate is valid

```bash
# Verify certificate exists
ls -la ../../signing-certs/F0RT1KA.pfx

# Re-sign if needed
../../utils/codesign sign abc123-T1134.001.exe
```

### Stage Always Returns 999

**Problem:** Prerequisites not met (target process not running, insufficient privileges)
**Solution:** Add prerequisite checks in stage binary

```go
func performTechnique() error {
    // Check prerequisites first
    if !isAdmin() {
        return fmt.Errorf("administrator privileges required")
    }

    if !targetProcessRunning() {
        return fmt.Errorf("target process not found")
    }

    // Proceed with technique
    ...
}
```

## Best Practices

✅ **DO** sign stage binaries BEFORE embedding
✅ **DO** use standardized exit codes (0, 126, 105, 999)
✅ **DO** implement comprehensive logging in each stage
✅ **DO** test on both protected and unprotected systems
✅ **DO** clean up temporary stage binaries after build

❌ **DON'T** hardcode exit codes (evaluate actual results)
❌ **DON'T** forget to update //go:embed directives
❌ **DON'T** commit temporary stage binaries to git
❌ **DON'T** use multi-stage pattern for simple 1-2 technique tests

## Reference Documentation

- Main documentation: `/CLAUDE.md` (Multi-Stage Test Architecture section)
- Build script template: `/utils/templates/build_multistage_template.sh`
- Standard pattern: `/sample_tests/` (for single-binary tests)

## Support

For questions or issues:
1. Review `/CLAUDE.md` Multi-Stage Architecture section
2. Check existing multi-stage tests in `/tests_source/`
3. Consult build script documentation in `/utils/README.md`
