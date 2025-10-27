# Multi-Stage Test Pattern - Quick Reference

**F0RT1KA Security Testing Framework**

## When to Use

| Scenario | Use Multi-Stage? |
|----------|------------------|
| 1 technique | ❌ No - Use standard pattern |
| 2 techniques | ⚠️ Optional - Either pattern works |
| 3+ techniques | ✅ Yes - Use multi-stage pattern |
| Sequential killchain | ✅ Yes - Use multi-stage pattern |
| Need technique-level detection | ✅ Yes - Use multi-stage pattern |

## 5-Step Quick Start

### 1. Copy Template

```bash
cp -r sample_tests/multistage_template/ tests_source/<your-uuid>/
cd tests_source/<your-uuid>/
```

### 2. Rename & Configure

```bash
# Rename main file
mv TEMPLATE-UUID.go <your-uuid>.go

# Create stage files (one per technique)
cp stage-template.go stage-T1134.001.go
cp stage-template.go stage-T1055.001.go
cp stage-template.go stage-T1003.001.go
```

### 3. Update Constants

In `<your-uuid>.go`:
```go
const (
    TEST_UUID = "your-uuid-here"
    TEST_NAME = "Your Test Name"
)
```

In each `stage-T*.go`:
```go
const (
    TEST_UUID      = "your-uuid-here"  // Must match main
    TECHNIQUE_ID   = "T1134.001"        // Actual technique
    TECHNIQUE_NAME = "Token Manipulation"
    STAGE_ID       = 1                  // Stage number
)
```

### 4. Implement Techniques

In each `stage-T*.go`, edit `performTechnique()`:

```go
func performTechnique() error {
    // Your attack code here

    // If blocked, return error:
    if accessDenied {
        return fmt.Errorf("access denied")
    }

    // If successful, return nil:
    return nil
}
```

### 5. Build & Run

```bash
./build_all.sh
```

**Output:** `build/<uuid>/<uuid>.exe` (single binary)

## Exit Code Cheat Sheet

### Stage Binaries

```go
return nil              // = Exit 0 (Success - technique worked)
return error            // = Exit 126 (Blocked - technique prevented)
// File quarantined      // = Exit 105
// Prerequisites not met // = Exit 999
```

### Main Orchestrator

```
Stage exits 0    → Continue to next stage
Stage exits 126  → Stop, report PROTECTED, exit 126
Stage exits 105  → Stop, report PROTECTED, exit 126
Stage exits 999  → Stop, report ERROR, exit 999
All stages exit 0 → Report VULNERABLE, exit 101
```

## Build Process Flow

```
1. Build stage binaries      → unsigned .exe files
2. Sign stage binaries        → signed .exe files (CRITICAL)
3. Verify signatures          → confirm signatures valid
4. Build main orchestrator    → embeds signed stages
5. Sign main binary           → signed main .exe
6. Cleanup temp files         → remove stage .exe files
```

**Critical:** Stage binaries MUST be signed BEFORE embedding!

## File Naming Convention

```
Main orchestrator:  <uuid>.go
Stage binaries:     stage-T<technique>.go
Build output:       <uuid>-T<technique>.exe (temporary)
Final output:       build/<uuid>/<uuid>.exe (single file)
```

**Example:**
```
abc123.go                    # Main orchestrator
stage-T1134.001.go           # Stage 1 source
stage-T1055.001.go           # Stage 2 source
abc123-T1134.001.exe         # Stage 1 binary (temp, auto-deleted)
abc123-T1055.001.exe         # Stage 2 binary (temp, auto-deleted)
build/abc123/abc123.exe      # Final single binary
```

## Killchain Definition Template

```go
killchain := []Stage{
    {
        ID:          1,
        Name:        "Access Token Manipulation",
        Technique:   "T1134.001",
        BinaryName:  fmt.Sprintf("%s-T1134.001.exe", TEST_UUID),
        BinaryData:  stage1Binary,
        Description: "Manipulate access tokens for privilege escalation",
    },
    {
        ID:          2,
        Name:        "Process Injection",
        Technique:   "T1055.001",
        BinaryName:  fmt.Sprintf("%s-T1055.001.exe", TEST_UUID),
        BinaryData:  stage2Binary,
        Description: "Inject DLL into target process",
    },
    // Add more stages...
}
```

## Embed Directives Template

```go
//go:embed abc123-T1134.001.exe
var stage1Binary []byte

//go:embed abc123-T1055.001.exe
var stage2Binary []byte

//go:embed abc123-T1003.001.exe
var stage3Binary []byte
```

**Pattern:** `//go:embed <uuid>-T<technique>.exe`

## Logging Functions

### Main Orchestrator

```go
InitLogger(TEST_UUID, TEST_NAME)           // Initialize log
LogPhaseStart(0, "Stage Extraction")       // Log phase start
LogPhaseEnd(0, "success", "Details")       // Log phase end
LogFileDropped(name, path, size, quarantine) // Log file drop
LogProcessExecution(name, cmd, pid, ...)   // Log process
SaveLog(exitCode, reason)                  // Save final log
```

### Stage Binaries

```go
AttachLogger(TEST_UUID, "Stage: T1134.001") // Attach to shared log
LogMessage("INFO", TECHNIQUE_ID, msg)        // Log message
LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", details) // Log completion
LogStageBlocked(STAGE_ID, TECHNIQUE_ID, reason) // Log block
```

## Common Technique Patterns

### Process Injection

```go
func performTechnique() error {
    handle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, targetPID)
    if err != nil {
        return fmt.Errorf("process access denied: %v", err) // Blocked
    }
    defer windows.CloseHandle(handle)

    _, err = windows.WriteProcessMemory(handle, addr, payload, ...)
    if err != nil {
        return fmt.Errorf("memory write denied: %v", err) // Blocked
    }

    return nil // Success
}
```

### Token Manipulation

```go
func performTechnique() error {
    token, err := getProcessToken()
    if err != nil {
        return fmt.Errorf("token access denied: %v", err)
    }

    err = adjustTokenPrivileges(token, SE_DEBUG_NAME)
    if err != nil {
        return fmt.Errorf("privilege elevation denied: %v", err)
    }

    return nil
}
```

### LSASS Dump

```go
func performTechnique() error {
    lsassPID, err := findProcess("lsass.exe")
    if err != nil {
        return fmt.Errorf("LSASS process not found: %v", err) // Error
    }

    err = createDumpFile(lsassPID, "C:\\F0\\lsass.dmp")
    if err != nil {
        return fmt.Errorf("dump creation denied: %v", err) // Blocked
    }

    return nil
}
```

### Registry Modification

```go
func performTechnique() error {
    key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
    if err != nil {
        return fmt.Errorf("registry access denied: %v", err)
    }
    defer key.Close()

    err = key.SetStringValue(name, value)
    if err != nil {
        return fmt.Errorf("registry write denied: %v", err)
    }

    return nil
}
```

## Testing Checklist

- [ ] Build completes without errors
- [ ] All stage binaries signed
- [ ] Main binary signed
- [ ] Test on PROTECTED system (expect exit 126)
- [ ] Test on UNPROTECTED system (expect exit 101)
- [ ] Verify log files created
- [ ] Check log shows correct blocked stage
- [ ] Confirm only one .exe deployed (not multiple)

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Build fails "file not found" | Build stage binaries first, check //go:embed paths |
| All stages return 999 | Check prerequisites (admin rights, target process) |
| Signature verification fails | Re-sign with valid certificate |
| Stage always returns 0 | Check error handling in performTechnique() |
| Main binary too large (>10MB) | Normal for 5+ stages (each ~500KB signed) |
| Git tracking stage binaries | Add `*-T*.exe` to .gitignore |

## Decision Tree

```
Q: How many techniques in your test?
├─ 1 technique
│  └─ Use standard pattern (sample_tests/)
├─ 2 techniques
│  ├─ Simple simulation? → Standard pattern
│  └─ Need technique detection? → Multi-stage pattern
└─ 3+ techniques
   └─ Use multi-stage pattern (this guide)
```

## Architecture Comparison

| Feature | Standard Pattern | Multi-Stage Pattern |
|---------|------------------|---------------------|
| Techniques | 1-2 | 3+ |
| Detection Precision | Test-level | Technique-level |
| Binary Count | 1 .exe | 1 .exe (3-10 embedded) |
| Build Complexity | Simple | Complex (sign-embed-sign) |
| Deployment | Single file | Single file |
| Use Case | Simple tests | Complex killchains |

## Real-World Example

**Privilege Escalation Killchain:**

```
Stage 1: T1134.001 (Token Theft)
  → Success (Exit 0) → Continue

Stage 2: T1055.001 (Process Injection)
  → Blocked (Exit 126) → Stop here
  → Log: "EDR blocked T1055.001"
  → Result: PROTECTED

Stage 3: T1003.001 (Credential Dump)
  → Not executed (test stopped at Stage 2)
```

**Log Output:**
```json
{
  "blockedAtStage": 2,
  "blockedTechnique": "T1055.001",
  "stages": [
    {"stageId": 1, "technique": "T1134.001", "status": "success"},
    {"stageId": 2, "technique": "T1055.001", "status": "blocked"}
  ],
  "exitCode": 126
}
```

**Benefit:** Security team knows **exactly** which technique triggered EDR!

## Key Takeaways

✅ Use for 3+ techniques
✅ Sign stages BEFORE embedding
✅ Each stage = ONE technique
✅ Stage returns `nil` = success, `error` = blocked
✅ Main orchestrator stops at first blocked stage
✅ Final binary is SINGLE .exe file
✅ Provides technique-level detection precision

## Next Steps

1. **Read full documentation:** `/CLAUDE.md` (Multi-Stage Architecture section)
2. **Review template:** `sample_tests/multistage_template/`
3. **Study build process:** `utils/templates/build_multistage_template.sh`
4. **Create your test:** Follow 5-step quick start above

---

**Questions?** See `/CLAUDE.md` or `sample_tests/multistage_template/README.md`
