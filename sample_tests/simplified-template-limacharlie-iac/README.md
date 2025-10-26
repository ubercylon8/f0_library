# F0RT1KA Test Template - Simplified (LimaCharlie IaC)

This is a simplified test template for F0RT1KA tests deployed via LimaCharlie with Infrastructure as Code certificate management.

## Key Differences from Legacy Template

**This template DOES NOT include:**
- ❌ `cert_installer` module
- ❌ Certificate pre-flight check in `main()`
- ❌ Embedded F0RT1KA.cer certificate

**Why:**
- ✅ Certificate already installed via LimaCharlie D&R rule on sensor enrollment
- ✅ Simpler code, smaller binaries
- ✅ Centralized certificate management

## Prerequisites

Before using this template, ensure:
1. ✅ LimaCharlie IaC deployed to your organization(s)
2. ✅ Payload `f0rtika-cert-installer` uploaded
3. ✅ D&R rule `f0rtika-cert-auto-install` active
4. ✅ Sensors enrolled and certificate installed

**Verify:**
```bash
# Check rule deployed
limacharlie --org <org-name> dr list | grep f0rtika-cert-auto-install

# Check certificate on endpoint
certutil -store Root | findstr /i "F0RT1KA"
```

## Creating a New Test

### Step 1: Generate UUID

```bash
uuidgen | tr '[:upper:]' '[:lower:]'
# Example: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

### Step 2: Copy Template

```bash
# Replace <uuid> with your actual UUID
UUID="<your-uuid-here>"
cp -r sample_tests/simplified-template-limacharlie-iac tests_source/$UUID
cd tests_source/$UUID
```

### Step 3: Rename Files

```bash
mv template.go $UUID.go
```

### Step 4: Update Placeholders

Edit `$UUID.go` and replace:
- `<uuid>` → Your actual UUID
- `<TestName>` → Test name (e.g., "Registry Persistence")
- `<Description>` → Brief description
- `<MITRE_ID>` → MITRE ATT&CK ID (e.g., T1547.001)

Edit `go.mod` and replace:
- `<uuid>` → Your actual UUID

### Step 5: Implement Test Logic

Implement your test in the `test()` function:
1. **Phase 1: Setup** - Initialize test environment
2. **Phase 2: Main Test** - Execute attack simulation
3. **Phase 3: Cleanup** - Remove artifacts
4. **Evaluation** - Determine protection status

### Step 6: Add Logging (Optional but Recommended)

Copy `test_logger.go` from an existing test:
```bash
cp ../931f91ef-c7c0-4c3c-b61b-03992edb5e5f/test_logger.go .
```

### Step 7: Build and Sign

```bash
# Build test
cd ../..
./utils/gobuild build tests_source/$UUID/

# Sign with dual signing (recommended)
./utils/codesign sign build/$UUID/$UUID.exe sb

# Or sign with F0RT1KA only
./utils/codesign sign build/$UUID/$UUID.exe
```

### Step 8: Test

```bash
# Deploy via LimaCharlie to test endpoint
# Test should execute normally (exit 101 or 126, not 999)
```

## go.mod Structure

```go
module <uuid>
go 1.21

require (
	github.com/preludeorg/libraries/go/tests/dropper v0.0.0
	github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
)

replace github.com/preludeorg/libraries/go/tests/dropper => ../../preludeorg-libraries/go/tests/dropper
replace github.com/preludeorg/libraries/go/tests/endpoint => ../../preludeorg-libraries/go/tests/endpoint
```

**Note:** No `cert_installer` dependency needed!

## Exit Code Logic

Always implement proper exit code evaluation:

```go
func evaluateResults() {
    var finalExitCode int
    var finalReason string

    if attackBlocked {
        finalExitCode = Endpoint.ExecutionPrevented  // 126
        finalReason = "System protected - attack prevented"
    } else if attackSucceeded {
        finalExitCode = Endpoint.Unprotected  // 101
        finalReason = "System vulnerable - attack succeeded"
    } else {
        finalExitCode = Endpoint.UnexpectedTestError  // 999
        finalReason = "Inconclusive results"
    }

    SaveLog(finalExitCode, finalReason)
    Endpoint.Stop(finalExitCode)
}
```

**Never hardcode exit codes!**

## Documentation Files

Create these files for your test:

1. **README.md** - Overview, usage, building, testing
2. **`<uuid>_info.md`** - Detailed technical documentation
3. **`<uuid>_detections.kql`** (optional) - KQL detection queries

## Example Tests Using This Template

Future tests will use this simplified approach. Existing tests using embedded `cert_installer` will continue to work.

## Troubleshooting

### Error: Certificate not installed (exit 999)

**Cause:** LimaCharlie IaC not deployed or sensor enrolled before rule activation

**Solution:**
```bash
# Verify rule deployed
limacharlie --org <org> dr list | grep f0rtika-cert-auto-install

# Manually install certificate if needed
# Then re-run test
```

### Test fails with permission errors

**Cause:** Test not running with sufficient privileges

**Solution:**
- Ensure test deployed via LimaCharlie (runs as SYSTEM)
- If running manually, use administrator PowerShell

## Migration from Legacy Template

If you have existing tests with embedded `cert_installer`:

**Option 1: Keep as-is**
- Tests continue to work
- No changes needed
- Hybrid approach (IaC + embedded fallback)

**Option 2: Remove cert_installer**
1. Remove `cert_installer` import
2. Remove pre-flight check from `main()`
3. Remove `cert_installer` from `go.mod`
4. Rebuild and test

**Recommended:** Keep existing tests unchanged, use simplified template for NEW tests only.

## See Also

- `CLAUDE.md` - Complete development guidelines
- `limacharlie-iac/README.md` - LimaCharlie IaC deployment guide
- `DUAL_SIGNING_STRATEGY.md` - Dual signing documentation
- Existing tests with `test_logger.go` for logging examples
