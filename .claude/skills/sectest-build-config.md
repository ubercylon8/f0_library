---
name: sectest-build-config
description: Configure build system for F0RT1KA tests including go.mod, build_all.sh, platform build commands, code signing, gzip compression, and binary verification. Actually runs the build and verifies output.
---

# Build Configuration & Compilation

This skill handles Phase 1 (final step) of security test creation: configuring the build system, compiling, and verifying the binary. It assumes `sectest-implementation` has completed and all `.go` files exist.

## Step 1: Create go.mod

### Standard Tests (Windows)

```go
module <uuid>
go 1.21

require (
    github.com/google/uuid v1.6.0
    github.com/preludeorg/libraries/go/tests/cert_installer v0.0.0
    github.com/preludeorg/libraries/go/tests/dropper v0.0.0
    github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
    golang.org/x/sys v0.19.0
)

replace github.com/preludeorg/libraries/go/tests/cert_installer => ../../preludeorg-libraries/go/tests/cert_installer
replace github.com/preludeorg/libraries/go/tests/dropper => ../../preludeorg-libraries/go/tests/dropper
replace github.com/preludeorg/libraries/go/tests/endpoint => ../../preludeorg-libraries/go/tests/endpoint
```

### Standard Tests (Linux/macOS)

Same as above but **without** `golang.org/x/sys` (not needed for Linux/macOS tests).

### After creating go.mod

```bash
cd tests_source/intel-driven/<uuid>/ && go mod tidy
```

## Step 2: Build Command (Standard Tests)

### Per-Platform Build

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o <uuid>.exe <uuid>.go test_logger.go test_logger_windows.go org_resolver.go

# Linux
GOOS=linux GOARCH=amd64 go build -o <uuid> <uuid>.go test_logger.go test_logger_linux.go org_resolver.go

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o <uuid> <uuid>.go test_logger.go test_logger_darwin.go org_resolver.go
```

Or use the build utility:
```bash
./utils/gobuild build tests_source/intel-driven/<uuid>/
```

## Step 3: Code Signing (Standard Tests)

| Platform | Method | Command |
|----------|--------|---------|
| Windows | Authenticode (PFX) | `./utils/codesign sign build/<uuid>/<uuid>.exe` |
| Linux | Skipped | — |
| macOS | Ad-hoc | `codesign -s - build/<uuid>/<uuid>` |

## Step 4: Multi-Stage build_all.sh (MANDATORY for 3+ techniques)

All multi-stage tests MUST use the modern build_all.sh pattern with:
- Organization registry integration via `utils/resolve_org.sh`
- Dual signing (org cert + F0RT1KA) via `sign-nested`
- Signature verification via `osslsigncode verify`
- **Gzip compression** of stage binaries before embedding
- SHA1 hash reporting
- Automatic cleanup
- No interactive prompts

### Modern build_all.sh Template (8 steps)

```bash
#!/bin/bash
set -e

TEST_UUID="<uuid>"
TEST_DIR="tests_source/intel-driven/${TEST_UUID}"
BUILD_DIR="build/${TEST_UUID}"

# Parse command-line arguments
ORG_CERT=""
USAGE="Usage: $0 [--org <org-identifier>]

Options:
  --org <org-identifier>    Organization for dual signing (UUID or short name)
                            Examples: sb, 09b59276-9efb-4d3d-bbdd-4b4663ef0c42
                            Available short names: sb, tpsgl, rga"

while [[ $# -gt 0 ]]; do
    case $1 in
        --org) ORG_CERT="$2"; shift 2 ;;
        -h|--help) echo "$USAGE"; exit 0 ;;
        *) echo "ERROR: Unknown option: $1"; echo "$USAGE"; exit 1 ;;
    esac
done

# Determine script location and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Source organization registry helper
RESOLVE_ORG_SCRIPT="${PROJECT_ROOT}/utils/resolve_org.sh"
if [ -f "${RESOLVE_ORG_SCRIPT}" ]; then
    source "${RESOLVE_ORG_SCRIPT}"
else
    echo "ERROR: Organization registry helper not found"
    exit 1
fi

# Resolve organization to certificate file
CERT_FILE=$(resolve_org_to_cert "$ORG_CERT")
if [ $? -ne 0 ] || [ -z "$CERT_FILE" ]; then
    echo "ERROR: Could not resolve organization '$ORG_CERT' to certificate"
    list_organizations
    exit 1
fi

# Set certificate paths
ORG_CERT_FILE="${PROJECT_ROOT}/signing-certs/${CERT_FILE}"
ORG_CERT_FILE_RELATIVE="../../signing-certs/${CERT_FILE}"

# Verify certificate file exists
if [ ! -f "${ORG_CERT_FILE}" ]; then
    echo "ERROR: Certificate file not found: ${ORG_CERT_FILE}"
    exit 1
fi

# Stage definitions — UPDATE for each test
declare -a STAGES=(
    "T1134.001:${TEST_UUID}-T1134.001"
    "T1055.001:${TEST_UUID}-T1055.001"
    "T1003.001:${TEST_UUID}-T1003.001"
)

cd "${TEST_DIR}"

# Step 1: Build stage binaries (unsigned)
echo "[Step 1/8] Building ${#STAGES[@]} stage binaries..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    # Platform-specific extension
    output_name="${TEST_UUID}-${technique}.exe"  # Windows
    GOOS=windows GOARCH=amd64 go build -o "${output_name}" "stage-${technique}.go" test_logger.go test_logger_windows.go org_resolver.go
    echo "  Built: ${output_name} ($(stat -f%z "${output_name}" 2>/dev/null || stat -c%s "${output_name}") bytes)"
done

# Step 2: Dual-sign stage binaries (CRITICAL — before embedding!)
echo "[Step 2/8] Dual-signing stage binaries..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${TEST_UUID}-${technique}.exe"
    ../../utils/codesign sign-nested "${binary}" "${ORG_CERT_FILE_RELATIVE}" ../../signing-certs/F0RT1KA.pfx
done

# Step 3: Verify signatures
echo "[Step 3/8] Verifying stage signatures..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${TEST_UUID}-${technique}.exe"
    osslsigncode verify "${binary}" 2>&1 | grep -q "Message digest" && echo "  Verified: ${binary}" || echo "  WARNING: Signature verification failed for ${binary}"
done

# Step 4: Gzip compress stage binaries (MANDATORY — reduces orchestrator by ~35%)
echo "[Step 4/8] Compressing stage binaries with gzip..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${TEST_UUID}-${technique}.exe"
    gzip -9 -k "${binary}"
    orig_size=$(stat -f%z "${binary}" 2>/dev/null || stat -c%s "${binary}")
    gz_size=$(stat -f%z "${binary}.gz" 2>/dev/null || stat -c%s "${binary}.gz")
    echo "  Compressed: ${binary} (${orig_size} -> ${gz_size} bytes)"
done

# Step 5: Build main orchestrator (embeds SIGNED + COMPRESSED stages)
echo "[Step 5/8] Building main orchestrator..."
cd ../..
mkdir -p "${BUILD_DIR}"
cd "${TEST_DIR}"
GOOS=windows GOARCH=amd64 go build -o "../../${BUILD_DIR}/${TEST_UUID}.exe" "${TEST_UUID}.go" test_logger.go test_logger_windows.go org_resolver.go

# Step 6: Dual-sign main binary
echo "[Step 6/8] Dual-signing main binary..."
cd ../..
./utils/codesign sign-nested "${BUILD_DIR}/${TEST_UUID}.exe" "${ORG_CERT_FILE}" signing-certs/F0RT1KA.pfx

# Step 7: Calculate SHA1 hashes
echo "[Step 7/8] Calculating SHA1 hashes..."
cd "${TEST_DIR}"
declare -A STAGE_HASHES
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${TEST_UUID}-${technique}.exe"
    hash=$(shasum -a 1 "${binary}" | awk '{print $1}')
    STAGE_HASHES["${binary}"]="${hash}"
done
cd ../..
MAIN_HASH=$(shasum -a 1 "${BUILD_DIR}/${TEST_UUID}.exe" | awk '{print $1}')

# Step 8: Cleanup temporary files
echo "[Step 8/8] Cleaning up..."
cd "${TEST_DIR}"
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    rm -f "${TEST_UUID}-${technique}.exe" "${TEST_UUID}-${technique}.exe.gz"
done
cd ../..

# Show results
echo ""
echo "Build Complete"
echo "  Main Binary: ${BUILD_DIR}/${TEST_UUID}.exe"
echo ""
echo "SHA1 Hashes:"
echo "  Main: ${MAIN_HASH}"
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    echo "  ${TEST_UUID}-${technique}.exe: ${STAGE_HASHES[${TEST_UUID}-${technique}.exe]}"
done
```

### Customizing build_all.sh

For each test, update:
1. `TEST_UUID` — the test UUID
2. `STAGES` array — technique IDs and source file mappings
3. Platform-specific build flags (`GOOS`, `GOARCH`, extensions)
4. Step 1 build command — include correct `.go` files for each stage

## Step 5: Run the Build

### Standard tests
```bash
./utils/gobuild build tests_source/intel-driven/<uuid>/
./utils/codesign sign build/<uuid>/<uuid>.exe
```

### Multi-stage tests
```bash
chmod +x tests_source/intel-driven/<uuid>/build_all.sh
./tests_source/intel-driven/<uuid>/build_all.sh --org sb
```

## Step 6: Verify the Binary

After build completes:

1. **Check binary exists and has reasonable size**:
   ```bash
   ls -la build/<uuid>/<uuid>.exe
   ```

2. **For multi-stage**: Verify all stage binaries were embedded (orchestrator size should be > sum of stage sizes)

3. **Fix any build errors**: Common issues:
   - Missing imports → add to import block
   - Duplicate functions → check for conflicts with test_logger.go
   - Missing go.sum → run `go mod tidy`
   - Build tag mismatch → ensure `GOOS` matches build tag

## Proceed

After successful build, proceed to Phase 2 (parallel agents) in the orchestrator.
