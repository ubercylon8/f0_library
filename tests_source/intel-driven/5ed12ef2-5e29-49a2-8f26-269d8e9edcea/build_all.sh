#!/bin/bash
# build_all.sh - Build script for multi-stage ransomware test
# Builds and signs all stage binaries, then builds main orchestrator

set -e

TEST_UUID="5ed12ef2-5e29-49a2-8f26-269d8e9edcea"
TEST_DIR="tests_source/${TEST_UUID}"
BUILD_DIR="build/${TEST_UUID}"

echo "=========================================="
echo "Building Multi-Stage Ransomware Test"
echo "Test ID: ${TEST_UUID}"
echo "=========================================="
echo ""

# Get the absolute path to the f0_library root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
F0_ROOT="$( cd "${SCRIPT_DIR}/../.." && pwd )"

# Ensure we're working with absolute paths
TEST_DIR="${F0_ROOT}/tests_source/${TEST_UUID}"
BUILD_DIR="${F0_ROOT}/build/${TEST_UUID}"

# Create build directory if it doesn't exist
mkdir -p "${BUILD_DIR}"

cd "${TEST_DIR}"

# Step 1: Build stage binaries (unsigned)
echo "[1/6] Building stage binaries..."
echo ""

echo "  Building Stage 1: T1204.002 (Initial Execution)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" \
    -o ${TEST_UUID}-T1204.002.exe \
    stage-T1204.002.go test_logger.go test_logger_windows.go

echo "  Building Stage 2: T1134.001 (Privilege Escalation)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" \
    -o ${TEST_UUID}-T1134.001.exe \
    stage-T1134.001.go test_logger.go test_logger_windows.go

echo "  Building Stage 3: T1083 (Discovery)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" \
    -o ${TEST_UUID}-T1083.exe \
    stage-T1083.go test_logger.go test_logger_windows.go

echo "  Building Stage 4: T1486 (Encryption)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" \
    -o ${TEST_UUID}-T1486.exe \
    stage-T1486.go test_logger.go test_logger_windows.go

echo "  Building Stage 5: T1491.001 (Ransom Note)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" \
    -o ${TEST_UUID}-T1491.001.exe \
    stage-T1491.001.go test_logger.go test_logger_windows.go

echo ""
echo "[2/6] Signing stage binaries with F0RT1KA certificate..."
echo ""

# Signing is FAIL-LOUD: this build always signs — any failure aborts the build
# rather than embedding unsigned stage binaries.
if [ ! -x "${F0_ROOT}/utils/codesign" ]; then
    echo "[ERROR] codesign utility not found: ${F0_ROOT}/utils/codesign"
    exit 1
fi
if [ ! -f "${F0_ROOT}/signing-certs/F0RT1KA.pfx" ]; then
    echo "[ERROR] F0RT1KA certificate not found: ${F0_ROOT}/signing-certs/F0RT1KA.pfx"
    exit 1
fi
if [ ! -f "${F0_ROOT}/signing-certs/.F0RT1KA.pfx.txt" ]; then
    echo "[ERROR] cert password file missing: ${F0_ROOT}/signing-certs/.F0RT1KA.pfx.txt"
    exit 1
fi

# Read F0RT1KA certificate password
F0RT1KA_PASSWORD=$(cat "${F0_ROOT}/signing-certs/.F0RT1KA.pfx.txt" | tr -d '\n\r')

# Sign each stage binary (CRITICAL - before embedding)
for stage in T1204.002 T1134.001 T1083 T1486 T1491.001; do
    echo "  Signing ${TEST_UUID}-${stage}.exe..."
    if ! "${F0_ROOT}/utils/codesign" --cert "${F0_ROOT}/signing-certs/F0RT1KA.pfx" --password "${F0RT1KA_PASSWORD}" sign ${TEST_UUID}-${stage}.exe; then
        echo "[ERROR] codesign failed to sign ${TEST_UUID}-${stage}.exe — refusing to continue with unsigned binaries"
        exit 1
    fi
done

echo ""
echo "[3/6] Verifying stage signatures..."
echo ""

# Verify signatures (note: self-signed certs will show verification warnings but are still valid)
# FAIL-LOUD: a stage without a valid signature after signing means the build
# ships unsigned embedded binaries.
if command -v osslsigncode >/dev/null 2>&1; then
    for stage in T1204.002 T1134.001 T1083 T1486 T1491.001; do
        echo "  Verifying ${TEST_UUID}-${stage}.exe..."
        if osslsigncode verify ${TEST_UUID}-${stage}.exe 2>&1 | grep -q "Message digest"; then
            echo "    ✓ Signature present and valid (self-signed cert)"
        else
            echo "    ✗ ERROR: stage binary ${TEST_UUID}-${stage}.exe has NO valid signature — aborting (unsigned embedded binaries are forbidden)"
            exit 1
        fi
    done
else
    echo "[ERROR] osslsigncode not found — cannot verify signatures (required for this signed build)"
    exit 1
fi

echo ""
echo "[4/6] Building main orchestrator (embedding signed stages)..."
echo ""

# Build main orchestrator with embedded signed stage binaries
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" \
    -o ${BUILD_DIR}/${TEST_UUID}.exe \
    ${TEST_UUID}.go stage_launch.go test_logger.go test_logger_windows.go

cd "${F0_ROOT}"

echo "[5/6] Signing main orchestrator binary..."
echo ""

# Sign the main binary
if ! ./utils/codesign --cert "${F0_ROOT}/signing-certs/F0RT1KA.pfx" --password "${F0RT1KA_PASSWORD}" sign build/${TEST_UUID}/${TEST_UUID}.exe; then
    echo "[ERROR] codesign failed to sign the orchestrator — refusing to ship an unsigned binary"
    exit 1
fi

echo "[6/6] Cleaning up temporary stage binaries..."
echo ""

# Clean up temporary stage binaries from source directory
rm -f ${TEST_DIR}/${TEST_UUID}-T*.exe

# Calculate final binary size
if [ -f "${BUILD_DIR}/${TEST_UUID}.exe" ]; then
    SIZE=$(ls -lh ${BUILD_DIR}/${TEST_UUID}.exe | awk '{print $5}')
    echo "=========================================="
    echo "✅ BUILD SUCCESSFUL"
    echo "=========================================="
    echo ""
    echo "Binary: ${BUILD_DIR}/${TEST_UUID}.exe"
    echo "Size:   ${SIZE}"
    echo ""
    echo "This multi-stage test includes:"
    echo "  • 5 signed stage binaries (embedded)"
    echo "  • Recovery script"
    echo "  • Comprehensive logging"
    echo ""
    echo "Deploy with: scp ${BUILD_DIR}/${TEST_UUID}.exe target:C:\\"
    echo "=========================================="
else
    echo "[ERROR] Build failed - binary not found"
    exit 1
fi