#!/bin/bash
# Build script for Ransomware Encryption (Safe Mode) test
# UUID: b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08

set -e

TEST_UUID="b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08"
TEST_NAME="Ransomware Encryption (Safe Mode)"

# Parse command-line arguments
ORG_CERT=""
USAGE="Usage: $0 [--org <org-identifier>]

Build the Ransomware Encryption (Safe Mode) security test.

Options:
  --org <org-identifier>    Organization for dual signing (UUID or short name)
                            Examples: sb, 09b59276-9efb-4d3d-bbdd-4b4663ef0c42
                            Available short names: sb, tpsgl, rga
  -h, --help                Show this help message"

while [[ $# -gt 0 ]]; do
    case $1 in
        --org) ORG_CERT="$2"; shift 2 ;;
        -h|--help) echo "$USAGE"; exit 0 ;;
        *) echo "ERROR: Unknown option: $1"; echo "$USAGE"; exit 1 ;;
    esac
done

# Determine script location and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TEST_DIR="${SCRIPT_DIR}"
BUILD_DIR="${PROJECT_ROOT}/build/${TEST_UUID}"

echo "========================================"
echo "Building: ${TEST_NAME}"
echo "UUID: ${TEST_UUID}"
echo "========================================"
echo ""

# Source organization registry helper
RESOLVE_ORG_SCRIPT="${PROJECT_ROOT}/utils/resolve_org.sh"
if [ -f "${RESOLVE_ORG_SCRIPT}" ]; then
    source "${RESOLVE_ORG_SCRIPT}"
else
    echo "WARNING: Organization registry helper not found at ${RESOLVE_ORG_SCRIPT}"
    echo "Dual signing will not be available"
fi

# Resolve organization to certificate file (if provided)
CERT_FILE=""
ORG_CERT_FILE=""
if [ -n "$ORG_CERT" ]; then
    if type resolve_org_to_cert &>/dev/null; then
        CERT_FILE=$(resolve_org_to_cert "$ORG_CERT")
        if [ $? -ne 0 ] || [ -z "$CERT_FILE" ]; then
            echo "ERROR: Could not resolve organization '$ORG_CERT' to certificate"
            if type list_organizations &>/dev/null; then
                list_organizations
            fi
            exit 1
        fi
        ORG_CERT_FILE="${PROJECT_ROOT}/signing-certs/${CERT_FILE}"

        # Verify certificate file exists
        if [ ! -f "${ORG_CERT_FILE}" ]; then
            echo "ERROR: Certificate file not found: ${ORG_CERT_FILE}"
            exit 1
        fi
        echo "Organization: ${ORG_CERT}"
        echo "Certificate: ${CERT_FILE}"
    else
        echo "ERROR: resolve_org_to_cert function not available"
        exit 1
    fi
fi

echo ""

# Step 1: Get dependencies
echo "[Step 1/4] Getting dependencies..."
cd "${TEST_DIR}"
go mod tidy 2>/dev/null || true

# Step 2: Build the binary
echo "[Step 2/4] Building test binary..."
mkdir -p "${BUILD_DIR}"
GOOS=windows GOARCH=amd64 go build -o "${BUILD_DIR}/${TEST_UUID}.exe" \
    "${TEST_UUID}.go" \
    test_logger.go \
    org_resolver.go \
    es_config.go

if [ ! -f "${BUILD_DIR}/${TEST_UUID}.exe" ]; then
    echo "ERROR: Build failed - binary not created"
    exit 1
fi

BINARY_SIZE=$(stat -c%s "${BUILD_DIR}/${TEST_UUID}.exe" 2>/dev/null || stat -f%z "${BUILD_DIR}/${TEST_UUID}.exe")
echo "  Binary created: ${BUILD_DIR}/${TEST_UUID}.exe (${BINARY_SIZE} bytes)"

# Step 3: Sign the binary
echo "[Step 3/4] Signing binary..."
cd "${PROJECT_ROOT}"

F0RTIKA_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
if [ ! -f "${F0RTIKA_CERT}" ]; then
    echo "WARNING: F0RT1KA certificate not found at ${F0RTIKA_CERT}"
    echo "Binary will not be signed"
else
    if [ -n "${ORG_CERT_FILE}" ]; then
        # Dual signing with org cert + F0RT1KA
        echo "  Dual signing with: ${CERT_FILE} + F0RT1KA.pfx"
        ./utils/codesign sign-nested "${BUILD_DIR}/${TEST_UUID}.exe" "${ORG_CERT_FILE}" "${F0RTIKA_CERT}"
    else
        # F0RT1KA only signing
        echo "  Signing with: F0RT1KA.pfx"
        ./utils/codesign sign "${BUILD_DIR}/${TEST_UUID}.exe"
    fi
fi

# Step 4: Calculate SHA1 hash
echo "[Step 4/4] Calculating SHA1 hash..."
MAIN_HASH=$(shasum -a 1 "${BUILD_DIR}/${TEST_UUID}.exe" | awk '{print $1}')

# Show results
echo ""
echo "========================================"
echo "Build Complete"
echo "========================================"
echo "  Test UUID:    ${TEST_UUID}"
echo "  Test Name:    ${TEST_NAME}"
echo "  Binary:       ${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Size:         ${BINARY_SIZE} bytes"
echo "  SHA1:         ${MAIN_HASH}"
if [ -n "${ORG_CERT}" ]; then
    echo "  Organization: ${ORG_CERT}"
    echo "  Signing:      Dual (${CERT_FILE} + F0RT1KA)"
else
    echo "  Signing:      F0RT1KA only"
fi
echo ""
echo "Deployment Instructions:"
echo "  1. Copy ${TEST_UUID}.exe to target Windows system"
echo "  2. Execute with administrator privileges"
echo "  3. Results saved to c:\\F0\\test_execution_log.json"
echo ""
echo "Safety Notice:"
echo "  - This test does NOT encrypt any files"
echo "  - Files are only renamed with .f0rtika extension"
echo "  - All test files are automatically cleaned up"
echo "========================================"
