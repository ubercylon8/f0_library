#!/bin/bash
set -e

TEST_UUID="640e6458-5b6b-4153-87b4-8327599829a8"
TEST_DIR="tests_source/${TEST_UUID}"
BUILD_DIR="build/${TEST_UUID}"

# Parse command-line arguments
ORG_CERT=""
USAGE="Usage: $0 [--org <org-identifier>]

Options:
  --org <org-identifier>    Organization for dual signing (UUID or short name)
                            Examples: sb, 09b59276-9efb-4d3d-bbdd-4b4663ef0c42
                            Available short names: sb, tpsgl, rga

Examples:
  $0                           # Use default organization from registry
  $0 --org sb                  # Use sb short name
  $0 --org 09b59276-9efb...    # Use UUID
"

while [[ $# -gt 0 ]]; do
    case $1 in
        --org)
            ORG_CERT="$2"
            shift 2
            ;;
        -h|--help)
            echo "$USAGE"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1"
            echo "$USAGE"
            exit 1
            ;;
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
    echo "ERROR: Organization registry helper not found: ${RESOLVE_ORG_SCRIPT}"
    exit 1
fi

# Resolve organization to certificate file using registry
CERT_FILE=$(resolve_org_to_cert "$ORG_CERT")
if [ $? -ne 0 ] || [ -z "$CERT_FILE" ]; then
    echo "ERROR: Could not resolve organization '$ORG_CERT' to certificate"
    list_organizations
    exit 1
fi

# Set certificate paths
ORG_CERT_FILE="${PROJECT_ROOT}/signing-certs/${CERT_FILE}"
ORG_CERT_FILE_RELATIVE="../../signing-certs/${CERT_FILE}"  # For use from test directory

# Verify certificate file exists
if [ ! -f "${ORG_CERT_FILE}" ]; then
    echo "ERROR: Certificate file not found: ${ORG_CERT_FILE}"
    exit 1
fi

echo "================================================================="
echo "Building Multi-Stage Test: EDR Network Isolation via WFP"
echo "Test ID: ${TEST_UUID}"
echo "Organization: ${ORG_CERT:-default}"
echo "Certificate: ${CERT_FILE}"
echo "================================================================="
echo ""

# Stage definitions: "TECHNIQUE:SOURCE_FILE"
declare -a STAGES=(
    "T1016:${TEST_UUID}-T1016"
    "T1562.004:${TEST_UUID}-T1562.004"
    "T1489:${TEST_UUID}-T1489"
)

# Change to test directory
cd "${TEST_DIR}"

# Step 1: Build stage binaries (unsigned)
echo "[Step 1/7] Building ${#STAGES[@]} stage binaries..."
echo ""

for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    output_name="${technique}.exe"

    echo "  Building ${technique} (${source}.go)..."
    GOOS=windows GOARCH=amd64 go build -o "${output_name}" "${source}.go" test_logger.go org_resolver.go

    if [ ! -f "${output_name}" ]; then
        echo "ERROR: Failed to build ${output_name}"
        exit 1
    fi

    file_size=$(ls -lh "${output_name}" | awk '{print $5}')
    echo "    ✓ ${output_name} created (${file_size})"
done

echo ""

# Step 2: Build cleanup utility
echo "[Step 2/7] Building cleanup utility..."
GOOS=windows GOARCH=amd64 go build -o cleanup_utility.exe cleanup_utility.go
cleanup_size=$(ls -lh cleanup_utility.exe | awk '{print $5}')
echo "    ✓ cleanup_utility.exe created (${cleanup_size})"
echo ""

# Step 3: Dual-sign stage binaries (CRITICAL - before embedding!)
echo "[Step 3/7] Dual-signing stage binaries and cleanup utility (${ORG_CERT:-default} + F0RT1KA)..."
echo ""

for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${technique}.exe"

    echo "  Dual-signing ${binary}..."
    ../../utils/codesign sign-nested "${binary}" "${ORG_CERT_FILE_RELATIVE}" ../../signing-certs/F0RT1KA.pfx

    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to sign ${binary}"
        exit 1
    fi
done

echo "  Dual-signing cleanup_utility.exe..."
../../utils/codesign sign-nested cleanup_utility.exe "${ORG_CERT_FILE_RELATIVE}" ../../signing-certs/F0RT1KA.pfx

echo ""

# Step 4: Verify signatures
echo "[Step 4/7] Verifying stage signatures..."
echo ""

for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${technique}.exe"

    echo "  Verifying ${binary}..."
    # Check that signature exists (don't fail on self-signed cert warnings)
    osslsigncode verify "${binary}" 2>&1 | grep -q "Message digest"

    if [ $? -ne 0 ]; then
        echo "ERROR: Signature verification failed for ${binary}"
        exit 1
    fi

    echo "    ✓ ${binary} signature valid"
done

echo "  Verifying cleanup_utility.exe..."
osslsigncode verify cleanup_utility.exe 2>&1 | grep -q "Message digest"
echo "    ✓ cleanup_utility.exe signature valid"

echo ""

# Step 5: Build main orchestrator (embeds SIGNED stage binaries)
echo "[Step 5/7] Building main orchestrator (embedding signed stages)..."
echo ""

cd ../..

mkdir -p "${BUILD_DIR}"

echo "  Building ${TEST_UUID}.exe..."
cd "${TEST_DIR}"
GOOS=windows GOARCH=amd64 go build -o "../../${BUILD_DIR}/${TEST_UUID}.exe" "${TEST_UUID}.go" test_logger.go org_resolver.go

if [ ! -f "../../${BUILD_DIR}/${TEST_UUID}.exe" ]; then
    echo "ERROR: Failed to build main binary"
    exit 1
fi

main_size=$(ls -lh "../../${BUILD_DIR}/${TEST_UUID}.exe" | awk '{print $5}')
echo "    ✓ Main binary created (${main_size})"
echo ""

cd ../..

# Step 6: Dual-sign main binary
echo "[Step 6/7] Dual-signing main binary (${ORG_CERT:-default} + F0RT1KA)..."
echo ""

./utils/codesign sign-nested "${BUILD_DIR}/${TEST_UUID}.exe" "${ORG_CERT_FILE}" signing-certs/F0RT1KA.pfx

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to sign main binary"
    exit 1
fi

echo "    ✓ Main binary dual-signed"
echo ""

# Step 7: Calculate SHA1 hashes and cleanup
echo "[Step 7/7] Calculating SHA1 hashes and cleaning up..."
echo ""

cd "${TEST_DIR}"

declare -A STAGE_HASHES
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${technique}.exe"
    if [ -f "${binary}" ]; then
        hash=$(shasum -a 1 "${binary}" | awk '{print $1}')
        STAGE_HASHES["${binary}"]="${hash}"
    fi
done

# Calculate cleanup utility hash
if [ -f "cleanup_utility.exe" ]; then
    CLEANUP_HASH=$(shasum -a 1 cleanup_utility.exe | awk '{print $1}')
fi

# Calculate main binary hash
cd ../..
MAIN_HASH=$(shasum -a 1 "${BUILD_DIR}/${TEST_UUID}.exe" | awk '{print $1}')

# Cleanup temporary files
echo "  Cleaning up temporary stage binaries from source directory..."
cd "${TEST_DIR}"

for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    rm -f "${technique}.exe"
done

rm -f cleanup_utility.exe

cd ../..

# Show results
echo ""
echo "================================================================="
echo "Build Complete!"
echo "================================================================="
echo ""
echo "Test Binary:"
ls -lh "${BUILD_DIR}/${TEST_UUID}.exe"
echo ""
echo "Signing:"
echo "  ✓ All binaries dual-signed (${ORG_CERT:-default} org cert + F0RT1KA)"
echo "  ✓ Stage binaries: 3 stages + cleanup utility"
echo "  ✓ Main orchestrator: Full test binary"
echo ""
echo "SHA1 Hashes:"
echo "  Main Binary:"
echo "    ${TEST_UUID}.exe: ${MAIN_HASH}"
echo ""
echo "  Embedded Binaries:"
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${technique}.exe"
    if [ -n "${STAGE_HASHES[$binary]}" ]; then
        echo "    ${binary}: ${STAGE_HASHES[$binary]}"
    fi
done
if [ -n "${CLEANUP_HASH}" ]; then
    echo "    cleanup_utility.exe: ${CLEANUP_HASH}"
fi
echo ""
echo "Deployment:"
echo "  1. Copy ${TEST_UUID}.exe to target system"
echo "  2. Run as Administrator: ${TEST_UUID}.exe"
echo "  3. Review test_execution_log.json for results"
echo "  4. Cleanup (if needed): C:\\F0\\cleanup_utility.exe"
echo ""
echo "Test Stages:"
echo "  Stage 1 (T1016):     EDR Process Discovery"
echo "  Stage 2 (T1562.004): WFP Filter Application"
echo "  Stage 3 (T1489):     Service Disruption"
echo ""
echo "================================================================="
