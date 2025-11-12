#!/bin/bash
set -e

TEST_UUID="eafce2fc-75fd-4c62-92dc-32cabe5cf206"
TEST_DIR="tests_source/${TEST_UUID}"
BUILD_DIR="build/${TEST_UUID}"

# Parse command-line arguments
ORG_CERT=""
USAGE="Usage: $0 [--org <org-name>]

Options:
  --org <org-name>    Organization certificate to use for dual signing (default: sb)
                      Available: sb, tpsgl, rga

Examples:
  $0                  # Use default sb certificate
  $0 --org tpsgl      # Use tpsgl certificate
  $0 --org rga        # Use rga certificate
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

# Default to sb if no org specified
if [ -z "$ORG_CERT" ]; then
    ORG_CERT="sb"
fi

# Map org name to certificate file (paths relative from test directory)
case "$ORG_CERT" in
    sb)
        ORG_CERT_FILE="../../signing-certs/F0-LocalCodeSigningCert-CST-SB.pfx"
        ORG_CERT_FILE_ROOT="signing-certs/F0-LocalCodeSigningCert-CST-SB.pfx"
        ;;
    tpsgl)
        ORG_CERT_FILE="../../signing-certs/F0-LocalCodeSigningCert-CST-TPSGL.pfx"
        ORG_CERT_FILE_ROOT="signing-certs/F0-LocalCodeSigningCert-CST-TPSGL.pfx"
        ;;
    rga)
        ORG_CERT_FILE="../../signing-certs/F0-LocalCodeSigningCert-CST-RGA.pfx"
        ORG_CERT_FILE_ROOT="signing-certs/F0-LocalCodeSigningCert-CST-RGA.pfx"
        ;;
    *)
        echo "ERROR: Unknown organization: $ORG_CERT"
        echo "Available organizations: sb, tpsgl, rga"
        exit 1
        ;;
esac

# Verify certificate file exists (check from root)
if [ ! -f "signing-certs/$(basename ${ORG_CERT_FILE})" ]; then
    echo "ERROR: Certificate file not found: signing-certs/$(basename ${ORG_CERT_FILE})"
    exit 1
fi

echo "================================================================="
echo "Building Multi-Stage Test: Tailscale Remote Access"
echo "Test ID: ${TEST_UUID}"
echo "Organization: ${ORG_CERT}"
echo "Certificate: $(basename ${ORG_CERT_FILE})"
echo "================================================================="
echo ""

# Stage definitions: "TECHNIQUE:SOURCE_FILE"
declare -a STAGES=(
    "T1105:stage-T1105"
    "T1543.003:stage-T1543.003"
    "T1219:stage-T1219"
    "T1021.004:stage-T1021.004"
    "T1041:stage-T1041"
)

# Change to test directory
cd "${TEST_DIR}"

# Step 1: Build stage binaries (unsigned)
echo "[Step 1/7] Building ${#STAGES[@]} stage binaries..."
echo ""

for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    output_name="${TEST_UUID}-${technique}.exe"

    echo "  Building ${technique} (${source}.go)..."
    GOOS=windows GOARCH=amd64 go build -o "${output_name}" "${source}.go" test_logger.go

    if [ ! -f "${output_name}" ]; then
        echo "ERROR: Failed to build ${output_name}"
        exit 1
    fi

    echo "    ✓ ${output_name} created"
done

echo ""

# Step 2: Build cleanup utility
echo "[Step 2/7] Building cleanup utility..."
GOOS=windows GOARCH=amd64 go build -o cleanup_utility.exe cleanup_utility.go
echo "    ✓ cleanup_utility.exe created"
echo ""

# Step 3: Dual-sign stage binaries (CRITICAL - before embedding!)
echo "[Step 3/7] Dual-signing stage binaries and cleanup utility (${ORG_CERT} + F0RT1KA)..."
echo ""

for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${TEST_UUID}-${technique}.exe"

    echo "  Dual-signing ${binary}..."
    ../../utils/codesign sign-nested "${binary}" "${ORG_CERT_FILE}" ../../signing-certs/F0RT1KA.pfx

    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to sign ${binary}"
        exit 1
    fi
done

echo "  Dual-signing cleanup_utility.exe..."
../../utils/codesign sign-nested cleanup_utility.exe "${ORG_CERT_FILE}" ../../signing-certs/F0RT1KA.pfx

echo ""

# Step 4: Verify signatures
echo "[Step 4/7] Verifying stage signatures..."
echo ""

for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    binary="${TEST_UUID}-${technique}.exe"

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

# Step 5: Download Tailscale MSI (for embedded mode)
echo "[Step 5/7] Downloading Tailscale MSI for embedding..."
echo ""

TAILSCALE_MSI_URL="https://pkgs.tailscale.com/stable/tailscale-setup-1.78.3-amd64.msi"
TAILSCALE_EMBEDDED="tailscale_embedded.msi"

if [ ! -f "${TAILSCALE_EMBEDDED}" ]; then
    echo "  Downloading from ${TAILSCALE_MSI_URL}..."
    curl -L -o "${TAILSCALE_EMBEDDED}" "${TAILSCALE_MSI_URL}"

    if [ ! -f "${TAILSCALE_EMBEDDED}" ]; then
        echo "  WARNING: Failed to download Tailscale MSI"
        echo "  Creating placeholder (download mode will be required)"
        touch "${TAILSCALE_EMBEDDED}"
    else
        file_size=$(ls -lh "${TAILSCALE_EMBEDDED}" | awk '{print $5}')
        echo "    ✓ Tailscale MSI downloaded (${file_size})"
    fi
else
    file_size=$(ls -lh "${TAILSCALE_EMBEDDED}" | awk '{print $5}')
    echo "  Using existing ${TAILSCALE_EMBEDDED} (${file_size})"
fi

echo ""

# Step 6: Build main orchestrator (embeds SIGNED stage binaries)
echo "[Step 6/7] Building main orchestrator (embedding signed stages)..."
echo ""

cd ../..

mkdir -p "${BUILD_DIR}"

echo "  Building ${TEST_UUID}.exe..."
cd "${TEST_DIR}"
GOOS=windows GOARCH=amd64 go build -o "../../${BUILD_DIR}/${TEST_UUID}.exe" "${TEST_UUID}.go" test_logger.go

if [ ! -f "../../${BUILD_DIR}/${TEST_UUID}.exe" ]; then
    echo "ERROR: Failed to build main binary"
    exit 1
fi

echo "    ✓ Main binary created"
echo ""

cd ../..

# Step 7: Dual-sign main binary
echo "[Step 7/7] Dual-signing main binary (${ORG_CERT} + F0RT1KA)..."
echo ""

./utils/codesign sign-nested "${BUILD_DIR}/${TEST_UUID}.exe" "${ORG_CERT_FILE_ROOT}" signing-certs/F0RT1KA.pfx

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to sign main binary"
    exit 1
fi

echo "    ✓ Main binary dual-signed"
echo ""

# Cleanup temporary files
echo "Cleaning up temporary stage binaries from source directory..."
cd "${TEST_DIR}"

for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    rm -f "${TEST_UUID}-${technique}.exe"
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
echo "  ✓ All binaries dual-signed (${ORG_CERT} org cert + F0RT1KA)"
echo "  ✓ Stage binaries: 5 stages + cleanup utility"
echo "  ✓ Main orchestrator: Full test binary"
echo ""
echo "Deployment:"
echo "  1. Replace AUTH_KEY placeholder in source code before building"
echo "  2. Copy ${TEST_UUID}.exe to target system"
echo "  3. Run: ${TEST_UUID}.exe [--download]"
echo "  4. Cleanup: C:\\F0\\tailscale_cleanup.exe"
echo ""
echo "Flags:"
echo "  --download    Download Tailscale from official servers"
echo "  (default)     Use embedded Tailscale binary"
echo ""
echo "================================================================="
