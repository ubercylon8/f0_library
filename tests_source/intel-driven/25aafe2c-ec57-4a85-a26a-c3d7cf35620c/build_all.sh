#!/bin/bash
# Multi-Stage Intel-Driven Test Build Script
# ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira) - 5 stages + cleanup utility
#
# CRITICAL BUILD SEQUENCE:
# 1. Build unsigned stage binaries (each from stage .go + test_logger.go + org_resolver.go)
# 2. Build cleanup utility
# 3. Sign stage binaries + cleanup (BEFORE embedding)
# 4. Verify signatures
# 5. Build main orchestrator (embeds SIGNED stage binaries + cleanup)
# 6. Sign orchestrator
# 7. Cleanup temporary binaries + calculate hashes
#
# Usage: ./build_all.sh [--org <org-identifier>]
# Output: build/<uuid>/<uuid>

set -e  # Exit on any error
set -u  # Exit on undefined variable

# ==============================================================================
# CONFIGURATION
# ==============================================================================

TEST_UUID="25aafe2c-ec57-4a85-a26a-c3d7cf35620c"

# Stage definitions: "TECHNIQUE:SOURCE_FILE"
declare -a STAGES=(
    "T1046:stage-T1046"
    "T1021.004:stage-T1021.004"
    "T1489:stage-T1489"
    "T1048:stage-T1048"
    "T1486:stage-T1486"
)

# ==============================================================================
# DO NOT EDIT BELOW THIS LINE
# ==============================================================================

# Parse command-line arguments
ORG_CERT=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --org)
            ORG_CERT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--org <org-identifier>]"
            echo ""
            echo "Options:"
            echo "  --org <id>    Organization for dual signing (local mode only)"
            echo "                Examples: sb, 09b59276-9efb-4d3d-bbdd-4b4663ef0c42"
            echo "  -h, --help    Show this help message"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1"
            exit 1
            ;;
    esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "${SCRIPT_DIR}/../../utils" ]; then
    PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
else
    PROJECT_ROOT=""
fi
TEST_DIR="${SCRIPT_DIR}"
BUILD_DIR="${TEST_DIR}/build/${TEST_UUID}"

# Source helpers if available (local mode only)
if [ -n "$PROJECT_ROOT" ] && [ -f "${PROJECT_ROOT}/utils/resolve_org.sh" ]; then
    source "${PROJECT_ROOT}/utils/resolve_org.sh"
fi

# Build configuration
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"
export CGO_ENABLED="${CGO_ENABLED:-0}"

# ==============================================================================
# Signing Configuration
# ==============================================================================

SIGN_MODE="none"
SIGN_CERT=""
SIGN_PASS_FILE=""

if [ -n "${F0_SIGN_CERT_PATH:-}" ]; then
    SIGN_MODE="projectachilles"
    SIGN_CERT="${F0_SIGN_CERT_PATH}"
    SIGN_PASS_FILE="${F0_SIGN_CERT_PASS_FILE:-}"
elif [ -n "$PROJECT_ROOT" ]; then
    if [ -n "$ORG_CERT" ] && command -v resolve_org_to_cert &> /dev/null; then
        CERT_FILE=$(resolve_org_to_cert "$ORG_CERT") || true
        if [ -n "$CERT_FILE" ] && [ -f "${PROJECT_ROOT}/signing-certs/${CERT_FILE}" ]; then
            SIGN_MODE="f0library-org"
            SIGN_CERT="${PROJECT_ROOT}/signing-certs/${CERT_FILE}"
            F0RTIKA_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
        fi
    elif [ -f "${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx" ]; then
        SIGN_MODE="f0library"
        SIGN_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
        SIGN_PASS_FILE="${PROJECT_ROOT}/signing-certs/.F0RT1KA.pfx.txt"
    fi
fi

# ==============================================================================
# Helper Functions
# ==============================================================================

print_header() {
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=================================================${NC}"
}

print_step() {
    echo -e "${GREEN}[$1] $2${NC}"
}

print_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

sign_binary() {
    local binary="$1"
    local binary_name
    binary_name=$(basename "$binary")

    if [ "$SIGN_MODE" = "none" ]; then
        return 0
    fi

    if ! command -v osslsigncode &> /dev/null; then
        print_warning "osslsigncode not installed - skipping signing for ${binary_name}"
        return 0
    fi

    local signed_binary="${binary}.signed"

    if [ "$SIGN_MODE" = "projectachilles" ]; then
        if [ -z "$SIGN_PASS_FILE" ] || [ ! -f "$SIGN_PASS_FILE" ]; then
            print_warning "Cert password file not found - skipping signing for ${binary_name}"
            return 0
        fi
        osslsigncode sign \
            -pkcs12 "$SIGN_CERT" \
            -readpass "$SIGN_PASS_FILE" \
            -in "$binary" \
            -out "$signed_binary" 2>/dev/null
    elif [ "$SIGN_MODE" = "f0library-org" ]; then
        if [ -n "$PROJECT_ROOT" ] && [ -f "${PROJECT_ROOT}/utils/codesign" ]; then
            "${PROJECT_ROOT}/utils/codesign" sign-nested "$binary" "$SIGN_CERT" "${F0RTIKA_CERT:-}"
            echo "    Dual-signed: ${binary_name}"
            return 0
        else
            print_warning "codesign utility not found - falling back to single signing"
        fi
        local pass_file="${SIGN_CERT%.*}.pfx.txt"
        if [ -f "$pass_file" ]; then
            local password
            password=$(tr -d '\n\r' < "$pass_file")
            osslsigncode sign \
                -pkcs12 "$SIGN_CERT" \
                -pass "$password" \
                -in "$binary" \
                -out "$signed_binary" 2>/dev/null
        else
            print_warning "Cert password file not found for org cert - skipping"
            return 0
        fi
    elif [ "$SIGN_MODE" = "f0library" ]; then
        if [ ! -f "$SIGN_PASS_FILE" ]; then
            print_warning "Cert password file not found - skipping signing for ${binary_name}"
            return 0
        fi
        local password
        password=$(tr -d '\n\r' < "$SIGN_PASS_FILE")
        osslsigncode sign \
            -pkcs12 "$SIGN_CERT" \
            -pass "$password" \
            -in "$binary" \
            -out "$signed_binary" 2>/dev/null
    fi

    if [ $? -eq 0 ] && [ -f "$signed_binary" ]; then
        mv "$signed_binary" "$binary"
        echo "    Signed: ${binary_name}"
    else
        rm -f "$signed_binary"
        print_warning "Signing failed for ${binary_name} - continuing unsigned"
    fi
}

# ==============================================================================
# Build Process
# ==============================================================================

print_header "Multi-Stage Test Build: ESXi Hypervisor Ransomware Kill Chain"
echo "  Test UUID:  ${TEST_UUID}"
echo "  Platform:   ${GOOS}/${GOARCH}"
echo "  Signing:    ${SIGN_MODE}"
echo "  Stages:     ${#STAGES[@]}"

# Step 0: Validate environment
print_step "0/7" "Validating environment..."

if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

cd "${TEST_DIR}"
go mod download 2>/dev/null || true
print_success "Environment validated"

# Step 1: Build unsigned stage binaries
print_step "1/7" "Building ${#STAGES[@]} unsigned stage binaries..."

stage_count=0
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    output_name="${TEST_UUID}-${technique}"

    echo "  Building ${technique} (${source}.go)..."
    GOOS=${GOOS} GOARCH=${GOARCH} go build \
        -o "${output_name}" \
        "${source}.go" test_logger.go test_logger_linux.go org_resolver.go es_config.go

    if [ ! -f "${output_name}" ]; then
        print_error "Failed to build ${output_name}"
        exit 1
    fi

    stage_count=$((stage_count + 1))
done
print_success "Built ${stage_count} unsigned stage binaries"

# Step 2: Build cleanup utility
print_step "2/7" "Building cleanup utility..."
GOOS=${GOOS} GOARCH=${GOARCH} go build \
    -o cleanup_utility \
    cleanup_utility.go
print_success "cleanup_utility built"

# Step 3: Sign stage binaries + cleanup (CRITICAL - before embedding!)
print_step "3/7" "Signing stage binaries..."
if [ "$GOOS" = "linux" ]; then
    echo "  Skipped (Authenticode signing not applicable for Linux ELF binaries)"
elif [ "$SIGN_MODE" = "none" ]; then
    print_warning "No signing certificate found - stages will be unsigned"
else
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        sign_binary "${TEST_UUID}-${technique}"
    done
    sign_binary "cleanup_utility"
    print_success "Stage signing complete"
fi

# Step 4: Verify signatures
print_step "4/7" "Verifying stage signatures..."
if [ "$GOOS" = "linux" ]; then
    echo "  Skipped (Authenticode signing not applicable for Linux ELF binaries)"
elif [ "$SIGN_MODE" != "none" ] && command -v osslsigncode &> /dev/null; then
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        binary="${TEST_UUID}-${technique}"
        if osslsigncode verify "${binary}" 2>&1 | grep -q "Message digest"; then
            echo "    Verified: ${binary}"
        else
            print_warning "Could not verify signature for ${binary}"
        fi
    done
    if osslsigncode verify "cleanup_utility" 2>&1 | grep -q "Message digest"; then
        echo "    Verified: cleanup_utility"
    else
        print_warning "Could not verify signature for cleanup_utility"
    fi
    print_success "Signature verification complete"
else
    echo "  Skipped (no signing or osslsigncode not installed)"
fi

# Step 5: Build main orchestrator (embeds SIGNED stage binaries + cleanup)
print_step "5/7" "Building orchestrator (embedding signed stages)..."

mkdir -p "${BUILD_DIR}"
main_binary="${BUILD_DIR}/${TEST_UUID}"

GOOS=${GOOS} GOARCH=${GOARCH} go build \
    -o "${main_binary}" \
    "${TEST_UUID}.go" test_logger.go test_logger_linux.go org_resolver.go es_config.go

if [ ! -f "${main_binary}" ]; then
    print_error "Failed to build orchestrator"
    exit 1
fi

main_size=$(ls -lh "${main_binary}" | awk '{print $5}')
print_success "Orchestrator built (${main_size})"

# Step 6: Sign orchestrator
print_step "6/7" "Signing orchestrator..."
if [ "$GOOS" = "linux" ]; then
    echo "  Skipped (Authenticode signing not applicable for Linux ELF binaries)"
elif [ "$SIGN_MODE" != "none" ]; then
    sign_binary "${main_binary}"
    print_success "Orchestrator signing complete"
else
    print_warning "Skipping orchestrator signing (no certificate)"
fi

# Step 7: Cleanup temporary binaries + calculate hashes
print_step "7/7" "Cleaning up and calculating hashes..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    rm -f "${TEST_UUID}-${technique}"
done
rm -f cleanup_utility

main_hash=$(sha1sum "${main_binary}" | awk '{print $1}')
main_size_final=$(ls -lh "${main_binary}" | awk '{print $5}')

print_success "Cleanup complete"

# ==============================================================================
# Build Summary
# ==============================================================================

print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Test Name:        ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira)"
echo "  Stages Built:     ${stage_count}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}"
echo "  Binary Size:      ${main_size_final}"
echo "  SHA1 Hash:        ${main_hash}"
echo "  Signing Mode:     ${SIGN_MODE}"
echo ""
echo "Stages:"
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    echo "  - ${TEST_UUID}-${technique} (${source}.go)"
done
echo "  - cleanup_utility"
echo ""
print_success "Multi-stage test ready for deployment!"
echo ""
echo "Deployment:"
echo "  1. Copy ${BUILD_DIR}/${TEST_UUID} to target Linux system"
echo "  2. Run: ./${TEST_UUID}"
echo "  3. Test will extract and execute 5 stages in killchain order"
echo "  4. Cleanup: /tmp/F0/esxi_cleanup"
echo ""
