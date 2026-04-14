#!/bin/bash
# Multi-Stage Intel-Driven Test Build Script
# HONESTCUE LLM-Assisted Runtime C# Compilation — 3 stages
#
# CRITICAL BUILD SEQUENCE:
# 1. Build unsigned stage binaries
# 2. Sign stage binaries (BEFORE embedding)
# 3. Verify signatures
# 4. Compress signed binaries with gzip
# 5. Build main orchestrator (embeds SIGNED+COMPRESSED stages)
# 6. Sign orchestrator
# 7. Cleanup temporary binaries + calculate hashes
# 8. Summary report
#
# Usage: ./build_all.sh [--org <org-identifier>]
# Output: build/<uuid>/<uuid>.exe

set -e
set -u

# ==============================================================================
# CONFIGURATION
# ==============================================================================

TEST_UUID="e5472cd5-c799-4b07-b455-8c02665ca4cf"

# Stage definitions: "TECHNIQUE:SOURCE_FILE"
declare -a STAGES=(
    "T1071.001:stage-T1071.001"
    "T1027.004:stage-T1027.004"
    "T1105:stage-T1105"
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
if [ -d "${SCRIPT_DIR}/../../../utils" ]; then
    PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
else
    PROJECT_ROOT=""
fi
TEST_DIR="${SCRIPT_DIR}"
BUILD_DIR="${TEST_DIR}/build/${TEST_UUID}"

# Source helpers if available
if [ -n "$PROJECT_ROOT" ] && [ -f "${PROJECT_ROOT}/utils/resolve_org.sh" ]; then
    source "${PROJECT_ROOT}/utils/resolve_org.sh"
fi

# Build configuration
GOOS="${GOOS:-windows}"
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
        print_warning "osslsigncode not installed — skipping signing for ${binary_name}"
        return 0
    fi

    local signed_binary="${binary}.signed"

    if [ "$SIGN_MODE" = "projectachilles" ]; then
        if [ -z "$SIGN_PASS_FILE" ] || [ ! -f "$SIGN_PASS_FILE" ]; then
            print_warning "Cert password file not found — skipping signing for ${binary_name}"
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
            print_warning "codesign utility not found — falling back to single signing"
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
            print_warning "Cert password file not found for org cert — skipping"
            return 0
        fi
    elif [ "$SIGN_MODE" = "f0library" ]; then
        if [ ! -f "$SIGN_PASS_FILE" ]; then
            print_warning "Cert password file not found — skipping signing for ${binary_name}"
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
        print_warning "Signing failed for ${binary_name} — continuing unsigned"
    fi
}

# ==============================================================================
# Build Process
# ==============================================================================

print_header "Multi-Stage Test Build: HONESTCUE LLM-Assisted Runtime C# Compilation"
echo "  Test UUID:  ${TEST_UUID}"
echo "  Platform:   ${GOOS}/${GOARCH}"
echo "  Signing:    ${SIGN_MODE}"
echo "  Stages:     ${#STAGES[@]}"

# Step 0: Validate environment
print_step "0/8" "Validating environment..."

if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

cd "${TEST_DIR}"
go mod download 2>/dev/null || true
print_success "Environment validated"

# Step 1: Build unsigned stage binaries
print_step "1/8" "Building ${#STAGES[@]} unsigned stage binaries..."

stage_count=0
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    output_name="${TEST_UUID}-${technique}.exe"

    echo "  Building ${technique} (${source}.go)..."
    GOOS=${GOOS} GOARCH=${GOARCH} go build \
        -o "${output_name}" \
        "${source}.go" test_logger.go test_logger_windows.go org_resolver.go

    if [ ! -f "${output_name}" ]; then
        print_error "Failed to build ${output_name}"
        exit 1
    fi

    stage_count=$((stage_count + 1))
done
print_success "Built ${stage_count} unsigned stage binaries"

# Step 2: Sign stage binaries (CRITICAL — before embedding!)
print_step "2/8" "Signing stage binaries..."
if [ "$SIGN_MODE" = "none" ]; then
    print_warning "No signing certificate found — stages will be unsigned"
else
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        sign_binary "${TEST_UUID}-${technique}.exe"
    done
    print_success "Stage signing complete"
fi

# Step 3: Verify signatures
print_step "3/8" "Verifying stage signatures..."
if [ "$SIGN_MODE" != "none" ] && command -v osslsigncode &> /dev/null; then
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        binary="${TEST_UUID}-${technique}.exe"
        if osslsigncode verify "${binary}" 2>&1 | grep -q "Message digest"; then
            echo "    Verified: ${binary}"
        else
            print_warning "Could not verify signature for ${binary}"
        fi
    done
    print_success "Signature verification complete"
else
    echo "  Skipped (no signing or osslsigncode not installed)"
fi

# Step 4: Compress signed binaries with gzip (MANDATORY per CLAUDE.md)
print_step "4/8" "Compressing signed binaries with gzip..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    binary="${TEST_UUID}-${technique}.exe"
    orig_size=$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary" 2>/dev/null)
    gzip -9 -k "$binary"
    gz_size=$(stat -c%s "${binary}.gz" 2>/dev/null || stat -f%z "${binary}.gz" 2>/dev/null)
    echo "    ${binary}: $(numfmt --to=iec ${orig_size} 2>/dev/null || echo ${orig_size}B) -> $(numfmt --to=iec ${gz_size} 2>/dev/null || echo ${gz_size}B)"
done
print_success "Compression complete"

# Step 5: Build main orchestrator (embeds SIGNED+COMPRESSED stage binaries)
print_step "5/8" "Building orchestrator (embedding compressed stages)..."

mkdir -p "${BUILD_DIR}"
main_binary="${BUILD_DIR}/${TEST_UUID}.exe"

GOOS=${GOOS} GOARCH=${GOARCH} go build \
    -o "${main_binary}" \
    "${TEST_UUID}.go" test_logger.go test_logger_windows.go org_resolver.go

if [ ! -f "${main_binary}" ]; then
    print_error "Failed to build orchestrator"
    exit 1
fi

main_size=$(ls -lh "${main_binary}" | awk '{print $5}')
print_success "Orchestrator built (${main_size})"

# Step 6: Sign orchestrator
print_step "6/8" "Signing orchestrator..."
if [ "$SIGN_MODE" != "none" ]; then
    sign_binary "${main_binary}"
    print_success "Orchestrator signing complete"
else
    print_warning "Skipping orchestrator signing (no certificate)"
fi

# Step 7: Cleanup temporary stage binaries + calculate hashes
print_step "7/8" "Cleaning up and calculating hashes..."

main_hash=$(sha1sum "${main_binary}" | awk '{print $1}')
main_size_final=$(ls -lh "${main_binary}" | awk '{print $5}')

# Clean up temporary files (both .exe and .exe.gz)
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    rm -f "${TEST_UUID}-${technique}.exe" "${TEST_UUID}-${technique}.exe.gz"
done

# Step 8: Summary
print_step "8/8" "Build summary"
print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Test Name:        HONESTCUE LLM-Assisted Runtime C# Compilation"
echo "  Stages Built:     ${stage_count}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Binary Size:      ${main_size_final}"
echo "  SHA1 Hash:        ${main_hash}"
echo "  Signing Mode:     ${SIGN_MODE}"
echo ""
echo "Stages:"
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    echo "  - ${TEST_UUID}-${technique}.exe (${source}.go)"
done
echo ""
print_success "Multi-stage test ready for deployment!"
