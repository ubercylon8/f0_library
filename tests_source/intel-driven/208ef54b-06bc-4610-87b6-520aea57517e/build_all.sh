#!/bin/bash
# Multi-Stage Intel-Driven Test Build Script
# ScreenConnect Unsanctioned RMM Abuse for Third-Party Access — 3 stages + cleanup
#
# CRITICAL BUILD SEQUENCE (modern 8-step gzip pattern):
# 0. Validate environment + MANUAL MSI GATE
# 1. Build unsigned stage binaries
# 2. Build cleanup utility
# 3. Sign stage binaries (BEFORE embedding)
# 4. Verify signatures
# 5. Compress signed binaries with gzip (~35% smaller orchestrator)
# 6. Build main orchestrator (embeds SIGNED+COMPRESSED stages)
# 7. Sign orchestrator
# 8. Cleanup temporary binaries + calculate hashes
#
# MANUAL BUILD GATE:
#   Stage 1 (T1219) embeds the ConnectWise ScreenConnect Windows MSI, which is NOT
#   committed to the repo (vendor licensing / redistribution). The user must stage:
#       screenconnect_embedded.msi   (in THIS test directory)
#   before building. This script stops with an explicit message if it is missing.
#
# Usage: ./build_all.sh [--org <org-identifier>]
# Output: build/<uuid>/<uuid>.exe

set -e
set -u

# ==============================================================================
# CONFIGURATION
# ==============================================================================

TEST_UUID="208ef54b-06bc-4610-87b6-520aea57517e"

# Stage definitions: "TECHNIQUE:SOURCE_FILE"
declare -a STAGES=(
    "T1219:stage-T1219"
    "T1543.003:stage-T1543.003"
    "T1567.002:stage-T1567.002"
)

# The embedded vendor MSI (staged out-of-band by the user; see MANUAL BUILD GATE).
MSI_ASSET="screenconnect_embedded.msi"

# ==============================================================================
# DO NOT EDIT BELOW THIS LINE
# ==============================================================================

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

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Paths — tests live at tests_source/<category>/<uuid>/, three levels below f0_library/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "${SCRIPT_DIR}/../../../utils" ]; then
    PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
else
    PROJECT_ROOT=""
fi
TEST_DIR="${SCRIPT_DIR}"
BUILD_DIR="${TEST_DIR}/build/${TEST_UUID}"

if [ -n "$PROJECT_ROOT" ] && [ -f "${PROJECT_ROOT}/utils/resolve_org.sh" ]; then
    source "${PROJECT_ROOT}/utils/resolve_org.sh"
fi

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
print_step()    { echo -e "${GREEN}[$1] $2${NC}"; }
print_warning() { echo -e "${YELLOW}WARNING: $1${NC}"; }
print_error()   { echo -e "${RED}ERROR: $1${NC}"; }
print_success() { echo -e "${GREEN}$1${NC}"; }

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
        osslsigncode sign -pkcs12 "$SIGN_CERT" -readpass "$SIGN_PASS_FILE" \
            -in "$binary" -out "$signed_binary" 2>/dev/null
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
            osslsigncode sign -pkcs12 "$SIGN_CERT" -pass "$password" \
                -in "$binary" -out "$signed_binary" 2>/dev/null
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
        osslsigncode sign -pkcs12 "$SIGN_CERT" -pass "$password" \
            -in "$binary" -out "$signed_binary" 2>/dev/null
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

print_header "Multi-Stage Test Build: ScreenConnect Unsanctioned RMM Abuse"
echo "  Test UUID:  ${TEST_UUID}"
echo "  Platform:   ${GOOS}/${GOARCH}"
echo "  Signing:    ${SIGN_MODE}"
echo "  Stages:     ${#STAGES[@]}"

# Step 0: Validate environment + MANUAL MSI GATE
print_step "0/8" "Validating environment..."

if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

cd "${TEST_DIR}"

# ----- MANUAL BUILD GATE: vendor MSI must be staged by the user -----
if [ ! -f "${MSI_ASSET}" ] || [ ! -s "${MSI_ASSET}" ]; then
    echo ""
    print_error "MANUAL BUILD GATE — vendor MSI not staged."
    echo ""
    echo "  This test embeds the ConnectWise ScreenConnect Windows installer, which is"
    echo "  NOT committed to the repository (vendor licensing / redistribution)."
    echo ""
    echo "  ACTION REQUIRED — drop the MSI here, then re-run this script:"
    echo ""
    echo -e "      ${YELLOW}${TEST_DIR}/${MSI_ASSET}${NC}"
    echo ""
    echo "  Acquire it from ConnectWise (trial/free ScreenConnect access agent MSI,"
    echo "  Windows x64) out-of-band and rename it to '${MSI_ASSET}'."
    echo "  It is git-ignored (see .gitignore) and must remain a LOCAL build asset."
    echo ""
    exit 2
fi
echo "  ${MSI_ASSET}: $(ls -lh ${MSI_ASSET} | awk '{print $5}')"

go mod download 2>/dev/null || true
print_success "Environment validated (MSI present)"

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

# Step 2: Build cleanup utility (self-contained)
print_step "2/8" "Building cleanup utility..."
GOOS=${GOOS} GOARCH=${GOARCH} go build -o cleanup_utility.exe cleanup_utility.go
print_success "cleanup_utility.exe built"

# Step 3: Sign stage binaries (CRITICAL — before embedding!)
print_step "3/8" "Signing stage binaries..."
if [ "$SIGN_MODE" = "none" ]; then
    print_warning "No signing certificate found — stages will be unsigned"
else
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        sign_binary "${TEST_UUID}-${technique}.exe"
    done
    sign_binary "cleanup_utility.exe"
    print_success "Stage signing complete"
fi

# Step 4: Verify signatures
print_step "4/8" "Verifying stage signatures..."
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
    if osslsigncode verify "cleanup_utility.exe" 2>&1 | grep -q "Message digest"; then
        echo "    Verified: cleanup_utility.exe"
    else
        print_warning "Could not verify signature for cleanup_utility.exe"
    fi
    print_success "Signature verification complete"
else
    echo "  Skipped (no signing or osslsigncode not installed)"
fi

# Step 5: Compress signed binaries with gzip (EDR-safe; files on disk are normal PEs)
print_step "5/8" "Compressing signed binaries with gzip..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    binary="${TEST_UUID}-${technique}.exe"
    orig_size=$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary" 2>/dev/null)
    gzip -9 -f -k "$binary"
    gz_size=$(stat -c%s "${binary}.gz" 2>/dev/null || stat -f%z "${binary}.gz" 2>/dev/null)
    echo "    ${binary}: $(numfmt --to=iec ${orig_size} 2>/dev/null || echo ${orig_size}B) -> $(numfmt --to=iec ${gz_size} 2>/dev/null || echo ${gz_size}B)"
done
gzip -9 -f -k "cleanup_utility.exe"
echo "    cleanup_utility.exe compressed"
print_success "Compression complete"

# Step 6: Build main orchestrator (embeds SIGNED+COMPRESSED stage binaries)
print_step "6/8" "Building orchestrator (embedding compressed stages)..."
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

# Step 7: Sign orchestrator
print_step "7/8" "Signing orchestrator..."
if [ "$SIGN_MODE" != "none" ]; then
    sign_binary "${main_binary}"
    print_success "Orchestrator signing complete"
else
    print_warning "Skipping orchestrator signing (no certificate)"
fi

# Step 8: Cleanup temporary binaries + calculate hashes
print_step "8/8" "Cleaning up and calculating hashes..."
main_hash=$(sha1sum "${main_binary}" | awk '{print $1}')
main_size_final=$(ls -lh "${main_binary}" | awk '{print $5}')
main_size_bytes=$(stat -c%s "${main_binary}" 2>/dev/null || stat -f%z "${main_binary}" 2>/dev/null)

for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    rm -f "${TEST_UUID}-${technique}.exe" "${TEST_UUID}-${technique}.exe.gz"
done
rm -f cleanup_utility.exe cleanup_utility.exe.gz

# Size budget tier (CLAUDE.md Binary Size Budget)
tier="green"
if   [ "${main_size_bytes}" -gt 52428800 ]; then tier="FORBIDDEN (>50MB)"
elif [ "${main_size_bytes}" -gt 26214400 ]; then tier="red (25-50MB)"
elif [ "${main_size_bytes}" -gt 10485760 ]; then tier="yellow (10-25MB)"
fi

print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Test Name:        ScreenConnect Unsanctioned RMM Abuse for Third-Party Access"
echo "  Stages Built:     ${stage_count}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Binary Size:      ${main_size_final}  (tier: ${tier})"
echo "  SHA1 Hash:        ${main_hash}"
echo "  Signing Mode:     ${SIGN_MODE}"
echo ""
echo "Stages:"
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    echo "  - ${TEST_UUID}-${technique}.exe (${source}.go)"
done
echo "  - cleanup_utility.exe"
echo ""
print_success "Multi-stage test ready for deployment!"
