#!/bin/bash
# Multi-Stage Test Build Script Template
# F0RT1KA Security Testing Framework
#
# This template automates the complex build process for multi-stage tests where
# each ATT&CK technique is a separate binary that must be signed BEFORE embedding
# in the main orchestrator binary.
#
# CRITICAL BUILD SEQUENCE:
# 1. Build unsigned stage binaries
# 2. Sign stage binaries (BEFORE embedding)
# 3. Verify signatures
# 4. Build main orchestrator (embeds SIGNED stage binaries)
# 5. Sign main binary
# 6. Cleanup temporary files
#
# Usage: ./build_all.sh
# Output: build/<uuid>/<uuid>.exe (single deployable binary)

set -e  # Exit on any error
set -u  # Exit on undefined variable

# ==============================================================================
# CONFIGURATION - EDIT THIS SECTION FOR YOUR TEST
# ==============================================================================

# Test UUID (lowercase)
TEST_UUID="REPLACE_WITH_TEST_UUID"

# Stage binaries to build (technique ID → source file)
# Format: "T<technique-id>:<source-file-without-extension>"
# Example: "T1134.001:stage-token-manipulation"
declare -a STAGES=(
    "T1134.001:stage-token-manipulation"
    "T1055.001:stage-process-injection"
    "T1003.001:stage-credential-dump"
)

# ==============================================================================
# DO NOT EDIT BELOW THIS LINE (unless you know what you're doing)
# ==============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_DIR="${PROJECT_ROOT}/tests_source/${TEST_UUID}"
BUILD_DIR="${PROJECT_ROOT}/build/${TEST_UUID}"

# Build configuration
GOOS="windows"
GOARCH="amd64"

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
    echo -e "${YELLOW}⚠ WARNING: $1${NC}"
}

print_error() {
    echo -e "${RED}❌ ERROR: $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Validate environment
validate_environment() {
    print_step "0/6" "Validating environment..."

    # Check if test directory exists
    if [ ! -d "${TEST_DIR}" ]; then
        print_error "Test directory not found: ${TEST_DIR}"
        exit 1
    fi

    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed or not in PATH"
        exit 1
    fi

    # Check if codesign utility exists
    if [ ! -f "${PROJECT_ROOT}/utils/codesign" ]; then
        print_error "codesign utility not found: ${PROJECT_ROOT}/utils/codesign"
        exit 1
    fi

    # Check if osslsigncode is installed (for verification)
    if ! command -v osslsigncode &> /dev/null; then
        print_warning "osslsigncode not installed - signature verification will be skipped"
        print_warning "Install with: brew install osslsigncode (macOS) or apt-get install osslsigncode (Linux)"
    fi

    print_success "Environment validation passed"
}

# ==============================================================================
# Build Process
# ==============================================================================

print_header "Multi-Stage Test Build: ${TEST_UUID}"

# Step 0: Validate environment
validate_environment

# Change to test directory
cd "${TEST_DIR}"

# Step 1: Build unsigned stage binaries
print_step "1/6" "Building unsigned stage binaries..."
stage_count=0
for stage_def in "${STAGES[@]}"; do
    IFS=':' read -r technique source_file <<< "$stage_def"
    stage_binary="${TEST_UUID}-${technique}.exe"
    source_go="${source_file}.go"

    if [ ! -f "${source_go}" ]; then
        print_error "Source file not found: ${source_go}"
        exit 1
    fi

    echo "  Building ${stage_binary} from ${source_go}..."
    GOOS=${GOOS} GOARCH=${GOARCH} go build -o "${stage_binary}" "${source_go}" test_logger.go

    if [ ! -f "${stage_binary}" ]; then
        print_error "Failed to build ${stage_binary}"
        exit 1
    fi

    stage_count=$((stage_count + 1))
done
print_success "Built ${stage_count} unsigned stage binaries"

# Read F0RT1KA certificate password (auto-read from password file)
F0RT1KA_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
F0RT1KA_PASSWORD=$(cat "${PROJECT_ROOT}/signing-certs/.F0RT1KA.pfx.txt" | tr -d '\n\r')

# Step 2: Sign stage binaries (CRITICAL - before embedding)
print_step "2/6" "Signing stage binaries..."
for stage_def in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage_def"
    stage_binary="${TEST_UUID}-${technique}.exe"

    echo "  Signing ${stage_binary}..."
    "${PROJECT_ROOT}/utils/codesign" --cert "${F0RT1KA_CERT}" --password "${F0RT1KA_PASSWORD}" sign "${stage_binary}"

    if [ $? -ne 0 ]; then
        print_error "Failed to sign ${stage_binary}"
        exit 1
    fi
done
print_success "Signed ${stage_count} stage binaries"

# Step 3: Verify signatures (self-signed certs will show warnings but are cryptographically valid)
print_step "3/6" "Verifying stage signatures..."
if command -v osslsigncode &> /dev/null; then
    for stage_def in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage_def"
        stage_binary="${TEST_UUID}-${technique}.exe"

        echo "  Verifying ${stage_binary}..."
        # Check if signature is present by looking for "Message digest" in output
        if osslsigncode verify "${stage_binary}" 2>&1 | grep -q "Message digest"; then
            echo "    ✓ Signature present and valid (self-signed cert)"
        else
            print_error "Could not verify signature for ${stage_binary}"
            exit 1
        fi
    done
    print_success "All stage signatures verified"
else
    print_warning "Skipping signature verification (osslsigncode not installed)"
fi

# Step 4: Build main orchestrator (embeds SIGNED stage binaries)
print_step "4/6" "Building main orchestrator (embedding signed stages)..."

# Create build directory if it doesn't exist
mkdir -p "${BUILD_DIR}"

# Build main binary
main_binary="${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Building ${TEST_UUID}.exe with embedded stage binaries..."
GOOS=${GOOS} GOARCH=${GOARCH} go build -o "${main_binary}" "${TEST_UUID}.go" test_logger.go

if [ ! -f "${main_binary}" ]; then
    print_error "Failed to build main binary: ${TEST_UUID}.exe"
    exit 1
fi

# Get file size before signing
main_size_before=$(ls -lh "${main_binary}" | awk '{print $5}')
print_success "Main orchestrator built (${main_size_before})"

# Step 5: Sign main binary
print_step "5/6" "Signing main binary..."
cd "${PROJECT_ROOT}"
"${PROJECT_ROOT}/utils/codesign" --cert "${F0RT1KA_CERT}" --password "${F0RT1KA_PASSWORD}" sign "${BUILD_DIR}/${TEST_UUID}.exe"

if [ $? -ne 0 ]; then
    print_error "Failed to sign main binary"
    exit 1
fi

# Verify main binary signature
if command -v osslsigncode &> /dev/null; then
    osslsigncode verify "${BUILD_DIR}/${TEST_UUID}.exe" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        print_error "Main binary signature verification failed"
        exit 1
    fi
fi

main_size_after=$(ls -lh "${BUILD_DIR}/${TEST_UUID}.exe" | awk '{print $5}')
print_success "Main binary signed (${main_size_after})"

# Step 6: Cleanup temporary stage binaries
print_step "6/6" "Cleaning up temporary files..."
cd "${TEST_DIR}"
for stage_def in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage_def"
    stage_binary="${TEST_UUID}-${technique}.exe"

    if [ -f "${stage_binary}" ]; then
        echo "  Removing ${stage_binary}..."
        rm -f "${stage_binary}"
    fi
done
print_success "Cleanup complete"

# ==============================================================================
# Build Summary
# ==============================================================================

print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Stages Built:     ${stage_count}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Binary Size:      ${main_size_after}"
echo ""
echo "Stage Techniques:"
for stage_def in "${STAGES[@]}"; do
    IFS=':' read -r technique source_file <<< "$stage_def"
    echo "  - ${technique} (${source_file}.go)"
done
echo ""
print_success "Multi-stage test ready for deployment!"
echo ""
echo "Deployment:"
echo "  1. Copy ${BUILD_DIR}/${TEST_UUID}.exe to target Windows system"
echo "  2. Run: C:\\${TEST_UUID}.exe"
echo "  3. Test will extract and execute stages in killchain order"
echo ""
