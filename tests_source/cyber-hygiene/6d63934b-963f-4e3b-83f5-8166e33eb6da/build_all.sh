#!/bin/bash
# Multi-Binary CIS macOS Level 1 Hardening Bundle Build Script
# 5 validators, 22 controls — macOS (darwin/arm64)
#
# CRITICAL BUILD SEQUENCE:
# 1. Build unsigned validator binaries (each from multiple .go files)
# 2. Ad-hoc sign validator binaries (BEFORE embedding)
# 3. Verify signatures
# 4. Build main orchestrator (embeds SIGNED validator binaries via //go:embed)
# 5. Ad-hoc sign orchestrator
# 6. Cleanup temporary validator binaries
# 7. Calculate hashes
#
# Usage: ./build_all.sh [--es <profile>]
# Output: build/<uuid>/<uuid>

set -e  # Exit on any error
set -u  # Exit on undefined variable

# ==============================================================================
# CONFIGURATION
# ==============================================================================

TEST_UUID="6d63934b-963f-4e3b-83f5-8166e33eb6da"

# Validator definitions: "name:checks_file"
# Each validator is built from: validator_<name>.go + <checks_file>.go + check_utils.go + validator_output.go
declare -a VALIDATORS=(
    "sysprefs:checks_sysprefs"
    "auditlog:checks_auditlog"
    "network:checks_network"
    "accessctl:checks_accessctl"
    "eprotect:checks_eprotect"
)

# ==============================================================================
# DO NOT EDIT BELOW THIS LINE
# ==============================================================================

# Parse command-line arguments
ES_PROFILE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --es)
            ES_PROFILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--es <profile>]"
            echo ""
            echo "Options:"
            echo "  --es <prof>   Elasticsearch profile for direct result export"
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

# Source helpers if available
if [ -n "$PROJECT_ROOT" ] && [ -f "${PROJECT_ROOT}/utils/resolve_es.sh" ]; then
    source "${PROJECT_ROOT}/utils/resolve_es.sh"
fi

# Build configuration — macOS arm64 (Apple Silicon)
GOOS="${GOOS:-darwin}"
GOARCH="${GOARCH:-arm64}"
export CGO_ENABLED="${CGO_ENABLED:-0}"

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
    local binary_name=$(basename "$binary")

    if command -v codesign &> /dev/null; then
        codesign -s - --force "$binary" 2>/dev/null
        echo "    Ad-hoc signed: ${binary_name}"
    else
        print_warning "codesign not available — skipping signing for ${binary_name}"
    fi
}

# ==============================================================================
# Elasticsearch Config Generation
# ==============================================================================

generate_es_config() {
    local config_file="${TEST_DIR}/es_config.go"

    if [ -z "$ES_PROFILE" ]; then
        if [ -f "${config_file}" ]; then
            echo "  ES export: DISABLED (using existing es_config.go)"
            return
        fi
        cat > "${config_file}" << 'ESEOF'
//go:build darwin
// +build darwin

package main

const ES_ENABLED = false
const ES_ENDPOINT = ""
const ES_INDEX = ""
const ES_APIKEY = ""
ESEOF
        echo "  ES export: DISABLED"
    else
        if ! command -v resolve_es_to_endpoint &> /dev/null; then
            print_error "ES registry helper not available"
            exit 1
        fi
        local es_endpoint es_index es_apikey
        es_endpoint=$(resolve_es_to_endpoint "$ES_PROFILE")
        es_index=$(resolve_es_to_index "$ES_PROFILE")
        es_apikey=$(resolve_es_to_apikey "$ES_PROFILE")

        cat > "${config_file}" << ESEOF
//go:build darwin
// +build darwin

package main

const ES_ENABLED = true
const ES_ENDPOINT = "${es_endpoint}"
const ES_INDEX = "${es_index}"
const ES_APIKEY = "${es_apikey}"
ESEOF
        echo "  ES export: ENABLED (profile: ${ES_PROFILE})"
    fi
}

# ==============================================================================
# Build Process
# ==============================================================================

print_header "Multi-Binary Bundle Build: ${TEST_UUID}"
echo "  Platform: ${GOOS}/${GOARCH}"
echo "  Target:   macOS (CIS Level 1)"

# Step 0: Validate environment
print_step "0/7" "Validating environment..."

if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

generate_es_config
print_success "Environment validated"

# Change to test directory
cd "${TEST_DIR}"

# Ensure go modules are ready
go mod download 2>/dev/null || true
go mod tidy 2>/dev/null || true

# Step 1: Build unsigned validator binaries
print_step "1/7" "Building ${#VALIDATORS[@]} unsigned validator binaries..."

validator_count=0
for vdef in "${VALIDATORS[@]}"; do
    IFS=':' read -r vname checks_file <<< "$vdef"
    output_binary="validator-${vname}"
    validator_go="validator_${vname}.go"
    checks_go="${checks_file}.go"

    echo "  Building ${output_binary}..."
    GOOS=${GOOS} GOARCH=${GOARCH} go build \
        -o "${output_binary}" \
        "${validator_go}" "${checks_go}" check_utils.go validator_output.go

    if [ ! -f "${output_binary}" ]; then
        print_error "Failed to build ${output_binary}"
        exit 1
    fi

    validator_count=$((validator_count + 1))
done
print_success "Built ${validator_count} unsigned validator binaries"

# Step 2: Sign validator binaries (ad-hoc signing for macOS)
print_step "2/7" "Ad-hoc signing validator binaries..."

for vdef in "${VALIDATORS[@]}"; do
    IFS=':' read -r vname _ <<< "$vdef"
    sign_binary "validator-${vname}"
done
print_success "Validator signing complete"

# Step 3: Verify signatures
print_step "3/7" "Verifying validator signatures..."
if command -v codesign &> /dev/null; then
    for vdef in "${VALIDATORS[@]}"; do
        IFS=':' read -r vname _ <<< "$vdef"
        binary="validator-${vname}"
        if codesign -v "${binary}" 2>/dev/null; then
            echo "    Verified: ${binary}"
        else
            print_warning "Signature verification failed for ${binary}"
        fi
    done
    print_success "Signature verification complete"
else
    echo "  Skipped (codesign not available on this platform)"
fi

# Step 4: Build main orchestrator (embeds SIGNED validator binaries)
print_step "4/7" "Building orchestrator (embedding signed validators)..."

mkdir -p "${BUILD_DIR}"
main_binary="${BUILD_DIR}/${TEST_UUID}"

GOOS=${GOOS} GOARCH=${GOARCH} go build \
    -o "${main_binary}" \
    "${TEST_UUID}.go" orchestrator_utils.go test_logger.go test_logger_darwin.go org_resolver.go es_config.go

if [ ! -f "${main_binary}" ]; then
    print_error "Failed to build orchestrator"
    exit 1
fi

main_size=$(ls -lh "${main_binary}" | awk '{print $5}')
print_success "Orchestrator built (${main_size})"

# Step 5: Sign orchestrator
print_step "5/7" "Ad-hoc signing orchestrator..."
sign_binary "${main_binary}"
print_success "Orchestrator signing complete"

# Step 6: Cleanup temporary validator binaries from source dir
print_step "6/7" "Cleaning up temporary validator binaries..."
for vdef in "${VALIDATORS[@]}"; do
    IFS=':' read -r vname _ <<< "$vdef"
    rm -f "validator-${vname}"
done
print_success "Cleanup complete"

# Step 7: Calculate hashes
print_step "7/7" "Calculating hashes..."
if command -v shasum &> /dev/null; then
    main_hash=$(shasum -a 1 "${main_binary}" | awk '{print $1}')
elif command -v sha1sum &> /dev/null; then
    main_hash=$(sha1sum "${main_binary}" | awk '{print $1}')
else
    main_hash="(hash utility not available)"
fi
main_size_final=$(ls -lh "${main_binary}" | awk '{print $5}')

print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Validators Built: ${validator_count}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}"
echo "  Binary Size:      ${main_size_final}"
echo "  SHA1 Hash:        ${main_hash}"
echo "  Platform:         ${GOOS}/${GOARCH}"
echo ""
echo "Validators:"
for vdef in "${VALIDATORS[@]}"; do
    IFS=':' read -r vname checks_file <<< "$vdef"
    echo "  - validator-${vname} (${checks_file}.go)"
done
echo ""
echo "Deployment:"
echo "  scp ${BUILD_DIR}/${TEST_UUID} mac:/opt/f0/"
echo "  ssh mac 'xattr -cr /opt/f0/${TEST_UUID} && sudo /opt/f0/${TEST_UUID}'"
echo ""
print_success "Multi-binary macOS bundle ready for deployment!"
