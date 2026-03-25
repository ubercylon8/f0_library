#!/bin/bash
# Multi-Binary Cyber-Hygiene Bundle Build Script
# Baseline (Windows Defender Edition) — 10 validators
#
# CRITICAL BUILD SEQUENCE:
# 1. Build unsigned validator binaries (each from multiple .go files)
# 2. Sign validator binaries (BEFORE embedding)
# 3. Verify signatures
# 4. Build main orchestrator (embeds SIGNED validator binaries via //go:embed)
# 5. Sign orchestrator
# 6. Cleanup temporary validator binaries
# 7. Calculate hashes
#
# Usage: ./build_all.sh [--es <profile>]
# Output: build/<uuid>/<uuid>.exe

set -e  # Exit on any error
set -u  # Exit on undefined variable

# ==============================================================================
# CONFIGURATION
# ==============================================================================

TEST_UUID="a3c923ae-1a46-4b1f-b696-be6c2731a628"

# Validator definitions: "name:checks_file"
# Each validator is built from: validator_<name>.go + <checks_file>.go + check_utils.go + validator_output.go
declare -a VALIDATORS=(
    "defender:checks_defender"
    "lsass:checks_lsass"
    "asr:checks_asr"
    "smb:checks_smb"
    "powershell:checks_powershell"
    "network:checks_network"
    "audit:checks_audit"
    "lockout:checks_lockout"
    "laps:checks_laps"
    "printspooler:checks_printspooler"
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
# Detect if running inside f0_library or standalone
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

# Build configuration — inherit from environment or default to windows/amd64
GOOS="${GOOS:-windows}"
GOARCH="${GOARCH:-amd64}"
export CGO_ENABLED="${CGO_ENABLED:-0}"

# ==============================================================================
# Signing Configuration
# ==============================================================================

# Detect signing certificate (three modes):
# 1. ProjectAchilles build service: F0_SIGN_CERT_PATH + F0_SIGN_CERT_PASS_FILE env vars
# 2. Local f0_library certs: signing-certs/F0RT1KA.pfx
# 3. No cert: validators will be unsigned (warning)

SIGN_MODE="none"
SIGN_CERT=""
SIGN_PASS_FILE=""

if [ -n "${F0_SIGN_CERT_PATH:-}" ]; then
    SIGN_MODE="projectachilles"
    SIGN_CERT="${F0_SIGN_CERT_PATH}"
    SIGN_PASS_FILE="${F0_SIGN_CERT_PASS_FILE:-}"
elif [ -n "$PROJECT_ROOT" ] && [ -f "${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx" ]; then
    SIGN_MODE="f0library"
    SIGN_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
    SIGN_PASS_FILE="${PROJECT_ROOT}/signing-certs/.F0RT1KA.pfx.txt"
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
    local binary_name=$(basename "$binary")

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
# Elasticsearch Config Generation
# ==============================================================================

generate_es_config() {
    local config_file="${TEST_DIR}/es_config.go"

    if [ -z "$ES_PROFILE" ]; then
        # Use existing default es_config.go if present, otherwise generate disabled
        if [ -f "${config_file}" ]; then
            echo "  ES export: DISABLED (using existing es_config.go)"
            return
        fi
        cat > "${config_file}" << 'ESEOF'
//go:build windows
// +build windows

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
//go:build windows
// +build windows

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
echo "  Signing:  ${SIGN_MODE}"

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

# Step 1: Build unsigned validator binaries
print_step "1/7" "Building ${#VALIDATORS[@]} unsigned validator binaries..."

validator_count=0
for vdef in "${VALIDATORS[@]}"; do
    IFS=':' read -r vname checks_file <<< "$vdef"
    output_binary="validator-${vname}.exe"
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

# Step 2: Sign validator binaries (CRITICAL — before embedding)
print_step "2/7" "Signing validator binaries..."

if [ "$SIGN_MODE" = "none" ]; then
    print_warning "No signing certificate found — validators will be unsigned"
else
    for vdef in "${VALIDATORS[@]}"; do
        IFS=':' read -r vname _ <<< "$vdef"
        sign_binary "validator-${vname}.exe"
    done
    print_success "Validator signing complete"
fi

# Step 3: Verify signatures
print_step "3/7" "Verifying validator signatures..."
if [ "$SIGN_MODE" != "none" ] && command -v osslsigncode &> /dev/null; then
    for vdef in "${VALIDATORS[@]}"; do
        IFS=':' read -r vname _ <<< "$vdef"
        binary="validator-${vname}.exe"
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

# Step 4: Build main orchestrator (embeds SIGNED validator binaries)
print_step "4/7" "Building orchestrator (embedding signed validators)..."

mkdir -p "${BUILD_DIR}"
main_binary="${BUILD_DIR}/${TEST_UUID}.exe"

GOOS=${GOOS} GOARCH=${GOARCH} go build \
    -o "${main_binary}" \
    "${TEST_UUID}.go" orchestrator_utils.go test_logger.go test_logger_windows.go org_resolver.go es_config.go

if [ ! -f "${main_binary}" ]; then
    print_error "Failed to build orchestrator"
    exit 1
fi

main_size=$(ls -lh "${main_binary}" | awk '{print $5}')
print_success "Orchestrator built (${main_size})"

# Step 5: Sign orchestrator
print_step "5/7" "Signing orchestrator..."
if [ "$SIGN_MODE" != "none" ]; then
    sign_binary "${main_binary}"
    print_success "Orchestrator signing complete"
else
    print_warning "Skipping orchestrator signing (no certificate)"
fi

# Step 6: Cleanup temporary validator binaries from source dir
print_step "6/7" "Cleaning up temporary validator binaries..."
for vdef in "${VALIDATORS[@]}"; do
    IFS=':' read -r vname _ <<< "$vdef"
    rm -f "validator-${vname}.exe"
done
print_success "Cleanup complete"

# Step 7: Calculate hashes
print_step "7/7" "Calculating hashes..."
main_hash=$(sha1sum "${main_binary}" | awk '{print $1}')
main_size_final=$(ls -lh "${main_binary}" | awk '{print $5}')

print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Validators Built: ${validator_count}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Binary Size:      ${main_size_final}"
echo "  SHA1 Hash:        ${main_hash}"
echo "  Signing Mode:     ${SIGN_MODE}"
echo ""
echo "Validators:"
for vdef in "${VALIDATORS[@]}"; do
    IFS=':' read -r vname checks_file <<< "$vdef"
    echo "  - validator-${vname} (${checks_file}.go)"
done
echo ""
print_success "Multi-binary bundle ready for deployment!"
