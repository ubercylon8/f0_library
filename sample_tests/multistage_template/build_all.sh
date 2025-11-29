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
# Usage: ./build_all.sh [--org <org-identifier>] [--es <profile>]
# Output: build/<uuid>/<uuid>.exe (single deployable binary)
#
# Optional --org parameter:
#   --org sb             Dual-sign with SB cert + F0RT1KA (legacy short name)
#   --org 09b59276-...   Dual-sign with UUID (recommended for new tests)
#   (none)               F0RT1KA-only signing
#
# Optional --es parameter:
#   --es prod            Enable direct ES export with production profile
#   --es lab             Enable direct ES export with lab profile
#   (none)               ES export disabled (backward compatible)

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

# Parse command-line arguments
ORG_CERT=""
ES_PROFILE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --org)
            ORG_CERT="$2"
            shift 2
            ;;
        --es)
            ES_PROFILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--org <org-identifier>] [--es <profile>]"
            echo ""
            echo "Options:"
            echo "  --org <id>    Organization for dual signing (UUID or short name)"
            echo "                Examples: sb, 09b59276-9efb-4d3d-bbdd-4b4663ef0c42"
            echo "  --es <prof>   Elasticsearch profile for direct result export"
            echo "                Examples: prod, lab"
            echo "                If not specified, ES export is disabled"
            echo "  -h, --help    Show this help message"
            echo ""
            echo "If --org is not specified, uses F0RT1KA-only signing"
            echo "If --es is not specified, ES export is disabled (backward compatible)"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1"
            echo "Usage: $0 [--org <org-identifier>] [--es <profile>]"
            exit 1
            ;;
    esac
done

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

# Source organization registry helper
if [ -f "${PROJECT_ROOT}/utils/resolve_org.sh" ]; then
    source "${PROJECT_ROOT}/utils/resolve_org.sh"
fi

# Source Elasticsearch registry helper
if [ -f "${PROJECT_ROOT}/utils/resolve_es.sh" ]; then
    source "${PROJECT_ROOT}/utils/resolve_es.sh"
fi

# Determine signing mode and resolve certificates
if [ -z "$ORG_CERT" ]; then
    # F0RT1KA-only signing
    SIGNING_MODE="single"
    PRIMARY_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
    PRIMARY_PASSWORD_FILE="${PROJECT_ROOT}/signing-certs/.F0RT1KA.pfx.txt"
else
    # Dual signing: org cert + F0RT1KA
    SIGNING_MODE="dual"

    # Resolve organization to certificate file
    if command -v resolve_org_to_cert &> /dev/null; then
        CERT_FILE=$(resolve_org_to_cert "$ORG_CERT")
        if [ $? -ne 0 ] || [ -z "$CERT_FILE" ]; then
            print_error "Could not resolve organization '$ORG_CERT' to certificate"
            exit 1
        fi
        ORG_CERT_FILE="${PROJECT_ROOT}/signing-certs/${CERT_FILE}"
        ORG_PASSWORD_FILE="${PROJECT_ROOT}/signing-certs/.${CERT_FILE}.txt"
    else
        print_warning "Registry helper not available, using legacy certificate lookup"
        # Fallback: try to find cert by pattern matching
        ORG_CERT_FILE=$(find "${PROJECT_ROOT}/signing-certs" -name "*.pfx" | grep -i "$ORG_CERT" | head -1)
        if [ -z "$ORG_CERT_FILE" ]; then
            print_error "Could not find certificate for organization: $ORG_CERT"
            exit 1
        fi
        ORG_PASSWORD_FILE=$(find "${PROJECT_ROOT}/signing-certs" -name ".*" -type f | grep -i "$ORG_CERT" | head -1)
    fi

    # F0RT1KA certificate (secondary/nested)
    SECONDARY_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
    SECONDARY_PASSWORD_FILE="${PROJECT_ROOT}/signing-certs/.F0RT1KA.pfx.txt"
fi

# Build configuration
GOOS="windows"
GOARCH="amd64"

# ==============================================================================
# Elasticsearch Export Configuration
# ==============================================================================

# Generate es_config.go based on --es flag
generate_es_config() {
    local config_file="${TEST_DIR}/es_config.go"

    if [ -z "$ES_PROFILE" ]; then
        # ES export disabled - generate disabled config
        cat > "${config_file}" << 'EOF'
// es_config.go - Elasticsearch Export Configuration (DISABLED)
// Generated by build_all.sh - DO NOT EDIT MANUALLY

//go:build windows
// +build windows

package main

const ES_ENABLED = false
const ES_ENDPOINT = ""
const ES_INDEX = ""
const ES_APIKEY = ""
EOF
        echo "  ES export: DISABLED (no --es flag)"
    else
        # ES export enabled - resolve profile and generate config
        if ! command -v resolve_es_to_endpoint &> /dev/null; then
            print_error "ES registry helper not available"
            exit 1
        fi

        # Resolve ES profile
        local es_endpoint=$(resolve_es_to_endpoint "$ES_PROFILE")
        if [ $? -ne 0 ] || [ -z "$es_endpoint" ]; then
            print_error "Could not resolve ES profile '$ES_PROFILE'"
            list_es_profiles
            exit 1
        fi

        local es_index=$(resolve_es_to_index "$ES_PROFILE")
        local es_apikey=$(resolve_es_to_apikey "$ES_PROFILE")
        local es_fullname=$(resolve_es_to_fullname "$ES_PROFILE")

        if [ -z "$es_apikey" ]; then
            local apikey_envvar=$(resolve_es_to_apikey_envvar "$ES_PROFILE")
            print_error "ES API key not set. Please set: export ${apikey_envvar}='your-api-key'"
            exit 1
        fi

        # Generate enabled config
        cat > "${config_file}" << EOF
// es_config.go - Elasticsearch Export Configuration (ENABLED)
// Generated by build_all.sh - DO NOT EDIT MANUALLY
// Profile: ${ES_PROFILE} (${es_fullname})

//go:build windows
// +build windows

package main

const ES_ENABLED = true
const ES_ENDPOINT = "${es_endpoint}"
const ES_INDEX = "${es_index}"
const ES_APIKEY = "${es_apikey}"
EOF
        echo "  ES export: ENABLED (profile: ${ES_PROFILE})"
        echo "  ES endpoint: ${es_endpoint}"
        echo "  ES index: ${es_index}"
    fi
}

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
    print_step "0/7" "Validating environment..."

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

    # Generate ES config (disabled or enabled based on --es flag)
    generate_es_config

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
print_step "1/7" "Building unsigned stage binaries..."
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
    GOOS=${GOOS} GOARCH=${GOARCH} go build -o "${stage_binary}" "${source_go}" test_logger.go org_resolver.go es_config.go

    if [ ! -f "${stage_binary}" ]; then
        print_error "Failed to build ${stage_binary}"
        exit 1
    fi

    stage_count=$((stage_count + 1))
done
print_success "Built ${stage_count} unsigned stage binaries"

# Step 2: Sign stage binaries (CRITICAL - before embedding)
if [ "$SIGNING_MODE" = "dual" ]; then
    print_step "2/7" "Dual-signing stage binaries (org + F0RT1KA)..."
    for stage_def in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage_def"
        stage_binary="${TEST_UUID}-${technique}.exe"

        echo "  Dual-signing ${stage_binary}..."
        "${PROJECT_ROOT}/utils/codesign" sign-nested "${stage_binary}" "${ORG_CERT_FILE}" "${SECONDARY_CERT}"

        if [ $? -ne 0 ]; then
            print_error "Failed to dual-sign ${stage_binary}"
            exit 1
        fi
    done
    print_success "Dual-signed ${stage_count} stage binaries"
else
    print_step "2/7" "Signing stage binaries (F0RT1KA)..."
    PRIMARY_PASSWORD=$(cat "${PRIMARY_PASSWORD_FILE}" | tr -d '\n\r')

    for stage_def in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage_def"
        stage_binary="${TEST_UUID}-${technique}.exe"

        echo "  Signing ${stage_binary}..."
        "${PROJECT_ROOT}/utils/codesign" --cert "${PRIMARY_CERT}" --password "${PRIMARY_PASSWORD}" sign "${stage_binary}"

        if [ $? -ne 0 ]; then
            print_error "Failed to sign ${stage_binary}"
            exit 1
        fi
    done
    print_success "Signed ${stage_count} stage binaries"
fi

# Step 3: Verify signatures (self-signed certs will show warnings but are cryptographically valid)
print_step "3/7" "Verifying stage signatures..."
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
print_step "4/7" "Building main orchestrator (embedding signed stages)..."

# Create build directory if it doesn't exist
mkdir -p "${BUILD_DIR}"

# Build main binary
main_binary="${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Building ${TEST_UUID}.exe with embedded stage binaries..."
GOOS=${GOOS} GOARCH=${GOARCH} go build -o "${main_binary}" "${TEST_UUID}.go" test_logger.go org_resolver.go es_config.go

if [ ! -f "${main_binary}" ]; then
    print_error "Failed to build main binary: ${TEST_UUID}.exe"
    exit 1
fi

# Get file size before signing
main_size_before=$(ls -lh "${main_binary}" | awk '{print $5}')
print_success "Main orchestrator built (${main_size_before})"

# Step 5: Sign main binary
cd "${PROJECT_ROOT}"

if [ "$SIGNING_MODE" = "dual" ]; then
    print_step "5/7" "Dual-signing main binary (org + F0RT1KA)..."
    "${PROJECT_ROOT}/utils/codesign" sign-nested "${BUILD_DIR}/${TEST_UUID}.exe" "${ORG_CERT_FILE}" "${SECONDARY_CERT}"

    if [ $? -ne 0 ]; then
        print_error "Failed to dual-sign main binary"
        exit 1
    fi
else
    print_step "5/7" "Signing main binary (F0RT1KA)..."
    "${PROJECT_ROOT}/utils/codesign" --cert "${PRIMARY_CERT}" --password "${PRIMARY_PASSWORD}" sign "${BUILD_DIR}/${TEST_UUID}.exe"

    if [ $? -ne 0 ]; then
        print_error "Failed to sign main binary"
        exit 1
    fi
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
print_step "6/7" "Cleaning up temporary stage binaries..."
cd "${TEST_DIR}"
for stage_def in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage_def"
    stage_binary="${TEST_UUID}-${technique}.exe"

    if [ -f "${stage_binary}" ]; then
        echo "  Removing ${stage_binary}..."
        rm -f "${stage_binary}"
    fi
done
print_success "Stage binaries cleaned up"

# Step 7: Calculate SHA1 hashes and cleanup generated config
print_step "7/7" "Calculating hashes and final cleanup..."

# Calculate SHA1 hash of final binary
main_hash=$(shasum -a 1 "${BUILD_DIR}/${TEST_UUID}.exe" | awk '{print $1}')
echo "  SHA1: ${main_hash}"

# Remove generated es_config.go (will be regenerated on next build)
if [ -f "${TEST_DIR}/es_config.go" ]; then
    echo "  Removing generated es_config.go..."
    rm -f "${TEST_DIR}/es_config.go"
fi

print_success "Final cleanup complete"

# ==============================================================================
# Build Summary
# ==============================================================================

print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Stages Built:     ${stage_count}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Binary Size:      ${main_size_after}"
echo "  SHA1 Hash:        ${main_hash}"
if [ -n "$ES_PROFILE" ]; then
echo "  ES Export:        ENABLED (profile: ${ES_PROFILE})"
else
echo "  ES Export:        DISABLED"
fi
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
if [ -n "$ES_PROFILE" ]; then
echo "  4. Results will be exported directly to Elasticsearch"
fi
echo ""
