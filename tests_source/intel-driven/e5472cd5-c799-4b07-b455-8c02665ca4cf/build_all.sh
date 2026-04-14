#!/bin/bash
# Multi-Stage Intel-Driven Test Build Script (v2)
# HONESTCUE LLM-Assisted Runtime C# Compilation — 3 stages
#
# v2 CHANGES:
#   - Stage 2 is now a native .NET 8 self-contained exe (dotnet publish),
#     not a Go binary. See stage-T1027.004-csharp/ project.
#   - Stages 1 & 3 remain Go binaries.
#
# CRITICAL BUILD SEQUENCE:
# 1. Build unsigned stage binaries
#    1a. Go stages (T1071.001, T1105)
#    1b. C# stage 2 (T1027.004) via dotnet publish
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
#
# Prerequisites:
#   - Go 1.21+
#   - .NET 8 SDK (dotnet-sdk-8.0) — required to build stage 2
#   - osslsigncode (for signing)
#   - gzip
#
# The build will auto-detect an installed .NET 8 SDK in:
#   - $PATH (system-installed via pacman/apt)
#   - $HOME/.dotnet (userland via dotnet-install.sh)
#   - /usr/share/dotnet (Arch pacman default)

set -e
set -u

# ==============================================================================
# CONFIGURATION
# ==============================================================================

TEST_UUID="e5472cd5-c799-4b07-b455-8c02665ca4cf"

# Go stages: "TECHNIQUE:SOURCE_FILE"
declare -a GO_STAGES=(
    "T1071.001:stage-T1071.001"
    "T1105:stage-T1105"
)

# C# stage 2: dotnet publish
CSHARP_STAGE_TECHNIQUE="T1027.004"
CSHARP_STAGE_PROJECT_DIR="stage-T1027.004-csharp"
CSHARP_STAGE_PROJECT="HonestcueStage2.csproj"
CSHARP_STAGE_PUBLISHED_NAME="stage-T1027.004.exe"

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

# .NET SDK auto-detection
DOTNET_BIN=""
if command -v dotnet &> /dev/null; then
    if dotnet --list-sdks 2>/dev/null | grep -q '^8\.'; then
        DOTNET_BIN="dotnet"
    fi
fi
if [ -z "$DOTNET_BIN" ] && [ -x "$HOME/.dotnet/dotnet" ]; then
    if "$HOME/.dotnet/dotnet" --list-sdks 2>/dev/null | grep -q '^8\.'; then
        DOTNET_BIN="$HOME/.dotnet/dotnet"
        export DOTNET_ROOT="$HOME/.dotnet"
    fi
fi
if [ -z "$DOTNET_BIN" ] && [ -x "/usr/share/dotnet/dotnet" ]; then
    if /usr/share/dotnet/dotnet --list-sdks 2>/dev/null | grep -q '^8\.'; then
        DOTNET_BIN="/usr/share/dotnet/dotnet"
        export DOTNET_ROOT="/usr/share/dotnet"
    fi
fi

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

print_header "Multi-Stage Test Build: HONESTCUE v2 — GitHub-Raw + Roslyn"
echo "  Test UUID:  ${TEST_UUID}"
echo "  Platform:   ${GOOS}/${GOARCH}"
echo "  Signing:    ${SIGN_MODE}"
echo "  Go stages:  ${#GO_STAGES[@]}"
echo "  C# stage:   1 (T1027.004)"
echo "  dotnet:     ${DOTNET_BIN:-NOT-FOUND}"

# Step 0: Validate environment
print_step "0/8" "Validating environment..."

if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

if [ -z "$DOTNET_BIN" ]; then
    print_error ".NET 8 SDK is required to build stage 2 (T1027.004). None found."
    echo ""
    echo "Install one of:"
    echo "  sudo pacman -S dotnet-sdk-8.0           # Arch Linux"
    echo "  sudo apt install dotnet-sdk-8.0         # Debian/Ubuntu"
    echo "  https://dot.net/v1/dotnet-install.sh    # userland install"
    exit 1
fi

cd "${TEST_DIR}"
go mod download 2>/dev/null || true
print_success "Environment validated"

# Step 1: Build unsigned stage binaries
print_step "1/8" "Building stage binaries..."

total_stages=0

# 1a: Go stages
for stage in "${GO_STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    output_name="${TEST_UUID}-${technique}.exe"

    echo "  [Go] Building ${technique} (${source}.go)..."
    GOOS=${GOOS} GOARCH=${GOARCH} go build \
        -o "${output_name}" \
        "${source}.go" test_logger.go test_logger_windows.go org_resolver.go

    if [ ! -f "${output_name}" ]; then
        print_error "Failed to build ${output_name}"
        exit 1
    fi

    total_stages=$((total_stages + 1))
done

# 1b: C# stage 2
echo "  [C#] Building ${CSHARP_STAGE_TECHNIQUE} (${CSHARP_STAGE_PROJECT_DIR})..."
pushd "${CSHARP_STAGE_PROJECT_DIR}" > /dev/null
# Restore first (quiet), then publish
"${DOTNET_BIN}" restore "${CSHARP_STAGE_PROJECT}" --verbosity quiet
"${DOTNET_BIN}" publish "${CSHARP_STAGE_PROJECT}" \
    -c Release \
    -r win-x64 \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -o "./publish" \
    --verbosity quiet

if [ ! -f "./publish/${CSHARP_STAGE_PUBLISHED_NAME}" ]; then
    print_error "dotnet publish did not produce ./publish/${CSHARP_STAGE_PUBLISHED_NAME}"
    popd > /dev/null
    exit 1
fi

# Move the published exe to the TEST_DIR with the expected naming scheme
popd > /dev/null
mv "${CSHARP_STAGE_PROJECT_DIR}/publish/${CSHARP_STAGE_PUBLISHED_NAME}" \
   "${TEST_UUID}-${CSHARP_STAGE_TECHNIQUE}.exe"
total_stages=$((total_stages + 1))

print_success "Built ${total_stages} unsigned stage binaries (Go + C#)"

# Step 2: Sign stage binaries (CRITICAL — before embedding!)
print_step "2/8" "Signing stage binaries..."
if [ "$SIGN_MODE" = "none" ]; then
    print_warning "No signing certificate found — stages will be unsigned"
else
    for stage in "${GO_STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        sign_binary "${TEST_UUID}-${technique}.exe"
    done
    sign_binary "${TEST_UUID}-${CSHARP_STAGE_TECHNIQUE}.exe"
    print_success "Stage signing complete"
fi

# Step 3: Verify signatures
print_step "3/8" "Verifying stage signatures..."
if [ "$SIGN_MODE" != "none" ] && command -v osslsigncode &> /dev/null; then
    verify_one() {
        local binary="$1"
        if osslsigncode verify "${binary}" 2>&1 | grep -q "Message digest"; then
            echo "    Verified: ${binary}"
        else
            print_warning "Could not verify signature for ${binary}"
        fi
    }
    for stage in "${GO_STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        verify_one "${TEST_UUID}-${technique}.exe"
    done
    verify_one "${TEST_UUID}-${CSHARP_STAGE_TECHNIQUE}.exe"
    print_success "Signature verification complete"
else
    echo "  Skipped (no signing or osslsigncode not installed)"
fi

# Step 4: Compress signed binaries with gzip (MANDATORY per CLAUDE.md)
print_step "4/8" "Compressing signed binaries with gzip..."
compress_one() {
    local binary="$1"
    local orig_size gz_size
    orig_size=$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary" 2>/dev/null)
    gzip -9 -k -f "$binary"
    gz_size=$(stat -c%s "${binary}.gz" 2>/dev/null || stat -f%z "${binary}.gz" 2>/dev/null)
    echo "    ${binary}: $(numfmt --to=iec ${orig_size} 2>/dev/null || echo ${orig_size}B) -> $(numfmt --to=iec ${gz_size} 2>/dev/null || echo ${gz_size}B)"
}
for stage in "${GO_STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    compress_one "${TEST_UUID}-${technique}.exe"
done
compress_one "${TEST_UUID}-${CSHARP_STAGE_TECHNIQUE}.exe"
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
for stage in "${GO_STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    rm -f "${TEST_UUID}-${technique}.exe" "${TEST_UUID}-${technique}.exe.gz"
done
rm -f "${TEST_UUID}-${CSHARP_STAGE_TECHNIQUE}.exe" "${TEST_UUID}-${CSHARP_STAGE_TECHNIQUE}.exe.gz"

# Clean up dotnet publish + obj directories
rm -rf "${CSHARP_STAGE_PROJECT_DIR}/publish" \
       "${CSHARP_STAGE_PROJECT_DIR}/bin" \
       "${CSHARP_STAGE_PROJECT_DIR}/obj"

# Step 8: Summary
print_step "8/8" "Build summary"
print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Test Name:        HONESTCUE v2 — LLM-Assisted Runtime C# Compilation"
echo "  Stages Built:     ${total_stages}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Binary Size:      ${main_size_final}"
echo "  SHA1 Hash:        ${main_hash}"
echo "  Signing Mode:     ${SIGN_MODE}"
echo ""
echo "Stages:"
for stage in "${GO_STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    echo "  - ${TEST_UUID}-${technique}.exe    (Go: ${source}.go)"
done
echo "  - ${TEST_UUID}-${CSHARP_STAGE_TECHNIQUE}.exe    (C#: ${CSHARP_STAGE_PROJECT_DIR}/)"
echo ""
print_success "Multi-stage test ready for deployment!"
