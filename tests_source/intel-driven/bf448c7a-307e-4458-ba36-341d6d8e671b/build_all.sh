#!/bin/bash
# Multi-Stage Intel-Driven Test Build Script
# TclBanker Brazilian Banking Trojan Full Killchain — 6 stages + sideload host EXE
#
# CRITICAL BUILD SEQUENCE:
# 0. Validate environment
# 1. Build sideload host EXE (LogiAiPromptBuilder.exe) for stage 2 embed
# 2. Sign sideload host EXE, then gzip-compress and stage into stage 2 dir
# 3. Build unsigned stage binaries
# 4. Sign stage binaries (BEFORE embedding)
# 5. Verify signatures + gzip-compress signed stages
# 6. Build main orchestrator (embeds SIGNED+COMPRESSED stages)
# 7. Sign orchestrator
# 8. Cleanup + SHA1 hash + size-tier check
#
# Usage: ./build_all.sh [--org <org-identifier>]
# Output: build/<uuid>/<uuid>.exe

set -e
set -u

# ==============================================================================
# CONFIGURATION
# ==============================================================================

TEST_UUID="bf448c7a-307e-4458-ba36-341d6d8e671b"

# Stage definitions: "TECHNIQUE:SOURCE_FILE"
declare -a STAGES=(
    "T1218.007:stage-T1218.007"
    "T1574.002:stage-T1574.002"
    "T1140:stage-T1140"
    "T1053.005:stage-T1053.005"
    "T1056.003:stage-T1056.003"
    "T1071.001:stage-T1071.001"
)

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Test path is tests_source/intel-driven/<uuid>/ — project root is 3 levels up.
# The reference script uses ../../utils to *check* for utils, then ../.. to *set*
# PROJECT_ROOT, which works because intel-driven/<uuid>/ has 3 levels above f0_library.
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

print_header "Multi-Stage Test Build: TclBanker Brazilian Banking Trojan"
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

# Step 1: Build sideload host EXE (LogiAiPromptBuilder.exe) for stage 2 embed
# This is a separate small Go binary that calls LoadLibrary on the renamed
# Microsoft DLL — the load-bearing real-LoadLibrary lift for stage 2.
print_step "1/8" "Building sideload host EXE (LogiAiPromptBuilder.exe)..."

cd "${TEST_DIR}/sideload_host"
# Ensure standalone go.mod so it builds without dragging in the parent module's deps
if [ ! -f "go.mod" ]; then
    cat > go.mod <<EOF
module logiaipromptbuilder

go 1.21
EOF
fi
GOOS=${GOOS} GOARCH=${GOARCH} go build -o LogiAiPromptBuilder.exe -ldflags="-s -w" main.go
if [ ! -f "LogiAiPromptBuilder.exe" ]; then
    print_error "Failed to build LogiAiPromptBuilder.exe"
    exit 1
fi
host_size=$(stat -c%s LogiAiPromptBuilder.exe 2>/dev/null || stat -f%z LogiAiPromptBuilder.exe 2>/dev/null)
echo "    LogiAiPromptBuilder.exe built ($(numfmt --to=iec ${host_size} 2>/dev/null || echo ${host_size}B))"

# Sign + gzip the host EXE, then stage into the test dir for the stage 2 embed
sign_binary "LogiAiPromptBuilder.exe"
gzip -9 -k LogiAiPromptBuilder.exe
mv LogiAiPromptBuilder.exe.gz "${TEST_DIR}/LogiAiPromptBuilder.exe.gz"
rm -f LogiAiPromptBuilder.exe
cd "${TEST_DIR}"
print_success "Sideload host EXE built, signed, compressed, and staged for stage 2 embed"

# Step 2: Build unsigned stage binaries
print_step "2/8" "Building ${#STAGES[@]} unsigned stage binaries..."

stage_count=0
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    output_name="${TEST_UUID}-${technique}.exe"

    echo "  Building ${technique} (${source}.go)..."
    GOOS=${GOOS} GOARCH=${GOARCH} go build \
        -o "${output_name}" \
        -ldflags="-s -w" \
        "${source}.go" test_logger.go test_logger_windows.go org_resolver.go

    if [ ! -f "${output_name}" ]; then
        print_error "Failed to build ${output_name}"
        exit 1
    fi

    stage_count=$((stage_count + 1))
done
print_success "Built ${stage_count} unsigned stage binaries"

# Step 3: Sign stage binaries (CRITICAL — before embedding!)
print_step "3/8" "Signing stage binaries..."
if [ "$SIGN_MODE" = "none" ]; then
    print_warning "No signing certificate found — stages will be unsigned"
else
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        sign_binary "${TEST_UUID}-${technique}.exe"
    done
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
    print_success "Signature verification complete"
else
    echo "  Skipped (no signing or osslsigncode not installed)"
fi

# Step 5: Compress signed binaries with gzip (reduces orchestrator ~35%)
print_step "5/8" "Compressing signed binaries with gzip..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    binary="${TEST_UUID}-${technique}.exe"
    orig_size=$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary" 2>/dev/null)
    gzip -9 -k "$binary"
    gz_size=$(stat -c%s "${binary}.gz" 2>/dev/null || stat -f%z "${binary}.gz" 2>/dev/null)
    echo "    ${binary}: $(numfmt --to=iec ${orig_size} 2>/dev/null || echo ${orig_size}B) -> $(numfmt --to=iec ${gz_size} 2>/dev/null || echo ${gz_size}B)"
done
print_success "Compression complete"

# Step 6: Build main orchestrator (embeds SIGNED+COMPRESSED stage binaries)
print_step "6/8" "Building orchestrator (embedding compressed stages)..."

mkdir -p "${BUILD_DIR}"
main_binary="${BUILD_DIR}/${TEST_UUID}.exe"

GOOS=${GOOS} GOARCH=${GOARCH} go build \
    -o "${main_binary}" \
    -ldflags="-s -w" \
    "${TEST_UUID}.go" test_logger.go test_logger_windows.go org_resolver.go

if [ ! -f "${main_binary}" ]; then
    print_error "Failed to build orchestrator"
    exit 1
fi

main_size_bytes=$(stat -c%s "${main_binary}" 2>/dev/null || stat -f%z "${main_binary}" 2>/dev/null)
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

# Step 8: Cleanup + SHA1 hash + size-tier check
print_step "8/8" "Cleaning up and calculating hashes..."

main_hash=$(sha1sum "${main_binary}" | awk '{print $1}')
main_size_final_bytes=$(stat -c%s "${main_binary}" 2>/dev/null || stat -f%z "${main_binary}" 2>/dev/null)
main_size_final=$(ls -lh "${main_binary}" | awk '{print $5}')

# Cleanup temporary stage files + sideload host gzip
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    rm -f "${TEST_UUID}-${technique}.exe" "${TEST_UUID}-${technique}.exe.gz"
done
rm -f LogiAiPromptBuilder.exe.gz

# Size tier check per CLAUDE.md Binary Size Budget
size_mb=$((main_size_final_bytes / 1024 / 1024))
tier="GREEN"
if [ $size_mb -gt 50 ]; then
    tier="FORBIDDEN"
elif [ $size_mb -gt 25 ]; then
    tier="RED"
elif [ $size_mb -gt 10 ]; then
    tier="YELLOW"
fi

print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Test Name:        TclBanker Brazilian Banking Trojan Full Killchain"
echo "  Stages Built:     ${stage_count}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}.exe"
echo "  Binary Size:      ${main_size_final} (${size_mb} MB)"
echo "  Size Tier:        ${tier}"
echo "  SHA1 Hash:        ${main_hash}"
echo "  Signing Mode:     ${SIGN_MODE}"
echo ""
echo "Stages:"
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    echo "  - ${TEST_UUID}-${technique}.exe (${source}.go)"
done
echo ""
case "$tier" in
    GREEN)    print_success "Size tier: GREEN — proceed" ;;
    YELLOW)   print_warning "Size tier: YELLOW — document in info.md" ;;
    RED)      print_error  "Size tier: RED — refactor or document justification" ;;
    FORBIDDEN) print_error "Size tier: FORBIDDEN — must refactor (>50 MB)" ; exit 1 ;;
esac

print_success "Multi-stage test ready for deployment!"
