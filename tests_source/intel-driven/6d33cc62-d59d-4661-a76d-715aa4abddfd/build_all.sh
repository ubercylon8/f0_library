#!/bin/bash
# Multi-Stage Cross-Platform Build — PII Exfiltration to External Inference Services
# 3 stages (T1552.001, T1005, T1567), Windows + Linux, gzip-embedded stages.
#
# CRITICAL BUILD SEQUENCE (per platform):
#   1. Build unsigned stage binaries
#   2. (Windows) sign stage binaries BEFORE embedding
#   3. (Windows) verify signatures
#   4. gzip-compress the (signed) stage binaries        <-- MANDATORY
#   5. Build orchestrator (embeds SIGNED+COMPRESSED stages)
#   6. (Windows) sign orchestrator
#   7. Emit final binary + SHA1 + size tier
#   8. Cleanup temporary stage binaries
#
# Linux signing is a no-op (Authenticode is Windows-only).
#
# Usage: ./build_all.sh [--org <org-identifier>] [--platform windows|linux|all]
# Output: build/<uuid>/<uuid>.exe (windows), build/<uuid>/<uuid> (linux)

set -e
set -u

# ==============================================================================
# CONFIGURATION
# ==============================================================================

TEST_UUID="6d33cc62-d59d-4661-a76d-715aa4abddfd"
TEST_NAME="PII Exfiltration to External Inference Services"

# Stage definitions: "TECHNIQUE:SOURCE_FILE"
declare -a STAGES=(
    "T1552.001:stage-T1552.001"
    "T1005:stage-T1005"
    "T1567:stage-T1567"
)

# NOTE: `go build a.go b.go ...` (explicit file list) does NOT apply //go:build
# tag filtering — it compiles exactly the files given. So the per-platform logger,
# stage-1 path helper, and orchestrator embed file are selected explicitly per GOOS
# in the build loop below (see platform_files()).

# platform_files GOOS -> sets LOGGER, PATHS, EMBED for the given platform.
platform_files() {
    case "$1" in
        windows)
            LOGGER="test_logger_windows.go"
            PATHS="stage1_paths_windows.go"
            EMBED="orchestrator_embed_windows.go" ;;
        linux)
            LOGGER="test_logger_linux.go"
            PATHS="stage1_paths_linux.go"
            EMBED="orchestrator_embed_linux.go" ;;
    esac
}

# ==============================================================================
# ARG PARSING
# ==============================================================================

ORG_CERT=""
PLATFORMS="all"
while [[ $# -gt 0 ]]; do
    case $1 in
        --org) ORG_CERT="$2"; shift 2 ;;
        --platform) PLATFORMS="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--org <org-identifier>] [--platform windows|linux|all]"
            exit 0 ;;
        *) echo "ERROR: Unknown option: $1"; exit 1 ;;
    esac
done

case "$PLATFORMS" in
    windows) TARGETS=("windows") ;;
    linux)   TARGETS=("linux") ;;
    all)     TARGETS=("windows" "linux") ;;
    *) echo "ERROR: invalid --platform: $PLATFORMS"; exit 1 ;;
esac

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# Paths
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

export CGO_ENABLED="${CGO_ENABLED:-0}"
GOARCH="${GOARCH:-amd64}"

# ==============================================================================
# Signing configuration (Windows only)
# ==============================================================================

SIGN_MODE="none"; SIGN_CERT=""; SIGN_PASS_FILE=""; F0RTIKA_CERT=""
if [ -n "${F0_SIGN_CERT_PATH:-}" ]; then
    SIGN_MODE="projectachilles"; SIGN_CERT="${F0_SIGN_CERT_PATH}"; SIGN_PASS_FILE="${F0_SIGN_CERT_PASS_FILE:-}"
elif [ -n "$PROJECT_ROOT" ]; then
    if [ -n "$ORG_CERT" ] && command -v resolve_org_to_cert &> /dev/null; then
        CERT_FILE=$(resolve_org_to_cert "$ORG_CERT") || true
        if [ -n "$CERT_FILE" ] && [ -f "${PROJECT_ROOT}/signing-certs/${CERT_FILE}" ]; then
            SIGN_MODE="f0library-org"; SIGN_CERT="${PROJECT_ROOT}/signing-certs/${CERT_FILE}"
            F0RTIKA_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
        fi
    elif [ -f "${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx" ]; then
        SIGN_MODE="f0library"; SIGN_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
        SIGN_PASS_FILE="${PROJECT_ROOT}/signing-certs/.F0RT1KA.pfx.txt"
    fi
fi

# ==============================================================================
# Helpers
# ==============================================================================

print_header()  { echo -e "${BLUE}=================================================${NC}"; echo -e "${BLUE}$1${NC}"; echo -e "${BLUE}=================================================${NC}"; }
print_step()    { echo -e "${GREEN}[$1] $2${NC}"; }
print_warning() { echo -e "${YELLOW}WARNING: $1${NC}"; }
print_error()   { echo -e "${RED}ERROR: $1${NC}"; }
print_success() { echo -e "${GREEN}$1${NC}"; }

sign_binary() {
    local binary="$1"; local binary_name; binary_name=$(basename "$binary")
    [ "$SIGN_MODE" = "none" ] && return 0
    if ! command -v osslsigncode &> /dev/null; then
        print_warning "osslsigncode not installed — skipping signing for ${binary_name}"; return 0
    fi
    local signed_binary="${binary}.signed"
    if [ "$SIGN_MODE" = "projectachilles" ]; then
        [ -z "$SIGN_PASS_FILE" ] || [ ! -f "$SIGN_PASS_FILE" ] && { print_warning "cert pass file missing — skip ${binary_name}"; return 0; }
        osslsigncode sign -pkcs12 "$SIGN_CERT" -readpass "$SIGN_PASS_FILE" -in "$binary" -out "$signed_binary" 2>/dev/null
    elif [ "$SIGN_MODE" = "f0library-org" ]; then
        if [ -n "$PROJECT_ROOT" ] && [ -f "${PROJECT_ROOT}/utils/codesign" ]; then
            "${PROJECT_ROOT}/utils/codesign" sign-nested "$binary" "$SIGN_CERT" "${F0RTIKA_CERT:-}"
            echo "    Dual-signed: ${binary_name}"; return 0
        fi
        print_warning "codesign utility not found — skipping"; return 0
    elif [ "$SIGN_MODE" = "f0library" ]; then
        [ ! -f "$SIGN_PASS_FILE" ] && { print_warning "cert pass file missing — skip ${binary_name}"; return 0; }
        local password; password=$(tr -d '\n\r' < "$SIGN_PASS_FILE")
        osslsigncode sign -pkcs12 "$SIGN_CERT" -pass "$password" -in "$binary" -out "$signed_binary" 2>/dev/null
    fi
    if [ -f "$signed_binary" ]; then mv "$signed_binary" "$binary"; echo "    Signed: ${binary_name}"; else print_warning "signing failed for ${binary_name} — continuing unsigned"; fi
}

size_tier() {
    local bytes="$1"
    if   [ "$bytes" -le 10485760 ]; then echo "GREEN (<=10MB)";
    elif [ "$bytes" -le 26214400 ]; then echo "YELLOW (10-25MB) — document in info.md";
    elif [ "$bytes" -le 52428800 ]; then echo "RED (25-50MB) — refactor required";
    else echo "FORBIDDEN (>50MB) — DO NOT SHIP"; fi
}

# ==============================================================================
# Build
# ==============================================================================

print_header "Multi-Stage Build: ${TEST_NAME}"
echo "  Test UUID:  ${TEST_UUID}"
echo "  Platforms:  ${TARGETS[*]}"
echo "  Signing:    ${SIGN_MODE}"
echo "  Stages:     ${#STAGES[@]}"

print_step "0/8" "Validating environment..."
command -v go &> /dev/null || { print_error "Go is not installed or not in PATH"; exit 1; }
cd "${TEST_DIR}"
go mod tidy 2>/dev/null || true
print_success "Environment validated"

mkdir -p "${BUILD_DIR}"

for GOOS in "${TARGETS[@]}"; do
    if [ "$GOOS" = "windows" ]; then EXT=".exe"; else EXT=""; fi
    platform_files "$GOOS"
    STAGE_SHARED="canary.go artifact_dir.go ${PATHS} test_logger.go ${LOGGER} org_resolver.go"
    ORCH_SHARED="${EMBED} artifact_dir.go test_logger.go ${LOGGER} org_resolver.go"
    print_header "Target: ${GOOS}/${GOARCH}"

    # Step 1: build unsigned stage binaries
    print_step "1/8" "Building ${#STAGES[@]} ${GOOS} stage binaries..."
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r technique source <<< "$stage"
        out="${TEST_UUID}-${technique}${EXT}"
        echo "  Building ${technique} (${source}.go)..."
        GOOS=${GOOS} GOARCH=${GOARCH} go build -trimpath -ldflags "-s -w" -o "${out}" ${source}.go ${STAGE_SHARED}
        [ -f "${out}" ] || { print_error "Failed to build ${out}"; exit 1; }
    done
    print_success "Stage binaries built"

    # Step 2: sign stage binaries (Windows only, BEFORE embedding)
    print_step "2/8" "Signing stage binaries..."
    if [ "$GOOS" = "windows" ] && [ "$SIGN_MODE" != "none" ]; then
        for stage in "${STAGES[@]}"; do
            IFS=':' read -r technique _ <<< "$stage"
            sign_binary "${TEST_UUID}-${technique}${EXT}"
        done
        print_success "Stage signing complete"
    else
        echo "  Skipped (linux target or no signing configured)"
    fi

    # Step 3: verify signatures (Windows only)
    print_step "3/8" "Verifying signatures..."
    if [ "$GOOS" = "windows" ] && [ "$SIGN_MODE" != "none" ] && command -v osslsigncode &> /dev/null; then
        for stage in "${STAGES[@]}"; do
            IFS=':' read -r technique _ <<< "$stage"
            b="${TEST_UUID}-${technique}${EXT}"
            osslsigncode verify "${b}" 2>&1 | grep -q "Message digest" && echo "    Verified: ${b}" || print_warning "could not verify ${b}"
        done
    else
        echo "  Skipped"
    fi

    # Step 4: gzip-compress stage binaries (MANDATORY)
    print_step "4/8" "Compressing stage binaries with gzip..."
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        b="${TEST_UUID}-${technique}${EXT}"
        rm -f "${b}.gz"
        gzip -9 -k "${b}"
        echo "    ${b} -> ${b}.gz"
    done
    print_success "Compression complete"

    # Step 5: build orchestrator (embeds SIGNED+COMPRESSED stages)
    print_step "5/8" "Building ${GOOS} orchestrator (embedding compressed stages)..."
    main_binary="${BUILD_DIR}/${TEST_UUID}${EXT}"
    GOOS=${GOOS} GOARCH=${GOARCH} go build -trimpath -ldflags "-s -w" -o "${main_binary}" ${TEST_UUID}.go ${ORCH_SHARED}
    [ -f "${main_binary}" ] || { print_error "Failed to build orchestrator"; exit 1; }
    print_success "Orchestrator built: ${main_binary}"

    # Step 6: sign orchestrator (Windows only)
    print_step "6/8" "Signing orchestrator..."
    if [ "$GOOS" = "windows" ] && [ "$SIGN_MODE" != "none" ]; then
        sign_binary "${main_binary}"; print_success "Orchestrator signing complete"
    else
        echo "  Skipped (linux target or no signing configured)"
    fi

    # Step 7: report size + hash + tier
    print_step "7/8" "Reporting artifact..."
    bytes=$(stat -c%s "${main_binary}" 2>/dev/null || stat -f%z "${main_binary}")
    mb=$(awk "BEGIN{printf \"%.2f\", ${bytes}/1048576}")
    hash=$(sha1sum "${main_binary}" | awk '{print $1}')
    echo "    Binary:  ${main_binary}"
    echo "    Size:    ${bytes} bytes (${mb} MB)"
    echo "    Tier:    $(size_tier ${bytes})"
    echo "    SHA1:    ${hash}"

    # Step 8: cleanup temporary stage binaries
    print_step "8/8" "Cleaning up temporary stage binaries..."
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r technique _ <<< "$stage"
        rm -f "${TEST_UUID}-${technique}${EXT}" "${TEST_UUID}-${technique}${EXT}.gz"
    done
    print_success "${GOOS} build complete"
done

print_header "Build Complete"
echo "  Test UUID:  ${TEST_UUID}"
echo "  Test Name:  ${TEST_NAME}"
for GOOS in "${TARGETS[@]}"; do
    if [ "$GOOS" = "windows" ]; then EXT=".exe"; else EXT=""; fi
    b="${BUILD_DIR}/${TEST_UUID}${EXT}"
    [ -f "$b" ] && echo "  - ${GOOS}: ${b}"
done
print_success "Multi-stage test ready for deployment!"
