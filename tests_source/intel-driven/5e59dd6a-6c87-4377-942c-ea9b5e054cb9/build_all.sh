#!/bin/bash
# Multi-Stage Build: BlueHammer Early-Stage Behavioral Simulation (v2)
# Follows the modern 8-step F0RT1KA multi-stage pattern with gzip compression.
#
# Stages:
#   T1211-cfapi      — Cloud Files sync-root + fetch-placeholder callback + Mimikatz-named EICAR drop
#   T1562.001-oplock — Batch oplock on sandbox file
#   T1211-vssenum    — NT \Device enum + WMI Win32_ShadowCopy enum + transacted-open on sandbox file
#   T1003.002-samsim — Privilege-enable telemetry + synthetic SAM-named hive load/read (sandbox-only, watchdog-protected)

set -e
set -u

TEST_UUID="5e59dd6a-6c87-4377-942c-ea9b5e054cb9"

declare -a STAGES=(
    "T1211-cfapi:stage-T1211-cfapi"
    "T1562.001-oplock:stage-T1562.001-oplock"
    "T1211-vssenum:stage-T1211-vssenum"
    "T1003.002-samsim:stage-T1003.002-samsim"
)

# ==============================================================================

ORG_CERT=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --org) ORG_CERT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--org <org-identifier>]"
            exit 0
            ;;
        *) echo "ERROR: unknown option $1"; exit 1 ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

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

SIGN_MODE="none"; SIGN_CERT=""; SIGN_PASS_FILE=""

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

print_header() { echo -e "${BLUE}==================================${NC}\n${BLUE}$1${NC}\n${BLUE}==================================${NC}"; }
print_step() { echo -e "${GREEN}[$1] $2${NC}"; }
print_warning() { echo -e "${YELLOW}WARNING: $1${NC}"; }
print_error() { echo -e "${RED}ERROR: $1${NC}"; }
print_success() { echo -e "${GREEN}$1${NC}"; }

sign_binary() {
    local binary="$1"
    local binary_name
    binary_name=$(basename "$binary")
    if [ "$SIGN_MODE" = "none" ]; then return 0; fi
    if ! command -v osslsigncode &> /dev/null; then
        print_warning "osslsigncode missing — skip signing ${binary_name}"; return 0
    fi
    local signed="${binary}.signed"
    if [ "$SIGN_MODE" = "projectachilles" ]; then
        if [ -z "$SIGN_PASS_FILE" ] || [ ! -f "$SIGN_PASS_FILE" ]; then
            print_warning "Cert password file missing — skip ${binary_name}"; return 0
        fi
        osslsigncode sign -pkcs12 "$SIGN_CERT" -readpass "$SIGN_PASS_FILE" -in "$binary" -out "$signed" 2>/dev/null
    elif [ "$SIGN_MODE" = "f0library-org" ]; then
        if [ -n "$PROJECT_ROOT" ] && [ -f "${PROJECT_ROOT}/utils/codesign" ]; then
            "${PROJECT_ROOT}/utils/codesign" sign-nested "$binary" "$SIGN_CERT" "${F0RTIKA_CERT:-}"
            echo "    Dual-signed: ${binary_name}"; return 0
        fi
    elif [ "$SIGN_MODE" = "f0library" ]; then
        if [ ! -f "$SIGN_PASS_FILE" ]; then print_warning "Cert password file missing"; return 0; fi
        local password; password=$(tr -d '\n\r' < "$SIGN_PASS_FILE")
        osslsigncode sign -pkcs12 "$SIGN_CERT" -pass "$password" -in "$binary" -out "$signed" 2>/dev/null
    fi
    if [ -f "$signed" ]; then mv "$signed" "$binary"; echo "    Signed: ${binary_name}"
    else rm -f "$signed"; print_warning "Signing failed for ${binary_name}"; fi
}

print_header "Multi-Stage Build: BlueHammer Early-Stage Behavioral Simulation"
echo "  Test UUID:  ${TEST_UUID}"
echo "  Platform:   ${GOOS}/${GOARCH}"
echo "  Signing:    ${SIGN_MODE}"
echo "  Stages:     ${#STAGES[@]}"

print_step "0/8" "Validating environment..."
command -v go >/dev/null || { print_error "Go not installed"; exit 1; }
cd "${TEST_DIR}"
go mod download 2>/dev/null || true
print_success "Environment validated"

print_step "1/8" "Building ${#STAGES[@]} stage binaries..."
stage_count=0
for stage in "${STAGES[@]}"; do
    IFS=':' read -r tag source <<< "$stage"
    output_name="${TEST_UUID}-${tag}.exe"
    echo "  Building ${tag} (${source}.go)..."
    GOOS=${GOOS} GOARCH=${GOARCH} go build \
        -o "${output_name}" \
        "${source}.go" test_logger.go test_logger_windows.go org_resolver.go
    [ -f "${output_name}" ] || { print_error "Build failed: ${output_name}"; exit 1; }
    stage_count=$((stage_count + 1))
done
print_success "Built ${stage_count} stage binaries"

print_step "2/8" "(no cleanup utility for this test — skipping)"

print_step "3/8" "Signing stage binaries..."
if [ "$SIGN_MODE" = "none" ]; then
    print_warning "No signing — stages will be unsigned"
else
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r tag _ <<< "$stage"
        sign_binary "${TEST_UUID}-${tag}.exe"
    done
    print_success "Stage signing complete"
fi

print_step "4/8" "Verifying signatures..."
if [ "$SIGN_MODE" != "none" ] && command -v osslsigncode &> /dev/null; then
    for stage in "${STAGES[@]}"; do
        IFS=':' read -r tag _ <<< "$stage"
        binary="${TEST_UUID}-${tag}.exe"
        if osslsigncode verify "${binary}" 2>&1 | grep -q "Message digest"; then
            echo "    Verified: ${binary}"
        else
            print_warning "Could not verify ${binary}"
        fi
    done
else
    echo "  Skipped"
fi

print_step "5/8" "Compressing signed binaries with gzip..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r tag _ <<< "$stage"
    binary="${TEST_UUID}-${tag}.exe"
    gzip -9 -k "$binary"
    orig_size=$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary" 2>/dev/null)
    gz_size=$(stat -c%s "${binary}.gz" 2>/dev/null || stat -f%z "${binary}.gz" 2>/dev/null)
    echo "    ${binary}: ${orig_size}B -> ${gz_size}B"
done
print_success "Compression complete"

print_step "6/8" "Building orchestrator (embedding compressed stages)..."
mkdir -p "${BUILD_DIR}"
main_binary="${BUILD_DIR}/${TEST_UUID}.exe"
GOOS=${GOOS} GOARCH=${GOARCH} go build \
    -o "${main_binary}" \
    "${TEST_UUID}.go" test_logger.go test_logger_windows.go org_resolver.go
[ -f "${main_binary}" ] || { print_error "Orchestrator build failed"; exit 1; }
main_size=$(ls -lh "${main_binary}" | awk '{print $5}')
print_success "Orchestrator built (${main_size})"

print_step "7/8" "Signing orchestrator..."
if [ "$SIGN_MODE" != "none" ]; then
    sign_binary "${main_binary}"
    print_success "Orchestrator signing complete"
else
    print_warning "Skipping orchestrator signing"
fi

print_step "8/8" "Cleanup + hash..."
main_hash=$(sha1sum "${main_binary}" | awk '{print $1}')
main_size_final=$(ls -lh "${main_binary}" | awk '{print $5}')
for stage in "${STAGES[@]}"; do
    IFS=':' read -r tag _ <<< "$stage"
    rm -f "${TEST_UUID}-${tag}.exe" "${TEST_UUID}-${tag}.exe.gz"
done

print_header "Build Complete"
echo ""
echo "  Test UUID:    ${TEST_UUID}"
echo "  Test Name:    BlueHammer Early-Stage Behavioral Pattern"
echo "  Stages:       ${stage_count}"
echo "  Final Binary: ${main_binary}"
echo "  Binary Size:  ${main_size_final}"
echo "  SHA1:         ${main_hash}"
echo "  Signing:      ${SIGN_MODE}"
echo ""
print_success "Test ready for deployment."
