#!/bin/bash
# Multi-Stage Intel-Driven Test Build Script (Linux)
# Mini Shai-Hulud npm Supply Chain Kill Chain (@redhat-cloud-services) - 6 stages
#
# MODERN 8-STEP BUILD SEQUENCE:
# 1. Build unsigned stage binaries (each from stage .go + shared logger/org files)
# 2. Sign stage binaries (Linux: no-op; Authenticode is Windows-only)
# 3. Verify signatures (Linux: no-op)
# 4. Gzip-compress signed stage binaries (MANDATORY for multi-stage; ~35% smaller)
# 5. Build main orchestrator (embeds .gz stages)
# 6. Sign orchestrator (Linux: no-op)
# 7. Cleanup temporary binaries + .gz files
# 8. Calculate SHA1 hash + report binary size tier
#
# Usage: ./build_all.sh [--org <org-identifier>]
# Output: build/<uuid>/<uuid>

set -e
set -u

# ==============================================================================
# CONFIGURATION
# ==============================================================================

TEST_UUID="ae9002e4-3d82-4fcd-8b45-f7e0628f7375"

# Stage definitions: "TECHNIQUE:SOURCE_FILE"
declare -a STAGES=(
    "T1195.002:stage-T1195.002"
    "T1480.001:stage-T1480.001"
    "T1105:stage-T1105"
    "T1552.001:stage-T1552.001"
    "T1071.001:stage-T1071.001"
    "T1567.001:stage-T1567.001"
)

# ==============================================================================
# DO NOT EDIT BELOW THIS LINE
# ==============================================================================

ORG_CERT=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --org) ORG_CERT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--org <org-identifier>]"
            exit 0 ;;
        *) echo "ERROR: Unknown option: $1"; exit 1 ;;
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

GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"
export CGO_ENABLED="${CGO_ENABLED:-0}"

print_header() { echo -e "${BLUE}=================================================${NC}"; echo -e "${BLUE}$1${NC}"; echo -e "${BLUE}=================================================${NC}"; }
print_step()    { echo -e "${GREEN}[$1] $2${NC}"; }
print_warning() { echo -e "${YELLOW}WARNING: $1${NC}"; }
print_error()   { echo -e "${RED}ERROR: $1${NC}"; }
print_success() { echo -e "${GREEN}$1${NC}"; }

SHARED_FILES="test_logger.go test_logger_linux.go org_resolver.go es_config.go"

print_header "Multi-Stage Test Build: Mini Shai-Hulud npm Supply Chain Kill Chain"
echo "  Test UUID:  ${TEST_UUID}"
echo "  Platform:   ${GOOS}/${GOARCH}"
echo "  Stages:     ${#STAGES[@]}"

# Step 0: Validate environment
print_step "0/8" "Validating environment..."
if ! command -v go &> /dev/null; then print_error "Go is not installed"; exit 1; fi
cd "${TEST_DIR}"
go mod download 2>/dev/null || true
print_success "Environment validated"

# Step 1: Build unsigned stage binaries
print_step "1/8" "Building ${#STAGES[@]} unsigned stage binaries..."
stage_count=0
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    output_name="${TEST_UUID}-${technique}"
    echo "  Building ${technique} (${source}.go)..."
    GOOS=${GOOS} GOARCH=${GOARCH} go build -o "${output_name}" "${source}.go" ${SHARED_FILES}
    if [ ! -f "${output_name}" ]; then print_error "Failed to build ${output_name}"; exit 1; fi
    stage_count=$((stage_count + 1))
done
print_success "Built ${stage_count} unsigned stage binaries"

# Step 2: Sign stage binaries (Linux no-op)
print_step "2/8" "Signing stage binaries..."
echo "  Skipped (Authenticode signing not applicable for Linux ELF binaries)"

# Step 3: Verify signatures (Linux no-op)
print_step "3/8" "Verifying stage signatures..."
echo "  Skipped (Authenticode signing not applicable for Linux ELF binaries)"

# Step 4: Gzip-compress signed stage binaries (MANDATORY)
print_step "4/8" "Gzip-compressing stage binaries (embed size reduction)..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    binary="${TEST_UUID}-${technique}"
    gzip -9 -f -k "${binary}"          # produces ${binary}.gz, keeps original
    rm -f "${binary}"                  # orchestrator embeds the .gz, not the ELF
    if [ ! -f "${binary}.gz" ]; then print_error "gzip failed for ${binary}"; exit 1; fi
    echo "    Compressed: ${binary}.gz"
done
print_success "Stage compression complete"

# Step 5: Build main orchestrator (embeds .gz stages)
print_step "5/8" "Building orchestrator (embedding gzip-compressed stages)..."
mkdir -p "${BUILD_DIR}"
main_binary="${BUILD_DIR}/${TEST_UUID}"
GOOS=${GOOS} GOARCH=${GOARCH} go build -o "${main_binary}" "${TEST_UUID}.go" ${SHARED_FILES}
if [ ! -f "${main_binary}" ]; then print_error "Failed to build orchestrator"; exit 1; fi
main_size=$(ls -lh "${main_binary}" | awk '{print $5}')
print_success "Orchestrator built (${main_size})"

# Step 6: Sign orchestrator (Linux no-op)
print_step "6/8" "Signing orchestrator..."
echo "  Skipped (Authenticode signing not applicable for Linux ELF binaries)"

# Step 7: Cleanup temporary binaries + .gz files
print_step "7/8" "Cleaning up temporary build artifacts..."
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique _ <<< "$stage"
    rm -f "${TEST_UUID}-${technique}" "${TEST_UUID}-${technique}.gz"
done
print_success "Cleanup complete"

# Step 8: Calculate hash + size tier
print_step "8/8" "Calculating hash and size tier..."
main_hash=$(sha1sum "${main_binary}" | awk '{print $1}')
main_bytes=$(stat -c%s "${main_binary}")
main_mb=$(awk "BEGIN{printf \"%.1f\", ${main_bytes}/1048576}")
tier="GREEN"
if (( main_bytes > 52428800 )); then tier="FORBIDDEN (>50MB)"
elif (( main_bytes > 26214400 )); then tier="RED (25-50MB)"
elif (( main_bytes > 10485760 )); then tier="YELLOW (10-25MB)"
fi

print_header "Build Complete"
echo ""
echo "  Test UUID:        ${TEST_UUID}"
echo "  Test Name:        Mini Shai-Hulud npm Supply Chain Kill Chain (@redhat-cloud-services)"
echo "  Stages Built:     ${stage_count}"
echo "  Final Binary:     ${BUILD_DIR}/${TEST_UUID}"
echo "  Binary Size:      ${main_size} (${main_bytes} bytes / ${main_mb} MB)"
echo "  Size Tier:        ${tier}"
echo "  SHA1 Hash:        ${main_hash}"
echo ""
echo "Stages:"
for stage in "${STAGES[@]}"; do
    IFS=':' read -r technique source <<< "$stage"
    echo "  - ${TEST_UUID}-${technique} (${source}.go)"
done
echo ""
print_success "Multi-stage test ready for deployment!"
echo ""
echo "Deployment (Linux target):"
echo "  1. Copy ${BUILD_DIR}/${TEST_UUID} to target"
echo "  2. Run: ./${TEST_UUID}"
echo "  3. Test extracts and executes 6 stages in killchain order"
echo ""
