#!/bin/bash
# Prebuilt-Binary Deployment Test Build Script
# RoguePlanet — Windows Defender Remediation TOCTOU LPE (wermgr.exe SYSTEM hijack)
#
# This is a PREBUILT-BINARY DEPLOYMENT test: the orchestrator embeds an existing,
# signed RoguePlanet.exe (gzip-compressed). It does NOT compile the exploit from source.
#
# BUILD SEQUENCE (adapted 8-step pattern for a single embedded payload):
# 1. Sign the prebuilt payload (RoguePlanet.exe) with the F0RT1KA cert (BEFORE embedding)
# 2. Verify the payload signature
# 3. Compress the SIGNED payload with gzip -9  (RoguePlanet.exe -> RoguePlanet.exe.gz)
# 4. Build the orchestrator (embeds the SIGNED+COMPRESSED payload via //go:embed)
# 5. Sign the orchestrator (dual-sign with org cert if --org given, else F0RT1KA-only)
# 6. Verify the orchestrator signature
# 7. Cleanup the temporary .gz embed artifact
# 8. Emit SHA1/SHA256 hashes + binary size tier
#
# DESIGN NOTE (documented in <uuid>_info.md): signing the embedded RoguePlanet.exe with
# the F0RT1KA cert MAY suppress the very AV/EDR reaction the PROTECTED branch is meant to
# measure (ASR/whitelisting can treat a signed binary differently). Block-detection in the
# orchestrator keys on quarantine-of-dropped-file / OS execution-prevention so it stays
# meaningful even against a signed payload that behavioral rules dislike.
#
# Usage: ./build_all.sh [--org <org-identifier>]
# Output: build/<uuid>/<uuid>.exe

set -e
set -u

TEST_UUID="aa764293-94ed-4b25-a7fb-7d6fc14ac9a4"
PAYLOAD_SRC="RoguePlanet.exe"           # prebuilt PE staged in the test dir
EMBED_GZ="RoguePlanet.exe.gz"           # what //go:embed picks up

ORG_CERT=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --org) ORG_CERT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--org <org-identifier>]"
            echo "  --org <id>  Dual-sign orchestrator with org cert (sb, tpsgl, rga, or UUID)"
            exit 0 ;;
        *) echo "ERROR: Unknown option: $1"; exit 1 ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# The codesign utility can return a nonzero exit even when signing succeeds
# (its summary logic over-counts). Sign success is therefore confirmed by
# osslsigncode verify (presence of a "Message digest" line), not by exit code.
# This helper signs then VERIFIES, aborting only if no signature actually landed.
sign_and_verify() {
    local target="$1"
    if [ "$HAVE_SIGNING" != true ]; then
        print_warning "  Skipped signing ${target} (no osslsigncode)"
        return 0
    fi
    if [ -n "$ORG_CERT" ] && [ -f "${CODESIGN}" ]; then
        local org_pfx="${PROJECT_ROOT}/signing-certs/F0-LocalCodeSigningCert-CST-$(echo "$ORG_CERT" | tr '[:lower:]' '[:upper:]').pfx"
        if [ -f "$org_pfx" ]; then
            "${CODESIGN}" sign-nested "${target}" "${org_pfx}" "${F0RT1KA_CERT}" || true
        else
            print_warning "  Org cert not found; F0RT1KA-only signing for ${target}"
            "${CODESIGN}" --cert "${F0RT1KA_CERT}" sign "${target}" || true
        fi
    else
        "${CODESIGN}" --cert "${F0RT1KA_CERT}" sign "${target}" || true
    fi
    if osslsigncode verify "${target}" 2>&1 | grep -q "Message digest"; then
        print_success "  ${target} signed (verified)"
        return 0
    fi
    print_error "  ${target} did not get a valid signature"
    return 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TEST_DIR="${SCRIPT_DIR}"
BUILD_DIR="${TEST_DIR}/build/${TEST_UUID}"

GOOS="${GOOS:-windows}"
GOARCH="${GOARCH:-amd64}"

F0RT1KA_CERT="${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
CODESIGN="${PROJECT_ROOT}/utils/codesign"

cd "${TEST_DIR}"
mkdir -p "${BUILD_DIR}"

if [ ! -f "${PAYLOAD_SRC}" ]; then
    print_error "Prebuilt payload ${PAYLOAD_SRC} not found in ${TEST_DIR}"
    exit 1
fi

HAVE_SIGNING=true
if ! command -v osslsigncode &> /dev/null; then
    print_warning "osslsigncode not installed — signing will be SKIPPED (payload embedded unsigned)"
    HAVE_SIGNING=false
fi

# ------------------------------------------------------------------------------
# Step 1: Sign the prebuilt payload (BEFORE embedding)
# ------------------------------------------------------------------------------
print_info "Step 1/8: Signing prebuilt payload ${PAYLOAD_SRC} (BEFORE embedding)"
sign_and_verify "${PAYLOAD_SRC}"

# ------------------------------------------------------------------------------
# Step 2: Verify payload signature (already confirmed inside sign_and_verify)
# ------------------------------------------------------------------------------
print_info "Step 2/8: Payload signature verified in Step 1"

# ------------------------------------------------------------------------------
# Step 3: Compress signed payload with gzip -9
# ------------------------------------------------------------------------------
print_info "Step 3/8: Compressing signed payload (gzip -9)"
rm -f "${EMBED_GZ}"
gzip -9 -k -c "${PAYLOAD_SRC}" > "${EMBED_GZ}"
RAW_SZ=$(stat -c%s "${PAYLOAD_SRC}")
GZ_SZ=$(stat -c%s "${EMBED_GZ}")
print_success "  ${PAYLOAD_SRC} (${RAW_SZ} B) -> ${EMBED_GZ} (${GZ_SZ} B)"

# ------------------------------------------------------------------------------
# Step 4: Build the orchestrator (embeds signed+compressed payload)
# ------------------------------------------------------------------------------
print_info "Step 4/8: Building orchestrator (GOOS=${GOOS} GOARCH=${GOARCH})"
ORCH_OUT="${BUILD_DIR}/${TEST_UUID}.exe"
GOOS="${GOOS}" GOARCH="${GOARCH}" go build -trimpath -ldflags="-s -w" -o "${ORCH_OUT}" .
print_success "  Built ${ORCH_OUT}"

# ------------------------------------------------------------------------------
# Step 5: Sign the orchestrator
# ------------------------------------------------------------------------------
print_info "Step 5/8: Signing orchestrator"
sign_and_verify "${ORCH_OUT}"

# ------------------------------------------------------------------------------
# Step 6: Verify orchestrator signature (already confirmed inside sign_and_verify)
# ------------------------------------------------------------------------------
print_info "Step 6/8: Orchestrator signature verified in Step 5"

# ------------------------------------------------------------------------------
# Step 7: Cleanup temporary embed artifact
# ------------------------------------------------------------------------------
print_info "Step 7/8: Cleaning up temporary .gz embed artifact"
rm -f "${EMBED_GZ}"
print_success "  Removed ${EMBED_GZ}"

# ------------------------------------------------------------------------------
# Step 8: Hashes + size tier
# ------------------------------------------------------------------------------
print_info "Step 8/8: Hashes + size budget"
ORCH_SZ=$(stat -c%s "${ORCH_OUT}")
ORCH_MB=$(awk "BEGIN{printf \"%.2f\", ${ORCH_SZ}/1048576}")
if   (( ORCH_SZ <= 10485760 )); then TIER="GREEN"
elif (( ORCH_SZ <= 26214400 )); then TIER="YELLOW"
elif (( ORCH_SZ <= 52428800 )); then TIER="RED"
else TIER="FORBIDDEN"; fi
echo "  Orchestrator size: ${ORCH_SZ} B (${ORCH_MB} MB) — Tier: ${TIER}"
echo "  SHA1:   $(sha1sum   "${ORCH_OUT}" | awk '{print $1}')"
echo "  SHA256: $(sha256sum "${ORCH_OUT}" | awk '{print $1}')"
print_success "Build complete: ${ORCH_OUT}"
