#!/bin/bash
set -euo pipefail

TEST_UUID="262c6802-467c-42ed-ac3d-94e49f7d6ea4"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build/${TEST_UUID}"
ORG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --org)
            ORG="${2:-}"
            [[ -n "${ORG}" ]] || { echo "ERROR: --org requires an identifier"; exit 1; }
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--org <sb|tpsgl|rga|organization-uuid>]"
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1"
            exit 1
            ;;
    esac
done

for tool in go javac osslsigncode; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "ERROR: required build tool not found: ${tool}"; exit 1; }
done

cd "${SCRIPT_DIR}"
rm -rf generated
mkdir -p generated "${BUILD_DIR}"

echo "[1/7] Generating fresh validation certificates"
HOST_GOOS="$(go env GOHOSTOS)"
HOST_GOARCH="$(go env GOHOSTARCH)"
GOOS="${HOST_GOOS}" GOARCH="${HOST_GOARCH}" CGO_ENABLED=0 go run ./cmd/generate .

echo "[2/7] Compiling Java 8-compatible JSSE probe"
javac --release 8 -d generated helpers/TlsProbe.java

echo "[3/7] Building harmless Authenticode validation artifacts"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o generated/harmless.exe ./cmd/harmless
for kind in ov-g3b ov-g3c; do
    for path in direct aaa; do
        rm -f "generated/forged-${kind}-${path}.exe" "generated/forged-${kind}-${path}.exe.gz"
        osslsigncode sign -h sha256 \
            -certs "generated/codesign-${kind}-${path}-signer.pem" \
            -key "generated/codesign-${kind}-leaf.key" \
            -in generated/harmless.exe \
            -out "generated/forged-${kind}-${path}.exe"
        (osslsigncode verify "generated/forged-${kind}-${path}.exe" 2>&1 || true) | grep -q "Calculated message digest" || {
            echo "ERROR: Authenticode test artifact has no valid signature digest"
            exit 1
        }
        gzip -9 -c "generated/forged-${kind}-${path}.exe" > "generated/forged-${kind}-${path}.exe.gz"
        rm -f "generated/forged-${kind}-${path}.exe"
    done
done
rm -f generated/harmless.exe

echo "[4/7] Resolving Go dependencies"
go mod tidy

echo "[5/7] Building Linux and Windows assessment binaries"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${BUILD_DIR}/${TEST_UUID}" .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${BUILD_DIR}/${TEST_UUID}.exe" .

echo "[6/7] Signing and verifying Windows assessment binary"
SIGNED=false
if [[ -n "${ORG}" ]]; then
    source "${PROJECT_ROOT}/utils/resolve_org.sh"
    CERT_FILE="$(resolve_org_to_cert "${ORG}")"
    [[ -n "${CERT_FILE}" ]] || { echo "ERROR: could not resolve organization ${ORG}"; exit 1; }
    "${PROJECT_ROOT}/utils/codesign" sign-nested "${BUILD_DIR}/${TEST_UUID}.exe" \
        "${PROJECT_ROOT}/signing-certs/${CERT_FILE}" "${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx"
    SIGNED=true
elif [[ -n "${F0_SIGN_CERT_PATH:-}" ]]; then
    [[ -f "${F0_SIGN_CERT_PATH}" ]] || { echo "ERROR: PA signing certificate not found: ${F0_SIGN_CERT_PATH}"; exit 1; }
    [[ -n "${F0_SIGN_CERT_PASS_FILE:-}" && -f "${F0_SIGN_CERT_PASS_FILE}" ]] || {
        echo "ERROR: F0_SIGN_CERT_PASS_FILE must reference a readable password file"; exit 1;
    }
    PA_SIGNED="${BUILD_DIR}/${TEST_UUID}.pa-signed.exe"
    rm -f "${PA_SIGNED}"
    osslsigncode sign -h sha256 -pkcs12 "${F0_SIGN_CERT_PATH}" -readpass "${F0_SIGN_CERT_PASS_FILE}" \
        -in "${BUILD_DIR}/${TEST_UUID}.exe" -out "${PA_SIGNED}"
    mv "${PA_SIGNED}" "${BUILD_DIR}/${TEST_UUID}.exe"
    SIGNED=true
elif [[ -f "${PROJECT_ROOT}/signing-certs/F0RT1KA.pfx" ]]; then
    "${PROJECT_ROOT}/utils/codesign" sign "${BUILD_DIR}/${TEST_UUID}.exe"
    SIGNED=true
else
    echo "WARNING: no signing certificate configured; producing an UNSIGNED Windows binary"
fi
if [[ "${SIGNED}" == "true" ]]; then
    (osslsigncode verify "${BUILD_DIR}/${TEST_UUID}.exe" 2>&1 || true) | grep -q "Calculated message digest" || {
        echo "ERROR: final Windows binary signature verification failed"
        exit 1
    }
fi

echo "[7/7] Reporting hashes and size budget"
for binary in "${BUILD_DIR}/${TEST_UUID}" "${BUILD_DIR}/${TEST_UUID}.exe"; do
    size="$(stat -c%s "${binary}")"
    hash="$(shasum -a 1 "${binary}" | awk '{print $1}')"
    if [[ "${size}" -le 10485760 ]]; then tier="GREEN";
    elif [[ "${size}" -le 26214400 ]]; then tier="YELLOW";
    elif [[ "${size}" -le 52428800 ]]; then tier="RED";
    else tier="FORBIDDEN"; fi
    printf '  %s\n    size=%s bytes tier=%s sha1=%s\n' "${binary}" "${size}" "${tier}" "${hash}"
    [[ "${size}" -le 52428800 ]] || { echo "ERROR: binary exceeds the forbidden size budget"; exit 1; }
done
