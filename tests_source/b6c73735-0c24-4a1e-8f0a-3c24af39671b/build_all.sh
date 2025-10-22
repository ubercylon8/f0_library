#!/bin/bash
# build_all.sh - Build all components for MDE Authentication Bypass test
# This script builds the main test, watchdog, and all helper binaries

set -e  # Exit on error

echo "=========================================="
echo "F0RT1KA MDE Bypass Test - Build Script"
echo "=========================================="
echo ""

# Get the test directory
TEST_UUID="b6c73735-0c24-4a1e-8f0a-3c24af39671b"
TEST_DIR="tests_source/${TEST_UUID}"
BUILD_DIR="build/${TEST_UUID}"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}[INFO]${NC} Building all components for test: ${TEST_UUID}"
echo ""

# Step 1: Build helper binaries
echo -e "${BLUE}[1/4]${NC} Building helper binaries..."
echo ""

echo -e "  ${BLUE}→${NC} Building fake_mssense.exe..."
cd "${TEST_DIR}"
GOOS=windows GOARCH=amd64 go build -o fake_mssense.exe fake_mssense.go
echo -e "  ${GREEN}✓${NC} fake_mssense.exe built"

echo -e "  ${BLUE}→${NC} Building isolation_spoofer.exe..."
GOOS=windows GOARCH=amd64 go build -o isolation_spoofer.exe isolation_spoofer.go
echo -e "  ${GREEN}✓${NC} isolation_spoofer.exe built"

echo -e "  ${BLUE}→${NC} Building cert_bypass_watchdog.exe..."
GOOS=windows GOARCH=amd64 go build -o cert_bypass_watchdog.exe cert_bypass_watchdog.go
echo -e "  ${GREEN}✓${NC} cert_bypass_watchdog.exe built"

cd - > /dev/null

echo ""
echo -e "${GREEN}[SUCCESS]${NC} All helper binaries built"
echo ""

# Step 2: Build main test binary
echo -e "${BLUE}[2/4]${NC} Building main test binary..."
echo ""

./utils/gobuild build "${TEST_DIR}/"

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}[SUCCESS]${NC} Main test binary built"
else
    echo ""
    echo -e "${YELLOW}[WARNING]${NC} Main test build failed"
    exit 1
fi

echo ""

# Step 3: Copy helper binaries to build directory
echo -e "${BLUE}[3/4]${NC} Copying helper binaries to build directory..."
echo ""

mkdir -p "${BUILD_DIR}"

echo -e "  ${BLUE}→${NC} Copying fake_mssense.exe..."
cp "${TEST_DIR}/fake_mssense.exe" "${BUILD_DIR}/"
echo -e "  ${GREEN}✓${NC} Copied"

echo -e "  ${BLUE}→${NC} Copying isolation_spoofer.exe..."
cp "${TEST_DIR}/isolation_spoofer.exe" "${BUILD_DIR}/"
echo -e "  ${GREEN}✓${NC} Copied"

echo -e "  ${BLUE}→${NC} Copying cert_bypass_watchdog.exe..."
cp "${TEST_DIR}/cert_bypass_watchdog.exe" "${BUILD_DIR}/"
echo -e "  ${GREEN}✓${NC} Copied"

echo -e "  ${BLUE}→${NC} Copying emergency_restore.ps1..."
cp "${TEST_DIR}/emergency_restore.ps1" "${BUILD_DIR}/"
echo -e "  ${GREEN}✓${NC} Copied"

echo -e "  ${BLUE}→${NC} Copying documentation..."
cp "${TEST_DIR}/CERT_BYPASS_SAFETY_GUIDE.md" "${BUILD_DIR}/" 2>/dev/null || true
cp "${TEST_DIR}/RECOVERY_ARCHITECTURE.md" "${BUILD_DIR}/" 2>/dev/null || true
echo -e "  ${GREEN}✓${NC} Copied"

echo ""
echo -e "${GREEN}[SUCCESS]${NC} Helper binaries copied to build directory"
echo ""

# Step 4: Show build summary
echo -e "${BLUE}[4/4]${NC} Build Summary"
echo ""
echo "Build directory: ${BUILD_DIR}"
echo ""
echo "Files created:"
ls -lh "${BUILD_DIR}" | grep -E '\.(exe|ps1|md)$' | awk '{printf "  - %-40s %8s\n", $9, $5}'

echo ""
echo "=========================================="
echo -e "${GREEN}BUILD COMPLETE${NC}"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Sign the main test binary:"
echo "     ./utils/codesign sign ${BUILD_DIR}/${TEST_UUID}.exe"
echo ""
echo "  2. Read the safety guide:"
echo "     cat ${BUILD_DIR}/CERT_BYPASS_SAFETY_GUIDE.md"
echo ""
echo "  3. Deploy to test system and run"
echo ""
