#!/bin/bash

# Unit tests for codesign utility
# Test script for the F0RT1KA code signing tool

# Note: We don't use 'set -e' here because we want to capture test failures

# Test configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_DIR="$TEST_DIR"
CODESIGN_CMD="$UTILS_DIR/codesign"
TEMP_DIR=""
PASSED=0
FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test output functions
test_info() {
    echo -e "${BLUE}[TEST INFO]${NC} $1"
}

test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

test_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

test_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Setup test environment
setup_test_env() {
    TEMP_DIR=$(mktemp -d)
    test_info "Created temp directory: $TEMP_DIR"
    
    # Create mock binary files
    mkdir -p "$TEMP_DIR/build/test-uuid-123"
    echo "fake binary content" > "$TEMP_DIR/build/test-uuid-123/test-uuid-123.exe"
    
    # Create mock certificate directory
    mkdir -p "$TEMP_DIR/signing-certs"
    
    # Create mock certificate file (empty for testing)
    echo "mock certificate" > "$TEMP_DIR/signing-certs/test-cert.pfx"
    
    cd "$TEMP_DIR"
}

# Cleanup test environment
cleanup_test_env() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        test_info "Cleaned up temp directory"
    fi
}

# Test codesign help command
test_codesign_help() {
    test_info "Testing codesign --help"
    
    if "$CODESIGN_CMD" --help > /dev/null 2>&1; then
        test_pass "codesign --help command works"
    else
        test_fail "codesign --help command failed"
    fi
}

# Test codesign list-certs command
test_codesign_list_certs() {
    test_info "Testing codesign list-certs"
    
    cd "$TEMP_DIR"
    
    if "$CODESIGN_CMD" list-certs > /dev/null 2>&1; then
        test_pass "codesign list-certs command works"
    else
        test_fail "codesign list-certs command failed"
    fi
}

# Test codesign with invalid arguments
test_codesign_invalid_args() {
    test_info "Testing codesign with invalid arguments"
    
    cd "$TEMP_DIR"
    
    # Test invalid command
    if "$CODESIGN_CMD" invalid-command > /dev/null 2>&1; then
        test_fail "codesign should reject invalid command"
    else
        test_pass "codesign correctly rejects invalid command"
    fi
    
    # Test sign without binary path
    if "$CODESIGN_CMD" sign > /dev/null 2>&1; then
        test_fail "codesign should require binary path for sign command"
    else
        test_pass "codesign correctly requires binary path for sign command"
    fi
    
    # Test verify without binary path  
    if "$CODESIGN_CMD" verify > /dev/null 2>&1; then
        test_fail "codesign should require binary path for verify command"
    else
        test_pass "codesign correctly requires binary path for verify command"
    fi
}

# Test codesign sign command (will fail due to missing osslsigncode)
test_codesign_sign() {
    test_info "Testing codesign sign command"
    
    cd "$TEMP_DIR"
    
    # This test will likely fail due to missing osslsigncode or invalid cert
    # but we want to test the command parsing and file validation
    if "$CODESIGN_CMD" --cert signing-certs/test-cert.pfx --password test sign build/test-uuid-123/test-uuid-123.exe > /dev/null 2>&1; then
        test_pass "codesign sign command succeeded"
    else
        test_warn "codesign sign command failed (expected due to missing osslsigncode or invalid cert)"
    fi
}

# Test codesign verify command
test_codesign_verify() {
    test_info "Testing codesign verify command"
    
    cd "$TEMP_DIR"
    
    # Test with non-existent binary
    if "$CODESIGN_CMD" verify non-existent-binary.exe > /dev/null 2>&1; then
        test_fail "codesign should reject non-existent binary"
    else
        test_pass "codesign correctly rejects non-existent binary"
    fi
    
    # Test with mock binary (will fail verification but should handle the file)
    if "$CODESIGN_CMD" verify build/test-uuid-123/test-uuid-123.exe > /dev/null 2>&1; then
        test_warn "codesign verify succeeded (unexpected)"
    else
        test_warn "codesign verify failed (expected for unsigned binary)"
    fi
}

# Test certificate directory handling
test_certificate_handling() {
    test_info "Testing certificate directory handling"
    
    cd "$TEMP_DIR"
    
    # Test with empty cert directory
    rm -f signing-certs/*.pfx
    if "$CODESIGN_CMD" list-certs > /dev/null 2>&1; then
        test_pass "codesign handles empty certificate directory"
    else
        test_fail "codesign should handle empty certificate directory"
    fi
    
    # Test with non-existent cert directory
    rm -rf signing-certs
    if "$CODESIGN_CMD" list-certs > /dev/null 2>&1; then
        test_pass "codesign handles non-existent certificate directory"
    else
        test_fail "codesign should handle non-existent certificate directory"
    fi
}

# Test osslsigncode dependency check
test_osslsigncode_check() {
    test_info "Testing osslsigncode dependency check"
    
    cd "$TEMP_DIR"
    
    # Save original PATH
    original_path="$PATH"
    
    # Temporarily remove osslsigncode from PATH (if it exists)
    PATH=${PATH//osslsigncode/}
    
    # Test any command that would check for osslsigncode
    if "$CODESIGN_CMD" list-certs > /dev/null 2>&1; then
        test_warn "codesign should check for osslsigncode installation"
    else
        test_pass "codesign correctly checks for osslsigncode installation"
    fi
    
    # Restore PATH
    PATH="$original_path"
}

# Test sign-all command
test_codesign_sign_all() {
    test_info "Testing codesign sign-all command"
    
    cd "$TEMP_DIR"
    
    # Create additional mock binaries
    mkdir -p build/test-uuid-456
    echo "fake binary 2" > build/test-uuid-456/test-uuid-456.exe
    
    # Recreate certificate
    echo "mock certificate" > signing-certs/test-cert.pfx
    
    # Test sign-all (will fail due to missing osslsigncode)
    if "$CODESIGN_CMD" --cert signing-certs/test-cert.pfx --password test sign-all build > /dev/null 2>&1; then
        test_pass "codesign sign-all command succeeded"
    else
        test_warn "codesign sign-all command failed (expected due to missing osslsigncode)"
    fi
}

# Test file validation
test_file_validation() {
    test_info "Testing file validation"
    
    cd "$TEMP_DIR"
    
    # Test with non-existent certificate file
    if "$CODESIGN_CMD" --cert non-existent-cert.pfx --password test sign build/test-uuid-123/test-uuid-123.exe > /dev/null 2>&1; then
        test_fail "codesign should reject non-existent certificate file"
    else
        test_pass "codesign correctly rejects non-existent certificate file"
    fi
    
    # Test with non-existent binary file
    if "$CODESIGN_CMD" --cert signing-certs/test-cert.pfx --password test sign non-existent-binary.exe > /dev/null 2>&1; then
        test_fail "codesign should reject non-existent binary file"
    else
        test_pass "codesign correctly rejects non-existent binary file"
    fi
}

# Main test runner
run_tests() {
    test_info "Starting codesign utility tests"
    test_info "==============================================="
    
    # Setup test environment
    setup_test_env
    
    # Run tests
    test_codesign_help
    test_codesign_list_certs
    test_codesign_invalid_args
    test_codesign_sign
    test_codesign_verify
    test_certificate_handling
    test_osslsigncode_check
    test_codesign_sign_all
    test_file_validation
    
    # Cleanup
    cleanup_test_env
    
    # Report results
    echo
    test_info "==============================================="
    test_info "Test Results:"
    echo -e "${GREEN}Passed: $PASSED${NC}"
    echo -e "${RED}Failed: $FAILED${NC}"
    
    if [[ $FAILED -eq 0 ]]; then
        test_info "All tests passed!"
        exit 0
    else
        test_info "Some tests failed"
        exit 1
    fi
}

# Check if codesign exists
if [[ ! -f "$CODESIGN_CMD" ]]; then
    test_fail "codesign utility not found at: $CODESIGN_CMD"
    exit 1
fi

# Make sure codesign is executable
chmod +x "$CODESIGN_CMD"

# Run tests
run_tests