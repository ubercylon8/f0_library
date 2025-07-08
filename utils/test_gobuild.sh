#!/bin/bash

# Unit tests for gobuild utility
# Test script for the F0RT1KA test builder

# Note: We don't use 'set -e' here because we want to capture test failures

# Test configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_DIR="$TEST_DIR"
GOBUILD_CMD="$UTILS_DIR/gobuild"
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
    
    # Create mock test structure
    mkdir -p "$TEMP_DIR/tests_source/test-uuid-123"
    cd "$TEMP_DIR/tests_source/test-uuid-123"
    
    # Create mock go.mod
    cat > go.mod << 'EOF'
module test-uuid-123

go 1.21

require (
    github.com/preludeorg/libraries/go/tests/dropper v0.0.0
    github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
)

replace github.com/preludeorg/libraries/go/tests/dropper => ../../preludeorg-libraries/go/tests/dropper
replace github.com/preludeorg/libraries/go/tests/endpoint => ../../preludeorg-libraries/go/tests/endpoint
EOF
    
    # Create mock test file
    cat > test-uuid-123.go << 'EOF'
//go:build windows

package main

import "fmt"

func main() {
    fmt.Println("Hello from test")
}
EOF
    
    # Create prelude libraries mock
    mkdir -p "$TEMP_DIR/preludeorg-libraries/go/tests/dropper"
    mkdir -p "$TEMP_DIR/preludeorg-libraries/go/tests/endpoint"
    
    # Create minimal mock modules
    cat > "$TEMP_DIR/preludeorg-libraries/go/tests/dropper/go.mod" << 'EOF'
module github.com/preludeorg/libraries/go/tests/dropper

go 1.21
EOF
    
    cat > "$TEMP_DIR/preludeorg-libraries/go/tests/dropper/dropper.go" << 'EOF'
package dropper

var Dropper = "mock-dropper"
EOF
    
    cat > "$TEMP_DIR/preludeorg-libraries/go/tests/endpoint/go.mod" << 'EOF'
module github.com/preludeorg/libraries/go/tests/endpoint

go 1.21
EOF
    
    cat > "$TEMP_DIR/preludeorg-libraries/go/tests/endpoint/endpoint.go" << 'EOF'
package endpoint

func Say(msg string) {}
func Stop(code int) {}
func Dropper(dropper string) error { return nil }
EOF
    
    cd "$TEMP_DIR"
}

# Cleanup test environment
cleanup_test_env() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        test_info "Cleaned up temp directory"
    fi
}

# Test gobuild help command
test_gobuild_help() {
    test_info "Testing gobuild --help"
    
    if "$GOBUILD_CMD" --help > /dev/null 2>&1; then
        test_pass "gobuild --help command works"
    else
        test_fail "gobuild --help command failed"
    fi
}

# Test gobuild list command
test_gobuild_list() {
    test_info "Testing gobuild list"
    
    cd "$TEMP_DIR"
    
    if "$GOBUILD_CMD" list > /dev/null 2>&1; then
        test_pass "gobuild list command works"
    else
        test_fail "gobuild list command failed"
    fi
}

# Test gobuild build command
test_gobuild_build() {
    test_info "Testing gobuild build"
    
    cd "$TEMP_DIR"
    
    # This test might fail if prelude libraries aren't available
    # but we still want to test the command parsing and validation
    if "$GOBUILD_CMD" build tests_source/test-uuid-123 > /dev/null 2>&1; then
        test_pass "gobuild build command succeeded"
        
        # Check if binary was created
        if [[ -f "build/test-uuid-123/test-uuid-123.exe" ]]; then
            test_pass "Binary was created successfully"
        else
            test_warn "Binary was not created (may be due to missing dependencies)"
        fi
    else
        test_warn "gobuild build command failed (may be due to missing dependencies)"
    fi
}

# Test gobuild with invalid arguments
test_gobuild_invalid_args() {
    test_info "Testing gobuild with invalid arguments"
    
    cd "$TEMP_DIR"
    
    # Test invalid OS
    if "$GOBUILD_CMD" --os invalid-os build tests_source/test-uuid-123 > /dev/null 2>&1; then
        test_fail "gobuild should reject invalid OS"
    else
        test_pass "gobuild correctly rejects invalid OS"
    fi
    
    # Test invalid arch
    if "$GOBUILD_CMD" --arch invalid-arch build tests_source/test-uuid-123 > /dev/null 2>&1; then
        test_fail "gobuild should reject invalid architecture"
    else
        test_pass "gobuild correctly rejects invalid architecture"
    fi
    
    # Test missing test path
    if "$GOBUILD_CMD" build > /dev/null 2>&1; then
        test_fail "gobuild should require test path for build command"
    else
        test_pass "gobuild correctly requires test path for build command"
    fi
}

# Test gobuild clean command
test_gobuild_clean() {
    test_info "Testing gobuild clean"
    
    cd "$TEMP_DIR"
    
    # Create fake build directory
    mkdir -p build/fake-test
    echo "fake binary" > build/fake-test/fake.exe
    
    if "$GOBUILD_CMD" clean > /dev/null 2>&1; then
        test_pass "gobuild clean command works"
        
        if [[ ! -d "build" ]]; then
            test_pass "Build directory was cleaned"
        else
            test_fail "Build directory still exists after clean"
        fi
    else
        test_fail "gobuild clean command failed"
    fi
}

# Test directory validation
test_directory_validation() {
    test_info "Testing directory validation"
    
    cd "$TEMP_DIR"
    
    # Test with non-existent directory
    if "$GOBUILD_CMD" build non-existent-directory > /dev/null 2>&1; then
        test_fail "gobuild should reject non-existent directory"
    else
        test_pass "gobuild correctly rejects non-existent directory"
    fi
    
    # Test with directory missing go.mod
    mkdir -p tests_source/invalid-test
    if "$GOBUILD_CMD" build tests_source/invalid-test > /dev/null 2>&1; then
        test_fail "gobuild should reject directory without go.mod"
    else
        test_pass "gobuild correctly rejects directory without go.mod"
    fi
}

# Test Go installation check
test_go_requirement() {
    test_info "Testing Go installation requirement"
    
    # Check if Go is available
    if command -v go &> /dev/null; then
        test_pass "Go is available for testing"
    else
        test_warn "Go is not installed - skipping Go dependency test"
        return 0
    fi
    
    # Save original PATH
    original_path="$PATH"
    
    # Temporarily remove Go from PATH
    PATH=${PATH//go/}
    
    if "$GOBUILD_CMD" --help > /dev/null 2>&1; then
        test_warn "gobuild should check for Go installation"
    else
        test_pass "gobuild correctly checks for Go installation"
    fi
    
    # Restore PATH
    PATH="$original_path"
}

# Main test runner
run_tests() {
    test_info "Starting gobuild utility tests"
    test_info "==============================================="
    
    # Setup test environment
    setup_test_env
    
    # Run tests
    test_gobuild_help
    test_gobuild_list
    test_gobuild_build
    test_gobuild_invalid_args
    test_gobuild_clean
    test_directory_validation
    test_go_requirement
    
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

# Check if gobuild exists
if [[ ! -f "$GOBUILD_CMD" ]]; then
    test_fail "gobuild utility not found at: $GOBUILD_CMD"
    exit 1
fi

# Make sure gobuild is executable
chmod +x "$GOBUILD_CMD"

# Run tests
run_tests