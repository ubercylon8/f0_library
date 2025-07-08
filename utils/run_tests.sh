#!/bin/bash

# Test runner for F0RT1KA utilities
# Runs all utility tests and reports results

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Output functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# shellcheck disable=SC2317 # Function may be used in future updates
print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Show usage
show_usage() {
    cat << EOF
F0RT1KA Utilities Test Runner

USAGE:
    $(basename "$0") [OPTIONS]

OPTIONS:
    --verbose       Enable verbose output
    --help          Show this help message

TESTS:
    - gobuild utility tests
    - codesign utility tests

EXAMPLES:
    # Run all tests
    $(basename "$0")

    # Run with verbose output
    $(basename "$0") --verbose
EOF
}

# Run a test script
run_test_script() {
    local test_script="$1"
    local test_name="$2"
    
    print_info "Running $test_name tests..."
    
    if [[ ! -f "$test_script" ]]; then
        print_error "Test script not found: $test_script"
        return 1
    fi
    
    # Make script executable
    chmod +x "$test_script"
    
    # Run the test
    if "$test_script"; then
        print_success "$test_name tests passed"
        ((PASSED_TESTS++))
    else
        print_error "$test_name tests failed"
        ((FAILED_TESTS++))
    fi
    
    ((TOTAL_TESTS++))
}

# Main test runner
run_all_tests() {
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose)
                verbose=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    print_info "F0RT1KA Utilities Test Suite"
    print_info "=============================="
    
    # Set verbose mode if requested
    if [[ "$verbose" == "true" ]]; then
        export VERBOSE=true
    fi
    
    # Run gobuild tests
    run_test_script "$TEST_DIR/test_gobuild.sh" "gobuild"
    
    # Run codesign tests
    run_test_script "$TEST_DIR/test_codesign.sh" "codesign"
    
    # Report overall results
    echo
    print_info "=============================="
    print_info "Overall Test Results:"
    print_info "Total test suites: $TOTAL_TESTS"
    print_info "Passed: $PASSED_TESTS"
    print_info "Failed: $FAILED_TESTS"
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        print_success "All test suites passed!"
        exit 0
    else
        print_error "Some test suites failed"
        exit 1
    fi
}

# Check if we're in the correct directory
if [[ ! -f "$TEST_DIR/gobuild" ]] || [[ ! -f "$TEST_DIR/codesign" ]]; then
    print_error "Utilities not found in current directory"
    print_info "Please run this script from the utils/ directory"
    exit 1
fi

# Run all tests
run_all_tests "$@"