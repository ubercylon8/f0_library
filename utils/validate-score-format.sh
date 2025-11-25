#!/bin/bash
# Validate test score format compliance for security-test-browser
# Checks that README.md and info.md files use the correct score format

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTS_SOURCE_DIR="$PROJECT_ROOT/tests_source"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNINGS=0

# Regex patterns matching metadataExtractor.ts
README_PATTERN='^\*\*Test Score\*\*: \*\*[0-9]+\.[0-9]+/10\*\*'
INFO_PATTERN='^## Test Score: [0-9]+\.[0-9]+/10'

echo "================================================================="
echo "F0RT1KA Test Score Format Validator"
echo "================================================================="
echo ""
echo "This script validates that test documentation uses the correct"
echo "score format expected by the security-test-browser."
echo ""
echo "Expected formats:"
echo "  README.md: **Test Score**: **9.2/10**"
echo "  info.md:   ## Test Score: 9.2/10"
echo ""
echo "================================================================="
echo ""

# Check if tests_source directory exists
if [ ! -d "$TESTS_SOURCE_DIR" ]; then
    echo -e "${RED}Error: tests_source directory not found at $TESTS_SOURCE_DIR${NC}"
    exit 1
fi

# Function to validate a single test
validate_test() {
    local test_dir="$1"
    local test_uuid=$(basename "$test_dir")
    local has_errors=0
    local has_warnings=0

    # Skip if not a UUID directory
    if [[ ! "$test_uuid" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]]; then
        return
    fi

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    local readme_path="$test_dir/README.md"
    local info_path="$test_dir/${test_uuid}_info.md"

    echo -e "${BLUE}Checking:${NC} $test_uuid"

    # Check README.md
    if [ ! -f "$readme_path" ]; then
        echo -e "  ${YELLOW}⚠${NC}  README.md not found"
        has_warnings=1
    else
        # Extract score line
        local readme_score_line=$(grep -i "Test Score" "$readme_path" 2>/dev/null || echo "")

        if [ -z "$readme_score_line" ]; then
            echo -e "  ${RED}✗${NC}  README.md: No Test Score found"
            has_errors=1
        else
            # Check format
            if echo "$readme_score_line" | grep -qE "$README_PATTERN"; then
                local score=$(echo "$readme_score_line" | grep -oE '[0-9]+\.[0-9]+/10' | head -1)
                echo -e "  ${GREEN}✓${NC}  README.md: Correct format ($score)"
            else
                echo -e "  ${RED}✗${NC}  README.md: Incorrect format"
                echo -e "      Found:    $readme_score_line"
                echo -e "      Expected: **Test Score**: **X.X/10**"
                has_errors=1
            fi
        fi
    fi

    # Check info.md
    if [ ! -f "$info_path" ]; then
        echo -e "  ${YELLOW}⚠${NC}  ${test_uuid}_info.md not found"
        has_warnings=1
    else
        # Extract score header line
        local info_score_line=$(grep -E "^## Test Score:" "$info_path" 2>/dev/null || echo "")

        if [ -z "$info_score_line" ]; then
            echo -e "  ${RED}✗${NC}  info.md: No '## Test Score:' header found"
            echo -e "      Expected header format: ## Test Score: X.X/10"
            has_errors=1
        else
            # Check format
            if echo "$info_score_line" | grep -qE "$INFO_PATTERN"; then
                local score=$(echo "$info_score_line" | grep -oE '[0-9]+\.[0-9]+/10')
                echo -e "  ${GREEN}✓${NC}  info.md: Correct format ($score)"
            else
                echo -e "  ${RED}✗${NC}  info.md: Incorrect format"
                echo -e "      Found:    $info_score_line"
                echo -e "      Expected: ## Test Score: X.X/10"
                has_errors=1
            fi
        fi
    fi

    # Check score consistency
    if [ -f "$readme_path" ] && [ -f "$info_path" ]; then
        local readme_value=$(grep -oE '[0-9]+\.[0-9]+/10' "$readme_path" 2>/dev/null | head -1)
        local info_value=$(grep -oE '[0-9]+\.[0-9]+/10' "$info_path" 2>/dev/null | head -1)

        if [ -n "$readme_value" ] && [ -n "$info_value" ]; then
            if [ "$readme_value" = "$info_value" ]; then
                echo -e "  ${GREEN}✓${NC}  Score consistency: Both files show $readme_value"
            else
                echo -e "  ${RED}✗${NC}  Score mismatch: README has $readme_value, info has $info_value"
                has_errors=1
            fi
        fi
    fi

    echo ""

    # Update counters
    if [ $has_errors -eq 0 ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi

    if [ $has_warnings -eq 1 ]; then
        WARNINGS=$((WARNINGS + 1))
    fi
}

# Process specific test or all tests
if [ -n "$1" ]; then
    # Validate specific test
    if [ -d "$TESTS_SOURCE_DIR/$1" ]; then
        validate_test "$TESTS_SOURCE_DIR/$1"
    else
        echo -e "${RED}Error: Test directory not found: $1${NC}"
        exit 1
    fi
else
    # Validate all tests
    for test_dir in "$TESTS_SOURCE_DIR"/*; do
        if [ -d "$test_dir" ]; then
            validate_test "$test_dir"
        fi
    done
fi

# Summary
echo "================================================================="
echo "VALIDATION SUMMARY"
echo "================================================================="
echo -e "Total tests checked: $TOTAL_TESTS"
echo -e "${GREEN}Passed:${NC} $PASSED_TESTS"
echo -e "${RED}Failed:${NC} $FAILED_TESTS"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ All tests have correct score format!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests have incorrect score format.${NC}"
    echo ""
    echo "To fix score format issues:"
    echo "  README.md: Change to **Test Score**: **X.X/10**"
    echo "  info.md:   Add header ## Test Score: X.X/10"
    echo ""
    echo "See utils/validate-score-format.sh for details."
    exit 1
fi
