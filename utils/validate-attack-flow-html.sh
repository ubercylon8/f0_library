#!/bin/bash

# Attack Flow HTML Validation Utility
# Checks generated HTML files for JavaScript template literal syntax errors
# Specifically focuses on unescaped backticks that cause "Invalid or unexpected token" errors

set -euo pipefail

usage() {
    cat << EOF
Usage: $0 [OPTIONS] <html_file>

Validates attack flow HTML files for JavaScript syntax errors, specifically:
- Unescaped backticks in template literals
- PowerShell code block syntax issues
- Interactive component functionality

Options:
    -h, --help      Show this help message
    -v, --verbose   Show detailed validation output
    -q, --quiet     Only show errors

Examples:
    $0 sample_attack_flow.html
    $0 -v tests_source/akira_attack_flow.html
    $0 --quiet *.html

EOF
}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

VERBOSE=false
QUIET=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -*)
            echo "Unknown option $1"
            usage
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -eq 0 ]]; then
    echo "Error: No HTML file specified"
    usage
    exit 1
fi

HTML_FILE="$1"

if [[ ! -f "$HTML_FILE" ]]; then
    echo -e "${RED}Error: File '$HTML_FILE' not found${NC}"
    exit 1
fi

log_info() {
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1"
    fi
}

log_warning() {
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${YELLOW}[WARNING]${NC} $1"
    fi
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${GREEN}[SUCCESS]${NC} $1"
    fi
}

# Validation counters
ERRORS=0
WARNINGS=0

log_info "Validating attack flow HTML: $HTML_FILE"

# Check 1: Look for unescaped backticks in template literals
log_verbose "Checking for unescaped backticks in template literals..."

# Extract JavaScript content
JS_CONTENT=$(sed -n '/<script>/,/<\/script>/p' "$HTML_FILE" | grep -v '<script>' | grep -v '<\/script>')

# Look for template literals with unescaped backticks
UNESCAPED_BACKTICKS=$(echo "$JS_CONTENT" | grep -n '`[^`]*`[^`]*`' | grep -v '\\`' || true)

if [[ -n "$UNESCAPED_BACKTICKS" ]]; then
    log_error "Found potential unescaped backticks in template literals:"
    echo "$UNESCAPED_BACKTICKS" | while read -r line; do
        log_error "  Line: $line"
    done
    ((ERRORS++))
else
    log_verbose "No unescaped backticks found in template literals"
fi

# Check 2: Look for PowerShell code blocks with backticks
log_verbose "Checking PowerShell code blocks for proper backtick escaping..."

POWERSHELL_BACKTICKS=$(echo "$JS_CONTENT" | grep -n 'Set-ItemProperty\|Get-ItemProperty\|New-Item\|Remove-Item' | grep '`' | grep -v '\\`' || true)

if [[ -n "$POWERSHELL_BACKTICKS" ]]; then
    log_error "Found PowerShell code with unescaped backticks:"
    echo "$POWERSHELL_BACKTICKS" | while read -r line; do
        log_error "  Line: $line"
    done
    ((ERRORS++))
else
    log_verbose "PowerShell code blocks properly escaped"
fi

# Check 3: Look for common JavaScript syntax patterns that might be broken
log_verbose "Checking for common JavaScript syntax issues..."

# Check for malformed template literals
MALFORMED_TEMPLATES=$(echo "$JS_CONTENT" | grep -n '`[^`]*$' || true)

if [[ -n "$MALFORMED_TEMPLATES" ]]; then
    log_warning "Found potentially malformed template literals:"
    echo "$MALFORMED_TEMPLATES" | while read -r line; do
        log_warning "  Line: $line"
    done
    ((WARNINGS++))
fi

# Check 4: Verify HTML structure
log_verbose "Checking HTML structure..."

if ! grep -q '<script>' "$HTML_FILE"; then
    log_error "No JavaScript <script> tag found"
    ((ERRORS++))
fi

if ! grep -q 'phaseData' "$HTML_FILE"; then
    log_error "No phaseData object found - interactive functionality may be broken"
    ((ERRORS++))
fi

if ! grep -q 'showPhaseDetails' "$HTML_FILE"; then
    log_error "No showPhaseDetails function found - interactive functionality may be broken"
    ((ERRORS++))
fi

# Check 5: Look for MITRE ATT&CK technique references
log_verbose "Checking MITRE ATT&CK technique mappings..."

MITRE_TECHNIQUES=$(grep -o 'T[0-9]\{4\}' "$HTML_FILE" | sort -u || true)

if [[ -z "$MITRE_TECHNIQUES" ]]; then
    log_warning "No MITRE ATT&CK technique references found"
    ((WARNINGS++))
else
    log_verbose "Found MITRE techniques: $(echo "$MITRE_TECHNIQUES" | tr '\n' ' ')"
fi

# Check 6: Verify template structure matches samples
log_verbose "Checking template structure consistency..."

REQUIRED_CLASSES=("component" "timeline-item" "details-panel" "architecture-svg")

for class in "${REQUIRED_CLASSES[@]}"; do
    if ! grep -q "class=\"$class\"" "$HTML_FILE"; then
        log_warning "Missing required CSS class: $class"
        ((WARNINGS++))
    fi
done

# Summary
echo
echo "=== VALIDATION SUMMARY ==="
echo "File: $HTML_FILE"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

if [[ $ERRORS -eq 0 ]]; then
    log_success "HTML file passed validation! No syntax errors detected."
    if [[ $WARNINGS -gt 0 ]]; then
        log_warning "$WARNINGS warning(s) found - review recommended"
    fi
    exit 0
else
    log_error "$ERRORS error(s) found - HTML file needs fixes before use"
    exit 1
fi