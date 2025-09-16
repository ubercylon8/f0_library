#!/bin/bash

# Attack Flow HTML Backtick Fixer
# Automatically fixes unescaped backticks in JavaScript template literals
# Specifically targets PowerShell code snippets that cause syntax errors

set -euo pipefail

usage() {
    cat << EOF
Usage: $0 [OPTIONS] <html_file>

Fixes unescaped backticks in attack flow HTML files to prevent JavaScript syntax errors.
Creates a backup of the original file before making changes.

Options:
    -h, --help      Show this help message
    -n, --dry-run   Show what would be changed without making modifications
    -b, --backup    Backup directory (default: same directory with .bak extension)
    -v, --verbose   Show detailed processing output

Examples:
    $0 sample_attack_flow.html
    $0 --dry-run tests_source/akira_attack_flow.html
    $0 -v --backup ./backups sample_attack_flow.html

EOF
}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

VERBOSE=false
DRY_RUN=false
BACKUP_DIR=""

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
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -b|--backup)
            BACKUP_DIR="$2"
            shift 2
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
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1"
    fi
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_info "Processing attack flow HTML: $HTML_FILE"

# Create backup
if [[ "$DRY_RUN" != "true" ]]; then
    if [[ -n "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        BACKUP_FILE="$BACKUP_DIR/$(basename "$HTML_FILE").bak"
    else
        BACKUP_FILE="${HTML_FILE}.bak"
    fi

    cp "$HTML_FILE" "$BACKUP_FILE"
    log_info "Created backup: $BACKUP_FILE"
fi

# Create temporary file for processing
TEMP_FILE=$(mktemp)

log_verbose "Processing file for backtick escaping..."

# Process the file line by line
CHANGES_MADE=0

while IFS= read -r line; do
    ORIGINAL_LINE="$line"

    # Check if we're in a JavaScript context (inside <script> tags)
    if [[ "$line" =~ \<script\> ]]; then
        IN_SCRIPT=true
    elif [[ "$line" =~ \</script\> ]]; then
        IN_SCRIPT=false
    fi

    # If we're in a JavaScript context, look for template literals with PowerShell code
    if [[ "${IN_SCRIPT:-false}" == "true" ]]; then
        # Look for lines containing 'code:' which are likely PowerShell code blocks with template literals
        if echo "$line" | grep -q "code:" && echo "$line" | grep -q '`.*`'; then
            # Extract the content between backticks and escape any backticks inside
            # This is complex to do safely in bash, so we'll use a simple approach:
            # Look for PowerShell line continuation backticks and escape them
            if echo "$line" | grep -E "(Set-Item|Get-Item|New-Item|Remove-Item|ExecutionPolicy|ItemProperty)" >/dev/null; then
                # Look for PowerShell line continuation pattern: backtick at end of line or before newline
                if echo "$line" | grep -q ' `$\| `\\n'; then
                    # Escape the line continuation backticks
                    line=$(echo "$line" | sed 's/ `/  \\`/g')

                    if [[ "$line" != "$ORIGINAL_LINE" ]]; then
                        ((CHANGES_MADE++))
                        log_verbose "Fixed PowerShell line continuation backticks: $(echo "$ORIGINAL_LINE" | head -c 60)..."
                        if [[ "$DRY_RUN" == "true" ]]; then
                            echo -e "${YELLOW}WOULD CHANGE:${NC}"
                            echo -e "  ${RED}FROM:${NC} $ORIGINAL_LINE"
                            echo -e "  ${GREEN}TO:${NC}   $line"
                        fi
                    fi
                fi
            fi
        fi
    fi

    echo "$line" >> "$TEMP_FILE"

done < "$HTML_FILE"

# Summary
if [[ $CHANGES_MADE -eq 0 ]]; then
    log_info "No backtick escaping issues found"
    rm "$TEMP_FILE"
    if [[ "$DRY_RUN" != "true" ]] && [[ -f "$BACKUP_FILE" ]]; then
        rm "$BACKUP_FILE"
        log_info "Removed unnecessary backup file"
    fi
else
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run complete. Would make $CHANGES_MADE change(s)"
        rm "$TEMP_FILE"
    else
        # Replace the original file with the fixed version
        mv "$TEMP_FILE" "$HTML_FILE"
        log_success "Fixed $CHANGES_MADE backtick escaping issue(s)"
        log_info "Original file backed up to: $BACKUP_FILE"
        log_info "Run the validation script to verify the fixes"
    fi
fi

echo
echo "=== PROCESSING SUMMARY ==="
echo "File: $HTML_FILE"
echo "Changes made: $CHANGES_MADE"
if [[ "$DRY_RUN" == "true" ]]; then
    echo "Mode: Dry run (no files modified)"
else
    echo "Mode: Applied fixes"
fi