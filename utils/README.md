# F0RT1KA Utilities

This directory contains utility scripts for building and signing security tests in the F0RT1KA framework.

## Available Utilities

### 1. gobuild - Test Builder

A comprehensive build utility for compiling security tests with cross-platform support.

#### Features
- Cross-platform compilation (Windows, Linux, macOS)
- Multiple architecture support (amd64, 386, arm64)
- Build individual tests or all tests
- Validation of test structure
- Colored output and verbose logging

#### Usage Examples
```bash
# List all available tests
./utils/gobuild list

# Build a specific test for Windows (default)
./utils/gobuild build tests_source/ecd2514c-512a-4251-a6f4-eb3aa834d401

# Build for Linux
./utils/gobuild --os linux build tests_source/ecd2514c-512a-4251-a6f4-eb3aa834d401

# Build all tests
./utils/gobuild build-all

# Build with custom output directory
./utils/gobuild --output dist/ build-all

# Clean build artifacts
./utils/gobuild clean
```

#### Requirements
- Go 1.21 or higher
- Valid test structure in `tests_source/`

### 2. codesign - Code Signing Utility

A utility for signing Windows executables using osslsigncode with support for certificate management.

#### Features
- Interactive certificate selection
- Secure password prompting
- Batch signing of multiple binaries
- Signature verification
- Timestamping support
- Certificate listing

#### Usage Examples
```bash
# List available certificates
./utils/codesign list-certs

# Sign a binary (interactive certificate selection)
./utils/codesign sign build/test-uuid/test-uuid.exe

# Sign with specific certificate
./utils/codesign --cert signing-certs/mycert.pfx sign build/test-uuid/test-uuid.exe

# Sign all binaries in build directory
./utils/codesign sign-all

# Sign with metadata
./utils/codesign --cert signing-certs/mycert.pfx \
    --description "F0RT1KA Security Test" \
    --url "https://github.com/ubercylon8/f0_library" \
    sign build/test-uuid/test-uuid.exe

# Verify a signature
./utils/codesign verify build/test-uuid/test-uuid.exe
```

#### Requirements
- osslsigncode installed
- Code signing certificates in PFX/P12 format
- Certificates placed in `signing-certs/` directory

#### Installation of osslsigncode
```bash
# macOS
brew install osslsigncode

# Ubuntu/Debian
sudo apt-get install osslsigncode

# CentOS/RHEL
sudo yum install osslsigncode
```

### 3. Check-DefenderProtection.ps1 - Windows Defender Status Checker

A PowerShell utility that verifies Windows Defender protection status by examining registry settings targeted by malware like CyberEye RAT.

#### Features
- Checks critical Windows Defender registry values
- Determines if host is protected or vulnerable
- Color-coded output for easy status identification
- Verifies Tamper Protection, Anti-Spyware, and Real-Time Protection settings
- Queries actual Defender status via PowerShell cmdlets

#### Usage Examples
```powershell
# Run with Administrator privileges
powershell -ExecutionPolicy Bypass -File ./utils/Check-DefenderProtection.ps1
```

#### Registry Keys Checked
- `HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection`
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScanOnRealtimeEnable`

#### Output Interpretation
- **PROTECTED** (Green): Registry values indicate Defender features are enabled
- **VULNERABLE** (Red): One or more Defender features are disabled via registry
- **Not Set**: Registry key doesn't exist (default protection applies)

#### Requirements
- Windows PowerShell 5.0 or higher
- Administrator privileges
- Windows 10/11 or Windows Server 2016+

### 4. validate-attack-flow-html.sh - Attack Flow HTML Validator

A validation utility for checking attack flow HTML diagrams for JavaScript syntax errors, specifically focusing on unescaped backticks that cause "Invalid or unexpected token" errors in template literals.

#### Features
- Detects unescaped backticks in JavaScript template literals
- Validates PowerShell code block syntax
- Checks HTML structure and required components
- Verifies MITRE ATT&CK technique mappings
- Color-coded output with detailed error reporting
- Support for verbose and quiet modes

#### Usage Examples
```bash
# Validate a single HTML file
./utils/validate-attack-flow-html.sh sample_attack_flow.html

# Verbose validation with detailed output
./utils/validate-attack-flow-html.sh -v tests_source/akira_attack_flow.html

# Quiet mode - only show errors
./utils/validate-attack-flow-html.sh -q *.html

# Validate multiple files
find tests_source/ -name "*.html" -exec ./utils/validate-attack-flow-html.sh {} \;
```

#### Validation Checks
- **Backtick Escaping**: Detects unescaped backticks in template literals
- **PowerShell Syntax**: Validates PowerShell code blocks for proper escaping
- **HTML Structure**: Verifies presence of required script tags and functions
- **MITRE Mappings**: Checks for MITRE ATT&CK technique references
- **CSS Classes**: Validates required CSS classes for interactive components
- **Template Literals**: Identifies malformed JavaScript template literals

#### Exit Codes
- **0**: Validation passed (no errors)
- **1**: Validation failed (errors found that need fixing)

#### Requirements
- Bash 4.0 or higher
- grep, sed utilities

### 5. fix-attack-flow-backticks.sh - Attack Flow HTML Backtick Fixer

An automatic repair utility that fixes unescaped backticks in attack flow HTML files to prevent JavaScript syntax errors. Creates backups before making changes.

#### Features
- Automatically escapes unescaped backticks in PowerShell code snippets
- Creates backup copies before making changes
- Dry-run mode to preview changes without modification
- Targeted fixing for JavaScript template literals
- Safe processing that preserves legitimate template literals
- Color-coded output showing changes made

#### Usage Examples
```bash
# Fix backticks in a file (creates backup automatically)
./utils/fix-attack-flow-backticks.sh sample_attack_flow.html

# Dry run to see what would be changed
./utils/fix-attack-flow-backticks.sh --dry-run sample_attack_flow.html

# Verbose output with detailed processing
./utils/fix-attack-flow-backticks.sh -v tests_source/akira_attack_flow.html

# Custom backup directory
./utils/fix-attack-flow-backticks.sh --backup ./backups sample_attack_flow.html
```

#### Processing Logic
- Identifies JavaScript template literals containing PowerShell commands
- Escapes unescaped backticks in PowerShell code snippets
- Preserves legitimate template literal syntax
- Handles backticks at line beginnings and within content
- Creates automatic backups for safety

#### Backup Handling
- Default: Creates `.bak` file in same directory
- Custom: Use `--backup` to specify backup directory
- Automatic cleanup if no changes needed

#### Requirements
- Bash 4.0 or higher
- sed, grep utilities
- Write permissions in target directory

### 6. example-backtick-fix.js - Backtick Escaping Demo

A Node.js script that demonstrates the JavaScript template literal backtick escaping issue and shows the correct solution. This educational tool helps understand why the validation and fix utilities are necessary.

#### Features
- Shows problematic PowerShell code patterns that break JavaScript
- Demonstrates correct backtick escaping techniques
- Provides working code examples
- Explains the root cause of "Invalid or unexpected token" errors
- Lists common PowerShell patterns that need escaping

#### Usage Examples
```bash
# Run the demo to understand the issue and solution
node utils/example-backtick-fix.js

# Use Node.js if available
./utils/example-backtick-fix.js
```

#### Key Learning Points
- PowerShell line continuation backticks (`) must be escaped as (\\`) inside JavaScript template literals
- Template literal delimiters (outer backticks) should NOT be escaped
- Only escape backticks that are CONTENT within the template literal
- Test generated HTML in browser console to verify syntax

#### Requirements
- Node.js (any recent version)
- No additional dependencies

### 7. lc_events_query.py - LimaCharlie Events Query Tool

A Python utility for querying LimaCharlie sensor events specifically for F0RT1KA security test analysis with detailed reporting capabilities.

#### Features
- Query events by test UUID and date range using LCQL
- Generate formatted tables with key event data
- Provide statistics on error codes and test outcomes
- Show endpoints tested with event timestamps
- Support multiple output formats (table, JSON, CSV)
- Flexible authentication via environment variables or .env files

#### Usage Examples
```bash
# Query events using .env file credentials
python3 utils/lc_events_query.py --uuid "abc123def456" --date-range "last 24 hours"

# Query with explicit credentials
python3 utils/lc_events_query.py --uuid "abc123def456" --date-range "last 24 hours" -k API_KEY -o ORG_ID

# Show only endpoints tested
python3 utils/lc_events_query.py --uuid "abc123def456" --date-range "last 7 days" --hostnames

# Export to JSON for further processing
python3 utils/lc_events_query.py --uuid "abc123def456" --date-range "today" --output results.json
```

#### Authentication Methods
- Command line: `-k API_KEY -o ORG_ID`
- Environment variables: `LIMACHARLIE_API_KEY`, `LIMACHARLIE_OID`
- .env file: `LC_API_KEY`, `LC_ORG_ID`
- Custom .env file: `--env-file path/to/.env`

#### Requirements
- Python 3.7+
- LimaCharlie sensor binary (`lc-sensors`) in PATH or F0_CST/bin/
- Valid LimaCharlie API key and Organization ID
- Optional: python-dotenv package for enhanced .env support

### 8. combine_test_results.py - Combined Security Analysis Tool

A comprehensive Python utility that correlates LimaCharlie sensor events with Microsoft Defender alerts for F0RT1KA security test analysis, providing unified visibility across security platforms.

#### Features
- Correlates LimaCharlie events with Microsoft Defender alerts by hostname and timestamp
- Flexible hostname matching supports both FQDN and short hostnames
- Configurable time window for correlation matching (default: 5 minutes)
- Comprehensive correlation statistics and success rates
- Detailed analysis of unmatched events with time differences
- Multiple output formats (table, JSON)
- Dual authentication support for both LimaCharlie and Microsoft Defender

#### Usage Examples
```bash
# Basic correlation analysis
python3 utils/combine_test_results.py --uuid "abc123def456" --date-range "last 24 hours"

# Export to JSON for further processing
python3 utils/combine_test_results.py --uuid "abc123def456" --date-range "today" --output results.json

# Custom time window for correlation
python3 utils/combine_test_results.py --uuid "abc123def456" --date-range "last 7 days" --time-window 10

# Use custom .env file for credentials
python3 utils/combine_test_results.py --uuid "abc123def456" --date-range "today" --env-file custom.env
```

#### Authentication Requirements
**LimaCharlie**: API key and Organization ID via environment variables or .env file
**Microsoft Defender**: Azure tenant ID, client ID, and client secret

#### Key Capabilities
- **High Correlation Rates**: Typically achieves 90%+ correlation between platforms
- **Hostname Normalization**: Matches `DESKTOP-ABC123` with `DESKTOP-ABC123.domain.com`
- **Time-based Correlation**: Finds alerts within configurable time windows
- **Unmatched Analysis**: Explains why events didn't correlate (hostname mismatch, time difference)
- **Comprehensive Statistics**: Error code distribution, severity analysis, per-endpoint breakdown

#### Requirements
- Python 3.7+
- Both `lc_events_query.py` and `defender_alert_query.py` utilities
- LimaCharlie credentials (API key, Org ID)
- Microsoft Defender credentials (Azure tenant, client ID, secret)
- Optional: python-dotenv package for .env file support

---

## Validation Utilities

### validate - Test Results Validation Wrapper

Wrapper script that checks dependencies and invokes `validate_test_results.py`.

```bash
./utils/validate build/<uuid>/test_execution_log.json   # Single file
./utils/validate --directory build/<uuid>/               # Directory
./utils/validate --all                                   # All results in build/
```

### validate_test_results.py - Schema v2.0 Validator

Validates test result JSON files against Schema v2.0 structure requirements.

```bash
python3 utils/validate_test_results.py build/<uuid>/test_execution_log.json
python3 utils/validate_test_results.py --all
```

### validate-score-format.sh - Score Format Checker

Validates that README.md and info.md files use the correct score format patterns expected by the metadata extractor.

```bash
./utils/validate-score-format.sh              # All tests
./utils/validate-score-format.sh <test-uuid>  # Specific test
```

### validate-reference-urls.py - Reference URL Validator

Validates URLs in `_references.md` files for HTTP status, MITRE ATT&CK technique correctness, and broken links.

```bash
python3 utils/validate-reference-urls.py                    # All tests
python3 utils/validate-reference-urls.py --uuid <test-uuid> # Specific test
python3 utils/validate-reference-urls.py --fix              # Auto-fix known broken URLs
python3 utils/validate-reference-urls.py --dry-run          # Preview fixes
```

### fix-broken-urls.py - URL Fixer

Maps and fixes known broken URLs in `_references.md` files using predefined replacements (e.g., `docs.microsoft.com` → `learn.microsoft.com` migrations).

```bash
python3 utils/fix-broken-urls.py  # Operates on files in place
```

---

## Elasticsearch Utilities

### sync-test-catalog-to-elasticsearch.py - Test Catalog Sync

Synchronizes test metadata from `tests_source/` to Elasticsearch for the enrichment pipeline.

```bash
source .venv/bin/activate
python3 utils/sync-test-catalog-to-elasticsearch.py
python3 utils/sync-test-catalog-to-elasticsearch.py --dry-run
```

### create-kibana-dashboard.py - Dashboard Generator

Creates visualizations and dashboards for F0RT1KA test results in Kibana using the Saved Objects API.

```bash
python3 utils/create-kibana-dashboard.py
python3 utils/create-kibana-dashboard.py --dry-run
python3 utils/create-kibana-dashboard.py --delete  # Remove dashboards
```

### generate-synthetic-test-data.py - Synthetic Data Generator

Generates synthetic enriched RECEIPT events for Elasticsearch visualization experimentation.

```bash
python3 utils/generate-synthetic-test-data.py
python3 utils/generate-synthetic-test-data.py --count 500 --dry-run
```

### upload-legacy-results.py - Legacy Results Uploader

Enriches historical test execution results with metadata and uploads them to Elasticsearch.

```bash
python3 utils/upload-legacy-results.py --input results.json
python3 utils/upload-legacy-results.py --input results.json --dry-run --verbose
```

### f0_collector - Test Result Collector

Lightweight Go utility for collecting F0RT1KA test result JSON files from Windows endpoints and exporting to Elasticsearch with schema v2.0 validation and state management.

```bash
# Build and deploy
cd utils/f0_collector && go build -o f0_collector.exe .
# Deploy via PowerShell
powershell -File utils/f0_collector/deploy-collector-task.ps1
```

### resolve_es.sh - Elasticsearch Profile Resolver

Bash helper library for resolving Elasticsearch profile identifiers to endpoints, indices, and API keys from `elasticsearch-registry.json`.

```bash
source utils/resolve_es.sh
resolve_es_to_endpoint "production"
resolve_es_to_index "production"
resolve_es_to_apikey "production"
```

---

## Analytics & Querying Utilities

### get_tests.py - Test Catalog Lister

Displays all F0RT1KA security tests in a paginated formatted table.

```bash
python3 utils/get_tests.py      # Page 1 (default)
python3 utils/get_tests.py 2    # Page 2
```

### analyze_test_results.py - Test Result Analyzer

Analyzes LCQL NDJSON query results for test execution events, providing analysis of ERROR codes, STDOUT/STDERR patterns, and protection metrics.

```bash
python3 utils/analyze_test_results.py rga_all_tests.json tpsgl_all_tests.json
python3 utils/analyze_test_results.py --output-dir ./analysis_output results.json
python3 utils/analyze_test_results.py --console-only results.json
```

### defender_alert_query.py - Microsoft Defender Alert Query

Queries Microsoft Defender 365 alerts for security testing workflows using Azure AD service principal authentication.

```bash
python3 utils/defender_alert_query.py --days 7
python3 utils/defender_alert_query.py --severity high --search-term "F0RT1KA"
python3 utils/defender_alert_query.py --output alerts.json --env-file .env
```

### update-severity.py - Severity Updater

Updates severity assignments in test Go files based on MITRE ATT&CK technique mapping using F0RT1KA Severity Framework v2.

```bash
python3 utils/update-severity.py  # Auto-scans tests_source/
```

---

## Certificate Management Utilities

### Install-F0RT1KA-Certificate.ps1 - Certificate Installer

Installs the F0RT1KA code signing certificate to the Trusted Root store with embedded Base64-encoded certificate. Requires admin privileges.

```powershell
powershell -ExecutionPolicy Bypass -File ./utils/Install-F0RT1KA-Certificate.ps1
```

### Check-F0RT1KA-Certificate.ps1 - Certificate Diagnostic

Diagnostic tool for troubleshooting F0RT1KA certificate installation — checks execution context, Root Store, test logs, and certificate validity.

```powershell
powershell -ExecutionPolicy Bypass -File ./utils/Check-F0RT1KA-Certificate.ps1
```

### resolve_org.sh - Organization Certificate Resolver

Bash helper library for resolving organization identifiers to certificate file paths from `organization-registry.json`.

```bash
source utils/resolve_org.sh
resolve_org_to_cert "sb"
```

---

## Documentation Utilities

### generate-retroactive-references.py - References Generator

Generates `_references.md` files for existing tests by extracting data from info.md References sections and Go metadata headers.

```bash
python3 utils/generate-retroactive-references.py
python3 utils/generate-retroactive-references.py --uuid <test-uuid>
python3 utils/generate-retroactive-references.py --dry-run
```

### Monitor-RegistryChanges.ps1 - Registry Change Monitor

Monitors and displays recent Windows registry changes via WMI events, audit logs, and snapshot comparisons. Requires admin privileges.

```powershell
powershell -ExecutionPolicy Bypass -File ./utils/Monitor-RegistryChanges.ps1
```

---

## Testing Utilities

### run_tests.sh - Utility Test Runner

Runs all utility unit tests with colored pass/fail reporting.

```bash
./utils/run_tests.sh
./utils/run_tests.sh --verbose
```

### test_codesign.sh / test_gobuild.sh - Unit Tests

Unit test suites for the `codesign` and `gobuild` utilities.

```bash
./utils/test_codesign.sh
./utils/test_gobuild.sh
```

### templates/build_multistage_template.sh - Build Template

Template automating the multi-stage build process where each ATT&CK technique is a separate signed binary embedded in the main orchestrator.

---

## Typical Workflow

### Test Development and Building

1. **Build Tests**:
   ```bash
   ./utils/gobuild build-all
   ```

2. **Sign Binaries**:
   ```bash
   ./utils/codesign sign-all
   ```

3. **Verify Signatures**:
   ```bash
   find build/ -name "*.exe" -exec ./utils/codesign verify {} \;
   ```

### Attack Flow Diagram Development

1. **Validate Generated HTML**:
   ```bash
   ./utils/validate-attack-flow-html.sh tests_source/your_attack_flow.html
   ```

2. **Fix Backtick Issues (if needed)**:
   ```bash
   # Preview fixes first
   ./utils/fix-attack-flow-backticks.sh --dry-run tests_source/your_attack_flow.html

   # Apply fixes
   ./utils/fix-attack-flow-backticks.sh tests_source/your_attack_flow.html
   ```

3. **Re-validate After Fixes**:
   ```bash
   ./utils/validate-attack-flow-html.sh tests_source/your_attack_flow.html
   ```

4. **Batch Validation of All HTML Files**:
   ```bash
   find tests_source/ -name "*attack_flow*.html" -exec ./utils/validate-attack-flow-html.sh {} \;
   ```

### Elasticsearch Sync

1. **Sync test catalog** after creating/updating tests:
   ```bash
   source .venv/bin/activate
   python3 utils/sync-test-catalog-to-elasticsearch.py
   ```

2. **Re-execute enrichment policy** in Kibana Dev Tools:
   ```
   POST /_enrich/policy/f0rtika-test-enrichment/_execute
   ```

3. **Create/update dashboards**:
   ```bash
   python3 utils/create-kibana-dashboard.py
   ```

### Validation Workflow

1. **Validate test results**:
   ```bash
   ./utils/validate --all
   ```

2. **Check score formats**:
   ```bash
   ./utils/validate-score-format.sh
   ```

3. **Validate reference URLs**:
   ```bash
   python3 utils/validate-reference-urls.py
   ```

## Configuration

### Certificate Management
- Place certificates in `signing-certs/` directory
- Supported formats: `.pfx`, `.p12`
- Certificates should be password-protected

### Build Configuration
- Default target: Windows/amd64
- Default output: `build/` directory
- Each test builds to its own subdirectory

### Defender API Setup
See `utils/setup_defender_api.md` for Azure AD app registration, API permissions, and environment variable configuration.

## Error Handling

Utilities include comprehensive error handling:
- Input validation
- File existence checks
- Tool availability verification
- Clear error messages with colored output

## Security Considerations

- **Certificate Security**: Store certificates securely and use strong passwords
- **Password Handling**: Passwords are prompted securely and not logged
- **Binary Integrity**: Always verify signatures after signing
- **Access Control**: Limit access to signing certificates
- **API Credentials**: Use `.env` files (gitignored) for API keys, never hardcode

## Troubleshooting

### Common Issues

1. **Go not found**: Ensure Go 1.21+ is installed and in PATH
2. **osslsigncode not found**: Install using package manager
3. **Certificate not found**: Check `signing-certs/` directory
4. **Permission denied**: Ensure scripts are executable (`chmod +x`)
5. **Build failures**: Check test structure and go.mod files
6. **ES sync fails**: Verify `.env` has correct ES endpoint and API key
7. **Defender query fails**: Check Azure AD credentials in `.env` (see `setup_defender_api.md`)

### Verbose Output
Most utilities support `--verbose` or `--dry-run` flags for debugging.