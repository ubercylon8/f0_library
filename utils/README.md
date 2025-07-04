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

## Typical Workflow

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

## Configuration

### Certificate Management
- Place certificates in `signing-certs/` directory
- Supported formats: `.pfx`, `.p12`
- Certificates should be password-protected

### Build Configuration
- Default target: Windows/amd64
- Default output: `build/` directory
- Each test builds to its own subdirectory

## Error Handling

Both utilities include comprehensive error handling:
- Input validation
- File existence checks
- Tool availability verification
- Clear error messages with colored output

## Security Considerations

- **Certificate Security**: Store certificates securely and use strong passwords
- **Password Handling**: Passwords are prompted securely and not logged
- **Binary Integrity**: Always verify signatures after signing
- **Access Control**: Limit access to signing certificates

## Troubleshooting

### Common Issues

1. **Go not found**: Ensure Go 1.21+ is installed and in PATH
2. **osslsigncode not found**: Install using package manager
3. **Certificate not found**: Check `signing-certs/` directory
4. **Permission denied**: Ensure scripts are executable (`chmod +x`)
5. **Build failures**: Check test structure and go.mod files

### Verbose Output
Both utilities support `--verbose` flag for detailed debugging information.

## Integration with CLAUDE.md

These utilities are referenced in the main CLAUDE.md file for AI-assisted development. Future Claude instances will know to use these tools for building and signing tests.