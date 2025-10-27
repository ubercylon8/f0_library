# F0RT1KA Security Testing Framework

[![Build Status](https://github.com/ubercylon8/f0_library/actions/workflows/build.yml/badge.svg)](https://github.com/ubercylon8/f0_library/actions/workflows/build.yml)
[![Security Scan](https://github.com/ubercylon8/f0_library/actions/workflows/security.yml/badge.svg)](https://github.com/ubercylon8/f0_library/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shellcheck](https://img.shields.io/badge/shellcheck-passing-brightgreen.svg)](https://www.shellcheck.net/)

A comprehensive security testing framework for evaluating endpoint detection and response (EDR) capabilities against real-world attack techniques mapped to the MITRE ATT&CK framework.

## Overview

F0RT1KA is a professional, open-source security testing framework designed to assess the effectiveness of endpoint detection and response (EDR) solutions. By simulating real-world attack techniques mapped to the MITRE ATT&CK framework, it provides security teams with a standardized approach to validate their defensive capabilities.

This repository serves as the main tools repository for testing execution frameworks and includes comprehensive documentation, automated testing, and security scanning to ensure code quality and safety.

## Purpose

- **Security Validation**: Test and validate the detection and prevention capabilities of security solutions
- **MITRE ATT&CK Alignment**: All tests are mapped to specific MITRE ATT&CK techniques for standardized threat assessment
- **Automated Testing**: Provide a structured approach to security testing with consistent result codes
- **Research & Development**: Enable security teams to understand gaps in their defensive posture

## 🚀 Project Status

This project is **actively maintained** and **ready for community contributions**. We have:

- ✅ **Comprehensive Documentation**: Architecture, development guides, and API docs
- ✅ **Automated CI/CD**: All tests and security scans passing
- ✅ **Community Standards**: Code of conduct, contributing guidelines, and templates
- ✅ **Security First**: Vulnerability disclosure policy and automated security scanning
- ✅ **Professional Structure**: Clean codebase with proper testing and versioning

## Key Features

- **Standardized Test Structure**: Consistent format for all security tests
- **Binary Drop Testing**: Controlled testing of malicious binary detection
- **Execution Prevention Testing**: Validate runtime protection mechanisms
- **Result Code System**: Clear success/failure metrics (101, 105, 126)
- **Windows-Focused**: Optimized for Windows endpoint testing
- **Cross-Platform Building**: Build utilities for Windows, Linux, and macOS
- **Code Signing Support**: Integrated Windows executable signing with certificates

## Project Structure

```
f0_library/
├── .github/               # GitHub workflows and templates
│   ├── ISSUE_TEMPLATE/   # Issue templates for bugs and features
│   ├── workflows/        # CI/CD workflows (build, security)
│   └── pull_request_template.md
├── docs/                  # Documentation
│   ├── ARCHITECTURE.md   # System architecture overview
│   ├── DEVELOPMENT.md    # Developer setup guide
│   └── windows-ssh-setup.md # SSH configuration guide
├── sample_tests/          # Reference test implementations
├── tests_source/          # Active test development directory
├── rules/                 # Development guidelines and standards
├── signing-certs/         # Code signing certificates
├── utils/                 # Build and signing utilities
│   ├── gobuild           # Cross-platform test builder
│   ├── codesign          # Code signing utility
│   ├── Check-DefenderProtection.ps1 # Windows Defender status checker
│   ├── defender_alert_query.py # Microsoft Defender alerts query tool
│   ├── lc_events_query.py # LimaCharlie sensor events query tool
│   ├── combine_test_results.py # Combined security analysis tool
│   ├── test_*.sh         # Unit tests for utilities
│   ├── run_tests.sh      # Test runner
│   └── README.md         # Utility documentation
├── preludeorg-libraries/  # Prelude testing framework (setup required)
├── CLAUDE.md             # AI-assisted development guide
├── CONTRIBUTING.md       # Contribution guidelines
├── CODE_OF_CONDUCT.md    # Community standards
├── SECURITY.md           # Security policy
├── CHANGELOG.md          # Version history
├── LICENSE               # MIT License
└── README.md             # This file
```

## Getting Started

### Prerequisites

- **Go 1.21+**: Required for building tests
- **Python 3.7+**: Required for security analysis tools
- **Windows Environment**: Tests are designed for Windows systems
- **Prelude Libraries**: Must be configured in the `preludeorg-libraries/` directory
- **Administrator Access**: Some tests require elevated privileges
- **osslsigncode** (optional): For code signing Windows executables
- **Windows SDK** (optional): Recommended for signing Windows executables in a Windows environment

### Quick Start

1. **Clone the repository**:
```bash
git clone https://github.com/ubercylon8/f0_library.git
cd f0_library
```

2. **Read the documentation**:
   - [Development Guide](docs/DEVELOPMENT.md) - Complete setup instructions
   - [Architecture Overview](docs/ARCHITECTURE.md) - System design
   - [Contributing Guidelines](CONTRIBUTING.md) - How to contribute

3. **Set up Prelude libraries** (required for test compilation):
```bash
# Instructions for Prelude setup will be provided in future documentation
```

4. **Install dependencies** (optional):
```bash
# macOS
brew install osslsigncode

# Ubuntu/Debian
sudo apt-get install osslsigncode

# Windows
winget install Microsoft.WindowsSDK
```

### Building Tests

Use the provided `gobuild` utility for cross-platform compilation:

```bash
# Build a specific test (Windows/amd64 by default)
./utils/gobuild build tests_source/<test-uuid>/

# Build for different platforms
./utils/gobuild --os linux --arch amd64 build tests_source/<test-uuid>/

# Build all tests
./utils/gobuild build-all

# List available tests
./utils/gobuild list
```

### Code Signing

Sign Windows executables using the `codesign` utility:

```bash
# Sign a specific binary (interactive certificate selection)
./utils/codesign sign build/<test-uuid>/<test-uuid>.exe

# Sign all binaries in build directory
./utils/codesign sign-all

# Verify signature
./utils/codesign verify build/<test-uuid>/<test-uuid>.exe
```

Sign Windows executables using the `Windows SDK` utility:

```bash
# Search signtool.exe in your system (For Example)

C:\Program Files (x86)\Windows Kits\<Windows Version>\bin\<SDK Version>\x64\signtool.exe

# Sign a specific binary
signtool.exe sign /f signing-certs/MyCert.pfx /p <MyCertPassword> /fd SHA256 build/<test-uuid>/<test-uuid>.exe

# Verify signature
signtool.exe verify build/<test-uuid>/<test-uuid>.exe
```

### Windows Defender Protection Check

Use the Windows Defender protection checker to verify security posture:

```powershell
# Check if Windows Defender is properly configured (run as Administrator)
powershell -ExecutionPolicy Bypass -File ./utils/Check-DefenderProtection.ps1
```

This utility examines registry settings targeted by malware (like CyberEye RAT) and reports whether the host is protected or vulnerable. The script automatically handles execution policy bypass and requires administrator privileges.

### Security Analysis Tools

Query and analyze security test results across multiple platforms:

```bash
# Query LimaCharlie sensor events for a test
python3 utils/lc_events_query.py --uuid "test-uuid" --date-range "last 24 hours"

# Query Microsoft Defender alerts for a test
python3 utils/defender_alert_query.py --test-alerts "test-uuid" --fetch-all

# Correlate results from both platforms
python3 utils/combine_test_results.py --uuid "test-uuid" --date-range "last 24 hours"
```

These tools provide comprehensive analysis of security test outcomes, including:
- Event correlation between LimaCharlie and Microsoft Defender
- Hostname normalization and flexible matching
- Time-based correlation with configurable windows
- Detailed statistics on detection rates and test outcomes
- Analysis of unmatched events with explanations

### Running Tests

Run the utility test suite to ensure everything is working:

```bash
# Run all utility tests
./utils/run_tests.sh

# Run with verbose output
./utils/run_tests.sh --verbose

# Run specific test
./utils/test_gobuild.sh
./utils/test_codesign.sh
```

**Note**: Tests are automatically run on every push via GitHub Actions. Check the [build status](https://github.com/ubercylon8/f0_library/actions) for CI results.

## Test Development

### PowerShell Development Guidelines

All created PowerShell scripts must follow these security requirements:

- **Admin Privilege Check**: Include a function to verify administrator privileges
- **Execution Policy Bypass**: Implement automatic execution policy bypass functionality
- **Error Handling**: Proper exception handling for security operations
- **Logging**: Use appropriate output formatting with color coding

Example pattern for PowerShell scripts:
```powershell
#Requires -RunAsAdministrator

# Function to check if running with admin privileges
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to check and bypass execution policy
function Bypass-ExecutionPolicy {
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
    if ($currentPolicy -eq "Restricted" -or $currentPolicy -eq "AllSigned") {
        # Implement bypass logic
    }
}
```

### Creating a New Test

1. Generate a UUID for your test (lowercase format)
2. Create the test directory structure:
```bash
mkdir tests_source/<uuid>/
```

3. Implement the test following the standard pattern (see `sample_tests/` for examples)
4. Create required documentation:
   - `README.md` - Brief test overview
   - `<uuid>_info.md` - Detailed information card
   - `go.mod` - Go module configuration

### Test Result Codes

- **101** - System unprotected (attack succeeded)
- **105** - File quarantined on extraction
- **126** - Execution prevented by security solution

### Long-Running Test Support

The framework now supports tests that require more than the standard 30-second timeout limit. For complex simulations like ransomware operations that may take several minutes, use a custom test runner pattern:

```go
func main() {
    // Custom runner bypasses Endpoint.Start() timeout limitation
    done := make(chan bool, 1)
    go func() {
        test()
        done <- true
    }()
    
    select {
    case <-done:
        Endpoint.Say("Test completed within timeout window")
    case <-time.After(5 * time.Minute):  // Adjust as needed
        Endpoint.Say("Test timed out after 5 minutes")
        Endpoint.Stop(Endpoint.TimeoutExceeded)
    }
}
```

This approach is used in multi-phase attack simulations that include file creation, compression, encryption, and cleanup phases. See `tests_source/109266e2-2310-40ea-9f63-b97e4b7fda61/LONG_RUNNING_TEST_SOLUTION.md` for detailed implementation.

### Important Convention

**ALL test binaries MUST be dropped to `c:\F0`** - This is a critical requirement for test consistency.

## Security Considerations

⚠️ **WARNING**: This framework contains and executes real attack techniques. Use only in isolated, controlled environments with appropriate authorization.

- **Authorization Required**: Only use on systems you own or have explicit permission to test
- **Isolated Environments**: Never run on production systems or networks
- **Monitoring**: All test executions should be logged and monitored
- **Responsible Use**: Follow ethical hacking principles and local laws

For more details, see our [Security Policy](SECURITY.md).

## Contributing

We welcome contributions from the security community! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before getting started.

### Quick Contribution Checklist

1. Read [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines
2. Follow the established test structure patterns
3. Map all tests to MITRE ATT&CK techniques
4. Include comprehensive documentation
5. Test thoroughly in isolated environments
6. Submit pull requests using our [PR template](.github/pull_request_template.md)

### Reporting Issues

- **Bugs**: Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md)
- **Features**: Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md)
- **Security**: Follow our [vulnerability disclosure policy](SECURITY.md)

## Development Workflow

Our development process includes automated testing and security scanning:

1. **Develop**: Create tests following [Development Guide](docs/DEVELOPMENT.md)
2. **Test**: Run `./utils/run_tests.sh` to verify utilities work
3. **Build**: Use `./utils/gobuild build-all` to compile tests
4. **Sign**: Use `./utils/codesign sign-all` for Windows executables
5. **Validate**: Test in isolated environments only
6. **Document**: Update relevant documentation
7. **Submit**: Create PR following our [guidelines](CONTRIBUTING.md)

## CI/CD & Automation

Our repository features comprehensive automated testing and security scanning:

### 🔄 Continuous Integration
- **✅ Build Workflow**: Tests utilities on Ubuntu and macOS
- **✅ Security Workflow**: Scans for vulnerabilities and secrets
- **✅ Code Quality**: Shell scripts validated with ShellCheck
- **✅ PowerShell Analysis**: PSScriptAnalyzer for Windows scripts

### 🛡️ Security Scanning
- **Shell Script Analysis**: Detects security issues in bash scripts
- **Secret Detection**: Scans for hardcoded credentials
- **PowerShell Security**: Validates Windows PowerShell scripts
- **Weekly Scans**: Automated security checks every Monday

### 🧪 Automated Testing
- **Utility Tests**: Unit tests for `gobuild` and `codesign`
- **Cross-Platform**: Tests run on Linux and macOS
- **Test Coverage**: Comprehensive test suite with detailed reporting

## Documentation

- 📖 [Architecture Overview](docs/ARCHITECTURE.md) - System design and components
- 🛠️ [Development Guide](docs/DEVELOPMENT.md) - Complete setup and development
- 🔐 [Security Policy](SECURITY.md) - Vulnerability disclosure and best practices
- 🤝 [Contributing Guide](CONTRIBUTING.md) - How to contribute effectively
- 📝 [Changelog](CHANGELOG.md) - Version history and changes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Additional Notice**: This software is designed for security testing and evaluation purposes only. Users are responsible for ensuring they have proper authorization before conducting any security tests.

## Support & Community

- 🐛 **Bug Reports**: Use our [issue templates](.github/ISSUE_TEMPLATE/)
- 💡 **Feature Requests**: Submit via GitHub issues
- 🔒 **Security Issues**: Follow our [disclosure policy](SECURITY.md)
- 📧 **Questions**: Use GitHub Discussions for general questions

---

**⚠️ Ethical Use Notice**: This framework is intended for authorized security testing only. Always ensure you have explicit permission before testing any systems.
