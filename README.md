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
- **Compliance Support**: DORA/TIBER-EU aligned testing for regulatory compliance

## Key Features

- **49 Security Tests**: Organized into 4 categories covering attack simulation and configuration validation
- **Standardized Test Structure**: Consistent format with Schema v2.0 logging for analytics
- **Multi-Organization Support**: UUID-based organization tracking for enterprise deployments
- **LimaCharlie Integration**: Infrastructure as Code for detection rules and certificate deployment
- **Elasticsearch Analytics**: Pre-built dashboards and enrichment pipelines
- **Binary Drop Testing**: Controlled testing of malicious binary detection
- **Execution Prevention Testing**: Validate runtime protection mechanisms
- **Result Code System**: Clear success/failure metrics (101, 105, 126, 999)
- **Code Signing Support**: Integrated Windows executable signing with dual-signing for ASR bypass

## Test Categories

F0RT1KA tests are organized into four categories:

| Category | Tests | Description |
|----------|-------|-------------|
| [**intel-driven**](tests_source/intel-driven/) | 20 | Threat intelligence-based tests from APT reports, ransomware analysis, and CVE exploits |
| [**cyber-hygiene**](tests_source/cyber-hygiene/) | 11 | Configuration validation tests for security hardening (LAPS, ASR, Defender, etc.) |
| [**mitre-top10**](tests_source/mitre-top10/) | 10 | MITRE Top 10 Ransomware techniques test suite |
| [**phase-aligned**](tests_source/phase-aligned/) | 8 | DORA/TIBER-EU pentest phase tests (credential access, lateral movement) |

## Project Structure

```
f0_library/
├── .github/                   # GitHub workflows and templates
│   ├── ISSUE_TEMPLATE/       # Issue templates for bugs and features
│   ├── workflows/            # CI/CD workflows (build, security)
│   └── pull_request_template.md
├── docs/                      # Documentation
│   ├── ARCHITECTURE.md       # System architecture overview
│   ├── DEVELOPMENT.md        # Developer setup guide
│   └── windows-ssh-setup.md  # SSH configuration guide
├── limacharlie-iac/           # LimaCharlie Infrastructure as Code
│   ├── elasticsearch/        # Elasticsearch index templates
│   ├── payloads/             # PowerShell scripts and payloads
│   ├── rules/                # Detection & Response rules
│   ├── scripts/              # Deployment automation
│   └── README.md             # LimaCharlie deployment guide
├── sample_tests/              # Reference test implementations
│   └── multistage_template/  # Multi-stage test reference
├── tests_source/              # Active test development directory
│   ├── intel-driven/         # Threat intelligence-based tests (20)
│   ├── cyber-hygiene/        # Configuration validation tests (11)
│   ├── mitre-top10/          # MITRE Top 10 Ransomware tests (10)
│   └── phase-aligned/        # DORA/TIBER-EU pentest tests (8)
├── utils/                     # Build and signing utilities
│   ├── gobuild               # Cross-platform test builder
│   ├── codesign              # Code signing utility
│   ├── Check-DefenderProtection.ps1
│   ├── validate_test_results.py  # Schema v2.0 validator
│   ├── sync-test-catalog-to-elasticsearch.py
│   └── README.md             # Utility documentation
├── preludeorg-libraries/      # Prelude testing framework (setup required)
├── CONTRIBUTING.md           # Contribution guidelines
├── CODE_OF_CONDUCT.md        # Community standards
├── SECURITY.md               # Security policy
├── CHANGELOG.md              # Version history
├── LICENSE                   # MIT License
└── README.md                 # This file
```

## Getting Started

### Prerequisites

- **Go 1.21+**: Required for building tests
- **Python 3.7+**: Required for security analysis tools
- **Windows Environment**: Tests are designed for Windows systems
- **Prelude Libraries**: Must be configured in the `preludeorg-libraries/` directory
- **Administrator Access**: Some tests require elevated privileges
- **osslsigncode** (optional): For code signing Windows executables

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
./utils/gobuild build tests_source/intel-driven/<test-uuid>/

# Build all tests in a category
for dir in tests_source/intel-driven/*/; do
    ./utils/gobuild build "$dir"
done

# Build all tests
./utils/gobuild build-all

# List available tests
./utils/gobuild list
```

### Code Signing

Sign Windows executables using the `codesign` utility:

```bash
# Sign a specific binary
./utils/codesign sign build/<test-uuid>/<test-uuid>.exe

# Dual-sign with organization certificate (for ASR bypass)
./utils/codesign sign-nested build/<test-uuid>/<test-uuid>.exe --org sb

# Sign all binaries in build directory
./utils/codesign sign-all

# Verify signature
./utils/codesign verify build/<test-uuid>/<test-uuid>.exe
```

### Running Tests

Deploy and execute tests on Windows targets:

```bash
# Copy test binary to target
scp build/<test-uuid>/<test-uuid>.exe user@target:c:/F0/

# Execute on target
ssh user@target "c:/F0/<test-uuid>.exe"

# Check results
cat c:/F0/test_execution_log.json
```

## Test Development

### Test Result Codes

| Code | Name | Description |
|------|------|-------------|
| 101 | `Unprotected` | Attack succeeded - system unprotected |
| 105 | `FileQuarantinedOnExtraction` | File quarantined by AV/EDR |
| 126 | `ExecutionPrevented` | Execution blocked by security solution |
| 999 | `UnexpectedTestError` | Test prerequisites not met |

### Path Conventions

| Artifact Type | Path | Reason |
|--------------|------|--------|
| Test binaries (.exe) | `c:\F0` | Whitelisted - allows execution |
| Embedded tools | `c:\F0` | Same as above |
| Log files | `c:\F0` | Standard location |
| Simulation artifacts | `c:\Users\fortika-test` | NOT whitelisted - EDR detects |

### Schema v2.0 Logging

All tests implement Schema v2.0 compliant logging for analytics:

```go
// Required metadata
metadata := TestMetadata{
    Version:    "1.0.0",
    Category:   "defense_evasion",
    Severity:   "high",
    Techniques: []string{"T1562.001"},
    Tactics:    []string{"defense-evasion"},
    Score:      8.5,
}

// Execution context with organization UUID
executionContext := ExecutionContext{
    ExecutionID:  uuid.New().String(),
    Organization: orgInfo.UUID,  // From org_resolver.go
    Environment:  "lab",
}

InitLogger(testID, testName, metadata, executionContext)
```

### Creating a New Test

1. Generate a UUID for your test (lowercase format)
2. Choose the appropriate category:
   - `intel-driven/` - For threat intelligence-based tests
   - `cyber-hygiene/` - For configuration validation tests
   - `phase-aligned/` - For pentest phase tests
3. Create the test directory structure:
```bash
mkdir tests_source/<category>/<uuid>/
```
4. Copy required files from `sample_tests/multistage_template/`:
   - `test_logger.go` - Schema v2.0 logging
   - `org_resolver.go` - Organization UUID resolution
5. Implement the test following the standard pattern
6. Create documentation:
   - `README.md` - Brief test overview with score
   - `<uuid>_info.md` - Detailed information card

## LimaCharlie Integration

F0RT1KA includes Infrastructure as Code for LimaCharlie:

```bash
# Deploy certificate installer
./limacharlie-iac/scripts/deploy-cert-installer.sh <org-name>

# Deploy detection rules
limacharlie config push --config limacharlie-iac/f0rtika-org-template.yaml

# Sync test catalog to Elasticsearch
python3 utils/sync-test-catalog-to-elasticsearch.py
```

See [limacharlie-iac/README.md](limacharlie-iac/README.md) for full deployment guide.

## Security Considerations

**WARNING**: This framework contains and executes real attack techniques. Use only in isolated, controlled environments with appropriate authorization.

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
4. Include comprehensive documentation with test scores
5. Test thoroughly in isolated environments
6. Submit pull requests using our [PR template](.github/pull_request_template.md)

## CI/CD & Automation

### Continuous Integration
- **Build Workflow**: Tests utilities on Ubuntu and macOS
- **Security Workflow**: Scans for vulnerabilities and secrets
- **Code Quality**: Shell scripts validated with ShellCheck
- **PowerShell Analysis**: PSScriptAnalyzer for Windows scripts

### Security Scanning
- **Shell Script Analysis**: Detects security issues in bash scripts
- **Secret Detection**: Scans for hardcoded credentials
- **Weekly Scans**: Automated security checks every Monday

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md) - System design and components
- [Development Guide](docs/DEVELOPMENT.md) - Complete setup and development
- [Security Policy](SECURITY.md) - Vulnerability disclosure and best practices
- [Contributing Guide](CONTRIBUTING.md) - How to contribute effectively
- [Changelog](CHANGELOG.md) - Version history and changes
- [LimaCharlie IaC](limacharlie-iac/README.md) - Detection infrastructure deployment

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Additional Notice**: This software is designed for security testing and evaluation purposes only. Users are responsible for ensuring they have proper authorization before conducting any security tests.

## Support & Community

- **Bug Reports**: Use our [issue templates](.github/ISSUE_TEMPLATE/)
- **Feature Requests**: Submit via GitHub issues
- **Security Issues**: Follow our [disclosure policy](SECURITY.md)
- **Questions**: Use GitHub Discussions for general questions

---

**Ethical Use Notice**: This framework is intended for authorized security testing only. Always ensure you have explicit permission before testing any systems.
