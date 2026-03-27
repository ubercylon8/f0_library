# ACHILLES Security Testing Framework

[![Build Status](https://github.com/ubercylon8/f0_library/actions/workflows/build.yml/badge.svg)](https://github.com/ubercylon8/f0_library/actions/workflows/build.yml)
[![Security Scan](https://github.com/ubercylon8/f0_library/actions/workflows/security.yml/badge.svg)](https://github.com/ubercylon8/f0_library/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shellcheck](https://img.shields.io/badge/shellcheck-passing-brightgreen.svg)](https://www.shellcheck.net/)

A comprehensive security testing framework for evaluating endpoint detection and response (EDR) capabilities against real-world attack techniques mapped to the MITRE ATT&CK framework.

## Overview

F0RT1KA is a professional, open-source security testing framework designed to assess the effectiveness of endpoint detection and response (EDR) solutions. By simulating real-world attack techniques mapped to the MITRE ATT&CK framework, it provides security teams with a standardized approach to validate their defensive capabilities.

## Purpose

- **Security Validation**: Test and validate the detection and prevention capabilities of security solutions
- **MITRE ATT&CK Alignment**: All tests are mapped to specific MITRE ATT&CK techniques for standardized threat assessment
- **Automated Testing**: Provide a structured approach to security testing with consistent result codes
- **Research & Development**: Enable security teams to understand gaps in their defensive posture
- **Compliance Support**: DORA/TIBER-EU aligned testing for regulatory compliance

## Key Features

- **44 Security Tests** across 3 categories covering attack simulation and configuration validation
- **Cross-Platform Support**: Windows (primary), Linux, and macOS test targets
- **Agent-Driven Test Generation**: Orchestrator + specialized agents for automated test creation from threat intelligence
- **5 Detection Rule Formats**: KQL, YARA, Sigma, Elastic EQL, and LimaCharlie D&R rules generated per test
- **Defense Guidance**: Hardening scripts (Windows/Linux/macOS) and incident response playbooks
- **Standardized Test Structure**: Schema v2.0 logging with Elasticsearch analytics
- **Multi-Organization Support**: UUID-based organization tracking for enterprise deployments
- **LimaCharlie Integration**: Infrastructure as Code for detection rules and certificate deployment
- **Elasticsearch Analytics**: Pre-built dashboards and enrichment pipelines
- **Code Signing Support**: Integrated Windows executable signing with dual-signing for ASR bypass
- **Test Provenance**: References tracking with `_references.md` files linking tests to source intelligence

## Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| [**intel-driven**](tests_source/intel-driven/) | 26 | Threat intelligence-based tests from APT reports, ransomware analysis, and CVE exploits |
| [**mitre-top10**](tests_source/mitre-top10/) | 10 | MITRE Top 10 Ransomware techniques test suite |
| [**cyber-hygiene**](tests_source/cyber-hygiene/) | 8 | Configuration validation tests for endpoint, identity, and tenant security |

## Agent Architecture

F0RT1KA uses a decomposed agent architecture to generate complete test packages from threat intelligence. The `sectest-builder` orchestrator coordinates specialized skills and sub-agents in a 4-phase execution model.

### Execution Phases

1. **Phase 1 — Sequential Skills** (shared context): Source analysis → Go implementation → Build & sign
2. **Phase 2 — Parallel Agents** (independent): Documentation, detection rules, defense guidance, kill chain diagrams
3. **Phase 3 — Validation** (shared context): File verification, score consistency, ES catalog sync, git commit
4. **Phase 3b — Deployment** (shared context): SSH deploy to target endpoint, execute, capture results

### Agent Selection

| Need | Agent |
|------|-------|
| Create test from threat intel | `@sectest-builder` (orchestrates everything) |
| Validate TIBER-EU phase readiness | `@pentest-readiness-builder` |
| Visualize attack flow | `@attack-flow-diagram-builder` |
| Visualize kill chain | `@kill-chain-diagram-builder` |
| Generate detection rules | `@sectest-detection-rules` |
| Generate defense guidance | `@sectest-defense-guidance` |
| Deploy & execute test on endpoint | `@sectest-deploy-test` |

For detailed architecture documentation, see [docs/SECTEST_BUILDER_ARCHITECTURE.md](docs/SECTEST_BUILDER_ARCHITECTURE.md).

## Project Structure

```
f0_library/
├── .claude/                      # Claude Code agent and skill definitions
│   ├── agents/                  # 9 specialized agents (orchestrator + sub-agents)
│   └── skills/                  # 6 skills (analysis, implementation, build, validation, deploy)
├── .github/                      # GitHub workflows and templates
│   ├── ISSUE_TEMPLATE/          # Issue templates for bugs and features
│   ├── workflows/               # CI/CD workflows (build, security, Claude review)
│   └── pull_request_template.md
├── docs/                         # Documentation
│   ├── ARCHITECTURE.md          # System architecture (multi-binary bundles)
│   ├── CHANGELOG.md             # Version history
│   ├── DEVELOPMENT.md           # Developer setup guide
│   ├── DUAL_SIGNING_STRATEGY.md # Code signing details
│   ├── MULTISTAGE_QUICK_REFERENCE.md  # Multi-stage build reference
│   ├── SECTEST_BUILDER_ARCHITECTURE.md # Agent architecture
│   ├── TEST_RESULTS_SCHEMA_GUIDE.md   # Schema v2.0 guide
│   └── ...                      # Additional docs
├── limacharlie-iac/              # LimaCharlie Infrastructure as Code
│   ├── elasticsearch/           # Elasticsearch index templates
│   ├── payloads/                # PowerShell scripts and payloads
│   ├── rules/                   # Detection & Response rules
│   ├── scripts/                 # Deployment automation
│   └── README.md                # LimaCharlie deployment guide
├── sample_tests/                 # Reference test implementations
│   └── multistage_template/     # Multi-stage test reference
├── tests_source/                 # Active test development directory
│   ├── intel-driven/            # Threat intelligence-based tests (26)
│   ├── mitre-top10/             # MITRE Top 10 Ransomware tests (10)
│   └── cyber-hygiene/           # Configuration validation tests (8)
├── utils/                        # Build and signing utilities
│   ├── gobuild                  # Cross-platform test builder
│   ├── codesign                 # Code signing utility
│   ├── Check-DefenderProtection.ps1
│   ├── validate_test_results.py # Schema v2.0 validator
│   ├── sync-test-catalog-to-elasticsearch.py
│   └── README.md                # Utility documentation
├── rules/                        # Development guidelines
├── signing-certs/                # Code signing certificates
├── preludeorg-libraries/         # Prelude testing framework (setup required)
├── CONTRIBUTING.md              # Contribution guidelines
├── CODE_OF_CONDUCT.md           # Community standards
├── SECURITY.md                  # Security policy
├── LICENSE                      # MIT License
└── README.md                    # This file
```

## Getting Started

### Prerequisites

- **Go 1.21+**: Required for building tests
- **Python 3.7+**: Required for utilities and ES sync scripts
- **Supported platforms**: Windows (primary), Linux, macOS
- **Prelude Libraries**: Must be configured in the `preludeorg-libraries/` directory
- **Administrator Access**: Some tests require elevated privileges
- **osslsigncode** (optional): For code signing Windows executables

### Quick Start

1. **Clone the repository**:
```bash
git clone https://github.com/ubercylon8/f0_library.git
cd f0_library
```

2. **Set up Python virtual environment** (for utilities):
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # If present, or install elasticsearch, requests
```

3. **Read the documentation**:
   - [Development Guide](docs/DEVELOPMENT.md) - Complete setup instructions
   - [Architecture Overview](docs/ARCHITECTURE.md) - System design
   - [Contributing Guidelines](CONTRIBUTING.md) - How to contribute

4. **Set up Prelude libraries** (required for test compilation):
```bash
# Instructions for Prelude setup will be provided in future documentation
```

5. **Install dependencies** (optional):
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

### Cross-Platform Builds

```bash
# Windows (default)
GOOS=windows GOARCH=amd64 go build -o test.exe main.go test_logger.go test_logger_windows.go org_resolver.go

# Linux
GOOS=linux GOARCH=amd64 go build -o test main.go test_logger.go test_logger_linux.go org_resolver.go

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o test main.go test_logger.go test_logger_darwin.go org_resolver.go
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

Deploy and execute tests on target systems:

```bash
# Copy test binary to target
scp build/<test-uuid>/<test-uuid>.exe user@target:c:/F0/

# Execute on target
ssh user@target "c:/F0/<test-uuid>.exe"

# Check results
cat c:/F0/test_execution_log.json
```

## Cross-Platform Support

Tests can target Windows, Linux, or macOS. The platform is determined by the threat being simulated.

| Platform | `LOG_DIR` | `ARTIFACT_DIR` | Binary Extension |
|----------|-----------|----------------|-----------------|
| Windows | `C:\F0` | `c:\Users\fortika-test` | `.exe` |
| Linux | `/tmp/F0` | `/home/fortika-test` | (none) |
| macOS | `/tmp/F0` | `/Users/fortika-test` | (none) |

Platform-specific logger files (`test_logger_windows.go`, `test_logger_linux.go`, `test_logger_darwin.go`) define these constants. Copy the shared `test_logger.go` AND the appropriate platform file from `sample_tests/multistage_template/` when creating new tests.

## Detection & Defense Artifacts

Each test generates detection rules in 5 formats and comprehensive defense guidance:

### Detection Rules

| Format | File | Target Platform |
|--------|------|-----------------|
| KQL | `<uuid>_detections.kql` | Microsoft Sentinel / Defender |
| YARA | `<uuid>_rules.yar` | File-based scanning |
| Sigma | `<uuid>_sigma_rules.yml` | Vendor-agnostic SIEM |
| Elastic EQL | `<uuid>_elastic_rules.ndjson` | Elastic SIEM |
| LimaCharlie D&R | `<uuid>_dr_rules.yaml` | LimaCharlie |

### Defense Guidance

| Artifact | File | Purpose |
|----------|------|---------|
| Defense Guide | `<uuid>_DEFENSE_GUIDANCE.md` | Consolidated detection + hardening |
| Windows Hardening | `<uuid>_hardening.ps1` | PowerShell hardening script |
| Linux Hardening | `<uuid>_hardening_linux.sh` | Bash hardening script |
| macOS Hardening | `<uuid>_hardening_macos.sh` | macOS hardening script |

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
   - `mitre-top10/` - For MITRE ATT&CK top technique tests
   - `cyber-hygiene/` - For configuration validation tests
3. Create the test directory structure:
```bash
mkdir tests_source/<category>/<uuid>/
```
4. Copy required files from `sample_tests/multistage_template/`:
   - `test_logger.go` - Schema v2.0 logging
   - `test_logger_<platform>.go` - Platform constants
   - `org_resolver.go` - Organization UUID resolution
5. Implement the test following the standard pattern
6. Create documentation:
   - `README.md` - Brief test overview with score
   - `<uuid>_info.md` - Detailed information card
   - `<uuid>_references.md` - Source provenance and references

Or use the automated builder: `@sectest-builder <threat intelligence article>`

## LimaCharlie Integration

F0RT1KA includes Infrastructure as Code for LimaCharlie:

```bash
# Deploy certificate installer
./limacharlie-iac/scripts/deploy-cert-installer.sh <org-name>

# Deploy detection rules
limacharlie config push --config limacharlie-iac/f0rtika-org-template.yaml

# Sync test catalog to Elasticsearch
source .venv/bin/activate
python3 utils/sync-test-catalog-to-elasticsearch.py
```

See [limacharlie-iac/README.md](limacharlie-iac/README.md) for full deployment guide.

## CI/CD & Automation

### Continuous Integration

- **Build Workflow**: Tests utilities on Ubuntu and macOS, validates Go compilation
- **Security Workflow**: Gitleaks + TruffleHog secret scanning, ShellCheck, PSScriptAnalyzer
- **Claude Code Review**: Automated PR reviews with domain-specific security test knowledge
- **Claude Code Action**: Interactive issue/PR assistance via `@claude` mentions

### Security Scanning

- **Gitleaks**: Detects secrets and credentials in git history
- **TruffleHog**: Verified secret detection with reduced false positives
- **ShellCheck**: Static analysis for shell scripts
- **PSScriptAnalyzer**: PowerShell script security analysis
- **Weekly Scans**: Automated security checks every Monday

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

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md) - System design and multi-binary bundles
- [Agent Architecture](docs/SECTEST_BUILDER_ARCHITECTURE.md) - Orchestrator and agent design
- [Development Guide](docs/DEVELOPMENT.md) - Complete setup and development
- [Schema v2.0 Guide](docs/TEST_RESULTS_SCHEMA_GUIDE.md) - Test results schema
- [Multi-stage Reference](docs/MULTISTAGE_QUICK_REFERENCE.md) - Multi-stage build patterns
- [Dual Signing Strategy](docs/DUAL_SIGNING_STRATEGY.md) - Code signing details
- [Security Policy](SECURITY.md) - Vulnerability disclosure and best practices
- [Contributing Guide](CONTRIBUTING.md) - How to contribute effectively
- [Changelog](docs/CHANGELOG.md) - Version history and changes
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
