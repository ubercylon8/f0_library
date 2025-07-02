# F0RT1KA Security Testing Framework

A comprehensive security testing framework for evaluating antivirus (AV) and endpoint detection and response (EDR) solutions against various threat tactics and techniques.

## Overview

F0RT1KA is a specialized testing library designed to assess the effectiveness of security solutions by simulating real-world attack techniques mapped to the MITRE ATT&CK framework. This repository serves as the main tools repository for testing execution frameworks of all kinds.

## Purpose

- **Security Validation**: Test and validate the detection and prevention capabilities of security solutions
- **MITRE ATT&CK Alignment**: All tests are mapped to specific MITRE ATT&CK techniques for standardized threat assessment
- **Automated Testing**: Provide a structured approach to security testing with consistent result codes
- **Research & Development**: Enable security teams to understand gaps in their defensive posture

## Key Features

- **Standardized Test Structure**: Consistent format for all security tests
- **Binary Drop Testing**: Controlled testing of malicious binary detection
- **Execution Prevention Testing**: Validate runtime protection mechanisms
- **Result Code System**: Clear success/failure metrics (101, 105, 126)
- **Windows-Focused**: Optimized for Windows endpoint testing

## Project Structure

```
f0_library/
├── sample_tests/          # Reference test implementations
├── tests_source/          # Active test development directory
├── rules/                 # Development guidelines and standards
├── signing-certs/         # Code signing certificates
├── preludeorg-libraries/  # Prelude testing framework (setup required)
├── CLAUDE.md             # AI-assisted development guide
└── README.md             # This file
```

## Getting Started

### Prerequisites

- **Go 1.21+**: Required for building tests
- **Windows Environment**: Tests are designed for Windows systems
- **Prelude Libraries**: Must be configured in the `preludeorg-libraries/` directory
- **Administrator Access**: Some tests require elevated privileges

### Installation

1. Clone the repository:
```bash
git clone https://github.com/ubercylon8/f0_library.git
cd f0_library
```

2. Set up Prelude libraries (required for test compilation):
```bash
# Instructions for Prelude setup will be provided in future documentation
```

### Building Tests

Individual tests can be built using standard Go commands:

```bash
cd tests_source/<test-uuid>/
GOOS=windows GOARCH=amd64 go build -o <test-uuid>.exe <test-uuid>.go
```

## Test Development

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

### Important Convention

**ALL test binaries MUST be dropped to `c:\F0`** - This is a critical requirement for test consistency.

## Security Considerations

⚠️ **WARNING**: This framework contains and executes real attack techniques. Use only in isolated, controlled environments with appropriate security measures.

- Tests should only be run on dedicated testing systems
- Never run tests on production environments
- Ensure proper isolation from sensitive networks
- Monitor and log all test executions

## Contributing

We welcome contributions to expand the test library. Please:

1. Follow the established test structure
2. Map all tests to MITRE ATT&CK techniques
3. Include comprehensive documentation
4. Test thoroughly in isolated environments
5. Submit pull requests for review

## Roadmap

- Expanded test coverage across MITRE ATT&CK framework
- Enhanced reporting and analytics capabilities
- Cross-platform support (Linux/macOS)
- Integration with security orchestration platforms
- Comprehensive documentation and training materials

## License

[License information to be added]

## Support

For questions, issues, or contributions, please use the GitHub issue tracker.

---

**Note**: This is an active development project. Additional documentation and features will be added as the project evolves.