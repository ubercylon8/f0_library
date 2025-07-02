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
- **Cross-Platform Building**: Build utilities for Windows, Linux, and macOS
- **Code Signing Support**: Integrated Windows executable signing with certificates

## Project Structure

```
f0_library/
├── sample_tests/          # Reference test implementations
├── tests_source/          # Active test development directory
├── rules/                 # Development guidelines and standards
├── signing-certs/         # Code signing certificates
├── utils/                 # Build and signing utilities
│   ├── gobuild           # Cross-platform test builder
│   ├── codesign          # Code signing utility
│   └── README.md         # Utility documentation
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
- **osslsigncode** (optional): For code signing Windows executables

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

3. Install osslsigncode for code signing (optional):
```bash
# macOS
brew install osslsigncode

# Ubuntu/Debian
sudo apt-get install osslsigncode
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

## Development Workflow

1. **Create Test**: Follow the established test structure in `tests_source/`
2. **Build**: Use `./utils/gobuild build-all` to compile tests
3. **Sign**: Use `./utils/codesign sign-all` to sign Windows executables
4. **Test**: Execute in isolated Windows environments
5. **Document**: Update test information cards and README files

## Roadmap

- Expanded test coverage across MITRE ATT&CK framework
- Enhanced reporting and analytics capabilities
- Cross-platform test execution (Linux/macOS)
- Integration with security orchestration platforms
- Comprehensive documentation and training materials
- CI/CD pipeline integration for automated building and signing

## License

[License information to be added]

## Support

For questions, issues, or contributions, please use the GitHub issue tracker.

---

**Note**: This is an active development project. Additional documentation and features will be added as the project evolves.