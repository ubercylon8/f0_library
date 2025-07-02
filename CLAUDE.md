# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview
This is the F0RT1KA security testing framework - a specialized library for evaluating AV/EDR detection capabilities against various threat tactics and techniques. Tests are written in Go and mapped to the MITRE ATT&CK framework.

## Critical Development Rules
1. **ALL binaries MUST be dropped to `c:\F0`** - This is a hard requirement for all tests
2. Tests simulate real attack techniques - handle with appropriate security measures
3. Always use the established test structure pattern (see sample_tests/)
4. Map every test to specific MITRE ATT&CK techniques

## Building and Running Tests

### Build a Test
Use the `gobuild` utility for cross-platform compilation:
```bash
# Build specific test (Windows/amd64 by default)
./utils/gobuild build tests_source/<uuid>/

# Build for different platforms
./utils/gobuild --os linux --arch amd64 build tests_source/<uuid>/

# Build all tests
./utils/gobuild build-all
```

### Sign Test Binaries
Use the `codesign` utility for Windows executable signing:
```bash
# Sign specific binary
./utils/codesign sign build/<uuid>/<uuid>.exe

# Sign all binaries
./utils/codesign sign-all
```

### Test Result Codes
- **101** (`Endpoint.Unprotected`) - Attack succeeded, system unprotected
- **105** (`Endpoint.FileQuarantinedOnExtraction`) - File quarantined
- **126** (`Endpoint.ExecutionPrevented`) - Execution blocked

## Project Structure
```
tests_source/      # New tests go here
sample_tests/      # Reference implementations
rules/             # Development guidelines
signing-certs/     # Code signing certificates
utils/             # Build and signing utilities
  ├── gobuild      # Cross-platform test builder
  ├── codesign     # Code signing utility
  └── README.md    # Utility documentation
```

## Creating New Tests

### Required Files for Each Test
1. `<uuid>/` directory (use lowercase UUID)
2. `<uuid>.go` - Main test implementation
3. `README.md` - Brief overview
4. `<uuid>_info.md` - Detailed information card
5. `go.mod` - Module file with Prelude library dependencies

### Test Implementation Pattern
```go
//go:build windows

import (
    Dropper "github.com/preludeorg/libraries/go/tests/dropper"
    Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func test() {
    // Initialize dropper
    if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    // CRITICAL: Drop to c:\F0
    targetDir := "c:\\F0"
    os.MkdirAll(targetDir, 0755)
    
    // Test logic here
    
    // Use appropriate exit code
    Endpoint.Stop(Endpoint.Unprotected)
}
```

### go.mod Template
```go
module <uuid>
go 1.21

require (
    github.com/preludeorg/libraries/go/tests/dropper v0.0.0
    github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
)

replace github.com/preludeorg/libraries/go/tests/dropper => ../../preludeorg-libraries/go/tests/dropper
replace github.com/preludeorg/libraries/go/tests/endpoint => ../../preludeorg-libraries/go/tests/endpoint
```

## Prerequisites
- **Prelude Libraries**: Must be set up in `preludeorg-libraries/` directory
- **Go 1.21+**: Required for building
- **Windows Target**: Tests are Windows-specific

## Key Conventions
- Use `Endpoint.Say()` for all logging
- Check `Endpoint.Quarantined()` after dropping binaries
- Always clean up artifacts after test completion
- Follow MITRE ATT&CK mapping standards

## Github Repository Management
- Initialize and create a private repository on Github
- For all changes, additions and fixes, commit and create PRs for Github when applicable