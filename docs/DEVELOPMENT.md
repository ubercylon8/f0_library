# F0RT1KA Development Guide

## Prerequisites

- Go 1.21 or later
- Git
- Windows SDK (for Windows development)
- Code signing certificate (for production builds)

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/f0_library.git
cd f0_library
```

### 2. Set Up Dependencies

The Prelude libraries must be available in the `preludeorg-libraries/` directory:

```bash
# Clone or copy the Prelude libraries
git clone [prelude-repo-url] preludeorg-libraries
```

### 3. Verify Installation

```bash
# Build the utilities
cd utils
go build -o gobuild ./gobuild
go build -o codesign ./codesign
cd ..

# Test the build system
./utils/gobuild --help
```

## Creating a New Test

### 1. Generate Test UUID

```bash
# Generate a lowercase UUID
uuidgen | tr '[:upper:]' '[:lower:]'
# Example output: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

### 2. Create Test Structure

```bash
# Set your UUID
export TEST_UUID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"

# Create directory structure
mkdir -p tests_source/$TEST_UUID
cd tests_source/$TEST_UUID
```

### 3. Create go.mod

```go
module a1b2c3d4-e5f6-7890-abcd-ef1234567890

go 1.21

require (
    github.com/preludeorg/libraries/go/tests/dropper v0.0.0
    github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
)

replace github.com/preludeorg/libraries/go/tests/dropper => ../../preludeorg-libraries/go/tests/dropper
replace github.com/preludeorg/libraries/go/tests/endpoint => ../../preludeorg-libraries/go/tests/endpoint
```

### 4. Implement Test

Create `<uuid>.go`:

```go
//go:build windows

package main

import (
    "os"
    Dropper "github.com/preludeorg/libraries/go/tests/dropper"
    Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func main() {
    test()
}

func test() {
    // Initialize dropper
    if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
        Endpoint.Say("Failed to initialize dropper")
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    // Create target directory
    targetDir := "c:\\F0"
    if err := os.MkdirAll(targetDir, 0755); err != nil {
        Endpoint.Say("Failed to create target directory")
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    // Your test logic here
    // Example: Drop and execute a file
    
    // Check if protected
    if Endpoint.Quarantined() {
        Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
    }

    // If we get here, system is unprotected
    Endpoint.Stop(Endpoint.Unprotected)
}
```

### 5. Create Documentation

Create `README.md`:

```markdown
# Test UUID: <uuid>

## Overview
Brief description of what this test does.

## MITRE ATT&CK Mapping
- Technique: T1234 - Technique Name
- Tactic: Initial Access/Execution/etc.

## Expected Behavior
- Protected: File should be quarantined or execution blocked
- Unprotected: Test executes successfully
```

Create `<uuid>_info.md`:

```markdown
# Detailed Test Information

## Technical Details
Detailed explanation of the test methodology.

## Indicators of Compromise
- Files created
- Registry modifications
- Network connections

## Cleanup
Steps performed to clean up after test execution.
```

### 6. Build and Test

```bash
# Build the test
./utils/gobuild build tests_source/$TEST_UUID/

# For Windows targets, sign the binary
./utils/codesign sign build/$TEST_UUID/$TEST_UUID.exe

# Test in isolated environment
# WARNING: Only run on authorized test systems!
```

## Code Style Guidelines

### Go Code
- Use `gofmt` for formatting
- Follow Go best practices
- Handle all errors appropriately
- Use meaningful variable names
- Add comments for complex logic

### Error Handling
```go
if err != nil {
    Endpoint.Say("Descriptive error message: " + err.Error())
    Endpoint.Stop(Endpoint.UnexpectedTestError)
}
```

### Logging
```go
// Use Endpoint.Say for all output
Endpoint.Say("Starting test execution")
Endpoint.Say("Dropping file to: " + targetPath)
```

## Testing Guidelines

### Local Testing
1. Always test in isolated VMs
2. Take snapshots before testing
3. Monitor system changes
4. Verify cleanup procedures

### Continuous Integration
Tests are automatically built on:
- Windows (primary target)
- Linux (compatibility)
- macOS (compatibility)

## Debugging

### Common Issues

**Build Failures**
```bash
# Check Go version
go version

# Verify module dependencies
go mod tidy
go mod verify
```

**Signing Failures**
```bash
# Check certificate
./utils/codesign verify-cert

# Try manual signing
signtool sign /f cert.pfx /p password file.exe
```

**Test Failures**
- Check Windows Defender status
- Verify admin privileges
- Check target directory permissions

### Debug Output
```go
// Add verbose logging during development
Endpoint.Say("[DEBUG] Current directory: " + cwd)
Endpoint.Say("[DEBUG] File exists: " + strconv.FormatBool(exists))
```

## Best Practices

1. **Security First**
   - Always include authorization checks
   - Clean up all artifacts
   - Document all system changes

2. **Code Quality**
   - Write clear, maintainable code
   - Include comprehensive documentation
   - Follow the established patterns

3. **Testing**
   - Test on multiple Windows versions
   - Verify against different EDR solutions
   - Document expected vs. actual results

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Go Documentation](https://golang.org/doc/)
- [Windows Security](https://docs.microsoft.com/en-us/windows/security/)