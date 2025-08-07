# CLAUDE.md - F0RT1KA Test Development Guide

This file provides comprehensive guidance for developing tests in the F0RT1KA security testing framework.

## Overview
Tests in this directory simulate real attack techniques to evaluate AV/EDR detection capabilities. Each test is mapped to MITRE ATT&CK techniques and follows strict development patterns.

## Critical Requirements

### 1. Binary Drop Location
**ALL binaries MUST be dropped to `c:\F0`** - This is a hard requirement for all tests.

```go
targetDir := "c:\\F0"
os.MkdirAll(targetDir, 0755)
```

### 2. PowerShell Script Requirements
All PowerShell scripts must include:
- Admin privilege check function
- Execution policy bypass functionality
- Proper error handling

```powershell
# Required functions
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Host "[!] Failed to bypass execution policy: $_" -ForegroundColor Red
        return $false
    }
}
```

### 3. Test Exit Codes
Use the appropriate exit codes from the Endpoint library:

```go
// Protected outcomes
Endpoint.FileQuarantinedOnExtraction  // 105 - File caught before execution
Endpoint.ExecutionPrevented           // 126 - Execution blocked by EDR
Endpoint.FileQuarantinedOnExecution   // 127 - File caught during execution

// Unprotected outcome  
Endpoint.Unprotected                  // 101 - Attack succeeded

// Error conditions
Endpoint.UnexpectedTestError          // 1   - Test error
Endpoint.TimeoutExceeded              // 102 - Timeout (see special cases)
```

## Standard Test Structure

### Directory Layout
```
tests_source/
└── <uuid>/                       # Use lowercase UUID
    ├── <uuid>.go                 # Main test implementation
    ├── <uuid>_info.md           # Detailed information card
    ├── README.md                # Brief overview
    ├── go.mod                   # Module dependencies
    └── [embedded files]         # Any binaries/scripts to embed
```

### Test Implementation Template

```go
//go:build windows
// +build windows

/*
ID: <uuid>
NAME: <Test Name>
TECHNIQUE: <MITRE ATT&CK IDs>
UNIT: response
CREATED: <date>
*/
package main

import (
    _ "embed"
    "os"
    
    Dropper "github.com/preludeorg/libraries/go/tests/dropper"
    Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed malicious_file.exe
var maliciousFile []byte

func test() {
    // Initialize dropper
    if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
        Endpoint.Say("Dropper initialization failed: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    // CRITICAL: Drop to c:\F0
    targetDir := "c:\\F0"
    os.MkdirAll(targetDir, 0755)
    
    // Drop embedded files
    filePath := filepath.Join(targetDir, "malicious.exe")
    err := os.WriteFile(filePath, maliciousFile, 0755)
    if err != nil {
        Endpoint.Say("Failed to drop file: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }
    
    // Check for quarantine
    Endpoint.Say("Checking for defensive reaction")
    Endpoint.Wait(3)
    
    if Endpoint.Quarantined("malicious.exe", maliciousFile) {
        Endpoint.Say("File was quarantined!")
        Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
    }
    
    // Execute attack simulation
    Endpoint.Say("Executing attack simulation")
    // ... attack logic ...
    
    // Determine outcome
    if attackBlocked {
        Endpoint.Stop(Endpoint.ExecutionPrevented)
    } else {
        Endpoint.Stop(Endpoint.Unprotected)
    }
}

func main() {
    Endpoint.Start(test)
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

## Special Cases

### Long-Running Tests (>30 seconds)

The Endpoint framework has a **hardcoded 30-second timeout** that cannot be overridden. For tests requiring more time (e.g., ransomware simulations with multiple phases), use a custom test runner:

```go
func main() {
    // CUSTOM RUNNER: Bypass Endpoint.Start() to avoid 30-second timeout limitation
    Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
    Endpoint.Say("Using custom runner with extended timeout for long-running simulation")
    
    done := make(chan bool, 1)
    go func() {
        test()
        done <- true
    }()
    
    // Wait for test completion or custom timeout
    select {
    case <-done:
        Endpoint.Say("Test completed within timeout window")
    case <-time.After(5 * time.Minute):  // Adjust as needed
        Endpoint.Say("Test timed out after 5 minutes")
        Endpoint.Stop(Endpoint.TimeoutExceeded)
    }
}
```

**When to use custom runner:**
- Test requires >30 seconds to complete all phases
- Multi-stage attacks with waiting periods
- Tests monitoring background processes
- Simulations with realistic timing requirements

**Example: SafePay Ransomware Simulation (109266e2-2310-40ea-9f63-b97e4b7fda61)**
- Requires 4+ minutes for full simulation
- Tracks 5 distinct phases via status file
- Uses custom 5-minute timeout
- See `LONG_RUNNING_TEST_SOLUTION.md` for details

### PowerShell Execution

Always bypass execution policy when running PowerShell scripts:

```go
cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
```

For detached processes (when monitoring is needed):
```go
cmd := exec.Command("cmd.exe", "/C", "start", "/MIN", "powershell.exe", 
    "-ExecutionPolicy", "Bypass", "-File", scriptPath)
```

### Status Tracking for Complex Tests

For multi-phase tests, use status files for inter-process communication:

```powershell
# PowerShell side
"PHASE_1_COMPLETE" | Out-File "C:\F0\status.txt" -Encoding ASCII
```

```go
// Go side
func readStatus() string {
    data, err := os.ReadFile("C:\\F0\\status.txt")
    if err != nil {
        return ""
    }
    // Remove UTF-8 BOM if present
    if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        data = data[3:]
    }
    return strings.TrimSpace(string(data))
}
```

## Build and Sign Process

### Build Test
```bash
./utils/gobuild build tests_source/<uuid>/
```

### Sign Binary
```bash
./utils/codesign sign build/<uuid>/<uuid>.exe
```

### Build and Sign All Tests
```bash
./utils/gobuild build-all
./utils/codesign sign-all
```

## Best Practices

### 1. Logging
- Use `Endpoint.Say()` for all output
- Include phase transitions and key decision points
- Log enough detail for debugging but avoid verbosity

### 2. Error Handling
- Always check error returns
- Use appropriate exit codes
- Clean up resources even on failure

### 3. Timing Considerations
- Use `Endpoint.Wait()` judiciously
- Give EDR time to react (typically 3-5 seconds)
- For long operations, provide progress updates

### 4. File Operations
- Always use absolute paths
- Drop all files to `c:\F0`
- Check for quarantine after dropping files
- Clean up artifacts when possible

### 5. MITRE ATT&CK Mapping
- Accurately map techniques
- Include sub-techniques where applicable
- Document in test header and info card

## Test Information Card Template (<uuid>_info.md)

```markdown
# Test Name

## Overview
Brief description of what the test simulates.

## MITRE ATT&CK Mapping
- **Technique**: T1486 - Data Encrypted for Impact
- **Sub-technique**: T1486.001 - Specific variant

## Test Behavior
1. Drops malicious binary to C:\F0
2. Executes specific attack technique
3. Monitors for defensive response

## Detection Opportunities
- Process creation with suspicious parameters
- File system modifications
- Network connections to C2
- Registry modifications

## Expected Outcomes
- **Protected (105/126)**: EDR blocks execution or quarantines file
- **Unprotected (101)**: Attack completes successfully

## Notes
Any special considerations or requirements.
```

## Common Pitfalls to Avoid

1. **Forgetting to drop to C:\F0** - Will cause test failures
2. **Not handling PowerShell execution policy** - Scripts won't run
3. **Assuming 30-second timeout is enough** - Use custom runner for long tests
4. **Not checking for quarantine** - May miss detection events
5. **Using relative paths** - Always use absolute paths
6. **Forgetting UTF-8 BOM handling** - Can corrupt status file reading
7. **Not using proper exit codes** - Results won't be properly categorized

## Testing Your Test

Before committing:
1. Build the test locally
2. Verify it compiles without errors
3. Check that embedded files are included
4. Ensure proper MITRE ATT&CK mapping
5. Document expected behavior clearly
6. Test on a Windows system if possible

## Support and Resources

- Prelude Libraries: Located in `preludeorg-libraries/`
- Utility Scripts: See `utils/README.md`
- Sample Tests: Check `sample_tests/` for examples
- Main Documentation: See root `CLAUDE.md`

## Important Security Note

These tests simulate real attack techniques. Always:
- Run in isolated environments
- Follow security best practices
- Never run on production systems
- Ensure proper authorization before testing