# F0RT1KA Architecture

## Overview

F0RT1KA is a modular security testing framework designed to evaluate endpoint detection and response (EDR) capabilities. The framework maps tests to the MITRE ATT&CK framework and provides standardized result codes.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    F0RT1KA Framework                     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐ │
│  │   Tests     │  │   Utilities  │  │   Libraries   │ │
│  │             │  │              │  │               │ │
│  │ - Source    │  │ - gobuild    │  │ - Dropper     │ │
│  │ - Samples   │  │ - codesign   │  │ - Endpoint    │ │
│  │ - Built     │  │ - PS Scripts │  │               │ │
│  └─────────────┘  └──────────────┘  └───────────────┘ │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │            Test Execution Flow                   │   │
│  │                                                  │   │
│  │  1. Build → 2. Sign → 3. Deploy → 4. Execute   │   │
│  │                                                  │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Test Framework
- **Location**: `tests_source/` and `sample_tests/`
- **Purpose**: Individual security tests mapped to MITRE ATT&CK
- **Structure**: Each test is a self-contained Go module

### 2. Build System (gobuild)
- **Location**: `utils/gobuild`
- **Purpose**: Cross-platform compilation of tests
- **Features**:
  - Multi-OS support (Windows, Linux, macOS)
  - Multi-architecture support
  - Batch building capabilities

### 3. Code Signing (codesign)
- **Location**: `utils/codesign`
- **Purpose**: Sign Windows executables
- **Features**:
  - Certificate management
  - Batch signing
  - Validation

### 4. Prelude Libraries
- **Dropper**: Handles file deployment to target directories
- **Endpoint**: Provides standardized test lifecycle management

## Test Lifecycle

### 1. Development Phase
```go
// Test implementation following standard pattern
func test() {
    Endpoint.Dropper(Dropper.Dropper)
    // Test logic
    Endpoint.Stop(resultCode)
}
```

### 2. Build Phase
```bash
./utils/gobuild build tests_source/<uuid>/
```

### 3. Sign Phase (Windows)
```bash
./utils/codesign sign build/<uuid>/<uuid>.exe
```

### 4. Execution Phase
- Test deploys to `c:\F0`
- Performs security testing action
- Returns standardized result code

## Result Codes

| Code | Constant | Description |
|------|----------|-------------|
| 101  | Endpoint.Unprotected | Attack succeeded |
| 105  | Endpoint.FileQuarantinedOnExtraction | File quarantined |
| 126  | Endpoint.ExecutionPrevented | Execution blocked |

## Bundle Results Protocol

Cyber-hygiene bundles and multi-stage intel-driven tests write `c:\F0\bundle_results.json` so the agent and ProjectAchilles can fan the run out into one Elasticsearch document per control or stage. Multi-stage tests build a `[]StageBundleDef` and call `WriteStageBundleResults()` (in each test's `test_logger.go`), which converts each stage into an entry of the `controls` array.

Each `controls` entry carries `control_id`, `control_name`, `validator`, `exit_code`, `compliant`, `severity`, `category`, `subcategory`, `techniques`, `tactics`, `expected`, `actual`, `details`, `skipped` and `error_message`, plus one optional field:

| Field | Type | Description |
|-------|------|-------------|
| `description` | string (optional, omitted when empty) | One-line description of what the stage does, copied from the stage's `Description`. ProjectAchilles stores it as `f0rtika.control_description` and shows it in the execution detail view. |

## Security Considerations

1. **Isolation**: Tests should run in isolated environments
2. **Authorization**: Only use on systems with explicit permission
3. **Cleanup**: All artifacts must be removed after testing
4. **Monitoring**: Be aware of security alerts during testing

## Directory Structure

```
f0_library/
├── tests_source/        # New test development
├── sample_tests/        # Reference implementations
├── build/              # Compiled binaries (git-ignored)
├── utils/              # Build and support tools
├── signing-certs/      # Code signing certificates
├── rules/              # Development guidelines
├── docs/               # Documentation
└── preludeorg-libraries/ # External dependencies
```

## Extension Points

### Adding New Tests
1. Generate UUID
2. Create test directory structure
3. Implement test following patterns
4. Map to MITRE ATT&CK
5. Build and sign

### Adding New Utilities
1. Create utility in `utils/`
2. Follow Go best practices
3. Add documentation
4. Include in build workflows