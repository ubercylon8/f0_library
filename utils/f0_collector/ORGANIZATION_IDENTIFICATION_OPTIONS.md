# F0RT1KA Organization Identification Options

Comprehensive guide for implementing organization identifiers in F0RT1KA test results, with approaches that work with or without LimaCharlie.

**Created**: 2025-01-23
**Status**: Design Reference
**Related**: Schema v2.0 `executionContext.organization` field

---

## Problem Statement

F0RT1KA test results need consistent organization identification for multi-org Elasticsearch analytics. Challenges:

1. **Not all deployments have LimaCharlie** - Need standalone solution
2. **Multiple organizations** - sb, tpsgl, rga, and potentially more
3. **Consistent data in Elasticsearch** - Must work across all deployment methods
4. **Schema v2.0 compliance** - `executionContext.organization` is required field

---

## Current State

**Schema v2.0 Definition**:
```json
{
  "executionContext": {
    "organization": {
      "type": "string",
      "description": "Organization identifier (sb, tpsgl, rga, etc.)",
      "examples": ["sb", "tpsgl", "rga"]
    }
  }
}
```

**Current Gap**: Tests are not consistently setting the organization field, and there's no standardized mechanism for endpoints without LimaCharlie to specify their organization.

---

## Option 1: Configuration File Approach ⭐ (Simplest)

**How it works**: Add organization identifier to collector configuration file

### Configuration

Add to `collector_config.json`:

```json
{
  "version": "1.0",
  "organization": {
    "id": "sb",
    "name": "SafeBreach",
    "region": "us-east",
    "tenant": "prod-001"
  },
  "collector": {
    "scanPath": "c:\\F0",
    "scanPattern": "**/test_execution_log.json",
    "stateFile": "c:\\F0\\.collector_state.json",
    "moveCollected": true,
    "collectedPath": "c:\\F0\\collected"
  },
  "elasticsearch": { ... }
}
```

### Collection Flow

```
1. Test Execution
   └─→ Creates test_execution_log.json
       └─→ organization: "" (empty or missing)

2. Collector Scans
   └─→ Reads test_execution_log.json
   └─→ Reads organization from collector_config.json
   └─→ Enriches: result.executionContext.organization = config.organization.id

3. Export to Elasticsearch
   └─→ Test result now has organization: "sb"
```

### Implementation Notes

**Collector Enhancement Required**:
- Read organization config
- Enrich test results before validation
- Override only if test result is missing org field
- Log enrichment for audit trail

**Deployment**:
```powershell
# During collector deployment
$config = @{
    organization = @{
        id = "sb"
        name = "SafeBreach"
    }
} | ConvertTo-Json

$config | Out-File -FilePath "c:\F0\collector_config.json"
```

### Pros & Cons

✅ **Advantages**:
- Simple to implement
- No changes to test binaries required
- Centralized configuration per endpoint
- Works without LimaCharlie
- Easy to update (just edit config file)
- Human-readable configuration

❌ **Disadvantages**:
- Manual configuration per endpoint
- If collector config is missing/corrupt, no org ID
- Tests could theoretically override with wrong org
- Config file could be tampered with

### Best For
- **Small to medium deployments** (< 50 endpoints)
- **Manual deployment scenarios**
- **Quick setup without complex infrastructure**
- **Getting started quickly**

---

## Option 2: Environment Variable Approach (Flexible)

**How it works**: Read organization from system-level environment variable

### Configuration

**PowerShell** (Windows):
```powershell
# Set at system level (persists across reboots)
[System.Environment]::SetEnvironmentVariable(
    "F0_ORGANIZATION_ID",
    "sb",
    "Machine"
)

# Set additional context
[System.Environment]::SetEnvironmentVariable(
    "F0_ENVIRONMENT",
    "production",
    "Machine"
)
```

**CMD** (Windows):
```cmd
setx F0_ORGANIZATION_ID "sb" /M
setx F0_ENVIRONMENT "production" /M
```

### Test Implementation

Tests read environment variables directly:

```go
// In test code (or in test_logger.go)
import (
    "os"
    "github.com/google/uuid"
)

func initExecutionContext() ExecutionContext {
    // Read from environment
    orgID := os.Getenv("F0_ORGANIZATION_ID")
    if orgID == "" {
        orgID = "unknown"  // fallback
    }

    environment := os.Getenv("F0_ENVIRONMENT")
    if environment == "" {
        environment = "lab"  // fallback
    }

    return ExecutionContext{
        ExecutionID:  uuid.New().String(),
        Organization: orgID,
        Environment:  environment,
        DeploymentType: "automated",
    }
}
```

### Deployment Script

```powershell
# deploy-f0-with-org.ps1
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("sb", "tpsgl", "rga")]
    [string]$Organization,

    [Parameter(Mandatory=$false)]
    [ValidateSet("production", "staging", "lab", "development", "testing")]
    [string]$Environment = "lab"
)

# Set environment variables at system level
[System.Environment]::SetEnvironmentVariable(
    "F0_ORGANIZATION_ID",
    $Organization,
    "Machine"
)

[System.Environment]::SetEnvironmentVariable(
    "F0_ENVIRONMENT",
    $Environment,
    "Machine"
)

Write-Host "✓ Organization set to: $Organization"
Write-Host "✓ Environment set to: $Environment"
Write-Host ""
Write-Host "Note: Restart any running processes to pick up new environment variables"
```

### Pros & Cons

✅ **Advantages**:
- OS-level configuration (standard practice)
- Survives reboots
- Tests automatically pick it up
- Easy to script and automate
- Works without collector config
- No file management needed
- Can be set via Group Policy (Windows)

❌ **Disadvantages**:
- Requires environment variable to be set
- Not immediately visible in file system
- Could be overridden by user processes
- Requires process restart to pick up changes

### Best For
- **Automated deployments**
- **CI/CD pipelines**
- **Group Policy managed environments**
- **Infrastructure as Code (IaC)**

---

## Option 3: Registry-Based Configuration (Windows Native)

**How it works**: Store organization ID in Windows Registry

### Configuration

**Registry Location**: `HKLM:\SOFTWARE\F0RT1KA`

**PowerShell Setup**:
```powershell
# Create registry key
$regPath = "HKLM:\SOFTWARE\F0RT1KA"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set organization ID
New-ItemProperty -Path $regPath `
    -Name "OrganizationID" `
    -Value "sb" `
    -PropertyType String `
    -Force

# Set additional properties
New-ItemProperty -Path $regPath `
    -Name "OrganizationName" `
    -Value "SafeBreach" `
    -PropertyType String `
    -Force

New-ItemProperty -Path $regPath `
    -Name "Environment" `
    -Value "production" `
    -PropertyType String `
    -Force
```

### Test Implementation

```go
// Read from Windows Registry
import (
    "golang.org/x/sys/windows/registry"
)

func getOrgFromRegistry() (string, error) {
    k, err := registry.OpenKey(
        registry.LOCAL_MACHINE,
        `SOFTWARE\F0RT1KA`,
        registry.QUERY_VALUE,
    )
    if err != nil {
        return "unknown", err
    }
    defer k.Close()

    orgID, _, err := k.GetStringValue("OrganizationID")
    if err != nil {
        return "unknown", err
    }

    return orgID, nil
}

func initExecutionContext() ExecutionContext {
    orgID, _ := getOrgFromRegistry()
    if orgID == "" {
        orgID = "unknown"
    }

    return ExecutionContext{
        ExecutionID:  uuid.New().String(),
        Organization: orgID,
        Environment:  "production",
    }
}
```

### Deployment Script

```powershell
# deploy-f0-registry.ps1
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("sb", "tpsgl", "rga")]
    [string]$Organization
)

# Require admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges"
    exit 1
}

# Create registry configuration
$regPath = "HKLM:\SOFTWARE\F0RT1KA"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

New-ItemProperty -Path $regPath -Name "OrganizationID" -Value $Organization -PropertyType String -Force | Out-Null
New-ItemProperty -Path $regPath -Name "ConfiguredAt" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -PropertyType String -Force | Out-Null

Write-Host "✓ Organization ID '$Organization' configured in registry"
Write-Host "  Location: HKLM:\SOFTWARE\F0RT1KA\OrganizationID"
```

### Pros & Cons

✅ **Advantages**:
- Windows-native solution (standard location)
- Protected (requires admin rights to modify)
- Persistent across reboots
- Centralized system configuration
- Auditable (registry changes are logged)
- Cannot be accidentally deleted by users
- Works with Registry-based Group Policy

❌ **Disadvantages**:
- Windows-only solution
- Requires admin rights to configure
- Slightly more complex to implement
- Less portable than other options

### Best For
- **Enterprise Windows-only deployments**
- **Environments with strict governance**
- **High-security requirements**
- **Long-term production deployments**

---

## Option 4: File-Based Configuration (Simple)

**How it works**: Drop a simple, dedicated config file on the endpoint

### Configuration File

**Location**: `C:\F0\org.conf`

**Format** (INI-style):
```ini
[organization]
id=sb
name=SafeBreach
region=us-east
tenant=prod-001

[environment]
type=production
deployment=manual
```

**Alternative Format** (JSON):
```json
{
  "organization": {
    "id": "sb",
    "name": "SafeBreach"
  },
  "environment": {
    "type": "production"
  }
}
```

### Test Implementation

**Simple INI Parser**:
```go
import (
    "os"
    "strings"
)

func readOrgConfig() (string, error) {
    data, err := os.ReadFile("c:\\F0\\org.conf")
    if err != nil {
        return "", err
    }

    // Simple INI parsing
    lines := strings.Split(string(data), "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if strings.HasPrefix(line, "id=") {
            return strings.TrimPrefix(line, "id="), nil
        }
    }

    return "", fmt.Errorf("organization ID not found")
}

func initExecutionContext() ExecutionContext {
    orgID, err := readOrgConfig()
    if err != nil || orgID == "" {
        orgID = "unknown"
    }

    return ExecutionContext{
        ExecutionID:  uuid.New().String(),
        Organization: orgID,
        Environment:  "production",
    }
}
```

### Deployment

```powershell
# Simple deployment
@"
[organization]
id=sb
name=SafeBreach

[environment]
type=production
"@ | Out-File -FilePath "c:\F0\org.conf" -Encoding ASCII

# Set restrictive permissions
$acl = Get-Acl "c:\F0\org.conf"
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")))
Set-Acl "c:\F0\org.conf" $acl
```

### Pros & Cons

✅ **Advantages**:
- Very simple to implement
- Human-readable (easy to debug)
- Easy to deploy and update
- No special permissions needed (for reading)
- Works everywhere (cross-platform)
- Can be version controlled

❌ **Disadvantages**:
- Could be tampered with by users
- Could be accidentally deleted
- Another file to manage
- Not as secure as registry or env vars

### Best For
- **Lab environments**
- **Quick deployments**
- **Development/testing**
- **Environments without strict security**

---

## Option 5: Hybrid Approach ⭐ (Recommended for Production)

**How it works**: Hierarchical configuration with intelligent fallbacks

### Priority Order

```
1. LimaCharlie Metadata (if available)     [Highest Priority]
   └─→ Use org from LC sensor tags/metadata

2. Test-Embedded Value (if set)
   └─→ Test explicitly set organization

3. Environment Variable
   └─→ F0_ORGANIZATION_ID

4. Collector Config File
   └─→ collector_config.json → organization.id

5. Local Config File
   └─→ c:\F0\org.conf

6. Registry (Windows)
   └─→ HKLM:\SOFTWARE\F0RT1KA\OrganizationID

7. Hostname Parsing (convention-based)
   └─→ Parse "sb-prod-win01" → "sb"

8. Default/Unknown                          [Lowest Priority]
   └─→ "unknown"
```

### Implementation (Collector)

```go
// Determine organization with fallback chain
func determineOrganization(testResult *TestResult, config *Config) string {
    // 1. Check if test already set it explicitly
    if testResult.ExecutionContext.Organization != "" &&
       testResult.ExecutionContext.Organization != "unknown" {
        log.Debugf("Using organization from test result: %s",
            testResult.ExecutionContext.Organization)
        return testResult.ExecutionContext.Organization
    }

    // 2. Check LimaCharlie context (if available)
    if lcOrg := getLimaCharlieOrg(); lcOrg != "" {
        log.Debugf("Using organization from LimaCharlie: %s", lcOrg)
        return lcOrg
    }

    // 3. Check environment variable
    if envOrg := os.Getenv("F0_ORGANIZATION_ID"); envOrg != "" {
        log.Debugf("Using organization from environment variable: %s", envOrg)
        return envOrg
    }

    // 4. Check collector config
    if config.Organization.ID != "" {
        log.Debugf("Using organization from collector config: %s",
            config.Organization.ID)
        return config.Organization.ID
    }

    // 5. Check local org.conf file
    if fileOrg := readOrgConfigFile(); fileOrg != "" {
        log.Debugf("Using organization from org.conf: %s", fileOrg)
        return fileOrg
    }

    // 6. Check Windows Registry (Windows only)
    if runtime.GOOS == "windows" {
        if regOrg, err := getOrgFromRegistry(); err == nil && regOrg != "" {
            log.Debugf("Using organization from registry: %s", regOrg)
            return regOrg
        }
    }

    // 7. Try to parse from hostname
    if hostnameOrg := parseOrgFromHostname(); hostnameOrg != "" {
        log.Warnf("Using organization parsed from hostname: %s", hostnameOrg)
        return hostnameOrg
    }

    // 8. Default - log warning
    log.Warnf("No organization identifier found - using 'unknown'")
    return "unknown"
}

// Helper: Parse org from hostname (e.g., "sb-prod-win01" -> "sb")
func parseOrgFromHostname() string {
    hostname, err := os.Hostname()
    if err != nil {
        return ""
    }

    parts := strings.Split(hostname, "-")
    if len(parts) >= 1 {
        // Validate against known orgs
        org := strings.ToLower(parts[0])
        knownOrgs := []string{"sb", "tpsgl", "rga"}
        for _, known := range knownOrgs {
            if org == known {
                return org
            }
        }
    }

    return ""
}

// Helper: Get org from LimaCharlie (if available)
func getLimaCharlieOrg() string {
    // Check for LC environment variables or metadata files
    // This would be implemented based on LC integration
    return ""
}
```

### Configuration Example

```json
// collector_config.json with hybrid support
{
  "version": "1.0",
  "organization": {
    "id": "sb",
    "fallbackStrategy": "hybrid",
    "allowTestOverride": false
  },
  "collector": { ... }
}
```

### Pros & Cons

✅ **Advantages**:
- Maximum flexibility
- Works with or without LimaCharlie
- Graceful degradation
- Supports multiple deployment strategies
- Auto-detection capability
- Production-ready reliability

❌ **Disadvantages**:
- More complex to implement
- Need to document priority order clearly
- Debugging can be harder (which source was used?)
- Slightly higher maintenance

### Best For
- **Multi-environment deployments** (dev, staging, prod)
- **Multi-organization deployments** (sb, tpsgl, rga)
- **Mixed deployment strategies** (some with LC, some without)
- **Production environments requiring reliability**

---

## Option 6: Hostname Convention (Zero-Config)

**How it works**: Parse organization from system hostname using naming convention

### Naming Convention

**Format**: `<org>-<env>-<role>-<number>`

**Examples**:
```
sb-prod-win-01       → org: "sb",    env: "production"
tpsgl-lab-test-05    → org: "tpsgl", env: "lab"
rga-staging-web-12   → org: "rga",   env: "staging"
sb-dev-app-03        → org: "sb",    env: "development"
```

### Implementation

```go
import (
    "os"
    "strings"
)

type HostnameConfig struct {
    Organization string
    Environment  string
    Role         string
    Number       string
}

func parseOrgFromHostname() (HostnameConfig, error) {
    hostname, err := os.Hostname()
    if err != nil {
        return HostnameConfig{}, err
    }

    // Parse hostname: org-env-role-number
    parts := strings.Split(strings.ToLower(hostname), "-")

    if len(parts) < 4 {
        return HostnameConfig{}, fmt.Errorf("hostname doesn't match convention")
    }

    // Map environment abbreviations to full names
    envMap := map[string]string{
        "prod":    "production",
        "stage":   "staging",
        "stg":     "staging",
        "dev":     "development",
        "test":    "testing",
        "lab":     "lab",
    }

    environment := envMap[parts[1]]
    if environment == "" {
        environment = parts[1] // use as-is if not mapped
    }

    return HostnameConfig{
        Organization: parts[0],
        Environment:  environment,
        Role:         parts[2],
        Number:       parts[3],
    }, nil
}

func initExecutionContext() ExecutionContext {
    config, err := parseOrgFromHostname()

    orgID := "unknown"
    environment := "lab"

    if err == nil {
        orgID = config.Organization
        environment = config.Environment
    }

    return ExecutionContext{
        ExecutionID:  uuid.New().String(),
        Organization: orgID,
        Environment:  environment,
    }
}
```

### Validation

```go
// Validate parsed organization against known list
func validateOrganization(org string) bool {
    knownOrgs := []string{"sb", "tpsgl", "rga"}

    for _, known := range knownOrgs {
        if org == known {
            return true
        }
    }

    return false
}
```

### Pros & Cons

✅ **Advantages**:
- Zero configuration needed
- Automatically works everywhere
- Follows infrastructure naming standards
- Easy to implement
- No files or registry to manage
- Self-documenting (hostname tells the story)

❌ **Disadvantages**:
- Requires strict hostname convention
- May not work for all environments
- Limited flexibility
- Hostname changes break configuration
- Not suitable for dynamic/cloud environments with auto-generated names

### Best For
- **Environments with strict naming conventions**
- **Infrastructure as Code deployments**
- **Consistent on-prem environments**
- **Quick proof-of-concept**

---

## Comparison Matrix

| Approach | Complexity | Flexibility | Security | Setup Time | Maintenance | LC Required | Best Deployment Size |
|----------|-----------|-------------|----------|------------|-------------|-------------|---------------------|
| **Config File** | Low | Medium | Low | 5 min | Low | No | Small (< 50) |
| **Environment Var** | Low | High | Medium | 5 min | Low | No | Medium (50-200) |
| **Registry** | Medium | Medium | High | 10 min | Low | No | Large (200+) |
| **File-Based** | Low | Medium | Low | 2 min | Low | No | Lab/Dev |
| **Hybrid** | High | Very High | High | 30 min | Medium | No | Enterprise |
| **Hostname** | Low | Low | Medium | 0 min | None | No | Convention-based |

---

## Recommended Approach by Scenario

### Scenario 1: Quick Start / Lab Environment
**Recommendation**: Option 1 (Config File) or Option 4 (File-Based)
- Fast setup
- Easy to change
- Good for testing

### Scenario 2: Small Production (< 50 endpoints)
**Recommendation**: Option 2 (Environment Variable)
- Easy automation
- OS-level configuration
- No file management

### Scenario 3: Enterprise Windows (100+ endpoints)
**Recommendation**: Option 3 (Registry) + Option 2 (Environment Variable)
- Registry for production
- Env var for flexibility
- Group Policy compatible

### Scenario 4: Multi-Org, Multi-Environment
**Recommendation**: Option 5 (Hybrid)
- Maximum flexibility
- Graceful fallbacks
- Works everywhere

### Scenario 5: Infrastructure with Naming Standards
**Recommendation**: Option 6 (Hostname) as primary, Option 2 (Env Var) as override
- Zero config for standard deployments
- Manual override available

---

## Implementation Roadmap

### Phase 1: Simple Start (Option 1)
**Deliverables**:
- Add `organization` field to `collector_config.json`
- Collector enriches test results before export
- Documentation for manual configuration

**Timeline**: 1-2 hours

### Phase 2: Environment Variable Support (Option 2)
**Deliverables**:
- Test_logger.go reads `F0_ORGANIZATION_ID`
- Deployment script helper
- Fallback to config file

**Timeline**: 2-3 hours

### Phase 3: Hybrid Implementation (Option 5)
**Deliverables**:
- Priority-based fallback chain
- Auto-detection capabilities
- Comprehensive logging

**Timeline**: 4-6 hours

### Phase 4: Advanced Features
**Deliverables**:
- Registry support (Windows)
- Hostname parsing
- LimaCharlie integration
- Validation and alerts

**Timeline**: 6-8 hours

---

## Testing Strategy

### Test Cases

1. **No Configuration**
   - Expected: organization = "unknown"
   - Log: Warning message

2. **Config File Only**
   - Expected: Use value from collector_config.json
   - Log: "Using organization from collector config"

3. **Environment Variable Set**
   - Expected: Use env var (higher priority)
   - Log: "Using organization from environment variable"

4. **Multiple Sources**
   - Expected: Use highest priority source
   - Log: Show which source was used

5. **Invalid Organization ID**
   - Expected: Use "unknown" and log warning
   - Log: "Invalid organization ID: xyz"

### Validation

```bash
# Test collector enrichment
./f0_collector.exe collect --dry-run --verbose

# Expected output should show:
# [INFO] Organization determination:
# [INFO]   - Test value: (empty)
# [INFO]   - Environment variable: sb
# [INFO]   - Config file: (not set)
# [INFO]   - Using: sb (from environment variable)
```

---

## Security Considerations

### File-Based Configurations
- Set restrictive ACLs (SYSTEM and Administrators only)
- Use `icacls` to prevent user modifications
- Regular integrity checks

### Environment Variables
- Set at Machine level (requires admin)
- Cannot be overridden by user processes
- Audit changes via Windows Event Log

### Registry
- `HKLM` requires admin to modify
- Registry changes are audited
- Can be protected via Group Policy

### LimaCharlie
- Organization context from trusted source (LC platform)
- No local configuration needed
- Tamper-proof

---

## Migration Path

### Current State → Phase 1 (Config File)

1. **Add organization to collector config**
   ```json
   {
     "organization": {
       "id": "sb"
     }
   }
   ```

2. **Update collector to enrich results**
   - Before validation, set organization if missing

3. **Deploy updated collector**
   - No test changes needed

### Phase 1 → Phase 2 (Add Env Var Support)

1. **Update test_logger.go**
   - Read `F0_ORGANIZATION_ID` environment variable
   - Set in ExecutionContext

2. **Deploy env var script**
   ```powershell
   [System.Environment]::SetEnvironmentVariable("F0_ORGANIZATION_ID", "sb", "Machine")
   ```

3. **Tests now self-configure**
   - No collector enrichment needed (but keep as fallback)

---

## Troubleshooting

### Issue: Organization shows as "unknown"

**Check**:
1. Environment variable set? `echo %F0_ORGANIZATION_ID%`
2. Config file exists? `type c:\F0\collector_config.json`
3. Registry key exists? `reg query HKLM\SOFTWARE\F0RT1KA /v OrganizationID`
4. Hostname follows convention? `hostname`

**Solution**: Set at least one configuration source

### Issue: Wrong organization in Elasticsearch

**Check**:
1. Which source is being used? (Check collector logs)
2. Priority order correct?
3. Test overriding org value?

**Solution**: Check priority chain, ensure correct source has highest priority

### Issue: Organization changes not taking effect

**Check**:
1. Collector restarted? (Required for config file changes)
2. Process restarted? (Required for env var changes)
3. Cache/state file issue?

**Solution**: Restart collector, clear state file

---

## Future Enhancements

### Cloud Integration
- Azure Managed Identity → Tenant ID → Organization
- AWS Instance Tags → Organization
- GCP Instance Metadata → Organization

### Dynamic Organization
- Support multiple organizations per endpoint
- Organization determined by test execution context
- Per-test organization override

### Centralized Management
- REST API to query organization mapping
- Central configuration service
- Real-time updates without restart

---

## References

- **Schema v2.0**: `test-results-schema-v2.0.json`
- **Collector Config**: `utils/f0_collector/collector_config.json`
- **Deployment Guide**: `utils/f0_collector/README.md`
- **LimaCharlie Integration**: `utils/f0_collector/limacharlie/README.md`

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2025-01-23 | Document all options | Explore before implementing |
| TBD | Choose primary approach | Based on deployment requirements |
| TBD | Implement Phase 1 | Start with simplest (config file) |

---

**Last Updated**: 2025-01-23
**Status**: Options documented, implementation pending
**Next Step**: Implement Option 1 (Config File Approach)
