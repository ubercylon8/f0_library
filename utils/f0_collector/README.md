# F0RT1KA Results Collector

Lightweight utility for collecting F0RT1KA test result JSON files from Windows endpoints and exporting them to Elasticsearch for analytics and dashboard visualization.

## Overview

The F0RT1KA Results Collector (`f0_collector.exe`) is designed with clean separation of concerns:

- **Test binaries** remain pure security tests without network dependencies
- **Collector utility** handles result collection and export independently
- **Multiple deployment options** for different operational contexts

## Features

- Schema v2.0 validation
- Batch export to Elasticsearch
- Automatic retry logic for failed exports
- State management to prevent duplicate exports
- Configurable collection intervals
- Support for multiple Elasticsearch deployment types (self-hosted, Elastic Cloud)
- Flexible authentication (API keys, basic auth)
- File rotation and archival
- Comprehensive logging
- Windows Scheduled Task integration
- LimaCharlie D&R integration

## Architecture

```
Test Execution          Collection              Export
─────────────          ──────────              ──────

test.exe  ──┐
test2.exe ──┼─→ c:\F0\*.json ──→ Scanner ──→ Validator ──→ Elasticsearch
test3.exe ──┘                         │              │
                                      ↓              ↓
                                    State        Metrics
                                   Manager      Dashboard
```

## Quick Start

### 1. Build the Collector

```bash
cd utils/f0_collector
go build -o f0_collector.exe
```

For Windows cross-compilation from Linux:
```bash
GOOS=windows GOARCH=amd64 go build -o f0_collector.exe
```

### 2. Configure Elasticsearch

Edit `collector_config.json`:

```json
{
  "elasticsearch": {
    "enabled": true,
    "endpoints": ["https://your-elasticsearch.com:9200"],
    "apiKey": "YOUR_API_KEY_HERE",
    "indexPrefix": "f0rtika"
  }
}
```

**Recommended**: Use environment variable for API key:
```powershell
$env:F0_ELASTIC_API_KEY = "your-api-key-here"
```

### 3. Deploy to Elasticsearch

First, create the index template:

```bash
# Using curl
curl -X PUT "https://your-elasticsearch.com:9200/_index_template/f0rtika-template" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @elasticsearch-index-template.json

# Or using Kibana Dev Tools:
# Copy contents of elasticsearch-index-template.json and run:
PUT _index_template/f0rtika-template
{ ... paste template JSON ... }
```

Create the ILM policy:

```bash
curl -X PUT "https://your-elasticsearch.com:9200/_ilm/policy/f0rtika-ilm-policy" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @elasticsearch-ilm-policy.json
```

### 4. Test Collection

```powershell
# Test configuration and connectivity
.\f0_collector.exe validate

# Run one-time collection with verbose output
.\f0_collector.exe collect --once --verbose

# Check status
.\f0_collector.exe status
```

## Deployment Options

### Option 1: Windows Scheduled Task (Recommended)

Deploy as a scheduled task that runs every 5 minutes:

```powershell
# Run as Administrator
.\deploy-collector-task.ps1

# Or with custom interval (10 minutes)
.\deploy-collector-task.ps1 -Interval 10
```

**What it does:**
- Copies `f0_collector.exe` to `c:\F0\`
- Deploys configuration file
- Creates scheduled task running as SYSTEM
- Sets restrictive file permissions
- Validates deployment

**Verify deployment:**
```powershell
# Check task exists
Get-ScheduledTask -TaskName "F0RT1KA Results Collector"

# View task history
Get-ScheduledTask -TaskName "F0RT1KA Results Collector" | Get-ScheduledTaskInfo

# Manually trigger task
Start-ScheduledTask -TaskName "F0RT1KA Results Collector"
```

### Option 2: LimaCharlie D&R Integration

Deploy D&R rules for automatic collection when test results are created:

```bash
# Deploy rules to LimaCharlie organization
./deploy-limacharlie-rules.sh sb

# Rules will:
# - Detect new test_execution_log.json files in c:\F0
# - Automatically trigger collection
# - Monitor collector execution
# - Alert on failures
```

**Prerequisites:**
- LimaCharlie CLI installed: `pip install limacharlie`
- Authenticated to organization: `limacharlie login`
- Collector deployed to endpoints

**Verify rules:**
```bash
# List deployed rules
limacharlie dr list | grep f0rtika

# View rule details
limacharlie dr show f0rtika-test-result-created
```

### Option 3: Manual Collection

Simple batch script for ad-hoc collection:

```powershell
.\collect-now.ps1
```

## Configuration Reference

### Complete Configuration Example

```json
{
  "version": "1.0",
  "collector": {
    "scanPath": "c:\\F0",
    "scanPattern": "**/test_execution_log.json",
    "stateFile": "c:\\F0\\.collector_state.json",
    "moveCollected": true,
    "collectedPath": "c:\\F0\\collected"
  },
  "elasticsearch": {
    "enabled": true,
    "endpoints": ["https://elastic.example.com:9200"],
    "cloudId": "",
    "apiKey": "",
    "username": "",
    "password": "",
    "indexPrefix": "f0rtika",
    "indexPattern": "f0rtika-{yyyy.MM.dd}",
    "bulkSize": 100,
    "timeout": 30,
    "retryAttempts": 3,
    "retryDelay": 5,
    "tlsVerify": true,
    "tlsCert": ""
  },
  "logging": {
    "level": "info",
    "file": "c:\\F0\\collector.log",
    "maxSizeMB": 10,
    "maxBackups": 3,
    "console": true
  },
  "validation": {
    "schemaVersion": "2.0",
    "strictMode": true,
    "skipInvalid": false
  }
}
```

### Elasticsearch Authentication

**API Key (Recommended):**
```json
{
  "elasticsearch": {
    "apiKey": "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw=="
  }
}
```

Create API key in Kibana:
1. Stack Management → Security → API keys
2. Create API key with permissions:
   - `indices:data/write/bulk` on `f0rtika-*`
   - `indices:admin/create` on `f0rtika-*`

**Basic Auth:**
```json
{
  "elasticsearch": {
    "username": "f0rtika_collector",
    "password": "secure-password-here"
  }
}
```

**Elastic Cloud:**
```json
{
  "elasticsearch": {
    "cloudId": "deployment-name:abc123...",
    "apiKey": "your-api-key"
  }
}
```

### Environment Variables

Override sensitive configuration values:

```powershell
# API Key
$env:F0_ELASTIC_API_KEY = "your-api-key"

# Username/Password
$env:F0_ELASTIC_USERNAME = "collector"
$env:F0_ELASTIC_PASSWORD = "password"

# Cloud ID
$env:F0_ELASTIC_CLOUD_ID = "deployment:abc123..."
```

## CLI Reference

### Commands

```bash
# Collect test results
f0_collector.exe collect [options]

# Validate configuration and connectivity
f0_collector.exe validate

# Show collection status and statistics
f0_collector.exe status

# Reset state file
f0_collector.exe reset

# Show version
f0_collector.exe version
```

### Collect Options

```bash
--config <path>     Path to configuration file (default: c:\F0\collector_config.json)
--once              Run once and exit (vs. continuous mode)
--interval <sec>    Collection interval in seconds (default: 300)
--dry-run           Scan and validate only, don't export
--force             Force re-collection of already collected files
--verbose           Enable verbose logging
```

### Examples

```powershell
# One-time collection
f0_collector.exe collect --once

# Continuous collection every 5 minutes
f0_collector.exe collect --interval 300

# Dry run to test
f0_collector.exe collect --dry-run --verbose

# Force re-collection
f0_collector.exe collect --force --once

# Custom config location
f0_collector.exe collect --config c:\custom\config.json --once
```

## Monitoring and Troubleshooting

### View Logs

```powershell
# Tail log file
Get-Content c:\F0\collector.log -Tail 50 -Wait

# View errors only
Get-Content c:\F0\collector.log | Select-String "ERROR"

# View recent collections
Get-Content c:\F0\collector.log | Select-String "Collection complete"
```

### Check State

```powershell
# View state file
Get-Content c:\F0\.collector_state.json | ConvertFrom-Json | Format-List

# Check statistics
f0_collector.exe status
```

### Common Issues

**Issue:** Elasticsearch connection timeout

**Solution:**
- Check network connectivity: `Test-NetConnection elastic.example.com -Port 9200`
- Verify TLS certificates
- Check firewall rules
- Validate API key permissions

**Issue:** Validation errors

**Solution:**
- Check test results conform to schema v2.0
- Review validation errors in logs
- Use `--verbose` flag for detailed output
- Verify test_logger.go is up to date

**Issue:** Files not being collected

**Solution:**
- Check scan path configuration
- Verify file permissions
- Review state file for duplicates
- Use `--force` to re-collect

**Issue:** Scheduled task not running

**Solution:**
```powershell
# Check task status
Get-ScheduledTask -TaskName "F0RT1KA Results Collector" | Get-ScheduledTaskInfo

# View task history
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" |
  Where-Object {$_.Message -match "F0RT1KA"}

# Manually trigger
Start-ScheduledTask -TaskName "F0RT1KA Results Collector"
```

## Elasticsearch Queries

### View Recent Results

```json
GET f0rtika-*/_search
{
  "size": 10,
  "sort": [{"startTime": "desc"}],
  "query": {"match_all": {}}
}
```

### Protection Rate by Organization

```json
GET f0rtika-*/_search
{
  "size": 0,
  "aggs": {
    "by_org": {
      "terms": {"field": "executionContext.organization"},
      "aggs": {
        "protected": {
          "filter": {"term": {"outcome.protected": true}}
        }
      }
    }
  }
}
```

### Technique Coverage

```json
GET f0rtika-*/_search
{
  "size": 0,
  "aggs": {
    "techniques": {
      "terms": {"field": "testMetadata.techniques", "size": 50},
      "aggs": {
        "detection_rate": {
          "avg": {"field": "outcome.protected"}
        }
      }
    }
  }
}
```

### Time Series - Daily Test Count

```json
GET f0rtika-*/_search
{
  "size": 0,
  "aggs": {
    "daily": {
      "date_histogram": {
        "field": "startTime",
        "calendar_interval": "day"
      },
      "aggs": {
        "protected": {
          "filter": {"term": {"outcome.protected": true}}
        }
      }
    }
  }
}
```

## Dashboard Setup

### Import to Kibana

1. Navigate to **Stack Management → Saved Objects**
2. Click **Import**
3. Select dashboard JSON file (when available)
4. Resolve index pattern conflicts if needed

### Create Custom Dashboard

Key visualizations to create:

1. **Protection Rate Over Time**
   - Type: Line chart
   - X-axis: Date histogram on `startTime`
   - Y-axis: Average of `outcome.protected`

2. **Tests by Organization**
   - Type: Pie chart
   - Slice by: `executionContext.organization`

3. **Technique Detection Rates**
   - Type: Bar chart
   - X-axis: Terms aggregation on `testMetadata.techniques`
   - Y-axis: Percentage of `outcome.protected = true`

4. **Test Category Distribution**
   - Type: Tag cloud
   - Tags: `testMetadata.category`
   - Size: Count

5. **Recent Test Results**
   - Type: Data table
   - Columns: `testName`, `executionContext.organization`, `outcome.protected`, `startTime`
   - Sort: `startTime` descending

## File Structure

```
f0_collector/
├── README.md                           # This file
├── F0_COLLECTOR_SPECIFICATION.md       # Technical specification
├── go.mod                              # Go module dependencies
├── go.sum                              # Go dependency checksums
├── main.go                             # CLI entry point
├── config.go                           # Configuration handling
├── logger.go                           # Logging setup
├── scanner.go                          # File scanning
├── validator.go                        # Schema validation
├── exporter.go                         # Elasticsearch export
├── collector.go                        # Main orchestration
├── state.go                            # State management
├── collector_config.json               # Default configuration
├── elasticsearch-index-template.json   # ES index template
├── elasticsearch-ilm-policy.json       # ES lifecycle policy
├── deploy-collector-task.ps1           # Windows deployment script
├── collect-now.ps1                     # Manual collection script
├── limacharlie-dr-rules.yaml          # LimaCharlie D&R rules
└── deploy-limacharlie-rules.sh        # LC deployment script
```

## Security Considerations

### File Permissions

Configuration file should have restricted ACLs:
- SYSTEM: Full Control
- Administrators: Full Control
- All others: No access

Deployment script automatically sets these permissions.

### Credential Management

**Best Practices:**
1. Use API keys instead of username/password
2. Store sensitive values in environment variables
3. Rotate API keys regularly
4. Use principle of least privilege for API key permissions

**API Key Permissions Required:**
```
indices:data/write/bulk on f0rtika-*
indices:admin/create on f0rtika-*
```

### Network Security

- TLS verification enabled by default
- Support for custom CA certificates
- No credentials in command-line arguments
- Logs don't contain sensitive data

## Performance Tuning

### Bulk Size

Adjust `bulkSize` based on collection volume:
- Small deployments (< 10 tests/day): 10-50
- Medium deployments (10-100 tests/day): 50-100
- Large deployments (> 100 tests/day): 100-500

### Collection Interval

Balance between freshness and overhead:
- Real-time monitoring: 1-2 minutes
- Standard operations: 5-10 minutes
- Low-priority: 30-60 minutes

### State File Cleanup

State file is automatically cleaned up (30-day retention by default).

For manual cleanup:
```powershell
# Reset state completely
f0_collector.exe reset
```

## Version History

- **v1.0.0** (2024-11-14) - Initial release
  - Elasticsearch export support
  - Schema v2.0 validation
  - Windows Scheduled Task deployment
  - LimaCharlie D&R integration
  - State management
  - Retry logic

## Support

### Documentation
- Technical Specification: `F0_COLLECTOR_SPECIFICATION.md`
- Schema Guide: `../TEST_RESULTS_SCHEMA_GUIDE.md`
- Framework Docs: `../../CLAUDE.md`

### Common Commands

```powershell
# Quick health check
f0_collector.exe validate && f0_collector.exe status

# Test end-to-end
f0_collector.exe collect --once --dry-run --verbose

# View recent activity
Get-Content c:\F0\collector.log -Tail 20

# Reset and start fresh
f0_collector.exe reset
f0_collector.exe collect --once --verbose
```

## Future Enhancements

Planned for future versions:
- Additional export targets (S3, Azure Blob)
- Prometheus metrics endpoint
- Web UI for configuration and monitoring
- Dashboard auto-provisioning
- Real-time streaming mode
- Multi-platform support (Linux, macOS)
