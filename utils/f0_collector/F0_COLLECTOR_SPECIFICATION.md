# F0RT1KA Results Collector - Technical Specification

## Overview

The F0RT1KA Results Collector (`f0_collector.exe`) is a lightweight, signed utility that collects test result JSON files from Windows endpoints and exports them to Elasticsearch for analytics and dashboard visualization.

## Design Principles

1. **Separation of Concerns** - Collection is independent of test execution
2. **Test Integrity** - Tests remain pure security tests without network dependencies
3. **Reliability** - Retry logic and error handling for network failures
4. **Security** - Signed utility with secure credential management
5. **Flexibility** - Configuration-driven for easy deployment changes

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    f0_collector.exe                          │
│                                                              │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Scanner   │→ │  Validator   │→ │  Elasticsearch   │   │
│  │            │  │              │  │    Exporter      │   │
│  │ Scans      │  │ Schema v2.0  │  │                  │   │
│  │ c:\F0\**   │  │ validation   │  │ Bulk API         │   │
│  └────────────┘  └──────────────┘  └──────────────────┘   │
│                                              ↓               │
│                                    ┌──────────────────┐     │
│                                    │  State Manager   │     │
│                                    │                  │     │
│                                    │ Track collected  │     │
│                                    │ Retry failed     │     │
│                                    └──────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                        ↓
            ┌──────────────────────┐
            │   Elasticsearch      │
            │                      │
            │  Index: f0rtika-*    │
            │  Dashboards/Kibana   │
            └──────────────────────┘
```

## Configuration Schema

**File**: `c:\F0\collector_config.json`

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
    "endpoints": [
      "https://elastic.example.com:9200"
    ],
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

### Configuration Fields

#### Collector Section
- `scanPath`: Root directory to scan for test results
- `scanPattern`: Glob pattern for finding result files
- `stateFile`: Tracks which files have been collected
- `moveCollected`: Move files after successful export
- `collectedPath`: Destination for collected files

#### Elasticsearch Section
- `enabled`: Enable/disable Elasticsearch export
- `endpoints`: Array of Elasticsearch node URLs
- `cloudId`: Elastic Cloud ID (alternative to endpoints)
- `apiKey`: API key for authentication (recommended)
- `username`/`password`: Basic auth (fallback)
- `indexPrefix`: Prefix for index names
- `indexPattern`: Date-based index pattern
- `bulkSize`: Number of docs per bulk request
- `timeout`: Request timeout in seconds
- `retryAttempts`: Number of retry attempts
- `retryDelay`: Delay between retries in seconds
- `tlsVerify`: Verify TLS certificates
- `tlsCert`: Custom CA certificate path

#### Logging Section
- `level`: debug, info, warn, error
- `file`: Log file path
- `maxSizeMB`: Max log file size before rotation
- `maxBackups`: Number of log backups to keep
- `console`: Also log to console

#### Validation Section
- `schemaVersion`: Expected schema version
- `strictMode`: Fail on schema validation errors
- `skipInvalid`: Continue processing if file invalid

## Collection Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. SCAN PHASE                                               │
│    - Recursively scan c:\F0 for test_execution_log.json    │
│    - Check state file for previously collected files        │
│    - Build list of new files to process                     │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. VALIDATION PHASE                                         │
│    - Load JSON file                                         │
│    - Validate against schema v2.0                           │
│    - Check schemaVersion field matches expected             │
│    - Log validation errors                                  │
│    - Skip or fail based on configuration                    │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. ENRICHMENT PHASE                                         │
│    - Add collection metadata:                               │
│      - collectedAt (timestamp)                              │
│      - collectorVersion                                     │
│      - collectorHost (endpoint hostname)                    │
│      - filePath (source path)                               │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. EXPORT PHASE                                             │
│    - Batch results into bulk requests                       │
│    - Send to Elasticsearch bulk API                         │
│    - Handle partial failures                                │
│    - Retry failed documents                                 │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. STATE MANAGEMENT PHASE                                   │
│    - Update state file with successfully exported files     │
│    - Move collected files to collected/ subdirectory        │
│    - Track retry attempts for failed exports                │
│    - Clean up old state entries (configurable retention)    │
└─────────────────────────────────────────────────────────────┘
```

## State Management

**State File**: `c:\F0\.collector_state.json`

```json
{
  "version": "1.0",
  "lastRun": "2024-11-14T15:30:45.123Z",
  "collectedFiles": [
    {
      "filePath": "c:\\F0\\test_execution_log.json",
      "fileHash": "sha256:abc123...",
      "collectedAt": "2024-11-14T15:30:45.123Z",
      "exportedTo": ["elasticsearch"],
      "status": "success"
    }
  ],
  "failedFiles": [
    {
      "filePath": "c:\\F0\\failed\\test_execution_log.json",
      "fileHash": "sha256:def456...",
      "lastAttempt": "2024-11-14T15:30:45.123Z",
      "attempts": 3,
      "lastError": "connection timeout",
      "status": "failed"
    }
  ],
  "statistics": {
    "totalCollected": 1234,
    "totalFailed": 5,
    "lastSuccess": "2024-11-14T15:30:45.123Z"
  }
}
```

## Elasticsearch Integration

### Index Template

```json
{
  "index_patterns": ["f0rtika-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "f0rtika-ilm-policy"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "schemaVersion": { "type": "keyword" },
        "testId": { "type": "keyword" },
        "testName": { "type": "text" },
        "testMetadata": {
          "properties": {
            "version": { "type": "keyword" },
            "category": { "type": "keyword" },
            "severity": { "type": "keyword" },
            "techniques": { "type": "keyword" },
            "tactics": { "type": "keyword" },
            "score": { "type": "float" }
          }
        },
        "executionContext": {
          "properties": {
            "executionId": { "type": "keyword" },
            "organization": { "type": "keyword" },
            "environment": { "type": "keyword" },
            "deploymentType": { "type": "keyword" },
            "triggeredBy": { "type": "keyword" }
          }
        },
        "startTime": { "type": "date" },
        "endTime": { "type": "date" },
        "durationMs": { "type": "long" },
        "exitCode": { "type": "integer" },
        "outcome": {
          "properties": {
            "protected": { "type": "boolean" },
            "category": { "type": "keyword" },
            "detectionPhase": { "type": "keyword" },
            "blockedTechniques": { "type": "keyword" },
            "successfulTechniques": { "type": "keyword" }
          }
        },
        "systemInfo": {
          "properties": {
            "hostname": { "type": "keyword" },
            "os": { "type": "keyword" },
            "osVersion": { "type": "keyword" },
            "edrProduct": { "type": "keyword" },
            "edrVersion": { "type": "keyword" }
          }
        },
        "metrics": {
          "properties": {
            "totalPhases": { "type": "integer" },
            "successfulPhases": { "type": "integer" },
            "totalFilesDropped": { "type": "integer" },
            "filesQuarantined": { "type": "integer" },
            "totalProcesses": { "type": "integer" },
            "errorCount": { "type": "integer" }
          }
        },
        "collectionMetadata": {
          "properties": {
            "collectedAt": { "type": "date" },
            "collectorVersion": { "type": "keyword" },
            "collectorHost": { "type": "keyword" },
            "filePath": { "type": "keyword" }
          }
        }
      }
    }
  }
}
```

### Document ID Strategy

Use `testId` + `executionContext.executionId` as document ID to prevent duplicates:

```
Document ID = SHA256(testId + executionId + startTime)
```

This ensures:
- Same test execution = same document ID = update (idempotent)
- Different test executions = different document IDs
- Time-based uniqueness for multiple runs of same test

### Bulk API Usage

```go
// Pseudo-code
bulkRequest := esapi.BulkRequest{
    Index: "f0rtika-2024.11.14",
    Body:  bulkBody,
}

// Bulk body format:
// { "index": { "_id": "doc-id-123" } }
// { ...test result JSON... }
// { "index": { "_id": "doc-id-456" } }
// { ...test result JSON... }
```

## Error Handling

### Validation Errors
- **Strict Mode ON**: Log error, skip file, mark as failed
- **Strict Mode OFF**: Log warning, attempt export anyway

### Network Errors
- Retry with exponential backoff: 5s, 10s, 20s
- After max retries, mark as failed in state file
- Next run will retry failed files

### Partial Bulk Failures
- Parse bulk response for per-document errors
- Retry only failed documents
- Update state file for successful documents

### File System Errors
- Log error, continue processing other files
- Don't update state for files that couldn't be read

## Security Considerations

### Credential Management

**Recommended Approach**: Elasticsearch API Key
```json
{
  "elasticsearch": {
    "apiKey": "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw=="
  }
}
```

**Alternative**: Environment Variables
```powershell
$env:F0_ELASTIC_API_KEY = "api-key-here"
```

Collector reads from:
1. Environment variable (highest priority)
2. Configuration file
3. Secure credential store (future enhancement)

### Configuration File Permissions
- `collector_config.json` should have restricted ACLs
- Only SYSTEM and Administrators should have read access
- Collector runs as SYSTEM when deployed as scheduled task

### Network Security
- TLS verification enabled by default
- Support for custom CA certificates
- Optional mTLS (client certificates)

## Command-Line Interface

```
f0_collector.exe [command] [options]

Commands:
  collect       Collect and export test results (default)
  validate      Validate configuration and connectivity
  status        Show collection status and statistics
  reset         Reset state file (re-collect all files)
  version       Show version information

Options:
  --config      Path to configuration file (default: c:\F0\collector_config.json)
  --dry-run     Scan and validate only, don't export
  --force       Force re-collection of already collected files
  --verbose     Enable verbose logging
  --once        Run once and exit (vs. continuous mode)
  --interval    Collection interval in seconds (default: 300)
```

### Usage Examples

```powershell
# One-time collection
f0_collector.exe collect --once

# Continuous collection every 5 minutes
f0_collector.exe collect --interval 300

# Dry run to test configuration
f0_collector.exe collect --dry-run --verbose

# Validate configuration and connectivity
f0_collector.exe validate

# Show collection statistics
f0_collector.exe status

# Force re-collection of all files
f0_collector.exe collect --force

# Reset state and start fresh
f0_collector.exe reset
```

## Deployment Options

### Option 1: Windows Scheduled Task

**Deployment Script**: `deploy-collector-task.ps1`

```powershell
# Create scheduled task to run every 5 minutes
$action = New-ScheduledTaskAction -Execute "C:\F0\f0_collector.exe" -Argument "collect --once"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "F0RT1KA Results Collector" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings
```

### Option 2: LimaCharlie D&R Integration

**D&R Rule**: Detect test completion and trigger collection

```yaml
detect:
  event: NEW_DOCUMENT
  op: and
  rules:
    - op: ends with
      path: event/FILE_PATH
      value: '\test_execution_log.json'
    - op: starts with
      path: event/FILE_PATH
      value: 'c:\F0\'
respond:
  - action: task
    command: >
      C:\F0\f0_collector.exe collect --once --verbose
    wait_for_completion: false
```

### Option 3: Manual Execution

Simple batch script for ad-hoc collection:

```batch
@echo off
C:\F0\f0_collector.exe collect --once --verbose
pause
```

## Logging

### Log Format

```
2024-11-14T15:30:45.123Z [INFO] f0_collector v1.0.0 starting
2024-11-14T15:30:45.124Z [INFO] Loading configuration from c:\F0\collector_config.json
2024-11-14T15:30:45.125Z [INFO] Elasticsearch endpoint: https://elastic.example.com:9200
2024-11-14T15:30:45.200Z [INFO] Scanning c:\F0 for test results
2024-11-14T15:30:45.250Z [INFO] Found 3 new result files
2024-11-14T15:30:45.251Z [DEBUG] Validating c:\F0\test_execution_log.json
2024-11-14T15:30:45.252Z [INFO] Validation passed: test-uuid-123
2024-11-14T15:30:45.300Z [INFO] Exporting 3 results to Elasticsearch
2024-11-14T15:30:45.450Z [INFO] Bulk export successful: 3 documents indexed
2024-11-14T15:30:45.451Z [INFO] Moving collected files to c:\F0\collected
2024-11-14T15:30:45.500Z [INFO] Collection complete: 3 collected, 0 failed
```

### Log Rotation

- Max size: 10 MB (configurable)
- Max backups: 3 (configurable)
- Compression: gzip for rotated logs

## Performance Considerations

### Scanning Efficiency
- Use OS native file walking (Go's filepath.Walk)
- Skip collected/ subdirectory
- Cache file hashes to detect duplicates

### Bulk Export Optimization
- Batch size: 100 documents (configurable)
- Parallel bulk requests for large batches
- Connection pooling for Elasticsearch client

### Memory Usage
- Stream large JSON files instead of loading entire file
- Process files in batches
- Clean up state file periodically (remove old entries)

## Monitoring and Metrics

Collector exposes metrics for monitoring:

```json
{
  "collectorMetrics": {
    "version": "1.0.0",
    "uptime": 3600,
    "lastRun": "2024-11-14T15:30:45.123Z",
    "totalCollected": 1234,
    "totalFailed": 5,
    "elasticsearchStatus": "connected",
    "averageExportTime": 450,
    "failureRate": 0.004
  }
}
```

### Health Check Endpoint

Optional: Simple HTTP health endpoint for monitoring

```
GET http://localhost:8080/health

Response:
{
  "status": "healthy",
  "elasticsearch": "connected",
  "lastSuccess": "2024-11-14T15:30:45.123Z"
}
```

## Testing Strategy

### Unit Tests
- Configuration loading and validation
- Schema validation logic
- State file management
- Elasticsearch client mocking

### Integration Tests
- Test against local Elasticsearch instance
- Test file scanning and collection
- Test retry logic with simulated failures
- Test bulk export with large batches

### End-to-End Tests
- Deploy collector on test Windows VM
- Run F0RT1KA tests
- Verify results appear in Elasticsearch
- Verify dashboards display correct data

## Version History

- **v1.0.0** (2024-11-14) - Initial specification
  - Elasticsearch export support
  - Schema v2.0 validation
  - Windows Scheduled Task deployment
  - LimaCharlie D&R integration

## Future Enhancements

### v1.1.0 (Planned)
- Additional export targets (S3, Azure Blob)
- Metrics endpoint for Prometheus
- Dashboard auto-provisioning
- Compression for exported data

### v2.0.0 (Future)
- Real-time streaming mode (watch file system)
- Plugin architecture for custom exporters
- Web UI for configuration and monitoring
- Multi-platform support (Linux, macOS)

## References

- Test Results Schema v2.0: `../test-results-schema-v2.0.json`
- Schema Guide: `../TEST_RESULTS_SCHEMA_GUIDE.md`
- Elasticsearch Bulk API: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
- Go Elasticsearch Client: https://github.com/elastic/go-elasticsearch
