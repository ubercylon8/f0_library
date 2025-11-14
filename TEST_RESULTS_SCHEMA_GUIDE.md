# F0RT1KA Test Results Schema Guide v2.0

## Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Schema Structure](#schema-structure)
- [Field Reference](#field-reference)
- [Usage Examples](#usage-examples)
- [Analytics & Queries](#analytics--queries)
- [Validation](#validation)
- [Migration from v1.x](#migration-from-v1x)
- [Best Practices](#best-practices)

---

## Overview

The F0RT1KA Test Results Schema v2.0 is a standardized JSON schema designed for:
- **Consistent test result reporting** across all F0RT1KA security tests
- **Time-series analytics** and trending over time
- **Dashboard visualization** with pre-computed metrics
- **Cross-organizational comparison** of security posture
- **Backward compatibility** through schema versioning

### Key Features
✅ **Schema Versioning** - Track schema evolution over time
✅ **Rich Metadata** - MITRE ATT&CK mapping, severity, categories
✅ **Execution Context** - Batch runs, organizations, environments
✅ **Computed Outcomes** - Pre-calculated metrics for dashboards
✅ **ISO 8601 Timestamps** - Universal time format for global deployments
✅ **Extensibility** - Test-specific fields without breaking compatibility

---

## Quick Start

### Minimal Valid Result

```json
{
  "schemaVersion": "2.0",
  "testId": "b6c73735-0c24-4a1e-8f0a-3c24af39671b",
  "testName": "MDE Network Protection Bypass Test",
  "testMetadata": {
    "version": "1.0.0",
    "category": "defense_evasion",
    "severity": "high",
    "techniques": ["T1562.001"],
    "tactics": ["defense-evasion"]
  },
  "executionContext": {
    "executionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "organization": "sb",
    "environment": "lab"
  },
  "startTime": "2024-11-14T15:30:45.123Z",
  "endTime": "2024-11-14T15:32:18.456Z",
  "durationMs": 93333,
  "exitCode": 101,
  "exitReason": "System is unprotected - attack succeeded",
  "outcome": {
    "protected": false,
    "category": "unprotected",
    "detectionPhase": null
  },
  "systemInfo": {
    "hostname": "WIN11-LAB-01",
    "osVersion": "Microsoft Windows [Version 10.0.22621.2715]",
    "architecture": "AMD64",
    "defenderRunning": true,
    "mdeInstalled": true,
    "processId": 4568,
    "username": "Administrator",
    "isAdmin": true
  },
  "phases": [],
  "messages": [],
  "filesDropped": [],
  "processesExecuted": []
}
```

### Complete Example with All Features

See [examples/complete-test-result.json](#complete-example) below.

---

## Schema Structure

The schema is organized into logical sections:

```
test-results-schema-v2.0.json
├── Core Identifiers (schemaVersion, testId, testName)
├── Test Metadata (version, category, severity, techniques, scoring)
├── Execution Context (executionId, organization, environment)
├── Timing Information (startTime, endTime, durationMs)
├── Exit Information (exitCode, exitReason)
├── Computed Outcomes (protected, category, detectionPhase)
├── Multi-Stage Support (isMultiStage, stages, blockedAtStage)
├── System Information (hostname, OS, EDR products)
├── Execution Details (phases, messages, files, processes)
├── Test-Specific Data (certBypass, networkTest, identifierExtraction)
├── Aggregation Metrics (pre-computed counts and statistics)
└── Artifacts (file paths to logs, screenshots, captures)
```

---

## Field Reference

### Core Fields

#### `schemaVersion` (required)
- **Type**: String
- **Pattern**: `^\d+\.\d+$`
- **Description**: Schema version for backward compatibility
- **Example**: `"2.0"`
- **Usage**: Check this field before parsing to ensure compatibility

#### `testId` (required)
- **Type**: String (UUID v4, lowercase)
- **Pattern**: `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
- **Description**: Unique test identifier
- **Example**: `"b6c73735-0c24-4a1e-8f0a-3c24af39671b"`
- **Usage**: Primary key for test identification

#### `testName` (required)
- **Type**: String (1-256 chars)
- **Description**: Human-readable test name
- **Example**: `"MDE Network Protection Bypass Test"`
- **Usage**: Display name in dashboards and reports

---

### Test Metadata Section

#### `testMetadata` (required)

##### `testMetadata.version` (required)
- **Type**: String (semantic versioning)
- **Pattern**: `^\d+\.\d+\.\d+$`
- **Description**: Test implementation version
- **Example**: `"1.0.0"`, `"2.1.3"`
- **Usage**: Track test evolution over time

##### `testMetadata.category` (required)
- **Type**: Enum
- **Values**:
  - `ransomware`
  - `data_exfiltration`
  - `privilege_escalation`
  - `defense_evasion`
  - `persistence`
  - `credential_access`
  - `lateral_movement`
  - `command_and_control`
  - `impact`
  - `initial_access`
  - `execution`
  - `discovery`
  - `collection`
- **Description**: Primary test category for filtering
- **Example**: `"defense_evasion"`
- **Usage**: Dashboard filtering and grouping

##### `testMetadata.severity` (required)
- **Type**: Enum
- **Values**: `critical`, `high`, `medium`, `low`, `informational`
- **Description**: Threat severity level
- **Example**: `"high"`
- **Usage**: Prioritization and risk assessment

##### `testMetadata.techniques` (required)
- **Type**: Array of strings
- **Pattern**: `^T\d{4}(\.\d{3})?$`
- **Min Items**: 1
- **Description**: MITRE ATT&CK technique IDs
- **Example**: `["T1055.001", "T1134.001"]`
- **Usage**: ATT&CK coverage analysis

##### `testMetadata.tactics` (required)
- **Type**: Array of enums
- **Values**: MITRE ATT&CK tactic names (kebab-case)
  - `reconnaissance`, `resource-development`, `initial-access`, `execution`
  - `persistence`, `privilege-escalation`, `defense-evasion`
  - `credential-access`, `discovery`, `lateral-movement`
  - `collection`, `command-and-control`, `exfiltration`, `impact`
- **Min Items**: 1
- **Description**: MITRE ATT&CK tactic names
- **Example**: `["defense-evasion", "privilege-escalation"]`
- **Usage**: Tactic coverage heatmaps

##### `testMetadata.score` (optional)
- **Type**: Number (0-10)
- **Description**: Overall test quality score
- **Example**: `8.5`
- **Usage**: Test quality tracking

##### `testMetadata.scoreBreakdown` (optional)
- **Type**: Object with scoring components
- **Properties**:
  - `realWorldAccuracy` (0-3)
  - `technicalSophistication` (0-3)
  - `safetyMechanisms` (0-2)
  - `detectionOpportunities` (0-1)
  - `loggingObservability` (0-1)
- **Example**:
  ```json
  {
    "realWorldAccuracy": 2.5,
    "technicalSophistication": 3.0,
    "safetyMechanisms": 2.0,
    "detectionOpportunities": 0.5,
    "loggingObservability": 1.0
  }
  ```
- **Usage**: Detailed test quality analysis

##### `testMetadata.tags` (optional)
- **Type**: Array of strings
- **Description**: Additional classification tags
- **Example**: `["multi-stage", "memory-manipulation", "api-abuse"]`
- **Usage**: Custom filtering and categorization

---

### Execution Context Section

#### `executionContext` (required)

##### `executionContext.executionId` (required)
- **Type**: String (UUID)
- **Description**: Unique ID for this execution run - groups tests run together
- **Example**: `"a1b2c3d4-e5f6-7890-abcd-ef1234567890"`
- **Usage**:
  - Correlate multiple tests run in same batch
  - Track test suite executions
  - Time-series analysis of batch runs

##### `executionContext.batchId` (optional)
- **Type**: String
- **Description**: Named batch identifier
- **Example**: `"weekly-scan-2024-11-14"`, `"pre-deployment-validation"`
- **Usage**: Named test campaigns and scheduled runs

##### `executionContext.organization` (required)
- **Type**: String
- **Description**: Organization identifier
- **Example**: `"sb"`, `"tpsgl"`, `"rga"`
- **Usage**: Multi-tenant filtering and comparison

##### `executionContext.environment` (required)
- **Type**: Enum
- **Values**: `production`, `staging`, `lab`, `development`, `testing`
- **Description**: Deployment environment type
- **Example**: `"lab"`
- **Usage**: Environment-specific analytics

##### `executionContext.deploymentType` (optional)
- **Type**: Enum
- **Values**: `manual`, `automated`, `cicd`, `scheduled`, `on-demand`
- **Description**: How test was deployed
- **Example**: `"automated"`
- **Usage**: Track automation adoption

##### `executionContext.triggeredBy` (optional)
- **Type**: String
- **Description**: Who/what initiated the test
- **Example**: `"jim@example.com"`, `"jenkins-pipeline"`, `"scheduled-task"`
- **Usage**: Audit trail and attribution

##### `executionContext.configuration` (optional)
- **Type**: Object
- **Properties**:
  - `timeoutMs` (integer): Configured timeout
  - `certificateMode` (enum): `self-healing`, `pre-installed`, `embedded`
  - `multiStageEnabled` (boolean): Multi-stage architecture flag
- **Example**:
  ```json
  {
    "timeoutMs": 300000,
    "certificateMode": "self-healing",
    "multiStageEnabled": true
  }
  ```
- **Usage**: Test configuration tracking and troubleshooting

---

### Timing Fields

#### `startTime` (required)
- **Type**: String (ISO 8601 date-time, UTC)
- **Format**: `YYYY-MM-DDTHH:mm:ss.sssZ`
- **Description**: Test start timestamp
- **Example**: `"2024-11-14T15:30:45.123Z"`
- **Usage**: Time-series indexing, duration calculation

#### `endTime` (required)
- **Type**: String (ISO 8601 date-time, UTC)
- **Format**: `YYYY-MM-DDTHH:mm:ss.sssZ`
- **Description**: Test end timestamp
- **Example**: `"2024-11-14T15:32:18.456Z"`
- **Usage**: Time-series indexing, duration calculation

#### `durationMs` (required)
- **Type**: Integer (≥0)
- **Description**: Total execution duration in milliseconds
- **Example**: `93333` (93.333 seconds)
- **Usage**: Performance analytics, timeout analysis

---

### Exit Information

#### `exitCode` (required)
- **Type**: Integer (enum)
- **Values**:
  - `101` - Unprotected (attack succeeded)
  - `105` - File quarantined on extraction
  - `126` - Execution prevented
  - `127` - File quarantined on execution
  - `102` - Timeout exceeded
  - `999` - Unexpected test error
  - `1` - General error
- **Description**: Test exit code
- **Example**: `126`
- **Usage**: Primary outcome indicator

#### `exitReason` (required)
- **Type**: String (1-512 chars)
- **Description**: Human-readable exit reason
- **Example**: `"Attack execution prevented by security controls"`
- **Usage**: Display in reports and logs

---

### Computed Outcomes

#### `outcome` (required)

##### `outcome.protected` (required)
- **Type**: Boolean
- **Description**: Whether endpoint was protected
- **Computation**: `exitCode in [105, 126, 127]`
- **Example**: `true`
- **Usage**: Primary metric for dashboards - protection rate

##### `outcome.category` (required)
- **Type**: Enum
- **Values**:
  - `quarantined_on_extraction` (exitCode 105)
  - `execution_prevented` (exitCode 126)
  - `quarantined_on_execution` (exitCode 127)
  - `unprotected` (exitCode 101)
  - `timeout` (exitCode 102)
  - `test_error` (exitCode 999, 1)
  - `unknown` (other codes)
- **Description**: Categorized outcome
- **Example**: `"execution_prevented"`
- **Usage**: Outcome distribution charts

##### `outcome.detectionPhase` (required)
- **Type**: String or null
- **Values**: `file_drop`, `pre_execution`, `during_execution`, `post_execution`, `null`
- **Description**: Phase where detection occurred (null if unprotected)
- **Example**: `"pre_execution"`
- **Usage**: Detection timing analysis

##### `outcome.blockedTechniques` (optional)
- **Type**: Array of strings (ATT&CK technique IDs)
- **Description**: Which techniques were blocked (multi-stage only)
- **Example**: `["T1055.001", "T1134.001"]`
- **Usage**: Technique-level protection analysis

##### `outcome.successfulTechniques` (optional)
- **Type**: Array of strings (ATT&CK technique IDs)
- **Description**: Which techniques succeeded (multi-stage only)
- **Example**: `["T1003.001"]`
- **Usage**: Technique-level vulnerability analysis

---

### Multi-Stage Support

#### `isMultiStage` (optional)
- **Type**: Boolean
- **Default**: `false`
- **Description**: Whether this is a multi-stage test
- **Example**: `true`
- **Usage**: Filter multi-stage vs standard tests

#### `stages` (optional)
- **Type**: Array of stage objects
- **Description**: Stage execution details (multi-stage tests only)
- **Structure**:
  ```json
  {
    "stageId": 1,
    "technique": "T1134.001",
    "name": "Access Token Manipulation",
    "startTime": "2024-11-14T15:30:46.000Z",
    "endTime": "2024-11-14T15:30:52.000Z",
    "durationMs": 6000,
    "status": "success",
    "exitCode": 0,
    "blockedBy": null,
    "errorMessage": null
  }
  ```
- **Usage**: Multi-stage killchain analysis

#### `blockedAtStage` (optional)
- **Type**: Integer (≥1)
- **Description**: Stage number where execution was blocked
- **Example**: `2`
- **Usage**: Identify where in killchain detection occurred

#### `blockedTechnique` (optional)
- **Type**: String (ATT&CK technique ID)
- **Description**: Technique that was blocked
- **Example**: `"T1055.001"`
- **Usage**: Technique-specific detection analysis

---

### System Information

#### `systemInfo` (required)

All fields describe the target system where test executed:

- `hostname` (string, required): System hostname
- `osVersion` (string, required): OS version string
- `architecture` (enum, required): `AMD64`, `x86`, `ARM64`
- `defenderRunning` (boolean, required): Windows Defender status
- `mdeInstalled` (boolean, required): MDE installation status
- `mdeVersion` (string, optional): MDE version if installed
- `processId` (integer, required): Test process ID
- `username` (string, required): User running test
- `isAdmin` (boolean, required): Admin privilege flag
- `edrProducts` (array, optional): Detected EDR/AV products

**Example**:
```json
{
  "hostname": "WIN11-LAB-01",
  "osVersion": "Microsoft Windows [Version 10.0.22621.2715]",
  "architecture": "AMD64",
  "defenderRunning": true,
  "mdeInstalled": true,
  "mdeVersion": "10.8375.22621.2070",
  "processId": 4568,
  "username": "Administrator",
  "isAdmin": true,
  "edrProducts": [
    {
      "name": "Microsoft Defender for Endpoint",
      "version": "10.8375.22621.2070",
      "running": true
    }
  ]
}
```

**Usage**: Environment correlation, EDR version analysis

---

### Execution Details

#### `phases` (required)
- **Type**: Array of phase objects
- **Description**: Sequential execution phases
- **Structure**:
  ```json
  {
    "phaseNumber": 1,
    "phaseName": "Initialization",
    "startTime": "2024-11-14T15:30:45.123Z",
    "endTime": "2024-11-14T15:30:46.000Z",
    "durationMs": 877,
    "status": "success",
    "details": "Dropper initialized successfully",
    "errors": []
  }
  ```
- **Usage**: Phase-level performance analysis, failure point identification

#### `messages` (required)
- **Type**: Array of log entry objects
- **Description**: Detailed log messages
- **Structure**:
  ```json
  {
    "timestamp": "2024-11-14T15:30:45.200Z",
    "level": "INFO",
    "phase": "Initialization",
    "message": "Test logger initialized for MDE Network Protection Bypass Test"
  }
  ```
- **Levels**: `INFO`, `WARN`, `ERROR`, `CRITICAL`, `SUCCESS`, `DEBUG`
- **Usage**: Detailed troubleshooting, forensic analysis

#### `filesDropped` (required)
- **Type**: Array of file drop objects
- **Description**: Files created during test
- **Structure**:
  ```json
  {
    "filename": "malicious.exe",
    "path": "C:\\F0\\malicious.exe",
    "size": 2048576,
    "quarantined": false,
    "timestamp": "2024-11-14T15:30:47.000Z",
    "sha256": "a1b2c3...",
    "fileType": "exe"
  }
  ```
- **Usage**: File-level detection analysis, quarantine tracking

#### `processesExecuted` (required)
- **Type**: Array of process objects
- **Description**: Processes launched during test
- **Structure**:
  ```json
  {
    "processName": "powershell.exe",
    "commandLine": "powershell.exe -ExecutionPolicy Bypass -File attack.ps1",
    "pid": 8472,
    "success": true,
    "exitCode": 0,
    "timestamp": "2024-11-14T15:30:48.000Z",
    "errorMsg": null,
    "parentPid": 4568
  }
  ```
- **Usage**: Process-level detection analysis, command line analysis

---

### Test-Specific Sections

#### `certBypass` (optional)
Certificate bypass attempt details - only present in tests that attempt certificate manipulation.

#### `networkTest` (optional)
Network testing details - only present in network-focused tests.

#### `identifierExtraction` (optional)
MDE identifier extraction details - only present in tests that extract MDE identifiers.

See schema file for complete field definitions.

---

### Aggregation Metrics

#### `metrics` (optional)

Pre-computed counts for dashboard performance:

```json
{
  "totalPhases": 5,
  "successfulPhases": 4,
  "failedPhases": 1,
  "totalFilesDropped": 3,
  "filesQuarantined": 1,
  "totalProcesses": 2,
  "successfulProcesses": 2,
  "totalLogMessages": 45,
  "errorCount": 2,
  "criticalCount": 0
}
```

**Usage**: Fast dashboard rendering without iterating arrays

---

### Artifacts

#### `artifacts` (optional)

Paths to test-related files:

```json
{
  "logFilePath": "C:\\F0\\test_execution_log.txt",
  "jsonFilePath": "C:\\F0\\test_execution_log.json",
  "screenshotPaths": ["C:\\F0\\screenshot_001.png"],
  "packetCapturePath": "C:\\F0\\network_capture.pcap"
}
```

**Usage**: Link to supporting evidence and forensic data

---

## Usage Examples

### Example 1: Standard Single-Stage Test

```json
{
  "schemaVersion": "2.0",
  "testId": "7e93865c-0033-4db3-af3c-a9f4215c1c49",
  "testName": "Windows Defender Certificate Bypass",
  "testMetadata": {
    "version": "1.0.0",
    "category": "defense_evasion",
    "severity": "critical",
    "techniques": ["T1553.004"],
    "tactics": ["defense-evasion"],
    "score": 8.5,
    "scoreBreakdown": {
      "realWorldAccuracy": 2.5,
      "technicalSophistication": 3.0,
      "safetyMechanisms": 2.0,
      "detectionOpportunities": 0.5,
      "loggingObservability": 1.0
    },
    "tags": ["memory-patching", "watchdog"]
  },
  "executionContext": {
    "executionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "batchId": "weekly-scan-2024-11-14",
    "organization": "sb",
    "environment": "lab",
    "deploymentType": "automated",
    "triggeredBy": "jenkins-pipeline",
    "configuration": {
      "timeoutMs": 120000,
      "certificateMode": "self-healing",
      "multiStageEnabled": false
    }
  },
  "startTime": "2024-11-14T15:30:45.123Z",
  "endTime": "2024-11-14T15:31:52.456Z",
  "durationMs": 67333,
  "exitCode": 126,
  "exitReason": "Certificate bypass blocked by EDR",
  "outcome": {
    "protected": true,
    "category": "execution_prevented",
    "detectionPhase": "during_execution",
    "blockedTechniques": [],
    "successfulTechniques": []
  },
  "isMultiStage": false,
  "systemInfo": {
    "hostname": "WIN11-LAB-01",
    "osVersion": "Microsoft Windows [Version 10.0.22621.2715]",
    "architecture": "AMD64",
    "defenderRunning": true,
    "mdeInstalled": true,
    "mdeVersion": "10.8375.22621.2070",
    "processId": 4568,
    "username": "Administrator",
    "isAdmin": true
  },
  "phases": [
    {
      "phaseNumber": 0,
      "phaseName": "Initialization",
      "startTime": "2024-11-14T15:30:45.123Z",
      "endTime": "2024-11-14T15:30:46.000Z",
      "durationMs": 877,
      "status": "success",
      "details": "Test initialized successfully"
    },
    {
      "phaseNumber": 1,
      "phaseName": "Certificate Bypass Attempt",
      "startTime": "2024-11-14T15:30:46.000Z",
      "endTime": "2024-11-14T15:31:52.456Z",
      "durationMs": 66456,
      "status": "blocked",
      "details": "Memory patching detected and blocked",
      "errors": ["EDR blocked memory write operation"]
    }
  ],
  "messages": [
    {
      "timestamp": "2024-11-14T15:30:45.200Z",
      "level": "INFO",
      "phase": "Initialization",
      "message": "Test logger initialized"
    },
    {
      "timestamp": "2024-11-14T15:31:52.000Z",
      "level": "ERROR",
      "phase": "Certificate Bypass Attempt",
      "message": "Memory write operation blocked by EDR"
    }
  ],
  "filesDropped": [],
  "processesExecuted": [],
  "certBypass": {
    "mode": "memory_patch",
    "attempted": true,
    "success": false,
    "blocked": true,
    "blockedBy": "MDE Behavioral Blocking",
    "watchdogActive": true,
    "restoreSuccess": true,
    "durationMs": 66456,
    "patchAddress": "0x7FFE0304",
    "timestamp": "2024-11-14T15:30:46.000Z"
  },
  "metrics": {
    "totalPhases": 2,
    "successfulPhases": 1,
    "failedPhases": 1,
    "totalFilesDropped": 0,
    "filesQuarantined": 0,
    "totalProcesses": 0,
    "successfulProcesses": 0,
    "totalLogMessages": 2,
    "errorCount": 1,
    "criticalCount": 0
  }
}
```

### Example 2: Multi-Stage Test

```json
{
  "schemaVersion": "2.0",
  "testId": "931f91ef-c7c0-4c3c-b61b-03992edb5e5f",
  "testName": "Multi-Stage Privilege Escalation Chain",
  "testMetadata": {
    "version": "1.0.0",
    "category": "privilege_escalation",
    "severity": "critical",
    "techniques": ["T1134.001", "T1055.001", "T1003.001"],
    "tactics": ["privilege-escalation", "credential-access"],
    "score": 9.0,
    "tags": ["multi-stage", "killchain"]
  },
  "executionContext": {
    "executionId": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "organization": "tpsgl",
    "environment": "lab",
    "configuration": {
      "multiStageEnabled": true
    }
  },
  "startTime": "2024-11-14T16:00:00.000Z",
  "endTime": "2024-11-14T16:02:15.000Z",
  "durationMs": 135000,
  "exitCode": 126,
  "exitReason": "Stage 2 blocked - Process injection prevented",
  "outcome": {
    "protected": true,
    "category": "execution_prevented",
    "detectionPhase": "during_execution",
    "blockedTechniques": ["T1055.001"],
    "successfulTechniques": ["T1134.001"]
  },
  "isMultiStage": true,
  "stages": [
    {
      "stageId": 1,
      "technique": "T1134.001",
      "name": "Access Token Manipulation",
      "startTime": "2024-11-14T16:00:05.000Z",
      "endTime": "2024-11-14T16:00:45.000Z",
      "durationMs": 40000,
      "status": "success",
      "exitCode": 0
    },
    {
      "stageId": 2,
      "technique": "T1055.001",
      "name": "Process Injection - DLL Injection",
      "startTime": "2024-11-14T16:00:45.000Z",
      "endTime": "2024-11-14T16:02:15.000Z",
      "durationMs": 90000,
      "status": "blocked",
      "exitCode": 126,
      "blockedBy": "MDE Process Injection Detection"
    }
  ],
  "blockedAtStage": 2,
  "blockedTechnique": "T1055.001",
  "systemInfo": {
    "hostname": "WIN11-TPSGL-01",
    "osVersion": "Microsoft Windows [Version 10.0.22621.2715]",
    "architecture": "AMD64",
    "defenderRunning": true,
    "mdeInstalled": true,
    "processId": 5672,
    "username": "Administrator",
    "isAdmin": true
  },
  "phases": [],
  "messages": [],
  "filesDropped": [],
  "processesExecuted": [],
  "metrics": {
    "totalPhases": 0,
    "successfulPhases": 0,
    "failedPhases": 0,
    "totalFilesDropped": 2,
    "filesQuarantined": 1,
    "totalProcesses": 2,
    "successfulProcesses": 1,
    "totalLogMessages": 15,
    "errorCount": 1,
    "criticalCount": 0
  }
}
```

---

## Analytics & Queries

### SQL Query Examples

#### Protection Rate by Organization

```sql
SELECT
  executionContext->>'organization' as org,
  COUNT(*) as total_tests,
  SUM(CASE WHEN outcome->>'protected' = 'true' THEN 1 ELSE 0 END) as protected_count,
  ROUND(100.0 * SUM(CASE WHEN outcome->>'protected' = 'true' THEN 1 ELSE 0 END) / COUNT(*), 2) as protection_rate
FROM test_results
WHERE startTime >= '2024-11-01'
GROUP BY executionContext->>'organization'
ORDER BY protection_rate DESC;
```

#### Technique Detection Coverage

```sql
WITH technique_tests AS (
  SELECT
    jsonb_array_elements_text(testMetadata->'techniques') as technique,
    outcome->>'protected' = 'true' as protected
  FROM test_results
  WHERE startTime >= '2024-11-01'
)
SELECT
  technique,
  COUNT(*) as total_tests,
  SUM(CASE WHEN protected THEN 1 ELSE 0 END) as detected_count,
  ROUND(100.0 * SUM(CASE WHEN protected THEN 1 ELSE 0 END) / COUNT(*), 2) as detection_rate
FROM technique_tests
GROUP BY technique
ORDER BY detection_rate ASC;
```

#### Average Test Duration by Category

```sql
SELECT
  testMetadata->>'category' as category,
  COUNT(*) as test_count,
  ROUND(AVG(durationMs / 1000.0), 2) as avg_duration_seconds,
  MIN(durationMs / 1000.0) as min_duration_seconds,
  MAX(durationMs / 1000.0) as max_duration_seconds
FROM test_results
WHERE startTime >= '2024-11-01'
GROUP BY testMetadata->>'category'
ORDER BY avg_duration_seconds DESC;
```

#### Time-Series Protection Trend

```sql
SELECT
  DATE_TRUNC('day', startTime::timestamp) as test_date,
  COUNT(*) as total_tests,
  SUM(CASE WHEN outcome->>'protected' = 'true' THEN 1 ELSE 0 END) as protected,
  ROUND(100.0 * SUM(CASE WHEN outcome->>'protected' = 'true' THEN 1 ELSE 0 END) / COUNT(*), 2) as protection_rate
FROM test_results
WHERE startTime >= '2024-11-01'
GROUP BY DATE_TRUNC('day', startTime::timestamp)
ORDER BY test_date;
```

#### Multi-Stage Killchain Analysis

```sql
WITH stage_data AS (
  SELECT
    testId,
    testName,
    jsonb_array_elements(stages) as stage
  FROM test_results
  WHERE isMultiStage = true
)
SELECT
  stage->>'technique' as technique,
  COUNT(*) as total_executions,
  SUM(CASE WHEN stage->>'status' = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
  ROUND(100.0 * SUM(CASE WHEN stage->>'status' = 'blocked' THEN 1 ELSE 0 END) / COUNT(*), 2) as block_rate
FROM stage_data
GROUP BY stage->>'technique'
ORDER BY block_rate DESC;
```

### Python Analytics Examples

#### Load and Analyze Results

```python
import json
import pandas as pd
from datetime import datetime

# Load test results
def load_results(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

# Convert to DataFrame for analysis
def results_to_dataframe(results_list):
    df = pd.DataFrame([
        {
            'test_id': r['testId'],
            'test_name': r['testName'],
            'organization': r['executionContext']['organization'],
            'environment': r['executionContext']['environment'],
            'category': r['testMetadata']['category'],
            'severity': r['testMetadata']['severity'],
            'protected': r['outcome']['protected'],
            'exit_code': r['exitCode'],
            'outcome_category': r['outcome']['category'],
            'duration_ms': r['durationMs'],
            'start_time': pd.to_datetime(r['startTime']),
            'techniques': ','.join(r['testMetadata']['techniques']),
            'score': r['testMetadata'].get('score')
        }
        for r in results_list
    ])
    return df

# Calculate protection rate
def protection_rate(df):
    return (df['protected'].sum() / len(df)) * 100

# Group by organization
def org_comparison(df):
    return df.groupby('organization').agg({
        'test_id': 'count',
        'protected': lambda x: (x.sum() / len(x)) * 100,
        'duration_ms': 'mean'
    }).rename(columns={
        'test_id': 'total_tests',
        'protected': 'protection_rate',
        'duration_ms': 'avg_duration_ms'
    })

# Example usage
results = [load_results('test1.json'), load_results('test2.json')]
df = results_to_dataframe(results)
print(f"Overall Protection Rate: {protection_rate(df):.2f}%")
print("\nBy Organization:")
print(org_comparison(df))
```

#### Dashboard Metrics Generation

```python
def generate_dashboard_metrics(results_list):
    """Generate summary metrics for dashboard"""
    df = results_to_dataframe(results_list)

    metrics = {
        'total_tests': len(df),
        'protection_rate': protection_rate(df),
        'avg_duration_seconds': df['duration_ms'].mean() / 1000,
        'by_severity': df.groupby('severity')['protected'].apply(
            lambda x: (x.sum() / len(x)) * 100
        ).to_dict(),
        'by_category': df.groupby('category')['protected'].apply(
            lambda x: (x.sum() / len(x)) * 100
        ).to_dict(),
        'by_environment': df.groupby('environment')['protected'].apply(
            lambda x: (x.sum() / len(x)) * 100
        ).to_dict(),
        'outcome_distribution': df['outcome_category'].value_counts().to_dict(),
        'avg_score': df['score'].mean() if 'score' in df else None
    }

    return metrics
```

---

## Validation

### JSON Schema Validation

#### Python Validation

```python
import json
import jsonschema
from jsonschema import validate

# Load schema
with open('test-results-schema-v2.0.json', 'r') as f:
    schema = json.load(f)

# Load test result
with open('test_execution_log.json', 'r') as f:
    result = json.load(f)

# Validate
try:
    validate(instance=result, schema=schema)
    print("✓ Valid - Result conforms to schema v2.0")
except jsonschema.exceptions.ValidationError as e:
    print(f"✗ Invalid - {e.message}")
    print(f"  Path: {' -> '.join(str(p) for p in e.path)}")
```

#### JavaScript Validation

```javascript
const Ajv = require('ajv');
const fs = require('fs');

const ajv = new Ajv();

// Load schema
const schema = JSON.parse(fs.readFileSync('test-results-schema-v2.0.json'));

// Load test result
const result = JSON.parse(fs.readFileSync('test_execution_log.json'));

// Validate
const validate = ajv.compile(schema);
const valid = validate(result);

if (valid) {
    console.log('✓ Valid - Result conforms to schema v2.0');
} else {
    console.log('✗ Invalid - Errors:');
    console.log(validate.errors);
}
```

### Command-Line Validation

Using `ajv-cli`:

```bash
# Install ajv-cli
npm install -g ajv-cli

# Validate single file
ajv validate -s test-results-schema-v2.0.json -d test_execution_log.json

# Validate multiple files
ajv validate -s test-results-schema-v2.0.json -d "results/**/*.json"
```

---

## Migration from v1.x

### Key Changes in v2.0

1. **Added Required Fields**:
   - `schemaVersion` - Track schema version
   - `testMetadata` - Rich classification metadata
   - `executionContext` - Execution environment details
   - `outcome` - Computed outcome metrics

2. **Changed Field Names**:
   - `durationMs` renamed from `duration`
   - Timestamps now ISO 8601 format (previously varied)

3. **New Optional Fields**:
   - `testMetadata.score` and `scoreBreakdown`
   - `executionContext.batchId` and `triggeredBy`
   - `outcome.blockedTechniques` and `successfulTechniques`
   - `metrics` object for pre-computed aggregations
   - `artifacts` object for file paths

4. **Enhanced Enumerations**:
   - `testMetadata.category` - Expanded categories
   - `testMetadata.tactics` - MITRE ATT&CK tactics
   - `outcome.category` - Standardized outcome categories

### Migration Script (Python)

```python
import json
from datetime import datetime

def migrate_v1_to_v2(v1_result, execution_context):
    """
    Migrate v1.x result to v2.0 schema

    Args:
        v1_result: Old format test result
        execution_context: New execution context to add
    """

    # Compute outcome
    protected = v1_result['exitCode'] in [105, 126, 127]
    outcome_map = {
        105: 'quarantined_on_extraction',
        126: 'execution_prevented',
        127: 'quarantined_on_execution',
        101: 'unprotected',
        102: 'timeout',
        999: 'test_error',
        1: 'test_error'
    }

    v2_result = {
        'schemaVersion': '2.0',
        'testId': v1_result['testId'],
        'testName': v1_result['testName'],

        # Add required metadata (must be provided)
        'testMetadata': {
            'version': '1.0.0',  # Default version
            'category': execution_context.get('category', 'execution'),
            'severity': execution_context.get('severity', 'medium'),
            'techniques': execution_context.get('techniques', []),
            'tactics': execution_context.get('tactics', [])
        },

        # Add execution context
        'executionContext': execution_context,

        # Convert timestamps to ISO 8601
        'startTime': v1_result['startTime'] if 'Z' in v1_result['startTime']
                     else datetime.fromisoformat(v1_result['startTime']).isoformat() + 'Z',
        'endTime': v1_result['endTime'] if 'Z' in v1_result['endTime']
                   else datetime.fromisoformat(v1_result['endTime']).isoformat() + 'Z',

        'durationMs': v1_result.get('durationMs', v1_result.get('duration', 0)),
        'exitCode': v1_result['exitCode'],
        'exitReason': v1_result['exitReason'],

        # Compute outcome
        'outcome': {
            'protected': protected,
            'category': outcome_map.get(v1_result['exitCode'], 'unknown'),
            'detectionPhase': None  # Cannot infer from v1
        },

        # Copy existing fields
        'isMultiStage': v1_result.get('isMultiStage', False),
        'stages': v1_result.get('stages', []),
        'blockedAtStage': v1_result.get('blockedAtStage'),
        'blockedTechnique': v1_result.get('blockedTechnique'),
        'systemInfo': v1_result['systemInfo'],
        'phases': v1_result['phases'],
        'messages': v1_result['messages'],
        'filesDropped': v1_result['filesDropped'],
        'processesExecuted': v1_result['processesExecuted'],

        # Optional sections
        'certBypass': v1_result.get('certBypass'),
        'networkTest': v1_result.get('networkTest'),
        'identifierExtraction': v1_result.get('identifierExtraction'),

        # Compute metrics
        'metrics': {
            'totalPhases': len(v1_result.get('phases', [])),
            'successfulPhases': sum(1 for p in v1_result.get('phases', []) if p.get('status') == 'success'),
            'failedPhases': sum(1 for p in v1_result.get('phases', []) if p.get('status') == 'failed'),
            'totalFilesDropped': len(v1_result.get('filesDropped', [])),
            'filesQuarantined': sum(1 for f in v1_result.get('filesDropped', []) if f.get('quarantined')),
            'totalProcesses': len(v1_result.get('processesExecuted', [])),
            'successfulProcesses': sum(1 for p in v1_result.get('processesExecuted', []) if p.get('success')),
            'totalLogMessages': len(v1_result.get('messages', [])),
            'errorCount': sum(1 for m in v1_result.get('messages', []) if m.get('level') == 'ERROR'),
            'criticalCount': sum(1 for m in v1_result.get('messages', []) if m.get('level') == 'CRITICAL')
        }
    }

    return v2_result

# Example usage
with open('old_result_v1.json', 'r') as f:
    v1_result = json.load(f)

execution_context = {
    'executionId': 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    'organization': 'sb',
    'environment': 'lab',
    'category': 'defense_evasion',
    'severity': 'high',
    'techniques': ['T1562.001'],
    'tactics': ['defense-evasion']
}

v2_result = migrate_v1_to_v2(v1_result, execution_context)

with open('new_result_v2.json', 'w') as f:
    json.dump(v2_result, f, indent=2)
```

---

## Best Practices

### 1. Always Include Schema Version

```json
{
  "schemaVersion": "2.0",
  ...
}
```

This enables version detection and compatibility checks.

### 2. Use ISO 8601 UTC Timestamps

```json
{
  "startTime": "2024-11-14T15:30:45.123Z",
  "endTime": "2024-11-14T15:32:18.456Z"
}
```

Benefits:
- Sortable as strings
- Time zone agnostic
- Universal standard

### 3. Generate Unique Execution IDs

```python
import uuid

execution_id = str(uuid.uuid4())  # For each test run
batch_id = f"weekly-scan-{datetime.now().strftime('%Y-%m-%d')}"
```

This enables correlation across multiple tests in same batch.

### 4. Pre-Compute Metrics

Always populate the `metrics` object to avoid repeated array iterations:

```python
metrics = {
    'totalPhases': len(phases),
    'successfulPhases': sum(1 for p in phases if p['status'] == 'success'),
    'totalFilesDropped': len(files_dropped),
    'filesQuarantined': sum(1 for f in files_dropped if f['quarantined'])
    # ... etc
}
```

### 5. Validate Before Storage

```python
# Always validate before saving
validate(instance=result, schema=schema)
with open('result.json', 'w') as f:
    json.dump(result, f, indent=2)
```

### 6. Use Consistent Organization IDs

Standardize organization identifiers:
- `sb`, `tpsgl`, `rga` (lowercase, short codes)
- Avoid mixed case or special characters

### 7. Tag Tests Appropriately

Use `testMetadata.tags` for custom dimensions:

```json
{
  "tags": [
    "multi-stage",
    "memory-manipulation",
    "requires-admin",
    "network-dependent"
  ]
}
```

### 8. Document Test-Specific Fields

If adding custom fields (e.g., `ransomwareTest`), document them:

```json
{
  "ransomwareTest": {
    "encryptionAlgorithm": "AES-256",
    "filesEncrypted": 1500,
    "ransomNote": "C:\\F0\\RANSOM_NOTE.txt"
  }
}
```

### 9. Store Results in Time-Partitioned Storage

Organize by date for efficient querying:

```
results/
├── 2024-11/
│   ├── 2024-11-14/
│   │   ├── test1-result.json
│   │   ├── test2-result.json
│   ├── 2024-11-15/
│   │   ├── test3-result.json
```

### 10. Index Key Fields

For database storage, index:
- `schemaVersion`
- `testId`
- `executionContext.executionId`
- `executionContext.organization`
- `startTime`, `endTime`
- `outcome.protected`
- `testMetadata.category`
- `testMetadata.techniques`

---

## Complete Example

```json
{
  "schemaVersion": "2.0",
  "testId": "b6c73735-0c24-4a1e-8f0a-3c24af39671b",
  "testName": "MDE Network Protection Bypass Test",
  "testMetadata": {
    "version": "1.2.0",
    "category": "defense_evasion",
    "severity": "high",
    "techniques": ["T1562.001", "T1071.001"],
    "tactics": ["defense-evasion", "command-and-control"],
    "score": 8.5,
    "scoreBreakdown": {
      "realWorldAccuracy": 2.5,
      "technicalSophistication": 3.0,
      "safetyMechanisms": 2.0,
      "detectionOpportunities": 0.5,
      "loggingObservability": 1.0
    },
    "tags": ["network-test", "multi-endpoint", "api-based"]
  },
  "executionContext": {
    "executionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "batchId": "weekly-scan-2024-11-14",
    "organization": "sb",
    "environment": "lab",
    "deploymentType": "automated",
    "triggeredBy": "jenkins-pipeline",
    "configuration": {
      "timeoutMs": 300000,
      "certificateMode": "self-healing",
      "multiStageEnabled": false
    }
  },
  "startTime": "2024-11-14T15:30:45.123Z",
  "endTime": "2024-11-14T15:32:18.456Z",
  "durationMs": 93333,
  "exitCode": 101,
  "exitReason": "System is unprotected - attack succeeded",
  "outcome": {
    "protected": false,
    "category": "unprotected",
    "detectionPhase": null,
    "blockedTechniques": [],
    "successfulTechniques": ["T1562.001", "T1071.001"]
  },
  "isMultiStage": false,
  "systemInfo": {
    "hostname": "WIN11-LAB-01",
    "osVersion": "Microsoft Windows [Version 10.0.22621.2715]",
    "architecture": "AMD64",
    "defenderRunning": true,
    "mdeInstalled": true,
    "mdeVersion": "10.8375.22621.2070",
    "processId": 4568,
    "username": "Administrator",
    "isAdmin": true,
    "edrProducts": [
      {
        "name": "Microsoft Defender for Endpoint",
        "version": "10.8375.22621.2070",
        "running": true
      }
    ]
  },
  "phases": [
    {
      "phaseNumber": 0,
      "phaseName": "Initialization",
      "startTime": "2024-11-14T15:30:45.123Z",
      "endTime": "2024-11-14T15:30:46.000Z",
      "durationMs": 877,
      "status": "success",
      "details": "Dropper initialized successfully",
      "errors": []
    },
    {
      "phaseNumber": 1,
      "phaseName": "Network Endpoint Testing",
      "startTime": "2024-11-14T15:30:46.000Z",
      "endTime": "2024-11-14T15:32:18.456Z",
      "durationMs": 92456,
      "status": "success",
      "details": "All 10 endpoints successfully tested",
      "errors": []
    }
  ],
  "messages": [
    {
      "timestamp": "2024-11-14T15:30:45.200Z",
      "level": "INFO",
      "phase": "Initialization",
      "message": "Test logger initialized for MDE Network Protection Bypass Test"
    },
    {
      "timestamp": "2024-11-14T15:30:45.250Z",
      "level": "INFO",
      "phase": "Initialization",
      "message": "Running as: Administrator (Admin: true)"
    },
    {
      "timestamp": "2024-11-14T15:32:18.000Z",
      "level": "SUCCESS",
      "phase": "Network Endpoint Testing",
      "message": "Network protection bypass successful - all endpoints accessible"
    }
  ],
  "filesDropped": [
    {
      "filename": "network_tester.exe",
      "path": "C:\\F0\\network_tester.exe",
      "size": 2048576,
      "quarantined": false,
      "timestamp": "2024-11-14T15:30:45.500Z",
      "sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
      "fileType": "exe"
    }
  ],
  "processesExecuted": [
    {
      "processName": "network_tester.exe",
      "commandLine": "network_tester.exe --endpoints 10 --protocol https",
      "pid": 8472,
      "success": true,
      "exitCode": 0,
      "timestamp": "2024-11-14T15:30:46.000Z",
      "parentPid": 4568
    }
  ],
  "networkTest": {
    "totalEndpoints": 10,
    "successfulTests": 10,
    "failedTests": 0,
    "vulnerableCount": 10,
    "protectedCount": 0,
    "overallVulnerable": true,
    "results": [
      {
        "endpoint": "https://api.example.com/v1",
        "blocked": false,
        "latencyMs": 45
      }
    ]
  },
  "metrics": {
    "totalPhases": 2,
    "successfulPhases": 2,
    "failedPhases": 0,
    "totalFilesDropped": 1,
    "filesQuarantined": 0,
    "totalProcesses": 1,
    "successfulProcesses": 1,
    "totalLogMessages": 3,
    "errorCount": 0,
    "criticalCount": 0
  },
  "artifacts": {
    "logFilePath": "C:\\F0\\test_execution_log.txt",
    "jsonFilePath": "C:\\F0\\test_execution_log.json"
  }
}
```

---

## Support and Feedback

For questions, issues, or suggestions regarding the schema:

1. Review this guide thoroughly
2. Check schema validation errors carefully
3. Consult example files in `examples/` directory
4. File issues in the F0RT1KA repository

**Schema Version**: 2.0.0
**Last Updated**: 2024-11-14
**Status**: Production Ready
