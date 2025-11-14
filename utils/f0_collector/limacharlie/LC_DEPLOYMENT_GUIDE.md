# F0RT1KA Collector - LimaCharlie Deployment Guide

Complete guide for deploying and managing F0RT1KA Results Collector in LimaCharlie environments.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Deployment Options](#deployment-options)
5. [D&R Rules Reference](#dr-rules-reference)
6. [Output Module Configuration](#output-module-configuration)
7. [Monitoring and Alerting](#monitoring-and-alerting)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Configuration](#advanced-configuration)

---

## Overview

The LimaCharlie integration provides **automated, event-driven collection** of F0RT1KA test results with:

- ✅ Automatic collector deployment to new sensors
- ✅ Event-triggered collection (no polling delays)
- ✅ Built-in health monitoring and alerting
- ✅ Dual-path collection (collector + LC artifacts)
- ✅ Direct Elasticsearch export via LC outputs
- ✅ Tampering detection and recovery

### Architecture

```
┌──────────────────────────────────────────────────┐
│ Windows Sensor (LC Agent)                        │
│                                                  │
│  Test Execution → JSON → c:\F0\                 │
│         ↓                                        │
│  D&R: Detect NEW_DOCUMENT event                 │
│         ↓                                        │
│  ┌─────────────────┬──────────────────┐        │
│  │ Path 1:         │ Path 2:          │        │
│  │ Trigger         │ LC Artifact      │        │
│  │ f0_collector.exe│ Collection       │        │
│  └─────────────────┴──────────────────┘        │
│         │                    │                  │
└─────────┼────────────────────┼──────────────────┘
          ↓                    ↓
   ┌──────────────┐    ┌──────────────┐
   │ Elasticsearch│    │ LC Platform  │
   │ (Direct)     │    │ (Backup)     │
   └──────────────┘    └──────────────┘
```

---

## Prerequisites

### LimaCharlie

- Active LimaCharlie organization
- Windows sensors deployed
- Admin access to LC web interface
- LimaCharlie CLI installed: `pip install limacharlie`

### Elasticsearch

- Elasticsearch cluster (self-hosted or Elastic Cloud)
- API key with write permissions to `f0rtika-*`
- Index template deployed (see main README.md)

### Local Development

- F0RT1KA collector built: `./build.sh`
- Configuration file prepared: `collector_config.json`

---

## Quick Start

### 5-Minute Deployment

```bash
# 1. Build collector
cd utils/f0_collector
./build.sh

# 2. Deploy to LimaCharlie
cd limacharlie
./deploy-lc-integration.sh sb --auto-deploy --output elasticsearch

# 3. Configure Elasticsearch credentials in LC
# (via LC web interface → Settings → Environment Variables)
# Set: F0_ELASTIC_API_KEY

# 4. Tag a test sensor
limacharlie sensor tag <sensor-id> f0rtika-endpoint

# 5. Run a test on the sensor
# Results will be automatically collected!
```

---

## Deployment Options

### Option 1: Fully Automated (Recommended)

**Best for**: Production environments with multiple sensors

```bash
./deploy-lc-integration.sh <org> \
    --auto-deploy \
    --output elasticsearch
```

**What it does**:
- ✅ Uploads collector binary and config to LC
- ✅ Deploys D&R rules for automatic deployment
- ✅ Configures Elasticsearch output module
- ✅ Sets up health monitoring and alerting

**Benefits**:
- New sensors automatically get the collector
- Zero manual intervention per sensor
- Centralized configuration management

### Option 2: Manual Deployment per Sensor

**Best for**: Controlled rollout, specific test sensors

```bash
# Deploy D&R rules only (no auto-deploy)
./deploy-lc-integration.sh <org> --output elasticsearch

# Manually deploy to specific sensors
limacharlie sensor exec <sensor-id> \
    "powershell -File c:\path\to\deploy-collector-task.ps1"
```

**Benefits**:
- Granular control over deployment
- Test on specific sensors first
- Gradual rollout capability

### Option 3: Hybrid (LC Monitoring Only)

**Best for**: Existing collector deployments wanting LC monitoring

```bash
# Deploy monitoring rules only
./deploy-lc-integration.sh <org> \
    --skip-artifacts
```

**What it does**:
- ✅ Monitors existing collector executions
- ✅ Alerts on failures
- ✅ Collects logs for troubleshooting
- ❌ Does not deploy collector binaries

---

## D&R Rules Reference

### Rule 1: Auto-Deploy Collector

**Name**: `f0rtika-auto-deploy-collector`
**Trigger**: New Windows sensor registration
**Actions**:
1. Create `c:\F0` directory structure
2. Download collector from LC artifacts
3. Download configuration file
4. Create scheduled task (5-minute interval)

**Configuration**:
```yaml
detect:
  event: NEW_SENSOR
  op: is windows

respond:
  - Create directories
  - Deploy binaries
  - Configure scheduled task
```

**Enable/Disable**:
```bash
# Enable auto-deployment
limacharlie dr enable f0rtika-auto-deploy-collector

# Disable (manual deployment only)
limacharlie dr disable f0rtika-auto-deploy-collector
```

### Rule 2: Test Result Detection

**Name**: `f0rtika-test-result-created-enhanced`
**Trigger**: `test_execution_log.json` created in `c:\F0\`
**Actions**:
1. Log detection event
2. Collect file via LC artifacts (backup)
3. Trigger collector immediately
4. Optional: Send webhook notification

**Key Features**:
- ✅ Suppression (1 event per 60 seconds)
- ✅ File size validation (> 100 bytes)
- ✅ Excludes already-collected files
- ✅ Dual-path collection (reliability)

### Rule 3: Collector Execution Monitor

**Name**: `f0rtika-collector-monitor-enhanced`
**Trigger**: `f0_collector.exe` process creation
**Actions**:
1. Log execution with full context
2. Tag sensor as `f0rtika-active` (1-hour TTL)

**Use Cases**:
- Track collector execution frequency
- Identify sensors with stale collectors
- Audit collector usage

### Rule 4: Failure Alerting

**Name**: `f0rtika-collector-failure-alert-enhanced`
**Trigger**: Collector exits with non-zero code
**Actions**:
1. Create high-priority alert
2. Collect `collector.log` for analysis
3. Optional: Attempt automatic recovery

**Alert Metadata**:
- Exit code
- Runtime duration
- Command-line arguments
- Sensor hostname
- Organization

### Rule 5: Network Issue Detection

**Name**: `f0rtika-elastic-connection-failure`
**Trigger**: DNS resolution failure from collector
**Actions**:
1. Log network issue
2. Alert security team

**Use Cases**:
- Identify network connectivity problems
- Detect Elasticsearch endpoint issues
- Track DNS resolution failures

### Rule 6: Health Heartbeat

**Name**: `f0rtika-collector-heartbeat`
**Trigger**: State file modification (`c:\F0\.collector_state.json`)
**Actions**:
1. Update heartbeat timestamp
2. Refresh `f0rtika-healthy` tag (10-minute TTL)

**Monitoring**:
```bash
# List healthy sensors
limacharlie sensor search 'tag:f0rtika-healthy'

# List sensors missing heartbeat
limacharlie sensor search 'NOT tag:f0rtika-healthy AND tag:f0rtika-endpoint'
```

### Rule 7: Tampering Detection

**Name**: `f0rtika-collector-tampering-detection`
**Trigger**: Collector binary or config modified by non-SYSTEM user
**Actions**:
1. Create high-priority security alert
2. Collect modified files for analysis
3. Optional: Trigger forensic investigation

**Security Use Cases**:
- Detect unauthorized modifications
- Identify compromise attempts
- Trigger incident response workflows

### Rule 8: Scheduled Task Protection

**Name**: `f0rtika-scheduled-task-check`
**Trigger**: Scheduled task deletion (Windows Event Log 4699)
**Actions**:
1. Alert on task deletion
2. Attempt automatic recreation

**Use Cases**:
- Protect against accidental deletion
- Detect anti-forensics techniques
- Maintain collector persistence

---

## Output Module Configuration

### Direct Elasticsearch Export

**Configuration File**: `output-elasticsearch.yaml`

#### Setup

1. **Upload Configuration to LC**:
```bash
limacharlie output add -f output-elasticsearch.yaml
```

2. **Set Elasticsearch Credentials**:

Via LC Web Interface:
- Navigate to: **Settings → Environment Variables**
- Add variable:
  - Name: `F0_ELASTIC_API_KEY`
  - Value: `<your-api-key>`
  - Scope: Organization-wide

Via CLI:
```bash
limacharlie env set F0_ELASTIC_API_KEY <your-api-key>
```

3. **Verify Configuration**:
```bash
limacharlie output list | grep f0rtika
limacharlie output test f0rtika-elasticsearch-output
```

#### How It Works

```
LC Sensor → Artifact Collection → Transform → Elasticsearch
           (test_execution_log.json)  (add LC metadata)  (bulk index)
```

**Transform Pipeline**:
1. Extract JSON from artifact
2. Add `collectionMetadata`:
   - `sensorId`
   - `collectorVersion: "limacharlie-1.0"`
   - `collectorHost` (sensor hostname)
3. Add `@timestamp` for Kibana
4. Bulk export to Elasticsearch

#### Advantages

- ✅ **No collector needed** - LC handles everything
- ✅ **Centralized configuration** - Manage from LC console
- ✅ **Built-in reliability** - LC handles retries and buffering
- ✅ **Monitoring** - LC provides export metrics

#### Disadvantages

- ⚠ Requires LC output module license
- ⚠ Slight data latency vs. real-time collector
- ⚠ Different metadata structure

### Webhook Output (Alternative)

For custom processing or middleware:

```yaml
name: f0rtika-webhook-output
type: webhook
url: https://your-api.com/ingest
```

**Use Cases**:
- Custom data transformation
- Multi-destination routing
- Integration with existing pipelines

---

## Monitoring and Alerting

### Sensor Health Dashboard

**Query**: Sensors with active collectors
```bash
limacharlie sensor search 'tag:f0rtika-active'
```

**Query**: Sensors with recent heartbeat
```bash
limacharlie sensor search 'tag:f0rtika-healthy'
```

**Query**: Sensors requiring attention
```bash
limacharlie sensor search 'tag:f0rtika-endpoint AND NOT tag:f0rtika-healthy'
```

### Alert Categories

#### 1. Collector Failures

**Alert**: `f0rtika_collector_failure`
**Severity**: Medium
**Response**:
1. Check `collector.log` (auto-collected)
2. Verify Elasticsearch connectivity
3. Check sensor network connectivity
4. Review configuration

#### 2. Network Issues

**Alert**: `f0rtika_network_issue`
**Severity**: Medium
**Response**:
1. Verify DNS resolution
2. Check firewall rules
3. Test Elasticsearch endpoint
4. Review proxy configuration

#### 3. Missing Heartbeat

**Alert**: `f0rtika_collector_offline`
**Severity**: High
**Response**:
1. Check if collector process is running
2. Verify scheduled task exists
3. Check for service disruptions
4. Review sensor health

#### 4. Tampering Detection

**Alert**: `f0rtika_tampering_detected`
**Severity**: High
**Response**:
1. Review modified files (auto-collected)
2. Investigate user/process responsible
3. Check for compromise indicators
4. Initiate incident response if needed

### Custom Alerts

Create custom alerts in LC for specific scenarios:

**Example: High Failure Rate**

```yaml
detect:
  event: REPORT
  report_name: f0rtika_collector_failure
  threshold:
    count: 5
    period: 3600  # 5 failures in 1 hour

respond:
  - action: escalate
    severity: high
  - action: webhook
    url: https://your-pagerduty-url.com
```

---

## Troubleshooting

### Issue: Collector Not Auto-Deploying

**Symptoms**: New sensors don't get collector

**Check**:
1. Verify rule is enabled:
```bash
limacharlie dr show f0rtika-auto-deploy-collector
```

2. Check sensor tags:
```bash
limacharlie sensor info <sensor-id> | grep tags
```

3. Verify artifacts uploaded:
```bash
limacharlie artifact list | grep f0_collector
```

**Solution**:
- Enable rule: `limacharlie dr enable f0rtika-auto-deploy-collector`
- Upload artifacts: `./deploy-lc-integration.sh <org> --auto-deploy`
- Tag sensor: `limacharlie sensor tag <sensor-id> f0rtika-endpoint`

### Issue: Collection Not Triggering

**Symptoms**: Tests complete but results not collected

**Check**:
1. Verify detection rule:
```bash
limacharlie dr show f0rtika-test-result-created-enhanced
```

2. Check sensor events:
```bash
limacharlie sensor events <sensor-id> --type NEW_DOCUMENT
```

3. Verify file path:
```bash
# On sensor, check:
dir c:\F0\test_execution_log.json
```

**Solution**:
- Ensure file is in `c:\F0\` (not subdirectory)
- Verify filename is exactly `test_execution_log.json`
- Check rule suppression isn't blocking

### Issue: Elasticsearch Export Failing

**Symptoms**: Alerts showing export failures

**Check**:
1. Test Elasticsearch connectivity:
```bash
# From sensor:
Test-NetConnection your-elasticsearch-host -Port 9200
```

2. Verify API key:
```bash
limacharlie env list | grep F0_ELASTIC
```

3. Check output module:
```bash
limacharlie output test f0rtika-elasticsearch-output
```

**Solution**:
- Update API key: `limacharlie env set F0_ELASTIC_API_KEY <new-key>`
- Verify Elasticsearch endpoint in `output-elasticsearch.yaml`
- Check index template exists
- Review Elasticsearch logs

### Issue: Heartbeat Missing

**Symptoms**: Sensors showing as unhealthy

**Check**:
1. Verify collector is running:
```bash
# On sensor:
Get-ScheduledTask -TaskName "F0RT1KA Results Collector"
```

2. Check state file:
```bash
# On sensor:
Get-Content c:\F0\.collector_state.json | ConvertFrom-Json
```

3. Review collector logs:
```bash
# On sensor:
Get-Content c:\F0\collector.log -Tail 50
```

**Solution**:
- Restart scheduled task
- Verify collector binary is present
- Check for errors in collector.log
- Manually trigger: `c:\F0\f0_collector.exe collect --once --verbose`

---

## Advanced Configuration

### Multi-Organization Deployment

Deploy to multiple LC organizations:

```bash
for org in sb tpsgl rga; do
    echo "Deploying to $org..."
    ./deploy-lc-integration.sh $org --auto-deploy --output elasticsearch
done
```

### Environment-Specific Configurations

**Production**:
```bash
./deploy-lc-integration.sh prod \
    --auto-deploy \
    --output elasticsearch
```

**Lab**:
```bash
./deploy-lc-integration.sh lab \
    --auto-deploy \
    --output elasticsearch
```

Use different Elasticsearch indices:
- Production: `f0rtika-prod-{yyyy.MM.dd}`
- Lab: `f0rtika-lab-{yyyy.MM.dd}`

### Custom Collection Intervals

Modify scheduled task interval via D&R rule:

```yaml
- action: task
  command: >
    powershell.exe -Command "
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
    # Rest of task creation...
    "
```

### Selective Deployment by Sensor Tags

Target specific sensor groups:

```yaml
detect:
  event: NEW_SENSOR
  op: and
  rules:
    - op: is windows
    - op: has tag
      tag: production
```

### Integration with LC Yara

Scan collected test results with Yara:

```yaml
detect:
  event: ARTIFACT_GET
  file_path:
    ends_with: "test_execution_log.json"

respond:
  - action: yara_scan
    artifact: event/ARTIFACT_ID
    rules: f0rtika-validation
```

### Integration with LC Forensics

Automatically collect forensic artifacts on test failures:

```yaml
detect:
  event: REPORT
  report_name: f0rtika_test_result_detected

respond:
  - action: forensic_collect
    artifacts:
      - memory_dump
      - process_tree
      - network_connections
    condition:
      # Only if test showed unprotected
      outcome.protected: false
```

---

## Performance Optimization

### Reduce LC Event Volume

**Suppress duplicate detections**:
```yaml
suppression:
  is global: false
  keys:
    - event/SENSOR_ID
    - event/FILE_PATH
  max count: 1
  period: 300  # 5 minutes
```

### Optimize Artifact Collection

**Collect only on failure**:
```yaml
respond:
  - action: artifact_get
    file_path: c:\F0\collector.log
    condition:
      event/EXIT_CODE:
        not: 0
```

### Batch Processing

Configure output module for batch processing:

```yaml
bulk:
  size: 100
  flush_interval: 30s
```

---

## Security Best Practices

### 1. Restrict Collector Execution

Use LC D&R to allow only expected execution:

```yaml
detect:
  event: NEW_PROCESS
  file_path: f0_collector.exe
  parent:
    not: taskeng.exe|svchost.exe

respond:
  - action: deny
  - action: report
    severity: critical
```

### 2. Encrypt Sensitive Data

Store API keys securely:
- Use LC environment variables
- Never hardcode in rules
- Rotate regularly

### 3. Monitor for Anomalies

Alert on unexpected collector behavior:
- High failure rates
- Unusual execution times
- Unexpected parent processes
- File modifications

### 4. Audit Trail

All LC actions are logged:
```bash
limacharlie audit --filter "f0rtika"
```

---

## Cost Optimization

### LC Credits Usage

**High-cost operations**:
- Artifact collection (per MB)
- Task execution (per run)
- Output module (per event)

**Optimization strategies**:
1. **Selective artifact collection**: Only on failures
2. **Suppression**: Prevent duplicate triggers
3. **Batch processing**: Reduce output events
4. **Targeted deployment**: Tag-based filtering

### Estimate Monthly Costs

**Assumptions**:
- 10 sensors
- 5 tests/day per sensor
- 500KB per test result
- 95% success rate

**Estimated LC usage**:
- Artifact collection: 50 tests × 500KB = 25MB/day
- Task execution: ~300 runs/day
- Output events: 50 events/day

**Check actual usage**:
```bash
limacharlie billing usage --period month
```

---

## Migration from Standalone Collector

### Gradual Migration Path

1. **Phase 1**: Deploy LC monitoring alongside existing collectors
```bash
./deploy-lc-integration.sh <org> --skip-artifacts
```

2. **Phase 2**: Enable LC artifact collection (backup)
```bash
limacharlie dr enable f0rtika-test-result-created-enhanced
```

3. **Phase 3**: Configure LC output module
```bash
limacharlie output add -f output-elasticsearch.yaml
```

4. **Phase 4**: Disable standalone collectors on select sensors
```powershell
Unregister-ScheduledTask -TaskName "F0RT1KA Results Collector"
```

5. **Phase 5**: Monitor for 1 week, then full migration

---

## Appendix

### LC CLI Cheat Sheet

```bash
# Authentication
limacharlie login
limacharlie org use <org>

# Rules
limacharlie dr list
limacharlie dr show <rule-name>
limacharlie dr enable <rule-name>
limacharlie dr disable <rule-name>
limacharlie dr delete <rule-name>

# Artifacts
limacharlie artifact list
limacharlie artifact upload --name <name> --file <path>
limacharlie artifact download <name>

# Sensors
limacharlie sensor list
limacharlie sensor info <sensor-id>
limacharlie sensor tag <sensor-id> <tag>
limacharlie sensor search 'tag:<tag>'

# Outputs
limacharlie output list
limacharlie output test <output-name>

# Environment
limacharlie env list
limacharlie env set <key> <value>
```

### File Reference

```
limacharlie/
├── enhanced-dr-rules.yaml          # 10 production-ready D&R rules
├── output-elasticsearch.yaml       # Elasticsearch output config
├── deploy-lc-integration.sh        # Automated deployment script
├── LC_DEPLOYMENT_GUIDE.md          # This document
└── README.md                       # Quick reference (to be created)
```

### Support Resources

- **LimaCharlie Docs**: https://docs.limacharlie.io
- **F0RT1KA Collector**: `../README.md`
- **Elasticsearch Integration**: `../kibana-dashboard-examples.md`
- **General Framework**: `../../CLAUDE.md`

---

**Version**: 1.0.0
**Last Updated**: 2024-11-14
**Status**: Production Ready ✅
