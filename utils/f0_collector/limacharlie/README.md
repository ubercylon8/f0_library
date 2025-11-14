# F0RT1KA Collector - LimaCharlie Integration

Automated, event-driven collection of F0RT1KA test results for LimaCharlie-managed environments.

## Quick Start

```bash
# 1. Build collector (from parent directory)
cd ..
./build.sh

# 2. Deploy to LimaCharlie
cd limacharlie
./deploy-lc-integration.sh <organization> --auto-deploy --output elasticsearch

# 3. Configure Elasticsearch credentials
# Set F0_ELASTIC_API_KEY in LC environment variables

# 4. Tag sensors for deployment
limacharlie sensor tag <sensor-id> f0rtika-endpoint

# Done! Results will be automatically collected.
```

## What's Included

### 1. Enhanced D&R Rules (`enhanced-dr-rules.yaml`)

**10 Production-Ready Rules**:

| Rule | Purpose | Trigger |
|------|---------|---------|
| `f0rtika-auto-deploy-collector` | Auto-deploy to new sensors | Sensor registration |
| `f0rtika-test-result-created-enhanced` | Detect new test results | File creation |
| `f0rtika-collector-monitor-enhanced` | Track collector execution | Process start |
| `f0rtika-collector-failure-alert-enhanced` | Alert on failures | Non-zero exit |
| `f0rtika-elastic-connection-failure` | Network issue detection | DNS failure |
| `f0rtika-collector-heartbeat` | Health monitoring | State file update |
| `f0rtika-missing-heartbeat-alert` | Offline detection | Missing heartbeat |
| `f0rtika-collector-tampering-detection` | Security monitoring | File modification |
| `f0rtika-scheduled-task-check` | Task protection | Task deletion |
| `f0rtika-export-success-tracking` | Export monitoring | Log updates |

### 2. Output Module Configuration (`output-elasticsearch.yaml`)

**Direct Elasticsearch Export**:
- Transform LC artifacts to F0RT1KA schema
- Bulk indexing with retry logic
- Buffering for network outages
- Health checks and monitoring

**Alternative Outputs**:
- Webhook (custom processing)
- Syslog (SIEM integration)

### 3. Deployment Automation (`deploy-lc-integration.sh`)

**One-Command Deployment**:
```bash
./deploy-lc-integration.sh <org> [options]
```

**Options**:
- `--auto-deploy` - Enable automatic collector deployment
- `--output <type>` - Configure output module (elasticsearch, webhook, syslog)
- `--skip-artifacts` - Skip binary upload (monitoring only)
- `--dry-run` - Preview changes without deploying

### 4. Comprehensive Guide (`LC_DEPLOYMENT_GUIDE.md`)

**50+ pages covering**:
- Deployment strategies
- D&R rule reference
- Output configuration
- Monitoring and alerting
- Troubleshooting
- Advanced configurations
- Security best practices

## Deployment Options

### Option 1: Fully Automated (Recommended)

**Best for**: Production environments with multiple sensors

```bash
./deploy-lc-integration.sh <org> --auto-deploy --output elasticsearch
```

**Features**:
- ✅ Auto-deploy to new sensors
- ✅ Event-driven collection
- ✅ Dual-path (collector + LC artifacts)
- ✅ Health monitoring and alerting
- ✅ Direct Elasticsearch export

### Option 2: Monitoring Only

**Best for**: Existing collector deployments

```bash
./deploy-lc-integration.sh <org> --skip-artifacts
```

**Features**:
- ✅ Monitor existing collectors
- ✅ Alert on failures
- ✅ Collect logs for troubleshooting
- ❌ Does not deploy binaries

### Option 3: Manual Deployment

**Best for**: Controlled rollout

```bash
./deploy-lc-integration.sh <org>
# Then manually deploy to specific sensors
```

## Architecture

### Event-Driven Collection

```
Test Completes
      ↓
JSON Created in c:\F0\
      ↓
D&R Rule Detects (NEW_DOCUMENT)
      ↓
┌─────────────┬──────────────┐
│ Path 1:     │ Path 2:      │
│ Trigger     │ LC Artifact  │
│ Collector   │ Collection   │
└─────────────┴──────────────┘
      ↓             ↓
Elasticsearch   LC Platform
  (Primary)      (Backup)
```

### Dual-Path Reliability

**Path 1: Standalone Collector** (Primary)
- Fast, real-time export
- Optimized bulk operations
- Rich schema v2.0 metadata

**Path 2: LC Artifact Collection** (Backup)
- Guaranteed collection via LC
- Alternative export via output module
- Forensic artifact retention

## Key Features

### Automation
- ✅ Auto-deploy to new sensors
- ✅ Event-triggered collection (no polling)
- ✅ Automatic failure recovery
- ✅ Self-healing scheduled tasks

### Monitoring
- ✅ Real-time execution tracking
- ✅ Heartbeat health checks
- ✅ Network connectivity monitoring
- ✅ Export success/failure tracking

### Security
- ✅ Tampering detection
- ✅ Unauthorized modification alerts
- ✅ Scheduled task protection
- ✅ Anomaly detection

### Reliability
- ✅ Dual-path collection
- ✅ Automatic retry logic
- ✅ Network outage buffering
- ✅ Dead letter queue for failures

## Configuration

### Elasticsearch Credentials

**Via LC Web Interface**:
1. Navigate to: **Settings → Environment Variables**
2. Add: `F0_ELASTIC_API_KEY` = `<your-api-key>`

**Via CLI**:
```bash
limacharlie env set F0_ELASTIC_API_KEY <your-api-key>
```

### Sensor Targeting

**Tag sensors for auto-deployment**:
```bash
# Tag individual sensor
limacharlie sensor tag <sensor-id> f0rtika-endpoint

# Tag all Windows sensors
limacharlie sensor list --platform windows | \
  xargs -I {} limacharlie sensor tag {} f0rtika-endpoint
```

### Custom Collection Intervals

Edit `enhanced-dr-rules.yaml`:
```yaml
# Change from 5 minutes to 1 minute
-RepetitionInterval (New-TimeSpan -Minutes 1)
```

## Monitoring

### Sensor Health

```bash
# Active collectors
limacharlie sensor search 'tag:f0rtika-active'

# Healthy collectors (recent heartbeat)
limacharlie sensor search 'tag:f0rtika-healthy'

# Sensors needing attention
limacharlie sensor search 'tag:f0rtika-endpoint AND NOT tag:f0rtika-healthy'
```

### Alerts

**View recent alerts**:
```bash
limacharlie detect list --filter f0rtika
```

**Alert types**:
- `f0rtika_collector_failure` - Non-zero exit code
- `f0rtika_network_issue` - DNS/connectivity problems
- `f0rtika_collector_offline` - Missing heartbeat
- `f0rtika_tampering_detected` - Unauthorized modifications
- `f0rtika_scheduled_task_deleted` - Task protection

## Troubleshooting

### Quick Diagnostics

```bash
# Check rule deployment
limacharlie dr list | grep f0rtika

# Check artifact upload
limacharlie artifact list | grep f0_collector

# Check output configuration
limacharlie output list | grep f0rtika

# View recent detections
limacharlie detect list --filter f0rtika --limit 20
```

### Common Issues

**Collector not auto-deploying**:
```bash
# Verify rule is enabled
limacharlie dr show f0rtika-auto-deploy-collector

# Check artifacts exist
limacharlie artifact list | grep f0_collector
```

**Collection not triggering**:
```bash
# Check detection rule
limacharlie dr show f0rtika-test-result-created-enhanced

# View sensor events
limacharlie sensor events <sensor-id> --type NEW_DOCUMENT
```

**Elasticsearch export failing**:
```bash
# Test output module
limacharlie output test f0rtika-elasticsearch-output

# Check credentials
limacharlie env list | grep F0_ELASTIC
```

## Files Reference

```
limacharlie/
├── README.md                       # This file
├── LC_DEPLOYMENT_GUIDE.md          # Comprehensive guide (50+ pages)
├── enhanced-dr-rules.yaml          # 10 production-ready D&R rules
├── output-elasticsearch.yaml       # Elasticsearch output configuration
└── deploy-lc-integration.sh        # Automated deployment script
```

## Next Steps

1. **Read the full guide**: `LC_DEPLOYMENT_GUIDE.md`
2. **Deploy**: `./deploy-lc-integration.sh <org> --auto-deploy`
3. **Configure**: Set Elasticsearch credentials
4. **Tag**: Target sensors with `f0rtika-endpoint`
5. **Test**: Run F0RT1KA test on a sensor
6. **Monitor**: `limacharlie sensor search 'tag:f0rtika-active'`

## Support

- **Full Documentation**: `LC_DEPLOYMENT_GUIDE.md`
- **Collector Guide**: `../README.md`
- **Framework Docs**: `../../CLAUDE.md`
- **LimaCharlie Docs**: https://docs.limacharlie.io

---

**Version**: 1.0.0
**Status**: Production Ready ✅
**Last Updated**: 2024-11-14
