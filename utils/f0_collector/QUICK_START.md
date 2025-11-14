# F0RT1KA Results Collector - Quick Start Guide

Get up and running with F0RT1KA Results Collector in 10 minutes.

## Prerequisites

- Windows endpoint with F0RT1KA tests
- Elasticsearch cluster (self-hosted or Elastic Cloud)
- Administrator access on Windows endpoint

## Step 1: Build the Collector (5 minutes)

### On Linux/Mac (cross-compile for Windows):

```bash
cd utils/f0_collector
GOOS=windows GOARCH=amd64 go build -o f0_collector.exe
```

### On Windows:

```powershell
cd utils\f0_collector
go build -o f0_collector.exe
```

## Step 2: Configure Elasticsearch (3 minutes)

### Option A: Using API Key (Recommended)

1. In Kibana, go to **Stack Management → Security → API Keys**
2. Click **Create API key**
3. Name: `f0rtika-collector`
4. Set permissions:
   ```json
   {
     "f0rtika-writer": {
       "cluster": [],
       "index": [
         {
           "names": ["f0rtika-*"],
           "privileges": ["write", "create_index", "auto_configure"]
         }
       ]
     }
   }
   ```
5. Copy the generated API key

### Option B: Using Username/Password

Create a user with appropriate permissions or use existing credentials.

### Update Configuration

Edit `collector_config.json`:

```json
{
  "elasticsearch": {
    "enabled": true,
    "endpoints": ["https://your-elasticsearch-host:9200"],
    "apiKey": "YOUR_API_KEY_HERE"
  }
}
```

**OR** use environment variable (more secure):

```powershell
$env:F0_ELASTIC_API_KEY = "your-api-key-here"
```

## Step 3: Deploy Elasticsearch Templates (2 minutes)

### Create Index Template

Using curl:
```bash
curl -X PUT "https://your-elasticsearch:9200/_index_template/f0rtika-template" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @elasticsearch-index-template.json
```

OR in Kibana Dev Tools:
```
PUT _index_template/f0rtika-template
<paste contents of elasticsearch-index-template.json>
```

### Create ILM Policy

```bash
curl -X PUT "https://your-elasticsearch:9200/_ilm/policy/f0rtika-ilm-policy" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @elasticsearch-ilm-policy.json
```

## Step 4: Deploy to Windows Endpoint (5 minutes)

### Copy Files

Transfer to your Windows endpoint:
- `f0_collector.exe`
- `collector_config.json`
- `deploy-collector-task.ps1`

### Run Deployment Script

```powershell
# Run as Administrator
.\deploy-collector-task.ps1
```

This will:
- Copy files to `c:\F0\`
- Set up configuration
- Create scheduled task (runs every 5 minutes)
- Validate deployment

## Step 5: Verify Installation (3 minutes)

### Test Configuration

```powershell
cd c:\F0
.\f0_collector.exe validate
```

Expected output:
```
[INFO] Validating configuration...
[INFO] Elasticsearch connectivity test PASSED
[INFO] Configuration validation PASSED
```

### Run Test Collection

```powershell
.\f0_collector.exe collect --once --verbose
```

### Check Status

```powershell
.\f0_collector.exe status
```

## Step 6: Create Kibana Index Pattern (2 minutes)

1. Navigate to **Stack Management → Index Patterns**
2. Click **Create index pattern**
3. Enter: `f0rtika-*`
4. Select time field: `startTime`
5. Click **Create**

## Step 7: View Your Data (2 minutes)

### Quick Discovery Query

1. Go to **Discover** in Kibana
2. Select index pattern: `f0rtika-*`
3. You should see your test results

### Simple Visualization

Create a quick protection rate metric:

1. Go to **Visualize**
2. Create new **Metric** visualization
3. Add aggregation:
   - **Metric**: Average
   - **Field**: `outcome.protected`
4. Save as "Protection Rate"

## Troubleshooting

### No Data in Elasticsearch?

```powershell
# Check collector logs
Get-Content c:\F0\collector.log -Tail 50

# Check state file
Get-Content c:\F0\.collector_state.json | ConvertFrom-Json

# Run with verbose output
.\f0_collector.exe collect --once --verbose
```

### Connection Issues?

```powershell
# Test network connectivity
Test-NetConnection your-elasticsearch-host -Port 9200

# Verify API key
$headers = @{
    "Authorization" = "ApiKey YOUR_API_KEY"
}
Invoke-RestMethod -Uri "https://your-elasticsearch:9200/_cluster/health" -Headers $headers
```

### Validation Errors?

Check that test results conform to schema v2.0:
```powershell
# Validate a specific result file
.\f0_collector.exe collect --dry-run --verbose
```

## Next Steps

### 1. Run F0RT1KA Tests

Execute some F0RT1KA security tests on your endpoint:
```powershell
cd c:\F0
.\your-test.exe
```

Results will be automatically collected within 5 minutes.

### 2. Create Dashboards

Follow [kibana-dashboard-examples.md](kibana-dashboard-examples.md) to create:
- Executive dashboard
- Security operations dashboard
- Technique coverage analysis

### 3. Set Up Alerts

Configure alerts for:
- Protection rate drops
- Specific technique failures
- Collector errors

### 4. Deploy to Additional Endpoints

Repeat deployment steps on other test endpoints.

### 5. Optional: LimaCharlie Integration

If using LimaCharlie:
```bash
./deploy-limacharlie-rules.sh your-org
```

## Common Commands Reference

```powershell
# Validate configuration
.\f0_collector.exe validate

# One-time collection
.\f0_collector.exe collect --once

# View status
.\f0_collector.exe status

# Check logs
Get-Content c:\F0\collector.log -Tail 50 -Wait

# Reset state (force re-collection)
.\f0_collector.exe reset

# Manual collection with verbose output
.\f0_collector.exe collect --once --verbose
```

## Configuration Quick Reference

### Minimal Configuration

```json
{
  "version": "1.0",
  "collector": {
    "scanPath": "c:\\F0"
  },
  "elasticsearch": {
    "enabled": true,
    "endpoints": ["https://your-elastic:9200"],
    "apiKey": "YOUR_API_KEY"
  }
}
```

### Using Environment Variables

```powershell
# Set API key
$env:F0_ELASTIC_API_KEY = "your-api-key"

# Run collector (will use env var)
.\f0_collector.exe collect --once
```

### Collection Intervals

Adjust in deployment script or scheduled task:

```powershell
# 1 minute interval
.\deploy-collector-task.ps1 -Interval 1

# 10 minute interval
.\deploy-collector-task.ps1 -Interval 10
```

## Support

- Full documentation: [README.md](README.md)
- Technical spec: [F0_COLLECTOR_SPECIFICATION.md](F0_COLLECTOR_SPECIFICATION.md)
- Dashboard examples: [kibana-dashboard-examples.md](kibana-dashboard-examples.md)
- Schema guide: `../TEST_RESULTS_SCHEMA_GUIDE.md`

## Success Checklist

- [ ] Collector built successfully
- [ ] Elasticsearch templates deployed
- [ ] Configuration updated with credentials
- [ ] Collector deployed to Windows endpoint
- [ ] Validation test passed
- [ ] Test collection successful
- [ ] Data visible in Kibana
- [ ] Index pattern created
- [ ] First visualization created
- [ ] Scheduled task running

Congratulations! Your F0RT1KA Results Collector is now operational. 🎉
