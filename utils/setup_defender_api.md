# Microsoft Defender 365 API Setup Guide

## Prerequisites

1. **Azure AD App Registration** with Security Events permissions
2. **Python 3.7+** with requests library
3. **Environment variables** for authentication

## Azure AD App Registration

### 1. Create App Registration
```bash
# Using Azure CLI
az ad app create --display-name "F0RT1KA-Defender-Query" --sign-in-audience AzureADMyOrg
```

### 2. Add API Permissions
- Navigate to Azure Portal → Azure Active Directory → App registrations
- Select your app → API permissions → Add a permission
- Choose **Microsoft Graph** → Application permissions
- Add: `SecurityEvents.Read.All`
- Grant admin consent

### 3. Create Client Secret
- Go to Certificates & secrets → New client secret
- Save the secret value securely

## Environment Setup

### 1. Set Environment Variables
```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

## Usage Examples

### Basic File Path Search
```bash
# Search for alerts in F0RT1KA test directory
python defender_alert_query.py --file-path "c:\\F0\\*"

# Search for executable files
python defender_alert_query.py --file-path "*.exe" --severity high
```

### Advanced Filtering
```bash
# Multiple filters with JSON output
python defender_alert_query.py \
  --file-path "c:\\F0\\*" \
  --severity high \
  --status new \
  --days 7 \
  --format json \
  --output f0_alerts.json
```

### Claude Code Subagent Integration
```bash
# Export for subagent processing
python defender_alert_query.py \
  --search-term "akira" \
  --format json \
  --output akira_alerts.json

# CSV format for analysis
python defender_alert_query.py \
  --file-path "c:\\F0\\*" \
  --format csv \
  --output test_alerts.csv
```

## Permissions Required

| Permission | Scope | Description |
|------------|--------|-------------|
| SecurityEvents.Read.All | Application | Read security events and alerts |

## API Rate Limits

- Microsoft Graph: 10,000 requests per 10 minutes per app
- Defender API: 100 requests per minute per tenant

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify tenant ID, client ID, and secret
   - Check app registration permissions
   - Ensure admin consent granted

2. **No Results Found**
   - Verify search criteria (file paths, dates)
   - Check alert retention period (90 days default)
   - Try broader search terms

3. **Permission Denied**
   - Confirm SecurityEvents.Read.All permission
   - Verify admin consent status
   - Check Azure AD roles

### Debug Mode
```bash
# Enable verbose output
python defender_alert_query.py --file-path "c:\\F0\\*" --debug
```