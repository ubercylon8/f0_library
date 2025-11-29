# Elasticsearch Export Quick Start

Direct ES export enables F0RT1KA test orchestrators to send results to Elasticsearch in real-time, eliminating the need for the scheduled collector task.

## Quick Setup (3 Steps)

### 1. Configure ES Registry

Copy the template and add your endpoints:

```bash
cp docs/elasticsearch-registry.template.json signing-certs/elasticsearch-registry.json
```

Edit `elasticsearch-registry.json` with your ES cluster details:

```json
{
  "profiles": [
    {
      "shortName": "prod",
      "endpoint": "https://your-es-cluster.elastic-cloud.com:443",
      "index": "f0-test-results",
      "apiKeyEnvVar": "F0_ES_PROD_APIKEY"
    }
  ]
}
```

### 2. Set API Key Environment Variable

```bash
export F0_ES_PROD_APIKEY='your-base64-encoded-api-key'
```

### 3. Build with ES Export

```bash
cd tests_source/<test-uuid>/
./build_all.sh --org sb --es prod
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    Build Time                               │
├─────────────────────────────────────────────────────────────┤
│  build_all.sh --es prod                                     │
│       │                                                     │
│       ▼                                                     │
│  Reads elasticsearch-registry.json                          │
│       │                                                     │
│       ▼                                                     │
│  Generates es_config.go with:                               │
│    - ES_ENABLED = true                                      │
│    - ES_ENDPOINT = "https://..."                            │
│    - ES_INDEX = "f0-test-results"                           │
│    - ES_APIKEY = "<from env var>"                           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Runtime                                  │
├─────────────────────────────────────────────────────────────┤
│  Test executes on endpoint                                  │
│       │                                                     │
│       ▼                                                     │
│  1. Write JSON to c:\F0\test_execution_log.json             │
│       │                                                     │
│       ▼                                                     │
│  2. Attempt ES export (if ES_ENABLED)                       │
│       │                                                     │
│       ├──► Success: Update JSON with exportStatus           │
│       │                                                     │
│       └──► Failure: Update JSON with error + retryEligible  │
│                      (collector can retry later)            │
└─────────────────────────────────────────────────────────────┘
```

## Build Commands

```bash
# ES disabled (backward compatible - default)
./build_all.sh --org sb

# ES enabled with specific profile
./build_all.sh --org sb --es prod
./build_all.sh --org sb --es lab

# ES enabled with default profile (if configured)
./build_all.sh --org sb --es
```

## Result JSON Structure

When ES export is enabled, the results JSON includes an `exportStatus` field:

```json
{
  "testId": "abc123-...",
  "testName": "My Security Test",
  "exportStatus": {
    "attempted": true,
    "success": true,
    "timestamp": "2025-11-29T10:30:00Z",
    "endpoint": "https://es.example.com:443",
    "index": "f0-test-results-2025.11.29",
    "documentId": "sha256-hash-of-test-execution",
    "retryEligible": false
  }
}
```

If export fails:

```json
{
  "exportStatus": {
    "attempted": true,
    "success": false,
    "error": "connection refused",
    "retryEligible": true
  }
}
```

The collector can check `retryEligible: true` to retry failed exports.

## ES Profile Configuration

Full profile options in `elasticsearch-registry.json`:

| Field | Required | Description |
|-------|----------|-------------|
| `shortName` | Yes | Profile identifier (e.g., "prod", "lab") |
| `endpoint` | Yes | ES cluster URL with port |
| `index` | Yes | Base index name (date suffix added automatically) |
| `apiKeyEnvVar` | Yes | Environment variable containing API key |
| `uuid` | No | Unique identifier for the profile |
| `fullName` | No | Human-readable name |
| `enabled` | No | Enable/disable profile (default: true) |
| `default` | No | Mark as default profile |

## Security Notes

- API keys are read from environment variables at **build time**
- Keys are embedded in the binary (treat signed binaries appropriately)
- The `signing-certs/elasticsearch-registry.json` is gitignored (contains endpoint info)
- Use `docs/elasticsearch-registry.template.json` as your starting point

## Troubleshooting

**"Environment variable X is not set"**
```bash
export F0_ES_PROD_APIKEY='your-api-key'
```

**"Elasticsearch profile not found"**
```bash
# List available profiles
source utils/resolve_es.sh
list_es_profiles
```

**"ES export failed" in results**
- Check endpoint accessibility from test machine
- Verify API key has write permissions to index
- Check `exportStatus.error` in results JSON

## Backward Compatibility

- Tests built **without** `--es` flag work exactly as before
- Local JSON is **always** written first (ES export is secondary)
- If ES export fails, test execution is not affected
- Collector can still process results with `retryEligible: true`
