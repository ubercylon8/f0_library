# Elasticsearch Data Enrichment for F0RT1KA Test Results

This guide explains how to enrich F0RT1KA test results in Elasticsearch with additional metadata fields like test name, ATT&CK techniques, error code names, and protection status.

## Overview

RECEIPT events from LimaCharlie are enriched using an Elasticsearch ingest pipeline that:
1. **Extracts the test UUID** from the `event.FILE_PATH` field
2. **Maps error codes** to human-readable names (Unprotected, ExecutionPrevented, etc.)
3. **Looks up test metadata** from a catalog index (test name, techniques, score)

### Enriched Fields

After enrichment, documents will have these fields under the `f0rtika` namespace:

| Field | Description | Example |
|-------|-------------|---------|
| `f0rtika.test_uuid` | Test identifier extracted from FILE_PATH | `5ed12ef2-5e29-49a2-8f26-269d8e9edcea` |
| `f0rtika.test_name` | Human-readable test name | `Multi-Stage Ransomware Killchain` |
| `f0rtika.techniques` | MITRE ATT&CK technique IDs | `["T1204.002", "T1134.001"]` |
| `f0rtika.score` | Test quality score (0-10) | `8.5` |
| `f0rtika.error_name` | Human-readable exit code name | `Unprotected` |
| `f0rtika.is_protected` | Boolean: was endpoint protected? | `false` |

### Error Code Reference

| Code | Name | Description | is_protected |
|------|------|-------------|--------------|
| 101 | Unprotected | Attack succeeded, system vulnerable | `false` |
| 105 | FileQuarantinedOnExtraction | File quarantined before execution | `true` |
| 126 | ExecutionPrevented | Execution blocked by EDR | `true` |
| 127 | QuarantinedOnExecution | File quarantined during execution | `true` |
| 999 | UnexpectedTestError | Test error (prerequisites not met) | `false` |

## Prerequisites

- Elasticsearch/Kibana access with admin privileges
- API key with write access to indices
- Python 3.x (for catalog sync script)
- `elasticsearch` Python package: `pip install elasticsearch`

## Setup Steps

### Step 1: Create the Test Catalog Index

```bash
# Using curl
curl -X PUT "${ES_HOST}/f0rtika-test-catalog" \
  -H "Authorization: ApiKey ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d @limacharlie-iac/elasticsearch/catalog-index-mapping.json
```

Or in Kibana Dev Tools:
```json
PUT /f0rtika-test-catalog
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  },
  "mappings": {
    "properties": {
      "test_uuid": { "type": "keyword" },
      "test_name": { "type": "keyword" },
      "techniques": { "type": "keyword" },
      "score": { "type": "float" }
    }
  }
}
```

### Step 2: Sync Test Metadata to Catalog

```bash
# Set credentials
export ELASTIC_CLOUD_ID="your-cloud-id"
export ELASTIC_API_KEY="your-api-key"

# Preview what will be synced
python3 utils/sync-test-catalog-to-elasticsearch.py --dry-run

# Run the sync
python3 utils/sync-test-catalog-to-elasticsearch.py
```

The script reads metadata from:
- `tests_source/<uuid>/<uuid>.go` - Test name and techniques from header comment
- `tests_source/<uuid>/README.md` - Test score

### Step 3: Create the Enrich Policy

In Kibana Dev Tools:
```json
PUT /_enrich/policy/f0rtika-test-enrichment
{
  "match": {
    "indices": "f0rtika-test-catalog",
    "match_field": "test_uuid",
    "enrich_fields": ["test_name", "techniques", "score"]
  }
}
```

Then execute the policy to create the enrich index:
```json
POST /_enrich/policy/f0rtika-test-enrichment/_execute
```

### Step 4: Create the Ingest Pipeline

In Kibana Dev Tools:
```json
PUT /_ingest/pipeline/f0rtika-results-enrichment
{
  "description": "Enriches F0RT1KA test results with test metadata",
  "processors": [
    {
      "script": {
        "description": "Extract test UUID from FILE_PATH",
        "lang": "painless",
        "source": "String path = ctx.event?.FILE_PATH; if (path != null) { def matcher = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/.matcher(path.toLowerCase()); if (matcher.find()) { if (ctx.f0rtika == null) { ctx.f0rtika = new HashMap(); } ctx.f0rtika.test_uuid = matcher.group(1); } }"
      }
    },
    {
      "script": {
        "description": "Map error code to human-readable name",
        "lang": "painless",
        "source": "def errorCode = ctx.event?.ERROR; if (errorCode != null) { def errorNames = new HashMap(); errorNames.put(101, 'Unprotected'); errorNames.put(105, 'FileQuarantinedOnExtraction'); errorNames.put(126, 'ExecutionPrevented'); errorNames.put(127, 'QuarantinedOnExecution'); errorNames.put(999, 'UnexpectedTestError'); if (ctx.f0rtika == null) { ctx.f0rtika = new HashMap(); } ctx.f0rtika.error_name = errorNames.getOrDefault(errorCode, 'Unknown'); ctx.f0rtika.is_protected = (errorCode == 105 || errorCode == 126 || errorCode == 127); }"
      }
    },
    {
      "enrich": {
        "description": "Enrich with test metadata from catalog",
        "policy_name": "f0rtika-test-enrichment",
        "field": "f0rtika.test_uuid",
        "target_field": "f0rtika.test_metadata",
        "max_matches": 1,
        "ignore_missing": true
      }
    },
    {
      "script": {
        "description": "Flatten test metadata into f0rtika namespace",
        "lang": "painless",
        "source": "if (ctx.f0rtika?.test_metadata != null) { def meta = ctx.f0rtika.test_metadata; ctx.f0rtika.test_name = meta.test_name; ctx.f0rtika.techniques = meta.techniques; ctx.f0rtika.score = meta.score; ctx.f0rtika.remove('test_metadata'); }"
      }
    }
  ]
}
```

### Step 5: Update LimaCharlie Elasticsearch Output

Add the `pipeline` parameter to your Elasticsearch output configuration.

**In LimaCharlie Web UI:**
1. Go to **Outputs**
2. Edit the `f0-test-results-elasticsearch` output
3. Add parameter: `pipeline` = `f0rtika-results-enrichment`
4. Save

**Via CLI:**
```bash
limacharlie output add f0-test-results-elasticsearch \
  --module elastic \
  --stream tailored \
  --config cloud_id="$CLOUD_ID" \
  --config api_key="$API_KEY" \
  --config index="f0rtika-results-sb" \
  --config pipeline="f0rtika-results-enrichment"
```

## Verification

### Test the Pipeline

Simulate a document through the pipeline:
```json
POST /_ingest/pipeline/f0rtika-results-enrichment/_simulate
{
  "docs": [
    {
      "_source": {
        "event": {
          "FILE_PATH": "c:\\F0\\5ed12ef2-5e29-49a2-8f26-269d8e9edcea.exe",
          "ERROR": 101
        }
      }
    }
  ]
}
```

Expected output should include `f0rtika` fields:
```json
{
  "f0rtika": {
    "test_uuid": "5ed12ef2-5e29-49a2-8f26-269d8e9edcea",
    "test_name": "Multi-Stage Ransomware Killchain",
    "techniques": ["T1204.002", "T1134.001", "T1083", "T1486", "T1491.001"],
    "score": 8.5,
    "error_name": "Unprotected",
    "is_protected": false
  }
}
```

### Query Enriched Documents

```json
// Find all documents with enrichment
GET /f0rtika-results-*/_search
{
  "query": { "exists": { "field": "f0rtika.test_name" } },
  "size": 5
}

// Aggregate by test name
GET /f0rtika-results-*/_search
{
  "size": 0,
  "aggs": {
    "by_test": {
      "terms": { "field": "f0rtika.test_name" }
    }
  }
}

// Filter by protection status
GET /f0rtika-results-*/_search
{
  "query": {
    "term": { "f0rtika.is_protected": false }
  }
}

// Filter by ATT&CK technique
GET /f0rtika-results-*/_search
{
  "query": {
    "term": { "f0rtika.techniques": "T1486" }
  }
}
```

## Maintaining the Catalog

### When to Re-sync

Run the sync script when:
- A new test is added to `tests_source/`
- Test metadata (name, techniques, score) is updated
- After initial setup

```bash
python3 utils/sync-test-catalog-to-elasticsearch.py
```

### Re-execute Enrich Policy

After syncing new data, re-execute the enrich policy to update the enrich index:

```json
POST /_enrich/policy/f0rtika-test-enrichment/_execute
```

**Important**: The old enrich index is automatically replaced. No manual cleanup needed.

## CI/CD Integration (Future)

To automate catalog sync when tests change:

```yaml
# .github/workflows/sync-test-catalog.yml
name: Sync Test Catalog

on:
  push:
    paths:
      - 'tests_source/**/*.go'
      - 'tests_source/**/README.md'

jobs:
  sync-catalog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'

      - name: Install dependencies
        run: pip install elasticsearch

      - name: Sync test catalog
        env:
          ELASTIC_CLOUD_ID: ${{ secrets.ELASTIC_CLOUD_ID }}
          ELASTIC_API_KEY: ${{ secrets.ELASTIC_API_KEY }}
        run: python utils/sync-test-catalog-to-elasticsearch.py

      - name: Re-execute enrich policy
        run: |
          curl -X POST "${ES_HOST}/_enrich/policy/f0rtika-test-enrichment/_execute" \
            -H "Authorization: ApiKey ${{ secrets.ELASTIC_API_KEY }}"
```

## Troubleshooting

### Pipeline Simulation Fails

Check that the enrich policy has been executed:
```json
GET /_enrich/policy/f0rtika-test-enrichment
```

### Test Metadata Not Appearing

1. Verify the test exists in the catalog:
   ```json
   GET /f0rtika-test-catalog/_search
   {
     "query": { "term": { "test_uuid": "your-test-uuid" } }
   }
   ```

2. Re-sync the catalog and re-execute the enrich policy

### Unknown Error Names

The pipeline maps known error codes. Unknown codes will show as `"Unknown"`.
Add new codes to the script processor in the pipeline definition.

## Files Reference

| File | Purpose |
|------|---------|
| `utils/sync-test-catalog-to-elasticsearch.py` | Sync test metadata to Elasticsearch |
| `limacharlie-iac/elasticsearch/catalog-index-mapping.json` | Index mapping definition |
| `limacharlie-iac/elasticsearch/enrich-policy.json` | Enrich policy definition |
| `limacharlie-iac/elasticsearch/ingest-pipeline.json` | Ingest pipeline definition |
