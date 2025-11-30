# Elasticsearch Output Deployment Guide

Quick guide to deploy F0RT1KA test results export to additional organizations (tpsgl, rga).

## Prerequisites

- Elastic Cloud credentials (cloud_id, api_key) - same as used for sb
- LimaCharlie web UI access for target organization

## Deployment Steps (Per Organization)

### 1. Create Elasticsearch Output

In LimaCharlie Web UI for the target org:

1. Go to **Outputs** → **Add Output**
2. Configure:

| Field | Value |
|-------|-------|
| Name | `f0-test-results-elasticsearch` |
| Module | `elastic` |
| Stream | `tailored` |
| cloud_id | `<your-cloud-id>` |
| api_key | `<your-api-key>` |
| index | `f0rtika-results-tpsgl` or `f0rtika-results-rga` |

### 2. Create D&R Rule

1. Go to **D&R Rules** → **Add Rule**
2. Name: `f0-test-results-to-elasticsearch`

**Detect field** (paste exactly):
```yaml
event: RECEIPT
op: and
rules:
- op: contains
  path: event/FILE_PATH
  value: "c:\\F0"
- op: contains
  path: event/FILE_PATH
  value: f0rtika-cert-installer
  not: true
- op: is
  path: event/ERROR
  value: 200
  not: true
- op: is
  path: event/ERROR
  value: 259
  not: true
```

**Respond field** (paste exactly):
```yaml
- action: output
  name: f0-test-results-elasticsearch
```

3. Save the rule

### 3. Verify

Run a test on an endpoint in that org and check:
```bash
curl -s "https://${ES_HOST}:443/f0rtika-results-{org}/_search?pretty" \
  -H "Authorization: ApiKey ${API_KEY}" \
  -d '{"query": {"match_all": {}}, "size": 1}'
```

## Index Names by Organization

| Org | Index Name |
|-----|------------|
| sb | `f0rtika-results-sb` |
| tpsgl | `f0rtika-results-tpsgl` |
| rga | `f0rtika-results-rga` |

## Kibana Data View

After deploying to all orgs, update your Kibana data view:
- Pattern: `f0rtika-results-*` (covers all orgs)
- Timestamp: `routing.event_time`

## Checklist

- [ ] **tpsgl**: Output configured
- [ ] **tpsgl**: D&R rule created
- [ ] **tpsgl**: Test verified in Elasticsearch
- [ ] **rga**: Output configured
- [ ] **rga**: D&R rule created
- [ ] **rga**: Test verified in Elasticsearch
