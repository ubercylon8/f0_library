# F0RT1KA Kibana Dashboard Examples

This document provides example visualizations and dashboard configurations for analyzing F0RT1KA test results in Kibana/Elasticsearch.

## Prerequisites

1. Elasticsearch with F0RT1KA test results indexed
2. Kibana access
3. Index pattern created: `f0rtika-*`

## Quick Setup

### 1. Create Index Pattern

1. Navigate to **Stack Management → Index Patterns**
2. Click **Create index pattern**
3. Enter pattern: `f0rtika-*`
4. Select time field: `startTime`
5. Click **Create index pattern**

### 2. Import Sample Dashboard

Sample dashboard JSON files will be provided in future releases.

For now, create visualizations manually using the examples below.

## Core Visualizations

### 1. Protection Rate Over Time

**Type:** Line Chart

**Configuration:**
```
Data:
  - Metrics:
    - Aggregation: Average
    - Field: outcome.protected
    - Custom Label: Protection Rate
  - Buckets:
    - X-Axis:
      - Aggregation: Date Histogram
      - Field: startTime
      - Minimum Interval: 1 day

Options:
  - Y-axis: Format as Percentage
  - Line width: 2
  - Show dots: Yes
```

**Elasticsearch Query:**
```json
{
  "size": 0,
  "query": {
    "range": {
      "startTime": {
        "gte": "now-30d/d",
        "lte": "now/d"
      }
    }
  },
  "aggs": {
    "daily_stats": {
      "date_histogram": {
        "field": "startTime",
        "calendar_interval": "day"
      },
      "aggs": {
        "protection_rate": {
          "avg": {
            "field": "outcome.protected"
          }
        },
        "total_tests": {
          "value_count": {
            "field": "testId"
          }
        }
      }
    }
  }
}
```

### 2. Test Results by Organization

**Type:** Pie Chart

**Configuration:**
```
Data:
  - Metrics:
    - Aggregation: Count
  - Buckets:
    - Slice:
      - Aggregation: Terms
      - Field: executionContext.organization
      - Size: 10
    - Split Chart:
      - Sub-Aggregation: Terms
      - Field: outcome.protected
      - Custom Labels: Protected / Unprotected

Options:
  - Donut: Yes
  - Show Labels: Yes
  - Legend Position: Right
```

**Elasticsearch Query:**
```json
{
  "size": 0,
  "aggs": {
    "organizations": {
      "terms": {
        "field": "executionContext.organization"
      },
      "aggs": {
        "protected": {
          "filter": {
            "term": {
              "outcome.protected": true
            }
          }
        },
        "unprotected": {
          "filter": {
            "term": {
              "outcome.protected": false
            }
          }
        },
        "protection_rate": {
          "bucket_script": {
            "buckets_path": {
              "protected": "protected>_count",
              "total": "_count"
            },
            "script": "params.protected / params.total * 100"
          }
        }
      }
    }
  }
}
```

### 3. MITRE ATT&CK Technique Detection Rates

**Type:** Horizontal Bar Chart

**Configuration:**
```
Data:
  - Metrics:
    - Aggregation: Percentage
    - Field: outcome.protected (filter: true)
    - Custom Label: Detection Rate
  - Buckets:
    - Y-Axis:
      - Aggregation: Terms
      - Field: testMetadata.techniques
      - Order By: Metric (Detection Rate)
      - Order: Ascending
      - Size: 20

Options:
  - Color: Red to Green gradient
  - Show values: Yes
  - X-axis: 0-100%
```

**Elasticsearch Query:**
```json
{
  "size": 0,
  "aggs": {
    "techniques": {
      "terms": {
        "field": "testMetadata.techniques",
        "size": 50
      },
      "aggs": {
        "tests": {
          "value_count": {
            "field": "testId"
          }
        },
        "detected": {
          "filter": {
            "term": {
              "outcome.protected": true
            }
          }
        },
        "detection_rate": {
          "bucket_script": {
            "buckets_path": {
              "detected": "detected>_count",
              "total": "tests"
            },
            "script": "params.detected / params.total * 100"
          }
        }
      }
    }
  }
}
```

### 4. Test Category Distribution

**Type:** Tag Cloud

**Configuration:**
```
Data:
  - Metrics:
    - Aggregation: Count
  - Buckets:
    - Tags:
      - Aggregation: Terms
      - Field: testMetadata.category
      - Size: 20

Options:
  - Orientation: Multiple
  - Font size range: 12-72
  - Color scheme: Cool
```

**Elasticsearch Query:**
```json
{
  "size": 0,
  "aggs": {
    "categories": {
      "terms": {
        "field": "testMetadata.category",
        "size": 50
      }
    }
  }
}
```

### 5. Severity Distribution

**Type:** Vertical Bar Chart

**Configuration:**
```
Data:
  - Metrics:
    - Aggregation: Count
  - Buckets:
    - X-Axis:
      - Aggregation: Terms
      - Field: testMetadata.severity
      - Order: Custom (critical, high, medium, low, informational)
    - Split Series:
      - Aggregation: Terms
      - Field: outcome.protected

Options:
  - Mode: Stacked
  - Colors: Protected (Green), Unprotected (Red)
```

**Elasticsearch Query:**
```json
{
  "size": 0,
  "aggs": {
    "severity": {
      "terms": {
        "field": "testMetadata.severity",
        "order": {
          "_key": "desc"
        }
      },
      "aggs": {
        "by_outcome": {
          "terms": {
            "field": "outcome.protected"
          }
        }
      }
    }
  }
}
```

### 6. Recent Test Results Table

**Type:** Data Table

**Configuration:**
```
Data:
  - Metrics:
    - Top Hit
  - Buckets:
    - Split Rows:
      - Aggregation: Terms
      - Field: testId.keyword
      - Size: 50

Columns to Display:
  - testName
  - executionContext.organization
  - testMetadata.category
  - testMetadata.severity
  - outcome.protected
  - outcome.category
  - startTime
  - durationMs

Sort: startTime (descending)
```

**Elasticsearch Query:**
```json
{
  "size": 50,
  "sort": [
    {
      "startTime": {
        "order": "desc"
      }
    }
  ],
  "_source": [
    "testId",
    "testName",
    "executionContext.organization",
    "testMetadata.category",
    "testMetadata.severity",
    "outcome.protected",
    "outcome.category",
    "startTime",
    "durationMs"
  ]
}
```

### 7. Test Execution Timeline

**Type:** Area Chart

**Configuration:**
```
Data:
  - Metrics:
    - Aggregation: Count
  - Buckets:
    - X-Axis:
      - Aggregation: Date Histogram
      - Field: startTime
      - Minimum Interval: 1 hour
    - Split Series:
      - Aggregation: Terms
      - Field: executionContext.environment

Options:
  - Mode: Stacked
  - Fill opacity: 0.5
```

**Elasticsearch Query:**
```json
{
  "size": 0,
  "query": {
    "range": {
      "startTime": {
        "gte": "now-7d/d"
      }
    }
  },
  "aggs": {
    "timeline": {
      "date_histogram": {
        "field": "startTime",
        "fixed_interval": "1h"
      },
      "aggs": {
        "by_environment": {
          "terms": {
            "field": "executionContext.environment"
          }
        }
      }
    }
  }
}
```

### 8. Average Test Duration by Category

**Type:** Vertical Bar Chart

**Configuration:**
```
Data:
  - Metrics:
    - Aggregation: Average
    - Field: durationMs
    - Custom Label: Avg Duration (ms)
  - Buckets:
    - X-Axis:
      - Aggregation: Terms
      - Field: testMetadata.category
      - Order By: Metric
      - Order: Descending

Options:
  - Color by: Value
  - Color scheme: Heat map
```

**Elasticsearch Query:**
```json
{
  "size": 0,
  "aggs": {
    "categories": {
      "terms": {
        "field": "testMetadata.category"
      },
      "aggs": {
        "avg_duration": {
          "avg": {
            "field": "durationMs"
          }
        }
      }
    }
  }
}
```

### 9. Files Quarantined vs Dropped

**Type:** Metric Visualization

**Configuration:**
```
Multiple Metrics:
  1. Total Files Dropped:
     - Aggregation: Sum
     - Field: metrics.totalFilesDropped

  2. Files Quarantined:
     - Aggregation: Sum
     - Field: metrics.filesQuarantined

  3. Quarantine Rate:
     - Aggregation: Bucket Script
     - Formula: quarantined / total * 100

Options:
  - Layout: Vertical
  - Font size: Large
  - Color: Based on value (red < 50%, green > 80%)
```

**Elasticsearch Query:**
```json
{
  "size": 0,
  "aggs": {
    "total_dropped": {
      "sum": {
        "field": "metrics.totalFilesDropped"
      }
    },
    "quarantined": {
      "sum": {
        "field": "metrics.filesQuarantined"
      }
    },
    "quarantine_rate": {
      "bucket_script": {
        "buckets_path": {
          "quarantined": "quarantined",
          "total": "total_dropped"
        },
        "script": "params.quarantined / params.total * 100"
      }
    }
  }
}
```

### 10. Detection Phase Breakdown

**Type:** Donut Chart

**Configuration:**
```
Data:
  - Metrics:
    - Aggregation: Count
  - Buckets:
    - Slice:
      - Aggregation: Terms
      - Field: outcome.detectionPhase
      - Missing bucket: Include (label as "Not Detected")

Options:
  - Inner radius: 50%
  - Show labels: Yes
  - Legend: Bottom
```

**Elasticsearch Query:**
```json
{
  "size": 0,
  "aggs": {
    "detection_phases": {
      "terms": {
        "field": "outcome.detectionPhase",
        "missing": "not_detected"
      }
    }
  }
}
```

## Sample Dashboard Layout

### Executive Dashboard

**Layout:**
```
┌─────────────────────────────────────────────────────┐
│  KPIs (Row 1)                                       │
│  ┌───────────┬───────────┬───────────┬──────────┐ │
│  │Total Tests│ Protected │ Protection│ Avg Score│ │
│  │   1,234   │   1,156   │   93.7%   │   8.2    │ │
│  └───────────┴───────────┴───────────┴──────────┘ │
├─────────────────────────────────────────────────────┤
│  Trends (Row 2)                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │ Protection Rate Over Time                   │   │
│  │ (Line Chart - Last 30 days)                │   │
│  └─────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────┤
│  Distribution (Row 3)                               │
│  ┌────────────────────┬─────────────────────────┐  │
│  │ Tests by Org       │ Category Distribution   │  │
│  │ (Pie Chart)        │ (Tag Cloud)             │  │
│  └────────────────────┴─────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  Details (Row 4)                                    │
│  ┌─────────────────────────────────────────────┐   │
│  │ Recent Test Results (Data Table)            │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Security Operations Dashboard

**Layout:**
```
┌─────────────────────────────────────────────────────┐
│  ATT&CK Coverage (Row 1)                            │
│  ┌─────────────────────────────────────────────┐   │
│  │ Technique Detection Rates                   │   │
│  │ (Horizontal Bar - Top 20)                   │   │
│  └─────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────┤
│  Detection Analysis (Row 2)                         │
│  ┌────────────────────┬─────────────────────────┐  │
│  │ Detection Phase    │ Severity Distribution   │  │
│  │ (Donut)            │ (Stacked Bar)           │  │
│  └────────────────────┴─────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  File Analysis (Row 3)                              │
│  ┌────────────────────┬─────────────────────────┐  │
│  │ Files Quarantined  │ Process Blocks          │  │
│  │ (Metric + %)       │ (Metric + %)            │  │
│  └────────────────────┴─────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  Timeline (Row 4)                                   │
│  ┌─────────────────────────────────────────────┐   │
│  │ Test Execution Timeline (Area Chart)        │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Useful Filters

Add these as dashboard-level filters:

### 1. Time Range Filter
```
Field: startTime
Type: Time range picker
Default: Last 30 days
```

### 2. Organization Filter
```
Field: executionContext.organization
Type: Multi-select dropdown
```

### 3. Environment Filter
```
Field: executionContext.environment
Type: Multi-select dropdown
```

### 4. Protection Status Filter
```
Field: outcome.protected
Type: Toggle (Protected / Unprotected / All)
```

### 5. Severity Filter
```
Field: testMetadata.severity
Type: Multi-select buttons
Options: Critical, High, Medium, Low, Informational
```

### 6. Category Filter
```
Field: testMetadata.category
Type: Multi-select dropdown
```

## Advanced Queries

### 1. Gap Analysis - Unprotected Techniques

Find which techniques are consistently bypassing protection:

```json
POST f0rtika-*/_search
{
  "size": 0,
  "query": {
    "term": {
      "outcome.protected": false
    }
  },
  "aggs": {
    "unprotected_techniques": {
      "terms": {
        "field": "testMetadata.techniques",
        "size": 20,
        "order": {
          "_count": "desc"
        }
      },
      "aggs": {
        "test_names": {
          "terms": {
            "field": "testName.keyword",
            "size": 5
          }
        },
        "environments": {
          "terms": {
            "field": "executionContext.environment"
          }
        }
      }
    }
  }
}
```

### 2. Trend Analysis - Protection Rate Improvement

Compare protection rates week-over-week:

```json
POST f0rtika-*/_search
{
  "size": 0,
  "aggs": {
    "weekly_comparison": {
      "date_histogram": {
        "field": "startTime",
        "calendar_interval": "week"
      },
      "aggs": {
        "protection_rate": {
          "avg": {
            "script": {
              "source": "doc['outcome.protected'].value ? 1 : 0"
            }
          }
        },
        "protection_rate_change": {
          "derivative": {
            "buckets_path": "protection_rate"
          }
        }
      }
    }
  }
}
```

### 3. Performance Analysis - Slowest Tests

Identify tests taking longest to execute:

```json
POST f0rtika-*/_search
{
  "size": 20,
  "sort": [
    {
      "durationMs": {
        "order": "desc"
      }
    }
  ],
  "_source": [
    "testName",
    "testId",
    "durationMs",
    "metrics.totalPhases",
    "executionContext.organization"
  ],
  "query": {
    "range": {
      "startTime": {
        "gte": "now-7d/d"
      }
    }
  }
}
```

### 4. Correlation Analysis - EDR Product Effectiveness

Compare protection rates across different EDR products:

```json
POST f0rtika-*/_search
{
  "size": 0,
  "aggs": {
    "by_edr": {
      "terms": {
        "field": "systemInfo.edrProduct"
      },
      "aggs": {
        "protection_rate": {
          "avg": {
            "script": {
              "source": "doc['outcome.protected'].value ? 1 : 0"
            }
          }
        },
        "by_technique": {
          "terms": {
            "field": "testMetadata.techniques",
            "size": 10
          },
          "aggs": {
            "detection_rate": {
              "avg": {
                "script": {
                  "source": "doc['outcome.protected'].value ? 1 : 0"
                }
              }
            }
          }
        }
      }
    }
  }
}
```

## Dashboard Refresh Settings

Recommended refresh settings:

- **Executive Dashboard**: Auto-refresh every 5 minutes
- **Security Operations**: Auto-refresh every 1 minute
- **Historical Analysis**: Manual refresh only

## Alerts and Watches

### Protection Rate Drop Alert

Create a watch to alert when protection rate drops below threshold:

```json
PUT _watcher/watch/f0rtika-protection-rate-drop
{
  "trigger": {
    "schedule": {
      "interval": "1h"
    }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["f0rtika-*"],
        "body": {
          "size": 0,
          "query": {
            "range": {
              "startTime": {
                "gte": "now-1h"
              }
            }
          },
          "aggs": {
            "protection_rate": {
              "avg": {
                "script": {
                  "source": "doc['outcome.protected'].value ? 1 : 0"
                }
              }
            }
          }
        }
      }
    }
  },
  "condition": {
    "script": {
      "source": "ctx.payload.aggregations.protection_rate.value < 0.80"
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "security-team@example.com",
        "subject": "F0RT1KA Protection Rate Alert",
        "body": "Protection rate has dropped to {{ctx.payload.aggregations.protection_rate.value}}%"
      }
    }
  }
}
```

## Tips and Best Practices

1. **Use Index Lifecycle Management**: Configure ILM for automatic data retention
2. **Create Index Patterns Wisely**: Use time-based patterns for better performance
3. **Leverage Pre-computed Metrics**: Use `metrics.*` fields instead of aggregating arrays
4. **Set Appropriate Refresh Intervals**: Balance freshness vs. system load
5. **Use Filters Liberally**: Add time range and organization filters to all dashboards
6. **Create Role-Based Dashboards**: Different dashboards for executives vs. SOC analysts
7. **Monitor Dashboard Performance**: Use Kibana's metrics to identify slow queries
8. **Export and Version Control**: Export dashboard configurations for backup

## Next Steps

1. Import index template and ILM policy
2. Create index pattern in Kibana
3. Build visualizations from examples above
4. Combine into dashboards
5. Set up alerts for critical metrics
6. Share dashboards with team
7. Iterate based on feedback
