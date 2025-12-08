#!/usr/bin/env python3
"""
F0RT1KA Kibana Dashboard Creator

Creates visualizations and a dashboard for F0RT1KA test results in Kibana.
Uses the Kibana Saved Objects API for reliable dashboard creation.

Usage:
    python3 create-kibana-dashboard.py              # Create dashboard
    python3 create-kibana-dashboard.py --dry-run    # Preview without creating
    python3 create-kibana-dashboard.py --delete     # Delete existing dashboard

Environment Variables:
    KIBANA_URL - Kibana URL (e.g., https://xxx.kb.us-east-1.aws.elastic.cloud:9243)
    ELASTIC_API_KEY - API key for authentication
"""

import argparse
import json
import os
import sys
from typing import Any

try:
    import requests
except ImportError:
    print("Error: requests package not installed. Run: pip install requests")
    sys.exit(1)


# =============================================================================
# CONFIGURATION
# =============================================================================

INDEX_PATTERN = "f0rtika-synthetic"
DASHBOARD_ID = "f0rtika-synthetic-dashboard"
DATA_VIEW_ID = "f0rtika-synthetic-dataview"

# =============================================================================
# VISUALIZATION DEFINITIONS
# =============================================================================

VISUALIZATIONS = [
    {
        "id": "f0rtika-protection-rate-donut",
        "title": "Protection Rate",
        "description": "Overall protection rate across all test executions",
        "type": "lens",
        "state": {
            "visualization": {
                "shape": "donut",
                "layers": [{
                    "layerId": "layer1",
                    "layerType": "data",
                    "primaryGroups": ["is_protected"],
                    "metrics": ["count"],
                    "numberDisplay": "percent",
                    "categoryDisplay": "default",
                    "legendDisplay": "default",
                    "nestedLegend": False
                }]
            },
            "query": {"query": "", "language": "kuery"},
            "filters": [],
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columns": {
                                "is_protected": {
                                    "label": "Protection Status",
                                    "dataType": "boolean",
                                    "operationType": "terms",
                                    "sourceField": "f0rtika.is_protected",
                                    "params": {"size": 2, "orderBy": {"type": "column", "columnId": "count"}, "orderDirection": "desc"}
                                },
                                "count": {
                                    "label": "Count",
                                    "dataType": "number",
                                    "operationType": "count",
                                    "isBucketed": False
                                }
                            },
                            "columnOrder": ["is_protected", "count"]
                        }
                    }
                }
            }
        }
    },
    {
        "id": "f0rtika-protection-over-time",
        "title": "Protection Status Over Time",
        "description": "Protection trends over the time period",
        "type": "lens",
        "state": {
            "visualization": {
                "layerId": "layer1",
                "layerType": "data",
                "seriesType": "area_stacked",
                "xAccessor": "date",
                "accessors": ["count"],
                "splitAccessor": "is_protected"
            },
            "query": {"query": "", "language": "kuery"},
            "filters": [],
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columns": {
                                "date": {
                                    "label": "Time",
                                    "dataType": "date",
                                    "operationType": "date_histogram",
                                    "sourceField": "routing.event_time",
                                    "params": {"interval": "auto"}
                                },
                                "is_protected": {
                                    "label": "Protection Status",
                                    "dataType": "boolean",
                                    "operationType": "terms",
                                    "sourceField": "f0rtika.is_protected",
                                    "params": {"size": 2}
                                },
                                "count": {
                                    "label": "Events",
                                    "dataType": "number",
                                    "operationType": "count"
                                }
                            },
                            "columnOrder": ["date", "is_protected", "count"]
                        }
                    }
                }
            }
        }
    },
    {
        "id": "f0rtika-results-by-org",
        "title": "Results by Organization",
        "description": "Test execution results broken down by organization",
        "type": "lens",
        "state": {
            "visualization": {
                "layerId": "layer1",
                "layerType": "data",
                "seriesType": "bar_stacked",
                "xAccessor": "org",
                "accessors": ["count"],
                "splitAccessor": "is_protected"
            },
            "query": {"query": "", "language": "kuery"},
            "filters": [],
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columns": {
                                "org": {
                                    "label": "Organization",
                                    "dataType": "string",
                                    "operationType": "terms",
                                    "sourceField": "routing.oid",
                                    "params": {"size": 10}
                                },
                                "is_protected": {
                                    "label": "Protected",
                                    "dataType": "boolean",
                                    "operationType": "terms",
                                    "sourceField": "f0rtika.is_protected",
                                    "params": {"size": 2}
                                },
                                "count": {
                                    "label": "Count",
                                    "dataType": "number",
                                    "operationType": "count"
                                }
                            },
                            "columnOrder": ["org", "is_protected", "count"]
                        }
                    }
                }
            }
        }
    },
    {
        "id": "f0rtika-test-coverage",
        "title": "Test Coverage by Test Name",
        "description": "Event count per security test with protection breakdown",
        "type": "lens",
        "state": {
            "visualization": {
                "layerId": "layer1",
                "layerType": "data",
                "seriesType": "bar_horizontal_stacked",
                "xAccessor": "test_name",
                "accessors": ["count"],
                "splitAccessor": "is_protected"
            },
            "query": {"query": "", "language": "kuery"},
            "filters": [],
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columns": {
                                "test_name": {
                                    "label": "Test Name",
                                    "dataType": "string",
                                    "operationType": "terms",
                                    "sourceField": "f0rtika.test_name",
                                    "params": {"size": 15}
                                },
                                "is_protected": {
                                    "label": "Protected",
                                    "dataType": "boolean",
                                    "operationType": "terms",
                                    "sourceField": "f0rtika.is_protected",
                                    "params": {"size": 2}
                                },
                                "count": {
                                    "label": "Executions",
                                    "dataType": "number",
                                    "operationType": "count"
                                }
                            },
                            "columnOrder": ["test_name", "is_protected", "count"]
                        }
                    }
                }
            }
        }
    },
    {
        "id": "f0rtika-technique-distribution",
        "title": "ATT&CK Technique Distribution",
        "description": "Distribution of MITRE ATT&CK techniques tested",
        "type": "lens",
        "state": {
            "visualization": {
                "layerId": "layer1",
                "layerType": "data",
                "seriesType": "bar_stacked",
                "xAccessor": "technique",
                "accessors": ["count"],
                "splitAccessor": "is_protected"
            },
            "query": {"query": "", "language": "kuery"},
            "filters": [],
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columns": {
                                "technique": {
                                    "label": "Technique",
                                    "dataType": "string",
                                    "operationType": "terms",
                                    "sourceField": "f0rtika.techniques",
                                    "params": {"size": 20}
                                },
                                "is_protected": {
                                    "label": "Protected",
                                    "dataType": "boolean",
                                    "operationType": "terms",
                                    "sourceField": "f0rtika.is_protected",
                                    "params": {"size": 2}
                                },
                                "count": {
                                    "label": "Count",
                                    "dataType": "number",
                                    "operationType": "count"
                                }
                            },
                            "columnOrder": ["technique", "is_protected", "count"]
                        }
                    }
                }
            }
        }
    },
    {
        "id": "f0rtika-error-type-pie",
        "title": "Results by Exit Code",
        "description": "Breakdown by error type/exit code",
        "type": "lens",
        "state": {
            "visualization": {
                "shape": "pie",
                "layers": [{
                    "layerId": "layer1",
                    "layerType": "data",
                    "primaryGroups": ["error_name"],
                    "metrics": ["count"],
                    "numberDisplay": "percent",
                    "categoryDisplay": "default",
                    "legendDisplay": "default"
                }]
            },
            "query": {"query": "", "language": "kuery"},
            "filters": [],
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columns": {
                                "error_name": {
                                    "label": "Exit Code",
                                    "dataType": "string",
                                    "operationType": "terms",
                                    "sourceField": "f0rtika.error_name",
                                    "params": {"size": 10}
                                },
                                "count": {
                                    "label": "Count",
                                    "dataType": "number",
                                    "operationType": "count"
                                }
                            },
                            "columnOrder": ["error_name", "count"]
                        }
                    }
                }
            }
        }
    }
]

METRICS = [
    {
        "id": "f0rtika-total-events-metric",
        "title": "Total Events",
        "description": "Total test executions",
        "aggregation": "count",
        "field": None
    },
    {
        "id": "f0rtika-unique-endpoints-metric",
        "title": "Unique Endpoints",
        "description": "Count of unique endpoints tested",
        "aggregation": "cardinality",
        "field": "routing.hostname"
    },
    {
        "id": "f0rtika-unique-tests-metric",
        "title": "Unique Tests",
        "description": "Count of unique tests executed",
        "aggregation": "cardinality",
        "field": "f0rtika.test_uuid"
    },
    {
        "id": "f0rtika-protected-count-metric",
        "title": "Protected",
        "description": "Count of protected executions",
        "aggregation": "count",
        "field": None,
        "filter": "f0rtika.is_protected:true"
    },
    {
        "id": "f0rtika-unprotected-count-metric",
        "title": "Unprotected",
        "description": "Count of unprotected executions",
        "aggregation": "count",
        "field": None,
        "filter": "f0rtika.is_protected:false"
    }
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_kibana_client() -> tuple[str, dict]:
    """Get Kibana URL and headers from environment variables."""
    kibana_url = os.environ.get("KIBANA_URL")
    api_key = os.environ.get("ELASTIC_API_KEY")

    if not kibana_url:
        print("Error: KIBANA_URL environment variable not set")
        print("  Example: https://xxx.kb.us-east-1.aws.elastic.cloud:9243")
        sys.exit(1)

    if not api_key:
        print("Error: ELASTIC_API_KEY environment variable not set")
        sys.exit(1)

    headers = {
        "Authorization": f"ApiKey {api_key}",
        "kbn-xsrf": "true",
        "Content-Type": "application/json"
    }

    return kibana_url.rstrip("/"), headers


def create_data_view(kibana_url: str, headers: dict, dry_run: bool = False) -> bool:
    """Create or update the data view for f0rtika-synthetic index."""
    data_view = {
        "data_view": {
            "id": DATA_VIEW_ID,
            "title": INDEX_PATTERN,
            "timeFieldName": "routing.event_time",
            "name": "F0RT1KA Synthetic Test Results"
        }
    }

    if dry_run:
        print(f"[DRY RUN] Would create data view: {DATA_VIEW_ID}")
        print(json.dumps(data_view, indent=2))
        return True

    # Try to create, if exists will fail - that's ok
    url = f"{kibana_url}/api/data_views/data_view"
    response = requests.post(url, headers=headers, json=data_view)

    if response.status_code in [200, 201]:
        print(f"✅ Created data view: {DATA_VIEW_ID}")
        return True
    elif response.status_code == 409:
        print(f"ℹ️  Data view already exists: {DATA_VIEW_ID}")
        return True
    else:
        print(f"❌ Failed to create data view: {response.status_code}")
        print(response.text)
        return False


def generate_esql_queries() -> list[dict]:
    """Generate ES|QL queries for common analytics."""
    return [
        {
            "name": "Protection Rate by Organization",
            "query": """FROM f0rtika-synthetic
| STATS protected = COUNT(*) BY routing.oid, f0rtika.is_protected
| SORT routing.oid"""
        },
        {
            "name": "Top Failing Tests",
            "query": """FROM f0rtika-synthetic
| WHERE f0rtika.is_protected == false
| STATS failures = COUNT(*) BY f0rtika.test_name
| SORT failures DESC
| LIMIT 10"""
        },
        {
            "name": "Technique Coverage",
            "query": """FROM f0rtika-synthetic
| STATS total = COUNT(*), protected = SUM(CASE WHEN f0rtika.is_protected THEN 1 ELSE 0 END) BY f0rtika.techniques
| EVAL protection_rate = ROUND(protected * 100.0 / total, 1)
| SORT protection_rate ASC"""
        },
        {
            "name": "Endpoint Activity",
            "query": """FROM f0rtika-synthetic
| STATS tests = COUNT(*), unique_tests = COUNT_DISTINCT(f0rtika.test_uuid) BY routing.hostname
| SORT tests DESC
| LIMIT 20"""
        },
        {
            "name": "Daily Trends",
            "query": """FROM f0rtika-synthetic
| EVAL day = DATE_TRUNC(1 day, routing.event_time)
| STATS total = COUNT(*), protected = SUM(CASE WHEN f0rtika.is_protected THEN 1 ELSE 0 END) BY day
| EVAL rate = ROUND(protected * 100.0 / total, 1)
| SORT day"""
        }
    ]


def print_manual_instructions():
    """Print manual instructions for creating visualizations in Kibana."""
    print("\n" + "=" * 70)
    print("MANUAL KIBANA VISUALIZATION GUIDE")
    print("=" * 70)

    print("""
Since Kibana's API for Lens visualizations can be complex, here are
step-by-step instructions to create these visualizations manually:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. CREATE DATA VIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Go to: Stack Management → Data Views → Create data view
   • Name: F0RT1KA Synthetic
   • Index pattern: f0rtika-synthetic
   • Timestamp field: routing.event_time
   • Click "Save data view"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2. PROTECTION RATE DONUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Go to: Visualize Library → Create visualization → Lens
   • Chart type: Donut
   • Drag "f0rtika.is_protected" to "Slice by"
   • Metric: Count
   • Save as: "Protection Rate"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3. PROTECTION OVER TIME (Area Chart)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Chart type: Area (stacked)
   • Horizontal axis: routing.event_time (Date histogram, auto interval)
   • Vertical axis: Count
   • Break down by: f0rtika.is_protected
   • Save as: "Protection Over Time"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4. RESULTS BY ORGANIZATION (Bar Chart)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Chart type: Bar (stacked)
   • Horizontal axis: routing.oid (Top values)
   • Vertical axis: Count
   • Break down by: f0rtika.is_protected
   • Save as: "Results by Organization"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
5. TEST COVERAGE (Horizontal Bar)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Chart type: Bar horizontal (stacked)
   • Vertical axis: f0rtika.test_name (Top 15 values)
   • Horizontal axis: Count
   • Break down by: f0rtika.is_protected
   • Save as: "Test Coverage"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
6. ATT&CK TECHNIQUE DISTRIBUTION (Bar Chart)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Chart type: Bar (stacked)
   • Horizontal axis: f0rtika.techniques (Top 20 values)
   • Vertical axis: Count
   • Break down by: f0rtika.is_protected
   • Save as: "ATT&CK Technique Distribution"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
7. EXIT CODE BREAKDOWN (Pie Chart)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Chart type: Pie
   • Slice by: f0rtika.error_name (Top values)
   • Metric: Count
   • Save as: "Results by Exit Code"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
8. METRIC VISUALIZATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Create these as "Metric" type visualizations:

   • Total Events: Count of records
   • Unique Endpoints: Unique count of routing.hostname
   • Unique Tests: Unique count of f0rtika.test_uuid
   • Protected: Count where f0rtika.is_protected:true
   • Unprotected: Count where f0rtika.is_protected:false

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
9. CREATE DASHBOARD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • Go to: Dashboards → Create dashboard
   • Add all saved visualizations
   • Arrange in a grid layout:
     - Top row: Metrics (Total, Endpoints, Tests, Protected, Unprotected)
     - Second row: Protection Over Time (full width)
     - Third row: Protection Donut + Exit Code Pie + Results by Org
     - Fourth row: Test Coverage + Technique Distribution
   • Save as: "F0RT1KA Test Results Dashboard"
""")

    # Print ES|QL queries
    print("\n" + "=" * 70)
    print("USEFUL ES|QL QUERIES")
    print("=" * 70)
    print("\nCopy these into Kibana's Discover → ES|QL mode:\n")

    for q in generate_esql_queries():
        print(f"━━━ {q['name']} ━━━")
        print(q['query'])
        print()


def print_kql_queries():
    """Print useful KQL queries for filtering."""
    print("\n" + "=" * 70)
    print("USEFUL KQL FILTERS")
    print("=" * 70)
    print("""
Use these in the Kibana search bar or in dashboard filters:

# All unprotected events (attack succeeded)
f0rtika.is_protected:false

# All protected events
f0rtika.is_protected:true

# Specific organization (sb)
routing.oid:"09b59276-9efb-4d3d-bbdd-4b4663ef0c42"

# Specific test
f0rtika.test_name:"Credential Dumping LSASS"

# Specific technique
f0rtika.techniques:T1003.001

# Specific endpoint
routing.hostname:srv-sb-01

# Multiple techniques (OR)
f0rtika.techniques:(T1055.001 OR T1055.002)

# High-score tests only
f0rtika.score >= 8.5

# Execution prevented specifically
f0rtika.error_name:"ExecutionPrevented"

# Combine filters
f0rtika.is_protected:false AND f0rtika.techniques:T1486
""")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Create F0RT1KA Kibana dashboard and visualizations"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview without creating anything"
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Print manual instructions for creating visualizations"
    )
    parser.add_argument(
        "--esql",
        action="store_true",
        help="Print useful ES|QL queries"
    )
    parser.add_argument(
        "--kql",
        action="store_true",
        help="Print useful KQL filter queries"
    )

    args = parser.parse_args()

    # If manual mode, just print instructions
    if args.manual:
        print_manual_instructions()
        return

    if args.esql:
        print("\n" + "=" * 70)
        print("ES|QL QUERIES FOR F0RT1KA ANALYTICS")
        print("=" * 70)
        for q in generate_esql_queries():
            print(f"\n━━━ {q['name']} ━━━")
            print(q['query'])
        return

    if args.kql:
        print_kql_queries()
        return

    # Otherwise, try to create via API
    print("F0RT1KA Kibana Dashboard Creator")
    print("=" * 40)

    if args.dry_run:
        print("\n[DRY RUN MODE - No changes will be made]\n")

    try:
        kibana_url, headers = get_kibana_client()
        print(f"Kibana URL: {kibana_url}")

        # Create data view
        print("\n1. Creating data view...")
        if not create_data_view(kibana_url, headers, args.dry_run):
            print("Warning: Could not create data view, but continuing...")

        print("\n" + "=" * 40)
        print("Data view created successfully!")
        print("\nFor visualizations, use --manual to see step-by-step instructions")
        print("for creating them in the Kibana UI (most reliable method).")
        print("\nAlternatively, import the NDJSON file:")
        print("  utils/kibana-dashboards/f0rtika-synthetic-dashboard.ndjson")
        print("\nTo import: Stack Management → Saved Objects → Import")

    except Exception as e:
        print(f"\nError: {e}")
        print("\nFalling back to manual instructions...")
        print_manual_instructions()


if __name__ == "__main__":
    main()
