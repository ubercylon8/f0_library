#!/usr/bin/env python3
"""
F0RT1KA Synthetic Test Data Generator

Generates synthetic enriched RECEIPT events for Elasticsearch visualization experimentation.
Mimics the structure of real LimaCharlie RECEIPT events after enrichment pipeline processing.

Usage:
    python3 generate-synthetic-test-data.py              # Generate and push 1000 events
    python3 generate-synthetic-test-data.py --dry-run    # Preview without pushing
    python3 generate-synthetic-test-data.py --count 500  # Custom event count

Environment Variables:
    ELASTIC_CLOUD_ID or ELASTIC_HOST - Elasticsearch connection
    ELASTIC_API_KEY - API key for authentication
"""

import argparse
import json
import os
import random
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any

try:
    from elasticsearch import Elasticsearch, helpers
except ImportError:
    print("Error: elasticsearch package not installed. Run: pip install elasticsearch")
    sys.exit(1)


# =============================================================================
# TEST DEFINITIONS (10 tests with ATT&CK mappings)
# =============================================================================

TESTS = [
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567001",
        "name": "Process Injection via CreateRemoteThread",
        "techniques": ["T1055.001"],
        "score": 8.5,
    },
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567002",
        "name": "Credential Dumping LSASS",
        "techniques": ["T1003.001"],
        "score": 9.0,
    },
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567003",
        "name": "Ransomware File Encryption",
        "techniques": ["T1486", "T1083"],
        "score": 8.8,
    },
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567004",
        "name": "UAC Bypass via fodhelper",
        "techniques": ["T1548.002"],
        "score": 7.5,
    },
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567005",
        "name": "Scheduled Task Persistence",
        "techniques": ["T1053.005"],
        "score": 7.2,
    },
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567006",
        "name": "Windows Defender Tampering",
        "techniques": ["T1562.001"],
        "score": 9.2,
    },
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567007",
        "name": "Reflective DLL Injection",
        "techniques": ["T1055.002"],
        "score": 8.7,
    },
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567008",
        "name": "Pass-the-Hash Attack",
        "techniques": ["T1550.002"],
        "score": 8.3,
    },
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567009",
        "name": "WMI Remote Execution",
        "techniques": ["T1047"],
        "score": 7.8,
    },
    {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567010",
        "name": "Browser Credential Theft",
        "techniques": ["T1555.003"],
        "score": 8.0,
    },
]


# =============================================================================
# ORGANIZATION DEFINITIONS (4 organizations)
# =============================================================================

ORGANIZATIONS = [
    {
        "uuid": "09b59276-9efb-4d3d-bbdd-4b4663ef0c42",
        "short": "sb",
        "name": "Superintendency of Banks",
        "endpoint_prefix": "srv-sb",
        "endpoint_count": 10,
    },
    {
        "uuid": "b2f8dccb-6d23-492e-aa87-a0a8a6103189",
        "short": "tpsgl",
        "name": "Transact Pay",
        "endpoint_prefix": "wks-tpsgl",
        "endpoint_count": 8,
    },
    {
        "uuid": "9634119d-fa6b-42b8-9b9b-90ad8f22e482",
        "short": "rga",
        "name": "RG Associates",
        "endpoint_prefix": "endpoint-rga",
        "endpoint_count": 7,
    },
    {
        "uuid": "f1a2b3c4-d5e6-f7a8-b9c0-d1e2f3a4b5c6",
        "short": "demo",
        "name": "Demo Organization",
        "endpoint_prefix": "lab-demo",
        "endpoint_count": 5,
    },
]


# =============================================================================
# ERROR CODE MAPPINGS
# =============================================================================

ERROR_CODES = {
    101: {"name": "Unprotected", "is_protected": False},
    105: {"name": "FileQuarantinedOnExtraction", "is_protected": True},
    126: {"name": "ExecutionPrevented", "is_protected": True},
    127: {"name": "QuarantinedOnExecution", "is_protected": True},
}

# Weight distribution for protection outcomes (~70% protected)
OUTCOME_WEIGHTS = [
    (101, 30),  # Unprotected - 30%
    (105, 15),  # FileQuarantinedOnExtraction - 15%
    (126, 45),  # ExecutionPrevented - 45%
    (127, 10),  # QuarantinedOnExecution - 10%
]


# =============================================================================
# INDEX CONFIGURATION
# =============================================================================

INDEX_NAME = "f0rtika-synthetic"

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "event.FILE_PATH": {"type": "keyword"},
            "event.ERROR": {"type": "integer"},
            "event.STDOUT": {"type": "text"},
            "routing.oid": {"type": "keyword"},
            "routing.hostname": {"type": "keyword"},
            "routing.event_type": {"type": "keyword"},
            "routing.event_time": {"type": "date"},
            "routing.sid": {"type": "keyword"},
            "routing.tags": {"type": "keyword"},
            "f0rtika.test_uuid": {"type": "keyword"},
            "f0rtika.test_name": {"type": "keyword"},
            "f0rtika.techniques": {"type": "keyword"},
            "f0rtika.score": {"type": "float"},
            "f0rtika.error_name": {"type": "keyword"},
            "f0rtika.is_protected": {"type": "boolean"},
        }
    }
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def build_endpoints() -> list[dict]:
    """Build list of all endpoints across all organizations."""
    endpoints = []
    for org in ORGANIZATIONS:
        for i in range(1, org["endpoint_count"] + 1):
            hostname = f"{org['endpoint_prefix']}-{i:02d}"
            sensor_id = str(uuid.uuid4())
            endpoints.append({
                "hostname": hostname,
                "org_uuid": org["uuid"],
                "org_short": org["short"],
                "sensor_id": sensor_id,
            })
    return endpoints


def weighted_choice(choices: list[tuple[Any, int]]) -> Any:
    """Make a weighted random choice."""
    total = sum(weight for _, weight in choices)
    r = random.uniform(0, total)
    cumulative = 0
    for choice, weight in choices:
        cumulative += weight
        if r <= cumulative:
            return choice
    return choices[-1][0]


def generate_timestamp(days_back: int = 30) -> str:
    """Generate a random timestamp within the last N days."""
    from datetime import timezone
    now = datetime.now(timezone.utc)
    seconds_back = random.randint(0, days_back * 24 * 60 * 60)
    timestamp = now - timedelta(seconds=seconds_back)
    return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_stdout(test: dict, error_code: int) -> str:
    """Generate synthetic STDOUT content."""
    error_info = ERROR_CODES[error_code]
    status = "PROTECTED" if error_info["is_protected"] else "UNPROTECTED"
    return f"""[F0RT1KA] Test: {test['name']}
[F0RT1KA] UUID: {test['uuid']}
[F0RT1KA] Techniques: {', '.join(test['techniques'])}
[F0RT1KA] Result: {status}
[F0RT1KA] Exit Code: {error_code}"""


def generate_event(test: dict, endpoint: dict, days_back: int) -> dict:
    """Generate a single synthetic RECEIPT event."""
    error_code = weighted_choice(OUTCOME_WEIGHTS)
    error_info = ERROR_CODES[error_code]
    timestamp = generate_timestamp(days_back)

    return {
        "event.FILE_PATH": f"c:\\F0\\{test['uuid']}.exe",
        "event.ERROR": error_code,
        "event.STDOUT": generate_stdout(test, error_code),
        "routing.oid": endpoint["org_uuid"],
        "routing.hostname": endpoint["hostname"],
        "routing.event_type": "RECEIPT",
        "routing.event_time": timestamp,
        "routing.sid": endpoint["sensor_id"],
        "routing.tags": ["f0_testing", "synthetic"],
        "f0rtika.test_uuid": test["uuid"],
        "f0rtika.test_name": test["name"],
        "f0rtika.techniques": test["techniques"],
        "f0rtika.score": test["score"],
        "f0rtika.error_name": error_info["name"],
        "f0rtika.is_protected": error_info["is_protected"],
    }


def generate_events(count: int, days_back: int = 30) -> list[dict]:
    """Generate synthetic events."""
    endpoints = build_endpoints()
    events = []

    for _ in range(count):
        test = random.choice(TESTS)
        endpoint = random.choice(endpoints)
        event = generate_event(test, endpoint, days_back)
        events.append(event)

    return events


def compute_statistics(events: list[dict]) -> dict:
    """Compute summary statistics for generated events."""
    stats = {
        "total_events": len(events),
        "protected_count": sum(1 for e in events if e["f0rtika.is_protected"]),
        "unprotected_count": sum(1 for e in events if not e["f0rtika.is_protected"]),
        "by_test": {},
        "by_org": {},
        "by_endpoint": {},
        "by_technique": {},
    }

    stats["protection_rate"] = (
        stats["protected_count"] / stats["total_events"] * 100
        if stats["total_events"] > 0
        else 0
    )

    for event in events:
        # By test
        test_name = event["f0rtika.test_name"]
        if test_name not in stats["by_test"]:
            stats["by_test"][test_name] = {"total": 0, "protected": 0}
        stats["by_test"][test_name]["total"] += 1
        if event["f0rtika.is_protected"]:
            stats["by_test"][test_name]["protected"] += 1

        # By org
        org = event["routing.oid"]
        if org not in stats["by_org"]:
            stats["by_org"][org] = {"total": 0, "protected": 0}
        stats["by_org"][org]["total"] += 1
        if event["f0rtika.is_protected"]:
            stats["by_org"][org]["protected"] += 1

        # By endpoint
        hostname = event["routing.hostname"]
        if hostname not in stats["by_endpoint"]:
            stats["by_endpoint"][hostname] = 0
        stats["by_endpoint"][hostname] += 1

        # By technique
        for tech in event["f0rtika.techniques"]:
            if tech not in stats["by_technique"]:
                stats["by_technique"][tech] = {"total": 0, "protected": 0}
            stats["by_technique"][tech]["total"] += 1
            if event["f0rtika.is_protected"]:
                stats["by_technique"][tech]["protected"] += 1

    return stats


def print_statistics(stats: dict) -> None:
    """Print formatted statistics."""
    print("\n" + "=" * 60)
    print("SYNTHETIC DATA GENERATION SUMMARY")
    print("=" * 60)

    print(f"\nTotal Events: {stats['total_events']}")
    print(f"Protected: {stats['protected_count']} ({stats['protection_rate']:.1f}%)")
    print(f"Unprotected: {stats['unprotected_count']}")

    print("\n--- By Organization ---")
    org_map = {o["uuid"]: o["short"] for o in ORGANIZATIONS}
    for org_uuid, data in sorted(stats["by_org"].items()):
        org_name = org_map.get(org_uuid, org_uuid[:8])
        rate = data["protected"] / data["total"] * 100 if data["total"] > 0 else 0
        print(f"  {org_name}: {data['total']} events ({rate:.1f}% protected)")

    print("\n--- By Test ---")
    for test_name, data in sorted(stats["by_test"].items()):
        rate = data["protected"] / data["total"] * 100 if data["total"] > 0 else 0
        print(f"  {test_name[:40]}: {data['total']} events ({rate:.1f}% protected)")

    print("\n--- By Technique ---")
    for tech, data in sorted(stats["by_technique"].items()):
        rate = data["protected"] / data["total"] * 100 if data["total"] > 0 else 0
        print(f"  {tech}: {data['total']} events ({rate:.1f}% protected)")

    print(f"\n--- Unique Endpoints: {len(stats['by_endpoint'])} ---")
    print("=" * 60)


def get_elasticsearch_client() -> Elasticsearch:
    """Create Elasticsearch client from environment variables."""
    cloud_id = os.environ.get("ELASTIC_CLOUD_ID")
    host = os.environ.get("ELASTIC_HOST")
    api_key = os.environ.get("ELASTIC_API_KEY")

    if not api_key:
        print("Error: ELASTIC_API_KEY environment variable not set")
        sys.exit(1)

    if cloud_id:
        return Elasticsearch(cloud_id=cloud_id, api_key=api_key)
    elif host:
        return Elasticsearch(hosts=[host], api_key=api_key)
    else:
        print("Error: ELASTIC_CLOUD_ID or ELASTIC_HOST environment variable not set")
        sys.exit(1)


def create_index_if_not_exists(es: Elasticsearch) -> bool:
    """Create the synthetic index if it doesn't exist."""
    if es.indices.exists(index=INDEX_NAME):
        print(f"Index '{INDEX_NAME}' already exists")
        return False

    print(f"Creating index '{INDEX_NAME}'...")
    es.indices.create(index=INDEX_NAME, body=INDEX_MAPPING)
    print(f"Index '{INDEX_NAME}' created successfully")
    return True


def bulk_ingest(es: Elasticsearch, events: list[dict]) -> dict:
    """Bulk ingest events into Elasticsearch."""
    actions = [
        {
            "_index": INDEX_NAME,
            "_source": event,
        }
        for event in events
    ]

    success, failed = helpers.bulk(es, actions, stats_only=True)
    return {"success": success, "failed": failed}


# =============================================================================
# MAIN
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic F0RT1KA test data for Elasticsearch"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of events to generate (default: 1000)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Days of history to span (default: 30)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate events but don't push to Elasticsearch",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=3,
        help="Number of sample events to display in dry-run (default: 3)",
    )

    args = parser.parse_args()

    print(f"\nGenerating {args.count} synthetic events spanning {args.days} days...")

    # Generate events
    events = generate_events(args.count, args.days)

    # Compute and print statistics
    stats = compute_statistics(events)
    print_statistics(stats)

    if args.dry_run:
        print("\n--- DRY RUN MODE ---")
        print(f"\nSample events ({args.sample}):\n")
        for i, event in enumerate(events[: args.sample]):
            print(f"Event {i + 1}:")
            print(json.dumps(event, indent=2, default=str))
            print()
        print("Dry run complete. No data pushed to Elasticsearch.")
        return

    # Connect and push to Elasticsearch
    print("\nConnecting to Elasticsearch...")
    es = get_elasticsearch_client()

    # Test connection
    info = es.info()
    print(f"Connected to: {info['cluster_name']} (v{info['version']['number']})")

    # Create index if needed
    create_index_if_not_exists(es)

    # Bulk ingest
    print(f"\nIngesting {len(events)} events...")
    result = bulk_ingest(es, events)
    print(f"Ingestion complete: {result['success']} succeeded, {result['failed']} failed")

    # Final summary
    print(f"\n{'=' * 60}")
    print("DATA GENERATION COMPLETE")
    print(f"{'=' * 60}")
    print(f"Index: {INDEX_NAME}")
    print(f"Events: {result['success']}")
    print(f"\nKibana Query Examples:")
    print(f"  - All events: index:{INDEX_NAME}")
    print(f"  - Protected: f0rtika.is_protected:true")
    print(f"  - By technique: f0rtika.techniques:T1055.001")
    print(f"  - By org (sb): routing.oid:09b59276-9efb-4d3d-bbdd-4b4663ef0c42")


if __name__ == "__main__":
    main()
