#!/usr/bin/env python3
"""
F0RT1KA Legacy RGA Results Upload Utility

Enriches historical RGA test execution results (RECEIPT events) with test metadata
from the tests_source/ directory and uploads them to Elasticsearch.

Usage:
    python3 utils/upload-legacy-rga-results.py [OPTIONS]

Options:
    --dry-run       Preview enriched documents without uploading
    --input FILE    Input NDJSON file (default: temp_resources/rga_all_tests.json)
    --index NAME    Target index (default: f0rtika-results-rga)
    --batch-size N  Bulk upload batch size (default: 100)
    --verbose       Show detailed output

Environment Variables:
    ELASTIC_CLOUD_ID or ELASTIC_HOST
    ELASTIC_API_KEY

Examples:
    # Preview enriched documents
    python3 utils/upload-legacy-rga-results.py --dry-run

    # Upload to Elasticsearch
    ELASTIC_CLOUD_ID=xxx ELASTIC_API_KEY=yyy python3 utils/upload-legacy-rga-results.py
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

# Elasticsearch client (optional import)
try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
    HAS_ELASTICSEARCH = True
except ImportError:
    HAS_ELASTICSEARCH = False


# Error code to human-readable name mapping
ERROR_CODE_MAP = {
    0: ("Success", False),
    1: ("GenericError", False),
    101: ("Unprotected", False),
    105: ("FileQuarantinedOnExtraction", True),
    126: ("ExecutionPrevented", True),
    127: ("QuarantinedOnExecution", True),
    200: ("TestCompleted", False),
    259: ("Pending", False),
    999: ("UnexpectedTestError", False),
}


class TestMetadataExtractor:
    """Extracts metadata from F0RT1KA test source files."""

    # All supported test categories (auto-derived from directory)
    CATEGORIES = ["cyber-hygiene", "intel-driven", "mitre-top10", "phase-aligned"]

    # Default values for optional fields
    DEFAULTS = {
        "severity": "medium",
        "complexity": "medium",
        "target": [],
        "threat_actor": None,
        "subcategory": None,
        "tags": [],
        "tactics": [],
        "author": None,
        "created": None,
    }

    def __init__(self, tests_source_dir: Path):
        self.tests_source_dir = tests_source_dir
        self.uuid_pattern = re.compile(
            r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
        )
        self._cache: Dict[str, Dict[str, Any]] = {}

    def _parse_comma_separated(self, value: str) -> List[str]:
        """Parse a comma-separated string into a list of trimmed values."""
        if not value:
            return []
        return [v.strip() for v in value.split(',') if v.strip()]

    def _find_test_category(self, test_uuid: str) -> Optional[str]:
        """Find which category a test UUID belongs to."""
        for category in self.CATEGORIES:
            test_dir = self.tests_source_dir / category / test_uuid
            if test_dir.exists():
                return category
        return None

    def extract_from_go_file(self, category: str, test_uuid: str) -> Dict[str, Any]:
        """Extract all metadata fields from Go file header comment."""
        test_dir = self.tests_source_dir / category / test_uuid
        go_file = test_dir / f"{test_uuid}.go"

        # Start with defaults and auto-derived category
        result = {
            "test_uuid": test_uuid,
            "category": category,
            "test_name": None,
            "techniques": [],
            **self.DEFAULTS.copy()
        }

        if not go_file.exists():
            return result

        try:
            with open(go_file, 'r', encoding='utf-8') as f:
                content = f.read(4000)  # Read first 4KB for header

            # Extract NAME from comment block
            name_match = re.search(r'^NAME:\s*(.+)$', content, re.MULTILINE)
            if name_match:
                result["test_name"] = name_match.group(1).strip()

            # Extract TECHNIQUES from comment block
            tech_match = re.search(r'^TECHNIQUES?:\s*(.+)$', content, re.MULTILINE)
            if tech_match:
                result["techniques"] = self._parse_comma_separated(tech_match.group(1))

            # Extract TACTICS
            tactics_match = re.search(r'^TACTICS?:\s*(.+)$', content, re.MULTILINE)
            if tactics_match:
                result["tactics"] = self._parse_comma_separated(tactics_match.group(1))

            # Extract SEVERITY
            severity_match = re.search(r'^SEVERITY:\s*(\w+)$', content, re.MULTILINE)
            if severity_match:
                severity = severity_match.group(1).strip().lower()
                if severity in ["critical", "high", "medium", "low", "informational"]:
                    result["severity"] = severity

            # Extract TARGET
            target_match = re.search(r'^TARGET:\s*(.+)$', content, re.MULTILINE)
            if target_match:
                result["target"] = self._parse_comma_separated(target_match.group(1))

            # Extract COMPLEXITY
            complexity_match = re.search(r'^COMPLEXITY:\s*(\w+)$', content, re.MULTILINE)
            if complexity_match:
                complexity = complexity_match.group(1).strip().lower()
                if complexity in ["low", "medium", "high"]:
                    result["complexity"] = complexity

            # Extract THREAT_ACTOR
            threat_actor_match = re.search(r'^THREAT_ACTOR:\s*(.+)$', content, re.MULTILINE)
            if threat_actor_match:
                value = threat_actor_match.group(1).strip()
                if value.lower() not in ["n/a", "none", ""]:
                    result["threat_actor"] = value

            # Extract SUBCATEGORY
            subcategory_match = re.search(r'^SUBCATEGORY:\s*(.+)$', content, re.MULTILINE)
            if subcategory_match:
                result["subcategory"] = subcategory_match.group(1).strip().lower()

            # Extract TAGS
            tags_match = re.search(r'^TAGS:\s*(.+)$', content, re.MULTILINE)
            if tags_match:
                result["tags"] = self._parse_comma_separated(tags_match.group(1))

            # Extract AUTHOR
            author_match = re.search(r'^AUTHOR:\s*(.+)$', content, re.MULTILINE)
            if author_match:
                result["author"] = author_match.group(1).strip()

            # Extract CREATED date
            created_match = re.search(r'^CREATED:\s*(\d{4}-\d{2}-\d{2})$', content, re.MULTILINE)
            if created_match:
                result["created"] = created_match.group(1)

        except Exception as e:
            print(f"  Warning: Error reading {go_file}: {e}")

        return result

    def extract_score_from_readme(self, category: str, test_uuid: str) -> Optional[float]:
        """Extract test score from README.md."""
        readme_file = self.tests_source_dir / category / test_uuid / "README.md"

        if not readme_file.exists():
            return None

        try:
            with open(readme_file, 'r', encoding='utf-8') as f:
                content = f.read(5000)

            score_match = re.search(
                r'\*\*Test Score\*\*:\s*\*\*(\d+(?:\.\d+)?)/10\*\*',
                content,
                re.IGNORECASE
            )
            if score_match:
                return float(score_match.group(1))

        except Exception as e:
            print(f"  Warning: Error reading {readme_file}: {e}")

        return None

    def get_metadata(self, test_uuid: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a test UUID (with caching)."""
        if test_uuid in self._cache:
            return self._cache[test_uuid]

        # Find category
        category = self._find_test_category(test_uuid)
        if not category:
            self._cache[test_uuid] = None
            return None

        # Extract metadata
        metadata = self.extract_from_go_file(category, test_uuid)

        # Add score from README
        score = self.extract_score_from_readme(category, test_uuid)
        if score is not None:
            metadata["score"] = score

        self._cache[test_uuid] = metadata
        return metadata


def extract_uuid_from_path(file_path: str) -> Optional[str]:
    """Extract test UUID from FILE_PATH like c:\\F0\\<uuid>.exe"""
    uuid_pattern = re.compile(
        r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
        re.IGNORECASE
    )
    match = uuid_pattern.search(file_path)
    if match:
        return match.group(1).lower()
    return None


def get_error_info(error_code: int) -> tuple:
    """Get error name and protection status for an error code."""
    return ERROR_CODE_MAP.get(error_code, (f"Unknown_{error_code}", False))


def parse_timestamp(ts_string: str) -> str:
    """Convert timestamp string to ISO 8601 format."""
    # Input format: "2025-04-23 11:00:23"
    try:
        dt = datetime.strptime(ts_string, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        return ts_string


def enrich_document(doc: Dict[str, Any], extractor: TestMetadataExtractor) -> Dict[str, Any]:
    """Enrich a RECEIPT event document with test metadata."""
    enriched = doc.copy()

    # Extract test UUID from FILE_PATH
    file_path = doc.get("event", {}).get("FILE_PATH", "")
    test_uuid = extract_uuid_from_path(file_path)

    if not test_uuid:
        return enriched

    # Get error code info
    error_code = doc.get("event", {}).get("ERROR", 0)
    error_name, is_protected = get_error_info(error_code)

    # Build f0rtika namespace
    f0rtika = {
        "test_uuid": test_uuid,
        "error_name": error_name,
        "is_protected": is_protected,
    }

    # Get test metadata
    metadata = extractor.get_metadata(test_uuid)
    if metadata:
        if metadata.get("test_name"):
            f0rtika["test_name"] = metadata["test_name"]
        if metadata.get("category"):
            f0rtika["category"] = metadata["category"]
        if metadata.get("subcategory"):
            f0rtika["subcategory"] = metadata["subcategory"]
        if metadata.get("techniques"):
            f0rtika["techniques"] = metadata["techniques"]
        if metadata.get("tactics"):
            f0rtika["tactics"] = metadata["tactics"]
        if metadata.get("severity"):
            f0rtika["severity"] = metadata["severity"]
        if metadata.get("target"):
            f0rtika["target"] = metadata["target"]
        if metadata.get("complexity"):
            f0rtika["complexity"] = metadata["complexity"]
        if metadata.get("threat_actor"):
            f0rtika["threat_actor"] = metadata["threat_actor"]
        if metadata.get("tags"):
            f0rtika["tags"] = metadata["tags"]
        if metadata.get("score") is not None:
            f0rtika["score"] = metadata["score"]

    enriched["f0rtika"] = f0rtika

    # Add ISO 8601 timestamp
    if "ts" in enriched:
        enriched["@timestamp"] = parse_timestamp(enriched["ts"])

    return enriched


def read_ndjson(file_path: Path) -> List[Dict[str, Any]]:
    """Read NDJSON file and return list of parsed documents."""
    documents = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
                documents.append(doc)
            except json.JSONDecodeError as e:
                print(f"  Warning: Invalid JSON on line {line_num}: {e}")
    return documents


def upload_to_elasticsearch(
    es: Any,  # Elasticsearch client
    index_name: str,
    documents: List[Dict[str, Any]],
    batch_size: int = 100,
    verbose: bool = False
) -> int:
    """Upload documents to Elasticsearch using bulk API."""
    total_uploaded = 0
    total_errors = 0

    # Create index if it doesn't exist
    if not es.indices.exists(index=index_name):
        print(f"Creating index '{index_name}'...")
        mapping = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "ts": {"type": "keyword"},
                    "event": {
                        "properties": {
                            "ERROR": {"type": "integer"},
                            "FILE_PATH": {"type": "keyword"}
                        }
                    },
                    "routing": {
                        "properties": {
                            "hostname": {"type": "keyword"},
                            "oid": {"type": "keyword"},
                            "sid": {"type": "keyword"},
                            "ext_ip": {"type": "ip"},
                            "int_ip": {"type": "ip"},
                            "tags": {"type": "keyword"},
                            "event_type": {"type": "keyword"},
                            "event_id": {"type": "keyword"},
                            "investigation_id": {"type": "keyword"}
                        }
                    },
                    "f0rtika": {
                        "properties": {
                            "test_uuid": {"type": "keyword"},
                            "test_name": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "subcategory": {"type": "keyword"},
                            "techniques": {"type": "keyword"},
                            "tactics": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "target": {"type": "keyword"},
                            "complexity": {"type": "keyword"},
                            "threat_actor": {"type": "keyword"},
                            "tags": {"type": "keyword"},
                            "score": {"type": "float"},
                            "error_name": {"type": "keyword"},
                            "is_protected": {"type": "boolean"}
                        }
                    }
                }
            }
        }
        es.indices.create(index=index_name, body=mapping)
        print(f"Created index '{index_name}'")

    # Process in batches
    for i in range(0, len(documents), batch_size):
        batch = documents[i:i + batch_size]
        actions = []

        for doc in batch:
            # Use event_id as document ID if available
            event_id = doc.get("routing", {}).get("event_id")
            action = {
                "_index": index_name,
                "_source": doc
            }
            if event_id:
                action["_id"] = event_id
            actions.append(action)

        try:
            success, errors = bulk(es, actions, raise_on_error=False)
            total_uploaded += success
            if errors:
                total_errors += len(errors)
                if verbose:
                    for error in errors[:3]:
                        print(f"  Error: {error}")
        except Exception as e:
            print(f"  Batch error: {e}")
            total_errors += len(batch)

        # Progress update
        progress = min(i + batch_size, len(documents))
        print(f"  Uploaded {progress}/{len(documents)} documents...", end="\r")

    print()  # Clear progress line
    return total_uploaded


def main():
    parser = argparse.ArgumentParser(
        description="Upload and enrich legacy RGA test results to Elasticsearch"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview enriched documents without uploading"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Input NDJSON file (default: temp_resources/rga_all_tests.json)"
    )
    parser.add_argument(
        "--index",
        type=str,
        default="f0rtika-results-rga",
        help="Target Elasticsearch index (default: f0rtika-results-rga)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Bulk upload batch size (default: 100)"
    )
    parser.add_argument(
        "--tests-dir",
        type=Path,
        default=None,
        help="Path to tests_source directory"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    args = parser.parse_args()

    # Resolve paths relative to repo root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent

    if args.input is None:
        args.input = repo_root / "temp_resources" / "rga_all_tests.json"
    if args.tests_dir is None:
        args.tests_dir = repo_root / "tests_source"

    print("F0RT1KA Legacy RGA Results Upload")
    print("=" * 60)
    print()

    # Check input file exists
    if not args.input.exists():
        print(f"ERROR: Input file not found: {args.input}")
        sys.exit(1)

    # Read input documents
    print(f"Reading input file: {args.input}")
    documents = read_ndjson(args.input)
    print(f"Loaded {len(documents)} RECEIPT events")
    print()

    # Initialize metadata extractor
    print(f"Loading test metadata from: {args.tests_dir}")
    extractor = TestMetadataExtractor(args.tests_dir)

    # Enrich all documents
    print("Enriching documents with test metadata...")
    enriched_docs = []
    test_stats: Dict[str, int] = {}
    protection_stats = {"protected": 0, "unprotected": 0}

    for doc in documents:
        enriched = enrich_document(doc, extractor)
        enriched_docs.append(enriched)

        # Collect statistics
        f0rtika = enriched.get("f0rtika", {})
        test_name = f0rtika.get("test_name", "Unknown")
        test_stats[test_name] = test_stats.get(test_name, 0) + 1

        if f0rtika.get("is_protected"):
            protection_stats["protected"] += 1
        else:
            protection_stats["unprotected"] += 1

    print(f"Enriched {len(enriched_docs)} documents")
    print()

    # Print statistics
    print("Test Distribution:")
    print("-" * 50)
    for test_name, count in sorted(test_stats.items(), key=lambda x: -x[1]):
        print(f"  {test_name[:40]:<40} {count:>5}")
    print()

    print("Protection Status:")
    print("-" * 50)
    total = protection_stats["protected"] + protection_stats["unprotected"]
    pct_protected = (protection_stats["protected"] / total * 100) if total > 0 else 0
    print(f"  Protected:   {protection_stats['protected']:>5} ({pct_protected:.1f}%)")
    print(f"  Unprotected: {protection_stats['unprotected']:>5} ({100 - pct_protected:.1f}%)")
    print()

    # Unique endpoints
    hostnames = set()
    for doc in documents:
        hostname = doc.get("routing", {}).get("hostname")
        if hostname:
            hostnames.add(hostname)
    print(f"Unique endpoints: {len(hostnames)}")
    print()

    if args.dry_run:
        print("DRY RUN - No changes made to Elasticsearch")
        print()
        print("Sample enriched document:")
        if enriched_docs:
            print(json.dumps(enriched_docs[0], indent=2))
        return

    # Check for Elasticsearch credentials
    cloud_id = os.environ.get("ELASTIC_CLOUD_ID")
    host = os.environ.get("ELASTIC_HOST")
    api_key = os.environ.get("ELASTIC_API_KEY")

    if not (cloud_id or host):
        print()
        print("ERROR: No Elasticsearch connection configured")
        print("Set environment variables:")
        print("  ELASTIC_CLOUD_ID=<cloud-id>  (for Elastic Cloud)")
        print("  ELASTIC_HOST=<host>          (for self-hosted)")
        print("  ELASTIC_API_KEY=<api-key>    (required)")
        print()
        print("Or use --dry-run to preview without connecting")
        sys.exit(1)

    if not api_key:
        print("ERROR: ELASTIC_API_KEY environment variable not set")
        sys.exit(1)

    if not HAS_ELASTICSEARCH:
        print("ERROR: elasticsearch package not installed")
        print("Install with: pip install elasticsearch")
        sys.exit(1)

    # Connect to Elasticsearch
    print(f"Connecting to Elasticsearch...")
    try:
        if cloud_id:
            es = Elasticsearch(cloud_id=cloud_id, api_key=api_key)
        else:
            es = Elasticsearch(hosts=[host], api_key=api_key)

        if not es.ping():
            raise ConnectionError("Could not connect to Elasticsearch")
        print("Connected!")
        print()

        # Upload documents
        print(f"Uploading to index '{args.index}'...")
        uploaded = upload_to_elasticsearch(
            es,
            args.index,
            enriched_docs,
            batch_size=args.batch_size,
            verbose=args.verbose
        )

        # Refresh index
        es.indices.refresh(index=args.index)

        print()
        print(f"Successfully uploaded {uploaded} documents to '{args.index}'")

    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print()
    print("Done! Verification queries:")
    print()
    print("# Check document count:")
    print(f"GET /{args.index}/_count")
    print()
    print("# Aggregate by test name:")
    print(f"""GET /{args.index}/_search
{{
  "size": 0,
  "aggs": {{
    "by_test": {{ "terms": {{ "field": "f0rtika.test_name", "size": 20 }} }}
  }}
}}""")
    print()
    print("# Check protection rate:")
    print(f"""GET /{args.index}/_search
{{
  "size": 0,
  "aggs": {{
    "protected": {{ "terms": {{ "field": "f0rtika.is_protected" }} }}
  }}
}}""")


if __name__ == "__main__":
    main()
