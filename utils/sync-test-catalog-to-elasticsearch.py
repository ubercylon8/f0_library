#!/usr/bin/env python3
"""
F0RT1KA Test Catalog Sync Utility

Synchronizes test metadata from tests_source/{cyber-hygiene,intel-driven,mitre-top10,phase-aligned}/
to Elasticsearch for use with the f0rtika-results-enrichment ingest pipeline.

Usage:
    python3 utils/sync-test-catalog-to-elasticsearch.py [--dry-run]

Prerequisites:
    - Elasticsearch credentials in environment variables:
      - ELASTIC_CLOUD_ID or ELASTIC_HOST
      - ELASTIC_API_KEY
    - Or use --dry-run to preview without connecting

Examples:
    # Preview what would be synced
    python3 utils/sync-test-catalog-to-elasticsearch.py --dry-run

    # Sync to Elasticsearch
    ELASTIC_CLOUD_ID=xxx ELASTIC_API_KEY=yyy python3 utils/sync-test-catalog-to-elasticsearch.py
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

# Elasticsearch client (optional import)
try:
    from elasticsearch import Elasticsearch
    HAS_ELASTICSEARCH = True
except ImportError:
    HAS_ELASTICSEARCH = False


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
        "source_url": None,
    }

    def __init__(self, tests_source_dir: Path):
        self.tests_source_dir = tests_source_dir
        self.uuid_pattern = re.compile(
            r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
        )

    def scan_test_directories(self) -> List[Tuple[str, str]]:
        """Find all valid test UUID directories in all categories."""
        if not self.tests_source_dir.exists():
            return []

        tests = []
        for category in self.CATEGORIES:
            category_dir = self.tests_source_dir / category
            if category_dir.exists():
                for item in category_dir.iterdir():
                    if item.is_dir() and self.uuid_pattern.match(item.name):
                        tests.append((category, item.name))

        return sorted(tests, key=lambda x: (x[0], x[1]))

    def _parse_comma_separated(self, value: str) -> List[str]:
        """Parse a comma-separated string into a list of trimmed values."""
        if not value:
            return []
        return [v.strip() for v in value.split(',') if v.strip()]

    def extract_from_go_file(self, category: str, test_uuid: str) -> Dict[str, Any]:
        """Extract all metadata fields from Go file header comment."""
        test_dir = self.tests_source_dir / category / test_uuid
        go_file = test_dir / f"{test_uuid}.go"

        # Start with defaults and auto-derived category
        result = {
            "test_uuid": test_uuid,
            "category": category,  # Auto-derived from directory
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

            # Extract TECHNIQUES from comment block (handle both singular and plural)
            tech_match = re.search(r'^TECHNIQUES?:\s*(.+)$', content, re.MULTILINE)
            if tech_match:
                result["techniques"] = self._parse_comma_separated(tech_match.group(1))

            # Extract TACTICS (new field)
            tactics_match = re.search(r'^TACTICS?:\s*(.+)$', content, re.MULTILINE)
            if tactics_match:
                result["tactics"] = self._parse_comma_separated(tactics_match.group(1))

            # Extract SEVERITY (new field)
            severity_match = re.search(r'^SEVERITY:\s*(\w+)$', content, re.MULTILINE)
            if severity_match:
                severity = severity_match.group(1).strip().lower()
                if severity in ["critical", "high", "medium", "low", "informational"]:
                    result["severity"] = severity

            # Extract TARGET (new field - can be comma-separated)
            target_match = re.search(r'^TARGET:\s*(.+)$', content, re.MULTILINE)
            if target_match:
                result["target"] = self._parse_comma_separated(target_match.group(1))

            # Extract COMPLEXITY (new field)
            complexity_match = re.search(r'^COMPLEXITY:\s*(\w+)$', content, re.MULTILINE)
            if complexity_match:
                complexity = complexity_match.group(1).strip().lower()
                if complexity in ["low", "medium", "high"]:
                    result["complexity"] = complexity

            # Extract THREAT_ACTOR (new field - can be comma-separated for multiple groups)
            threat_actor_match = re.search(r'^THREAT_ACTOR:\s*(.+)$', content, re.MULTILINE)
            if threat_actor_match:
                value = threat_actor_match.group(1).strip()
                # Handle "N/A" or empty as None
                if value.lower() not in ["n/a", "none", ""]:
                    result["threat_actor"] = value

            # Extract SUBCATEGORY (new field)
            subcategory_match = re.search(r'^SUBCATEGORY:\s*(.+)$', content, re.MULTILINE)
            if subcategory_match:
                result["subcategory"] = subcategory_match.group(1).strip().lower()

            # Extract TAGS (new field - comma-separated keywords)
            tags_match = re.search(r'^TAGS:\s*(.+)$', content, re.MULTILINE)
            if tags_match:
                result["tags"] = self._parse_comma_separated(tags_match.group(1))

            # Extract AUTHOR (new field)
            author_match = re.search(r'^AUTHOR:\s*(.+)$', content, re.MULTILINE)
            if author_match:
                result["author"] = author_match.group(1).strip()

            # Extract CREATED date
            created_match = re.search(r'^CREATED:\s*(\d{4}-\d{2}-\d{2})$', content, re.MULTILINE)
            if created_match:
                result["created"] = created_match.group(1)

            # Extract SOURCE_URL (optional - primary threat intel source)
            source_url_match = re.search(r'^SOURCE_URL:\s*(.+)$', content, re.MULTILINE)
            if source_url_match:
                value = source_url_match.group(1).strip()
                if value.lower() not in ["n/a", "none", ""]:
                    result["source_url"] = value

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
                content = f.read(5000)  # Read enough for the score line

            # Pattern: **Test Score**: **X.X/10**
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

    def extract_metadata(self, category: str, test_uuid: str) -> Dict[str, Any]:
        """Extract all metadata for a test."""
        # Start with Go file extraction
        metadata = self.extract_from_go_file(category, test_uuid)

        # Add score from README
        score = self.extract_score_from_readme(category, test_uuid)
        if score is not None:
            metadata["score"] = score

        # Clean up None values for cleaner output (keep empty lists)
        cleaned = {}
        for key, value in metadata.items():
            if value is None and key not in ["test_name", "threat_actor", "subcategory", "author", "created", "source_url"]:
                continue
            cleaned[key] = value

        return cleaned


class ElasticsearchSync:
    """Syncs test metadata to Elasticsearch."""

    INDEX_NAME = "f0rtika-test-catalog"

    def __init__(self, cloud_id: Optional[str] = None, host: Optional[str] = None,
                 api_key: Optional[str] = None):
        if not HAS_ELASTICSEARCH:
            raise ImportError(
                "elasticsearch package not installed. "
                "Install with: pip install elasticsearch"
            )

        if cloud_id:
            self.es = Elasticsearch(
                cloud_id=cloud_id,
                api_key=api_key
            )
        elif host:
            self.es = Elasticsearch(
                hosts=[host],
                api_key=api_key
            )
        else:
            raise ValueError("Either cloud_id or host must be provided")

        # Test connection
        if not self.es.ping():
            raise ConnectionError("Could not connect to Elasticsearch")

    def ensure_index_exists(self, mapping_file: Optional[Path] = None):
        """Create the index if it doesn't exist."""
        if self.es.indices.exists(index=self.INDEX_NAME):
            print(f"Index '{self.INDEX_NAME}' already exists")
            return

        # Load mapping from file or use default
        if mapping_file and mapping_file.exists():
            with open(mapping_file, 'r') as f:
                mapping = json.load(f)
        else:
            # Default mapping with all new fields
            mapping = {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                },
                "mappings": {
                    "properties": {
                        "test_uuid": {"type": "keyword", "doc_values": True},
                        "category": {"type": "keyword"},
                        "subcategory": {"type": "keyword"},
                        "test_name": {"type": "keyword"},
                        "techniques": {"type": "keyword"},
                        "tactics": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "target": {"type": "keyword"},
                        "complexity": {"type": "keyword"},
                        "threat_actor": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "score": {"type": "float"},
                        "created": {"type": "date", "format": "yyyy-MM-dd"},
                        "author": {"type": "keyword"},
                        "source_url": {"type": "keyword"}
                    }
                }
            }

        self.es.indices.create(index=self.INDEX_NAME, body=mapping)
        print(f"Created index '{self.INDEX_NAME}'")

    def sync_document(self, metadata: Dict[str, Any]) -> bool:
        """Upsert a single test metadata document."""
        test_uuid = metadata.get("test_uuid")
        if not test_uuid:
            return False

        # Only sync if we have a test name
        if not metadata.get("test_name"):
            print(f"  Skipping {test_uuid}: No test name found")
            return False

        self.es.index(
            index=self.INDEX_NAME,
            id=test_uuid,
            document=metadata
        )
        return True

    def sync_all(self, documents: List[Dict[str, Any]]) -> int:
        """Sync all documents and return count of successful syncs."""
        synced = 0
        for doc in documents:
            if self.sync_document(doc):
                synced += 1
        return synced

    def refresh_index(self):
        """Refresh the index to make documents searchable."""
        self.es.indices.refresh(index=self.INDEX_NAME)


def main():
    parser = argparse.ArgumentParser(
        description="Sync F0RT1KA test metadata to Elasticsearch"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be synced without connecting to Elasticsearch"
    )
    parser.add_argument(
        "--tests-dir",
        type=Path,
        default=Path("tests_source"),
        help="Path to tests_source directory"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show all extracted fields in preview"
    )
    args = parser.parse_args()

    # Change to repo root if running from utils/
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    if args.tests_dir == Path("tests_source"):
        args.tests_dir = repo_root / "tests_source"

    print("F0RT1KA Test Catalog Sync")
    print("=" * 60)
    print()

    # Extract metadata from all tests
    categories_str = "{" + ",".join(TestMetadataExtractor.CATEGORIES) + "}"
    print(f"Scanning {args.tests_dir}/{categories_str}/...")
    extractor = TestMetadataExtractor(args.tests_dir)
    tests = extractor.scan_test_directories()

    # Count by category
    category_counts = {}
    for category in TestMetadataExtractor.CATEGORIES:
        count = len([t for t in tests if t[0] == category])
        if count > 0:
            category_counts[category] = count

    print(f"Found {len(tests)} test directories")
    for cat, count in sorted(category_counts.items()):
        print(f"  {cat}: {count}")
    print()

    # Extract metadata for each test
    all_metadata = []
    print("Extracting metadata...")
    for category, test_uuid in tests:
        metadata = extractor.extract_metadata(category, test_uuid)
        all_metadata.append(metadata)

        # Print preview
        name = metadata.get("test_name", "Unknown")
        score = metadata.get("score", "N/A")
        cat_short = category[:10]
        severity = metadata.get("severity", "-")[:4]
        threat_actor = metadata.get("threat_actor", "-")
        if threat_actor and len(threat_actor) > 12:
            threat_actor = threat_actor[:12] + ".."

        if metadata.get("test_name"):
            if args.verbose:
                print(f"  [{cat_short}] {test_uuid[:8]}...")
                print(f"    Name: {name}")
                print(f"    Techniques: {metadata.get('techniques', [])}")
                print(f"    Tactics: {metadata.get('tactics', [])}")
                print(f"    Severity: {metadata.get('severity', 'N/A')}")
                print(f"    Target: {metadata.get('target', [])}")
                print(f"    Complexity: {metadata.get('complexity', 'N/A')}")
                print(f"    Threat Actor: {metadata.get('threat_actor', 'N/A')}")
                print(f"    Tags: {metadata.get('tags', [])}")
                print(f"    Source URL: {metadata.get('source_url', 'N/A')}")
                print(f"    Score: {score}")
                print()
            else:
                print(f"  [{cat_short:<10}] {test_uuid[:8]}... | {name[:25]:<25} | {severity:<4} | {threat_actor or '-':<14} | {score}")
        else:
            print(f"  [{cat_short:<10}] {test_uuid[:8]}... | (No metadata found)")

    print()

    # Filter to only valid entries
    valid_metadata = [m for m in all_metadata if m.get("test_name")]
    print(f"Valid entries: {len(valid_metadata)} of {len(all_metadata)}")

    # Count new vs legacy format
    new_format_count = sum(1 for m in valid_metadata if m.get("tactics") or m.get("severity") != "medium")
    print(f"  New format (with enhanced metadata): {new_format_count}")
    print(f"  Legacy format (minimal): {len(valid_metadata) - new_format_count}")

    if args.dry_run:
        print()
        print("DRY RUN - No changes made to Elasticsearch")
        print()
        print("Sample document (first valid entry):")
        if valid_metadata:
            print(json.dumps(valid_metadata[0], indent=2))
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

    # Sync to Elasticsearch
    print()
    print("Connecting to Elasticsearch...")
    try:
        sync = ElasticsearchSync(cloud_id=cloud_id, host=host, api_key=api_key)
        print("Connected!")

        # Ensure index exists
        mapping_file = repo_root / "limacharlie-iac" / "elasticsearch" / "catalog-index-mapping.json"
        sync.ensure_index_exists(mapping_file)

        # Sync documents
        print()
        print("Syncing documents...")
        synced = sync.sync_all(valid_metadata)

        # Refresh index
        sync.refresh_index()

        print()
        print(f"Successfully synced {synced} documents to '{sync.INDEX_NAME}'")

    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print()
    print("Done! Next steps:")
    print("  1. Execute enrich policy: POST /_enrich/policy/f0rtika-test-enrichment/_execute")
    print("  2. Verify enrichment works by running a test")


if __name__ == "__main__":
    main()
