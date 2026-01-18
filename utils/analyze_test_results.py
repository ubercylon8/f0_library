#!/usr/bin/env python3
"""
F0RT1KA Test Results Analyzer

Analyzes LCQL query results (NDJSON format) for security test execution events.
Provides comprehensive analysis of ERROR codes, STDOUT/STDERR patterns, and protection metrics.

Usage:
    python3 analyze_test_results.py rga_all_tests.json tpsgl_all_tests.json --output-dir ./analysis
    python3 analyze_test_results.py rga_all_tests.json --console-only
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    GRAY = '\033[90m'

# Error code definitions
ERROR_CODES = {
    0: ("NormalExit", "Normal exit - varies by context", "inconclusive"),
    1: ("BinaryNotRecognized", "Binary not recognized or permission denied", "contextual"),
    101: ("Unprotected", "Attack succeeded - endpoint unprotected", "failed"),
    105: ("FileQuarantinedOnExtraction", "File quarantined during extraction", "protected"),
    126: ("ExecutionPrevented", "Execution blocked/prevented by AV/EDR", "protected"),
    200: ("NoOutput", "No output - quick AV block before execution", "inconclusive"),
    259: ("StillActive", "Windows STILL_ACTIVE - process timeout", "inconclusive"),
    999: ("UnexpectedTestError", "Test error - prerequisites not met", "error"),
}

# Organization mapping
ORGANIZATIONS = {
    "b2f8dccb-6d23-492e-aa87-a0a8a6103189": ("tpsgl", "Transact Pay"),
    "9634119d-fa6b-42b8-9b9b-90ad8f22e482": ("rga", "RG Associates"),
    "09b59276-9efb-4d3d-bbdd-4b4663ef0c42": ("sb", "Superintendency of Banks"),
}

# STDOUT pattern definitions
STDOUT_PATTERNS = {
    "stage_completed": re.compile(r"Stage \d+ completed|Phase \d+ completed", re.IGNORECASE),
    "stage_failed": re.compile(r"Stage \d+ failed|Phase \d+ failed", re.IGNORECASE),
    "test_start": re.compile(r"Starting test at:|F0RT1KA TEST:", re.IGNORECASE),
    "test_end": re.compile(r"Ending test at:|Test completed", re.IGNORECASE),
    "technique_exec": re.compile(r"Technique:?\s*T\d+", re.IGNORECASE),
    "quarantined": re.compile(r"was caught|quarantine|blocked", re.IGNORECASE),
    "execution_prevented": re.compile(r"virus or potentially unwanted|Operation did not complete", re.IGNORECASE),
    "unprotected": re.compile(r"was not caught|was not prevented|unprotected", re.IGNORECASE),
}

# STDERR pattern definitions
STDERR_PATTERNS = {
    "binary_quarantined": re.compile(r"not recognized as|not recognized", re.IGNORECASE),
    "access_denied": re.compile(r"Access is denied|permission denied", re.IGNORECASE),
    "file_not_found": re.compile(r"cannot find|file not found|no such file", re.IGNORECASE),
    "virus_detected": re.compile(r"virus|malware|threat", re.IGNORECASE),
}


@dataclass
class TestMetadata:
    """Metadata extracted from test source files."""
    uuid: str
    name: str = "Unknown"
    techniques: List[str] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    severity: str = "unknown"
    category: str = "unknown"
    tags: List[str] = field(default_factory=list)


@dataclass
class EventRecord:
    """Represents a single test execution event."""
    error_code: int
    file_path: str
    hostname: str
    organization_id: str
    timestamp: str
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    @property
    def test_uuid(self) -> str:
        """Extract test UUID from file path."""
        # Pattern: c:\F0\<uuid>.exe or similar
        match = re.search(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
                         self.file_path, re.IGNORECASE)
        return match.group(1).lower() if match else "unknown"

    @property
    def error_name(self) -> str:
        """Get human-readable error name."""
        return ERROR_CODES.get(self.error_code, ("Unknown", "", "unknown"))[0]

    @property
    def protection_status(self) -> str:
        """Determine protection status from error code and context."""
        base_status = ERROR_CODES.get(self.error_code, ("Unknown", "", "unknown"))[2]

        # Contextual analysis for error code 1
        if self.error_code == 1 and self.stderr:
            stderr_lower = self.stderr.lower()
            if "not recognized" in stderr_lower or "access is denied" in stderr_lower:
                return "protected"

        return base_status


class ResultsAnalyzer:
    """Main analyzer class for F0RT1KA test results."""

    def __init__(self, tests_source_path: Optional[str] = None):
        self.events: List[EventRecord] = []
        self.test_metadata: Dict[str, TestMetadata] = {}
        self.tests_source_path = tests_source_path or self._find_tests_source()

        # Pre-load test metadata
        if self.tests_source_path:
            self._load_all_test_metadata()

    def _find_tests_source(self) -> Optional[str]:
        """Auto-detect tests_source directory."""
        candidates = [
            Path(__file__).parent.parent / "tests_source",
            Path.cwd() / "tests_source",
            Path.cwd().parent / "tests_source",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None

    def _load_all_test_metadata(self):
        """Load metadata from all test source files."""
        tests_source = Path(self.tests_source_path)

        # Scan both intel-driven and phase-aligned
        for category_dir in ["intel-driven", "phase-aligned"]:
            category_path = tests_source / category_dir
            if not category_path.exists():
                continue

            for test_dir in category_path.iterdir():
                if test_dir.is_dir() and self._is_uuid(test_dir.name):
                    metadata = self._extract_test_metadata(test_dir, category_dir)
                    if metadata:
                        self.test_metadata[metadata.uuid] = metadata

    def _is_uuid(self, name: str) -> bool:
        """Check if string looks like a UUID."""
        return bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',
                            name, re.IGNORECASE))

    def _extract_test_metadata(self, test_dir: Path, category: str) -> Optional[TestMetadata]:
        """Extract metadata from test source files."""
        uuid = test_dir.name.lower()
        metadata = TestMetadata(uuid=uuid, category=category)

        # Try to find and parse the main Go file
        go_file = test_dir / f"{uuid}.go"
        if go_file.exists():
            self._parse_go_metadata(go_file, metadata)

        # Supplement with README if needed
        readme = test_dir / "README.md"
        if readme.exists() and metadata.name == "Unknown":
            self._parse_readme_metadata(readme, metadata)

        return metadata if metadata.name != "Unknown" else metadata

    def _parse_go_metadata(self, go_file: Path, metadata: TestMetadata):
        """Parse metadata from Go source file header comment."""
        try:
            with open(go_file, 'r', encoding='utf-8') as f:
                content = f.read(2000)  # Read first 2KB for header

            # Look for metadata block in comment /* ... */
            header_match = re.search(r'/\*\s*(.*?)\*/', content, re.DOTALL)
            if not header_match:
                return

            header = header_match.group(1)

            # Extract fields
            patterns = {
                'name': r'NAME:\s*(.+?)(?:\n|$)',
                'technique': r'TECHNIQUE[S]?:\s*(.+?)(?:\n|$)',
                'severity': r'SEVERITY:\s*(\w+)',
                'tactics': r'TACTICS:\s*(.+?)(?:\n|$)',
                'tags': r'TAGS:\s*(.+?)(?:\n|$)',
            }

            for field, pattern in patterns.items():
                match = re.search(pattern, header, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if field == 'name':
                        metadata.name = value
                    elif field == 'technique':
                        metadata.techniques = [t.strip() for t in value.split(',')]
                    elif field == 'severity':
                        metadata.severity = value.lower()
                    elif field == 'tactics':
                        metadata.tactics = [t.strip() for t in value.split(',')]
                    elif field == 'tags':
                        metadata.tags = [t.strip() for t in value.split(',')]
        except Exception:
            pass

    def _parse_readme_metadata(self, readme: Path, metadata: TestMetadata):
        """Parse metadata from README.md."""
        try:
            with open(readme, 'r', encoding='utf-8') as f:
                content = f.read(1000)

            # Get title from first heading
            title_match = re.search(r'^#\s+(.+?)$', content, re.MULTILINE)
            if title_match:
                metadata.name = title_match.group(1).strip()

            # Get technique from MITRE section
            technique_match = re.search(r'T\d{4}(?:\.\d{3})?', content)
            if technique_match and not metadata.techniques:
                metadata.techniques = [technique_match.group(0)]
        except Exception:
            pass

    def load_file(self, file_path: str) -> int:
        """Load events from an NDJSON file. Returns number of events loaded."""
        count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = self._parse_event(data)
                    if event:
                        self.events.append(event)
                        count += 1
                except json.JSONDecodeError:
                    continue
        return count

    def _parse_event(self, data: Dict) -> Optional[EventRecord]:
        """Parse a single JSON record into an EventRecord."""
        try:
            event_data = data.get('event', {})
            routing = data.get('routing', {})

            return EventRecord(
                error_code=event_data.get('ERROR', 0),
                file_path=event_data.get('FILE_PATH', ''),
                hostname=routing.get('hostname', 'unknown'),
                organization_id=routing.get('oid', 'unknown'),
                timestamp=data.get('ts', ''),
                stdout=event_data.get('STDOUT'),
                stderr=event_data.get('STDERR'),
                tags=routing.get('tags', []),
            )
        except Exception:
            return None

    def analyze_by_organization(self) -> Dict[str, Dict]:
        """Analyze events grouped by organization."""
        results = {}

        # Group events by organization
        by_org = defaultdict(list)
        for event in self.events:
            by_org[event.organization_id].append(event)

        for org_id, events in by_org.items():
            org_short, org_name = ORGANIZATIONS.get(org_id, (org_id[:8], "Unknown"))

            # Calculate metrics
            error_counts = Counter(e.error_code for e in events)
            unique_hosts = set(e.hostname for e in events)
            unique_tests = set(e.test_uuid for e in events)

            # Protection rate calculation
            protected = sum(1 for e in events if e.protection_status == "protected")
            failed = sum(1 for e in events if e.protection_status == "failed")
            decisive = protected + failed
            protection_rate = (protected / decisive * 100) if decisive > 0 else 0

            results[org_id] = {
                "short_name": org_short,
                "full_name": org_name,
                "total_events": len(events),
                "unique_hosts": len(unique_hosts),
                "unique_tests": len(unique_tests),
                "host_list": sorted(unique_hosts),
                "test_list": sorted(unique_tests),
                "error_distribution": dict(error_counts),
                "protection_rate": round(protection_rate, 1),
                "protected_count": protected,
                "failed_count": failed,
                "decisive_count": decisive,
            }

        return results

    def analyze_by_test(self) -> Dict[str, Dict]:
        """Analyze events grouped by test UUID."""
        results = {}

        # Group events by test UUID
        by_test = defaultdict(list)
        for event in self.events:
            by_test[event.test_uuid].append(event)

        for test_uuid, events in by_test.items():
            metadata = self.test_metadata.get(test_uuid, TestMetadata(uuid=test_uuid))

            # Calculate metrics per test
            error_counts = Counter(e.error_code for e in events)
            unique_hosts = set(e.hostname for e in events)

            # Protection analysis
            protected = sum(1 for e in events if e.protection_status == "protected")
            failed = sum(1 for e in events if e.protection_status == "failed")
            decisive = protected + failed
            protection_rate = (protected / decisive * 100) if decisive > 0 else 0

            # Organization breakdown
            by_org_for_test = defaultdict(lambda: {"protected": 0, "failed": 0, "total": 0})
            for event in events:
                org_short = ORGANIZATIONS.get(event.organization_id, (event.organization_id[:8],))[0]
                by_org_for_test[org_short]["total"] += 1
                if event.protection_status == "protected":
                    by_org_for_test[org_short]["protected"] += 1
                elif event.protection_status == "failed":
                    by_org_for_test[org_short]["failed"] += 1

            results[test_uuid] = {
                "name": metadata.name,
                "techniques": metadata.techniques,
                "tactics": metadata.tactics,
                "severity": metadata.severity,
                "category": metadata.category,
                "total_events": len(events),
                "unique_hosts": len(unique_hosts),
                "error_distribution": dict(error_counts),
                "protection_rate": round(protection_rate, 1),
                "protected_count": protected,
                "failed_count": failed,
                "decisive_count": decisive,
                "by_organization": dict(by_org_for_test),
            }

        return results

    def analyze_by_host(self) -> Dict[str, Dict]:
        """Analyze events grouped by hostname."""
        results = {}

        # Group events by hostname
        by_host = defaultdict(list)
        for event in self.events:
            by_host[event.hostname].append(event)

        for hostname, events in by_host.items():
            error_counts = Counter(e.error_code for e in events)
            unique_tests = set(e.test_uuid for e in events)
            org_id = events[0].organization_id if events else "unknown"
            tags = list(set(tag for e in events for tag in e.tags))

            # Protection analysis
            protected = sum(1 for e in events if e.protection_status == "protected")
            failed = sum(1 for e in events if e.protection_status == "failed")
            decisive = protected + failed
            protection_rate = (protected / decisive * 100) if decisive > 0 else 0

            results[hostname] = {
                "organization": ORGANIZATIONS.get(org_id, (org_id[:8], "Unknown"))[0],
                "total_events": len(events),
                "unique_tests": len(unique_tests),
                "tags": tags,
                "error_distribution": dict(error_counts),
                "protection_rate": round(protection_rate, 1),
                "protected_count": protected,
                "failed_count": failed,
                "decisive_count": decisive,
            }

        return results

    def analyze_stdout_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in STDOUT content."""
        pattern_counts = defaultdict(int)
        examples = defaultdict(list)

        for event in self.events:
            if not event.stdout:
                continue

            for pattern_name, pattern in STDOUT_PATTERNS.items():
                matches = pattern.findall(event.stdout)
                if matches:
                    pattern_counts[pattern_name] += len(matches)
                    if len(examples[pattern_name]) < 3:
                        examples[pattern_name].append({
                            "test": event.test_uuid,
                            "host": event.hostname,
                            "match": matches[0] if matches else "",
                        })

        return {
            "pattern_counts": dict(pattern_counts),
            "examples": dict(examples),
        }

    def analyze_stderr_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in STDERR content."""
        pattern_counts = defaultdict(int)
        unique_messages = defaultdict(set)

        for event in self.events:
            if not event.stderr:
                continue

            stderr = event.stderr.strip()
            if not stderr:
                continue

            for pattern_name, pattern in STDERR_PATTERNS.items():
                if pattern.search(stderr):
                    pattern_counts[pattern_name] += 1
                    # Store unique messages (limit to 100 chars)
                    unique_messages[pattern_name].add(stderr[:100])

        return {
            "pattern_counts": dict(pattern_counts),
            "unique_messages": {k: list(v)[:5] for k, v in unique_messages.items()},
        }

    def get_summary(self) -> Dict:
        """Get overall summary statistics."""
        total_events = len(self.events)
        unique_tests = len(set(e.test_uuid for e in self.events))
        unique_hosts = len(set(e.hostname for e in self.events))
        unique_orgs = len(set(e.organization_id for e in self.events))

        # Overall protection rate
        protected = sum(1 for e in self.events if e.protection_status == "protected")
        failed = sum(1 for e in self.events if e.protection_status == "failed")
        decisive = protected + failed
        protection_rate = (protected / decisive * 100) if decisive > 0 else 0

        return {
            "total_events": total_events,
            "unique_tests": unique_tests,
            "unique_hosts": unique_hosts,
            "unique_organizations": unique_orgs,
            "overall_protection_rate": round(protection_rate, 1),
            "protected_count": protected,
            "failed_count": failed,
            "decisive_count": decisive,
            "events_with_stdout": sum(1 for e in self.events if e.stdout),
            "events_with_stderr": sum(1 for e in self.events if e.stderr),
        }

    def export_json(self, output_path: str):
        """Export complete analysis to JSON file."""
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
            "summary": self.get_summary(),
            "by_organization": self.analyze_by_organization(),
            "by_test": self.analyze_by_test(),
            "by_host": self.analyze_by_host(),
            "stdout_patterns": self.analyze_stdout_patterns(),
            "stderr_patterns": self.analyze_stderr_patterns(),
            "error_code_reference": {
                str(code): {"name": info[0], "description": info[1], "category": info[2]}
                for code, info in ERROR_CODES.items()
            },
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        return output_path

    def export_markdown(self, output_path: str):
        """Export analysis report to Markdown file."""
        summary = self.get_summary()
        org_analysis = self.analyze_by_organization()
        test_analysis = self.analyze_by_test()
        host_analysis = self.analyze_by_host()

        lines = []
        lines.append("# F0RT1KA Test Results Analysis Report\n")
        lines.append(f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

        # Executive Summary
        lines.append("## Executive Summary\n")
        lines.append(f"- **Total Events**: {summary['total_events']:,}")
        lines.append(f"- **Unique Tests**: {summary['unique_tests']}")
        lines.append(f"- **Unique Hosts**: {summary['unique_hosts']}")
        lines.append(f"- **Overall Protection Rate**: {summary['overall_protection_rate']}%")
        lines.append(f"  - Protected: {summary['protected_count']:,} | Failed: {summary['failed_count']:,} | Decisive: {summary['decisive_count']:,}\n")

        # Organization Analysis
        lines.append("## Results by Organization\n")
        for org_id, data in sorted(org_analysis.items(), key=lambda x: x[1]['short_name']):
            lines.append(f"### {data['full_name']} ({data['short_name'].upper()})\n")
            lines.append(f"- **Total Events**: {data['total_events']:,}")
            lines.append(f"- **Unique Hosts**: {data['unique_hosts']}")
            lines.append(f"- **Unique Tests**: {data['unique_tests']}")
            lines.append(f"- **Protection Rate**: {data['protection_rate']}% ({data['protected_count']}/{data['decisive_count']} decisive)\n")

            lines.append("**Error Distribution:**\n")
            lines.append("| Code | Name | Count | Percentage |")
            lines.append("|------|------|-------|------------|")
            for code, count in sorted(data['error_distribution'].items(), key=lambda x: -x[1]):
                name = ERROR_CODES.get(int(code), ("Unknown",))[0]
                pct = count / data['total_events'] * 100
                lines.append(f"| {code} | {name} | {count} | {pct:.1f}% |")
            lines.append("")

        # Top Failing Tests
        lines.append("## Top Tests by Failure Rate\n")
        lines.append("| Test UUID | Name | Failures | Protection Rate | Techniques |")
        lines.append("|-----------|------|----------|-----------------|------------|")

        sorted_tests = sorted(test_analysis.items(),
                             key=lambda x: -x[1]['failed_count'])[:10]
        for uuid, data in sorted_tests:
            techniques = ", ".join(data['techniques']) if data['techniques'] else "N/A"
            lines.append(f"| {uuid[:8]}... | {data['name'][:30]} | {data['failed_count']} | {data['protection_rate']}% | {techniques} |")
        lines.append("")

        # Host Vulnerability Rankings
        lines.append("## Hosts with Most Failures\n")
        lines.append("| Hostname | Org | Failures | Protection Rate |")
        lines.append("|----------|-----|----------|-----------------|")

        sorted_hosts = sorted(host_analysis.items(),
                             key=lambda x: -x[1]['failed_count'])[:15]
        for hostname, data in sorted_hosts:
            if data['failed_count'] > 0:
                lines.append(f"| {hostname[:40]} | {data['organization'].upper()} | {data['failed_count']} | {data['protection_rate']}% |")
        lines.append("")

        # Error Code Reference
        lines.append("## Error Code Reference\n")
        lines.append("| Code | Name | Description | Category |")
        lines.append("|------|------|-------------|----------|")
        for code, (name, desc, cat) in sorted(ERROR_CODES.items()):
            emoji = "✅" if cat == "protected" else ("❌" if cat == "failed" else "⚪")
            lines.append(f"| {code} | {name} | {desc} | {emoji} {cat} |")
        lines.append("")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

        return output_path

    def print_summary(self, use_colors: bool = True):
        """Print colored console summary."""
        C = Colors if use_colors else type('NoColors', (), {k: '' for k in dir(Colors) if not k.startswith('_')})()

        summary = self.get_summary()
        org_analysis = self.analyze_by_organization()
        test_analysis = self.analyze_by_test()

        # Header
        print(f"\n{C.BOLD}{C.CYAN}{'═' * 70}{C.END}")
        print(f"{C.BOLD}{C.CYAN}{'F0RT1KA Test Results Analysis':^70}{C.END}")
        print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.END}\n")

        # Overall Summary
        print(f"{C.BOLD}📊 Overall Summary{C.END}")
        print(f"   Total Events: {C.BOLD}{summary['total_events']:,}{C.END}")
        print(f"   Unique Tests: {summary['unique_tests']}")
        print(f"   Unique Hosts: {summary['unique_hosts']}")

        prot_color = C.GREEN if summary['overall_protection_rate'] >= 50 else C.RED
        print(f"   Protection Rate: {prot_color}{C.BOLD}{summary['overall_protection_rate']}%{C.END} "
              f"({summary['protected_count']} protected / {summary['decisive_count']} decisive)")
        print()

        # Organization Breakdown
        print(f"{C.BOLD}🏢 Organization Analysis{C.END}\n")

        for org_id, data in sorted(org_analysis.items(), key=lambda x: x[1]['short_name']):
            prot_color = C.GREEN if data['protection_rate'] >= 50 else C.RED
            print(f"   {C.BOLD}{C.BLUE}{data['full_name']} ({data['short_name'].upper()}){C.END}")
            print(f"   ├── Events: {data['total_events']:,}  |  Hosts: {data['unique_hosts']}  |  Tests: {data['unique_tests']}")
            print(f"   └── Protection: {prot_color}{C.BOLD}{data['protection_rate']}%{C.END} "
                  f"({data['protected_count']}/{data['decisive_count']} decisive)")
            print()

            # Error distribution with visual bar
            print(f"       {C.GRAY}Error Distribution:{C.END}")
            for code, count in sorted(data['error_distribution'].items(), key=lambda x: -x[1])[:5]:
                name = ERROR_CODES.get(int(code), ("Unknown",))[0]
                pct = count / data['total_events'] * 100
                bar_len = int(pct / 5)

                # Color based on error type
                cat = ERROR_CODES.get(int(code), ("", "", "unknown"))[2]
                bar_color = C.GREEN if cat == "protected" else (C.RED if cat == "failed" else C.GRAY)

                print(f"       {code:>3} ({name[:20]:<20}): {bar_color}{'█' * bar_len}{C.END} {count:>4} ({pct:>5.1f}%)")
            print()

        # Top Failing Tests
        print(f"{C.BOLD}🎯 Top 5 Tests by Failure Count{C.END}\n")
        sorted_tests = sorted(test_analysis.items(), key=lambda x: -x[1]['failed_count'])[:5]

        for uuid, data in sorted_tests:
            techniques = ", ".join(data['techniques'][:2]) if data['techniques'] else "N/A"
            print(f"   {C.YELLOW}{uuid[:8]}...{C.END} \"{data['name'][:35]}\"")
            print(f"   ├── Failures: {C.RED}{data['failed_count']}{C.END}  |  Protection: {data['protection_rate']}%")
            print(f"   └── Techniques: {techniques}")
            print()

        # Footer
        print(f"{C.GRAY}{'─' * 70}{C.END}")
        print(f"{C.GRAY}Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC{C.END}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze F0RT1KA test execution results from NDJSON files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full analysis with all outputs
  python3 analyze_test_results.py rga.json tpsgl.json --output-dir ./analysis

  # Console output only
  python3 analyze_test_results.py rga.json --console-only

  # Specify tests source for metadata enrichment
  python3 analyze_test_results.py data.json --tests-source /path/to/tests_source
        """
    )

    parser.add_argument('files', nargs='+', help='NDJSON result files to analyze')
    parser.add_argument('--output-dir', '-o', help='Output directory for reports')
    parser.add_argument('--console-only', '-c', action='store_true',
                       help='Only print console summary, no file output')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--tests-source', help='Path to tests_source directory for metadata')
    parser.add_argument('--json-only', action='store_true', help='Only output JSON (skip markdown)')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress console output')

    args = parser.parse_args()

    # Initialize analyzer
    analyzer = ResultsAnalyzer(tests_source_path=args.tests_source)

    # Load all input files
    total_loaded = 0
    for file_path in args.files:
        if not os.path.exists(file_path):
            print(f"Warning: File not found: {file_path}", file=sys.stderr)
            continue

        count = analyzer.load_file(file_path)
        if not args.quiet:
            print(f"Loaded {count:,} events from {file_path}")
        total_loaded += count

    if total_loaded == 0:
        print("Error: No events loaded from input files", file=sys.stderr)
        sys.exit(1)

    # Print console summary (unless quiet)
    if not args.quiet:
        analyzer.print_summary(use_colors=not args.no_color)

    # Generate file outputs (unless console-only)
    if not args.console_only:
        output_dir = args.output_dir or '.'
        os.makedirs(output_dir, exist_ok=True)

        # JSON report
        json_path = os.path.join(output_dir, 'analysis_report.json')
        analyzer.export_json(json_path)
        if not args.quiet:
            print(f"JSON report saved to: {json_path}")

        # Markdown report (unless json-only)
        if not args.json_only:
            md_path = os.path.join(output_dir, 'analysis_report.md')
            analyzer.export_markdown(md_path)
            if not args.quiet:
                print(f"Markdown report saved to: {md_path}")


if __name__ == '__main__':
    main()
