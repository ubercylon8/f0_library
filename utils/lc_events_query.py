#!/usr/bin/env python3
"""
LimaCharlie Sensor Events Query Script
=====================================

Query LimaCharlie sensor events for F0RT1KA security test results with
detailed analysis and reporting capabilities.

Features:
- Query events by test UUID and date range
- Generate formatted tables with key event data
- Provide statistics on error codes and test outcomes
- Show endpoints tested with event timestamps
- Support multiple output formats (table, JSON, CSV)

Requirements:
- LimaCharlie sensor binary (lc-sensors) in PATH or F0_CST/bin/
- Valid LimaCharlie API key and Organization ID
- Authentication via any of:
  * Command line: -k API_KEY -o ORG_ID
  * Environment variables: LIMACHARLIE_API_KEY, LIMACHARLIE_OID
  * .env file: LC_API_KEY, LC_ORG_ID
  * Optional: python-dotenv package for enhanced .env support

Usage Examples:
    # Query events using .env file credentials
    python lc_events_query.py --uuid "abc123def456" --date-range "last 24 hours"

    # Query with explicit credentials
    python lc_events_query.py --uuid "abc123def456" --date-range "last 24 hours" -k API_KEY -o ORG_ID

    # Show only endpoints tested
    python lc_events_query.py --uuid "abc123def456" --date-range "last 7 days" --hostnames

    # Use custom .env file
    python lc_events_query.py --uuid "abc123def456" --date-range "today" --env-file /path/to/.env

    # Export to JSON for further processing
    python lc_events_query.py --uuid "abc123def456" --date-range "today" --output results.json
"""

import argparse
import json
import os
import sys
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any

# Optional .env file support
try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False


class LCEventsQuery:
    """LimaCharlie Sensor Events Query Client"""

    def __init__(self, lc_sensors_path: Optional[str] = None, api_key: Optional[str] = None, org_id: Optional[str] = None, env_file: Optional[str] = None):
        # Load environment variables from .env file if available
        self._load_env_file(env_file)

        # Try to find lc-sensors binary
        self.lc_sensors_path = self._find_lc_sensors(lc_sensors_path)
        if not self.lc_sensors_path:
            raise ValueError(
                "lc-sensors binary not found. Please ensure it's in PATH or "
                "specify the path with --lc-sensors-path"
            )

        # Get authentication parameters with priority order:
        # 1. Command line arguments
        # 2. Environment variables (including from .env file)
        # 3. .env file specific variables (LC_API_KEY, LC_ORG_ID)
        self.api_key = (
            api_key or
            os.getenv('LIMACHARLIE_API_KEY') or
            os.getenv('LC_API_KEY')
        )
        self.org_id = (
            org_id or
            os.getenv('LIMACHARLIE_OID') or
            os.getenv('LIMACHARLIE_ORG_ID') or
            os.getenv('LC_ORG_ID')
        )

        if not self.api_key or not self.org_id:
            raise ValueError(
                "Missing required authentication. Please provide API key and Organization ID via:\n"
                "  1. Command line arguments: -k API_KEY -o ORG_ID\n"
                "  2. Environment variables: LIMACHARLIE_API_KEY, LIMACHARLIE_OID\n"
                "  3. .env file with: LC_API_KEY, LC_ORG_ID\n"
                "  4. Specify custom .env file: --env-file path/to/.env"
            )

    def _load_env_file(self, env_file: Optional[str] = None):
        """Load environment variables from .env file"""
        if not DOTENV_AVAILABLE:
            return

        # Try specified env file first
        if env_file and os.path.isfile(env_file):
            load_dotenv(env_file)
            return

        # Try common .env file locations
        env_locations = [
            '.env',
            os.path.join(os.getcwd(), '.env'),
            os.path.join(os.path.dirname(__file__), '.env'),
            os.path.join(os.path.dirname(__file__), '..', '.env'),
        ]

        for env_path in env_locations:
            if os.path.isfile(env_path):
                load_dotenv(env_path)
                break

    def _find_lc_sensors(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Find the lc-sensors binary"""
        if custom_path and os.path.isfile(custom_path):
            return custom_path

        # Try common locations
        search_paths = [
            "lc-sensors",  # In PATH
            "/Users/jimx/Documents/F0RT1KA/F0_CST/bin/lc-sensors",  # Correct path with underscore
            "/Users/jimx/Documents/F0RT1KA/F0-CST/bin/lc-sensors",
            "/Users/jimx/Documents/F0RT1KA/F0-CST/LC_utils/bin/lc-sensors",
            "./bin/lc-sensors",
            "../F0_CST/bin/lc-sensors",
        ]

        for path in search_paths:
            try:
                # Test if binary exists and is executable
                result = subprocess.run([path, "--help"],
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0 or "events" in result.stderr:
                    return path
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue

        return None

    def query_events(self,
                    uuid: str,
                    date_range: str,
                    show_progress: bool = True) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Query LimaCharlie sensor events for a specific test UUID

        Args:
            uuid: Test UUID to search for
            date_range: Date range string for LCQL query
            show_progress: Whether to show progress during execution

        Returns:
            Tuple of (events_list, query_info)
        """
        # Build LCQL query
        lcql_query = f"{date_range} | * | RECEIPT | routing/investigation_id contains '{uuid}' and event/ERROR != 1"

        # Execute lc-sensors command with authentication
        cmd = [
            self.lc_sensors_path, "events",
            "-o", self.org_id,
            "-k", self.api_key,
            "--lcql", lcql_query,
            "--output", "json",
            "--no-banner"  # Clean output for parsing
        ]

        if show_progress:
            print(f"Executing: {' '.join(cmd)}")
            print(f"Query: {lcql_query}")
            print("Fetching events...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                raise RuntimeError(f"lc-sensors command failed: {result.stderr}")

            # Parse JSON output
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse JSON output: {e}")

            # Extract events from schema structure
            events = data.get('results', [])
            stats = data.get('stats', {})

            if show_progress:
                print(f"Found {len(events)} events")

            query_info = {
                'uuid': uuid,
                'date_range': date_range,
                'lcql_query': lcql_query,
                'total_events': len(events),
                'query_stats': stats
            }

            return events, query_info

        except subprocess.TimeoutExpired:
            raise RuntimeError("Query timed out after 120 seconds")
        except Exception as e:
            raise RuntimeError(f"Failed to execute query: {e}")

    def extract_event_data(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract key fields from event data based on schema

        Args:
            events: Raw events from LimaCharlie API

        Returns:
            List of processed event dictionaries
        """
        processed_events = []

        for event in events:
            try:
                # Extract data according to schema structure
                data = event.get('data', {})
                event_data = data.get('event', {})
                routing = data.get('routing', {})
                event_ts = data.get('ts', '')

                processed_event = {
                    'error_code': event_data.get('ERROR', 0),
                    'file_path': event_data.get('FILE_PATH', ''),
                    'stdout': event_data.get('STDOUT', ''),
                    'stderr': event_data.get('STDERR', ''),
                    'hostname': routing.get('hostname', 'N/A'),
                    'investigation_id': routing.get('investigation_id', ''),
                    'event_id': routing.get('event_id', ''),
                    'event_type': routing.get('event_type', ''),
                    'event_time': routing.get('event_time', 0),
                    'timestamp': event_ts,
                    'outer_timestamp': event.get('ts', ''),
                    'platform': routing.get('plat', 0),
                    'architecture': routing.get('arch', 0),
                    'tags': routing.get('tags', [])
                }

                processed_events.append(processed_event)

            except Exception as e:
                print(f"Warning: Failed to process event: {e}")
                continue

        return processed_events

    def format_events_table(self, events: List[Dict[str, Any]]) -> str:
        """Format events as a table"""
        if not events:
            return "No events found matching the search criteria."

        output = []
        output.append("F0RT1KA LimaCharlie Security Test Results")
        output.append("=" * 80)
        output.append("")

        # Table headers
        headers = ["Error", "Hostname", "Timestamp", "STDOUT", "STDERR", "File Path"]
        col_widths = [8, 20, 16, 22, 22, 30]

        # Header row
        header_row = "| " + " | ".join(f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers))) + " |"
        output.append(header_row)
        output.append("|" + "|".join("-" * (w + 2) for w in col_widths) + "|")

        # Data rows
        for event in events:
            # Format timestamp
            timestamp = event.get('timestamp', '')
            if timestamp:
                try:
                    # Parse ISO timestamp and format
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamp = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    timestamp = timestamp[:16]  # Fallback to first 16 chars

            # Truncate long fields
            stdout_short = (event.get('stdout', '') or '')[:20]
            stderr_short = (event.get('stderr', '') or '')[:20]
            file_path_short = (event.get('file_path', '') or '')[:28]

            row_data = [
                str(event.get('error_code', 0)),
                event.get('hostname', 'N/A')[:18],
                timestamp,
                stdout_short,
                stderr_short,
                file_path_short
            ]

            # Create row
            row = "| " + " | ".join(f"{row_data[i]:<{col_widths[i]}}" for i in range(len(row_data))) + " |"
            output.append(row)

        return '\n'.join(output)

    def generate_statistics(self, events: List[Dict[str, Any]], query_info: Dict[str, Any], format_type: str = 'table') -> str:
        """Generate summary statistics for events"""
        if not events:
            return "No statistics available."

        total_events = len(events)

        # Error code breakdown
        error_counts = {}
        for event in events:
            error_code = event.get('error_code', 0)
            error_counts[error_code] = error_counts.get(error_code, 0) + 1

        # Hostname analysis
        hostnames = set()
        hostname_events = {}
        for event in events:
            hostname = event.get('hostname', 'N/A')
            hostnames.add(hostname)
            if hostname not in hostname_events:
                hostname_events[hostname] = []
            hostname_events[hostname].append(event.get('timestamp', ''))

        # Time range analysis
        timestamps = []
        for event in events:
            timestamp = event.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamps.append(dt)
                except:
                    pass

        # Build statistics output
        stats = []

        if format_type == 'markdown':
            stats.append("\n---\n")
            stats.append("## Statistics Summary\n")
            stats.append(f"- **Total Events Found:** {total_events}")
            stats.append(f"- **Unique Endpoints Tested:** {len(hostnames)}")
            stats.append(f"- **Test UUID:** {query_info.get('uuid', 'N/A')}")
            stats.append(f"- **Date Range Query:** {query_info.get('date_range', 'N/A')}")

            if timestamps:
                min_time = min(timestamps).strftime('%Y-%m-%d %H:%M:%S')
                max_time = max(timestamps).strftime('%Y-%m-%d %H:%M:%S')
                stats.append(f"- **Time Range:** {min_time} to {max_time}")

            # Query performance stats
            query_stats = query_info.get('query_stats', {})
            if query_stats:
                stats.append("\n### Query Performance")
                if 'wall_time' in query_stats:
                    stats.append(f"- **Wall Time:** {query_stats['wall_time']}ms")
                if 'n_proc' in query_stats:
                    stats.append(f"- **Events Processed:** {query_stats['n_proc']}")
                if 'n_scan' in query_stats:
                    stats.append(f"- **Events Scanned:** {query_stats['n_scan']}")

            # Endpoints tested with timestamps
            if hostname_events:
                stats.append("\n### Endpoints Tested")
                for hostname in sorted(hostname_events.keys()):
                    event_times = []
                    for timestamp in hostname_events[hostname]:
                        if timestamp:
                            try:
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                formatted_time = dt.strftime('%Y-%m-%d %H:%M')
                                if formatted_time not in event_times:
                                    event_times.append(formatted_time)
                            except:
                                pass

                    if event_times:
                        event_times.sort()
                        times_str = ", ".join(event_times)
                        stats.append(f"- **{hostname}** (events: {times_str})")
                    else:
                        stats.append(f"- **{hostname}** (no valid timestamps)")

            stats.append("\n---\n")
            stats.append(f"*Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")
        else:
            # Table format
            stats.append("STATISTICS SUMMARY")
            stats.append("-" * 50)
            stats.append(f"Total Events Found: {total_events}")
            stats.append(f"Unique Endpoints Tested: {len(hostnames)}")
            stats.append(f"Test UUID: {query_info.get('uuid', 'N/A')}")
            stats.append(f"Date Range Query: {query_info.get('date_range', 'N/A')}")

            if timestamps:
                min_time = min(timestamps).strftime('%Y-%m-%d %H:%M:%S')
                max_time = max(timestamps).strftime('%Y-%m-%d %H:%M:%S')
                stats.append(f"Time Range: {min_time} to {max_time}")

            stats.append("")
            stats.append("Error Code Breakdown:")
            for error_code, count in sorted(error_counts.items()):
                percentage = (count / total_events) * 100
                error_meaning = self._get_error_meaning(error_code)
                stats.append(f"  {error_code} ({error_meaning}): {count} events ({percentage:.1f}%)")

            # Query statistics if available
            query_stats = query_info.get('query_stats', {})
            if query_stats:
                stats.append("")
                stats.append("Query Performance:")
                if 'wall_time' in query_stats:
                    stats.append(f"  Wall Time: {query_stats['wall_time']}ms")
                if 'n_proc' in query_stats:
                    stats.append(f"  Events Processed: {query_stats['n_proc']}")
                if 'n_scan' in query_stats:
                    stats.append(f"  Events Scanned: {query_stats['n_scan']}")

        return '\n'.join(stats)

    def format_endpoints_only(self, events: List[Dict[str, Any]]) -> str:
        """Format only the endpoints tested information"""
        if not events:
            return "No events found - no endpoints to display."

        # Hostname analysis with timestamps
        hostname_events = {}
        for event in events:
            hostname = event.get('hostname', 'N/A')
            timestamp = event.get('timestamp', '')

            if hostname not in hostname_events:
                hostname_events[hostname] = []
            hostname_events[hostname].append(timestamp)

        if not hostname_events:
            return "No hostnames found in event data."

        output = []
        output.append(f"Endpoints Tested ({len(hostname_events)} unique endpoints):")
        output.append("-" * 50)

        for hostname in sorted(hostname_events.keys()):
            # Get unique event times for this hostname and format them
            event_times = []
            for timestamp in hostname_events[hostname]:
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        formatted_time = dt.strftime('%Y-%m-%d %H:%M')
                        if formatted_time not in event_times:
                            event_times.append(formatted_time)
                    except:
                        pass

            # Sort times and display
            if event_times:
                event_times.sort()
                times_str = ", ".join(event_times)
                output.append(f"{hostname} (events: {times_str})")
            else:
                output.append(f"{hostname} (no valid timestamps)")

        return '\n'.join(output)

    def _get_error_meaning(self, error_code: int) -> str:
        """Get human-readable meaning of error codes"""
        error_meanings = {
            0: "Success",
            101: "Endpoint.Unprotected",
            105: "Endpoint.FileQuarantinedOnExtraction",
            126: "Endpoint.ExecutionPrevented",
            # Add more error codes as needed
        }
        return error_meanings.get(error_code, "Unknown")

    def format_events(self, events: List[Dict[str, Any]], format_type: str = 'table') -> str:
        """Format events for display"""
        if not events:
            return "No events found matching the search criteria."

        if format_type == 'json':
            return json.dumps(events, indent=2, default=str)

        elif format_type == 'markdown':
            output = []
            output.append("# F0RT1KA LimaCharlie Security Test Results\n")

            # Summary metrics
            output.append("## Summary")
            output.append(f"- **Total Events Found:** {len(events)}")

            # Error code breakdown for summary
            error_counts = {}
            for event in events:
                error_code = event.get('error_code', 0)
                error_counts[error_code] = error_counts.get(error_code, 0) + 1

            output.append("\n### Error Code Breakdown")
            for error_code, count in sorted(error_counts.items()):
                percentage = (count / len(events)) * 100
                error_meaning = self._get_error_meaning(error_code)
                output.append(f"- **{error_code} ({error_meaning}):** {count} events ({percentage:.1f}%)")

            # Endpoint summary
            hostnames = set(event.get('hostname', 'N/A') for event in events)
            output.append(f"\n### Endpoints Tested")
            output.append(f"- **Unique Endpoints:** {len(hostnames)}")

            # Event details table
            output.append("\n---\n")
            output.append("## Event Details\n")
            output.append("| Error Code | Hostname | Timestamp | STDOUT | STDERR | File Path |")
            output.append("|------------|----------|-----------|--------|--------|-----------|")

            for event in events:
                # Format timestamp
                timestamp = event.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = dt.strftime('%Y-%m-%d %H:%M')
                    except:
                        timestamp = timestamp[:16]

                # Escape pipe characters and truncate
                error_code = str(event.get('error_code', 0))
                hostname = event.get('hostname', 'N/A').replace('|', '\\|')[:20]
                stdout = (event.get('stdout', '') or '').replace('|', '\\|')[:25]
                stderr = (event.get('stderr', '') or '').replace('|', '\\|')[:25]
                file_path = (event.get('file_path', '') or '').replace('|', '\\|')[:35]

                output.append(f"| {error_code} | {hostname} | {timestamp} | {stdout} | {stderr} | {file_path} |")

            return '\n'.join(output)

        elif format_type == 'csv':
            import csv
            import io

            output = io.StringIO()
            writer = csv.writer(output)

            # Headers
            writer.writerow(['Error Code', 'Hostname', 'Timestamp', 'STDOUT', 'STDERR', 'File Path'])

            for event in events:
                writer.writerow([
                    event.get('error_code', 0),
                    event.get('hostname', ''),
                    event.get('timestamp', ''),
                    event.get('stdout', ''),
                    event.get('stderr', ''),
                    event.get('file_path', '')
                ])

            return output.getvalue()

        else:  # table format
            return self.format_events_table(events)


def main():
    parser = argparse.ArgumentParser(
        description="Query LimaCharlie sensor events for F0RT1KA security tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --uuid "abc123def456" --date-range "last 24 hours"  # Uses .env file
  %(prog)s --uuid "abc123def456" --date-range "last 24 hours" -k API_KEY -o ORG_ID
  %(prog)s --uuid "abc123def456" --date-range "last 7 days" --hostnames
  %(prog)s --uuid "abc123def456" --date-range "today" --env-file custom.env
  %(prog)s --uuid "abc123def456" --date-range "today" --output results.json
        """
    )

    parser.add_argument('--uuid', required=True,
                       help='Security test UUID to search for')
    parser.add_argument('--date-range', required=True,
                       help='Date range string for LCQL query (e.g., "last 24 hours", "today")')
    parser.add_argument('--lc-sensors-path',
                       help='Path to lc-sensors binary (auto-detected if not specified)')
    parser.add_argument('-k', '--api-key',
                       help='LimaCharlie API Key (can also use LIMACHARLIE_API_KEY env var)')
    parser.add_argument('-o', '--org-id',
                       help='LimaCharlie Organization ID (can also use LIMACHARLIE_OID env var)')
    parser.add_argument('--env-file',
                       help='Path to .env file for loading credentials (auto-detected if not specified)')
    parser.add_argument('--format', choices=['table', 'json', 'csv', 'markdown'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--hostnames', action='store_true',
                       help='Show only endpoints tested with event timestamps')
    parser.add_argument('--output', help='Output file path (stdout if not specified)')

    args = parser.parse_args()

    try:
        client = LCEventsQuery(args.lc_sensors_path, args.api_key, args.org_id, args.env_file)

        # Query events
        events, query_info = client.query_events(args.uuid, args.date_range)

        # Extract and process event data
        processed_events = client.extract_event_data(events)

        # Generate output based on options
        if args.hostnames:
            formatted_output = client.format_endpoints_only(processed_events)
        else:
            formatted_output = client.format_events(processed_events, args.format)

            # Add statistics for table and markdown formats
            if args.format in ['table', 'markdown']:
                stats = client.generate_statistics(processed_events, query_info, args.format)
                formatted_output += "\n\n" + stats

        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                f.write(formatted_output)
            print(f"Results written to {args.output}")
        else:
            print(formatted_output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()