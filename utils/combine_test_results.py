#!/usr/bin/env python3
"""
Combined Security Test Results Script
====================================

Combines results from LimaCharlie sensor events and Microsoft Defender alerts
for F0RT1KA security test analysis with hostname correlation and timing analysis.

Features:
- Execute both LC events query and Defender alerts query
- Correlate results by hostname with 5-minute timestamp window
- Generate comprehensive table with test outcomes
- Handle authentication for both services
- Provide detailed statistics and analysis

Requirements:
- LimaCharlie credentials (API key, Org ID)
- Microsoft Defender credentials (Azure tenant, client ID, secret)
- Both utils/lc_events_query.py and utils/defender_alert_query.py

Usage Examples:
    # Basic correlation analysis
    python combine_test_results.py --uuid "abc123def456" --date-range "last 24 hours"

    # Export to JSON for further processing
    python combine_test_results.py --uuid "abc123def456" --date-range "today" --output results.json

    # Use custom .env file for credentials
    python combine_test_results.py --uuid "abc123def456" --date-range "last 7 days" --env-file custom.env
"""

import argparse
import json
import os
import sys
import subprocess
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

# Optional .env file support
try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False


class CombinedTestResults:
    """Combined security test results analyzer"""

    def __init__(self, env_file: Optional[str] = None):
        # Load environment variables from .env file if available
        self._load_env_file(env_file)

        # Get script directory for relative paths
        self.script_dir = os.path.dirname(os.path.abspath(__file__))

        # Paths to query scripts
        self.lc_script = os.path.join(self.script_dir, "lc_events_query.py")
        self.defender_script = os.path.join(self.script_dir, "defender_alert_query.py")

        # Validate scripts exist
        if not os.path.isfile(self.lc_script):
            raise FileNotFoundError(f"LimaCharlie query script not found: {self.lc_script}")
        if not os.path.isfile(self.defender_script):
            raise FileNotFoundError(f"Defender query script not found: {self.defender_script}")

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

    def execute_lc_query(self, uuid: str, date_range: str, show_progress: bool = True) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Execute LimaCharlie events query"""
        if show_progress:
            print("Executing LimaCharlie events query...")

        # Create temporary file for JSON output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            # Build command
            cmd = [
                "python3", self.lc_script,
                "--uuid", uuid,
                "--date-range", date_range,
                "--format", "json",
                "--output", temp_path
            ]

            if show_progress:
                print(f"Running: {' '.join(cmd)}")

            # Execute command with environment variables
            env = os.environ.copy()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)

            if result.returncode != 0:
                raise RuntimeError(f"LimaCharlie query failed: {result.stderr}")

            # Read results from temporary file
            with open(temp_path, 'r') as f:
                lc_results = json.load(f)

            if show_progress:
                print(f"LimaCharlie query completed: {len(lc_results)} events found")

            # Create query info
            query_info = {
                'uuid': uuid,
                'date_range': date_range,
                'total_events': len(lc_results)
            }

            return lc_results, query_info

        except subprocess.TimeoutExpired:
            raise RuntimeError("LimaCharlie query timed out after 180 seconds")
        except Exception as e:
            raise RuntimeError(f"Failed to execute LimaCharlie query: {e}")
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def execute_defender_query(self, uuid: str, show_progress: bool = True) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Execute Microsoft Defender alerts query"""
        if show_progress:
            print("Executing Microsoft Defender alerts query...")

        # Create temporary file for JSON output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            # Build command
            cmd = [
                "python3", self.defender_script,
                "--test-alerts", uuid,
                "--days", "90",
                "--fetch-all",
                "--max-results", "800",
                "--format", "json",
                "--output", temp_path
            ]

            if show_progress:
                print(f"Running: {' '.join(cmd)}")

            # Execute command with environment variables
            env = os.environ.copy()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)

            if result.returncode != 0:
                raise RuntimeError(f"Defender query failed: {result.stderr}")

            # Read results from temporary file
            with open(temp_path, 'r') as f:
                defender_results = json.load(f)

            if show_progress:
                print(f"Defender query completed: {len(defender_results)} alerts found")

            # Create query info
            query_info = {
                'uuid': uuid,
                'total_alerts': len(defender_results)
            }

            return defender_results, query_info

        except subprocess.TimeoutExpired:
            raise RuntimeError("Defender query timed out after 300 seconds")
        except Exception as e:
            raise RuntimeError(f"Failed to execute Defender query: {e}")
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse various timestamp formats and ensure consistent timezone handling"""
        if not timestamp_str:
            return None

        # Clean up the timestamp string
        clean_ts = timestamp_str.strip()

        # Try fromisoformat first (handles most ISO formats)
        try:
            # Replace Z with +00:00 for fromisoformat compatibility
            if clean_ts.endswith('Z'):
                clean_ts = clean_ts[:-1] + '+00:00'

            dt = datetime.fromisoformat(clean_ts)
            # Convert to UTC naive datetime for consistent comparison
            if dt.tzinfo is not None:
                dt = dt.utctimetuple()
                dt = datetime(*dt[:6])
            return dt
        except ValueError:
            pass

        # Common timestamp formats to try
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M'
        ]

        for fmt in formats:
            try:
                # Remove timezone indicators for strptime
                test_str = clean_ts.replace('Z', '').split('+')[0].split('-', 3)
                if len(test_str) > 3:
                    test_str = '-'.join(test_str[:3]) + ' ' + '+'.join(test_str[3:]).split('+')[0]
                else:
                    test_str = clean_ts.replace('Z', '').split('+')[0]

                return datetime.strptime(test_str, fmt)
            except ValueError:
                continue

        return None

    def correlate_results(self, lc_results: List[Dict[str, Any]], defender_results: List[Dict[str, Any]],
                         time_window_minutes: int = 5) -> List[Dict[str, Any]]:
        """Correlate LimaCharlie and Defender results by hostname and timestamp"""
        correlations = []

        # Process each LC event
        for lc_event in lc_results:
            lc_hostname = lc_event.get('hostname', 'N/A')
            lc_timestamp_str = lc_event.get('timestamp', '')
            lc_timestamp = self.parse_timestamp(lc_timestamp_str)

            # Initialize correlation row
            correlation = {
                'lc_hostname': lc_hostname,
                'lc_timestamp': lc_timestamp_str,
                'lc_timestamp_parsed': lc_timestamp,
                'defender_match': '',
                'defender_timestamp': '',
                'severity': '',
                'status': '',
                'remediation_status': '',
                'detection_status': '',
                'lc_error_code': lc_event.get('error_code', 0),
                'lc_file_path': lc_event.get('file_path', ''),
                'lc_stdout': lc_event.get('stdout', ''),
                'lc_stderr': lc_event.get('stderr', ''),
                'match_analysis': {}
            }

            # Find matching Defender alert
            if lc_timestamp and lc_hostname != 'N/A':
                best_match, match_analysis = self._find_best_defender_match_with_analysis(
                    lc_hostname, lc_timestamp, defender_results, time_window_minutes
                )

                correlation['match_analysis'] = match_analysis

                if best_match:
                    correlation.update({
                        'defender_match': 'Yes',
                        'defender_timestamp': best_match.get('createdDateTime', ''),
                        'severity': best_match.get('severity', ''),
                        'status': best_match.get('status', ''),
                        'remediation_status': self._extract_remediation_status(best_match),
                        'detection_status': self._extract_detection_status(best_match),
                        'defender_alert_id': best_match.get('id', ''),
                        'defender_title': best_match.get('title', ''),
                        'defender_hostname': self._extract_hostname_from_alert(best_match)
                    })

            correlations.append(correlation)

        return correlations

    def _normalize_hostname(self, hostname: str) -> str:
        """Normalize hostname by extracting base hostname from FQDN and converting to lowercase"""
        if not hostname:
            return ""
        # Remove domain suffix and convert to lowercase
        return hostname.split('.')[0].lower().strip()

    def _hostnames_match(self, hostname1: str, hostname2: str) -> bool:
        """Check if two hostnames match using flexible comparison"""
        if not hostname1 or not hostname2:
            return False

        # Normalize both hostnames
        norm1 = self._normalize_hostname(hostname1)
        norm2 = self._normalize_hostname(hostname2)

        # Direct comparison of normalized hostnames
        if norm1 == norm2:
            return True

        # Additional checks for edge cases
        # Check if one is contained in the other (for cases like "hostname" vs "hostname.domain")
        if norm1 in norm2 or norm2 in norm1:
            return True

        return False

    def _find_best_defender_match(self, hostname: str, lc_timestamp: datetime,
                                 defender_results: List[Dict[str, Any]],
                                 time_window_minutes: int) -> Optional[Dict[str, Any]]:
        """Find the best matching Defender alert for a given hostname and timestamp"""
        best_match = None
        smallest_time_diff = timedelta(minutes=time_window_minutes + 1)

        for alert in defender_results:
            # Check if hostname matches using flexible comparison
            alert_hostname = self._extract_hostname_from_alert(alert)
            if not alert_hostname or not self._hostnames_match(hostname, alert_hostname):
                continue

            # Check timestamp within window
            alert_timestamp_str = alert.get('createdDateTime', '')
            alert_timestamp = self.parse_timestamp(alert_timestamp_str)

            if alert_timestamp:
                time_diff = abs(alert_timestamp - lc_timestamp)
                if time_diff <= timedelta(minutes=time_window_minutes) and time_diff < smallest_time_diff:
                    best_match = alert
                    smallest_time_diff = time_diff

        return best_match

    def _find_best_defender_match_with_analysis(self, hostname: str, lc_timestamp: datetime,
                                               defender_results: List[Dict[str, Any]],
                                               time_window_minutes: int) -> tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """Find the best matching Defender alert with detailed analysis of why matches failed"""
        best_match = None
        smallest_time_diff = timedelta(minutes=time_window_minutes + 1)

        analysis = {
            'hostname_matches_found': 0,
            'time_window_matches_found': 0,
            'closest_hostname_match': None,
            'closest_time_diff_minutes': None,
            'all_hostname_matches': [],
            'total_alerts_checked': len(defender_results)
        }

        for alert in defender_results:
            alert_hostname = self._extract_hostname_from_alert(alert)
            alert_timestamp_str = alert.get('createdDateTime', '')
            alert_timestamp = self.parse_timestamp(alert_timestamp_str)

            # Check hostname matching
            hostname_matches = alert_hostname and self._hostnames_match(hostname, alert_hostname)

            if hostname_matches:
                analysis['hostname_matches_found'] += 1
                analysis['all_hostname_matches'].append({
                    'defender_hostname': alert_hostname,
                    'defender_timestamp': alert_timestamp_str,
                    'alert_id': alert.get('id', '')[:36],
                    'time_diff_minutes': None
                })

                if not analysis['closest_hostname_match']:
                    analysis['closest_hostname_match'] = alert_hostname

            # Check timestamp within window
            if alert_timestamp and lc_timestamp:
                time_diff = abs(alert_timestamp - lc_timestamp)
                time_diff_minutes = time_diff.total_seconds() / 60

                # Update closest time difference regardless of hostname match
                if analysis['closest_time_diff_minutes'] is None or time_diff_minutes < analysis['closest_time_diff_minutes']:
                    analysis['closest_time_diff_minutes'] = time_diff_minutes

                # Update time diff in hostname matches
                if hostname_matches:
                    analysis['all_hostname_matches'][-1]['time_diff_minutes'] = time_diff_minutes

                # Check if within time window
                if time_diff <= timedelta(minutes=time_window_minutes):
                    analysis['time_window_matches_found'] += 1

                    # Check if this is the best match (hostname + time)
                    if hostname_matches and time_diff < smallest_time_diff:
                        best_match = alert
                        smallest_time_diff = time_diff

        return best_match, analysis

    def _extract_hostname_from_alert(self, alert: Dict[str, Any]) -> Optional[str]:
        """Extract hostname from Defender alert evidence"""
        for evidence in alert.get('evidence', []):
            if evidence.get('@odata.type') == '#microsoft.graph.security.deviceEvidence':
                hostname = evidence.get('deviceDnsName')
                if hostname:
                    return hostname
        return None

    def _extract_remediation_status(self, alert: Dict[str, Any]) -> str:
        """Extract remediation status from alert evidence"""
        statuses = set()
        for evidence in alert.get('evidence', []):
            status = evidence.get('remediationStatus')
            if status:
                statuses.add(status)
        return '/'.join(sorted(statuses)) if statuses else 'N/A'

    def _extract_detection_status(self, alert: Dict[str, Any]) -> str:
        """Extract detection status from alert evidence"""
        statuses = set()
        for evidence in alert.get('evidence', []):
            status = evidence.get('detectionStatus')
            if status:
                statuses.add(status)
        return '/'.join(sorted(statuses)) if statuses else 'N/A'

    def format_correlations_table(self, correlations: List[Dict[str, Any]]) -> str:
        """Format correlations as a table"""
        if not correlations:
            return "No correlations found."

        output = []
        output.append("F0RT1KA Combined Security Test Results")
        output.append("=" * 120)
        output.append("")

        # Table headers
        headers = ["LC Hostname", "LC Timestamp", "LC Error", "Defender Match", "Def Timestamp", "Severity", "Status", "Remediation", "Detection"]
        col_widths = [16, 16, 8, 12, 16, 10, 12, 12, 12]

        # Header row
        header_row = "| " + " | ".join(f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers))) + " |"
        output.append(header_row)
        output.append("|" + "|".join("-" * (w + 2) for w in col_widths) + "|")

        # Data rows
        for corr in correlations:
            # Format LC timestamp
            lc_ts = corr.get('lc_timestamp', '')
            if lc_ts and corr.get('lc_timestamp_parsed'):
                try:
                    lc_ts = corr['lc_timestamp_parsed'].strftime('%Y-%m-%d %H:%M')
                except:
                    lc_ts = lc_ts[:16]
            else:
                lc_ts = lc_ts[:16] if lc_ts else 'N/A'

            # Format Defender timestamp
            def_ts = corr.get('defender_timestamp', '')
            if def_ts:
                def_parsed = self.parse_timestamp(def_ts)
                if def_parsed:
                    def_ts = def_parsed.strftime('%Y-%m-%d %H:%M')
                else:
                    def_ts = def_ts[:16]
            else:
                def_ts = 'N/A'

            row_data = [
                corr.get('lc_hostname', 'N/A')[:15],
                lc_ts,
                str(corr.get('lc_error_code', 0)),
                corr.get('defender_match', 'No')[:11],
                def_ts,
                corr.get('severity', 'N/A')[:9],
                corr.get('status', 'N/A')[:11],
                corr.get('remediation_status', 'N/A')[:11],
                corr.get('detection_status', 'N/A')[:11]
            ]

            # Create row
            row = "| " + " | ".join(f"{row_data[i]:<{col_widths[i]}}" for i in range(len(row_data))) + " |"
            output.append(row)

        return '\n'.join(output)

    def generate_statistics(self, correlations: List[Dict[str, Any]],
                          lc_query_info: Dict[str, Any],
                          defender_query_info: Dict[str, Any]) -> str:
        """Generate summary statistics"""
        if not correlations:
            return "No statistics available."

        total_lc_events = len(correlations)
        matched_events = len([c for c in correlations if c.get('defender_match') == 'Yes'])

        # Hostname analysis
        unique_hostnames = set(c.get('lc_hostname', 'N/A') for c in correlations if c.get('lc_hostname') != 'N/A')
        matched_hostnames = set(c.get('lc_hostname', 'N/A') for c in correlations if c.get('defender_match') == 'Yes')

        # Error code analysis
        error_counts = {}
        for corr in correlations:
            error_code = corr.get('lc_error_code', 0)
            error_counts[error_code] = error_counts.get(error_code, 0) + 1

        # Severity analysis for matched events
        severity_counts = {}
        for corr in correlations:
            if corr.get('defender_match') == 'Yes':
                severity = corr.get('severity', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Build statistics
        stats = []
        stats.append("CORRELATION STATISTICS")
        stats.append("-" * 50)
        stats.append(f"Total LC Events: {total_lc_events}")
        stats.append(f"Total Defender Alerts: {defender_query_info.get('total_alerts', 0)}")
        stats.append(f"Matched Events: {matched_events} ({(matched_events/total_lc_events)*100:.1f}%)")
        stats.append(f"Unique Endpoints: {len(unique_hostnames)}")
        stats.append(f"Endpoints with Matches: {len(matched_hostnames)}")
        stats.append(f"Test UUID: {lc_query_info.get('uuid', 'N/A')}")
        stats.append(f"Date Range: {lc_query_info.get('date_range', 'N/A')}")

        stats.append("")
        stats.append("LC Error Code Distribution:")
        for error_code, count in sorted(error_counts.items()):
            percentage = (count / total_lc_events) * 100
            error_meaning = self._get_error_meaning(error_code)
            stats.append(f"  {error_code} ({error_meaning}): {count} events ({percentage:.1f}%)")

        if severity_counts:
            stats.append("")
            stats.append("Defender Alert Severity Distribution:")
            total_matched = sum(severity_counts.values())
            for severity, count in sorted(severity_counts.items()):
                percentage = (count / total_matched) * 100
                stats.append(f"  {severity.capitalize()}: {count} alerts ({percentage:.1f}%)")

        stats.append("")
        stats.append("Endpoint Analysis:")
        for hostname in sorted(unique_hostnames):
            lc_events = len([c for c in correlations if c.get('lc_hostname') == hostname])
            defender_matches = len([c for c in correlations if c.get('lc_hostname') == hostname and c.get('defender_match') == 'Yes'])
            match_rate = (defender_matches / lc_events) * 100 if lc_events > 0 else 0
            stats.append(f"  {hostname}: {lc_events} events, {defender_matches} matches ({match_rate:.1f}%)")

        return '\n'.join(stats)

    def analyze_unmatched_events(self, correlations: List[Dict[str, Any]]) -> str:
        """Analyze why certain events didn't match"""
        unmatched_events = [c for c in correlations if c.get('defender_match') != 'Yes']

        if not unmatched_events:
            return "All events were successfully matched!"

        output = []
        output.append("UNMATCHED EVENTS ANALYSIS")
        output.append("-" * 50)

        for i, event in enumerate(unmatched_events, 1):
            hostname = event.get('lc_hostname', 'N/A')
            timestamp = event.get('lc_timestamp', 'N/A')
            analysis = event.get('match_analysis', {})

            output.append(f"\n{i}. LC Event: {hostname} at {timestamp}")
            output.append(f"   Error Code: {event.get('lc_error_code', 'N/A')}")

            # Hostname analysis
            hostname_matches = analysis.get('hostname_matches_found', 0)
            if hostname_matches > 0:
                output.append(f"   ✓ Found {hostname_matches} hostname matches in Defender")

                # Show time differences for hostname matches
                for match in analysis.get('all_hostname_matches', []):
                    time_diff = match.get('time_diff_minutes')
                    if time_diff is not None:
                        output.append(f"     - {match['defender_hostname']}: {time_diff:.1f} minutes difference")
                        output.append(f"       Alert ID: {match['alert_id']}")
                    else:
                        output.append(f"     - {match['defender_hostname']}: Unable to parse timestamp")
            else:
                output.append(f"   ✗ No hostname matches found in Defender alerts")

            # Time window analysis
            closest_time = analysis.get('closest_time_diff_minutes')
            if closest_time is not None:
                output.append(f"   ⏱ Closest time match (any hostname): {closest_time:.1f} minutes")
                if closest_time > 5:
                    output.append(f"   ⚠ Closest match exceeds 5-minute correlation window")

            total_checked = analysis.get('total_alerts_checked', 0)
            output.append(f"   📊 Total Defender alerts checked: {total_checked}")

        return '\n'.join(output)

    def _get_error_meaning(self, error_code: int) -> str:
        """Get human-readable meaning of LC error codes"""
        error_meanings = {
            0: "Success",
            101: "Endpoint.Unprotected",
            105: "Endpoint.FileQuarantinedOnExtraction",
            126: "Endpoint.ExecutionPrevented"
        }
        return error_meanings.get(error_code, "Unknown")

    def format_output(self, correlations: List[Dict[str, Any]],
                     lc_query_info: Dict[str, Any],
                     defender_query_info: Dict[str, Any],
                     format_type: str = 'table') -> str:
        """Format output in the requested format"""
        if format_type == 'json':
            return json.dumps({
                'correlations': correlations,
                'lc_query_info': lc_query_info,
                'defender_query_info': defender_query_info
            }, indent=2, default=str)

        else:  # table format
            table_output = self.format_correlations_table(correlations)
            stats_output = self.generate_statistics(correlations, lc_query_info, defender_query_info)
            unmatched_analysis = self.analyze_unmatched_events(correlations)
            return f"{table_output}\n\n{stats_output}\n\n{unmatched_analysis}"


def main():
    parser = argparse.ArgumentParser(
        description="Combine LimaCharlie and Microsoft Defender security test results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --uuid "abc123def456" --date-range "last 24 hours"
  %(prog)s --uuid "abc123def456" --date-range "today" --output results.json
  %(prog)s --uuid "abc123def456" --date-range "last 7 days" --env-file custom.env
        """
    )

    parser.add_argument('--uuid', required=True,
                       help='Security test UUID to analyze')
    parser.add_argument('--date-range', required=True,
                       help='Date range for LimaCharlie query (e.g., "last 24 hours", "today")')
    parser.add_argument('--env-file',
                       help='Path to .env file for loading credentials')
    parser.add_argument('--time-window', type=int, default=5,
                       help='Time window in minutes for correlation matching (default: 5)')
    parser.add_argument('--format', choices=['table', 'json'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--output', help='Output file path (stdout if not specified)')

    args = parser.parse_args()

    try:
        analyzer = CombinedTestResults(args.env_file)

        # Execute both queries
        lc_results, lc_query_info = analyzer.execute_lc_query(args.uuid, args.date_range)
        defender_results, defender_query_info = analyzer.execute_defender_query(args.uuid)

        # Correlate results
        correlations = analyzer.correlate_results(lc_results, defender_results, args.time_window)

        # Generate output
        formatted_output = analyzer.format_output(correlations, lc_query_info, defender_query_info, args.format)

        # Write output
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