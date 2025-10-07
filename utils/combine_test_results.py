#!/usr/bin/env python3
"""
Combined Security Test Results Script
====================================

Combines results from LimaCharlie sensor events and Microsoft Defender alerts
for F0RT1KA security test analysis with hostname correlation and timing analysis.

Features:
- Execute both LC events query and Defender alerts query
- Search by UUID (LC events + Defender) or SHA1 hash (Defender only)
- Correlate results by hostname with 5-minute timestamp window
- Generate comprehensive table with test outcomes
- Handle authentication for both services
- Provide detailed statistics and analysis

Requirements:
- LimaCharlie credentials (API key, Org ID)
- Microsoft Defender credentials (Azure tenant, client ID, secret)
- Both utils/lc_events_query.py and utils/defender_alert_query.py

Usage Examples:
    # Basic correlation analysis with UUID
    python combine_test_results.py --uuid "abc123def456" --date-range "last 24 hours"

    # Search Defender alerts by SHA1 hash
    python combine_test_results.py --sha1 "1234567890abcdef1234567890abcdef12345678" --date-range "last 24 hours"

    # Search by both UUID and SHA1
    python combine_test_results.py --uuid "abc123" --sha1 "1234567890abcdef" --date-range "last 7 days"

    # Exclude specific error codes from analysis
    python combine_test_results.py --uuid "abc123" --date-range "last 7 days" --exclude-error-codes "1,200"

    # Enable comprehensive defense scoring (NEW)
    python combine_test_results.py --uuid "abc123def456" --date-range "last 24 hours" --score
    python combine_test_results.py --uuid "abc123" --date-range "last 7 days" --score --format markdown --output report.md

    # Export to JSON for further processing
    python combine_test_results.py --uuid "abc123def456" --date-range "today" --output results.json

    # Use custom .env file for credentials
    python combine_test_results.py --uuid "abc123def456" --date-range "last 7 days" --env-file custom.env

    # Use separate .env file for Azure Defender credentials
    python combine_test_results.py --uuid "abc123def456" --date-range "last 7 days" --defender-env-file azure.env
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

    def __init__(self, env_file: Optional[str] = None, defender_env_file: Optional[str] = None):
        # Load environment variables from .env file if available
        self._load_env_file(env_file)

        # Store defender env file path for passing to defender_alert_query.py
        self.defender_env_file = defender_env_file

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

    def execute_lc_query(self, uuid: str, date_range: str, limit: int = 1000, show_progress: bool = True) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
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
                "--limit", str(limit),
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

            # Show stderr if there was any output (even with returncode 0)
            if result.stderr:
                print(f"Query stderr output: {result.stderr}")

            # Read results from temporary file
            try:
                with open(temp_path, 'r') as f:
                    file_content = f.read()
                    if not file_content.strip():
                        raise ValueError(f"Output file is empty. Command stderr: {result.stderr}")
                    lc_results = json.loads(file_content)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse JSON from output file. Error: {e}\nFile content: {file_content[:200]}\nCommand stderr: {result.stderr}")

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

    def execute_defender_query(self, uuid: Optional[str] = None, sha1: Optional[str] = None, show_progress: bool = True) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Execute Microsoft Defender alerts query

        Args:
            uuid: Test UUID to search for (uses --test-alerts)
            sha1: SHA1 hash to search for (uses --test-alerts-sha1)
            show_progress: Whether to show progress

        Returns:
            Tuple of (alerts, query_info)
        """
        if not uuid and not sha1:
            raise ValueError("Either uuid or sha1 must be provided")

        if show_progress:
            print("Executing Microsoft Defender alerts query...")

        # Create temporary file for JSON output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            # Build command based on search type
            cmd = [
                "python3", self.defender_script,
                "--days", "90",
                "--fetch-all",
                "--max-results", "5000",
                "--format", "json",
                "--output", temp_path
            ]

            # Add env-file flag if specified
            if self.defender_env_file:
                cmd.extend(["--env-file", self.defender_env_file])

            # Add search parameters - both if available for intersection search
            if uuid:
                cmd.extend(["--test-alerts", uuid])
            if sha1:
                cmd.extend(["--test-alerts-sha1", sha1])

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
                'sha1': sha1,
                'search_type': 'sha1' if sha1 else 'uuid',
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
                         time_window_minutes: int = 5, enable_scoring: bool = False) -> List[Dict[str, Any]]:
        """Correlate LimaCharlie and Defender results by hostname and timestamp

        Args:
            lc_results: LimaCharlie event results
            defender_results: Defender alert results
            time_window_minutes: Time window for correlation matching
            enable_scoring: If True, calculate scoring metrics for each correlation
        """
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

            # Calculate scoring if enabled
            if enable_scoring:
                correlation['scoring'] = self.calculate_event_score(correlation)

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

    def format_correlations_table(self, correlations: List[Dict[str, Any]], enable_scoring: bool = False) -> str:
        """Format correlations as a table

        Args:
            correlations: List of correlation dictionaries
            enable_scoring: If True, include score column in table
        """
        if not correlations:
            return "No correlations found."

        output = []
        output.append("F0RT1KA - Security Test Results")
        output.append("=" * 120)
        output.append("")

        # Table headers - add Score column if scoring enabled
        if enable_scoring:
            headers = ["LC Hostname", "LC Timestamp", "LC Error", "Defender Match", "Def Timestamp", "Severity", "Status", "Remediation", "Detection", "Score"]
            col_widths = [16, 16, 8, 12, 16, 13, 12, 12, 12, 8]
        else:
            headers = ["LC Hostname", "LC Timestamp", "LC Error", "Defender Match", "Def Timestamp", "Severity", "Status", "Remediation", "Detection"]
            col_widths = [16, 16, 8, 12, 16, 13, 12, 12, 12]

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
                corr.get('severity', 'N/A')[:13],
                corr.get('status', 'N/A')[:11],
                corr.get('remediation_status', 'N/A')[:11],
                corr.get('detection_status', 'N/A')[:11]
            ]

            # Add score column if enabled
            if enable_scoring:
                score = corr.get('scoring', {}).get('total_score', 0)
                row_data.append(f"{score:.1f}")

            # Create row
            row = "| " + " | ".join(f"{row_data[i]:<{col_widths[i]}}" for i in range(len(row_data))) + " |"
            output.append(row)

        return '\n'.join(output)

    def generate_statistics(self, correlations: List[Dict[str, Any]],
                          lc_query_info: Dict[str, Any],
                          defender_query_info: Dict[str, Any],
                          time_window_minutes: int = 5,
                          enable_scoring: bool = False) -> str:
        """Generate summary statistics

        Args:
            correlations: List of correlation dictionaries
            lc_query_info: LimaCharlie query information
            defender_query_info: Defender query information
            time_window_minutes: Time window for correlation
            enable_scoring: If True, include scoring statistics
        """
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

        # Show excluded events if any
        excluded_count = lc_query_info.get('excluded_count', 0)
        if excluded_count > 0:
            excluded_codes = lc_query_info.get('excluded_error_codes', [])
            stats.append(f"Excluded Events: {excluded_count} (error codes: {', '.join(map(str, excluded_codes))})")

        stats.append(f"Total Defender Alerts: {defender_query_info.get('total_alerts', 0)}")
        stats.append(f"Matched Events: {matched_events} ({(matched_events/total_lc_events)*100:.1f}%)")
        stats.append(f"Unique Endpoints: {len(unique_hostnames)}")
        stats.append(f"Endpoints with Matches: {len(matched_hostnames)}")
        stats.append(f"Test UUID: {lc_query_info.get('uuid', 'N/A')}")
        stats.append(f"Date Range: {lc_query_info.get('date_range', 'N/A')}")
        stats.append(f"Time Window: {time_window_minutes} minutes")

        # Add defense score statistics if enabled
        if enable_scoring:
            defense_score_data = self.calculate_defense_score(correlations)
            stats.append("")
            stats.append("=" * 50)
            stats.append("DEFENSE SCORE ANALYSIS")
            stats.append("=" * 50)
            stats.append(f"Final Defense Score: {defense_score_data['final_score']:.2f}%")
            stats.append(f"Rating: {defense_score_data['interpretation']}")
            stats.append(f"Assessment: {defense_score_data['description']}")
            stats.append("")
            stats.append("Component Breakdown:")

            comp_avgs = defense_score_data['component_averages']
            stats.append(f"  Detection Coverage:    {comp_avgs['detection_coverage']['average']:.2f}/{comp_avgs['detection_coverage']['max']} ({comp_avgs['detection_coverage']['percentage']:.1f}%)")
            stats.append(f"  Prevention Quality:    {comp_avgs['prevention_quality']['average']:.2f}/{comp_avgs['prevention_quality']['max']} ({comp_avgs['prevention_quality']['percentage']:.1f}%)")
            stats.append(f"  Response Speed:        {comp_avgs['response_speed']['average']:.2f}/{comp_avgs['response_speed']['max']} ({comp_avgs['response_speed']['percentage']:.1f}%)")
            stats.append(f"  Severity Recognition:  {comp_avgs['severity_recognition']['average']:.2f}/{comp_avgs['severity_recognition']['max']} ({comp_avgs['severity_recognition']['percentage']:.1f}%)")

            # Show penalties if any
            penalties = defense_score_data['penalties']
            if penalties['total_penalty'] > 0:
                stats.append("")
                stats.append("Penalties Applied:")
                if penalties['unmatched_events'] > 0:
                    stats.append(f"  Unmatched Events: -{penalties['unmatched_events']} points")
                if penalties['late_detections'] > 0:
                    stats.append(f"  Late Detections: -{penalties['late_detections']} points")
                if penalties['not_remediated'] > 0:
                    stats.append(f"  Not Remediated: -{penalties['not_remediated']} points")
                if penalties['not_detected'] > 0:
                    stats.append(f"  Not Detected: -{penalties['not_detected']} points")
                stats.append(f"  Total Penalties: -{penalties['total_penalty']} points")

            stats.append("")
            stats.append(f"Average Score Before Penalties: {defense_score_data['average_score_before_penalties']:.2f}")
            stats.append("=" * 50)

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
            0: "exec_error",
            1: "NF_denied",
            3: "Quarantined",
            200: "Uploaded",
            259: "exec_stop"
        }
        return error_meanings.get(error_code, "Unknown")

    # ============================================================================
    # SCORING METHODS (Optional - only used when --score flag is enabled)
    # ============================================================================

    def calculate_detection_coverage_score(self, correlation: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate detection coverage score (0-40 points)

        Scoring breakdown:
        - Base detection (matched): 20 points
        - Evidence diversity: 0-20 points
        """
        score_breakdown = {
            'base_detection': 0,
            'evidence_diversity': 0,
            'total': 0
        }

        # Base detection: 20 points if matched
        if correlation.get('defender_match') == 'Yes':
            score_breakdown['base_detection'] = 20

        # Evidence diversity analysis (only if we have a match)
        if correlation.get('defender_match') == 'Yes':
            # Count evidence types from the defender alert
            # We don't have direct access to the alert here, so we'll estimate based on available data
            evidence_score = 0

            # If we have multiple status types, indicates multiple evidence
            if correlation.get('remediation_status') and correlation.get('remediation_status') != 'N/A':
                evidence_score += 5

            if correlation.get('detection_status') and correlation.get('detection_status') != 'N/A':
                evidence_score += 5

            # If we have defender hostname, indicates device evidence
            if correlation.get('defender_hostname'):
                evidence_score += 5

            # If severity is assessed, indicates analysis depth
            if correlation.get('severity') and correlation.get('severity') != 'N/A':
                evidence_score += 5

            score_breakdown['evidence_diversity'] = min(evidence_score, 20)

        score_breakdown['total'] = score_breakdown['base_detection'] + score_breakdown['evidence_diversity']
        return score_breakdown

    def calculate_prevention_quality_score(self, lc_error_code: int, defender_status: str) -> Dict[str, Any]:
        """Calculate prevention quality score (0-30 points)

        Scoring breakdown:
        - LC error code base points
        - Defender status multiplier
        """
        # LC error code base points
        error_code_points = {
            3: 30,    # Quarantined - pre-execution blocking (best)
            1: 25,    # NF_denied - kernel-level denial
            259: 20,  # exec_stop - execution stopped
            0: 15,    # exec_error - failed execution
            200: 5    # Uploaded - detection only (worst)
        }

        base_points = error_code_points.get(lc_error_code, 10)  # Default 10 for unknown codes

        # Defender status multiplier
        status_multipliers = {
            'prevented': 1.0,
            'blocked': 0.8,
            'resolved': 0.6,
            'inProgress': 0.4,
            'new': 0.2
        }

        # Normalize status (case-insensitive)
        status_normalized = defender_status.lower() if defender_status else ''
        multiplier = status_multipliers.get(status_normalized, 0.5)  # Default 0.5 for unknown

        final_score = base_points * multiplier

        return {
            'base_points': base_points,
            'error_code': lc_error_code,
            'status': defender_status,
            'multiplier': multiplier,
            'total': round(final_score, 2)
        }

    def calculate_response_speed_score(self, lc_timestamp: Optional[datetime],
                                       defender_timestamp_str: str) -> Dict[str, Any]:
        """Calculate response speed score (0-20 points)

        Based on time difference between LC event and Defender alert
        """
        score_breakdown = {
            'time_diff_seconds': None,
            'time_diff_category': 'N/A',
            'total': 0
        }

        if not lc_timestamp or not defender_timestamp_str:
            return score_breakdown

        defender_timestamp = self.parse_timestamp(defender_timestamp_str)
        if not defender_timestamp:
            return score_breakdown

        # Calculate time difference
        time_diff = abs(defender_timestamp - lc_timestamp)
        time_diff_seconds = time_diff.total_seconds()
        score_breakdown['time_diff_seconds'] = time_diff_seconds

        # Score based on time difference
        if time_diff_seconds < 5:
            score_breakdown['total'] = 20
            score_breakdown['time_diff_category'] = 'Real-time (<5s)'
        elif time_diff_seconds < 30:
            score_breakdown['total'] = 18
            score_breakdown['time_diff_category'] = 'Near real-time (5-30s)'
        elif time_diff_seconds < 60:
            score_breakdown['total'] = 15
            score_breakdown['time_diff_category'] = 'Fast (30-60s)'
        elif time_diff_seconds < 120:
            score_breakdown['total'] = 12
            score_breakdown['time_diff_category'] = 'Good (1-2m)'
        elif time_diff_seconds < 180:
            score_breakdown['total'] = 8
            score_breakdown['time_diff_category'] = 'Acceptable (2-3m)'
        elif time_diff_seconds < 300:
            score_breakdown['total'] = 4
            score_breakdown['time_diff_category'] = 'Slow (3-5m)'
        else:
            score_breakdown['total'] = 0
            score_breakdown['time_diff_category'] = 'Delayed (>5m)'

        return score_breakdown

    def calculate_severity_score(self, severity: str) -> Dict[str, Any]:
        """Calculate severity recognition score (0-10 points)

        Rewards accurate threat severity assessment
        """
        severity_points = {
            'high': 10,
            'medium': 7,
            'low': 4,
            'informational': 1
        }

        # Normalize severity (case-insensitive)
        severity_normalized = severity.lower() if severity else ''
        points = severity_points.get(severity_normalized, 0)

        return {
            'severity': severity,
            'total': points
        }

    def calculate_event_score(self, correlation: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate total score for a single event (0-100 points)

        Combines all scoring components:
        - Detection coverage: 0-40 points
        - Prevention quality: 0-30 points
        - Response speed: 0-20 points
        - Severity recognition: 0-10 points
        """
        # Calculate individual component scores
        detection_score = self.calculate_detection_coverage_score(correlation)

        prevention_score = self.calculate_prevention_quality_score(
            correlation.get('lc_error_code', 0),
            correlation.get('status', '')
        )

        response_speed_score = self.calculate_response_speed_score(
            correlation.get('lc_timestamp_parsed'),
            correlation.get('defender_timestamp', '')
        )

        severity_score = self.calculate_severity_score(
            correlation.get('severity', '')
        )

        # Calculate total score
        total_score = (
            detection_score['total'] +
            prevention_score['total'] +
            response_speed_score['total'] +
            severity_score['total']
        )

        return {
            'detection_coverage': detection_score,
            'prevention_quality': prevention_score,
            'response_speed': response_speed_score,
            'severity_recognition': severity_score,
            'total_score': round(total_score, 2),
            'max_score': 100
        }

    def calculate_penalties(self, correlations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate penalty points for various failure conditions

        Penalties:
        - Unmatched events: -5 per event
        - Late detection (>5 min): -3 per event
        - Not remediated: -5 per event
        - Not detected (but alert exists): -10 per event
        """
        penalties = {
            'unmatched_events': 0,
            'late_detections': 0,
            'not_remediated': 0,
            'not_detected': 0,
            'total_penalty': 0,
            'breakdown': []
        }

        for corr in correlations:
            # Unmatched events
            if corr.get('defender_match') != 'Yes':
                penalties['unmatched_events'] += 5
                penalties['breakdown'].append({
                    'hostname': corr.get('lc_hostname', 'N/A'),
                    'type': 'unmatched',
                    'penalty': 5
                })

            # Late detection (>5 minutes)
            if 'scoring' in corr:
                response_speed = corr['scoring'].get('response_speed', {})
                time_diff = response_speed.get('time_diff_seconds')
                if time_diff and time_diff > 300:
                    penalties['late_detections'] += 3
                    penalties['breakdown'].append({
                        'hostname': corr.get('lc_hostname', 'N/A'),
                        'type': 'late_detection',
                        'penalty': 3,
                        'time_diff': time_diff
                    })

            # Not remediated
            remediation_status = corr.get('remediation_status', '').lower()
            if 'notremediated' in remediation_status:
                penalties['not_remediated'] += 5
                penalties['breakdown'].append({
                    'hostname': corr.get('lc_hostname', 'N/A'),
                    'type': 'not_remediated',
                    'penalty': 5
                })

            # Not detected (but alert exists - false positive indicator)
            detection_status = corr.get('detection_status', '').lower()
            if corr.get('defender_match') == 'Yes' and 'notdetected' in detection_status:
                penalties['not_detected'] += 10
                penalties['breakdown'].append({
                    'hostname': corr.get('lc_hostname', 'N/A'),
                    'type': 'not_detected',
                    'penalty': 10
                })

        penalties['total_penalty'] = (
            penalties['unmatched_events'] +
            penalties['late_detections'] +
            penalties['not_remediated'] +
            penalties['not_detected']
        )

        return penalties

    def calculate_defense_score(self, correlations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate final defense score with component breakdown

        Returns comprehensive scoring analysis including:
        - Overall defense score (0-100%)
        - Component averages
        - Penalties applied
        - Score interpretation
        """
        if not correlations:
            return {
                'final_score': 0,
                'interpretation': 'No data',
                'total_events': 0
            }

        # Calculate average scores for each component
        total_events = len(correlations)
        events_with_scores = [c for c in correlations if 'scoring' in c]

        if not events_with_scores:
            return {
                'final_score': 0,
                'interpretation': 'Scoring not calculated',
                'total_events': total_events
            }

        # Sum up all component scores
        component_totals = {
            'detection_coverage': 0,
            'prevention_quality': 0,
            'response_speed': 0,
            'severity_recognition': 0
        }

        total_score_sum = 0

        for corr in events_with_scores:
            scoring = corr.get('scoring', {})
            component_totals['detection_coverage'] += scoring.get('detection_coverage', {}).get('total', 0)
            component_totals['prevention_quality'] += scoring.get('prevention_quality', {}).get('total', 0)
            component_totals['response_speed'] += scoring.get('response_speed', {}).get('total', 0)
            component_totals['severity_recognition'] += scoring.get('severity_recognition', {}).get('total', 0)
            total_score_sum += scoring.get('total_score', 0)

        # Calculate averages
        num_scored_events = len(events_with_scores)
        avg_detection = component_totals['detection_coverage'] / num_scored_events
        avg_prevention = component_totals['prevention_quality'] / num_scored_events
        avg_speed = component_totals['response_speed'] / num_scored_events
        avg_severity = component_totals['severity_recognition'] / num_scored_events
        avg_total = total_score_sum / num_scored_events

        # Calculate penalties
        penalties = self.calculate_penalties(correlations)

        # Final score (average score minus penalties, capped at 0-100)
        final_score = max(0, min(100, avg_total - penalties['total_penalty']))

        # Score interpretation
        if final_score >= 90:
            interpretation = "⭐⭐⭐⭐⭐ Excellent"
            description = "Comprehensive pre-execution prevention with fast response"
        elif final_score >= 75:
            interpretation = "⭐⭐⭐⭐ Strong"
            description = "Effective early-stage blocking and good coverage"
        elif final_score >= 60:
            interpretation = "⭐⭐⭐ Good"
            description = "Solid detection with moderate prevention"
        elif final_score >= 40:
            interpretation = "⭐⭐ Fair"
            description = "Basic detection capabilities, needs improvement"
        elif final_score >= 20:
            interpretation = "⭐ Weak"
            description = "Limited and delayed detection, critical gaps"
        else:
            interpretation = "❌ Critical"
            description = "Inadequate protection, immediate action required"

        return {
            'final_score': round(final_score, 2),
            'average_score_before_penalties': round(avg_total, 2),
            'interpretation': interpretation,
            'description': description,
            'total_events': total_events,
            'scored_events': num_scored_events,
            'component_averages': {
                'detection_coverage': {
                    'average': round(avg_detection, 2),
                    'max': 40,
                    'percentage': round((avg_detection / 40) * 100, 1)
                },
                'prevention_quality': {
                    'average': round(avg_prevention, 2),
                    'max': 30,
                    'percentage': round((avg_prevention / 30) * 100, 1)
                },
                'response_speed': {
                    'average': round(avg_speed, 2),
                    'max': 20,
                    'percentage': round((avg_speed / 20) * 100, 1)
                },
                'severity_recognition': {
                    'average': round(avg_severity, 2),
                    'max': 10,
                    'percentage': round((avg_severity / 10) * 100, 1)
                }
            },
            'penalties': penalties
        }

    # ============================================================================
    # END SCORING METHODS
    # ============================================================================

    def _format_markdown(self, correlations: List[Dict[str, Any]],
                        lc_query_info: Dict[str, Any],
                        defender_query_info: Dict[str, Any],
                        time_window_minutes: int = 5,
                        enable_scoring: bool = False) -> str:
        """Format output in markdown format with Defense Score prominently displayed

        Args:
            correlations: List of correlation dictionaries
            lc_query_info: LimaCharlie query information
            defender_query_info: Defender query information
            time_window_minutes: Time window for correlation
            enable_scoring: If True, include comprehensive scoring analysis
        """
        if not correlations:
            return "# F0RT1KA Combined Security Test Results\n\nNo correlations found."

        output = []
        output.append("# F0RT1KA - Security Test Results\n")

        # Calculate Defense Score (matched events percentage)
        total_lc_events = len(correlations)
        matched_events = len([c for c in correlations if c.get('defender_match') == 'Yes'])
        defense_score = (matched_events / total_lc_events * 100) if total_lc_events > 0 else 0

        # Prominent Defense Score section
        if enable_scoring:
            # Use comprehensive scoring
            defense_score_data = self.calculate_defense_score(correlations)
            output.append("## 🛡️ Defense Score")
            output.append(f"## **{defense_score_data['final_score']:.1f}%** - {defense_score_data['interpretation']}")
            output.append(f"*{defense_score_data['description']}*\n")

            # Component breakdown
            output.append("### Score Components")
            comp_avgs = defense_score_data['component_averages']
            output.append(f"- **Detection Coverage:** {comp_avgs['detection_coverage']['average']:.2f}/{comp_avgs['detection_coverage']['max']} ({comp_avgs['detection_coverage']['percentage']:.1f}%)")
            output.append(f"- **Prevention Quality:** {comp_avgs['prevention_quality']['average']:.2f}/{comp_avgs['prevention_quality']['max']} ({comp_avgs['prevention_quality']['percentage']:.1f}%)")
            output.append(f"- **Response Speed:** {comp_avgs['response_speed']['average']:.2f}/{comp_avgs['response_speed']['max']} ({comp_avgs['response_speed']['percentage']:.1f}%)")
            output.append(f"- **Severity Recognition:** {comp_avgs['severity_recognition']['average']:.2f}/{comp_avgs['severity_recognition']['max']} ({comp_avgs['severity_recognition']['percentage']:.1f}%)")

            # Penalties if any
            penalties = defense_score_data['penalties']
            if penalties['total_penalty'] > 0:
                output.append(f"\n**Penalties Applied:** -{penalties['total_penalty']} points")
                if penalties['unmatched_events'] > 0:
                    output.append(f"- Unmatched Events: -{penalties['unmatched_events']}")
                if penalties['late_detections'] > 0:
                    output.append(f"- Late Detections: -{penalties['late_detections']}")
                if penalties['not_remediated'] > 0:
                    output.append(f"- Not Remediated: -{penalties['not_remediated']}")
                if penalties['not_detected'] > 0:
                    output.append(f"- Not Detected: -{penalties['not_detected']}")

            output.append(f"\n*{matched_events} out of {total_lc_events} LimaCharlie events detected by Microsoft Defender*\n")
        else:
            # Use simple match percentage (existing behavior)
            output.append("## 🛡️ Defense Score")
            output.append(f"## **{defense_score:.1f}%**")
            output.append(f"*{matched_events} out of {total_lc_events} LimaCharlie events detected by Microsoft Defender*\n")

        # Summary section
        output.append("## Summary")
        unique_hostnames = set(c.get('lc_hostname', 'N/A') for c in correlations if c.get('lc_hostname') != 'N/A')
        matched_hostnames = set(c.get('lc_hostname', 'N/A') for c in correlations if c.get('defender_match') == 'Yes')

        output.append(f"- **Total LC Events:** {total_lc_events}")

        # Show excluded events if any
        excluded_count = lc_query_info.get('excluded_count', 0)
        if excluded_count > 0:
            excluded_codes = lc_query_info.get('excluded_error_codes', [])
            output.append(f"- **Excluded Events:** {excluded_count} (error codes: {', '.join(map(str, excluded_codes))})")

        output.append(f"- **Total Defender Alerts:** {defender_query_info.get('total_alerts', 0)}")
        output.append(f"- **Matched Events:** {matched_events} ({defense_score:.1f}%)")
        output.append(f"- **Unique Endpoints:** {len(unique_hostnames)}")
        output.append(f"- **Endpoints with Matches:** {len(matched_hostnames)}")
        output.append(f"- **Test UUID:** {lc_query_info.get('uuid', 'N/A')}")
        output.append(f"- **Date Range:** {lc_query_info.get('date_range', 'N/A')}")
        output.append(f"- **Time Window:** {time_window_minutes} minutes")

        # Correlation Results Table
        output.append("\n---\n")
        output.append("## Correlation Results\n")

        # Table headers - add Score column if scoring enabled
        if enable_scoring:
            output.append("| LC Hostname | LC Timestamp | LC Error | Defender Match | Def Timestamp | Severity | Status | Remediation | Detection | Score |")
            output.append("|-------------|--------------|----------|----------------|---------------|----------|--------|-------------|-----------|-------|")
        else:
            output.append("| LC Hostname | LC Timestamp | LC Error | Defender Match | Def Timestamp | Severity | Status | Remediation | Detection |")
            output.append("|-------------|--------------|----------|----------------|---------------|----------|--------|-------------|-----------|")

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

            # Escape pipe characters
            hostname = corr.get('lc_hostname', 'N/A').replace('|', '\\|')[:16]
            defender_match = corr.get('defender_match', 'No').replace('|', '\\|')
            severity = corr.get('severity', 'N/A').replace('|', '\\|')
            status = corr.get('status', 'N/A').replace('|', '\\|')
            remediation = corr.get('remediation_status', 'N/A').replace('|', '\\|')[:12]
            detection = corr.get('detection_status', 'N/A').replace('|', '\\|')[:12]

            # Build row with optional score column
            if enable_scoring:
                score = corr.get('scoring', {}).get('total_score', 0)
                output.append(f"| {hostname} | {lc_ts} | {corr.get('lc_error_code', 0)} | {defender_match} | {def_ts} | {severity} | {status} | {remediation} | {detection} | {score:.1f} |")
            else:
                output.append(f"| {hostname} | {lc_ts} | {corr.get('lc_error_code', 0)} | {defender_match} | {def_ts} | {severity} | {status} | {remediation} | {detection} |")

        # Statistics Summary
        output.append("\n---\n")
        output.append("## Statistics Summary\n")

        # Error code distribution
        error_counts = {}
        for corr in correlations:
            error_code = corr.get('lc_error_code', 0)
            error_counts[error_code] = error_counts.get(error_code, 0) + 1

        output.append("### LC Error Code Distribution")
        for error_code, count in sorted(error_counts.items()):
            percentage = (count / total_lc_events) * 100
            error_meaning = self._get_error_meaning(error_code)
            output.append(f"- **{error_code} ({error_meaning}):** {count} events ({percentage:.1f}%)")

        # Severity distribution
        severity_counts = {}
        for corr in correlations:
            if corr.get('defender_match') == 'Yes':
                severity = corr.get('severity', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts:
            output.append("\n### Defender Alert Severity Distribution")
            total_matched = sum(severity_counts.values())
            for severity, count in sorted(severity_counts.items()):
                percentage = (count / total_matched) * 100
                output.append(f"- **{severity.capitalize()}:** {count} alerts ({percentage:.1f}%)")

        # Endpoint analysis
        output.append("\n### Endpoint Analysis")
        for hostname in sorted(unique_hostnames):
            lc_events = len([c for c in correlations if c.get('lc_hostname') == hostname])
            defender_matches = len([c for c in correlations if c.get('lc_hostname') == hostname and c.get('defender_match') == 'Yes'])
            match_rate = (defender_matches / lc_events) * 100 if lc_events > 0 else 0
            output.append(f"- **{hostname}:** {lc_events} events, {defender_matches} matches ({match_rate:.1f}%)")

        # Unmatched Events Analysis
        unmatched_events = [c for c in correlations if c.get('defender_match') != 'Yes']
        if unmatched_events:
            output.append("\n---\n")
            output.append("## Unmatched Events Analysis\n")
            output.append(f"*{len(unmatched_events)} events did not match with Defender alerts*\n")

            for i, event in enumerate(unmatched_events[:10], 1):  # Limit to first 10 for readability
                hostname = event.get('lc_hostname', 'N/A')
                timestamp = event.get('lc_timestamp', 'N/A')
                analysis = event.get('match_analysis', {})

                output.append(f"### {i}. {hostname} at {timestamp}")
                output.append(f"- **Error Code:** {event.get('lc_error_code', 'N/A')}")

                hostname_matches = analysis.get('hostname_matches_found', 0)
                if hostname_matches > 0:
                    output.append(f"- ✓ Found {hostname_matches} hostname matches in Defender")
                    for match in analysis.get('all_hostname_matches', [])[:3]:  # Show first 3
                        time_diff = match.get('time_diff_minutes')
                        if time_diff is not None:
                            output.append(f"  - {match['defender_hostname']}: {time_diff:.1f} minutes difference")
                else:
                    output.append(f"- ✗ No hostname matches found in Defender alerts")

                closest_time = analysis.get('closest_time_diff_minutes')
                if closest_time is not None:
                    output.append(f"- ⏱ Closest time match (any hostname): {closest_time:.1f} minutes")

            if len(unmatched_events) > 10:
                output.append(f"\n*Showing first 10 of {len(unmatched_events)} unmatched events*")

        output.append("\n---\n")
        output.append(f"*Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")

        return '\n'.join(output)

    def format_output(self, correlations: List[Dict[str, Any]],
                     lc_query_info: Dict[str, Any],
                     defender_query_info: Dict[str, Any],
                     format_type: str = 'table',
                     time_window_minutes: int = 5,
                     enable_scoring: bool = False) -> str:
        """Format output in the requested format

        Args:
            correlations: List of correlation dictionaries
            lc_query_info: LimaCharlie query information
            defender_query_info: Defender query information
            format_type: Output format (table, json, or markdown)
            time_window_minutes: Time window for correlation
            enable_scoring: If True, include comprehensive scoring analysis
        """
        if format_type == 'json':
            output_data = {
                'correlations': correlations,
                'lc_query_info': lc_query_info,
                'defender_query_info': defender_query_info,
                'time_window_minutes': time_window_minutes
            }

            # Add defense score data if scoring enabled
            if enable_scoring:
                output_data['defense_score'] = self.calculate_defense_score(correlations)

            return json.dumps(output_data, indent=2, default=str)

        elif format_type == 'markdown':
            return self._format_markdown(correlations, lc_query_info, defender_query_info, time_window_minutes, enable_scoring)

        else:  # table format
            table_output = self.format_correlations_table(correlations, enable_scoring)
            stats_output = self.generate_statistics(correlations, lc_query_info, defender_query_info, time_window_minutes, enable_scoring)
            unmatched_analysis = self.analyze_unmatched_events(correlations)
            return f"{table_output}\n\n{stats_output}\n\n{unmatched_analysis}"


def main():
    parser = argparse.ArgumentParser(
        description="Combine LimaCharlie and Microsoft Defender security test results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Search by UUID (both LC events and Defender alerts)
  %(prog)s --uuid "abc123def456" --date-range "last 24 hours"
  %(prog)s --uuid "abc123def456" --date-range "today" --output results.json

  # Search by SHA1 hash (Defender alerts only)
  %(prog)s --sha1 "1234567890abcdef1234567890abcdef12345678" --date-range "last 24 hours"

  # Search by both UUID and SHA1
  %(prog)s --uuid "abc123def456" --sha1 "1234567890abcdef1234567890abcdef12345678" --date-range "last 7 days"

  # Exclude specific error codes from analysis
  %(prog)s --uuid "abc123def456" --date-range "last 7 days" --exclude-error-codes "1,200"

  # Enable comprehensive defense scoring
  %(prog)s --uuid "abc123def456" --date-range "last 24 hours" --score
  %(prog)s --uuid "abc123def456" --date-range "last 7 days" --score --format markdown --output report.md

  # With additional options
  %(prog)s --uuid "abc123def456" --date-range "last 30 days" --limit 5000 --env-file custom.env

  # Use separate Azure credentials file for Defender
  %(prog)s --uuid "abc123def456" --date-range "last 7 days" --defender-env-file azure.env
        """
    )

    parser.add_argument('--uuid',
                       help='Security test UUID to analyze (for LimaCharlie and Defender --test-alerts search)')
    parser.add_argument('--sha1',
                       help='SHA1 hash to search for in Defender alerts (uses --test-alerts-sha1)')
    parser.add_argument('--date-range', required=True,
                       help='Date range for LimaCharlie query (e.g., "last 24 hours", "today")')
    parser.add_argument('--env-file',
                       help='Path to .env file for loading credentials')
    parser.add_argument('--defender-env-file',
                       help='Path to .env file for Azure credentials (passed to defender_alert_query.py)')
    parser.add_argument('--limit', type=int, default=1000,
                       help='Maximum number of LC events to return (default: 1000)')
    parser.add_argument('--time-window', type=int, default=5,
                       help='Time window in minutes for correlation matching (default: 5)')
    parser.add_argument('--exclude-error-codes',
                       help='Comma-separated list of LC error codes to exclude from analysis (e.g., "1,200")')
    parser.add_argument('--format', choices=['table', 'json', 'markdown'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--output', help='Output file path (stdout if not specified)')
    parser.add_argument('--score', action='store_true',
                       help='Enable comprehensive defense scoring analysis (optional)')

    args = parser.parse_args()

    # Validate that at least one search parameter is provided
    if not args.uuid and not args.sha1:
        parser.error("At least one of --uuid or --sha1 must be provided")

    try:
        analyzer = CombinedTestResults(args.env_file, args.defender_env_file)

        # Parse exclude error codes
        exclude_error_codes = []
        if args.exclude_error_codes:
            try:
                exclude_error_codes = [int(code.strip()) for code in args.exclude_error_codes.split(',')]
                print(f"Excluding LC events with error codes: {exclude_error_codes}")
            except ValueError:
                parser.error(f"Invalid error codes format: {args.exclude_error_codes}. Use comma-separated integers (e.g., '1,200')")

        # Execute LimaCharlie query (requires UUID)
        if args.uuid:
            lc_results, lc_query_info = analyzer.execute_lc_query(args.uuid, args.date_range, args.limit)

            # Filter out excluded error codes before correlation
            if exclude_error_codes:
                original_count = len(lc_results)
                lc_results = [event for event in lc_results if event.get('error_code', 0) not in exclude_error_codes]
                excluded_count = original_count - len(lc_results)
                if excluded_count > 0:
                    print(f"Excluded {excluded_count} LC events with error codes {exclude_error_codes}")
                # Update query info with filtered count
                lc_query_info['total_events'] = len(lc_results)
                lc_query_info['excluded_count'] = excluded_count
                lc_query_info['excluded_error_codes'] = exclude_error_codes
        else:
            # If only SHA1 is provided, skip LC query
            lc_results, lc_query_info = [], {'uuid': None, 'date_range': args.date_range, 'total_events': 0}

        # Execute Defender query (can use UUID or SHA1)
        defender_results, defender_query_info = analyzer.execute_defender_query(
            uuid=args.uuid,
            sha1=args.sha1
        )

        # Correlate results
        correlations = analyzer.correlate_results(lc_results, defender_results, args.time_window, enable_scoring=args.score)

        # Generate output
        formatted_output = analyzer.format_output(correlations, lc_query_info, defender_query_info, args.format, args.time_window, enable_scoring=args.score)

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
