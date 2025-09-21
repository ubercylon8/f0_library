#!/usr/bin/env python3
"""
Microsoft Defender 365 Alert Query Script
=========================================

Query Microsoft Defender 365 alerts with search filters, specifically designed
for use by Claude Code subagents in security testing workflows.

Features:
- Search alerts by file path patterns
- Filter by severity, status, detection source
- Azure AD authentication via service principal
- JSON/CSV output formats
- Command-line interface for automation

Requirements:
- Azure AD app registration with SecurityAlert.Read.All permission
- Environment variables: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID

Usage Examples:
    # Search for alerts with specific file path
    python defender_alert_query.py --file-path "c:\\F0\\*"

    # Search with multiple filters
    python defender_alert_query.py --file-path "*.exe" --severity high --days 7

    # Export to JSON for subagent processing
    python defender_alert_query.py --search-term "malware" --output alerts.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import requests
from urllib.parse import quote


class DefenderAlertQuery:
    """Microsoft Defender 365 Alert Query Client"""

    def __init__(self):
        self.tenant_id = os.getenv('AZURE_TENANT_ID')
        self.client_id = os.getenv('AZURE_CLIENT_ID')
        self.client_secret = os.getenv('AZURE_CLIENT_SECRET')
        self.access_token = None
        self.base_url = "https://graph.microsoft.com/v1.0"

        if not all([self.tenant_id, self.client_id, self.client_secret]):
            raise ValueError(
                "Missing required environment variables: "
                "AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET"
            )

    def authenticate(self) -> str:
        """Authenticate with Azure AD and get access token"""
        auth_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }

        response = requests.post(auth_url, data=data)
        response.raise_for_status()

        token_data = response.json()
        self.access_token = token_data['access_token']
        return self.access_token

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers with authorization"""
        if not self.access_token:
            self.authenticate()

        return {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

    def _fetch_all_pages(self,
                        url: str,
                        params: Dict[str, Any],
                        max_results: Optional[int] = None,
                        show_progress: bool = True) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Fetch all pages from Microsoft Graph API with proper pagination handling

        Args:
            url: Base API URL
            params: Query parameters for the request
            max_results: Maximum number of results to fetch (safety limit)
            show_progress: Whether to show progress during fetching

        Returns:
            Tuple of (all_results, pagination_info)
        """
        all_results = []
        pages_fetched = 0
        api_calls = 0
        next_link = None
        truncated = False
        next_link_available = False

        # Store original $top value for $skip calculation
        original_top = params.get('$top', 100)

        while True:
            api_calls += 1

            if next_link:
                # Use the full nextLink URL provided by API
                response = requests.get(next_link, headers=self._get_headers())
            else:
                # Use base URL with parameters
                response = requests.get(url, headers=self._get_headers(), params=params)

            response.raise_for_status()
            data = response.json()

            results = data.get('value', [])
            all_results.extend(results)
            pages_fetched += 1

            # Check for next page link
            next_link = data.get('@odata.nextLink')
            next_link_available = bool(next_link)

            # Safety limit check
            if max_results and len(all_results) >= max_results:
                if show_progress:
                    print(f"\nWarning: Reached max_results limit ({max_results})")
                truncated = True
                break

            # Show progress
            if show_progress:
                print(f"Fetched page {pages_fetched}, total alerts: {len(all_results)}", end='\r')

            # If no nextLink provided, try manual pagination with $skip
            if not next_link:
                # Check if we got a full page (indicates more data might be available)
                if len(results) == original_top:
                    # Try manual pagination
                    params['$skip'] = len(all_results)
                    # Continue the loop to make another request
                    continue
                else:
                    # Got fewer results than requested, we're done
                    break
            else:
                # Clear the $skip parameter since we're using nextLink
                params.pop('$skip', None)

        if show_progress and pages_fetched > 1:
            print()  # New line after progress indicator

        pagination_info = {
            'pages': pages_fetched,
            'api_calls': api_calls,
            'truncated': truncated,
            'next_link_available': next_link_available,
            'total_results': len(all_results)
        }

        return all_results, pagination_info

    def search_alerts(self,
                     file_path: Optional[str] = None,
                     search_term: Optional[str] = None,
                     severity: Optional[str] = None,
                     status: Optional[str] = None,
                     alert_id: Optional[str] = None,
                     days: int = 30,
                     limit: int = 100,
                     fetch_all: bool = False,
                     page_size: int = 100,
                     max_results: Optional[int] = None,
                     show_progress: bool = True) -> tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Search Microsoft Defender 365 alerts with filters

        Args:
            file_path: File path pattern to search for (supports wildcards)
            search_term: General search term across alert fields
            severity: Alert severity (low, medium, high, informational)
            status: Alert status (new, inProgress, resolved)
            alert_id: Specific alert ID to retrieve
            days: Number of days to look back (default: 30)
            limit: Maximum number of alerts to return (default: 100)
            fetch_all: Whether to fetch all pages using pagination (default: False)
            page_size: Number of results per API request (default: 100)
            max_results: Maximum total results when using fetch_all (safety limit)
            show_progress: Whether to show progress during pagination (default: True)

        Returns:
            Tuple of (alert_list, pagination_info). pagination_info is None if fetch_all=False
        """
        # If searching by specific alert ID, use direct endpoint
        if alert_id:
            url = f"{self.base_url}/security/alerts_v2/{alert_id}"
            response = requests.get(url, headers=self._get_headers())
            if response.status_code == 200:
                return [response.json()], None
            elif response.status_code == 404:
                return [], None
            else:
                response.raise_for_status()

        url = f"{self.base_url}/security/alerts_v2"

        # Build OData filter
        filters = []

        # Time filter
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'
        filters.append(f"createdDateTime ge {start_date}")

        # Severity filter
        if severity:
            filters.append(f"severity eq '{severity}'")

        # Status filter
        if status:
            filters.append(f"status eq '{status}'")

        # File path filter - search in evidence file paths using simple string matching
        # Note: Complex OData queries on evidence collections can be problematic
        # Using a simpler approach that works with the Graph API alerts_v2 endpoint
        if file_path:
            # Remove wildcards for exact path matching
            search_path = file_path.replace("*", "").replace("?", "").strip("\\")

            # File path filtering is done in post-processing due to OData query complexity
            # Results will be filtered after retrieval from the API

        # Search term filtering will be done in post-processing due to OData complexity
        # No additional filters added here for search_term

        params = {
            '$top': page_size if fetch_all else limit,
            '$orderby': 'createdDateTime desc'
        }

        if filters:
            params['$filter'] = ' and '.join(filters)

        # Use pagination if fetch_all is enabled
        pagination_info = None
        if fetch_all:
            alerts, pagination_info = self._fetch_all_pages(
                url,
                params,
                max_results=max_results or limit,
                show_progress=show_progress
            )
        else:
            response = requests.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            data = response.json()
            alerts = data.get('value', [])

            # Check if more results might be available
            if len(alerts) == limit or '@odata.nextLink' in data:
                if show_progress:
                    print("Warning: More results may be available. Use --fetch-all to get all results.")

        # Post-process file path and search term filtering if specified
        filtered_alerts = alerts

        if file_path:
            temp_filtered = []
            search_path = file_path.replace("*", "").replace("?", "").strip("\\").lower()

            for alert in filtered_alerts:
                match_found = False
                for evidence in alert.get('evidence', []):
                    evidence_path = ""
                    evidence_filename = ""

                    # Check fileEvidence
                    if evidence.get('@odata.type') == '#microsoft.graph.security.fileEvidence':
                        evidence_path = evidence.get('fileDetails', {}).get('filePath', '').lower()
                        evidence_filename = evidence.get('fileDetails', {}).get('fileName', '').lower()
                    # Check processEvidence
                    elif evidence.get('@odata.type') == '#microsoft.graph.security.processEvidence':
                        image_file = evidence.get('imageFile') or {}
                        evidence_path = image_file.get('filePath', '').lower()
                        evidence_filename = image_file.get('fileName', '').lower()

                        # Also check parent process image file (CRITICAL FIX)
                        parent_image_file = evidence.get('parentProcessImageFile') or {}
                        parent_evidence_path = (parent_image_file.get('filePath') or '').lower()
                        parent_evidence_filename = (parent_image_file.get('fileName') or '').lower()

                        # If parent process file matches, use it
                        if parent_evidence_path or parent_evidence_filename:
                            if file_path.endswith("*") or file_path.endswith("\\*"):
                                if parent_evidence_path.startswith(search_path) or parent_evidence_filename.startswith(search_path):
                                    match_found = True
                                    break
                            else:
                                parent_combined_path = f"{parent_evidence_path}\\{parent_evidence_filename}".lower() if parent_evidence_path and parent_evidence_filename else ""
                                if (search_path in parent_evidence_path or
                                    search_path in parent_evidence_filename or
                                    search_path in parent_combined_path or
                                    parent_evidence_filename in search_path):
                                    match_found = True
                                    break

                    if evidence_path or evidence_filename:
                        if file_path.endswith("*") or file_path.endswith("\\*"):
                            if evidence_path.startswith(search_path) or evidence_filename.startswith(search_path):
                                match_found = True
                                break
                        else:
                            # Check if search_path matches the combined path
                            combined_path = f"{evidence_path}\\{evidence_filename}".lower() if evidence_path and evidence_filename else ""
                            if (search_path in evidence_path or
                                search_path in evidence_filename or
                                search_path in combined_path or
                                evidence_filename in search_path):
                                match_found = True
                                break

                # Also check if the alert title or description mentions the path
                title = alert.get('title', '').lower()
                description = alert.get('description', '').lower()
                if search_path in title or search_path in description:
                    match_found = True

                if match_found:
                    temp_filtered.append(alert)

            filtered_alerts = temp_filtered

        if search_term:
            temp_filtered = []
            search_lower = search_term.lower()

            for alert in filtered_alerts:
                match_found = False

                # Check title and description (already filtered by OData if no file_path)
                title = alert.get('title', '').lower()
                description = alert.get('description', '').lower()
                if search_lower in title or search_lower in description:
                    match_found = True

                # Also check file and process evidence for the search term
                if not match_found:
                    for evidence in alert.get('evidence', []):
                        evidence_path = ""
                        evidence_filename = ""

                        # Check fileEvidence
                        if evidence.get('@odata.type') == '#microsoft.graph.security.fileEvidence':
                            file_details = evidence.get('fileDetails') or {}
                            evidence_path = file_details.get('filePath', '').lower()
                            evidence_filename = file_details.get('fileName', '').lower()
                        # Check processEvidence
                        elif evidence.get('@odata.type') == '#microsoft.graph.security.processEvidence':
                            image_file = evidence.get('imageFile') or {}
                            evidence_path = image_file.get('filePath', '').lower()
                            evidence_filename = image_file.get('fileName', '').lower()

                            # Also check parent process image file (CRITICAL FIX)
                            parent_image_file = evidence.get('parentProcessImageFile') or {}
                            parent_evidence_path = (parent_image_file.get('filePath') or '').lower()
                            parent_evidence_filename = (parent_image_file.get('fileName') or '').lower()

                            if search_lower in parent_evidence_path or search_lower in parent_evidence_filename:
                                match_found = True
                                break

                        if search_lower in evidence_path or search_lower in evidence_filename:
                            match_found = True
                            break

                if match_found:
                    temp_filtered.append(alert)

            filtered_alerts = temp_filtered

        return filtered_alerts, pagination_info

    def search_test_alerts(self,
                          search_term: str,
                          days: int = 30,
                          limit: int = 100,
                          fetch_all: bool = False,
                          page_size: int = 100,
                          max_results: Optional[int] = None,
                          show_progress: bool = True) -> tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Search Microsoft Defender 365 alerts for test-related indicators across multiple evidence fields

        Args:
            search_term: String to search for in evidence fields
            days: Number of days to look back (default: 30)
            limit: Maximum number of alerts to return (default: 100)
            fetch_all: Whether to fetch all pages using pagination (default: False)
            page_size: Number of results per API request (default: 100)
            max_results: Maximum total results when using fetch_all (safety limit)
            show_progress: Whether to show progress during pagination (default: True)

        Returns:
            Tuple of (alert_list, pagination_info). pagination_info is None if fetch_all=False
        """
        url = f"{self.base_url}/security/alerts_v2"

        # Build basic OData filter
        filters = []

        # Time filter
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'
        filters.append(f"createdDateTime ge {start_date}")

        params = {
            '$top': page_size if fetch_all else limit,
            '$orderby': 'createdDateTime desc'
        }

        if filters:
            params['$filter'] = ' and '.join(filters)

        # Use pagination if fetch_all is enabled
        pagination_info = None
        if fetch_all:
            alerts, pagination_info = self._fetch_all_pages(
                url,
                params,
                max_results=max_results or limit,
                show_progress=show_progress
            )
        else:
            response = requests.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            data = response.json()
            alerts = data.get('value', [])

            # Check if more results might be available
            if len(alerts) == limit or '@odata.nextLink' in data:
                if show_progress:
                    print("Warning: More results may be available. Use --fetch-all to get all results.")

        # Enhanced filtering for test alerts with match tracking
        enhanced_alerts = []
        search_lower = search_term.lower()

        for alert in alerts:
            matches = []
            alert_id = alert.get('id', 'N/A')

            # Check title and description
            title = alert.get('title', '').lower()
            description = alert.get('description', '').lower()
            if search_lower in title:
                matches.append('title')
            if search_lower in description:
                matches.append('description')

            # Check evidence for process and file information
            for evidence in alert.get('evidence', []):
                evidence_type = evidence.get('@odata.type', '')

                # Check fileEvidence
                if evidence_type == '#microsoft.graph.security.fileEvidence':
                    file_details = evidence.get('fileDetails') or {}
                    file_path = (file_details.get('filePath') or '').lower()
                    file_name = (file_details.get('fileName') or '').lower()

                    if search_lower in file_path:
                        matches.append('filePath')
                    if search_lower in file_name:
                        matches.append('fileName')

                # Check processEvidence
                elif evidence_type == '#microsoft.graph.security.processEvidence':
                    # Image file information
                    image_file = evidence.get('imageFile') or {}
                    image_path = (image_file.get('filePath') or '').lower()
                    image_name = (image_file.get('fileName') or '').lower()

                    if search_lower in image_path:
                        matches.append('filePath')
                    if search_lower in image_name:
                        matches.append('fileName')

                    # Parent process image file information (CRITICAL FIX)
                    parent_image_file = evidence.get('parentProcessImageFile') or {}
                    parent_image_path = (parent_image_file.get('filePath') or '').lower()
                    parent_image_name = (parent_image_file.get('fileName') or '').lower()

                    if search_lower in parent_image_path:
                        matches.append('parentFilePath')
                    if search_lower in parent_image_name:
                        matches.append('parentFileName')

                    # Process command lines
                    process_command = (evidence.get('processCommandLine') or '').lower()
                    parent_command = (evidence.get('parentProcessCommandLine') or '').lower()

                    if search_lower in process_command:
                        matches.append('processCommandLine')
                    if search_lower in parent_command:
                        matches.append('parentProcessCommandLine')

                # Check deviceEvidence for hostname
                elif evidence_type == '#microsoft.graph.security.deviceEvidence':
                    device_name = evidence.get('deviceDnsName', '').lower()
                    if search_lower in device_name:
                        matches.append('hostname')

            # If we found matches, add to results with match metadata
            if matches:
                # Remove duplicates while preserving order
                unique_matches = []
                for match in matches:
                    if match not in unique_matches:
                        unique_matches.append(match)

                # Add match information to alert
                enhanced_alert = alert.copy()
                enhanced_alert['_match_fields'] = unique_matches
                enhanced_alert['_match_count'] = len(unique_matches)
                enhanced_alerts.append(enhanced_alert)

        return enhanced_alerts, pagination_info

    def search_test_alerts_sha1(self,
                               sha1_hash: str,
                               days: int = 30,
                               limit: int = 100,
                               fetch_all: bool = False,
                               page_size: int = 100,
                               max_results: Optional[int] = None,
                               show_progress: bool = True) -> tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Search Microsoft Defender 365 alerts for specific SHA1 hash in file evidence

        Args:
            sha1_hash: SHA1 hash to search for in evidence fields
            days: Number of days to look back (default: 30)
            limit: Maximum number of alerts to return (default: 100)
            fetch_all: Whether to fetch all pages using pagination (default: False)
            page_size: Number of results per API request (default: 100)
            max_results: Maximum total results when using fetch_all (safety limit)
            show_progress: Whether to show progress during pagination (default: True)

        Returns:
            Tuple of (alert_list, pagination_info). pagination_info is None if fetch_all=False
        """
        url = f"{self.base_url}/security/alerts_v2"

        # Build basic OData filter
        filters = []

        # Time filter
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'
        filters.append(f"createdDateTime ge {start_date}")

        params = {
            '$top': page_size if fetch_all else limit,
            '$orderby': 'createdDateTime desc'
        }

        if filters:
            params['$filter'] = ' and '.join(filters)

        # Use pagination if fetch_all is enabled
        pagination_info = None
        if fetch_all:
            alerts, pagination_info = self._fetch_all_pages(
                url,
                params,
                max_results=max_results or limit,
                show_progress=show_progress
            )
        else:
            response = requests.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            data = response.json()
            alerts = data.get('value', [])

            # Check if more results might be available
            if len(alerts) == limit or '@odata.nextLink' in data:
                if show_progress:
                    print("Warning: More results may be available. Use --fetch-all to get all results.")

        # Enhanced filtering for SHA1 hash matches with match tracking
        enhanced_alerts = []
        sha1_lower = sha1_hash.lower()

        for alert in alerts:
            matches = []

            # Check evidence for SHA1 hash information
            for evidence in alert.get('evidence', []):
                evidence_type = evidence.get('@odata.type', '')

                # Check fileEvidence
                if evidence_type == '#microsoft.graph.security.fileEvidence':
                    file_details = evidence.get('fileDetails') or {}
                    file_sha1 = (file_details.get('sha1') or '').lower()

                    if file_sha1 and sha1_lower == file_sha1:
                        matches.append('fileDetails.sha1')

                # Check processEvidence
                elif evidence_type == '#microsoft.graph.security.processEvidence':
                    # Image file SHA1
                    image_file = evidence.get('imageFile') or {}
                    image_sha1 = (image_file.get('sha1') or '').lower()

                    if image_sha1 and sha1_lower == image_sha1:
                        matches.append('imageFile.sha1')

                    # Parent process image file SHA1
                    parent_image_file = evidence.get('parentProcessImageFile') or {}
                    parent_sha1 = (parent_image_file.get('sha1') or '').lower()

                    if parent_sha1 and sha1_lower == parent_sha1:
                        matches.append('parentProcessImageFile.sha1')

            # If we found matches, add to results with match metadata
            if matches:
                # Remove duplicates while preserving order
                unique_matches = []
                for match in matches:
                    if match not in unique_matches:
                        unique_matches.append(match)

                # Add match information to alert
                enhanced_alert = alert.copy()
                enhanced_alert['_match_fields'] = unique_matches
                enhanced_alert['_match_count'] = len(unique_matches)
                enhanced_alerts.append(enhanced_alert)

        return enhanced_alerts, pagination_info

    def format_hostnames_only(self, alerts: List[Dict[str, Any]]) -> str:
        """
        Format only the affected hostnames with alert creation times

        Args:
            alerts: List of alert dictionaries

        Returns:
            Formatted string with only hostname information
        """
        if not alerts:
            return "No alerts found - no hostnames to display."

        # Hostname analysis with creation times
        hostname_alerts = {}
        for alert in alerts:
            created_date = alert.get('createdDateTime', '')
            for evidence in alert.get('evidence', []):
                if evidence.get('@odata.type') == '#microsoft.graph.security.deviceEvidence':
                    hostname = evidence.get('deviceDnsName')
                    if hostname:
                        if hostname not in hostname_alerts:
                            hostname_alerts[hostname] = []
                        hostname_alerts[hostname].append(created_date)

        if not hostname_alerts:
            return "No hostnames found in alert evidence."

        output = []
        output.append(f"Affected Hostnames ({len(hostname_alerts)} unique hosts):")
        output.append("-" * 50)

        for hostname in sorted(hostname_alerts.keys()):
            # Get unique alert times for this hostname and format them
            alert_times = []
            for created_date in hostname_alerts[hostname]:
                if created_date:
                    try:
                        dt = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                        formatted_time = dt.strftime('%Y-%m-%d %H:%M')
                        if formatted_time not in alert_times:
                            alert_times.append(formatted_time)
                    except:
                        pass

            # Sort times and display
            if alert_times:
                alert_times.sort()
                times_str = ", ".join(alert_times)
                output.append(f"{hostname} (alerts: {times_str})")
            else:
                output.append(f"{hostname} (no valid timestamps)")

        return '\n'.join(output)

    def format_test_alerts(self, alerts: List[Dict[str, Any]]) -> str:
        """
        Format test alerts with enhanced information including match fields

        Args:
            alerts: List of alert dictionaries with match metadata

        Returns:
            Formatted string with table and statistics
        """
        if not alerts:
            return "No alerts found matching the test criteria."

        output = []
        output.append("F0RT1KA Test Alert Analysis")
        output.append("=" * 80)
        output.append("")

        # Table headers
        headers = ["Alert ID", "Title", "Severity", "Status", "Created", "Hostname", "Remediation", "Detection", "Match Fields"]
        col_widths = [36, 26, 8, 10, 16, 18, 12, 10, 20]

        # Header row
        header_row = "| " + " | ".join(f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers))) + " |"
        output.append(header_row)
        output.append("|" + "|".join("-" * (w + 2) for w in col_widths) + "|")

        # Data rows
        for alert in alerts:
            # Extract hostname from deviceEvidence and collect remediation/detection status
            hostname = "N/A"
            remediation_statuses = set()
            detection_statuses = set()

            for evidence in alert.get('evidence', []):
                if evidence.get('@odata.type') == '#microsoft.graph.security.deviceEvidence':
                    hostname = evidence.get('deviceDnsName', 'N/A')

                # Collect remediation status from all evidence types
                remediation_status = evidence.get('remediationStatus')
                if remediation_status:
                    remediation_statuses.add(remediation_status)

                # Collect detection status from file and process evidence
                detection_status = evidence.get('detectionStatus')
                if detection_status:
                    detection_statuses.add(detection_status)

            # Format date
            created_date = alert.get('createdDateTime', '')
            if created_date:
                try:
                    dt = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                    created_date = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    created_date = created_date[:16]  # Fallback to first 16 chars

            # Format status collections
            remediation_str = '/'.join(sorted(remediation_statuses)) if remediation_statuses else "N/A"
            detection_str = '/'.join(sorted(detection_statuses)) if detection_statuses else "N/A"

            # Prepare row data
            row_data = [
                alert.get('id', 'N/A')[:35],  # Truncate long IDs
                alert.get('title', 'N/A')[:25],  # Truncate long titles
                alert.get('severity', 'N/A').upper()[:7],
                alert.get('status', 'N/A')[:9],
                created_date,
                hostname[:17],  # Truncate long hostnames
                remediation_str[:11],  # Truncate long remediation status
                detection_str[:9],   # Truncate long detection status
                ', '.join(alert.get('_match_fields', []))[:19]  # Truncate long match lists
            ]

            # Create row
            row = "| " + " | ".join(f"{row_data[i]:<{col_widths[i]}}" for i in range(len(row_data))) + " |"
            output.append(row)

        output.append("")

        # Add statistics
        stats = self.generate_statistics(alerts)
        output.append(stats)

        return '\n'.join(output)

    def generate_statistics(self, alerts: List[Dict[str, Any]], pagination_info: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate summary statistics for test alerts

        Args:
            alerts: List of alert dictionaries with match metadata
            pagination_info: Optional pagination information from API calls

        Returns:
            Formatted statistics string
        """
        if not alerts:
            return "No statistics available."

        # Basic counts
        total_alerts = len(alerts)

        # Severity breakdown
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'unknown').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Status breakdown
        status_counts = {}
        for alert in alerts:
            status = alert.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1

        # Remediation status analysis
        remediation_counts = {}
        detection_counts = {}
        for alert in alerts:
            # Collect all remediation and detection statuses from evidence
            for evidence in alert.get('evidence', []):
                remediation_status = evidence.get('remediationStatus')
                if remediation_status:
                    remediation_counts[remediation_status] = remediation_counts.get(remediation_status, 0) + 1

                detection_status = evidence.get('detectionStatus')
                if detection_status:
                    detection_counts[detection_status] = detection_counts.get(detection_status, 0) + 1

        # Match field analysis
        field_matches = {}
        total_matches = 0
        for alert in alerts:
            match_fields = alert.get('_match_fields', [])
            total_matches += len(match_fields)
            for field in match_fields:
                field_matches[field] = field_matches.get(field, 0) + 1

        # Hostname analysis with creation times
        hostname_alerts = {}
        for alert in alerts:
            created_date = alert.get('createdDateTime', '')
            for evidence in alert.get('evidence', []):
                if evidence.get('@odata.type') == '#microsoft.graph.security.deviceEvidence':
                    hostname = evidence.get('deviceDnsName')
                    if hostname:
                        if hostname not in hostname_alerts:
                            hostname_alerts[hostname] = []
                        hostname_alerts[hostname].append(created_date)

        # Time range analysis
        dates = []
        for alert in alerts:
            created_date = alert.get('createdDateTime', '')
            if created_date:
                try:
                    dt = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                    dates.append(dt)
                except:
                    pass

        # Build statistics output
        stats = []
        stats.append("STATISTICS SUMMARY")
        stats.append("-" * 50)
        stats.append(f"Total Alerts Found: {total_alerts}")
        stats.append(f"Total Match Instances: {total_matches}")
        stats.append(f"Unique Hosts Affected: {len(hostname_alerts)}")

        if dates:
            min_date = min(dates).strftime('%Y-%m-%d %H:%M')
            max_date = max(dates).strftime('%Y-%m-%d %H:%M')
            stats.append(f"Date Range: {min_date} to {max_date}")

        stats.append("")
        stats.append("Severity Breakdown:")
        for severity, count in sorted(severity_counts.items()):
            percentage = (count / total_alerts) * 100
            stats.append(f"  {severity.capitalize()}: {count} ({percentage:.1f}%)")

        stats.append("")
        stats.append("Status Breakdown:")
        for status, count in sorted(status_counts.items()):
            percentage = (count / total_alerts) * 100
            stats.append(f"  {status}: {count} ({percentage:.1f}%)")

        if remediation_counts:
            stats.append("")
            stats.append("Remediation Status Breakdown:")
            total_remediation = sum(remediation_counts.values())
            for status, count in sorted(remediation_counts.items()):
                percentage = (count / total_remediation) * 100
                stats.append(f"  {status}: {count} evidence items ({percentage:.1f}%)")

        if detection_counts:
            stats.append("")
            stats.append("Detection Status Breakdown:")
            total_detection = sum(detection_counts.values())
            for status, count in sorted(detection_counts.items()):
                percentage = (count / total_detection) * 100
                stats.append(f"  {status}: {count} evidence items ({percentage:.1f}%)")

        stats.append("")
        stats.append("Match Field Distribution:")
        for field, count in sorted(field_matches.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_matches) * 100
            stats.append(f"  {field}: {count} matches ({percentage:.1f}%)")

        if hostname_alerts:
            stats.append("")
            stats.append("Affected Hostnames:")
            for hostname in sorted(hostname_alerts.keys()):
                # Get unique alert times for this hostname and format them
                alert_times = []
                for created_date in hostname_alerts[hostname]:
                    if created_date:
                        try:
                            dt = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                            formatted_time = dt.strftime('%Y-%m-%d %H:%M')
                            if formatted_time not in alert_times:
                                alert_times.append(formatted_time)
                        except:
                            pass

                # Sort times and display
                if alert_times:
                    alert_times.sort()
                    times_str = ", ".join(alert_times)
                    stats.append(f"  - {hostname} (alerts: {times_str})")
                else:
                    stats.append(f"  - {hostname} (no valid timestamps)")

        # Add pagination information if available
        if pagination_info:
            stats.append("")
            stats.append("Pagination Information:")
            stats.append(f"  Pages fetched: {pagination_info['pages']}")
            stats.append(f"  Total API calls: {pagination_info['api_calls']}")
            stats.append(f"  Total results retrieved: {pagination_info['total_results']}")

            if pagination_info.get('truncated'):
                stats.append("  ⚠️ Results truncated due to max_results limit")
            elif pagination_info.get('next_link_available'):
                stats.append("  ℹ️ More results may be available")

            if pagination_info['pages'] > 1:
                stats.append(f"  ✓ Used pagination to retrieve complete results")
            else:
                stats.append("  ℹ️ Single page result - consider using --fetch-all for complete data")

        return '\n'.join(stats)

    def format_alerts(self, alerts: List[Dict[str, Any]], format_type: str = 'table') -> str:
        """Format alerts for display"""
        if not alerts:
            return "No alerts found matching the search criteria."

        if format_type == 'json':
            return json.dumps(alerts, indent=2, default=str)

        elif format_type == 'csv':
            import csv
            import io

            output = io.StringIO()
            writer = csv.writer(output)

            # Headers
            writer.writerow(['ID', 'Title', 'Severity', 'Status', 'Created', 'File Paths'])

            for alert in alerts:
                file_paths = []
                for evidence in alert.get('evidence', []):
                    file_path = ""
                    # Check fileEvidence
                    if evidence.get('@odata.type') == '#microsoft.graph.security.fileEvidence':
                        file_details = evidence.get('fileDetails') or {}
                        file_path = file_details.get('filePath', '')
                    # Check processEvidence
                    elif evidence.get('@odata.type') == '#microsoft.graph.security.processEvidence':
                        image_file = evidence.get('imageFile') or {}
                        file_path = image_file.get('filePath', '')
                        file_name = image_file.get('fileName', '')
                        if file_path and file_name:
                            file_path = f"{file_path}\\{file_name}"

                    if file_path:
                        file_paths.append(file_path)

                writer.writerow([
                    alert.get('id', ''),
                    alert.get('title', ''),
                    alert.get('severity', ''),
                    alert.get('status', ''),
                    alert.get('createdDateTime', ''),
                    '; '.join(file_paths)
                ])

            return output.getvalue()

        else:  # table format
            output = []
            output.append(f"Found {len(alerts)} alerts:")
            output.append("-" * 80)

            for alert in alerts:
                output.append(f"ID: {alert.get('id', 'N/A')}")
                output.append(f"Title: {alert.get('title', 'N/A')}")
                output.append(f"Severity: {alert.get('severity', 'N/A')}")
                output.append(f"Status: {alert.get('status', 'N/A')}")
                output.append(f"Created: {alert.get('createdDateTime', 'N/A')}")

                # Extract file paths from evidence
                file_paths = []
                for evidence in alert.get('evidence', []):
                    file_path = ""
                    # Check fileEvidence
                    if evidence.get('@odata.type') == '#microsoft.graph.security.fileEvidence':
                        file_details = evidence.get('fileDetails') or {}
                        file_path = file_details.get('filePath', '')
                    # Check processEvidence
                    elif evidence.get('@odata.type') == '#microsoft.graph.security.processEvidence':
                        image_file = evidence.get('imageFile') or {}
                        file_path = image_file.get('filePath', '')
                        file_name = image_file.get('fileName', '')
                        if file_path and file_name:
                            file_path = f"{file_path}\\{file_name}"

                    if file_path:
                        file_paths.append(file_path)

                if file_paths:
                    output.append(f"File Paths: {', '.join(file_paths)}")

                output.append("-" * 80)

            return '\n'.join(output)

    def prepare_pdf_data(self, alerts: List[Dict[str, Any]],
                        query_params: Dict[str, Any],
                        pagination_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Prepare data structure for PDF report generation"""

        # Calculate comprehensive statistics
        total_alerts = len(alerts)

        # Severity breakdown
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'unknown').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Remediation status analysis
        remediation_counts = {}
        detection_counts = {}
        for alert in alerts:
            for evidence in alert.get('evidence', []):
                remediation_status = evidence.get('remediationStatus')
                if remediation_status:
                    remediation_counts[remediation_status] = remediation_counts.get(remediation_status, 0) + 1

                detection_status = evidence.get('detectionStatus')
                if detection_status:
                    detection_counts[detection_status] = detection_counts.get(detection_status, 0) + 1

        # Host analysis with creation times
        hostname_alerts = {}
        for alert in alerts:
            created_date = alert.get('createdDateTime', '')
            for evidence in alert.get('evidence', []):
                if evidence.get('@odata.type') == '#microsoft.graph.security.deviceEvidence':
                    hostname = evidence.get('deviceDnsName')
                    if hostname:
                        if hostname not in hostname_alerts:
                            hostname_alerts[hostname] = []
                        hostname_alerts[hostname].append(created_date)

        # Match field analysis
        field_matches = {}
        total_matches = 0
        for alert in alerts:
            match_fields = alert.get('_match_fields', [])
            total_matches += len(match_fields)
            for field in match_fields:
                field_matches[field] = field_matches.get(field, 0) + 1

        # Prepare comprehensive data structure
        pdf_data = {
            'alerts': alerts,
            'query_params': query_params,
            'statistics': {
                'total_alerts': total_alerts,
                'unique_hosts': len(hostname_alerts),
                'total_matches': total_matches,
                'severity_breakdown': severity_counts,
                'remediation_breakdown': remediation_counts,
                'detection_breakdown': detection_counts,
                'field_matches': field_matches,
                'affected_hostnames': sorted(hostname_alerts.keys()),
                'pagination_info': pagination_info
            }
        }

        return pdf_data

    def generate_pdf_report(self, alerts: List[Dict[str, Any]],
                           query_params: Dict[str, Any],
                           pagination_info: Optional[Dict[str, Any]] = None,
                           output_file: str = "f0rt1ka_security_report.pdf") -> str:
        """Generate professional PDF security report"""
        try:
            # Import the PDF generator
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from pdf_report_generator import F0RT1KAPDFReport

            # Prepare data
            pdf_data = self.prepare_pdf_data(alerts, query_params, pagination_info)

            # Generate report
            generator = F0RT1KAPDFReport()
            result_file = generator.generate_report(
                pdf_data['alerts'],
                pdf_data['query_params'],
                pdf_data['statistics'],
                output_file
            )

            return result_file

        except ImportError:
            raise ImportError("PDF generation requires reportlab library. Install with: pip install reportlab")
        except Exception as e:
            raise Exception(f"Failed to generate PDF report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Query Microsoft Defender 365 alerts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file-path "c:\\F0\\*"
  %(prog)s --search-term "malware" --severity high
  %(prog)s --file-path "*.exe" --days 7 --output alerts.json
  %(prog)s --test-alerts "F0" --hostnames  # Show only hostnames
        """
    )

    parser.add_argument('--file-path', help='File path pattern to search for')
    parser.add_argument('--search-term', help='General search term')
    parser.add_argument('--alert-id', help='Specific alert ID to retrieve')
    parser.add_argument('--test-alerts', help='Search for string in filePath, fileName, processCommandLine, and parentProcessCommandLine fields')
    parser.add_argument('--test-alerts-sha1', help='Search for alerts matching SHA1 hash in imageFile.sha1 and fileDetails.sha1 fields')
    parser.add_argument('--severity', choices=['low', 'medium', 'high', 'informational'],
                       help='Alert severity filter')
    parser.add_argument('--status', choices=['new', 'inProgress', 'resolved'],
                       help='Alert status filter')
    parser.add_argument('--days', type=int, default=30,
                       help='Number of days to look back (default: 30)')
    parser.add_argument('--limit', type=int, default=100,
                       help='Maximum number of alerts (default: 100)')
    parser.add_argument('--fetch-all', action='store_true',
                       help='Fetch all available results using pagination (may be slow for large result sets)')
    parser.add_argument('--page-size', type=int, default=100,
                       help='Number of results per API request (default: 100, max: 999)')
    parser.add_argument('--max-results', type=int,
                       help='Maximum total results to fetch when using --fetch-all (safety limit)')
    parser.add_argument('--show-pagination-info', action='store_true',
                       help='Display detailed pagination statistics in output')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--hostnames', action='store_true',
                       help='Show only affected hostnames with alert creation times')
    parser.add_argument('--output', help='Output file path (stdout if not specified)')

    args = parser.parse_args()

    # Validate pagination arguments
    if args.page_size > 999:
        print("Error: --page-size cannot exceed 999 (Microsoft Graph API limit)", file=sys.stderr)
        sys.exit(1)

    if args.fetch_all and args.max_results and args.max_results < args.limit:
        print("Warning: --max-results is less than --limit, some results may be missed")

    try:
        client = DefenderAlertQuery()

        # Handle hostnames-only output
        if args.hostnames:
            # Determine which search method to use
            if args.test_alerts:
                alerts, pagination_info = client.search_test_alerts(
                    search_term=args.test_alerts,
                    days=args.days,
                    limit=args.limit,
                    fetch_all=getattr(args, 'fetch_all', False),
                    page_size=getattr(args, 'page_size', 100),
                    max_results=getattr(args, 'max_results', None),
                    show_progress=True
                )
            elif args.test_alerts_sha1:
                alerts, pagination_info = client.search_test_alerts_sha1(
                    sha1_hash=args.test_alerts_sha1,
                    days=args.days,
                    limit=args.limit,
                    fetch_all=getattr(args, 'fetch_all', False),
                    page_size=getattr(args, 'page_size', 100),
                    max_results=getattr(args, 'max_results', None),
                    show_progress=True
                )
            else:
                alerts, pagination_info = client.search_alerts(
                    file_path=args.file_path,
                    search_term=args.search_term,
                    alert_id=args.alert_id,
                    severity=args.severity,
                    status=args.status,
                    days=args.days,
                    limit=args.limit,
                    fetch_all=getattr(args, 'fetch_all', False),
                    page_size=getattr(args, 'page_size', 100),
                    max_results=getattr(args, 'max_results', None),
                    show_progress=True
                )

            formatted_output = client.format_hostnames_only(alerts)

        # Handle test-alerts workflow
        elif args.test_alerts:
            alerts, pagination_info = client.search_test_alerts(
                search_term=args.test_alerts,
                days=args.days,
                limit=args.limit,
                fetch_all=getattr(args, 'fetch_all', False),
                page_size=getattr(args, 'page_size', 100),
                max_results=getattr(args, 'max_results', None),
                show_progress=True
            )
            if args.format == 'json':
                formatted_output = client.format_alerts(alerts, 'json')
            else:
                formatted_output = client.format_test_alerts(alerts)
                if getattr(args, 'show_pagination_info', False) and pagination_info:
                    formatted_output += "\n\n" + client.generate_statistics(alerts, pagination_info)
        # Handle test-alerts-sha1 workflow
        elif args.test_alerts_sha1:
            alerts, pagination_info = client.search_test_alerts_sha1(
                sha1_hash=args.test_alerts_sha1,
                days=args.days,
                limit=args.limit,
                fetch_all=getattr(args, 'fetch_all', False),
                page_size=getattr(args, 'page_size', 100),
                max_results=getattr(args, 'max_results', None),
                show_progress=True
            )
            if args.format == 'json':
                formatted_output = client.format_alerts(alerts, 'json')
            else:
                formatted_output = client.format_test_alerts(alerts)
                if getattr(args, 'show_pagination_info', False) and pagination_info:
                    formatted_output += "\n\n" + client.generate_statistics(alerts, pagination_info)
        else:
            # Handle regular workflow
            alerts, pagination_info = client.search_alerts(
                file_path=args.file_path,
                search_term=args.search_term,
                alert_id=args.alert_id,
                severity=args.severity,
                status=args.status,
                days=args.days,
                limit=args.limit,
                fetch_all=getattr(args, 'fetch_all', False),
                page_size=getattr(args, 'page_size', 100),
                max_results=getattr(args, 'max_results', None),
                show_progress=True
            )
            formatted_output = client.format_alerts(alerts, args.format)

            # Add pagination info for regular search if requested
            if getattr(args, 'show_pagination_info', False) and pagination_info and args.format == 'table':
                pagination_stats = client.generate_statistics(alerts, pagination_info)
                formatted_output += "\n\n" + pagination_stats


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