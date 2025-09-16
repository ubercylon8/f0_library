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
- Azure AD app registration with SecurityEvents.Read.All permission
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

    def search_alerts(self,
                     file_path: Optional[str] = None,
                     search_term: Optional[str] = None,
                     severity: Optional[str] = None,
                     status: Optional[str] = None,
                     days: int = 30,
                     limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search Microsoft Defender 365 alerts with filters

        Args:
            file_path: File path pattern to search for (supports wildcards)
            search_term: General search term across alert fields
            severity: Alert severity (low, medium, high, informational)
            status: Alert status (new, inProgress, resolved)
            days: Number of days to look back (default: 30)
            limit: Maximum number of alerts to return (default: 100)

        Returns:
            List of alert dictionaries
        """
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

        # File path filter - search in evidence file paths
        if file_path:
            # Escape single quotes and build contains filter
            escaped_path = file_path.replace("'", "''")
            filters.append(f"evidence/any(e: contains(e/fileDetails/filePath, '{escaped_path}'))")

        # General search term across multiple fields
        if search_term:
            escaped_term = search_term.replace("'", "''")
            search_filters = [
                f"contains(title, '{escaped_term}')",
                f"contains(description, '{escaped_term}')",
                f"evidence/any(e: contains(e/fileDetails/fileName, '{escaped_term}'))"
            ]
            filters.append(f"({' or '.join(search_filters)})")

        params = {
            '$top': limit,
            '$orderby': 'createdDateTime desc'
        }

        if filters:
            params['$filter'] = ' and '.join(filters)

        response = requests.get(url, headers=self._get_headers(), params=params)
        response.raise_for_status()

        return response.json().get('value', [])

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
                    if evidence.get('@odata.type') == '#microsoft.graph.security.fileEvidence':
                        file_path = evidence.get('fileDetails', {}).get('filePath', '')
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
                    if evidence.get('@odata.type') == '#microsoft.graph.security.fileEvidence':
                        file_path = evidence.get('fileDetails', {}).get('filePath', '')
                        if file_path:
                            file_paths.append(file_path)

                if file_paths:
                    output.append(f"File Paths: {', '.join(file_paths)}")

                output.append("-" * 80)

            return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description="Query Microsoft Defender 365 alerts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file-path "c:\\F0\\*"
  %(prog)s --search-term "malware" --severity high
  %(prog)s --file-path "*.exe" --days 7 --output alerts.json
        """
    )

    parser.add_argument('--file-path', help='File path pattern to search for')
    parser.add_argument('--search-term', help='General search term')
    parser.add_argument('--severity', choices=['low', 'medium', 'high', 'informational'],
                       help='Alert severity filter')
    parser.add_argument('--status', choices=['new', 'inProgress', 'resolved'],
                       help='Alert status filter')
    parser.add_argument('--days', type=int, default=30,
                       help='Number of days to look back (default: 30)')
    parser.add_argument('--limit', type=int, default=100,
                       help='Maximum number of alerts (default: 100)')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--output', help='Output file path (stdout if not specified)')

    args = parser.parse_args()

    try:
        client = DefenderAlertQuery()

        alerts = client.search_alerts(
            file_path=args.file_path,
            search_term=args.search_term,
            severity=args.severity,
            status=args.status,
            days=args.days,
            limit=args.limit
        )

        formatted_output = client.format_alerts(alerts, args.format)

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