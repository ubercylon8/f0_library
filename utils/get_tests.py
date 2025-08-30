#!/usr/bin/env python3
"""
F0RT1KA Get Tests Utility

Fast Python script to display F0RT1KA security tests in a formatted table.
Replaces the slow bash-based get-tests command for better performance.

Usage:
    python3 utils/get_tests.py [page_number]

Examples:
    python3 utils/get_tests.py        # Show first page
    python3 utils/get_tests.py 2      # Show page 2
"""

import os
import sys
import re
import glob
from pathlib import Path
from datetime import datetime


class TestsDisplay:
    def __init__(self, tests_per_page=10):
        self.tests_per_page = tests_per_page
        self.tests_source_dir = Path("tests_source")
        
    def get_test_name(self, uuid):
        """Extract test name from *_info.md files"""
        try:
            info_files = list(self.tests_source_dir.glob(f"{uuid}/*_info.md"))
            if info_files:
                info_file = info_files[0]
                with open(info_file, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    # Remove markdown heading formatting
                    return first_line.lstrip('# ').rstrip()
            return "No info card found"
        except Exception:
            return "Error reading info card"
    
    def get_mod_time(self, uuid):
        """Get directory modification time"""
        try:
            test_dir = self.tests_source_dir / uuid
            if test_dir.exists():
                mod_time = test_dir.stat().st_mtime
                return datetime.fromtimestamp(mod_time).strftime("%Y-%m-%d %H:%M")
            return "Unknown"
        except Exception:
            return "Unknown"
    
    def scan_tests(self):
        """Scan for valid UUID test directories"""
        uuid_pattern = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
        
        if not self.tests_source_dir.exists():
            return []
        
        test_uuids = []
        for item in self.tests_source_dir.iterdir():
            if item.is_dir() and uuid_pattern.match(item.name):
                test_uuids.append(item.name)
        
        return sorted(test_uuids)
    
    def print_table_header(self):
        """Print formatted table header"""
        print("+" + "-" * 38 + "+" + "-" * 50 + "+" + "-" * 17 + "+")
        print(f"| {'Test UUID':<36} | {'Test Name':<48} | {'Last Modified':<15} |")
        print("+" + "-" * 38 + "+" + "-" * 50 + "+" + "-" * 17 + "+")
    
    def print_table_footer(self):
        """Print formatted table footer"""
        print("+" + "-" * 38 + "+" + "-" * 50 + "+" + "-" * 17 + "+")
    
    def print_test_row(self, uuid, test_name, mod_time):
        """Print a single test row"""
        # Truncate test name if too long
        if len(test_name) > 48:
            test_name = test_name[:45] + "..."
        
        print(f"| {uuid:<36} | {test_name:<48} | {mod_time:<15} |")
    
    def display_tests(self, page=1):
        """Display tests with pagination"""
        print("🔍 Scanning tests_source/ directory...")
        
        test_uuids = self.scan_tests()
        total_tests = len(test_uuids)
        
        if total_tests == 0:
            print("❌ No tests found in tests_source/ directory")
            return False
        
        # Calculate pagination
        total_pages = (total_tests + self.tests_per_page - 1) // self.tests_per_page
        
        # Validate page number
        if page < 1 or page > total_pages:
            print(f"❌ Invalid page number. Please use a number between 1 and {total_pages}")
            print(f"Total tests: {total_tests}")
            return False
        
        # Calculate indices
        start_idx = (page - 1) * self.tests_per_page
        end_idx = min(start_idx + self.tests_per_page, total_tests)
        
        # Display header
        print()
        print("📋 F0RT1KA Security Tests")
        print(f"Page {page} of {total_pages} | Showing tests {start_idx + 1}-{end_idx} of {total_tests}")
        print()
        
        # Display table
        self.print_table_header()
        
        for i in range(start_idx, end_idx):
            uuid = test_uuids[i]
            test_name = self.get_test_name(uuid)
            mod_time = self.get_mod_time(uuid)
            self.print_test_row(uuid, test_name, mod_time)
        
        self.print_table_footer()
        print()
        
        # Navigation info
        if total_pages > 1:
            print("📖 Navigation:")
            if page > 1:
                print(f"   Previous page: python3 utils/get_tests.py {page - 1}")
            if page < total_pages:
                print(f"   Next page: python3 utils/get_tests.py {page + 1}")
            print()
        
        # Tips
        print("💡 Tips:")
        print("   • Use '/stage-test <uuid> <cert>' to build and sign a test")
        print("   • Use '/check-test <uuid>' to deploy and run a test")
        print("   • Test info cards contain detailed MITRE ATT&CK mappings")
        print()
        print("✅ Scan complete!")
        
        return True


def main():
    """Main function"""
    # Parse command line arguments
    page = 1
    if len(sys.argv) > 1:
        try:
            page = int(sys.argv[1])
        except ValueError:
            print("❌ Invalid page number. Please provide a valid integer.")
            sys.exit(1)
    
    # Change to script directory for relative path resolution
    script_dir = Path(__file__).parent.parent
    os.chdir(script_dir)
    
    # Create and run tests display
    display = TestsDisplay()
    success = display.display_tests(page)
    
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()