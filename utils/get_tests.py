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
        self.categories = ["intel-driven", "phase-aligned"]

    def get_test_name(self, category, uuid):
        """Extract test name from *_info.md files"""
        try:
            info_files = list(self.tests_source_dir.glob(f"{category}/{uuid}/*_info.md"))
            if info_files:
                info_file = info_files[0]
                with open(info_file, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    # Remove markdown heading formatting
                    return first_line.lstrip('# ').rstrip()
            return "No info card found"
        except Exception:
            return "Error reading info card"

    def get_mod_time(self, category, uuid):
        """Get directory modification time"""
        try:
            test_dir = self.tests_source_dir / category / uuid
            if test_dir.exists():
                mod_time = test_dir.stat().st_mtime
                return datetime.fromtimestamp(mod_time).strftime("%Y-%m-%d %H:%M")
            return "Unknown"
        except Exception:
            return "Unknown"

    def scan_tests(self):
        """Scan for valid UUID test directories in all categories"""
        uuid_pattern = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')

        if not self.tests_source_dir.exists():
            return []

        tests = []
        for category in self.categories:
            category_dir = self.tests_source_dir / category
            if category_dir.exists():
                for item in category_dir.iterdir():
                    if item.is_dir() and uuid_pattern.match(item.name):
                        tests.append((category, item.name))

        # Sort by category, then UUID
        return sorted(tests, key=lambda x: (x[0], x[1]))

    def print_table_header(self):
        """Print formatted table header"""
        print("+" + "-" * 16 + "+" + "-" * 38 + "+" + "-" * 42 + "+" + "-" * 17 + "+")
        print(f"| {'Category':<14} | {'Test UUID':<36} | {'Test Name':<40} | {'Last Modified':<15} |")
        print("+" + "-" * 16 + "+" + "-" * 38 + "+" + "-" * 42 + "+" + "-" * 17 + "+")

    def print_table_footer(self):
        """Print formatted table footer"""
        print("+" + "-" * 16 + "+" + "-" * 38 + "+" + "-" * 42 + "+" + "-" * 17 + "+")

    def print_test_row(self, category, uuid, test_name, mod_time):
        """Print a single test row"""
        # Truncate test name if too long
        if len(test_name) > 40:
            test_name = test_name[:37] + "..."

        # Shorten category for display
        cat_display = category[:14] if len(category) <= 14 else category[:11] + "..."

        print(f"| {cat_display:<14} | {uuid:<36} | {test_name:<40} | {mod_time:<15} |")

    def display_tests(self, page=1):
        """Display tests with pagination"""
        print("🔍 Scanning tests_source/{intel-driven,phase-aligned}/ directories...")

        tests = self.scan_tests()
        total_tests = len(tests)

        if total_tests == 0:
            print("❌ No tests found in tests_source/ directories")
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

        # Count tests per category
        intel_count = len([t for t in tests if t[0] == "intel-driven"])
        phase_count = len([t for t in tests if t[0] == "phase-aligned"])

        # Display header
        print()
        print("📋 F0RT1KA Security Tests")
        print(f"Page {page} of {total_pages} | Showing tests {start_idx + 1}-{end_idx} of {total_tests}")
        print(f"Categories: intel-driven ({intel_count}) | phase-aligned ({phase_count})")
        print()

        # Display table
        self.print_table_header()

        for i in range(start_idx, end_idx):
            category, uuid = tests[i]
            test_name = self.get_test_name(category, uuid)
            mod_time = self.get_mod_time(category, uuid)
            self.print_test_row(category, uuid, test_name, mod_time)

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
