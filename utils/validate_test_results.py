#!/usr/bin/env python3
"""
F0RT1KA Test Results Validator
Validates test result JSON files against schema v2.0

Usage:
    python validate_test_results.py <json_file>
    python validate_test_results.py --directory <directory>
    python validate_test_results.py --all  # Validate all in build/

Exit codes:
    0 - All validations passed
    1 - Validation errors found
    2 - File/schema not found
"""

import json
import sys
import os
import glob
from pathlib import Path
from typing import List, Dict, Any, Tuple
import argparse

# Try to import jsonschema, provide helpful error if not available
try:
    import jsonschema
    from jsonschema import validate, ValidationError, SchemaError
except ImportError:
    print("ERROR: jsonschema module not found")
    print("Install with: pip install jsonschema")
    sys.exit(2)


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def find_schema_file() -> Path:
    """Locate the schema file in the repository"""
    # Try multiple possible locations
    possible_locations = [
        Path(__file__).parent.parent / "test-results-schema-v2.0.json",
        Path.cwd() / "test-results-schema-v2.0.json",
        Path("/home/ubercylon8/F0RT1KA/f0_library/test-results-schema-v2.0.json"),
    ]

    for loc in possible_locations:
        if loc.exists():
            return loc

    raise FileNotFoundError(
        "Could not find test-results-schema-v2.0.json\n"
        "Searched locations:\n" + "\n".join(f"  - {loc}" for loc in possible_locations)
    )


def load_schema() -> Dict[str, Any]:
    """Load the JSON schema"""
    schema_path = find_schema_file()
    print(f"{Colors.BLUE}Using schema: {schema_path}{Colors.END}")

    try:
        with open(schema_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"{Colors.RED}ERROR: Invalid JSON in schema file: {e}{Colors.END}")
        sys.exit(2)


def load_test_result(file_path: Path) -> Dict[str, Any]:
    """Load a test result JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {file_path}: {e}")


def validate_test_result(result: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate a test result against the schema

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []

    try:
        validate(instance=result, schema=schema)
        return True, []
    except ValidationError as e:
        # Extract detailed error information
        error_path = " -> ".join(str(p) for p in e.path) if e.path else "root"
        error_msg = f"Validation error at '{error_path}': {e.message}"
        errors.append(error_msg)

        # Add context if available
        if e.context:
            for ctx_err in e.context:
                ctx_path = " -> ".join(str(p) for p in ctx_err.path) if ctx_err.path else "root"
                errors.append(f"  Context at '{ctx_path}': {ctx_err.message}")

        return False, errors
    except SchemaError as e:
        errors.append(f"Schema error: {e.message}")
        return False, errors


def perform_additional_checks(result: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Perform additional logical validations beyond schema

    Returns:
        Tuple of (is_valid, warning_messages)
    """
    warnings = []

    # Check schema version
    if result.get('schemaVersion') != '2.0':
        warnings.append(f"Unexpected schema version: {result.get('schemaVersion')} (expected '2.0')")

    # Check exit code consistency with outcome
    exit_code = result.get('exitCode')
    outcome = result.get('outcome', {})
    protected = outcome.get('protected')

    if exit_code in [105, 126, 127] and not protected:
        warnings.append(f"Exit code {exit_code} indicates protection, but outcome.protected is False")
    elif exit_code == 101 and protected:
        warnings.append(f"Exit code 101 indicates unprotected, but outcome.protected is True")

    # Check technique arrays match for non-multi-stage
    if not result.get('isMultiStage'):
        metadata_techniques = set(result.get('testMetadata', {}).get('techniques', []))
        blocked = set(outcome.get('blockedTechniques', []))
        successful = set(outcome.get('successfulTechniques', []))

        if protected and metadata_techniques != blocked:
            warnings.append("For protected outcome, blocked techniques should match metadata techniques")
        elif not protected and metadata_techniques != successful:
            warnings.append("For unprotected outcome, successful techniques should match metadata techniques")

    # Check timestamps are in order
    start_time = result.get('startTime')
    end_time = result.get('endTime')
    if start_time and end_time:
        # Simple string comparison works for ISO 8601
        if start_time > end_time:
            warnings.append(f"Start time ({start_time}) is after end time ({end_time})")

    # Check metrics consistency
    metrics = result.get('metrics')
    if metrics:
        # Check phases count
        phases_count = len(result.get('phases', []))
        if metrics.get('totalPhases', 0) != phases_count:
            warnings.append(f"Metrics totalPhases ({metrics.get('totalPhases')}) doesn't match actual phases ({phases_count})")

        # Check files count
        files_count = len(result.get('filesDropped', []))
        if metrics.get('totalFilesDropped', 0) != files_count:
            warnings.append(f"Metrics totalFilesDropped ({metrics.get('totalFilesDropped')}) doesn't match actual files ({files_count})")

        # Check processes count
        processes_count = len(result.get('processesExecuted', []))
        if metrics.get('totalProcesses', 0) != processes_count:
            warnings.append(f"Metrics totalProcesses ({metrics.get('totalProcesses')}) doesn't match actual processes ({processes_count})")

    return len(warnings) == 0, warnings


def validate_file(file_path: Path, schema: Dict[str, Any], verbose: bool = False) -> bool:
    """
    Validate a single test result file

    Returns:
        True if validation passed, False otherwise
    """
    print(f"\n{Colors.BOLD}Validating: {file_path}{Colors.END}")

    try:
        # Load test result
        result = load_test_result(file_path)

        # Schema validation
        is_valid, errors = validate_test_result(result, schema)

        if not is_valid:
            print(f"{Colors.RED}✗ Schema validation FAILED{Colors.END}")
            for error in errors:
                print(f"  {Colors.RED}{error}{Colors.END}")
            return False

        print(f"{Colors.GREEN}✓ Schema validation passed{Colors.END}")

        # Additional checks
        checks_valid, warnings = perform_additional_checks(result)

        if warnings:
            print(f"{Colors.YELLOW}⚠ Warnings:{Colors.END}")
            for warning in warnings:
                print(f"  {Colors.YELLOW}{warning}{Colors.END}")

        if verbose:
            # Print summary
            print(f"\n{Colors.BLUE}Summary:{Colors.END}")
            print(f"  Schema Version: {result.get('schemaVersion')}")
            print(f"  Test ID: {result.get('testId')}")
            print(f"  Test Name: {result.get('testName')}")
            print(f"  Category: {result.get('testMetadata', {}).get('category')}")
            print(f"  Severity: {result.get('testMetadata', {}).get('severity')}")
            print(f"  Outcome: {'Protected' if result.get('outcome', {}).get('protected') else 'Unprotected'}")
            print(f"  Exit Code: {result.get('exitCode')}")

        return True

    except Exception as e:
        print(f"{Colors.RED}✗ Error: {e}{Colors.END}")
        return False


def find_test_results(directory: Path) -> List[Path]:
    """Find all test result JSON files in a directory"""
    return list(directory.glob("**/test_execution_log.json"))


def main():
    parser = argparse.ArgumentParser(
        description="Validate F0RT1KA test result JSON files against schema v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Validate single file
    python validate_test_results.py build/test-uuid/test_execution_log.json

    # Validate all files in directory
    python validate_test_results.py --directory build/

    # Validate all test results
    python validate_test_results.py --all

    # Verbose output
    python validate_test_results.py --all --verbose
        """
    )

    parser.add_argument('file', nargs='?', help='Path to test result JSON file')
    parser.add_argument('-d', '--directory', help='Validate all test_execution_log.json files in directory')
    parser.add_argument('-a', '--all', action='store_true', help='Validate all test results in build/')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output with test summary')

    args = parser.parse_args()

    # Determine what to validate
    files_to_validate = []

    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"{Colors.RED}ERROR: File not found: {file_path}{Colors.END}")
            sys.exit(2)
        files_to_validate.append(file_path)

    elif args.directory:
        dir_path = Path(args.directory)
        if not dir_path.is_dir():
            print(f"{Colors.RED}ERROR: Directory not found: {dir_path}{Colors.END}")
            sys.exit(2)
        files_to_validate = find_test_results(dir_path)
        if not files_to_validate:
            print(f"{Colors.YELLOW}No test_execution_log.json files found in {dir_path}{Colors.END}")
            sys.exit(0)

    elif args.all:
        # Look in build directory
        build_dir = Path(__file__).parent.parent / "build"
        if not build_dir.exists():
            print(f"{Colors.YELLOW}Build directory not found: {build_dir}{Colors.END}")
            sys.exit(0)
        files_to_validate = find_test_results(build_dir)
        if not files_to_validate:
            print(f"{Colors.YELLOW}No test results found in {build_dir}{Colors.END}")
            sys.exit(0)

    else:
        parser.print_help()
        sys.exit(1)

    # Load schema
    try:
        schema = load_schema()
    except Exception as e:
        print(f"{Colors.RED}ERROR: Failed to load schema: {e}{Colors.END}")
        sys.exit(2)

    # Validate all files
    print(f"\n{Colors.BOLD}Found {len(files_to_validate)} file(s) to validate{Colors.END}")

    results = []
    for file_path in files_to_validate:
        is_valid = validate_file(file_path, schema, args.verbose)
        results.append((file_path, is_valid))

    # Print summary
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}VALIDATION SUMMARY{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}")

    passed = sum(1 for _, valid in results if valid)
    failed = len(results) - passed

    print(f"Total files: {len(results)}")
    print(f"{Colors.GREEN}Passed: {passed}{Colors.END}")
    if failed > 0:
        print(f"{Colors.RED}Failed: {failed}{Colors.END}")
        print(f"\n{Colors.RED}Failed files:{Colors.END}")
        for file_path, is_valid in results:
            if not is_valid:
                print(f"  {Colors.RED}✗ {file_path}{Colors.END}")

    # Exit with appropriate code
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
