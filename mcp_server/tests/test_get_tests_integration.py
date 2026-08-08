import subprocess
import sys
from f0_library_mcp.config import resolve_root
from f0_library_mcp.catalog import build_index

ROOT = resolve_root()


def test_get_tests_reports_full_corpus():
    """utils/get_tests.py must agree with the shared parser -- one parser, no drift."""
    proc = subprocess.run(
        [sys.executable, "utils/get_tests.py", "--count"],
        cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == str(len(build_index(ROOT).tests))


def test_get_tests_covers_all_three_categories():
    proc = subprocess.run(
        [sys.executable, "utils/get_tests.py", "--json"],
        cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    import json
    cats = {row["category"] for row in json.loads(proc.stdout)}
    assert cats == {"intel-driven", "cyber-hygiene", "mitre-top10"}
