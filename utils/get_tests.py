#!/usr/bin/env python3
"""F0RT1KA Get Tests Utility.

Thin presentation layer over the MCP server's catalog parser. Categories are
discovered from the filesystem, so this cannot drift out of sync with the
corpus the way the previous hardcoded category list did.
"""
import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "mcp_server" / "src"))


def _ensure_deps() -> None:
    """Make the catalog parser importable regardless of how we were launched.

    The parser depends on ``pydantic``, whose native ``pydantic_core`` extension
    is compiled per Python minor version. When this script runs inside the
    mcp_server venv (as the test suite does via ``sys.executable``) the deps are
    already satisfied — no-op. But ``/get-tests`` invokes the system ``python3``,
    which has no third-party packages and may be a different minor version than
    the venv, so path-splicing the venv site-packages would load an ABI-mismatched
    ``.so``. Instead, re-exec under the mcp_server venv's own interpreter, which
    is guaranteed ABI-compatible with its site-packages. Guarded against
    re-exec loops so a genuinely broken venv surfaces the real ImportError.
    """
    try:
        import pydantic  # noqa: F401
        return
    except ModuleNotFoundError:
        pass
    if os.environ.get("_F0_GET_TESTS_REEXEC"):
        return  # already re-exec'd once; let the import fail loudly below
    venv_python = REPO_ROOT / "mcp_server" / ".venv" / "bin" / "python"
    if venv_python.is_file() and Path(sys.executable).resolve() != venv_python.resolve():
        os.environ["_F0_GET_TESTS_REEXEC"] = "1"
        os.execv(str(venv_python), [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]])


_ensure_deps()

from f0_library_mcp.catalog import build_index  # noqa: E402

TESTS_PER_PAGE = 10


def rows():
    index = build_index(REPO_ROOT)
    return [
        {
            "uuid": t.uuid,
            "category": t.category,
            "name": t.name or "(no name in header)",
            "techniques": ",".join(t.techniques),
            "severity": t.severity,
            "score": t.score,
        }
        for t in sorted(index.tests, key=lambda t: (t.category, t.name))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="List F0RT1KA security tests")
    parser.add_argument("page", nargs="?", type=int, default=1)
    parser.add_argument("--count", action="store_true", help="print the test count only")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    data = rows()

    if args.count:
        print(len(data))
        return 0
    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    total_pages = max(1, (len(data) + TESTS_PER_PAGE - 1) // TESTS_PER_PAGE)
    page = min(max(args.page, 1), total_pages)
    start = (page - 1) * TESTS_PER_PAGE
    chunk = data[start:start + TESTS_PER_PAGE]

    print(f"{'UUID':<38} {'CATEGORY':<15} {'SEV':<9} {'SCORE':<6} NAME")
    print("-" * 110)
    for row in chunk:
        score = f"{row['score']:.1f}" if row["score"] is not None else "-"
        print(f"{row['uuid']:<38} {row['category']:<15} "
              f"{row['severity']:<9} {score:<6} {row['name'][:44]}")
    print(f"\nPage {page}/{total_pages} — {len(data)} tests total")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
