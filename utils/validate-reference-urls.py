#!/usr/bin/env python3
"""
Validate URLs in _references.md files across all F0RT1KA tests.

Checks each URL for:
- HTTP status code (200 = ok, 301/302 = redirect, 404 = broken, timeout)
- MITRE ATT&CK technique URL correctness (validates T-code format)
- Completely unreachable hosts

Usage:
    python3 utils/validate-reference-urls.py [--fix] [--uuid UUID]
"""

import os
import re
import sys
import json
import argparse
import urllib.request
import urllib.error
import ssl
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# Skip SSL verification for speed (we're just checking existence)
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def extract_urls_from_file(filepath: Path) -> list[dict]:
    """Extract all URLs and their context from a references file."""
    content = filepath.read_text(encoding="utf-8")
    results = []

    # Match markdown links [text](url)
    for match in re.finditer(r'\[([^\]]*)\]\((https?://[^)]+)\)', content):
        results.append({
            "title": match.group(1),
            "url": match.group(2),
            "line": content[:match.start()].count('\n') + 1,
            "match_text": match.group(0),
        })

    # Match bare URLs in table cells: | url |
    for match in re.finditer(r'\|\s*(https?://[^\s|]+)\s*\|', content):
        url = match.group(1)
        # Skip if already captured as markdown link
        if any(r["url"] == url for r in results):
            continue
        results.append({
            "title": "(table cell)",
            "url": url,
            "line": content[:match.start()].count('\n') + 1,
            "match_text": match.group(0),
        })

    return results


def check_url(url: str, timeout: int = 10) -> dict:
    """Check if a URL is reachable. Returns status info."""
    # Special case: MITRE ATT&CK URLs — validate format first
    mitre_match = re.match(r'https://attack\.mitre\.org/techniques/(T\d{4}(?:/\d{3})?)/', url)
    if mitre_match:
        technique = mitre_match.group(1)
        # Validate technique format
        if not re.match(r'^T\d{4}(/\d{3})?$', technique):
            return {"url": url, "status": "invalid_format", "code": 0, "error": f"Invalid technique format: {technique}"}

    # Special case: "Not available" or placeholder
    if url in ("Not available", "N/A", ""):
        return {"url": url, "status": "placeholder", "code": 0, "error": None}

    try:
        req = urllib.request.Request(url, method='HEAD', headers={
            'User-Agent': 'Mozilla/5.0 (compatible; F0RT1KA-URLValidator/1.0)',
            'Accept': 'text/html,application/xhtml+xml',
        })
        resp = urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)
        return {"url": url, "status": "ok", "code": resp.status, "error": None}
    except urllib.error.HTTPError as e:
        # Some servers block HEAD, try GET
        if e.code == 405 or e.code == 403:
            try:
                req = urllib.request.Request(url, method='GET', headers={
                    'User-Agent': 'Mozilla/5.0 (compatible; F0RT1KA-URLValidator/1.0)',
                    'Accept': 'text/html,application/xhtml+xml',
                })
                resp = urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)
                return {"url": url, "status": "ok", "code": resp.status, "error": None}
            except urllib.error.HTTPError as e2:
                return {"url": url, "status": "error", "code": e2.code, "error": str(e2)}
            except Exception as e2:
                return {"url": url, "status": "error", "code": 0, "error": str(e2)}
        return {"url": url, "status": "error", "code": e.code, "error": str(e)}
    except urllib.error.URLError as e:
        return {"url": url, "status": "unreachable", "code": 0, "error": str(e.reason)}
    except TimeoutError:
        return {"url": url, "status": "timeout", "code": 0, "error": "Connection timed out"}
    except Exception as e:
        return {"url": url, "status": "error", "code": 0, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Validate URLs in _references.md files")
    parser.add_argument("--uuid", type=str, help="Check a specific test UUID only")
    parser.add_argument("--fix", action="store_true", help="Output fix report as JSON")
    parser.add_argument("--threads", type=int, default=8, help="Concurrent URL checks (default: 8)")
    args = parser.parse_args()

    repo_root = Path(__file__).parent.parent
    tests_dir = repo_root / "tests_source"
    categories = ["intel-driven", "mitre-top10"]

    print("F0RT1KA Reference URL Validator")
    print("=" * 60)

    # Collect all URLs to check
    all_urls = []  # list of {file, uuid, title, url, line}
    files_checked = 0

    for category in categories:
        cat_dir = tests_dir / category
        if not cat_dir.exists():
            continue
        for test_dir in sorted(cat_dir.iterdir()):
            if not test_dir.is_dir():
                continue
            uuid = test_dir.name
            if args.uuid and uuid != args.uuid:
                continue

            refs_file = test_dir / f"{uuid}_references.md"
            if not refs_file.exists():
                continue

            files_checked += 1
            urls = extract_urls_from_file(refs_file)
            for u in urls:
                u["file"] = str(refs_file)
                u["uuid"] = uuid
                u["category"] = category
            all_urls.extend(urls)

    # Deduplicate URLs for checking (same URL may appear in multiple files)
    unique_urls = list({u["url"] for u in all_urls})
    print(f"\nFiles scanned: {files_checked}")
    print(f"Total URL instances: {len(all_urls)}")
    print(f"Unique URLs to check: {len(unique_urls)}")
    print(f"\nChecking URLs with {args.threads} threads...\n")

    # Check URLs in parallel
    url_results = {}
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(check_url, url): url for url in unique_urls}
        done = 0
        for future in as_completed(future_to_url):
            done += 1
            result = future.result()
            url_results[result["url"]] = result
            status_char = "." if result["status"] == "ok" else "X"
            if done % 20 == 0 or result["status"] != "ok":
                if result["status"] != "ok":
                    print(f"  [{done}/{len(unique_urls)}] {status_char} {result['url'][:80]}")
                    print(f"           → {result['status']} (code={result['code']}) {result.get('error', '')[:60]}")

    # Report results
    print(f"\n{'=' * 60}")
    print("RESULTS")
    print(f"{'=' * 60}\n")

    ok_count = sum(1 for r in url_results.values() if r["status"] == "ok")
    broken = [(u, url_results[u["url"]]) for u in all_urls if url_results[u["url"]]["status"] != "ok"]

    print(f"  OK: {ok_count}/{len(unique_urls)} unique URLs")
    print(f"  Broken/Unreachable: {len(set(u['url'] for _, r in broken for u in [_]))}")
    print()

    if broken:
        print("BROKEN URLs by test:")
        print("-" * 60)

        # Group by uuid
        by_uuid = {}
        for entry, result in broken:
            uuid = entry["uuid"]
            if uuid not in by_uuid:
                by_uuid[uuid] = []
            by_uuid[uuid].append((entry, result))

        for uuid in sorted(by_uuid.keys()):
            items = by_uuid[uuid]
            print(f"\n  {uuid[:8]}... ({items[0][0]['category']})")
            for entry, result in items:
                print(f"    Line {entry['line']:3d}: {result['status']} (code={result['code']})")
                print(f"             URL: {entry['url'][:90]}")
                print(f"             Title: {entry['title'][:60]}")
                if result.get("error"):
                    print(f"             Error: {result['error'][:60]}")

    # Output JSON fix report
    if args.fix and broken:
        fix_report = []
        for entry, result in broken:
            fix_report.append({
                "uuid": entry["uuid"],
                "category": entry["category"],
                "file": entry["file"],
                "line": entry["line"],
                "title": entry["title"],
                "url": entry["url"],
                "status": result["status"],
                "code": result["code"],
                "error": str(result.get("error", "")),
            })

        report_path = repo_root / "utils" / "broken-urls-report.json"
        report_path.write_text(json.dumps(fix_report, indent=2), encoding="utf-8")
        print(f"\nFix report saved to: {report_path}")

    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
