#!/usr/bin/env python3
"""
Generate retroactive _references.md files for existing F0RT1KA tests.

Extracts data from existing info.md References sections and Go metadata headers
to produce structured provenance files matching the new references template.

Usage:
    python3 utils/generate-retroactive-references.py [--dry-run] [--uuid UUID]
"""

import os
import re
import sys
import argparse
from pathlib import Path
from datetime import datetime


def extract_go_metadata(go_file: Path) -> dict:
    """Extract metadata from Go file header comment block."""
    result = {
        "name": None,
        "techniques": [],
        "tactics": [],
        "threat_actor": None,
        "created": None,
        "source_url": None,
    }
    if not go_file.exists():
        return result

    content = go_file.read_text(encoding="utf-8")[:4000]

    name_match = re.search(r'^NAME:\s*(.+)$', content, re.MULTILINE)
    if name_match:
        result["name"] = name_match.group(1).strip()

    tech_match = re.search(r'^TECHNIQUES?:\s*(.+)$', content, re.MULTILINE)
    if tech_match:
        result["techniques"] = [t.strip() for t in tech_match.group(1).split(',') if t.strip()]

    tactics_match = re.search(r'^TACTICS?:\s*(.+)$', content, re.MULTILINE)
    if tactics_match:
        result["tactics"] = [t.strip() for t in tactics_match.group(1).split(',') if t.strip()]

    threat_match = re.search(r'^THREAT_ACTOR:\s*(.+)$', content, re.MULTILINE)
    if threat_match:
        val = threat_match.group(1).strip()
        if val.lower() not in ["n/a", "none", ""]:
            result["threat_actor"] = val

    created_match = re.search(r'^CREATED:\s*(\d{4}-\d{2}-\d{2})$', content, re.MULTILINE)
    if created_match:
        result["created"] = created_match.group(1)

    source_match = re.search(r'^SOURCE_URL:\s*(.+)$', content, re.MULTILINE)
    if source_match:
        val = source_match.group(1).strip()
        if val.lower() not in ["n/a", "none", ""]:
            result["source_url"] = val

    return result


def extract_references_from_info(info_file: Path) -> list[dict]:
    """Extract references from info.md ## References section."""
    if not info_file.exists():
        return []

    content = info_file.read_text(encoding="utf-8")

    # Find ## References section
    refs_match = re.search(r'^## References\s*\n(.*?)(?=^## |\Z)', content, re.MULTILINE | re.DOTALL)
    if not refs_match:
        # Try ## Threat Intelligence Sources
        refs_match = re.search(r'^## Threat Intelligence Sources?\s*\n(.*?)(?=^## |\Z)', content, re.MULTILINE | re.DOTALL)

    if not refs_match:
        return []

    refs_text = refs_match.group(1).strip()
    references = []

    # Parse markdown links: - [Title](URL)
    link_pattern = re.compile(r'[-*]\s*\[([^\]]+)\]\(([^)]+)\)')
    for match in link_pattern.finditer(refs_text):
        title = match.group(1).strip()
        url = match.group(2).strip()
        ref_type = classify_reference(title, url)
        references.append({"title": title, "url": url, "type": ref_type})

    # Parse plain text references: - Text with URL
    # Also catch lines like "- SafePay Technical Report" without links
    plain_lines = refs_text.split('\n')
    for line in plain_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Skip lines already parsed as markdown links
        if link_pattern.search(line):
            continue
        # Plain bullet point
        if line.startswith(('-', '*')):
            text = line.lstrip('-* ').strip()
            if text:
                references.append({"title": text, "url": "Not available", "type": classify_reference(text, "")})

    return references


def classify_reference(title: str, url: str) -> str:
    """Classify a reference by its title/URL into a type."""
    title_lower = title.lower()
    url_lower = url.lower()

    if 'attack.mitre.org' in url_lower:
        return "MITRE ATT&CK"
    if 'cve-' in title_lower or 'cve-' in url_lower:
        return "CVE Advisory"
    if 'cisa' in title_lower or 'cisa.gov' in url_lower:
        return "Government Advisory"
    if 'fbi' in title_lower or 'ic3' in title_lower:
        return "Government Advisory"
    if 'ncsc' in title_lower:
        return "Government Advisory"
    if 'advisory' in title_lower:
        return "Security Advisory"
    if 'github.com' in url_lower:
        return "Tool Repository"
    if 'blog' in url_lower or 'blog' in title_lower:
        return "Blog Post"
    if 'microsoft.com/security' in url_lower or 'microsoft threat' in title_lower:
        return "Threat Intelligence"
    if any(vendor in title_lower for vendor in ['mandiant', 'crowdstrike', 'secureworks', 'palo alto', 'sophos', 'trend micro', 'kaspersky', 'sentinel', 'elastic']):
        return "Threat Intelligence"
    if 'documentation' in title_lower or 'docs.' in url_lower:
        return "Documentation"
    if 'analysis' in title_lower or 'report' in title_lower:
        return "Threat Intelligence"

    return "Reference"


def technique_name_lookup(technique_id: str) -> str:
    """Return human-readable name for common MITRE ATT&CK techniques."""
    # Common technique names - not exhaustive, just covers frequently used ones
    names = {
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
        "T1059.003": "Windows Command Shell",
        "T1059.006": "Python",
        "T1055": "Process Injection",
        "T1055.001": "Dynamic-link Library Injection",
        "T1055.012": "Process Hollowing",
        "T1003": "OS Credential Dumping",
        "T1003.001": "LSASS Memory",
        "T1003.006": "DCSync",
        "T1486": "Data Encrypted for Impact",
        "T1490": "Inhibit System Recovery",
        "T1562": "Impair Defenses",
        "T1562.001": "Disable or Modify Tools",
        "T1562.004": "Disable or Modify System Firewall",
        "T1547": "Boot or Logon Autostart Execution",
        "T1547.001": "Registry Run Keys / Startup Folder",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1548.002": "Bypass User Account Control",
        "T1053": "Scheduled Task/Job",
        "T1053.005": "Scheduled Task",
        "T1543": "Create or Modify System Process",
        "T1543.003": "Windows Service",
        "T1036": "Masquerading",
        "T1036.005": "Match Legitimate Name or Location",
        "T1071": "Application Layer Protocol",
        "T1071.001": "Web Protocols",
        "T1105": "Ingress Tool Transfer",
        "T1140": "Deobfuscate/Decode Files or Information",
        "T1218": "System Binary Proxy Execution",
        "T1218.011": "Rundll32",
        "T1574": "Hijack Execution Flow",
        "T1574.001": "DLL Search Order Hijacking",
        "T1574.002": "DLL Side-Loading",
        "T1027": "Obfuscated Files or Information",
        "T1070": "Indicator Removal",
        "T1070.001": "Clear Windows Event Logs",
        "T1070.004": "File Deletion",
        "T1082": "System Information Discovery",
        "T1083": "File and Directory Discovery",
        "T1087": "Account Discovery",
        "T1087.002": "Domain Account",
        "T1021": "Remote Services",
        "T1021.001": "Remote Desktop Protocol",
        "T1021.006": "Windows Remote Management",
        "T1550": "Use Alternate Authentication Material",
        "T1550.002": "Pass the Hash",
        "T1558": "Steal or Forge Kerberos Tickets",
        "T1558.003": "Kerberoasting",
        "T1485": "Data Destruction",
        "T1489": "Service Stop",
        "T1505": "Server Software Component",
        "T1505.003": "Web Shell",
        "T1068": "Exploitation for Privilege Escalation",
        "T1041": "Exfiltration Over C2 Channel",
        "T1048": "Exfiltration Over Alternative Protocol",
        "T1567": "Exfiltration Over Web Service",
        "T1567.002": "Exfiltration to Cloud Storage",
        "T1078": "Valid Accounts",
        "T1078.001": "Default Accounts",
        "T1078.004": "Cloud Accounts",
        "T1098": "Account Manipulation",
        "T1110": "Brute Force",
        "T1556": "Modify Authentication Process",
        "T1204": "User Execution",
        "T1204.002": "Malicious File",
        "T1566": "Phishing",
        "T1497": "Virtualization/Sandbox Evasion",
        "T1497.001": "System Checks",
        "T1542": "Pre-OS Boot",
        "T1542.003": "Bootkit",
        "T1528": "Steal Application Access Token",
        "T1518": "Software Discovery",
        "T1518.001": "Security Software Discovery",
        "T1057": "Process Discovery",
        "T1112": "Modify Registry",
        "T1569": "System Services",
        "T1569.002": "Service Execution",
        "T1553": "Subvert Trust Controls",
        "T1553.005": "Mark-of-the-Web Bypass",
        "T1222": "File and Directory Permissions Modification",
        "T1222.001": "Windows File and Directory Permissions Modification",
        "T1047": "Windows Management Instrumentation",
        "T1134": "Access Token Manipulation",
        "T1134.001": "Token Impersonation/Theft",
    }
    return names.get(technique_id, technique_id)


def generate_references_md(uuid: str, metadata: dict, references: list[dict]) -> str:
    """Generate the _references.md content."""
    lines = ["# References & Sources", ""]

    # Primary Source section
    lines.append("## Primary Source")
    lines.append("")
    lines.append("*Retroactively reconstructed from existing test documentation.*")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")

    # Try to identify a primary source from the references
    primary = None
    for ref in references:
        if ref["type"] == "MITRE ATT&CK":
            continue  # Skip MITRE refs as primary
        if ref["type"] in ("Threat Intelligence", "Blog Post", "Security Advisory", "Government Advisory"):
            primary = ref
            break

    if not primary and references:
        # Use first non-MITRE reference
        for ref in references:
            if ref["type"] != "MITRE ATT&CK":
                primary = ref
                break

    if primary:
        lines.append(f"| **Title** | {primary['title']} |")
        # Try to extract org from title/URL
        org = extract_org_from_ref(primary)
        lines.append(f"| **Author/Organization** | {org} |")
        lines.append(f"| **Date Published** | {metadata.get('created', 'Unknown')} |")
        lines.append(f"| **Document Type** | {primary['type'].lower().replace(' ', '-')} |")
        lines.append(f"| **URL** | {primary['url']} |")
    else:
        actor = metadata.get("threat_actor", "Unknown")
        lines.append(f"| **Title** | {metadata.get('name', 'Unknown')} |")
        lines.append(f"| **Author/Organization** | F0RT1KA Research |")
        lines.append(f"| **Date Published** | {metadata.get('created', 'Unknown')} |")
        lines.append(f"| **Document Type** | threat-report |")
        lines.append(f"| **URL** | Not available |")

    lines.append("")

    # Supporting Resources
    lines.append("## Supporting Resources")
    lines.append("")
    lines.append("Additional threat intelligence, incident reports, and TTP analyses referenced during test development.")
    lines.append("")

    # Filter out the primary source and MITRE refs for supporting resources
    supporting = [r for r in references if r != primary and r["type"] != "MITRE ATT&CK"]

    if supporting:
        lines.append("| # | Title | Type | URL |")
        lines.append("|---|-------|------|-----|")
        for i, ref in enumerate(supporting, 1):
            lines.append(f"| {i} | {ref['title']} | {ref['type']} | {ref['url']} |")
    else:
        lines.append("No additional supporting resources documented for this test.")

    lines.append("")

    # MITRE ATT&CK References
    lines.append("## MITRE ATT&CK References")
    lines.append("")
    lines.append("| Technique | Name | URL |")
    lines.append("|-----------|------|-----|")

    techniques = metadata.get("techniques", [])
    for tech in techniques:
        name = technique_name_lookup(tech)
        # Convert T1055.001 to T1055/001 for URL
        url_tech = tech.replace(".", "/")
        url = f"https://attack.mitre.org/techniques/{url_tech}/"
        lines.append(f"| {tech} | {name} | {url} |")

    if not techniques:
        lines.append("| - | No techniques documented | - |")

    lines.append("")

    # Related Advisories (from MITRE refs in the original)
    mitre_refs = [r for r in references if r["type"] == "MITRE ATT&CK" and "groups" in r.get("url", "")]
    gov_refs = [r for r in references if r["type"] == "Government Advisory"]

    if mitre_refs or gov_refs:
        lines.append("## Related Advisories & News")
        lines.append("")
        for ref in gov_refs + mitre_refs:
            lines.append(f"- [{ref['title']}]({ref['url']})")
        lines.append("")

    return "\n".join(lines)


def extract_org_from_ref(ref: dict) -> str:
    """Try to extract the publishing organization from a reference."""
    url = ref.get("url", "").lower()
    title = ref.get("title", "").lower()

    if "microsoft.com" in url or "microsoft" in title:
        return "Microsoft"
    if "mandiant" in url or "mandiant" in title:
        return "Mandiant"
    if "crowdstrike" in url or "crowdstrike" in title:
        return "CrowdStrike"
    if "secureworks" in url or "secureworks" in title:
        return "Secureworks"
    if "cisa.gov" in url or "cisa" in title:
        return "CISA"
    if "paloalto" in url or "palo alto" in title or "unit42" in url or "unit 42" in title:
        return "Palo Alto Networks / Unit 42"
    if "sophos" in url or "sophos" in title:
        return "Sophos"
    if "sentinel" in url or "sentinelone" in title:
        return "SentinelOne"
    if "elastic" in url or "elastic" in title:
        return "Elastic Security"
    if "trend" in url or "trend micro" in title:
        return "Trend Micro"
    if "kaspersky" in url or "kaspersky" in title:
        return "Kaspersky"
    if "github.com" in url:
        return "Open Source Community"
    if "gbhackers" in url:
        return "GBHackers"
    if "bleeping" in url or "bleepingcomputer" in title:
        return "BleepingComputer"
    if "therecord" in url:
        return "The Record"
    if "anomali" in url or "anomali" in title:
        return "Anomali"

    return "Security Research"


def main():
    parser = argparse.ArgumentParser(description="Generate retroactive _references.md files")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing files")
    parser.add_argument("--uuid", type=str, help="Generate for a specific test UUID only")
    args = parser.parse_args()

    # Resolve paths
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    tests_dir = repo_root / "tests_source"

    categories = ["intel-driven", "mitre-top10"]
    generated = 0
    skipped = 0
    errors = 0

    print("F0RT1KA Retroactive References Generator")
    print("=" * 50)
    print()

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

            # Skip if already exists
            if refs_file.exists():
                skipped += 1
                print(f"  [{category[:10]:<10}] {uuid[:8]}... SKIP (already exists)")
                continue

            # Extract metadata from Go file
            go_file = test_dir / f"{uuid}.go"
            metadata = extract_go_metadata(go_file)

            if not metadata["name"]:
                errors += 1
                print(f"  [{category[:10]:<10}] {uuid[:8]}... ERROR (no Go metadata)")
                continue

            # Extract references from info.md
            info_file = test_dir / f"{uuid}_info.md"
            references = extract_references_from_info(info_file)

            # Generate content
            content = generate_references_md(uuid, metadata, references)

            if args.dry_run:
                print(f"  [{category[:10]:<10}] {uuid[:8]}... WOULD GENERATE ({len(references)} refs)")
            else:
                refs_file.write_text(content, encoding="utf-8")
                generated += 1
                print(f"  [{category[:10]:<10}] {uuid[:8]}... GENERATED ({len(references)} refs)")

    print()
    print(f"Results: {generated} generated, {skipped} skipped, {errors} errors")
    if args.dry_run:
        print("(DRY RUN — no files written)")


if __name__ == "__main__":
    main()
