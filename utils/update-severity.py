#!/usr/bin/env python3
"""
Updates severity assignments in F0RT1KA test Go files based on MITRE ATT&CK technique mapping.

This script implements the F0RT1KA Severity Framework v2.
"""

import os
import re
import sys
from pathlib import Path

# Technique to severity mapping (Framework v2)
TECHNIQUE_SEVERITY = {
    # CRITICAL techniques - system/domain compromise
    "T1486": "critical",      # Data Encrypted for Impact (ransomware)
    "T1490": "critical",      # Inhibit System Recovery
    "T1003.001": "critical",  # LSASS Memory
    "T1003": "critical",      # OS Credential Dumping
    "T1068": "critical",      # Exploitation for Privilege Escalation (kernel)
    "T1558.001": "critical",  # Golden Ticket
    "T1558.002": "critical",  # Silver Ticket
    "T1542": "critical",      # Pre-OS Boot
    "T1491.001": "critical",  # Internal Defacement (often with ransomware)

    # HIGH techniques - significant access or lateral movement
    "T1562.001": "high",      # Disable Security Tools
    "T1562.004": "high",      # Disable or Modify Firewall
    "T1562": "high",          # Impair Defenses (generic)
    "T1055": "high",          # Process Injection (generic)
    "T1055.001": "high",      # Process Injection: DLL
    "T1055.002": "high",      # PE Injection
    "T1055.003": "high",      # Thread Execution Hijacking
    "T1550.001": "high",      # Application Access Token
    "T1550.002": "high",      # Pass the Hash
    "T1550.003": "high",      # Pass the Ticket
    "T1550": "high",          # Use Alternate Auth Material
    "T1021.001": "high",      # Remote Desktop Protocol
    "T1021.002": "high",      # SMB/Windows Admin Shares
    "T1021.003": "high",      # DCOM
    "T1021.004": "high",      # SSH
    "T1021": "high",          # Remote Services (generic)
    "T1071": "high",          # Application Layer Protocol (C2)
    "T1041": "high",          # Exfiltration Over C2
    "T1558.003": "high",      # Kerberoasting
    "T1558.004": "high",      # AS-REP Roasting
    "T1059.001": "high",      # PowerShell
    "T1059.003": "high",      # Windows Command Shell
    "T1059": "high",          # Command and Scripting Interpreter
    "T1047": "high",          # WMI
    "T1489": "high",          # Service Stop
    "T1105": "high",          # Ingress Tool Transfer
    "T1190": "high",          # Exploit Public-Facing Application
    "T1557.001": "high",      # NTLM Relay
    "T1557": "high",          # Adversary-in-the-Middle
    "T1110.003": "high",      # Password Spraying
    "T1110": "high",          # Brute Force
    "T1134.001": "high",      # Token Impersonation
    "T1134": "high",          # Access Token Manipulation
    "T1204.002": "high",      # User Execution: Malicious File
    "T1140": "high",          # Deobfuscate/Decode Files
    "T1546.003": "high",      # WMI Event Subscription
    "T1555.004": "high",      # Windows Credential Manager
    "T1219": "high",          # Remote Access Software
    "T1543.003": "high",      # Windows Service

    # MEDIUM techniques - reconnaissance or persistence foothold
    "T1087.001": "medium",    # Local Account Discovery
    "T1087.002": "medium",    # Domain Account Discovery
    "T1087": "medium",        # Account Discovery
    "T1083": "medium",        # File and Directory Discovery
    "T1053": "medium",        # Scheduled Task/Job
    "T1543": "medium",        # Create or Modify System Process
    "T1548.002": "medium",    # UAC Bypass
    "T1548": "medium",        # Abuse Elevation Control
    "T1021.006": "medium",    # WinRM
    "T1119": "medium",        # Automated Collection
    "T1078.003": "medium",    # Local Accounts
    "T1070.001": "medium",    # Clear Windows Event Logs

    # LOW techniques - information disclosure
    "T1082": "low",           # System Information Discovery
    "T1057": "low",           # Process Discovery
}

# Test name to severity overrides (for tests without techniques defined)
NAME_SEVERITY = {
    "ransomware": "critical",
    "encryption": "critical",
    "bitlocker": "critical",
    "lsass": "critical",
    "credential dump": "critical",
    "byovd": "critical",
    "c2": "high",
    "sliver": "high",
    "edr": "high",
    "process injection": "high",
    "defense evasion": "high",
    "amsi bypass": "high",
    "defender disabling": "high",
    "lateral movement": "high",
    "exfiltration": "high",
    "remote access": "high",
    "pass-the-hash": "high",
    "pass-the-ticket": "high",
    "kerberoasting": "high",
    "as-rep roasting": "high",
    "ntlm relay": "high",
    "uac bypass": "medium",
    "enumeration": "medium",
    "discovery": "medium",
}


def get_severity_from_techniques(techniques: list) -> str:
    """Determine severity based on techniques (highest wins)."""
    if not techniques:
        return None

    severity_order = ["critical", "high", "medium", "low", "informational"]
    found_severity = "informational"

    for tech in techniques:
        tech = tech.strip()
        # Check exact match first
        if tech in TECHNIQUE_SEVERITY:
            sev = TECHNIQUE_SEVERITY[tech]
        # Check parent technique (e.g., T1055 for T1055.001)
        elif "." in tech:
            parent = tech.split(".")[0]
            sev = TECHNIQUE_SEVERITY.get(parent, "informational")
        else:
            sev = "informational"

        # Keep highest severity
        if severity_order.index(sev) < severity_order.index(found_severity):
            found_severity = sev

    return found_severity


def get_severity_from_name(name: str) -> str:
    """Determine severity based on test name keywords."""
    if not name:
        return None

    name_lower = name.lower()
    for keyword, severity in NAME_SEVERITY.items():
        if keyword in name_lower:
            return severity
    return None


def update_go_file(filepath: Path, dry_run: bool = False) -> dict:
    """Update severity in a Go file's metadata header."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return {"status": "error", "message": str(e)}

    # Check if already has severity
    if re.search(r'^SEVERITY:\s*\w+', content, re.MULTILINE):
        sev_match = re.search(r'^SEVERITY:\s*(\w+)', content, re.MULTILINE)
        return {"status": "already_set", "severity": sev_match.group(1) if sev_match else "unknown"}

    # Extract test name
    name_match = re.search(r'^NAME:\s*(.+)$', content, re.MULTILINE)
    name = name_match.group(1).strip() if name_match else None

    # Extract techniques
    tech_match = re.search(r'^TECHNIQUES?:\s*(.+)$', content, re.MULTILINE)
    techniques = []
    if tech_match:
        techniques = [t.strip() for t in tech_match.group(1).split(',')]

    # Determine severity
    severity = get_severity_from_techniques(techniques)
    if not severity or severity == "informational":
        name_sev = get_severity_from_name(name)
        if name_sev:
            severity = name_sev

    if not severity:
        return {"status": "no_severity", "name": name, "techniques": techniques}

    # Find where to insert SEVERITY (after TECHNIQUES or TACTICS line)
    insert_patterns = [
        (r'^(TACTICS?:.+)$', 'TACTICS'),
        (r'^(TECHNIQUES?:.+)$', 'TECHNIQUES'),
        (r'^(NAME:.+)$', 'NAME'),
    ]

    for pattern, after_field in insert_patterns:
        match = re.search(pattern, content, re.MULTILINE)
        if match:
            insertion_point = match.end()
            new_content = content[:insertion_point] + f"\nSEVERITY: {severity}" + content[insertion_point:]

            if not dry_run:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)

            return {
                "status": "updated",
                "severity": severity,
                "name": name,
                "techniques": techniques,
                "inserted_after": after_field
            }

    return {"status": "no_insertion_point", "name": name}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Update severity in F0RT1KA tests")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without writing")
    parser.add_argument("--category", help="Only process specific category")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    tests_source = repo_root / "tests_source"

    categories = ["cyber-hygiene", "intel-driven", "mitre-top10", "phase-aligned"]
    if args.category:
        categories = [args.category]

    print("F0RT1KA Severity Update Tool")
    print("=" * 60)
    if args.dry_run:
        print("DRY RUN - No changes will be made")
    print()

    stats = {"updated": 0, "already_set": 0, "no_severity": 0, "error": 0}

    for category in categories:
        cat_dir = tests_source / category
        if not cat_dir.exists():
            continue

        print(f"\n[{category}]")

        uuid_pattern = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')

        for item in sorted(cat_dir.iterdir()):
            if not item.is_dir() or not uuid_pattern.match(item.name):
                continue

            uuid = item.name
            go_file = item / f"{uuid}.go"

            if not go_file.exists():
                continue

            result = update_go_file(go_file, args.dry_run)
            status = result.get("status")

            if status == "updated":
                stats["updated"] += 1
                sev = result.get("severity", "?").upper()
                name = result.get("name", "Unknown")[:40]
                print(f"  {uuid[:8]}... [{sev:8}] {name}")
            elif status == "already_set":
                stats["already_set"] += 1
                sev = result.get("severity", "?").upper()
                print(f"  {uuid[:8]}... [{sev:8}] (already set)")
            elif status == "no_severity":
                stats["no_severity"] += 1
                name = result.get("name", "Unknown")
                print(f"  {uuid[:8]}... [UNKNOWN ] {name} - needs manual review")
            else:
                stats["error"] += 1
                print(f"  {uuid[:8]}... [ERROR   ] {result.get('message', status)}")

    print()
    print("=" * 60)
    print(f"Updated:     {stats['updated']}")
    print(f"Already set: {stats['already_set']}")
    print(f"Needs review:{stats['no_severity']}")
    print(f"Errors:      {stats['error']}")

    if args.dry_run and stats["updated"] > 0:
        print()
        print("Run without --dry-run to apply changes")


if __name__ == "__main__":
    main()
