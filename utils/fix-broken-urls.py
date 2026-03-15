#!/usr/bin/env python3
"""
Fix known broken URLs in _references.md files.
Maps old/broken URLs to their correct replacements.
"""

import re
from pathlib import Path

# URL replacement map: old_url -> new_url
URL_FIXES = {
    # Microsoft docs.microsoft.com → learn.microsoft.com migrations
    "https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/":
        "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/",

    "https://docs.microsoft.com/en-us/security/certificate-pinning":
        "https://learn.microsoft.com/en-us/windows/security/identity-protection/enterprise-certificate-pinning",

    "https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/":
        "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows",

    # Microsoft security blog tag pages (removed/restructured)
    "https://www.microsoft.com/security/blog/tag/peach-sandstorm/":
        "https://www.microsoft.com/en-us/security/blog/2024/08/28/peach-sandstorm-deploys-new-custom-tickler-malware-in-long-running-intelligence-gathering-operations/",

    "https://www.microsoft.com/en-us/security/blog/tag/pink-sandstorm/":
        "https://attack.mitre.org/groups/G1030/",

    # CISA advisory URL changes
    "https://www.cisa.gov/uscert/ncas/alerts/aa21-265a":
        "https://www.cisa.gov/news-events/news/updated-conti-ransomware",

    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a":
        "https://www.cisa.gov/news-events/news/updated-conti-ransomware",

    # harmj0y domain change
    "https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/":
        "https://blog.harmj0y.net/activedirectory/roasting-as-reps/",

    # Aqua Security blog path change
    "https://www.aquasec.com/blog/perfctl-malware/":
        "https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/",

    # InfoGuard blog domain/path change
    "https://www.infoguard.ch/en/blog/microsoft-defender-for-endpoint-authentication-bypass":
        "https://labs.infoguard.ch/posts/attacking_edr_part5_vulnerabilities_in_defender_for_endpoint_communication/",

    # UAC bypass blog (site gone) → replace with well-known alternative
    "https://www.activecyber.us/activelabs/windows-uac-bypass":
        "https://attack.mitre.org/techniques/T1548/002/",

    # SANS blog URL correction
    "https://www.sans.org/blog/detecting-wmi-abuse/":
        "https://www.sans.org/blog/investigating-wmi-attacks",

    # NIST ransomware guide path correction
    "https://www.nist.gov/itl/applied-cybersecurity/nist-cybersecurity-insights/ransomware-risk-management":
        "https://csrc.nist.gov/pubs/ir/8374/final",

    # Unit42 URL (was truncated) — replace with correct full URL
    "https://unit42.paloaltonetworks.com/north-korean-threat-actors-luring-tech-job-seekers-as-fake-recruiters/":
        "https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/",

    # Internal repo link (private, doesn't exist publicly)
    "https://github.com/ubercylon8/f0_library/blob/main/tech-reports/SafePay-Technical-Report.md":
        "https://www.picussecurity.com/resource/blog/inside-safepay-analyzing-the-new-centralized-ransomware-group",

    # Secureworks (timeout — replace with alternative that's accessible)
    "https://www.secureworks.com/research/safepay-malware":
        "https://businessinsights.bitdefender.com/safepay-ransomware-attacks-ttps",

    # FortiGuard (timeout/unreachable)
    "https://www.fortiguard.com/threat-signal-report/":
        "https://www.fortinet.com/blog/threat-research",
}

def fix_references_files():
    repo_root = Path(__file__).parent.parent
    tests_dir = repo_root / "tests_source"
    categories = ["intel-driven", "mitre-top10"]

    total_fixes = 0
    files_fixed = 0

    print("F0RT1KA Reference URL Fixer")
    print("=" * 60)

    for category in categories:
        cat_dir = tests_dir / category
        if not cat_dir.exists():
            continue

        for test_dir in sorted(cat_dir.iterdir()):
            if not test_dir.is_dir():
                continue
            uuid = test_dir.name
            refs_file = test_dir / f"{uuid}_references.md"
            if not refs_file.exists():
                continue

            content = refs_file.read_text(encoding="utf-8")
            original = content
            fixes_in_file = 0

            for old_url, new_url in URL_FIXES.items():
                if old_url in content:
                    content = content.replace(old_url, new_url)
                    fixes_in_file += 1

            if fixes_in_file > 0:
                refs_file.write_text(content, encoding="utf-8")
                total_fixes += fixes_in_file
                files_fixed += 1
                print(f"  [{category[:10]:<10}] {uuid[:8]}... FIXED ({fixes_in_file} URLs)")

    print(f"\nResults: {total_fixes} URLs fixed across {files_fixed} files")


if __name__ == "__main__":
    fix_references_files()
