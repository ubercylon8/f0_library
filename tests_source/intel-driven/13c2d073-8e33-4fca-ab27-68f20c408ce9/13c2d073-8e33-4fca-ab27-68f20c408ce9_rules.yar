/*
    ============================================================
    APT33 Tickler Backdoor Detection - YARA Rules
    Test ID: 13c2d073-8e33-4fca-ab27-68f20c408ce9
    MITRE ATT&CK: T1566.001, T1574.002, T1547.001, T1053.005, T1036, T1071.001
    Threat Actor: APT33 (Elfin / Peach Sandstorm / Refined Kitten)
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    ============================================================

    These rules detect APT33 Tickler backdoor artifacts, DLL sideloading
    patterns, masqueraded binaries, and C2 communication indicators.

    IMPORTANT: These rules target technique-level behaviors and real-world
    Tickler artifacts. They do NOT detect F0RT1KA test framework artifacts.

    Usage:
        yara -r 13c2d073-8e33-4fca-ab27-68f20c408ce9_rules.yar /path/to/scan

    ============================================================
*/


/*
    ============================================================
    Rule: APT33_Tickler_DLL_Sideloading_Marker
    Confidence: High
    Description: Detects simulated sideloading DLLs with MZ header
                 placed alongside renamed Microsoft binaries.
                 Real Tickler uses modified msvcp140.dll/vcruntime140.dll
                 with malicious exports.
    ============================================================
*/
rule APT33_Tickler_DLL_Sideloading_Marker
{
    meta:
        description = "Detects suspicious DLL files with minimal PE headers placed for sideloading alongside renamed binaries"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
        mitre_attack = "T1574.002"
        confidence = "high"
        reference = "https://www.microsoft.com/en-us/security/blog/2024/08/28/peach-sandstorm-deploys-new-custom-tickler-malware-in-long-running-intelligence-gathering-operations/"

    strings:
        // Minimal PE header (MZ + partial DOS header) - abnormally small DLL
        $mz = { 4D 5A }

        // DLL names that are sideloading targets
        $dll1 = "msvcp140" ascii wide nocase
        $dll2 = "vcruntime140" ascii wide nocase
        $dll3 = "msvcp_win" ascii wide nocase

    condition:
        $mz at 0 and
        filesize < 10KB and  // Legitimate msvcp140.dll is ~400KB+, sideloading stubs are tiny
        any of ($dll*)
}


/*
    ============================================================
    Rule: APT33_Tickler_Backdoor_Binary
    Confidence: High
    Description: Detects Tickler backdoor binary characteristics
                 including C2 communication strings, system fingerprinting
                 functions, and SharePoint-themed naming.
    ============================================================
*/
rule APT33_Tickler_Backdoor_Binary
{
    meta:
        description = "Detects APT33 Tickler backdoor binary by C2 protocol strings and behavioral patterns"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
        mitre_attack = "T1071.001, T1036"
        confidence = "high"
        reference = "https://attack.mitre.org/groups/G0064/"

    strings:
        // Tickler C2 User-Agent string
        $ua1 = "Microsoft SharePoint/16.0" ascii wide
        $ua2 = "Microsoft SharePoint/" ascii wide

        // C2 port indicators in binary
        $port1 = ":808/" ascii wide
        $port2 = ":880/" ascii wide
        $port3 = ":808" ascii wide
        $port4 = ":880" ascii wide

        // System fingerprinting patterns
        $fp1 = "HOST=" ascii wide
        $fp2 = "USER=" ascii wide
        $fp3 = "COMP=" ascii wide
        $fp4 = "AGENT=Tickler" ascii wide

        // SharePoint masquerading names in binary
        $masq1 = "Microsoft.SharePoint.NativeMessaging" ascii wide
        $masq2 = "SharePoint.exe" ascii wide
        $masq3 = "MicrosoftSharePointSync" ascii wide

        // Base64 encoding for C2 data
        $enc1 = "base64" ascii wide nocase
        $enc2 = "Content-Type: application/x-www-form-urlencoded" ascii wide

        // Registry persistence indicators
        $reg1 = "CurrentVersion\\Run" ascii wide
        $reg2 = "SharePoint" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 15MB and
        (
            // High confidence: Tickler-specific C2 strings
            ($ua1 and any of ($port*)) or
            // High confidence: Fingerprinting with Tickler agent
            ($fp4 and 2 of ($fp*)) or
            // Medium confidence: SharePoint masquerading + C2 ports
            (any of ($masq*) and any of ($port*) and any of ($enc*)) or
            // Medium confidence: SharePoint persistence + C2 communication
            (any of ($masq*) and any of ($reg*) and any of ($ua*))
        )
}


/*
    ============================================================
    Rule: APT33_Spearphishing_ZIP_Double_Extension
    Confidence: Medium
    Description: Detects ZIP archive files that use double extensions
                 to masquerade as documents (e.g., .pdf.zip, .doc.zip).
                 This is the delivery mechanism used by APT33 Tickler.
    ============================================================
*/
rule APT33_Spearphishing_ZIP_Double_Extension
{
    meta:
        description = "Detects ZIP archives with double extension masquerading as documents - APT33 delivery pattern"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
        mitre_attack = "T1566.001"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1566/001/"

    strings:
        // ZIP local file header magic
        $zip_magic = { 50 4B 03 04 }

        // Filenames inside ZIP that indicate sideloading payload
        $payload1 = "Microsoft.SharePoint.NativeMessaging.exe" ascii
        $payload2 = "SharePoint.exe" ascii
        $payload3 = "NativeMessaging.exe" ascii

        // DLL filenames inside ZIP indicating sideloading setup
        $dll1 = "msvcp140.dll" ascii
        $dll2 = "vcruntime140.dll" ascii

        // Decoy document names inside ZIP
        $decoy1 = ".pdf" ascii
        $decoy2 = "Financial_Report" ascii
        $decoy3 = "Report_20" ascii

    condition:
        $zip_magic at 0 and
        filesize < 50MB and
        (
            // ZIP containing sideloading payload + DLLs
            (any of ($payload*) and any of ($dll*)) or
            // ZIP containing masqueraded executable + decoy
            (any of ($payload*) and any of ($decoy*))
        )
}


/*
    ============================================================
    Rule: APT33_C2_Beacon_Data
    Confidence: Medium
    Description: Detects base64-encoded system fingerprint data
                 formatted in the Tickler C2 beacon pattern.
                 This can identify staged exfiltration data on disk.
    ============================================================
*/
rule APT33_C2_Beacon_Data
{
    meta:
        description = "Detects APT33 Tickler C2 beacon data files containing base64-encoded system fingerprints"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
        mitre_attack = "T1071.001"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1071/001/"

    strings:
        // Base64-encoded Tickler fingerprint patterns
        // "HOST=" base64 encoded starts with "SE9TVD"
        $b64_host = "SE9TVD" ascii
        // "USER=" base64 encoded starts with "VVNFUJ"
        $b64_user = "VVNFUJ" ascii
        // "COMP=" base64 encoded starts with "Q09NUD"
        $b64_comp = "Q09NUD" ascii
        // "AGENT=Tickler" base64 encoded
        $b64_agent = "QUdFTlQ9VGlja2xlcg" ascii

        // Raw fingerprint format (if not base64 encoded)
        $raw1 = "HOST=" ascii
        $raw2 = "USER=" ascii
        $raw3 = "COMP=" ascii
        $raw4 = "AGENT=Tickler" ascii

    condition:
        filesize < 10KB and
        (
            // Base64-encoded beacon
            ($b64_host and $b64_user) or
            $b64_agent or
            // Raw fingerprint data
            ($raw1 and $raw2 and $raw3 and $raw4)
        )
}


/*
    ============================================================
    Rule: Renamed_Microsoft_Binary_Sideloading
    Confidence: Medium
    Description: Generic detection for Microsoft-signed binaries that
                 have been renamed and placed in non-standard directories
                 alongside DLL files. This is a common DLL sideloading
                 pattern used by multiple threat actors including APT33.
    ============================================================
*/
rule Renamed_Microsoft_Binary_Sideloading
{
    meta:
        description = "Detects renamed Microsoft signed binaries with version info mismatches - generic DLL sideloading indicator"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
        mitre_attack = "T1574.002, T1036"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1574/002/"

    strings:
        // Microsoft version info strings
        $ms1 = "Microsoft Corporation" ascii wide
        $ms2 = "Microsoft" ascii wide
        $ms3 = "Windows" ascii wide

        // Original filename metadata (from PE version info)
        $orig1 = "OriginalFilename" ascii wide
        $orig2 = "notepad.exe" ascii wide
        $orig3 = "cmd.exe" ascii wide
        $orig4 = "explorer.exe" ascii wide
        $orig5 = "mmc.exe" ascii wide
        $orig6 = "calc.exe" ascii wide

        // Product name metadata
        $prod1 = "ProductName" ascii wide
        $prod2 = "Microsoft\x00" ascii wide

        // File description
        $desc1 = "FileDescription" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        // Has Microsoft version info
        any of ($ms*) and
        $orig1 and
        // Has an OriginalFilename that is a known Microsoft utility
        any of ($orig2, $orig3, $orig4, $orig5, $orig6) and
        any of ($prod*) and
        $desc1
}


/*
    ============================================================
    Rule: Scheduled_Task_XML_SharePoint_Persistence
    Confidence: High
    Description: Detects Windows scheduled task XML definition files
                 that reference SharePoint-themed executables for
                 persistence. Catches exported or created task definitions.
    ============================================================
*/
rule Scheduled_Task_XML_SharePoint_Persistence
{
    meta:
        description = "Detects scheduled task XML files with SharePoint-themed persistence"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
        mitre_attack = "T1053.005, T1036"
        confidence = "high"

    strings:
        // Task XML structure
        $xml1 = "<Task " ascii wide nocase
        $xml2 = "<Actions" ascii wide nocase
        $xml3 = "<Exec>" ascii wide nocase
        $xml4 = "<Command>" ascii wide nocase

        // Logon trigger
        $trigger1 = "<LogonTrigger>" ascii wide nocase
        $trigger2 = "ONLOGON" ascii wide nocase

        // SharePoint-themed references
        $sp1 = "SharePoint" ascii wide nocase
        $sp2 = "NativeMessaging" ascii wide nocase
        $sp3 = "MicrosoftSharePointSync" ascii wide nocase

    condition:
        filesize < 100KB and
        any of ($xml*) and
        (any of ($trigger*)) and
        (any of ($sp*))
}
