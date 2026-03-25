/*
    ============================================================
    TA453 NICECURL VBScript Backdoor Detection - YARA Rules
    Test ID: 8e2cf534-857b-4d29-a1ac-0f23d248db93
    MITRE ATT&CK: T1204.002, T1059.005, T1047, T1518.001, T1071.001, T1105, T1036.004
    Threat Actor: TA453 (APT42 / Charming Kitten / Mint Sandstorm)
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-24
    ============================================================

    These rules detect NICECURL VBScript backdoor artifacts, WMI discovery
    patterns, and curl.exe C2 communication indicators.

    IMPORTANT: These rules target technique-level behaviors and real-world
    NICECURL artifacts. They do NOT detect F0RT1KA test framework artifacts.

    Usage:
        yara -r 8e2cf534-857b-4d29-a1ac-0f23d248db93_rules.yar /path/to/scan

    ============================================================
*/


/*
    ============================================================
    Rule: NICECURL_VBScript_Backdoor_Indicators
    Confidence: High
    Description: Detects VBScript files containing NICECURL-style backdoor
                 patterns including WMI SecurityCenter2 queries, curl.exe
                 invocation, and Glitch.me C2 domain references.
    ============================================================
*/
rule NICECURL_VBScript_Backdoor_Indicators
{
    meta:
        description = "Detects VBScript files with NICECURL backdoor patterns: WMI AV discovery, curl C2, Glitch.me domains"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-24"
        test_id = "8e2cf534-857b-4d29-a1ac-0f23d248db93"
        mitre_attack = "T1059.005, T1047, T1518.001"
        confidence = "high"
        reference = "https://hawk-eye.io/wp-content/advisories/apt42-threat-advisory.html"

    strings:
        // WMI SecurityCenter2 access patterns (NICECURL discovery)
        $wmi1 = "SecurityCenter2" ascii wide nocase
        $wmi2 = "AntiVirusProduct" ascii wide nocase
        $wmi3 = "winmgmts:" ascii wide nocase

        // curl.exe invocation from VBScript
        $curl1 = "curl.exe" ascii wide nocase
        $curl2 = "curl " ascii wide nocase

        // Glitch.me C2 domain patterns
        $glitch1 = "glitch.me" ascii wide nocase
        $glitch2 = "glitch.io" ascii wide nocase

        // VBScript execution patterns
        $vbs1 = "WScript.Shell" ascii wide nocase
        $vbs2 = "CreateObject" ascii wide nocase
        $vbs3 = "GetObject" ascii wide nocase

        // Victim identification patterns
        $vid1 = "config.txt" ascii wide nocase
        $vid2 = "victim_id" ascii wide nocase
        $vid3 = "LOCALAPPDATA" ascii wide nocase

    condition:
        filesize < 500KB and
        (
            // VBScript with WMI AV discovery
            (2 of ($wmi*) and any of ($vbs*)) or
            // VBScript with curl C2
            (any of ($curl*) and any of ($glitch*)) or
            // VBScript with victim ID creation and WMI
            (any of ($vid*) and any of ($wmi*) and any of ($vbs*))
        )
}


/*
    ============================================================
    Rule: NICECURL_Malicious_LNK_Double_Extension
    Confidence: Medium
    Description: Detects Windows Shell Link (.lnk) files that use double
                 extension masquerading (e.g., .pdf.lnk) and target
                 wscript.exe or cscript.exe for VBScript execution.
    ============================================================
*/
rule NICECURL_Malicious_LNK_Double_Extension
{
    meta:
        description = "Detects LNK files targeting script interpreters with double-extension masquerading"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-24"
        test_id = "8e2cf534-857b-4d29-a1ac-0f23d248db93"
        mitre_attack = "T1204.002, T1036.004"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1204/002/"

    strings:
        // Windows Shell Link CLSID
        $lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

        // Script interpreter targets
        $target1 = "wscript.exe" ascii wide nocase
        $target2 = "cscript.exe" ascii wide nocase

        // VBScript file references
        $vbs1 = ".vbs" ascii wide nocase
        $vbs2 = ".vbe" ascii wide nocase

    condition:
        $lnk_clsid at 4 and
        any of ($target*) and
        any of ($vbs*)
}


/*
    ============================================================
    Rule: NICECURL_WMI_AV_Discovery_Script
    Confidence: High
    Description: Detects scripts (VBScript, JScript, PowerShell) that
                 query WMI SecurityCenter2 for AntiVirusProduct. This is
                 a common pre-exploitation discovery technique used by
                 NICECURL, TAMECAT, and other Iranian APT tooling.
    ============================================================
*/
rule NICECURL_WMI_AV_Discovery_Script
{
    meta:
        description = "Detects scripts performing WMI AntiVirusProduct enumeration via SecurityCenter2 namespace"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-24"
        test_id = "8e2cf534-857b-4d29-a1ac-0f23d248db93"
        mitre_attack = "T1047, T1518.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1518/001/"

    strings:
        // WMI SecurityCenter2 query patterns
        $query1 = "SecurityCenter2" ascii wide nocase
        $query2 = "AntiVirusProduct" ascii wide nocase

        // WMI access methods
        $method1 = "ExecQuery" ascii wide nocase
        $method2 = "winmgmts" ascii wide nocase
        $method3 = "root\\SecurityCenter2" ascii wide nocase
        $method4 = "root/SecurityCenter2" ascii wide nocase

    condition:
        filesize < 1MB and
        $query1 and $query2 and
        any of ($method*)
}


/*
    ============================================================
    Rule: NICECURL_Curl_C2_Beacon
    Confidence: Medium
    Description: Detects files containing curl.exe command patterns with
                 indicators of C2 beacon activity: base64-encoded data,
                 Glitch.me domains, and custom User-Agent strings.
    ============================================================
*/
rule NICECURL_Curl_C2_Beacon
{
    meta:
        description = "Detects scripts or configs with curl.exe C2 beacon patterns targeting Glitch.me infrastructure"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-24"
        test_id = "8e2cf534-857b-4d29-a1ac-0f23d248db93"
        mitre_attack = "T1071.001, T1105"
        confidence = "medium"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations"

    strings:
        // curl.exe invocation
        $curl = "curl" ascii wide nocase

        // C2 domain patterns
        $domain1 = "glitch.me" ascii wide nocase
        $domain2 = ".glitch.me/" ascii wide nocase

        // Beacon patterns
        $beacon1 = "beacon" ascii wide nocase
        $beacon2 = "X-Request-ID" ascii wide nocase
        $beacon3 = "NICECURL" ascii wide nocase

        // HTTP method indicators
        $http1 = "POST" ascii wide
        $http2 = "--data" ascii wide
        $http3 = "-X POST" ascii wide

    condition:
        filesize < 1MB and
        $curl and
        any of ($domain*) and
        (any of ($beacon*) or any of ($http*))
}
