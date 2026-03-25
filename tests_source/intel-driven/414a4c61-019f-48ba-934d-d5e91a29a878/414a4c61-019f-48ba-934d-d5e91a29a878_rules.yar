/*
    ============================================================
    UNK_RobotDreams Rust Backdoor Detection - YARA Rules
    Test ID: 414a4c61-019f-48ba-934d-d5e91a29a878
    MITRE ATT&CK: T1204.002, T1059.001, T1105, T1071.001, T1573.001, T1036.005
    Threat Actor: UNK_RobotDreams (Pakistan-aligned)
    Author: F0RT1KA sectest-builder
    Date: 2026-03-24
    ============================================================

    These rules detect UNK_RobotDreams attack artifacts: PDF lures with
    embedded URI actions, PowerShell download cradle patterns, and
    encrypted C2 beacon staging files.

    IMPORTANT: These rules target technique-level behaviors and real-world
    attack artifacts. They do NOT detect F0RT1KA test framework artifacts.

    Usage:
        yara -r 414a4c61-019f-48ba-934d-d5e91a29a878_rules.yar /path/to/scan

    ============================================================
*/


/*
    ============================================================
    Rule: UNK_RobotDreams_PDF_Lure_With_URI_Action
    Confidence: High
    Description: Detects PDF files containing OpenAction with URI
                 action pointing to executable downloads. The
                 UNK_RobotDreams campaign uses PDF lures themed as
                 Gulf Security Alerts with fake Adobe buttons that
                 trigger downloads from Azure Front Door.
    ============================================================
*/
rule UNK_RobotDreams_PDF_Lure_With_URI_Action
{
    meta:
        description = "Detects PDF files with OpenAction URI pointing to executable download - UNK_RobotDreams spearphishing pattern"
        author = "F0RT1KA sectest-builder"
        date = "2026-03-24"
        test_id = "414a4c61-019f-48ba-934d-d5e91a29a878"
        mitre_attack = "T1204.002"
        confidence = "high"
        reference = "https://gbhackers.com/iran-war-bait/"

    strings:
        // PDF header
        $pdf_header = "%PDF-" ascii

        // OpenAction with URI action pattern
        $open_action = "/OpenAction" ascii nocase
        $uri_action = "/S /URI" ascii nocase

        // Executable download references
        $exe_uri1 = ".exe" ascii nocase
        $exe_uri2 = "azurefd.net" ascii nocase
        $exe_uri3 = "azureedge.net" ascii nocase

        // Gulf Security Alert themed content
        $lure1 = "Gulf" ascii nocase
        $lure2 = "Security Alert" ascii nocase
        $lure3 = "Ministry" ascii nocase
        $lure4 = "External Affairs" ascii nocase

        // Fake Adobe button social engineering
        $adobe1 = "Adobe Reader" ascii nocase
        $adobe2 = "secure viewing" ascii nocase
        $adobe3 = "enable" ascii nocase

    condition:
        $pdf_header at 0
        and $open_action
        and $uri_action
        and ($exe_uri1 or $exe_uri2 or $exe_uri3)
        and (2 of ($lure*) or 2 of ($adobe*))
}


/*
    ============================================================
    Rule: PowerShell_Hidden_Download_Cradle
    Confidence: High
    Description: Detects PowerShell scripts or command lines containing
                 hidden window execution combined with web download
                 cmdlets. This is the staging mechanism used by
                 UNK_RobotDreams and many other threat actors.
    ============================================================
*/
rule PowerShell_Hidden_Download_Cradle
{
    meta:
        description = "Detects PowerShell hidden window download cradle pattern used for payload staging"
        author = "F0RT1KA sectest-builder"
        date = "2026-03-24"
        test_id = "414a4c61-019f-48ba-934d-d5e91a29a878"
        mitre_attack = "T1059.001, T1105"
        confidence = "high"

    strings:
        // Hidden window indicators
        $hidden1 = "-w hidden" ascii nocase
        $hidden2 = "-WindowStyle Hidden" ascii nocase
        $hidden3 = "-windowstyle h" ascii nocase

        // Download cmdlets
        $download1 = "Invoke-WebRequest" ascii nocase
        $download2 = "iwr " ascii nocase
        $download3 = "Invoke-RestMethod" ascii nocase
        $download4 = "Net.WebClient" ascii nocase
        $download5 = "DownloadFile" ascii nocase
        $download6 = "Start-BitsTransfer" ascii nocase

        // Output file indicators
        $outfile1 = "-OutFile" ascii nocase
        $outfile2 = "-outf" ascii nocase
        $outfile3 = "agent.exe" ascii nocase

        // Execution after download
        $exec1 = "Start-Process" ascii nocase
        $exec2 = "start " ascii nocase
        $exec3 = "& " ascii

    condition:
        filesize < 50KB
        and (1 of ($hidden*))
        and (1 of ($download*))
        and (1 of ($outfile*) or 1 of ($exec*))
}


/*
    ============================================================
    Rule: AES_Encrypted_Beacon_Staging_File
    Confidence: Medium
    Description: Detects files containing base64-encoded data that
                 appears to be AES-encrypted C2 beacon payloads.
                 UNK_RobotDreams Rust backdoor encrypts system metadata
                 with AES-256-GCM before staging for exfiltration.
    ============================================================
*/
rule AES_Encrypted_Beacon_Staging_File
{
    meta:
        description = "Detects staging files containing AES-encrypted beacon data in base64 encoding"
        author = "F0RT1KA sectest-builder"
        date = "2026-03-24"
        test_id = "414a4c61-019f-48ba-934d-d5e91a29a878"
        mitre_attack = "T1573.001, T1071.001"
        confidence = "medium"

    strings:
        // Base64-encoded data patterns (high entropy blocks)
        // AES-GCM output starts with 12-byte nonce followed by ciphertext
        // When base64-encoded, produces continuous alphanumeric blocks
        $b64_block = /[A-Za-z0-9+\/]{64,}={0,2}/ ascii

    condition:
        filesize < 10KB
        and filesize > 50
        and #b64_block >= 1
        and @b64_block[1] == 0
}


/*
    ============================================================
    Rule: Azure_Front_Door_Domain_Fronting_Script
    Confidence: Medium
    Description: Detects scripts or configuration files containing
                 Azure Front Door or Azure CDN domain references
                 combined with executable download patterns. This
                 models the CDN infrastructure abuse technique.
    ============================================================
*/
rule Azure_Front_Door_Domain_Fronting_Script
{
    meta:
        description = "Detects scripts referencing Azure Front Door/CDN domains with executable download patterns"
        author = "F0RT1KA sectest-builder"
        date = "2026-03-24"
        test_id = "414a4c61-019f-48ba-934d-d5e91a29a878"
        mitre_attack = "T1036.005, T1071.001"
        confidence = "medium"

    strings:
        // Azure CDN domains
        $azure1 = "azurefd.net" ascii nocase
        $azure2 = "azureedge.net" ascii nocase
        $azure3 = "trafficmanager.net" ascii nocase

        // Download or execution indicators
        $action1 = ".exe" ascii nocase
        $action2 = "agent" ascii nocase
        $action3 = "update" ascii nocase
        $action4 = "download" ascii nocase

        // HTTP/HTTPS patterns
        $http1 = "https://" ascii nocase
        $http2 = "POST" ascii nocase
        $http3 = "Host:" ascii nocase

    condition:
        filesize < 100KB
        and (1 of ($azure*))
        and (1 of ($action*))
        and (1 of ($http*))
}
