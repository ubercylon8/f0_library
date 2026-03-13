/*
============================================================================
DEFENSE GUIDANCE: YARA Detection Rules
============================================================================
Test ID: f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06
Test Name: LOLBIN Download Detection
MITRE ATT&CK: T1105 - Ingress Tool Transfer, T1059.001 - PowerShell
Created: 2026-03-13
Author: F0RT1KA Defense Guidance Builder
============================================================================

TECHNIQUE-FOCUSED DETECTION PRINCIPLE:
These YARA rules detect scripts, batch files, and tools that orchestrate
LOLBIN-based downloads. They target the technique patterns themselves
(certutil download flags, bitsadmin transfer commands, PowerShell download
cradles), NOT the F0RT1KA testing framework.

============================================================================
*/


// ============================================================================
// RULE 1: Script Containing Certutil Download Commands
// Detects scripts or documents embedding certutil download patterns
// ============================================================================

rule LOLBIN_Certutil_Download_Script
{
    meta:
        description = "Detects scripts or files containing certutil download command patterns used for ingress tool transfer"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06"
        mitre_attack = "T1105"
        confidence = "high"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1105/"
        reference2 = "https://lolbas-project.github.io/lolbas/Binaries/Certutil/"

    strings:
        // Certutil download patterns
        $certutil_url1 = "certutil" ascii wide nocase
        $certutil_flag1 = "-urlcache" ascii wide nocase
        $certutil_flag2 = "-split" ascii wide nocase
        $certutil_flag3 = "-f " ascii wide nocase
        $certutil_flag4 = "/urlcache" ascii wide nocase

        // Certutil encode/decode (alternate file transfer)
        $certutil_enc1 = "-encode" ascii wide nocase
        $certutil_enc2 = "-decode" ascii wide nocase
        $certutil_enc3 = "/encode" ascii wide nocase
        $certutil_enc4 = "/decode" ascii wide nocase

        // URL indicators
        $url1 = "http://" ascii wide nocase
        $url2 = "https://" ascii wide nocase
        $url3 = "ftp://" ascii wide nocase

    condition:
        filesize < 5MB and
        $certutil_url1 and
        (
            (1 of ($certutil_flag*) and 1 of ($url*)) or
            (1 of ($certutil_enc*))
        )
}


// ============================================================================
// RULE 2: Script Containing BITSAdmin Download Commands
// Detects scripts using bitsadmin for file transfer
// ============================================================================

rule LOLBIN_BITSAdmin_Download_Script
{
    meta:
        description = "Detects scripts or files containing bitsadmin transfer command patterns used for ingress tool transfer"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06"
        mitre_attack = "T1105"
        confidence = "high"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1105/"
        reference2 = "https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/"

    strings:
        // BITSAdmin command patterns
        $bits1 = "bitsadmin" ascii wide nocase
        $transfer1 = "/transfer" ascii wide nocase
        $transfer2 = "/addfile" ascii wide nocase
        $transfer3 = "/create" ascii wide nocase
        $transfer4 = "/resume" ascii wide nocase
        $transfer5 = "/download" ascii wide nocase

        // URL indicators
        $url1 = "http://" ascii wide nocase
        $url2 = "https://" ascii wide nocase

    condition:
        filesize < 5MB and
        $bits1 and
        1 of ($transfer*) and
        1 of ($url*)
}


// ============================================================================
// RULE 3: PowerShell Download Cradle Patterns
// Detects scripts containing PowerShell download methods
// ============================================================================

rule LOLBIN_PowerShell_Download_Cradle
{
    meta:
        description = "Detects scripts containing PowerShell download cradle patterns including IWR, WebClient, and BITS transfer methods"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06"
        mitre_attack = "T1059.001"
        confidence = "high"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        // PowerShell download methods
        $ps_iwr1 = "Invoke-WebRequest" ascii wide nocase
        $ps_iwr2 = "iwr " ascii wide nocase
        $ps_irm1 = "Invoke-RestMethod" ascii wide nocase
        $ps_irm2 = "irm " ascii wide nocase
        $ps_wc1 = "Net.WebClient" ascii wide nocase
        $ps_wc2 = "System.Net.WebClient" ascii wide nocase
        $ps_wc3 = "New-Object Net.WebClient" ascii wide nocase
        $ps_dl1 = ".DownloadFile(" ascii wide nocase
        $ps_dl2 = ".DownloadString(" ascii wide nocase
        $ps_dl3 = ".DownloadData(" ascii wide nocase
        $ps_bits1 = "Start-BitsTransfer" ascii wide nocase
        $ps_http1 = "Net.HttpWebRequest" ascii wide nocase
        $ps_http2 = "[System.Net.WebRequest]::Create" ascii wide nocase

        // Output redirection indicators
        $out1 = "-OutFile" ascii wide nocase
        $out2 = "-Destination" ascii wide nocase
        $out3 = "Set-Content" ascii wide nocase
        $out4 = "Out-File" ascii wide nocase

        // URL indicators
        $url1 = "http://" ascii wide nocase
        $url2 = "https://" ascii wide nocase

    condition:
        filesize < 5MB and
        1 of ($ps_*) and
        1 of ($url*) and
        (1 of ($out*) or 1 of ($ps_dl*))
}


// ============================================================================
// RULE 4: Multi-LOLBIN Download Script
// HIGH CONFIDENCE: Detects scripts that chain multiple LOLBIN download
// methods - a hallmark of attacker toolkits and penetration testing tools
// ============================================================================

rule LOLBIN_Multi_Download_Toolkit
{
    meta:
        description = "Detects scripts containing multiple distinct LOLBIN download methods, indicating an attacker toolkit or automated download tool"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06"
        mitre_attack = "T1105,T1059.001"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1105/"

    strings:
        // Certutil download
        $method_certutil = "certutil" ascii wide nocase
        $certutil_dl = "-urlcache" ascii wide nocase

        // BITSAdmin download
        $method_bits = "bitsadmin" ascii wide nocase
        $bits_dl = "/transfer" ascii wide nocase

        // PowerShell download
        $method_ps_iwr = "Invoke-WebRequest" ascii wide nocase
        $method_ps_wc = "WebClient" ascii wide nocase
        $method_ps_dl = "DownloadFile" ascii wide nocase

        // Curl download
        $method_curl1 = "curl.exe" ascii wide nocase
        $method_curl2 = "curl -o" ascii wide nocase
        $method_curl3 = "curl --output" ascii wide nocase

        // Wget
        $method_wget = "wget " ascii wide nocase

        // URL indicators
        $url1 = "http://" ascii wide nocase
        $url2 = "https://" ascii wide nocase

    condition:
        filesize < 5MB and
        1 of ($url*) and
        (
            // At least 2 distinct LOLBIN download methods in one file
            (($method_certutil and $certutil_dl) and ($method_bits and $bits_dl)) or
            (($method_certutil and $certutil_dl) and 1 of ($method_ps_*)) or
            (($method_certutil and $certutil_dl) and 1 of ($method_curl*)) or
            (($method_bits and $bits_dl) and 1 of ($method_ps_*)) or
            (($method_bits and $bits_dl) and 1 of ($method_curl*)) or
            (1 of ($method_ps_*) and 1 of ($method_curl*)) or
            // 3+ methods is extremely suspicious
            (($method_certutil and $certutil_dl) and ($method_bits and $bits_dl) and 1 of ($method_ps_*))
        )
}


// ============================================================================
// RULE 5: Encoded PowerShell Download Command
// Detects Base64-encoded PowerShell that contains download patterns
// ============================================================================

rule LOLBIN_Encoded_PowerShell_Download
{
    meta:
        description = "Detects Base64-encoded PowerShell commands containing download patterns, commonly used to evade command-line logging"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06"
        mitre_attack = "T1059.001"
        confidence = "medium"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        // PowerShell encoded command indicators
        $ps_enc1 = "-EncodedCommand" ascii wide nocase
        $ps_enc2 = "-enc " ascii wide nocase
        $ps_enc3 = "-ec " ascii wide nocase
        $ps_enc4 = "-e " ascii wide nocase

        // Base64 encoded versions of common download strings
        // "IEX" base64 = "SUVY"
        $b64_iex = "SUVY" ascii wide
        // "Net.WebClient" partial base64
        $b64_wc1 = "TgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdA" ascii wide
        // "DownloadString" partial base64
        $b64_dl1 = "RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBn" ascii wide
        // "DownloadFile" partial base64
        $b64_dl2 = "RABvAHcAbgBsAG8AYQBkAEYAaQBsAGUA" ascii wide
        // "Invoke-WebRequest" partial base64
        $b64_iwr = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0" ascii wide

        // PowerShell launcher patterns
        $ps_launch1 = "powershell" ascii wide nocase
        $ps_launch2 = "pwsh" ascii wide nocase

    condition:
        filesize < 5MB and
        1 of ($ps_launch*) and
        1 of ($ps_enc*) and
        1 of ($b64_*)
}


// ============================================================================
// RULE 6: Batch File with LOLBIN Download Chain
// Detects batch scripts orchestrating LOLBIN downloads
// ============================================================================

rule LOLBIN_Batch_Download_Chain
{
    meta:
        description = "Detects batch files (.bat/.cmd) that use LOLBIN commands to download files from the internet"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06"
        mitre_attack = "T1105"
        confidence = "medium"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1105/"

    strings:
        // Batch file indicators
        $batch1 = "@echo off" ascii nocase
        $batch2 = "echo off" ascii nocase
        $batch3 = "%~dp0" ascii
        $batch4 = "setlocal" ascii nocase

        // LOLBIN download commands in batch context
        $dl_certutil = "certutil" ascii nocase
        $dl_bits = "bitsadmin" ascii nocase
        $dl_curl = "curl.exe" ascii nocase
        $dl_ps = "powershell" ascii nocase
        $dl_wget = "wget" ascii nocase

        // Download action indicators
        $action1 = "-urlcache" ascii nocase
        $action2 = "/transfer" ascii nocase
        $action3 = "-o " ascii nocase
        $action4 = "DownloadFile" ascii nocase
        $action5 = "Invoke-WebRequest" ascii nocase

        // URL patterns
        $url1 = "http://" ascii nocase
        $url2 = "https://" ascii nocase

    condition:
        filesize < 1MB and
        1 of ($batch*) and
        1 of ($dl_*) and
        1 of ($action*) and
        1 of ($url*)
}
