/*
    ============================================================
    YARA Rule Set: PowerShell Execution & AMSI Bypass Detection
    Test ID: f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01
    MITRE ATT&CK: T1059.001, T1140
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-03-14
    ============================================================
    These rules target technique-inherent behaviors:
    - PowerShell encoded command execution arguments
    - AMSI bypass indicator strings used by real attackers
    - Base64 deobfuscation patterns in PowerShell scripts
    - Download cradle construction patterns
    ============================================================
*/

/*
    ============================================================
    Rule: AMSI Bypass Pattern - AmsiScanBuffer Patching
    Confidence: High
    Description: Detects scripts or binaries containing strings characteristic
                 of AmsiScanBuffer patching techniques. This function is the
                 primary target for AMSI bypass because patching it prevents
                 AMSI from scanning subsequent PowerShell content.
    ============================================================
*/
rule AMSI_Bypass_AmsiScanBuffer_Patch
{
    meta:
        description = "Detects AMSI bypass attempt targeting AmsiScanBuffer function"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01"
        mitre_attack = "T1059.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $amsi_func      = "AmsiScanBuffer" ascii wide nocase
        $amsi_init      = "amsiInitFailed" ascii wide nocase
        $amsi_dll       = "amsi.dll" ascii wide nocase
        $amsi_init2     = "AmsiInitialize" ascii wide nocase
        $amsi_scan_str  = "AmsiScanString" ascii wide nocase
        // Hex-encoded "AmsiScanBuffer" (UTF-16LE common in PowerShell scripts)
        $amsi_hex_utf16 = { 41 00 6D 00 73 00 69 00 53 00 63 00 61 00 6E 00 42 00 75 00 66 00 66 00 65 00 72 00 }

    condition:
        any of ($amsi_func, $amsi_init, $amsi_dll, $amsi_init2, $amsi_scan_str, $amsi_hex_utf16)
}

/*
    ============================================================
    Rule: AMSI Bypass - Reflection-Based AmsiUtils Tampering
    Confidence: High
    Description: Detects the reflection-based AMSI bypass technique that uses
                 .NET reflection to locate and patch AmsiUtils. This is one of
                 the most prevalent AMSI bypass families and is present in many
                 commodity and APT toolkits.
    ============================================================
*/
rule AMSI_Bypass_Reflection_AmsiUtils
{
    meta:
        description = "Detects reflection-based AMSI bypass via System.Management.Automation.AmsiUtils"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01"
        mitre_attack = "T1059.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $amsi_utils      = "System.Management.Automation.AmsiUtils" ascii wide nocase
        $amsi_utils_s    = "AmsiUtils" ascii wide nocase
        $ref_assembly    = "[Ref].Assembly.GetType" ascii wide nocase
        $ref_assembly2   = "GetType('System.Management.Automation.AmsiUtils')" ascii wide nocase
        $get_field       = "GetField('amsiInitFailed'" ascii wide nocase
        $set_value       = "SetValue($null,$true)" ascii wide nocase
        // UTF-16LE encoded "[Ref]" commonly found in in-memory PS scripts
        $ref_utf16       = { 5B 00 52 00 65 00 66 00 5D 00 }

    condition:
        ($amsi_utils or $amsi_utils_s) and
        ($ref_assembly or $ref_assembly2 or $get_field or $set_value)
}

/*
    ============================================================
    Rule: PowerShell Encoded Command Script File
    Confidence: Medium
    Description: Detects PowerShell script files (.ps1) containing patterns
                 associated with runtime base64 decoding followed by execution.
                 Real attackers use this to deliver obfuscated second-stage
                 payloads that bypass static script inspection.
    ============================================================
*/
rule PowerShell_Base64_Deobfuscation_Execution
{
    meta:
        description = "Detects PowerShell scripts that decode and execute base64 content at runtime"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01"
        mitre_attack = "T1140"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1140/"

    strings:
        $from_b64        = "FromBase64String" ascii wide nocase
        $from_b64_full   = "[System.Convert]::FromBase64String" ascii wide nocase
        $encoding_uni    = "[System.Text.Encoding]::Unicode" ascii wide nocase
        $encoding_utf8   = "[System.Text.Encoding]::UTF8" ascii wide nocase
        $iex             = "IEX" ascii wide
        $invoke_expr     = "Invoke-Expression" ascii wide nocase
        $get_string      = "GetString(" ascii wide nocase
        // Common encoded PS that calls IEX after decode
        $iex_b64_pattern = { 49 45 58 20 28 5B } // "IEX ([" in ASCII

    condition:
        filesize < 5MB and
        ($from_b64 or $from_b64_full) and
        ($iex or $invoke_expr) and
        ($encoding_uni or $encoding_utf8 or $get_string)
}

/*
    ============================================================
    Rule: PowerShell Download Cradle Patterns
    Confidence: High
    Description: Detects PowerShell scripts or documents containing download
                 cradle constructs. Download cradles are used to retrieve and
                 execute remote code without writing payloads to disk, making
                 them a primary fileless execution vector.
    ============================================================
*/
rule PowerShell_Download_Cradle
{
    meta:
        description = "Detects PowerShell download cradle patterns used for fileless payload delivery"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01"
        mitre_attack = "T1059.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $webclient        = "New-Object Net.WebClient" ascii wide nocase
        $webclient2       = "New-Object System.Net.WebClient" ascii wide nocase
        $download_string  = "DownloadString(" ascii wide nocase
        $download_file    = "DownloadFile(" ascii wide nocase
        $download_data    = "DownloadData(" ascii wide nocase
        $invoke_webreq    = "Invoke-WebRequest" ascii wide nocase
        $iwr              = "iwr " ascii wide
        $iex              = "IEX" ascii wide
        $invoke_expr      = "Invoke-Expression" ascii wide nocase
        // Hex bytes for "Net.WebClient" in UTF-16LE
        $webclient_utf16  = { 4E 00 65 00 74 00 2E 00 57 00 65 00 62 00 43 00 6C 00 69 00 65 00 6E 00 74 00 }

    condition:
        filesize < 10MB and
        ($webclient or $webclient2 or $webclient_utf16) and
        ($download_string or $download_file or $download_data) and
        ($iex or $invoke_expr)
}

/*
    ============================================================
    Rule: PowerShell Obfuscated Execution - Suspicious Argument Combination
    Confidence: High
    Description: Detects scripts or documents that spawn powershell.exe with
                 characteristic combinations of evasion arguments. The specific
                 combination of -EncodedCommand with -ExecutionPolicy Bypass and
                 -WindowStyle Hidden is a well-known attacker pattern.
    ============================================================
*/
rule PowerShell_Suspicious_Argument_Combination
{
    meta:
        description = "Detects suspicious powershell.exe argument combinations used in attacks"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01"
        mitre_attack = "T1059.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $ps_exe           = "powershell.exe" ascii wide nocase
        $enc_cmd          = "-EncodedCommand" ascii wide nocase
        $enc_cmd_s        = "-enc " ascii wide nocase
        $enc_cmd_e        = "-ec " ascii wide nocase
        $bypass           = "-ExecutionPolicy Bypass" ascii wide nocase
        $bypass_s         = "-ep bypass" ascii wide nocase
        $bypass_b         = "-ep b" ascii wide nocase
        $hidden           = "-WindowStyle Hidden" ascii wide nocase
        $hidden_s         = "-w hidden" ascii wide nocase
        $hidden_h         = "-wi h" ascii wide nocase
        $noprofile        = "-NoProfile" ascii wide nocase
        $nop              = "-nop" ascii wide nocase
        $noninteractive   = "-NonInteractive" ascii wide nocase
        $noni             = "-noni" ascii wide nocase

    condition:
        filesize < 50MB and
        $ps_exe and
        ($enc_cmd or $enc_cmd_s or $enc_cmd_e) and
        ($bypass or $bypass_s or $bypass_b) and
        ($hidden or $hidden_s or $hidden_h)
}
