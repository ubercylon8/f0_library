/*
    ============================================================
    HONESTCUE LLM-Assisted Runtime C# Compilation — YARA Rules
    Test ID: e5472cd5-c799-4b07-b455-8c02665ca4cf
    MITRE ATT&CK: T1071.001, T1027.004, T1027.010, T1620, T1105, T1583.006, T1565.001
    Threat Actor: N/A (unattributed per GTIG)
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-04-13
    ============================================================

    These rules target HONESTCUE-class TTPs: LLM-API-driven runtime C# source
    delivery, in-memory CSharpCodeProvider compilation, reflective Assembly.Load
    patterns, Discord-CDN abuse, and hosts-file redirect manipulation.

    Rules are technique-level. They do NOT detect F0RT1KA test framework
    artifacts (UUIDs, test-specific filenames, or build infrastructure).

    Usage:
        yara -r e5472cd5-c799-4b07-b455-8c02665ca4cf_rules.yar /path/to/scan

    ============================================================
*/

import "pe"

// -----------------------------------------------------------------
// Rule 1: LLM runtime source fetch + in-memory C# compile loader
// -----------------------------------------------------------------
rule HONESTCUE_Class_LLM_Runtime_Compile_Loader
{
    meta:
        author      = "F0RT1KA Defense Guidance Builder"
        description = "HONESTCUE-class loader: PowerShell/C# script fetching LLM-sourced C# and invoking CSharpCodeProvider with GenerateInMemory"
        mitre_attck = "T1027.004, T1620"
        severity    = "high"
        date        = "2026-04-13"

    strings:
        // PowerShell + CSharpCodeProvider in-memory compile pattern
        $ps_compile_a  = "CSharpCodeProvider" ascii wide nocase
        $ps_compile_b  = "CompileAssemblyFromSource" ascii wide nocase
        $ps_params     = "GenerateInMemory" ascii wide nocase
        $ps_refload_a  = "Assembly" ascii wide
        $ps_refload_b  = "::Load(" ascii wide nocase
        $ps_byte_arr_a = "[byte[]]" ascii wide nocase
        $ps_byte_arr_b = "byte[]" ascii wide nocase

        // LLM API endpoints referenced at runtime
        $llm_gemini    = "generativelanguage.googleapis.com" ascii wide nocase
        $llm_openai    = "api.openai.com" ascii wide nocase
        $llm_anthropic = "api.anthropic.com" ascii wide nocase
        $llm_path      = "v1beta/models" ascii wide nocase
        $llm_method    = "generateContent" ascii wide nocase

        // Gemini response schema the loader parses
        $sch_candidates = "\"candidates\"" ascii wide
        $sch_content    = "\"content\"" ascii wide
        $sch_parts      = "\"parts\"" ascii wide
        $sch_text       = "\"text\"" ascii wide

    condition:
        // Two strong compile signals AND a reflective load pattern AND an LLM reference
        2 of ($ps_compile_a, $ps_compile_b, $ps_params)
        and ($ps_refload_a and $ps_refload_b and any of ($ps_byte_arr_*))
        and any of ($llm_*)
        and 2 of ($sch_*)
}


// -----------------------------------------------------------------
// Rule 2: Reflective Assembly.Load(byte[]) pattern in scripts/PE
// -----------------------------------------------------------------
rule Reflective_Assembly_Load_Byte_Array
{
    meta:
        author      = "F0RT1KA Defense Guidance Builder"
        description = "Reflective .NET assembly load via Assembly.Load(byte[]) — HONESTCUE stage-2 hallmark"
        mitre_attck = "T1620"
        severity    = "medium"
        date        = "2026-04-13"

    strings:
        $a = "[System.Reflection.Assembly]::Load" ascii wide nocase
        $b = "System.Reflection.Assembly.Load" ascii wide nocase
        $c = "[Reflection.Assembly]::Load" ascii wide nocase
        $arr1 = "[byte[]]" ascii wide nocase
        $arr2 = "byte[]" ascii wide nocase
        $arr3 = "System.Byte[]" ascii wide nocase

    condition:
        any of ($a, $b, $c) and any of ($arr1, $arr2, $arr3)
}


// -----------------------------------------------------------------
// Rule 3: CDN-abuse loader pattern (Discord CDN + redirect)
// -----------------------------------------------------------------
rule CDN_Abuse_Discord_Loader_Pattern
{
    meta:
        author      = "F0RT1KA Defense Guidance Builder"
        description = "Loader that fetches payloads from cdn.discordapp.com and drops to %TEMP% — HONESTCUE stage-3 pattern"
        mitre_attck = "T1105, T1583.006"
        severity    = "medium"
        date        = "2026-04-13"

    strings:
        $cdn_a = "cdn.discordapp.com" ascii wide nocase
        $cdn_b = "media.discordapp.net" ascii wide nocase
        $cdn_path = "/attachments/" ascii wide nocase
        $temp_drop_a = "\\Windows\\Temp\\" ascii wide nocase
        $temp_drop_b = "\\AppData\\Local\\Temp\\" ascii wide nocase
        $exe_ext = ".exe" ascii wide nocase
        $http_get = "HTTP/1.1" ascii wide
        $host_hdr = "Host: cdn.discordapp" ascii wide nocase

    condition:
        any of ($cdn_*)
        and $cdn_path
        and any of ($temp_drop_*)
        and $exe_ext
        and any of ($http_get, $host_hdr)
}


// -----------------------------------------------------------------
// Rule 4: Hosts-file redirect containing trusted CDN hostnames
// -----------------------------------------------------------------
rule Hosts_File_CDN_Redirect_Manipulation
{
    meta:
        author      = "F0RT1KA Defense Guidance Builder"
        description = "Hosts file containing a redirect entry for a trusted CDN/cloud hostname to loopback or RFC1918"
        mitre_attck = "T1565.001"
        severity    = "high"
        date        = "2026-04-13"

    strings:
        $loop1 = "127.0.0.1" ascii
        $loop2 = "0.0.0.0" ascii
        $loop3 = "::1" ascii
        $cdn1 = "cdn.discordapp.com" ascii wide nocase
        $cdn2 = "media.discordapp.net" ascii wide nocase
        $cdn3 = "raw.githubusercontent.com" ascii wide nocase
        $cdn4 = "api.github.com" ascii wide nocase
        $cdn5 = "generativelanguage.googleapis.com" ascii wide nocase
        $cdn6 = "cdn.jsdelivr.net" ascii wide nocase

    condition:
        // A hosts-file line would have loopback/blackhole + CDN hostname on same line
        filesize < 1MB
        and any of ($loop*)
        and any of ($cdn*)
}


// -----------------------------------------------------------------
// Rule 5: Non-browser HTTP client invoking Gemini generateContent
// -----------------------------------------------------------------
rule LLM_API_Invocation_NonBrowser_Client
{
    meta:
        author      = "F0RT1KA Defense Guidance Builder"
        description = "Binary containing hardcoded Gemini/LLM API endpoints with non-browser User-Agent strings"
        mitre_attck = "T1071.001"
        severity    = "medium"
        date        = "2026-04-13"

    strings:
        $ep1 = "v1beta/models" ascii wide nocase
        $ep2 = "generateContent" ascii wide nocase
        $ep3 = ":generateContent" ascii wide nocase
        $llm1 = "generativelanguage.googleapis.com" ascii wide nocase
        $llm2 = "api.openai.com" ascii wide nocase
        $llm3 = "api.anthropic.com" ascii wide nocase
        $hdr1 = "x-goog-api-key" ascii wide nocase
        $hdr2 = "Authorization: Bearer sk-" ascii wide nocase
        $hdr3 = "anthropic-version" ascii wide nocase
        $ua_suspect1 = "User-Agent: Mozilla" ascii wide nocase  // too-generic UA in malware
        $ua_suspect2 = "User-Agent: curl" ascii wide nocase

    condition:
        // Hardcoded LLM endpoint + API key header. NOT a rule about legitimate SDKs
        // (those embed richer UA + version strings); malware tends to use minimal UA.
        any of ($ep*)
        and any of ($llm*)
        and any of ($hdr*)
        and not pe.version_info["CompanyName"] contains "Google"
        and not pe.version_info["CompanyName"] contains "OpenAI"
        and not pe.version_info["CompanyName"] contains "Anthropic"
        and not pe.version_info["CompanyName"] contains "Microsoft"
}
