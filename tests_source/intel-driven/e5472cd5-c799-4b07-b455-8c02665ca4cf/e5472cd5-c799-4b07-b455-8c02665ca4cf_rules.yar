/*
    ============================================================
    HONESTCUE v2 LLM-Assisted Runtime C# Compilation — YARA Rules
    Test ID: e5472cd5-c799-4b07-b455-8c02665ca4cf
    MITRE ATT&CK: T1071.001, T1027.004, T1027.010, T1620, T1105, T1204.002
    Threat Actor: N/A (unattributed per GTIG)
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-04-13 (v2)
    ============================================================

    These rules target HONESTCUE-class TTPs: LLM-API-driven runtime C# source
    delivery via trusted-hosting CDN, in-memory Roslyn compilation,
    Assembly.Load(byte[]) reflective loads, and PE drop-from-GitHub-raw
    followed by execution under c:\Windows\Temp.

    v2 IOCs differ from v1:
      - raw.githubusercontent.com replaces cdn.discordapp.com
      - Microsoft.CodeAnalysis.CSharp (Roslyn) replaces CSharpCodeProvider
      - No hosts-file IOC (v1's hosts-redirect rule is replaced by
        Rule 5 that matches the Gemini-shaped JSON IOC on disk)

    Rules are technique-level. They do NOT detect F0RT1KA test framework
    artifacts (UUIDs, test-specific filenames, or build infrastructure).

    Usage:
        yara -r e5472cd5-c799-4b07-b455-8c02665ca4cf_rules.yar /path/to/scan

    ============================================================
*/

import "pe"

// -----------------------------------------------------------------
// Rule 1: Exact GTIG HONESTCUE prompts embedded in binary
// -----------------------------------------------------------------
rule HONESTCUE_Exact_GTIG_Prompts
{
    meta:
        author      = "F0RT1KA Defense Guidance Builder"
        description = "Binary containing verbatim GTIG-disclosed HONESTCUE prompts as string constants"
        mitre_attck = "T1071.001, T1027.004"
        severity    = "high"
        date        = "2026-04-13"
        reference   = "https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use"

    strings:
        // Distinctive phrases from the three exact GTIG prompts
        $p1 = "HonestcueStage2" ascii wide nocase
        $p2 = "You are an expert C# developer" ascii wide nocase
        $p3 = ".NET Framework 4.x APIs" ascii wide nocase
        $p4 = "Windows Defender\\Features" ascii wide nocase
        $p5 = "public static string Run()" ascii wide nocase
        $p6 = "Return only the source code" ascii wide nocase
        $p7 = "no markdown formatting or explanation" ascii wide nocase

    condition:
        // The class name HonestcueStage2 is highly specific — match on it plus
        // any corroborating prompt phrase.
        $p1 and 2 of ($p2, $p3, $p4, $p5, $p6, $p7)
}


// -----------------------------------------------------------------
// Rule 2: Roslyn in-memory compile + reflective load pattern
// -----------------------------------------------------------------
rule HONESTCUE_Class_Roslyn_Runtime_Compile_Loader
{
    meta:
        author      = "F0RT1KA Defense Guidance Builder"
        description = "HONESTCUE-class .NET loader: Roslyn CSharpCompilation + Assembly.Load(byte[])"
        mitre_attck = "T1027.004, T1620"
        severity    = "high"
        date        = "2026-04-13"

    strings:
        // Roslyn API surface
        $roslyn_ns_a    = "Microsoft.CodeAnalysis" ascii wide nocase
        $roslyn_ns_b    = "Microsoft.CodeAnalysis.CSharp" ascii wide nocase
        $roslyn_api_a   = "CSharpCompilation" ascii wide nocase
        $roslyn_api_b   = "CSharpSyntaxTree" ascii wide nocase
        $roslyn_api_c   = "CSharpCompilationOptions" ascii wide nocase
        $roslyn_api_d   = "CompilationOptions" ascii wide nocase
        $roslyn_emit    = "Emit(" ascii wide nocase
        $roslyn_ms      = "MemoryStream" ascii wide nocase

        // Legacy CSharpCodeProvider path (kept for completeness; HONESTCUE on
        // .NET Framework 4.x hosts will still match these)
        $legacy_a       = "CSharpCodeProvider" ascii wide nocase
        $legacy_b       = "CompileAssemblyFromSource" ascii wide nocase
        $legacy_params  = "GenerateInMemory" ascii wide nocase

        // Reflective load
        $refload_a = "Assembly" ascii wide
        $refload_b = "::Load(" ascii wide nocase
        $refload_c = ".Load(" ascii wide
        $byte_arr  = "byte[]" ascii wide nocase

        // Gemini response schema the loader parses
        $sch_candidates = "\"candidates\"" ascii wide
        $sch_content    = "\"content\"" ascii wide
        $sch_parts      = "\"parts\"" ascii wide
        $sch_text       = "\"text\"" ascii wide

    condition:
        // Match Roslyn path OR legacy path, plus reflective load, plus Gemini schema.
        (
            (2 of ($roslyn_api_*) and ($roslyn_emit or $roslyn_ms))
            or
            (2 of ($legacy_a, $legacy_b, $legacy_params))
        )
        and $refload_a and ($refload_b or $refload_c) and $byte_arr
        and 2 of ($sch_*)
}


// -----------------------------------------------------------------
// Rule 3: Reflective Assembly.Load(byte[]) pattern (generic)
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
        $d = "Assembly.Load(" ascii wide
        $arr1 = "[byte[]]" ascii wide nocase
        $arr2 = "byte[]" ascii wide nocase
        $arr3 = "System.Byte[]" ascii wide nocase

    condition:
        any of ($a, $b, $c, $d) and any of ($arr1, $arr2, $arr3)
}


// -----------------------------------------------------------------
// Rule 4: GitHub-raw loader fetching PE + dropping to %TEMP%
// -----------------------------------------------------------------
rule GitHub_Raw_PE_Fetch_TempDrop_Loader
{
    meta:
        author      = "F0RT1KA Defense Guidance Builder"
        description = "Loader that fetches a PE from raw.githubusercontent.com and drops to c:\\Windows\\Temp — HONESTCUE v2 stage-3 pattern"
        mitre_attck = "T1105, T1204.002"
        severity    = "medium"
        date        = "2026-04-13"

    strings:
        $gh_a = "raw.githubusercontent.com" ascii wide nocase
        $gh_b = "objects.githubusercontent.com" ascii wide nocase
        $gh_c = "/releases/download/" ascii wide nocase
        $temp_drop_a = "\\Windows\\Temp\\" ascii wide nocase
        $temp_drop_b = "\\AppData\\Local\\Temp\\" ascii wide nocase
        $exe_ext = ".exe" ascii wide nocase
        $https = "https://" ascii wide nocase
        $mz_header = "MZ" ascii
        // Non-browser / non-git UAs often used by downloader malware
        $ua_1 = "User-Agent: HonestcueDownloader" ascii wide nocase
        $ua_2 = "HttpClient" ascii wide nocase
        $ua_3 = "System.Net.Http" ascii wide nocase
        $ua_4 = "WebClient" ascii wide nocase

    condition:
        any of ($gh_*)
        and any of ($temp_drop_*)
        and $exe_ext
        and $https
        and (any of ($ua_*) or $mz_header)
}


// -----------------------------------------------------------------
// Rule 5: Gemini-shaped JSON response hosting C# source on disk
// -----------------------------------------------------------------
rule Gemini_Shaped_Response_Hosting_CSharp_Source
{
    meta:
        author      = "F0RT1KA Defense Guidance Builder"
        description = "JSON file matching Gemini generateContent schema with embedded C# source in parts[0].text — HONESTCUE lab asset IOC"
        mitre_attck = "T1027.004, T1071.001"
        severity    = "high"
        date        = "2026-04-13"

    strings:
        // Gemini schema markers
        $s_candidates = "\"candidates\"" ascii wide
        $s_content    = "\"content\"" ascii wide
        $s_parts      = "\"parts\"" ascii wide
        $s_text       = "\"text\"" ascii wide
        $s_role_model = "\"role\": \"model\"" ascii wide nocase
        $s_finish     = "\"finishReason\"" ascii wide nocase

        // C# source markers that shouldn't normally appear in a Gemini response
        $cs_using_sys = "using System" ascii wide
        $cs_class     = "public class" ascii wide
        $cs_static    = "public static" ascii wide
        $cs_registry  = "Registry.LocalMachine" ascii wide
        $cs_win32ns   = "Microsoft.Win32" ascii wide

    condition:
        filesize < 2MB
        and 3 of ($s_*)
        and 2 of ($cs_*)
}


// -----------------------------------------------------------------
// Rule 6: Non-browser HTTP client invoking Gemini generateContent
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
        $ua_suspect1 = "User-Agent: HonestcueClient" ascii wide nocase
        $ua_suspect2 = "User-Agent: HonestcueDownloader" ascii wide nocase

    condition:
        any of ($ep*)
        and any of ($llm*)
        and (any of ($hdr*) or any of ($ua_suspect*))
        and not pe.version_info["CompanyName"] contains "Google"
        and not pe.version_info["CompanyName"] contains "OpenAI"
        and not pe.version_info["CompanyName"] contains "Anthropic"
        and not pe.version_info["CompanyName"] contains "Microsoft"
}
