/*
    PROMPTFLUX v1 — YARA Detection Rules
    Test UUID: 0a749b39-409e-46f5-9338-ee886b439cfa
    Techniques: T1071.001, T1027.001, T1547.001, T1091

    These rules target REAL PROMPTFLUX tradecraft patterns, not this test's
    artefacts. Rules avoid matching on the test's own UUID, F0RT1KA strings,
    or PA lab-asset URLs — those would be false-positive generators.
*/

import "pe"

rule PROMPTFLUX_VBS_Dropper_Chr_Obfuscated_Body
{
    meta:
        author = "F0RT1KA sectest-builder"
        description = "Generic VBScript using Chr()-based string assembly to build Scripting.FileSystemObject / WScript.Shell / Scripting object creations — the shape PROMPTFLUX's Gemini prompts produce"
        reference = "GTIG PROMPTFLUX disclosure Nov 2025"
        severity = "medium"
        mitre_technique = "T1027.001"
        mitre_tactic = "defense-evasion"

    strings:
        // Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116) = "Script"
        // Many Chr() calls concatenated with & is a strong obfuscation marker
        $chr_seq = /Chr\(\d{2,3}\)\s*&\s*Chr\(\d{2,3}\)\s*&\s*Chr\(\d{2,3}\)\s*&\s*Chr\(\d{2,3}\)\s*&\s*Chr\(\d{2,3}\)/ ascii nocase

        $wscript_shell = "WScript.Shell" ascii nocase
        $fso = "Scripting.FileSystemObject" ascii nocase
        $createobject = "CreateObject" ascii nocase

    condition:
        filesize < 256KB
        and #chr_seq >= 3
        and 1 of ($wscript_shell, $fso, $createobject)
}

rule PROMPTFLUX_Thinking_Log_Filename
{
    meta:
        author = "F0RT1KA sectest-builder"
        description = "Exact filename IOC for PROMPTFLUX's Thinging staging trail — presence of this string in a file or process-memory dump is a strong PROMPTFLUX indicator"
        reference = "GTIG PROMPTFLUX disclosure Nov 2025"
        severity = "high"
        mitre_technique = "T1074.001"

    strings:
        $fn = "thinking_robot_log.txt" ascii nocase wide

    condition:
        any of them
}

rule PROMPTFLUX_Staged_VBScript_Filename
{
    meta:
        author = "F0RT1KA sectest-builder"
        description = "Exact filename IOC for PROMPTFLUX's on-disk VBS dropper"
        reference = "GTIG PROMPTFLUX disclosure Nov 2025"
        severity = "high"
        mitre_technique = "T1059.005"

    strings:
        $fn = "crypted_ScreenRec_webinstall.vbs" ascii nocase wide

    condition:
        any of them
}

rule PROMPTFLUX_Gemini_API_Response_Shape_In_Memory
{
    meta:
        author = "F0RT1KA sectest-builder"
        description = "Gemini /v1beta/models/*:generateContent response envelope structure present in a process memory dump. Combined with a non-browser parent process, this is a strong LLM-proxy / runtime-LLM-abuse signal."
        reference = "GTIG PROMPTFLUX disclosure Nov 2025, Google Gemini API docs"
        severity = "medium"
        mitre_technique = "T1071.001"

    strings:
        $s1 = "candidates" ascii
        $s2 = "content" ascii
        $s3 = "parts" ascii
        $s4 = "finishReason" ascii
        $s5 = "safetyRatings" ascii
        $s6 = "promptFeedback" ascii
        $s7 = "HARM_CATEGORY_DANGEROUS_CONTENT" ascii
        $s8 = "generateContent" ascii

    condition:
        4 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8)
}

rule PROMPTFLUX_Startup_Folder_VBS_Name
{
    meta:
        author = "F0RT1KA sectest-builder"
        description = "Exact filename IOC for PROMPTFLUX's Startup-folder persistence VBS drop"
        reference = "GTIG PROMPTFLUX disclosure Nov 2025"
        severity = "high"
        mitre_technique = "T1547.001"

    strings:
        $fn = "ScreenRecUpdater.vbs" ascii nocase wide

    condition:
        any of them
}

rule PROMPTFLUX_Thinging_Module_Prompt_Strings
{
    meta:
        author = "F0RT1KA sectest-builder"
        description = "Prompt fragments indicative of a PROMPTFLUX-style Thinging module — a caller asking an LLM to rewrite its own VBScript body with the same semantic behaviour"
        reference = "GTIG PROMPTFLUX disclosure Nov 2025"
        severity = "medium"
        mitre_technique = "T1027.001"

    strings:
        $p1 = "rewrite this VBScript" ascii nocase
        $p2 = "generate a new variant" ascii nocase
        $p3 = "produce equivalent code" ascii nocase
        $p4 = "return only the source code" ascii nocase
        $p5 = "without markdown formatting" ascii nocase
        $p6 = "obfuscate each string" ascii nocase
        $p7 = "use Chr()" ascii nocase
        $p8 = "Thinging" ascii nocase wide

    condition:
        2 of them
}
