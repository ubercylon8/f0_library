/*
 * ============================================================
 * YARA Rules — PII Exfiltration to External Inference Services
 * Test ID: 6d33cc62-d59d-4661-a76d-715aa4abddfd
 * MITRE ATT&CK: T1552.001, T1119, T1005, T1567
 * Generated: 2026-07-07
 * ============================================================
 * FOCUS: Technique-level artifacts of shadow-AI PII egress — a helper tool
 * that harvests AI keys and pastes local records to inference vendors, and
 * staged files that combine AI endpoints with PII. These match real-world
 * shadow-AI tooling, NOT this test's specific filenames.
 * ============================================================
 */

import "pe"

rule ShadowAI_Harvester_Tool
{
    meta:
        description = "Script/tool that references AI inference endpoints and harvests env-var API keys"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-07-07"
        mitre = "T1552.001, T1119"
        confidence = "medium"
    strings:
        $ep1 = "api.openai.com" ascii nocase
        $ep2 = "api.anthropic.com" ascii nocase
        $ep3 = "generativelanguage.googleapis.com" ascii nocase
        $ep4 = "api.githubcopilot.com" ascii nocase
        $harvest1 = "OPENAI_API_KEY" ascii nocase
        $harvest2 = "ANTHROPIC_API_KEY" ascii nocase
        $harvest3 = "os.environ" ascii
        $harvest4 = "getenv" ascii nocase
    condition:
        filesize < 200KB and 1 of ($ep*) and 2 of ($harvest*)
}

rule ShadowAI_PII_Egress_Payload
{
    meta:
        description = "Staged data file combining an AI inference endpoint with PII patterns (SSN, PAN, email) — candidate exfil payload"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-07-07"
        mitre = "T1005, T1567"
        confidence = "medium"
    strings:
        $ai = /api\.(openai|anthropic|githubcopilot)\.com|generativelanguage\.googleapis\.com/ ascii nocase
        // Structural PII: US SSN (nnn-nn-nnnn) and a 16-digit Visa-range PAN
        $ssn = /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/ ascii
        $pan = /\b4[0-9]{15}\b/ ascii
        $email = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/ ascii nocase
    condition:
        filesize < 5MB and $ai and ($ssn or $pan) and $email
}

rule ShadowAI_ChatCompletion_With_PII
{
    meta:
        description = "Chat-completion JSON body embedding PII being prepared for an inference service"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-07-07"
        mitre = "T1567"
        confidence = "medium"
    strings:
        $m1 = "\"messages\"" ascii
        $m2 = "\"role\"" ascii
        $m3 = "\"content\"" ascii
        $m4 = "\"contents\"" ascii   // Gemini shape
        $ssn = /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/ ascii
        $pan = /\b4[0-9]{15}\b/ ascii
    condition:
        filesize < 1MB and (2 of ($m*)) and ($ssn or $pan)
}
