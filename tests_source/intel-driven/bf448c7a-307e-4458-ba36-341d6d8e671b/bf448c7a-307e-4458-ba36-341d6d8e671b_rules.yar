/*
   TclBanker Brazilian Banking Trojan — YARA Rules
   Source: https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan
   Test:   bf448c7a-307e-4458-ba36-341d6d8e671b

   Rules target real TclBanker indicators (.NET namespaces, scheduled task name,
   campaign GUID, Cloudflare Workers account, debug artifact path, Portuguese
   vishing strings). Avoid F0RT1KA-test-specific markers — these are
   technique-focused so they match real TclBanker samples in the wild.
*/

import "pe"

rule TclBanker_DotNet_Assembly_Names
{
    meta:
        description    = "TclBanker .NET Reactor-protected assembly namespaces"
        author         = "F0RT1KA"
        date           = "2026-05-11"
        severity       = "high"
        threat_actor   = "TclBanker"
        reference      = "https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan"
        mitre_id       = "T1027"

    strings:
        $tcl_agent    = "Tcl.Agent" ascii wide
        $tcl_wppbot   = "Tcl.WppBot" ascii wide
        $reactor_ns   = "Tcl.Agent.Program" ascii wide
        $netreactor1  = ".NET Reactor" ascii wide
        $netreactor2  = "EzirizReactor" ascii wide

    condition:
        // .NET binary that exposes Tcl.Agent or Tcl.WppBot namespaces
        // alongside .NET Reactor protection markers
        pe.is_pe and
        2 of ($tcl_agent, $tcl_wppbot, $reactor_ns) and
        1 of ($netreactor1, $netreactor2)
}

rule TclBanker_Persistence_Task
{
    meta:
        description    = "TclBanker scheduled task name 'RuntimeOptimizeService'"
        author         = "F0RT1KA"
        date           = "2026-05-11"
        severity       = "high"
        threat_actor   = "TclBanker"
        reference      = "https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan"
        mitre_id       = "T1053.005"

    strings:
        $task_name      = "RuntimeOptimizeService" ascii wide
        $clsid_taskschd = "0F87369F-A4E5-4CFC-BD3E-73E6154572DD" ascii wide nocase

    condition:
        all of them
}

rule TclBanker_DLL_Sideload_Pair
{
    meta:
        description    = "TclBanker DLL sideload pair (LogiAiPromptBuilder + screen_retriever_plugin)"
        author         = "F0RT1KA"
        date           = "2026-05-11"
        severity       = "high"
        threat_actor   = "TclBanker"
        reference      = "https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan"
        mitre_id       = "T1574.002"

    strings:
        $host_exe       = "LogiAiPromptBuilder.exe" ascii wide
        $sideload_dll   = "screen_retriever_plugin.dll" ascii wide
        $install_path1  = "LogiAI" ascii wide
        $install_path2  = "%LocalAppData%\\LogiAI" ascii wide nocase

    condition:
        pe.is_pe and
        all of ($host_exe, $sideload_dll) and
        any of ($install_path*)
}

rule TclBanker_Cloudflare_Workers_C2
{
    meta:
        description    = "TclBanker Cloudflare Workers C2 (account ef971a42 + campaign GUID)"
        author         = "F0RT1KA"
        date           = "2026-05-11"
        severity       = "high"
        threat_actor   = "TclBanker"
        reference      = "https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan"
        mitre_id       = "T1071.001,T1102"

    strings:
        $account_id     = "ef971a42" ascii wide
        $campaign_guid  = "70e4f943-e323-4484-97d7-35401bf6812c" ascii wide nocase
        $workers_domain = ".workers.dev" ascii wide
        $ws_path        = "/ws" ascii wide
        $ua_wppbot      = "Tcl.WppBot" ascii wide
        $header_camp    = "X-Campaign-Id" ascii wide

    condition:
        2 of ($campaign_guid, $account_id, $workers_domain, $ua_wppbot, $header_camp)
}

rule TclBanker_Debug_Artifact_Path
{
    meta:
        description    = "TclBanker distinctive debug-artifact path C:\\temp\\tcl-debug.txt"
        author         = "F0RT1KA"
        date           = "2026-05-11"
        severity       = "medium"
        threat_actor   = "TclBanker"
        reference      = "https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan"
        mitre_id       = "T1027"

    strings:
        $debug_path1 = "C:\\temp\\tcl-debug.txt" ascii wide nocase
        $debug_path2 = "tcl-debug.txt" ascii wide nocase

    condition:
        any of them
}

rule TclBanker_Portuguese_Vishing_Strings
{
    meta:
        description    = "TclBanker overlay/vishing Portuguese strings"
        author         = "F0RT1KA"
        date           = "2026-05-11"
        severity       = "high"
        threat_actor   = "TclBanker"
        reference      = "https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan"
        mitre_id       = "T1056.003"

    strings:
        $vish1 = "Estamos entrando em contato" ascii wide
        $vish2 = "Aguarde enquanto" ascii wide
        $vish3 = "Atualiza" wide  // Atualização do Windows / Atualizando
        $vish4 = "central de seguran" ascii wide nocase
        $bank1 = "bb.com.br" ascii wide
        $bank2 = "itau.com.br" ascii wide
        $bank3 = "bradesco.com.br" ascii wide
        $bank4 = "santander.com.br" ascii wide
        $bank5 = "caixa.gov.br" ascii wide

    condition:
        // Strong: Portuguese fraud string + Brazilian banking domain match
        (1 of ($vish*) and 1 of ($bank*)) or
        // Or: multiple Portuguese vishing strings together
        2 of ($vish*)
}

rule TclBanker_MSI_Logitech_Update_Wrapper
{
    meta:
        description    = "Logitech_Update_*.msi delivery wrapper (CFB + TclBanker markers)"
        author         = "F0RT1KA"
        date           = "2026-05-11"
        severity       = "medium"
        threat_actor   = "TclBanker"
        reference      = "https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan"
        mitre_id       = "T1566.001,T1218.007"

    strings:
        $cfb_header = { D0 CF 11 E0 A1 B1 1A E1 }
        $logi_str1  = "Logitech Update" ascii wide nocase
        $logi_str2  = "LogiAI" ascii wide
        $logi_str3  = "Logitech_Update_" ascii wide
        // Markers commonly present inside the embedded payload
        $payload1   = "Tcl.Agent" ascii wide
        $payload2   = "screen_retriever_plugin" ascii wide

    condition:
        $cfb_header at 0 and
        1 of ($logi_str*) and
        1 of ($payload*)
}

rule TclBanker_Killchain_Composite
{
    meta:
        description    = "TclBanker killchain composite — multiple stage indicators in one binary"
        author         = "F0RT1KA"
        date           = "2026-05-11"
        severity       = "critical"
        threat_actor   = "TclBanker"
        reference      = "https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan"
        mitre_id       = "T1027,T1053.005,T1071.001,T1574.002"

    strings:
        $task   = "RuntimeOptimizeService" ascii wide
        $host   = "LogiAiPromptBuilder.exe" ascii wide
        $dll    = "screen_retriever_plugin.dll" ascii wide
        $clsid  = "0F87369F-A4E5-4CFC-BD3E-73E6154572DD" ascii wide nocase
        $campid = "70e4f943-e323-4484-97d7-35401bf6812c" ascii wide nocase
        $acct   = "ef971a42" ascii wide
        $debug  = "tcl-debug.txt" ascii wide nocase
        $tcl    = "Tcl.Agent" ascii wide
        $logipath = "LogiAI" ascii wide

    condition:
        // Three or more independent killchain markers in the same file
        3 of them
}
