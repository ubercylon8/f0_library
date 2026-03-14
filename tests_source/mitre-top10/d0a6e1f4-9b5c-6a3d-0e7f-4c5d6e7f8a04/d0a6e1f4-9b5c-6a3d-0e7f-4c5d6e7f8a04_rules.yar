/*
    ============================================================
    YARA Rules: WMI Execution and Persistence
    Test ID: d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04
    MITRE ATT&CK: T1047, T1546.003
    Platform: Windows
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-03-14
    ============================================================
    Scope: These rules target the TECHNIQUE, not the test framework.
    They detect binaries that embed WMI execution primitives, scripts
    that invoke WMI for process creation, and WMI persistence tooling.
    ============================================================
*/


/*
    ============================================================
    Rule 1: WMI Process Creation via Win32_Process::Create (Binary)
    Technique: T1047
    Confidence: High
    Description: Detects compiled binaries (PE files) that embed WMI
                 invocation strings for process creation. Attackers compile
                 custom tools embedding these COM strings to avoid
                 command-line-visible wmic.exe invocations. The combination
                 of Win32_Process, Create, and IWbemServices is required
                 for programmatic WMI process execution.
    ============================================================
*/
rule WMI_Process_Creation_Binary
{
    meta:
        description = "Detects PE files embedding WMI Win32_Process::Create execution primitives"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04"
        mitre_attack = "T1047"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1047/"

    strings:
        $wmi_class_proc  = "Win32_Process" ascii wide nocase
        $wmi_method_crt  = "Create" ascii wide
        $wmi_interface1  = "IWbemServices" ascii wide
        $wmi_interface2  = "IWbemLocator" ascii wide
        $wmi_namespace   = "root\\cimv2" ascii wide nocase
        $wmi_namespace2  = "root/cimv2" ascii wide nocase
        $wmi_moniker     = "winmgmts:" ascii wide nocase
        $com_clsid_wmi   = { 76 BE 6E 4D 5D 8B 11 D1 AD 1E 00 C0 4F D8 FD 63 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and (
            ($wmi_class_proc and $wmi_method_crt and $wmi_interface1)
            or ($wmi_class_proc and $wmi_method_crt and $wmi_interface2)
            or ($wmi_moniker and $wmi_class_proc and $wmi_method_crt)
            or ($com_clsid_wmi and $wmi_class_proc and $wmi_method_crt)
        )
}


/*
    ============================================================
    Rule 2: WMI Event Subscription Persistence Tool
    Technique: T1546.003
    Confidence: High
    Description: Detects binaries and scripts that contain the three
                 components required for WMI event subscription persistence:
                 EventFilter (what triggers), EventConsumer (what runs),
                 and FilterToConsumerBinding (links them). All three together
                 in one file is strongly indicative of persistence tooling.
    ============================================================
*/
rule WMI_Event_Subscription_Persistence
{
    meta:
        description = "Detects WMI event subscription persistence tooling (EventFilter + EventConsumer + Binding)"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04"
        mitre_attack = "T1546.003"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1546/003/"

    strings:
        $filter             = "__EventFilter" ascii wide nocase
        $consumer_act       = "ActiveScriptEventConsumer" ascii wide nocase
        $consumer_cmd       = "CommandLineEventConsumer" ascii wide nocase
        $binding            = "__FilterToConsumerBinding" ascii wide nocase
        $wmi_ns_sub         = "root\\subscription" ascii wide nocase
        $wmi_ns_sub2        = "root/subscription" ascii wide nocase
        $wmi_ns_cimv2       = "root\\cimv2" ascii wide nocase
        $wmi_ess_class      = "__InstanceCreationEvent" ascii wide nocase
        $wmi_ess_class2     = "__InstanceModificationEvent" ascii wide nocase
        $wmi_ess_class3     = "__TimerEvent" ascii wide nocase
        $wmi_ess_class4     = "Win32_ProcessStartTrace" ascii wide nocase

    condition:
        filesize < 20MB
        and $filter
        and ($consumer_act or $consumer_cmd)
        and $binding
        and ($wmi_ns_sub or $wmi_ns_sub2)
}


/*
    ============================================================
    Rule 3: PowerShell WMI Execution and Persistence Script
    Technique: T1047, T1546.003
    Confidence: High
    Description: Detects PowerShell scripts abusing WMI for process
                 creation (Invoke-WmiMethod, [wmiclass]) or establishing
                 WMI event subscription persistence. These patterns are
                 commonly used in fileless attacks and living-off-the-land
                 techniques.
    ============================================================
*/
rule PowerShell_WMI_Execution_Or_Persistence
{
    meta:
        description = "Detects PowerShell scripts using WMI for execution or persistence"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04"
        mitre_attack = "T1047, T1546.003"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1047/"

    strings:
        $invoke_wmi     = "Invoke-WmiMethod" ascii wide nocase
        $get_wmi        = "Get-WmiObject" ascii wide nocase
        $get_cim        = "Get-CimInstance" ascii wide nocase
        $invoke_cim     = "Invoke-CimMethod" ascii wide nocase
        $new_cim        = "New-CimInstance" ascii wide nocase
        $reg_wmi_event  = "Register-WmiEvent" ascii wide nocase
        $wmi_class_ps   = "[wmiclass]" ascii wide nocase
        $wmi_class_proc = "Win32_Process" ascii wide nocase
        $wmi_create_arg = "Create" ascii wide
        $wmi_sub_ns     = "root/subscription" ascii wide nocase
        $wmi_sub_ns2    = "root\\subscription" ascii wide nocase
        $filter_class   = "__EventFilter" ascii wide nocase
        $consumer_class = "CommandLineEventConsumer" ascii wide nocase
        $binding_class  = "__FilterToConsumerBinding" ascii wide nocase

    condition:
        filesize < 5MB
        and (
            // Process creation via WMI in PowerShell
            (($invoke_wmi or $invoke_cim or $wmi_class_ps)
             and $wmi_class_proc and $wmi_create_arg)
            or
            // WMI event subscription persistence in PowerShell
            ($filter_class and ($consumer_class or $binding_class))
            or
            // Register-WmiEvent persistence
            $reg_wmi_event
            or
            // New-CimInstance for subscription namespace
            ($new_cim and ($wmi_sub_ns or $wmi_sub_ns2))
        )
}


/*
    ============================================================
    Rule 4: Impacket-Style WMI Remote Execution (wmiexec)
    Technique: T1047
    Confidence: High
    Description: Detects Python-based Impacket wmiexec and wmiexec-Pro
                 style tooling. These tools use WMI Win32_Process::Create
                 with a cmd.exe wrapper writing output to a temp file and
                 reading it back. The specific temp file path pattern and
                 wmiexec shell prompt are highly characteristic signatures.
                 Any real attacker using Impacket-family WMI tools will
                 produce these strings.
    ============================================================
*/
rule Impacket_WMI_Remote_Execution
{
    meta:
        description = "Detects Impacket wmiexec / wmiexec-Pro remote WMI execution tooling"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04"
        mitre_attack = "T1047"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1047/"

    strings:
        // Impacket wmiexec characteristic output redirection pattern
        $wmiexec_output1  = "cmd.exe /Q /c " ascii nocase
        $wmiexec_output2  = "1> \\\\" ascii nocase
        $wmiexec_output3  = "\\ADMIN$\\" ascii nocase
        $wmiexec_output4  = "2>&1" ascii
        // wmiexec-Pro specific strings
        $wmiexec_pro1     = "wmiexec-Pro" ascii nocase
        $wmiexec_pro2     = "XiaoliChan" ascii nocase
        // Generic Impacket WMI RPC strings
        $impacket_dcerpc  = "MSRPC" ascii
        $impacket_wmi_ns  = "root/cimv2" ascii nocase
        $impacket_class   = "Win32_Process" ascii wide nocase
        $impacket_method  = "Create" ascii wide
        // Semi-interactive shell marker
        $shell_marker     = "Impacket v" ascii
        $wmiexec_shell    = "C:\\>" ascii

    condition:
        filesize < 5MB
        and (
            // wmiexec output redirection signature
            ($wmiexec_output1 and $wmiexec_output2 and $wmiexec_output4)
            or
            // wmiexec-Pro direct identification
            ($wmiexec_pro1 or $wmiexec_pro2)
            or
            // Impacket MSRPC + WMI combo
            ($shell_marker and $impacket_class and $impacket_method)
        )
}


/*
    ============================================================
    Rule 5: WMI MOF File with Embedded Payload
    Technique: T1546.003
    Confidence: Medium
    Description: Detects MOF (Managed Object Format) files that contain
                 both WMI event subscription class definitions and
                 embedded command strings typical of persistence payloads.
                 Malicious MOF files are compiled with mofcomp.exe to
                 register WMI persistence in the repository.
    ============================================================
*/
rule WMI_Malicious_MOF_Persistence
{
    meta:
        description = "Detects MOF files with WMI event subscription persistence payloads"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04"
        mitre_attack = "T1546.003"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1546/003/"

    strings:
        $mof_pragma      = "#pragma namespace" ascii nocase
        $mof_class       = "instance of " ascii nocase
        $filter_kw       = "__EventFilter" ascii nocase
        $consumer_kw1    = "CommandLineEventConsumer" ascii nocase
        $consumer_kw2    = "ActiveScriptEventConsumer" ascii nocase
        $binding_kw      = "__FilterToConsumerBinding" ascii nocase
        $script_text1    = "ScriptText" ascii nocase
        $cmd_template1   = "CommandLineTemplate" ascii nocase
        $sub_namespace   = "root\\subscription" ascii nocase
        $sub_namespace2  = "root/subscription" ascii nocase

    condition:
        filesize < 1MB
        and $mof_pragma
        and $mof_class
        and (
            ($filter_kw and ($consumer_kw1 or $consumer_kw2) and $binding_kw)
            or ($sub_namespace or $sub_namespace2)
        )
        and ($script_text1 or $cmd_template1)
}
