/*
    ============================================================
    YARA Rule Suite: RDP Lateral Movement
    Test ID: c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03
    MITRE ATT&CK: T1021.001, T1555.004
    Platform: Windows
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-03-14
    ============================================================
    Coverage:
      1. SharpRDP headless RDP command execution tool (in-memory and on-disk)
      2. Windows Credential Manager manipulation strings (credential harvesting)
      3. RDP reconnaissance command patterns in scripts and LOLBins wrappers
      4. RDP registry key access patterns embedded in binaries
    ============================================================
    Note: All rules target technique-inherent artifacts. They will match
    any attacker tooling that uses the same technique, not only F0RT1KA tests.
    ============================================================
*/

import "pe"


/*
    ============================================================
    Rule 1: SharpRDP Headless RDP Tool
    Technique: T1021.001
    Confidence: High
    Description: Detects the SharpRDP .NET tool used for headless RDP command
                 execution without a graphical session. SharpRDP is a known red
                 team and threat actor tool for stealthy lateral movement over RDP.
                 Matches characteristic string combinations unique to this tool's
                 command-line parsing and RDP API invocation.
    ============================================================
*/
rule RDP_SharpRDP_HeadlessExecution {
    meta:
        description = "Detects SharpRDP headless RDP command execution tool (T1021.001)"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03"
        mitre_attack = "T1021.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1021/001/"
        reference_tool = "https://github.com/0xthirteen/SharpRDP"

    strings:
        // SharpRDP argument parsing strings
        $arg_computername = "computername=" ascii wide nocase
        $arg_command      = "command=" ascii wide nocase
        $arg_restricted   = "restricted=true" ascii wide nocase
        $arg_exec_ps      = "exec=powershell" ascii wide nocase

        // SharpRDP RDP session creation strings (from AxMSTSCLib/MSTSCLib usage)
        $rdp_connect      = "IMsTscNonScriptable" ascii wide
        $rdp_aximp        = "AxMSTSCLib" ascii wide
        $rdp_mstsc        = "MSTSCLib" ascii wide
        $rdp_advanced     = "IMsRdpClientAdvancedSettings" ascii wide

        // Headless RDP behavioral strings
        $no_gui_1         = "SendKeys" ascii wide
        $no_gui_2         = "SendInput" ascii wide
        $rdp_shell        = "shell32" ascii wide nocase

        // SharpRDP namespace and class identifiers
        $ns_sharprdp      = "SharpRDP" ascii wide
        $cls_program      = "Program" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            // High confidence: SharpRDP argument syntax + RDP API strings
            ($arg_computername and $arg_command and ($rdp_connect or $rdp_advanced or $rdp_mstsc))
            or
            // High confidence: SharpRDP namespace with RDP API
            ($ns_sharprdp and ($rdp_connect or $rdp_advanced))
            or
            // Medium confidence: All SharpRDP argument types present
            ($arg_computername and $arg_command and $arg_restricted)
            or
            // Medium confidence: Headless RDP pattern (AxMSTSCLib + SendKeys without GUI)
            ($rdp_aximp and $no_gui_1 and $arg_computername)
        )
}


/*
    ============================================================
    Rule 2: Windows Credential Manager Manipulation Tool Patterns
    Technique: T1555.004
    Confidence: Medium
    Description: Detects compiled binaries or scripts containing Windows
                 Credential Manager API strings used for credential harvesting
                 or manipulation. Attackers use CredEnumerate/CredRead to
                 extract stored RDP, SMB, and web credentials, and CredWrite
                 to store credentials for subsequent use.
    ============================================================
*/
rule CredentialManager_API_Abuse_T1555_004 {
    meta:
        description = "Detects Windows Credential Manager API abuse for credential harvesting (T1555.004)"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03"
        mitre_attack = "T1555.004"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1555/004/"

    strings:
        // Windows Credential Manager Win32 API exports
        $api_enumerate    = "CredEnumerateW" ascii wide
        $api_read         = "CredReadW" ascii wide
        $api_write        = "CredWriteW" ascii wide
        $api_delete       = "CredDeleteW" ascii wide
        $api_free         = "CredFree" ascii wide

        // Credential type identifiers
        $cred_generic     = "CRED_TYPE_GENERIC" ascii wide
        $cred_domain      = "CRED_TYPE_DOMAIN_PASSWORD" ascii wide
        $cred_cert        = "CRED_TYPE_DOMAIN_CERTIFICATE" ascii wide

        // Vault credential access
        $vault_open       = "VaultOpenVault" ascii wide
        $vault_enum       = "VaultEnumerateItems" ascii wide
        $vault_get        = "VaultGetItem" ascii wide
        $vault_close      = "VaultCloseVault" ascii wide

        // vaultcli.dll (Windows Credential Vault)
        $vaultcli         = "vaultcli.dll" ascii wide nocase
        $wincred          = "wincred.h" ascii wide nocase
        $advapi32         = "Advapi32.dll" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            // High confidence: Multiple credential API calls indicate systematic harvesting
            (($api_enumerate or $api_read) and ($api_write or $api_delete) and $api_free)
            or
            // High confidence: Vault access with enumeration
            ($vault_open and $vault_enum and ($vault_get or $vault_close))
            or
            // Medium confidence: Enumerate + read (harvesting pattern)
            ($api_enumerate and $api_read and $advapi32)
            or
            // Medium confidence: Vault + vaultcli direct access
            ($vaultcli and ($vault_open or $vault_enum))
        )
}


/*
    ============================================================
    Rule 3: RDP Lateral Movement Reconnaissance Scripts
    Technique: T1021.001
    Confidence: Medium
    Description: Detects PowerShell scripts or batch files containing multiple
                 RDP reconnaissance commands (sc query TermService, reg query
                 Terminal Server, qwinsta). The combination of these commands
                 in a single script is highly indicative of automated RDP
                 lateral movement preparation.
    ============================================================
*/
rule RDP_Recon_Script_MultiCommand {
    meta:
        description = "Detects scripts containing multiple RDP reconnaissance commands (T1021.001)"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03"
        mitre_attack = "T1021.001"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1021/001/"

    strings:
        // RDP service query patterns
        $sc_termservice   = "TermService" ascii wide nocase
        $sc_rdp_query     = /sc(\s+\\\\[^\s]+)?\s+query\s+TermService/i

        // Registry key patterns for RDP config
        $reg_terminal     = "Terminal Server" ascii wide nocase
        $reg_fdeny        = "fDenyTSConnections" ascii wide nocase
        $reg_nla          = "UserAuthentication" ascii wide nocase
        $reg_rdptcp       = "RDP-Tcp" ascii wide nocase

        // Session enumeration
        $qwinsta          = "qwinsta" ascii wide nocase
        $query_session    = "query session" ascii wide nocase

        // RDP connection initiation
        $mstsc            = "mstsc" ascii wide nocase
        $xfreerdp         = "xfreerdp" ascii wide nocase

    condition:
        filesize < 1MB and
        (
            // Script with service + registry + session enum (3-stage recon)
            ($sc_termservice and $reg_fdeny and $qwinsta)
            or
            // Script with RDP registry keys (2+ distinct keys)
            ($reg_fdeny and $reg_nla and $reg_rdptcp)
            or
            // Registry enumeration + session enum combo
            ($reg_terminal and $qwinsta)
            or
            // sc query with reg query targeting RDP keys
            ($sc_rdp_query and ($reg_fdeny or $reg_nla))
        )
}


/*
    ============================================================
    Rule 4: cmdkey Credential Injection Tool Patterns
    Technique: T1555.004
    Confidence: High
    Description: Detects scripts or compiled tools invoking cmdkey.exe with
                 /add arguments to store credentials in Windows Credential
                 Manager. This is used by attackers to pre-stage credentials
                 for subsequent RDP or SMB lateral movement via "pass the
                 credentials" without triggering interactive authentication.
    ============================================================
*/
rule CmdKey_Credential_Staging {
    meta:
        description = "Detects cmdkey /add credential staging for lateral movement (T1555.004)"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03"
        mitre_attack = "T1555.004"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1555/004/"

    strings:
        // cmdkey invocation patterns
        $cmdkey_add       = /cmdkey[^"'\r\n]{0,20}\/add:/i
        $cmdkey_user      = /\/user:/i
        $cmdkey_pass      = /\/pass:/i
        $cmdkey_generic   = /cmdkey[^"'\r\n]{0,20}\/generic:/i

        // cmdkey with target server patterns
        $cmdkey_server    = /cmdkey[^"'\r\n]{0,20}\/add:[a-zA-Z0-9_\-\.\\]+/
        $cmdkey_list      = /cmdkey[^"'\r\n]{0,5}\/list/i
        $cmdkey_delete    = /cmdkey[^"'\r\n]{0,20}\/delete:/i

        // PowerShell invocation wrappers
        $ps_start         = "Start-Process" ascii wide nocase
        $ps_invoke        = "Invoke-Expression" ascii wide nocase
        $ps_iex           = "iex(" ascii wide nocase

    condition:
        filesize < 1MB and
        (
            // Direct cmdkey /add with user and password
            ($cmdkey_add and $cmdkey_user and $cmdkey_pass)
            or
            // cmdkey credential lifecycle (add + delete = staging then cleanup)
            ($cmdkey_server and $cmdkey_delete)
            or
            // Generic credential storage
            ($cmdkey_generic and $cmdkey_user)
            or
            // PowerShell wrapping cmdkey add
            (($ps_invoke or $ps_iex) and $cmdkey_add and $cmdkey_pass)
        )
}


/*
    ============================================================
    Rule 5: RDP Offensive Tool Generic Patterns
    Technique: T1021.001
    Confidence: Medium
    Description: Detects .NET binaries with patterns characteristic of
                 headless/programmatic RDP tools (SharpRDP and similar).
                 These tools use the Microsoft Terminal Services Client
                 ActiveX control (mstscax.dll) programmatically rather than
                 through the standard mstsc.exe GUI, allowing stealthy
                 command execution over RDP.
    ============================================================
*/
rule RDP_HeadlessTool_DotNET_Generic {
    meta:
        description = "Detects .NET-based headless RDP tool patterns (T1021.001)"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03"
        mitre_attack = "T1021.001"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1021/001/"
        note = "Covers SharpRDP and similar headless RDP execution tools"

    strings:
        // MSTSC ActiveX/COM interface strings (used by headless RDP tools)
        $mstscax          = "mstscax.dll" ascii wide nocase
        $rdpclientax      = "MsRdpClient" ascii wide
        $rdp_iface        = "IMsTscAx" ascii wide
        $rdp_adv_iface    = "IMsRdpClientAdvancedSettings" ascii wide
        $rdp_sec_iface    = "IMsRdpClientSecuredSettings" ascii wide

        // ActiveX dispatch IDs for headless RDP
        $dispatch_connect = "Connect" ascii wide
        $dispatch_server  = "Server" ascii wide

        // RDP API connection flags
        $rdp_port         = "AdvancedSettings2" ascii wide
        $rdp_smartcard    = "RedirectSmartCards" ascii wide
        $rdp_clipboard    = "RedirectClipboard" ascii wide

        // .NET CLR header
        $clr_header       = { 52 53 44 53 }  // "RSDS" PDB signature common in .NET

        // Headless RDP execution indicator: no window shown
        $no_window        = "ShowWindow" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        pe.imports("mscoree.dll") and
        (
            // .NET RDP tool with MSTSC ActiveX interfaces
            ($mstscax and ($rdp_iface or $rdpclientax) and $dispatch_connect)
            or
            // Advanced settings interface access (non-GUI RDP)
            ($rdp_adv_iface and $rdp_sec_iface and $dispatch_server)
            or
            // Headless: RDP interfaces + no window + command execution
            (($rdpclientax or $rdp_iface) and $no_window and $dispatch_connect)
        )
}
