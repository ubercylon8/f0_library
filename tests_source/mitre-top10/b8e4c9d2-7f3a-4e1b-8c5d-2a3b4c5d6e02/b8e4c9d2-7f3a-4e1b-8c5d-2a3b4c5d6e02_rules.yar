/*
    ============================================================
    YARA Rule Set: Local Account Enumeration & Kerberoasting
    Test ID: b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02
    MITRE ATT&CK: T1078.003, T1087.001, T1558.003
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-03-14
    ============================================================
    These rules target the ATTACK TECHNIQUE behaviors, not test
    framework artifacts. Each rule is tuned to the inherent
    properties of the tool or technique being simulated.
    ============================================================
*/


/*
    ============================================================
    Rule: Rubeus GhostPack Kerberoasting Tool
    MITRE ATT&CK: T1558.003
    Confidence: High
    Description: Detects the Rubeus .NET Kerberos abuse tool from
                 GhostPack. Rubeus has a distinct set of internal
                 string references, namespace structures, and
                 command-line argument parsers that remain stable
                 across builds. Strings are chosen from the tool's
                 core logic, not version-specific UI text.
    ============================================================
*/
rule Rubeus_GhostPack_Kerberos_Tool {
    meta:
        description     = "Detects Rubeus, the GhostPack Kerberos abuse tool used for Kerberoasting and AS-REP Roasting"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02"
        mitre_attack    = "T1558.003"
        confidence      = "high"
        reference       = "https://github.com/GhostPack/Rubeus"
        reference2      = "https://attack.mitre.org/techniques/T1558/003/"

    strings:
        // Core namespace and class identifiers stable across versions
        $ns1   = "Rubeus.Commands"            ascii wide
        $ns2   = "Rubeus.Lib.Kerberos"        ascii wide
        $ns3   = "GhostPack.Rubeus"           ascii wide

        // Command dispatcher strings present in all builds
        $cmd1  = "kerberoast"                 ascii wide nocase
        $cmd2  = "asreproast"                 ascii wide nocase
        $cmd3  = "asktgt"                     ascii wide nocase
        $cmd4  = "asktgs"                     ascii wide nocase
        $cmd5  = "tgtdeleg"                   ascii wide nocase
        $cmd6  = "s4u"                        ascii wide nocase
        $cmd7  = "harvest"                    ascii wide nocase
        $cmd8  = "ptt"                        ascii wide nocase

        // Argument parser identifiers
        $arg1  = "/outfile:"                  ascii wide nocase
        $arg2  = "/format:hashcat"            ascii wide nocase
        $arg3  = "/format:john"               ascii wide nocase
        $arg4  = "/opsec"                     ascii wide nocase
        $arg5  = "/nowrap"                    ascii wide nocase
        $arg6  = "/aes256:"                   ascii wide nocase
        $arg7  = "/rc4:"                      ascii wide nocase
        $arg8  = "/spn:"                      ascii wide nocase

        // Kerberos protocol constants and encoding patterns used by Rubeus
        $krb1  = "KRB_AS_REQ"                ascii wide
        $krb2  = "KRB_TGS_REQ"               ascii wide
        $krb3  = "KRB_AP_REQ"                ascii wide
        $krb4  = "KerberosRequestorSecurityToken" ascii wide

        // Rubeus-specific output formatting strings
        $out1  = "[*] Action: Kerberoasting"                   ascii wide
        $out2  = "[*] Action: AS-REP Roasting"                 ascii wide
        $out3  = "[*] Searching for accounts that do not require kerberos preauthentication" ascii wide
        $out4  = "[*] SamAccountName"                          ascii wide
        $out5  = "$krb5tgs$"                                   ascii wide
        $out6  = "$krb5asrep$"                                 ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            // Strong match: namespace references + commands
            (1 of ($ns*) and 3 of ($cmd*)) or
            // Alternative: output markers (hash formats)
            (any of ($out5, $out6) and 2 of ($cmd*)) or
            // Behavioral signature: argument parsers with Kerberos functions
            (3 of ($arg*) and 2 of ($cmd*)) or
            // High-confidence standalone: Rubeus output text with Kerberos types
            (2 of ($out*) and any of ($krb*))
        )
}


/*
    ============================================================
    Rule: Rubeus Kerberoast Hash Output File
    MITRE ATT&CK: T1558.003
    Confidence: High
    Description: Detects files containing Kerberoasted TGS hash
                 output in hashcat or John the Ripper format.
                 These characteristic $krb5tgs$ prefixes are
                 output by any Kerberoasting tool (Rubeus,
                 Impacket, PowerView) and are technique-inherent.
    ============================================================
*/
rule Kerberoast_Hash_Output_File {
    meta:
        description     = "Detects files containing Kerberoasted TGS-REP hashes in hashcat or JtR format"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02"
        mitre_attack    = "T1558.003"
        confidence      = "high"
        reference       = "https://attack.mitre.org/techniques/T1558/003/"

    strings:
        // Hashcat mode 13100 prefix for Kerberoasted TGS hashes
        $tgs_hashcat = "$krb5tgs$23$"   ascii
        $tgs_aes128  = "$krb5tgs$17$"   ascii
        $tgs_aes256  = "$krb5tgs$18$"   ascii

        // AS-REP hash prefix (AS-REP Roasting / mode 18200)
        $asrep_hash  = "$krb5asrep$23$" ascii
        $asrep_aes   = "$krb5asrep$18$" ascii

        // Rubeus output header lines that bracket hash output
        $header1     = "[*] Hash" wide ascii
        $header2     = "[*] SamAccountName" wide ascii
        $header3     = "[*] DistinguishedName" wide ascii

    condition:
        filesize < 50MB and
        (
            any of ($tgs_*) or
            any of ($asrep_*) or
            (2 of ($header*) and filesize < 5MB)
        )
}


/*
    ============================================================
    Rule: AS-REP Roasting Hash Output File
    MITRE ATT&CK: T1558.003
    Confidence: High
    Description: Detects AS-REP Roasted hash files (accounts
                 without Kerberos pre-authentication required).
                 The $krb5asrep$ prefix is written by Rubeus,
                 Impacket GetNPUsers, and PowerView and is
                 inherent to the technique output format.
    ============================================================
*/
rule ASREP_Roast_Hash_Output_File {
    meta:
        description     = "Detects files containing AS-REP Roasted Kerberos hashes (accounts without pre-auth)"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02"
        mitre_attack    = "T1558.003"
        confidence      = "high"
        reference       = "https://attack.mitre.org/techniques/T1558/003/"

    strings:
        $asrep_23   = "$krb5asrep$23$" ascii
        $asrep_18   = "$krb5asrep$18$" ascii
        $asrep_old  = "$krb5asrep$"    ascii

    condition:
        filesize < 50MB and
        any of them
}


/*
    ============================================================
    Rule: .NET Assembly Performing Kerberos Ticket Operations
    MITRE ATT&CK: T1558.003
    Confidence: Medium
    Description: Detects compiled .NET assemblies that contain
                 Kerberos ticket request logic matching patterns
                 used by Rubeus, PowerShell Kerberoasting modules,
                 and similar tooling. Targets the raw Kerberos API
                 usage patterns present in offensive .NET tools.
    ============================================================
*/
rule DotNet_Kerberos_Ticket_Abuse {
    meta:
        description     = "Detects .NET assemblies performing raw Kerberos ticket operations (Kerberoasting/AS-REP tooling)"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02"
        mitre_attack    = "T1558.003"
        confidence      = "medium"
        reference       = "https://attack.mitre.org/techniques/T1558/003/"

    strings:
        // .NET Assembly magic bytes and CLR header
        $dotnet_hdr = { 4D 5A }

        // System.IdentityModel Kerberos classes
        $kclass1 = "System.IdentityModel.Tokens.KerberosRequestorSecurityToken" ascii wide
        $kclass2 = "System.Security.Principal.KerberosPrincipal" ascii wide

        // Win32 SSPI API calls for Kerberos used by Rubeus
        $sspi1 = "AcquireCredentialsHandle" ascii wide
        $sspi2 = "InitializeSecurityContext" ascii wide
        $sspi3 = "QueryContextAttributes"    ascii wide

        // Kerberos encryption type constants (etype values from RFC 4120)
        // RC4-HMAC = 23 (0x17), AES128 = 17 (0x11), AES256 = 18 (0x12)
        $etype1 = "RC4_HMAC"   ascii wide
        $etype2 = "AES128_CTS" ascii wide
        $etype3 = "AES256_CTS" ascii wide

        // Ticket structure identifiers
        $ticket1 = "KRB_TGS_REP" ascii wide
        $ticket2 = "EncKDCRepPart" ascii wide
        $ticket3 = "KerberosPrincipalName" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        $dotnet_hdr at 0 and
        (
            (any of ($kclass*) and any of ($sspi*)) or
            (2 of ($kclass*) and any of ($etype*)) or
            (any of ($ticket*) and any of ($etype*) and any of ($sspi*))
        )
}


/*
    ============================================================
    Rule: Suspicious Account Enumeration Script in Memory/File
    MITRE ATT&CK: T1087.001
    Confidence: Medium
    Description: Detects PowerShell or batch scripts containing
                 multiple account enumeration commands chained
                 together. This pattern is indicative of
                 post-compromise enumeration scripts rather than
                 legitimate administrative tooling (which uses
                 singular, targeted queries).
    ============================================================
*/
rule Account_Enumeration_Script {
    meta:
        description     = "Detects scripts containing multiple chained account enumeration commands typical of post-compromise recon"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02"
        mitre_attack    = "T1087.001"
        confidence      = "medium"
        reference       = "https://attack.mitre.org/techniques/T1087/001/"

    strings:
        // Native enumeration commands
        $enum1 = "net user"                            ascii wide nocase
        $enum2 = "net localgroup administrators"       ascii wide nocase
        $enum3 = "whoami /all"                         ascii wide nocase
        $enum4 = "wmic useraccount"                    ascii wide nocase
        $enum5 = "Get-LocalUser"                       ascii wide nocase
        $enum6 = "Get-LocalGroupMember"                ascii wide nocase
        $enum7 = "Get-LocalGroup"                      ascii wide nocase

        // PowerShell ADSI account enumeration
        $ps1   = "[ADSI]\"WinNT://"                    ascii wide nocase
        $ps2   = "WinNT://./Administrators"            ascii wide nocase
        $ps3   = "WinNT://./Users"                     ascii wide nocase

    condition:
        filesize < 5MB and
        (
            // Two or more distinct enumeration methods indicates recon script
            2 of ($enum*) or
            // ADSI + native command combination
            (any of ($ps*) and any of ($enum*))
        )
}
