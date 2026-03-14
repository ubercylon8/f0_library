/*
    ============================================================
    YARA Rules: Pre-Encryption File Enumeration Behaviors
    Test ID: a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07
    MITRE ATT&CK: T1083, T1119, T1082
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-03-14
    ============================================================
    These rules detect technique-level behaviors and tool signatures
    inherent to pre-ransomware file enumeration and host reconnaissance.
    They are NOT specific to any test framework.
    ============================================================
*/

/*
    ============================================================
    Rule: Seatbelt GhostPack Host Enumeration Tool
    MITRE ATT&CK: T1082, T1083
    Confidence: High
    ============================================================
    Description: Detects the Seatbelt compiled binary from the GhostPack
    offensive toolkit. Seatbelt performs 60+ host security checks used by
    threat actors for pre-attack reconnaissance. The strings below are
    inherent to the tool's .NET assembly and command-line interface —
    any build of Seatbelt will contain these.
    ============================================================
*/
rule GhostPack_Seatbelt_Host_Enumeration_Tool
{
    meta:
        description = "Detects Seatbelt (GhostPack) compiled binary used for host security enumeration. Performs 60+ checks covering credentials, security config, browser data, and network state."
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07"
        mitre_attack = "T1082, T1083"
        confidence = "high"
        reference = "https://github.com/GhostPack/Seatbelt"

    strings:
        // Core Seatbelt class names (present in all builds)
        $class_seatbelt   = "Seatbelt.Commands" ascii wide
        $class_program    = "Seatbelt.Program" ascii wide
        $class_ghostpack  = "GhostPack" ascii wide nocase

        // Credential check module names — inherent to technique
        $check_cred_files = "WindowsCredentialFiles" ascii wide
        $check_vault      = "WindowsVault" ascii wide
        $check_dpapi      = "DPAPIMasterKeys" ascii wide
        $check_cred_enum  = "CredEnum" ascii wide

        // Comprehensive enumeration flags
        $flag_group_all   = "-group=all" ascii wide
        $flag_group_sys   = "-group=system" ascii wide
        $flag_group_user  = "-group=user" ascii wide
        $flag_group_misc  = "-group=misc" ascii wide

        // System survey checks
        $check_osinfo     = "OSInfo" ascii wide
        $check_processes  = "Processes" ascii wide
        $check_services   = "Services" ascii wide
        $check_envvars    = "EnvironmentVariables" ascii wide

        // Network and file recon checks
        $check_dns        = "DNSCache" ascii wide
        $check_shares     = "NetworkShares" ascii wide
        $check_interesting = "InterestingFiles" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            ($class_seatbelt or $class_program) and
            $class_ghostpack
        ) or (
            3 of ($check_cred_*) and
            2 of ($flag_group_*)
        ) or (
            $check_interesting and $check_vault and $check_cred_files and
            2 of ($check_osinfo, $check_processes, $check_services, $check_dns)
        )
}

/*
    ============================================================
    Rule: Pre-Encryption Target List Artifact
    MITRE ATT&CK: T1119 - Automated Collection, T1083 - File and Directory Discovery
    Confidence: Medium
    ============================================================
    Description: Detects text files containing enumerated file paths with
    file size metadata in the format used by ransomware to stage their
    pre-encryption target lists. The pattern "C:\path\to\file|<size>"
    or "C:\path\to\file,<size>" is a characteristic ransomware artifact.
    Matches memory dumps and files on disk alike.
    ============================================================
*/
rule PreEncryption_Target_List_Artifact
{
    meta:
        description = "Detects ransomware pre-encryption target list files containing enumerated file paths with size metadata. Format is filepath|size or filepath,size — characteristic reconnaissance staging artifact."
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07"
        mitre_attack = "T1119, T1083"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1119/"

    strings:
        // Path-with-size format commonly written by ransomware enumeration
        $path_pipe_size   = /[A-Za-z]:\\[^\r\n|]{10,200}\.(docx?|xlsx?|pdf|db|sql|bak|pptx?|csv|mdb|sqlite)\|\d+/ ascii
        $path_comma_size  = /[A-Za-z]:\\[^\r\n,]{10,200}\.(docx?|xlsx?|pdf|db|sql|bak|pptx?|csv|mdb|sqlite),\d+/ ascii

        // Header keywords found in ransomware target lists
        $header_encrypt   = "# Pre-Encryption" ascii nocase
        $header_target    = "# Target" ascii nocase
        $header_total     = "# Total Targets:" ascii nocase
        $header_source    = "# Source Directory:" ascii nocase

        // Extension markers appearing in bulk
        $ext_docx   = ".docx" ascii nocase
        $ext_xlsx   = ".xlsx" ascii nocase
        $ext_pdf    = ".pdf" ascii nocase
        $ext_sql    = ".sql" ascii nocase
        $ext_db     = ".db" ascii nocase
        $ext_bak    = ".bak" ascii nocase

    condition:
        filesize < 50MB and
        (
            ($path_pipe_size or $path_comma_size) and
            (2 of ($header_*) or
             (4 of ($ext_*) and ($path_pipe_size or $path_comma_size)))
        )
}

/*
    ============================================================
    Rule: Bulk File Enumeration Output via Windows dir Command
    MITRE ATT&CK: T1083 - File and Directory Discovery
    Confidence: Low-Medium
    ============================================================
    Description: Detects text output files produced by Windows "dir /s /b"
    style enumeration commands redirected to disk. The bare format (/b)
    produces one absolute path per line with no size info — distinct from
    target lists, but still a discovery artifact. Also matches PowerShell
    Get-ChildItem -Recurse output redirected to file.
    ============================================================
*/
rule DirCommandEnumeration_Output_File
{
    meta:
        description = "Detects text files containing bare recursive directory listing output (dir /s /b or equivalent) — a pre-encryption reconnaissance artifact written to disk by attackers staging file target lists."
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07"
        mitre_attack = "T1083"
        confidence = "low"
        reference = "https://attack.mitre.org/techniques/T1083/"

    strings:
        // Windows absolute paths in bare format (one per line)
        $win_path_docx  = /C:\\[^\r\n]{5,200}\.docx\r?\n/ ascii
        $win_path_xlsx  = /C:\\[^\r\n]{5,200}\.xlsx\r?\n/ ascii
        $win_path_pdf   = /C:\\[^\r\n]{5,200}\.pdf\r?\n/ ascii
        $win_path_sql   = /C:\\[^\r\n]{5,200}\.sql\r?\n/ ascii
        $win_path_db    = /C:\\[^\r\n]{5,200}\.db\r?\n/ ascii
        $win_path_bak   = /C:\\[^\r\n]{5,200}\.bak\r?\n/ ascii
        $win_path_mdb   = /C:\\[^\r\n]{5,200}\.mdb\r?\n/ ascii

        // Minimum 10 consecutive path lines indicating bulk enumeration
        $bulk_marker    = /([A-Za-z]:\\[^\r\n]{5,200}\r?\n){10,}/

    condition:
        filesize < 100MB and
        $bulk_marker and
        4 of ($win_path_*)
}

/*
    ============================================================
    Rule: .NET Assembly Performing Credential Store Enumeration
    MITRE ATT&CK: T1082 - System Information Discovery
    Confidence: Medium
    ============================================================
    Description: Detects .NET compiled binaries (C# assemblies) that
    reference credential store APIs and file paths used for host-based
    credential enumeration. Any .NET tool performing this technique —
    not just Seatbelt — would contain these API references. Covers
    Windows Credential Manager, DPAPI, and Vault APIs.
    ============================================================
*/
rule DotNet_Assembly_Credential_Store_Enumeration
{
    meta:
        description = "Detects .NET assembly binaries referencing Windows Credential Manager, DPAPI, and Vault APIs for credential store enumeration — technique-level indicator present in any .NET recon tool."
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07"
        mitre_attack = "T1082"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1082/"

    strings:
        // DPAPI credential protection APIs
        $api_dpapi_protect  = "CryptProtectData" ascii wide
        $api_dpapi_unprotect = "CryptUnprotectData" ascii wide
        $api_dpapi_blob     = "DATA_BLOB" ascii wide

        // Windows Credential Manager APIs
        $api_cred_read      = "CredRead" ascii wide
        $api_cred_enum      = "CredEnumerate" ascii wide
        $api_cred_write     = "CredWrite" ascii wide
        $api_cred_free      = "CredFree" ascii wide

        // Vault access
        $api_vault_open     = "VaultOpenVault" ascii wide
        $api_vault_enum     = "VaultEnumerateVaults" ascii wide
        $api_vault_items    = "VaultEnumerateItems" ascii wide

        // Credential file paths
        $path_credentials   = "\\Microsoft\\Credentials" ascii wide
        $path_protect       = "\\Microsoft\\Protect" ascii wide
        $path_vault         = "\\Microsoft\\Vault" ascii wide

        // .NET runtime marker
        $dotnet_header      = { 4D 5A 90 00 03 00 00 00 }

    condition:
        $dotnet_header at 0 and
        filesize < 30MB and
        (
            (2 of ($api_dpapi_*) and $path_protect) or
            (2 of ($api_cred_*) and $path_credentials) or
            (2 of ($api_vault_*) and $path_vault) or
            ($path_credentials and $path_protect and $path_vault)
        )
}

/*
    ============================================================
    Rule: Ransomware Pre-Encryption Reconnaissance Script
    MITRE ATT&CK: T1083, T1119
    Confidence: Medium
    ============================================================
    Description: Detects PowerShell or batch scripts containing multiple
    ransomware-typical enumeration patterns: recursive listing, extension
    filtering across document types, and file size/path collection.
    Matches the behavioral script pattern, not any specific tool.
    ============================================================
*/
rule RansomwareRecon_Script_Enumeration_Pattern
{
    meta:
        description = "Detects scripts (PowerShell, batch, VBScript) containing combined ransomware reconnaissance patterns: recursive enumeration, multi-extension filtering for documents/databases, and target list construction."
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07"
        mitre_attack = "T1083, T1119"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1083/"

    strings:
        // Recursive enumeration commands
        $recurse_dir    = "dir /s /b" ascii nocase
        $recurse_ps     = "Get-ChildItem" ascii wide nocase
        $recurse_walk   = "filepath.Walk" ascii
        $recurse_find   = "find . -name" ascii

        // Document extension targeting
        $ext_target_docx = "*.docx" ascii nocase
        $ext_target_xlsx = "*.xlsx" ascii nocase
        $ext_target_pdf  = "*.pdf" ascii nocase
        $ext_target_sql  = "*.sql" ascii nocase
        $ext_target_bak  = "*.bak" ascii nocase
        $ext_target_db   = "*.db" ascii nocase

        // Result collection patterns
        $collect_out    = "Out-File" ascii nocase
        $collect_redir  = " > " ascii
        $collect_write  = "WriteFile" ascii nocase
        $collect_append = "Add-Content" ascii nocase

        // Size enumeration
        $size_length    = ".Length" ascii nocase
        $size_getlength = "GetLength" ascii nocase
        $size_info      = "info.Size()" ascii

    condition:
        filesize < 5MB and
        (1 of ($recurse_*)) and
        (3 of ($ext_target_*)) and
        (1 of ($collect_*) or 1 of ($size_*))
}
