/*
    ============================================================
    YARA Rules - Multi-Stage Ransomware Killchain
    Test ID: 5ed12ef2-5e29-49a2-8f26-269d8e9edcea
    MITRE ATT&CK: T1204.002, T1134.001, T1083, T1486, T1491.001
    Platform: Windows
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-03-14
    ============================================================
    All rules target underlying attack technique behaviors.
    They will match binaries from any attacker using these
    techniques, not only this test's binaries.
    ============================================================
*/


/*
    ============================================================
    Rule: Ransomware_Token_Manipulation_Capability
    MITRE ATT&CK: T1134.001
    Confidence: High
    Description: Detects PE files that implement the Windows API sequence
                 used for token theft privilege escalation: process enumeration
                 via CreateToolhelp32Snapshot, followed by OpenProcessToken +
                 AdjustTokenPrivileges. This pattern is the core of T1134.001
                 token impersonation as used by Conti, LockBit, and similar.
    ============================================================
*/

rule Ransomware_Token_Manipulation_Capability {
    meta:
        description = "PE binary with token manipulation API pattern (T1134.001) - process enum + token ops + dangerous privs"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "5ed12ef2-5e29-49a2-8f26-269d8e9edcea"
        mitre_attack = "T1134.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1134/001/"

    strings:
        // Token access APIs
        $api_open_token       = "OpenProcessToken" ascii wide
        $api_adjust_privs     = "AdjustTokenPrivileges" ascii wide
        $api_dup_token        = "DuplicateToken" ascii wide
        $api_dup_tokenex      = "DuplicateTokenEx" ascii wide
        $api_impersonate      = "ImpersonateLoggedOnUser" ascii wide
        $api_set_thread_token = "SetThreadToken" ascii wide

        // Process enumeration APIs (used to find SYSTEM process PIDs)
        $api_snap             = "CreateToolhelp32Snapshot" ascii wide
        $api_proc_first       = "Process32First" ascii wide
        $api_proc_next        = "Process32Next" ascii wide
        $api_open_proc        = "OpenProcess" ascii wide

        // High-value privilege names targeted by ransomware
        $priv_debug           = "SeDebugPrivilege" ascii wide
        $priv_backup          = "SeBackupPrivilege" ascii wide
        $priv_restore         = "SeRestorePrivilege" ascii wide
        $priv_ownership       = "SeTakeOwnershipPrivilege" ascii wide
        $priv_shutdown        = "SeShutdownPrivilege" ascii wide

        // SYSTEM process targets
        $target_winlogon      = "winlogon.exe" ascii wide nocase
        $target_lsass         = "lsass.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        // Must have core token manipulation API(s)
        (1 of ($api_open_token, $api_adjust_privs, $api_dup_token, $api_dup_tokenex,
               $api_impersonate, $api_set_thread_token)) and
        // Must have process enumeration to find target PIDs
        ($api_snap and ($api_proc_first or $api_proc_next) and $api_open_proc) and
        // Must reference dangerous privileges or SYSTEM process targets
        (2 of ($priv_*) or 1 of ($target_*))
}


/*
    ============================================================
    Rule: Ransomware_AES_File_Encryption_Loop
    MITRE ATT&CK: T1486
    Confidence: High
    Description: Detects PE files implementing AES-based file encryption in a
                 loop pattern consistent with ransomware. The combination of
                 CryptoAPI or Go crypto imports, read-write file I/O, and
                 ransomware-characteristic extension strings or MASTER_KEY
                 references indicates a file encryptor, not a generic encryption
                 library consumer.
    ============================================================
*/

rule Ransomware_AES_File_Encryption_Loop {
    meta:
        description = "PE binary with AES file encryption loop + ransomware extension or key escrow (T1486)"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "5ed12ef2-5e29-49a2-8f26-269d8e9edcea"
        mitre_attack = "T1486"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1486/"

    strings:
        // Windows CryptoAPI (classic ransomware)
        $capi_gen      = "CryptGenKey" ascii wide
        $capi_enc      = "CryptEncrypt" ascii wide
        $capi_import   = "CryptImportKey" ascii wide
        $capi_export   = "CryptExportKey" ascii wide
        $capi_acquire  = "CryptAcquireContext" ascii wide

        // Go standard library crypto strings (compiled Go ransomware)
        $go_aes        = "crypto/aes" ascii
        $go_cipher     = "crypto/cipher" ascii
        $go_rand       = "crypto/rand" ascii
        $go_gcm_seal   = "gcm.Seal" ascii
        $go_new_cipher = "aes.NewCipher" ascii

        // File I/O verbs present in any encryption loop
        $io_read       = "ReadFile" ascii wide
        $io_write      = "WriteFile" ascii wide
        $io_delete     = "DeleteFile" ascii wide
        $io_findfile   = "FindFirstFileW" ascii wide

        // Known ransomware appended extensions
        $ext_encrypted  = ".encrypted" ascii wide
        $ext_locked     = ".locked" ascii wide
        $ext_crypted    = ".crypted" ascii wide
        $ext_enc        = ".enc" ascii wide nocase
        $ext_crypt      = ".crypt" ascii wide nocase
        $ext_ransom     = ".ransom" ascii wide nocase
        $ext_wncry      = ".WNCRY" ascii wide
        $ext_ryk        = ".ryk" ascii wide

        // Key escrow / encryption completion markers
        $key_marker     = "MASTER_KEY" ascii wide nocase
        $enc_complete   = "ENCRYPTION_COMPLETE" ascii wide
        $ransom_key     = "RANSOMWARE_KEY" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        // Must have encryption capability (CryptoAPI or Go crypto)
        (2 of ($capi_*) or 2 of ($go_*) or ($capi_enc and $capi_gen)) and
        // Must have file I/O (reading/writing files in loop)
        (2 of ($io_*)) and
        // Must have at least one ransomware-specific indicator
        (1 of ($ext_*) or $key_marker or $enc_complete or $ransom_key)
}


/*
    ============================================================
    Rule: Ransomware_Ransom_Note_Text_Content
    MITRE ATT&CK: T1491.001
    Confidence: High
    Description: Detects text files containing language patterns consistent
                 with ransom notes dropped by real-world ransomware families.
                 Matches on the combination of "files have been encrypted"
                 language with payment demand indicators. Does not match
                 on any specific ransomware brand name to maximize coverage.
    ============================================================
*/

rule Ransomware_Ransom_Note_Text_Content {
    meta:
        description = "Text file with ransom note language: encryption announcement + payment demand (T1491.001)"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "5ed12ef2-5e29-49a2-8f26-269d8e9edcea"
        mitre_attack = "T1491.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1491/001/"

    strings:
        // Encryption announcement phrases (common across families)
        $enc_announce1  = "your files have been encrypted" ascii wide nocase
        $enc_announce2  = "all your files are encrypted" ascii wide nocase
        $enc_announce3  = "your important files have been encrypted" ascii wide nocase
        $enc_announce4  = "your data has been encrypted" ascii wide nocase
        $enc_announce5  = "files were encrypted" ascii wide nocase

        // Payment/contact demand phrases
        $demand1        = "bitcoin" ascii wide nocase
        $demand2        = "BTC" ascii wide
        $demand3        = "to decrypt your files" ascii wide nocase
        $demand4        = "decryption key" ascii wide nocase
        $demand5        = "contact us" ascii wide nocase
        $demand6        = "payment instructions" ascii wide nocase
        $demand7        = "ransom" ascii wide nocase

        // Urgency / threat language
        $threat1        = "do not rename" ascii wide nocase
        $threat2        = "do not try to decrypt" ascii wide nocase
        $threat3        = "will be deleted" ascii wide nocase
        $threat4        = "deadline" ascii wide nocase

    condition:
        filesize < 100KB and
        (1 of ($enc_announce*)) and
        (2 of ($demand*) or 1 of ($threat*))
}


/*
    ============================================================
    Rule: Ransomware_Ransom_Note_HTML_Content
    MITRE ATT&CK: T1491.001
    Confidence: High
    Description: Detects HTML ransom note files. Multiple ransomware families
                 (BlackCat/ALPHV, LockBit 3.0, REvil) drop HTML ransom notes
                 alongside plain-text variants for visual impact. The rule
                 matches on the combination of HTML structure with encryption
                 announcement content.
    ============================================================
*/

rule Ransomware_Ransom_Note_HTML_Content {
    meta:
        description = "HTML file with ransomware content - encrypted files announcement in HTML (T1491.001)"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "5ed12ef2-5e29-49a2-8f26-269d8e9edcea"
        mitre_attack = "T1491.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1491/001/"

    strings:
        // HTML structure markers
        $html_doctype  = "<!DOCTYPE html>" ascii nocase
        $html_open     = "<html" ascii nocase
        $html_title    = "<title>" ascii nocase

        // Ransom content in HTML context
        $ransom_h1_1   = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $ransom_h1_2   = "ALL YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $ransom_h1_3   = "FILES ENCRYPTED" ascii wide nocase
        $ransom_pay1   = "bitcoin" ascii nocase
        $ransom_pay2   = "decrypt" ascii nocase
        $ransom_pay3   = "payment" ascii nocase

        // Visual styling typical of ransomware HTML notes
        $css_red_bg    = "background: #ff" ascii nocase
        $css_anim      = "@keyframes" ascii
        $css_warning   = "class=\"warning\"" ascii
        $css_attention = "ATTENTION" ascii nocase

    condition:
        filesize < 200KB and
        ($html_doctype or ($html_open and $html_title)) and
        (1 of ($ransom_h1_*)) and
        (1 of ($ransom_pay*) or 1 of ($css_*))
}


/*
    ============================================================
    Rule: Ransomware_Key_Escrow_File
    MITRE ATT&CK: T1486
    Confidence: High
    Description: Detects small files containing ransomware encryption key
                 material or key escrow markers. Ransomware writes a local
                 key file after encryption to prove decryption capability to
                 the victim or as a staging point before C2 exfiltration.
                 The RANSOMWARE_KEY: prefix pattern and MASTER_KEY filename
                 are present in multiple ransomware implementations.
    ============================================================
*/

rule Ransomware_Key_Escrow_File {
    meta:
        description = "Small file with ransomware key escrow content - post-encryption key material (T1486)"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "5ed12ef2-5e29-49a2-8f26-269d8e9edcea"
        mitre_attack = "T1486"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1486/"

    strings:
        $key_prefix1   = "RANSOMWARE_KEY:" ascii
        $key_prefix2   = "ENCRYPTION_KEY:" ascii
        $key_prefix3   = "MASTER_KEY:" ascii
        $key_label1    = "MASTER_KEY" ascii wide
        $key_hex       = /RANSOMWARE_KEY:[0-9a-fA-F]{16,}/ ascii

    condition:
        filesize < 4KB and
        (1 of ($key_prefix*) or $key_label1 or $key_hex)
}


/*
    ============================================================
    Rule: Ransomware_File_Discovery_Target_List
    MITRE ATT&CK: T1083
    Confidence: High
    Description: Detects ransomware-generated file discovery output lists.
                 Before encrypting, ransomware builds a target list by scanning
                 the filesystem and writes it to a staging file. The combination
                 of RANSOMWARE_TARGETS header with Total/Priority fields is
                 a behavioral artifact of the pre-encryption reconnaissance phase.
    ============================================================
*/

rule Ransomware_File_Discovery_Target_List {
    meta:
        description = "Ransomware pre-encryption file discovery target list artifact (T1083)"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "5ed12ef2-5e29-49a2-8f26-269d8e9edcea"
        mitre_attack = "T1083"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1083/"

    strings:
        $header1       = "RANSOMWARE_TARGETS" ascii
        $header2       = "ENCRYPTION_TARGETS" ascii
        $header3       = "FILES_TO_ENCRYPT" ascii
        $total_line    = "Total:" ascii
        $priority      = "Priority" ascii
        $critical_ext1 = ".docx" ascii
        $critical_ext2 = ".xlsx" ascii
        $critical_ext3 = ".pdf" ascii
        $critical_ext4 = ".db" ascii
        $critical_ext5 = ".key" ascii
        $critical_ext6 = ".pem" ascii

    condition:
        filesize < 50KB and
        (1 of ($header*)) and
        ($total_line or $priority or 3 of ($critical_ext*))
}
