/*
    ============================================================
    YARA Rules: T1490 — Inhibit System Recovery
    Test ID:    e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05
    MITRE ATT&CK: T1490
    Author:     F0RT1KA Detection Rules Generator
    Date:       2026-03-14
    ============================================================
    Scope: These rules target the inherent artifacts of the
    Inhibit System Recovery technique — command strings, WMI
    class references, and PE characteristics shared by any
    attacker tooling that implements T1490.  No framework-
    specific strings are included.
    ============================================================
*/


/*
    ============================================================
    Rule: T1490_VSS_Shadow_Deletion_Script
    Confidence: High
    Description: Detects script files (BAT, PS1, VBS, JS) that
    contain vssadmin shadow-deletion command strings — a near-
    universal pre-encryption step in ransomware.
    ============================================================
*/
rule T1490_VSS_Shadow_Deletion_Script
{
    meta:
        description     = "Script containing vssadmin shadow copy deletion commands (T1490)"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05"
        mitre_attack    = "T1490"
        confidence      = "high"
        reference       = "https://attack.mitre.org/techniques/T1490/"

    strings:
        $vss_del_all    = "vssadmin delete shadows /all"      ascii wide nocase
        $vss_del_for    = "vssadmin delete shadows /for="     ascii wide nocase
        $vss_resize     = "vssadmin resize shadowstorage"     ascii wide nocase
        $vss_del_store  = "vssadmin delete shadowstorage"     ascii wide nocase

    condition:
        any of ($vss_*)
}


/*
    ============================================================
    Rule: T1490_Bcdedit_Recovery_Disable_Script
    Confidence: High
    Description: Detects scripts that pass boot-recovery-disabling
    arguments to bcdedit.exe.  Ransomware uses this to prevent
    Windows from entering recovery mode after encryption.
    ============================================================
*/
rule T1490_Bcdedit_Recovery_Disable_Script
{
    meta:
        description     = "Script containing bcdedit commands that disable Windows Recovery (T1490)"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05"
        mitre_attack    = "T1490"
        confidence      = "high"
        reference       = "https://attack.mitre.org/techniques/T1490/"

    strings:
        $bcd_recovery   = "bcdedit /set"                      ascii wide nocase
        $bcd_recov_off  = "recoveryenabled No"                ascii wide nocase
        $bcd_boot_pol   = "bootstatuspolicy ignoreallfailures" ascii wide nocase
        $bcd_safeboot   = "bcdedit /set {default} safeboot"   ascii wide nocase
        $bcd_del        = "bcdedit /deletevalue"              ascii wide nocase

    condition:
        ($bcd_recovery and ($bcd_recov_off or $bcd_boot_pol)) or
        $bcd_safeboot or
        $bcd_del
}


/*
    ============================================================
    Rule: T1490_Wbadmin_Backup_Destruction_Script
    Confidence: High
    Description: Detects scripts or PE binaries that contain
    wbadmin backup-deletion command strings used by ransomware to
    destroy Windows Backup catalogs and system-state snapshots.
    ============================================================
*/
rule T1490_Wbadmin_Backup_Destruction_Script
{
    meta:
        description     = "Script/binary containing wbadmin backup-deletion commands (T1490)"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05"
        mitre_attack    = "T1490"
        confidence      = "high"
        reference       = "https://attack.mitre.org/techniques/T1490/"

    strings:
        $wba_catalog    = "wbadmin delete catalog"            ascii wide nocase
        $wba_state      = "wbadmin delete systemstatebackup"  ascii wide nocase
        $wba_keepzero   = "keepVersions:0"                    ascii wide nocase
        $wba_backup     = "wbadmin delete backup"             ascii wide nocase

    condition:
        any of ($wba_*)
}


/*
    ============================================================
    Rule: T1490_WMI_Shadow_Copy_Deletion
    Confidence: High
    Description: Detects WMI-based shadow copy deletion — used by
    ransomware variants that avoid vssadmin.exe to evade process-
    based detections.  Matches both PowerShell and WMIC invocations.
    ============================================================
*/
rule T1490_WMI_Shadow_Copy_Deletion
{
    meta:
        description     = "WMI shadow copy deletion via Win32_ShadowCopy class (T1490)"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05"
        mitre_attack    = "T1490"
        confidence      = "high"
        reference       = "https://attack.mitre.org/techniques/T1490/"

    strings:
        // WMIC command line
        $wmic_shadow    = "shadowcopy delete"                 ascii wide nocase
        $wmic_nointer   = "/nointeractive"                    ascii wide nocase

        // PowerShell WMI pattern
        $ps_wmi_class   = "Win32_ShadowCopy"                  ascii wide nocase
        $ps_delete      = ".Delete()"                         ascii wide nocase
        $ps_gwmi        = "Get-WmiObject"                     ascii wide nocase
        $ps_gwmi2       = "Get-CimInstance"                   ascii wide nocase

    condition:
        $wmic_shadow or
        ($ps_wmi_class and ($ps_delete or ($ps_gwmi and $ps_wmi_class) or ($ps_gwmi2 and $ps_wmi_class)))
}


/*
    ============================================================
    Rule: T1490_Recovery_Inhibition_PE_Multi_Indicator
    Confidence: Medium
    Description: Detects portable executables that embed multiple
    recovery-inhibition command strings — indicative of a
    ransomware payload that bundles the full T1490 kill-chain
    within a single binary.
    ============================================================
*/
rule T1490_Recovery_Inhibition_PE_Multi_Indicator
{
    meta:
        description     = "PE binary embedding multiple T1490 recovery-inhibition command strings"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05"
        mitre_attack    = "T1490"
        confidence      = "medium"
        reference       = "https://attack.mitre.org/techniques/T1490/"

    strings:
        $vss_del        = "vssadmin delete shadows"           ascii wide nocase
        $bcd_recov      = "recoveryenabled No"                ascii wide nocase
        $wba_del        = "wbadmin delete"                    ascii wide nocase
        $wmic_shad      = "shadowcopy delete"                 ascii wide nocase
        $bcd_boot       = "bootstatuspolicy ignoreallfailures" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        3 of ($vss_del, $bcd_recov, $wba_del, $wmic_shad, $bcd_boot)
}


/*
    ============================================================
    Rule: T1490_PowerShell_Encoded_Recovery_Inhibition
    Confidence: Medium
    Description: Detects PowerShell scripts that base64-encode
    recovery-inhibition commands — an obfuscation technique used
    to evade command-line string matching rules.
    ============================================================
*/
rule T1490_PowerShell_Encoded_Recovery_Inhibition
{
    meta:
        description     = "PowerShell with base64-encoded recovery-inhibition command (T1490)"
        author          = "F0RT1KA"
        date            = "2026-03-14"
        test_id         = "e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05"
        mitre_attack    = "T1490"
        confidence      = "medium"
        reference       = "https://attack.mitre.org/techniques/T1490/"

    strings:
        // PowerShell encoded command invocation
        $ps_enc1        = "-EncodedCommand"  ascii wide nocase
        $ps_enc2        = "-enc "            ascii wide nocase
        $ps_enc3        = "-e "              ascii wide nocase

        // Base64-encoded fragments of common T1490 strings
        // "vssadmin" encoded as UTF-16LE
        $b64_vss        = "dgBzAHMAYQBkAG0AaQBuAA==" ascii
        // "shadowcopy" encoded as UTF-16LE
        $b64_shadow     = "cwBoAGEAZABvAHcAYwBvAHAAeQA=" ascii
        // "recoveryenabled" encoded as UTF-16LE
        $b64_recovery   = "cgBlAGMAbwB2AGUAcgB5AGUAbgBhAGIAbABlAGQA" ascii

    condition:
        ($ps_enc1 or $ps_enc2 or $ps_enc3) and
        any of ($b64_*)
}
