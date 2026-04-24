/*
    ============================================================
    UnDefend Defender Update-DoS - YARA Rules
    Test ID: 6a2351ac-654a-4112-b378-e6919beef70d
    MITRE ATT&CK: T1562.001, T1083
    Threat Actor: Nightmare-Eclipse (PoC author)
    Author: F0RT1KA sectest-builder
    Date: 2026-04-24
    ============================================================

    These rules detect UnDefend-class Defender DoS binaries via the
    characteristic API-import fingerprint: NtCreateFile + LockFile /
    LockFileEx + NotifyServiceStatusChangeW + ReadDirectoryChangesW,
    combined with Defender registry-key strings.

    IMPORTANT: These rules target attacker tooling fingerprint patterns
    (API imports + embedded Defender path strings). They are intentionally
    generic across the UnDefend technique class and will also match future
    variants sharing the same primitive.

    Usage:
        yara -r 6a2351ac-654a-4112-b378-e6919beef70d_rules.yar /path/to/scan

    ============================================================
*/

import "pe"


rule UnDefend_Class_Defender_LockRace_API_Fingerprint
{
    meta:
        description = "PE imports the UnDefend-class Defender DoS API set: file locks + service notifications + directory-change watchers"
        author      = "F0RT1KA sectest-builder"
        date        = "2026-04-24"
        test_id     = "6a2351ac-654a-4112-b378-e6919beef70d"
        mitre       = "T1562.001, T1083"
        severity    = "high"
        reference   = "https://github.com/Nightmare-Eclipse/UnDefend"

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and pe.imports("kernel32.dll", "LockFile")
        and pe.imports("kernel32.dll", "LockFileEx")
        and pe.imports("kernel32.dll", "ReadDirectoryChangesW")
        and pe.imports("advapi32.dll", "NotifyServiceStatusChangeW")
        and (
            pe.imports("ntdll.dll", "NtCreateFile")
            or pe.imports("kernel32.dll", "CreateFileW")
        )
        and for any i in (0 .. pe.number_of_imports - 1) :
            (pe.import_details[i].library_name == "advapi32.dll"
             and for any f in pe.import_details[i].functions :
                (f.name == "RegOpenKeyExW" or f.name == "RegQueryValueExW"))
}


rule UnDefend_Class_Defender_Path_Strings
{
    meta:
        description = "Binary embeds Defender update-path strings characteristic of UnDefend-class tools"
        author      = "F0RT1KA sectest-builder"
        date        = "2026-04-24"
        test_id     = "6a2351ac-654a-4112-b378-e6919beef70d"
        mitre       = "T1562.001, T1083"
        severity    = "high"

    strings:
        $s_defender_key    = "SOFTWARE\\Microsoft\\Windows Defender" ascii wide
        $s_sig_updates_key = "Signature Updates" ascii wide
        $s_prod_path_val   = "ProductAppDataPath" ascii wide
        $s_sig_location    = "SignatureLocation" ascii wide
        $s_def_updates_dir = "Definition Updates" ascii wide
        $s_mrt_dir         = "System32\\MRT" ascii wide
        $s_mpavbase_vdm    = "mpavbase.vdm" ascii wide
        $s_mpavbase_lkg    = "mpavbase.lkg" ascii wide
        $s_windefend_svc   = "WinDefend" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and (
            // registry-path recon fingerprint
            ($s_defender_key and $s_prod_path_val and ($s_sig_location or $s_sig_updates_key))
            // or the engine-lock fingerprint
            or ($s_mpavbase_vdm and $s_windefend_svc)
            // or backup-lock fingerprint
            or ($s_mpavbase_lkg and $s_def_updates_dir)
            // or directory-watch fingerprint (passive mode)
            or ($s_def_updates_dir and $s_mrt_dir)
        )
}


rule UnDefend_Class_ServiceNotify_WinDefend
{
    meta:
        description = "PE imports NotifyServiceStatusChangeW and embeds the WinDefend service name — a near-unique fingerprint for Defender-service tampering"
        author      = "F0RT1KA sectest-builder"
        date        = "2026-04-24"
        test_id     = "6a2351ac-654a-4112-b378-e6919beef70d"
        mitre       = "T1562.001"
        severity    = "high"

    strings:
        $s_windefend_svc   = "WinDefend" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and pe.imports("advapi32.dll", "NotifyServiceStatusChangeW")
        and pe.imports("advapi32.dll", "OpenSCManagerW")
        and pe.imports("advapi32.dll", "OpenServiceW")
        and $s_windefend_svc
}


rule UnDefend_Class_DirWatch_DefenderUpdates
{
    meta:
        description = "PE that watches Defender Definition Updates via ReadDirectoryChangesW + embeds update-path strings"
        author      = "F0RT1KA sectest-builder"
        date        = "2026-04-24"
        test_id     = "6a2351ac-654a-4112-b378-e6919beef70d"
        mitre       = "T1562.001, T1083"
        severity    = "medium"

    strings:
        $s_def_updates_dir = "Definition Updates" ascii wide
        $s_prod_path_val   = "ProductAppDataPath" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and pe.imports("kernel32.dll", "ReadDirectoryChangesW")
        and ($s_def_updates_dir or $s_prod_path_val)
        and not pe.imports("mpclient.dll") // legitimate Defender clients import mpclient.dll
}
