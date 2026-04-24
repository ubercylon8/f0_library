/*
    YARA Rules — Nightmare-Eclipse RedSun Primitive Chain
    UUID: 0d7e7571-45e2-426a-ac8e-bdb000439761
    Focus: static pattern detection for code that exercises the RedSun
    API surface (CfApi + NtOpenDirectoryObject + FSCTL_REQUEST_BATCH_OPLOCK
    + IO_REPARSE_TAG_MOUNT_POINT + FILE_SUPERSEDE race).

    These rules target the TECHNIQUE FAMILY. They do not rely on
    F0RT1KA-specific strings (test UUID, provider name) because a real
    attacker would not carry those.
*/

import "pe"

rule REDSUN_CloudFiles_Rewrite_Primitive_Chain
{
    meta:
        description = "RedSun-style PE that imports Cloud Files API, ntdll object-manager enumeration, and uses FILE_SUPERSEDE / mount-point reparse patterns"
        author = "F0RT1KA sectest-builder"
        reference = "https://github.com/Nightmare-Eclipse/RedSun"
        mitre_attack = "T1211, T1006, T1574"
        threat_name = "Nightmare-Eclipse.RedSun"
        severity = "high"
        date = "2026-04-24"

    strings:
        // Cloud Files API imports
        $cf1 = "CfRegisterSyncRoot" ascii
        $cf2 = "CfConnectSyncRoot" ascii
        $cf3 = "CfCreatePlaceholders" ascii

        // ntdll object-manager enumeration
        $nt1 = "NtOpenDirectoryObject" ascii
        $nt2 = "NtQueryDirectoryObject" ascii

        // VSS device name prefix (UTF-16 LE for wide-char usage)
        $vss_w = "H\x00a\x00r\x00d\x00d\x00i\x00s\x00k\x00V\x00o\x00l\x00u\x00m\x00e\x00S\x00h\x00a\x00d\x00o\x00w\x00C\x00o\x00p\x00y\x00"
        $vss_a = "HarddiskVolumeShadowCopy" ascii

        // IOCTL control codes as 32-bit constants
        // FSCTL_REQUEST_BATCH_OPLOCK = 0x00090004 (approx; varies by METHOD/ACCESS encoding)
        $ioctl_oplock = { 04 00 09 00 }
        // FSCTL_SET_REPARSE_POINT = 0x000900A4
        $ioctl_set_reparse = { A4 00 09 00 }
        // IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
        $reparse_tag_mount = { 03 00 00 A0 }

        // FILE_SUPERSEDE disposition literal used with NtCreateFile
        $file_supersede_sym = "FILE_SUPERSEDE" ascii nocase

    condition:
        uint16(0) == 0x5A4D and   // PE MZ header
        filesize < 50MB and
        (
            // Core RedSun signature: Cloud Files API + object-manager enum + VSS name filter
            (any of ($cf*)) and (any of ($nt*)) and (any of ($vss_a, $vss_w))
        )
        and
        (
            // Plus at least one of the write-side primitives
            $ioctl_oplock or $ioctl_set_reparse or $reparse_tag_mount or $file_supersede_sym
        )
}

rule REDSUN_NonMicrosoft_CloudFiles_Provider_Registration
{
    meta:
        description = "PE that calls CfRegisterSyncRoot but is not a known Cloud Files provider (OneDrive, iCloud, Dropbox, Google Drive, Box)"
        author = "F0RT1KA sectest-builder"
        reference = "https://learn.microsoft.com/en-us/windows/win32/cfapi/cloud-files-api-portal"
        mitre_attack = "T1211"
        severity = "medium"
        date = "2026-04-24"

    strings:
        $cf_register = "CfRegisterSyncRoot" ascii

        // Known-good provider strings (UTF-16 LE or ASCII). Presence of any of
        // these while also importing CfRegisterSyncRoot is the benign baseline.
        $provider_onedrive   = "OneDrive" ascii wide
        $provider_icloud     = "iCloud" ascii wide
        $provider_dropbox    = "Dropbox" ascii wide
        $provider_googledrive= "Google Drive" ascii wide
        $provider_box        = "Box Drive" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $cf_register and
        not any of ($provider_*)
}

rule REDSUN_MountPoint_Reparse_Builder
{
    meta:
        description = "PE that hand-builds a REPARSE_DATA_BUFFER for IO_REPARSE_TAG_MOUNT_POINT and calls DeviceIoControl with FSCTL_SET_REPARSE_POINT — a legitimate but rarely-legitimate-in-usermode primitive"
        author = "F0RT1KA sectest-builder"
        mitre_attack = "T1574"
        severity = "medium"
        date = "2026-04-24"

    strings:
        $dioc = "DeviceIoControl" ascii
        $set_reparse_str = "FSCTL_SET_REPARSE_POINT" ascii nocase
        $set_reparse_code = { A4 00 09 00 }
        $mount_tag = { 03 00 00 A0 }
        // The "\??\" NT-path prefix wide-string that MountPointReparseBuffer
        // substitute names use
        $nt_prefix = "\\\x00?\x00?\x00\\\x00"

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $dioc and
        ($set_reparse_str or $set_reparse_code) and
        $mount_tag and
        $nt_prefix
}
