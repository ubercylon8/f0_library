/*
    ============================================================
    YARA Rules: BlueHammer Early-Stage Behavioral Pattern
    Test ID: 5e59dd6a-6c87-4377-942c-ea9b5e054cb9
    MITRE ATT&CK: T1211, T1562.001
    Threat Actor: Nightmare-Eclipse
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-04-24
    ============================================================
    These rules target technique-level indicators — the API imports,
    string patterns, and behavioral fingerprints that any tool
    implementing the BlueHammer technique chain would exhibit.
    They do NOT reference F0RT1KA test framework artifacts.
    ============================================================
*/


/*
    ============================================================
    Rule 1: Cloud Files API Combined with Transacted File Access
    Confidence: High
    Description: Detects PE files that import BOTH cldapi.dll (Cloud Files
                 sync-root API) AND ktmw32.dll (Kernel Transaction Manager).
                 No legitimate user-mode application combines these two libraries.
                 Legitimate cloud sync providers do not use KTM. Legitimate
                 KTM users (Windows Installer, DISM) do not use Cloud Files.
                 The combination is the architectural signature of the BlueHammer
                 attack chain (and any derivative using the same technique).
    ============================================================
*/
rule BlueHammer_CloudFiles_And_KTM_Import_Combination
{
    meta:
        description = "PE imports both cldapi.dll (Cloud Files) and ktmw32.dll (KTM) — highly anomalous combination used by BlueHammer-style scanner-freeze + TOCTOU attacks"
        author = "F0RT1KA"
        date = "2026-04-24"
        test_id = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
        mitre_attack = "T1211, T1562.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1211/"

    strings:
        $dll_cldapi      = "cldapi.dll" ascii nocase
        $dll_ktmw32      = "ktmw32.dll" ascii nocase
        $fn_register     = "CfRegisterSyncRoot" ascii
        $fn_connect      = "CfConnectSyncRoot" ascii
        $fn_createtx     = "CreateTransaction" ascii
        $fn_createtxfile = "CreateFileTransactedW" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            ($dll_cldapi and $dll_ktmw32) or
            ($fn_register and $fn_createtxfile) or
            ($fn_connect and $fn_createtx)
        )
}


/*
    ============================================================
    Rule 2: Cloud Files Sync-Root Registration API Imports
    Confidence: Medium
    Description: Detects binaries importing the Cloud Files API functions
                 used to register a custom sync-root and attach a
                 fetch-placeholder callback. Standalone cldapi.dll loading
                 is legitimate for OneDrive/Google Drive; this rule requires
                 the specific combination of Register + Connect (both needed
                 to establish a callback that intercepts scanner reads).
    ============================================================
*/
rule BlueHammer_CloudFiles_SyncRoot_Registration
{
    meta:
        description = "PE imports CfRegisterSyncRoot and CfConnectSyncRoot — the minimal API surface for establishing a fetch-placeholder callback to intercept AV scanner reads"
        author = "F0RT1KA"
        date = "2026-04-24"
        test_id = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
        mitre_attack = "T1211"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1211/"

    strings:
        $fn_register     = "CfRegisterSyncRoot" ascii
        $fn_connect      = "CfConnectSyncRoot" ascii
        $fn_disconnect   = "CfDisconnectSyncRoot" ascii
        $fn_unregister   = "CfUnregisterSyncRoot" ascii
        $dll_cldapi      = "cldapi.dll" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $dll_cldapi and
        $fn_register and
        $fn_connect and
        (not $fn_unregister or $fn_disconnect)
}


/*
    ============================================================
    Rule 3: Batch Oplock via DeviceIoControl — FSCTL_REQUEST_BATCH_OPLOCK
    Confidence: High
    Description: Detects binaries that contain the IOCTL code for
                 FSCTL_REQUEST_BATCH_OPLOCK (0x00090018 / 589848) as an
                 immediate operand or data constant, combined with imports
                 of DeviceIoControl. User-mode components legitimately using
                 batch oplocks are essentially limited to file-server drivers
                 and SMB redirectors — not user-space applications. The
                 constant appearing in user-space PE data is a strong indicator.
    ============================================================
*/
rule BlueHammer_BatchOplock_FSCTL_Constant
{
    meta:
        description = "PE contains FSCTL_REQUEST_BATCH_OPLOCK constant (0x00090018) and imports DeviceIoControl — scanner-stall primitive used by BlueHammer T1562.001 phase"
        author = "F0RT1KA"
        date = "2026-04-24"
        test_id = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
        mitre_attack = "T1562.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1562/001/"

    strings:
        // FSCTL_REQUEST_BATCH_OPLOCK = 0x00090018 in little-endian DWORD
        $ioctl_le       = { 18 00 09 00 }
        // Also catch as immediate value in push/mov instruction contexts
        $ioctl_hex_str  = "00090018" ascii nocase
        $fn_devioctl    = "DeviceIoControl" ascii
        $fn_cancelio    = "CancelIoEx" ascii
        $fn_wfso        = "WaitForSingleObject" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        ($ioctl_le or $ioctl_hex_str) and
        $fn_devioctl and
        ($fn_cancelio or $fn_wfso)
}


/*
    ============================================================
    Rule 4: NT Object Manager VSS Enumeration Pattern
    Confidence: High
    Description: Detects binaries that import NtOpenDirectoryObject and
                 NtQueryDirectoryObject from ntdll.dll together with a string
                 reference to "HarddiskVolumeShadowCopy" — the naming convention
                 for VSS device objects in the NT namespace. This specific
                 combination is the fingerprint of direct VSS recon that bypasses
                 the VSS COM API (IVssBackupComponents). Legitimate enumeration
                 goes through VSSAPI.DLL, not raw NT object-directory calls.
    ============================================================
*/
rule BlueHammer_VSS_NtObjectDir_Enumeration
{
    meta:
        description = "PE imports NtOpenDirectoryObject + NtQueryDirectoryObject and references HarddiskVolumeShadowCopy — direct VSS recon bypassing the COM API, T1211 precursor to shadow-copy TOCTOU"
        author = "F0RT1KA"
        date = "2026-04-24"
        test_id = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
        mitre_attack = "T1211"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1211/"

    strings:
        $fn_ntopendir   = "NtOpenDirectoryObject" ascii
        $fn_ntquerydir  = "NtQueryDirectoryObject" ascii
        $fn_ntclose     = "NtClose" ascii
        $str_device     = "\\Device" wide ascii
        $str_shadowcopy = "HarddiskVolumeShadowCopy" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $fn_ntopendir and
        $fn_ntquerydir and
        $str_shadowcopy and
        ($str_device or $fn_ntclose)
}


/*
    ============================================================
    Rule 5: Transacted File Open (KTM) by Non-Installer Binary
    Confidence: Medium
    Description: Detects binaries importing CreateFileTransactedW together
                 with CreateTransaction and RollbackTransaction from ktmw32.dll.
                 This is the KTM usage pattern for a TOCTOU race attack: open
                 a file transactionally, read its content inside the transaction
                 context, then roll back. Legitimate users of TxF (Transactional
                 NTFS) are Windows Installer, DISM, and CBS — all of which
                 commit, not rollback, their transactions.
    ============================================================
*/
rule BlueHammer_KTM_Transacted_Open_Rollback
{
    meta:
        description = "PE imports CreateFileTransactedW + CreateTransaction + RollbackTransaction — TOCTOU-race pattern using KTM; legitimate TxF apps commit, not rollback"
        author = "F0RT1KA"
        date = "2026-04-24"
        test_id = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
        mitre_attack = "T1211"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1211/"

    strings:
        $fn_createtxfile = "CreateFileTransactedW" ascii
        $fn_createtx     = "CreateTransaction" ascii
        $fn_rollback     = "RollbackTransaction" ascii
        $dll_ktmw32      = "ktmw32.dll" ascii nocase
        // Negative: legitimate Windows Installer strings present in msiexec
        $neg_msi         = "MsiInstallProduct" ascii
        $neg_dism        = "DismGetPackages" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $fn_createtxfile and
        $fn_createtx and
        $fn_rollback and
        $dll_ktmw32 and
        not ($neg_msi or $neg_dism)
}


/*
    ============================================================
    Rule 6: Full BlueHammer Technique Chain — All Three API Surfaces
    Confidence: Critical
    Description: Requires indicators from all three technique stages in a
                 single binary: Cloud Files API (stage 1), batch oplock IOCTL
                 constant (stage 2), AND NT object directory + KTM imports
                 (stage 3). No legitimate software combines all three. This is
                 the highest-confidence BlueHammer signature short of an exact
                 hash match — it catches any tool implementing the full chain.
    ============================================================
*/
rule BlueHammer_FullChain_AllThreeStages
{
    meta:
        description = "PE combines cldapi.dll imports, FSCTL_REQUEST_BATCH_OPLOCK constant, NtOpenDirectoryObject, and CreateFileTransactedW — full BlueHammer stage-1/2/3 technique chain in a single binary"
        author = "F0RT1KA"
        date = "2026-04-24"
        test_id = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
        mitre_attack = "T1211, T1562.001"
        confidence = "critical"
        reference = "https://github.com/Nightmare-Eclipse/BlueHammer"

    strings:
        // Stage 1 — Cloud Files
        $s1_cf_register = "CfRegisterSyncRoot" ascii
        $s1_cf_connect  = "CfConnectSyncRoot" ascii
        // Stage 2 — Batch oplock
        $s2_ioctl_le    = { 18 00 09 00 }
        $s2_devioctl    = "DeviceIoControl" ascii
        // Stage 3 — VSS enum + KTM
        $s3_ntopendir   = "NtOpenDirectoryObject" ascii
        $s3_ntquerydir  = "NtQueryDirectoryObject" ascii
        $s3_createtxf   = "CreateFileTransactedW" ascii
        $s3_shadowcopy  = "HarddiskVolumeShadowCopy" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100MB and
        // All three stage groups must be present
        ($s1_cf_register and $s1_cf_connect) and
        ($s2_ioctl_le and $s2_devioctl) and
        ($s3_ntopendir and $s3_ntquerydir) and
        ($s3_createtxf or $s3_shadowcopy)
}
