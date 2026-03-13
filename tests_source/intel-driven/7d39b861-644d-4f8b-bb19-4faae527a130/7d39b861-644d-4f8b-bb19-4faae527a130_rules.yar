/*
    ============================================================
    F0RT1KA YARA Detection Rules
    Test ID: 7d39b861-644d-4f8b-bb19-4faae527a130
    Test Name: Agrius Multi-Wiper Deployment Against Banking Infrastructure
    MITRE ATT&CK: T1505.003, T1543.003, T1562.001, T1485, T1070.001
    Threat Actor: Agrius / Pink Sandstorm / Agonizing Serpens / BlackShadow
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    ============================================================

    These rules detect TECHNIQUE BEHAVIORS and known tool artifacts,
    NOT F0RT1KA test framework artifacts. They will detect real-world
    use of the same attack techniques.

    Rule Index:
      1. ASPXSpy_Webshell - ASPXSpy webshell content patterns
      2. GMER64_Driver_File - GMER anti-rootkit driver used for BYOVD
      3. Wiper_MultiLayer_IOPattern - MultiLayer wiper I/O marker pattern
      4. Wiper_PartialWasher_Pattern - PartialWasher header corruption
      5. Wiper_BFG_Agonizer_Gutmann - BFG Agonizer multi-pass overwrite
      6. Agrius_Remover_Batch - Agrius self-deletion batch script
      7. EDR_Service_Tamper_Script - Scripts targeting EDR service names
      8. EventLog_Clearing_Script - Scripts clearing Windows event logs
    ============================================================
*/

import "pe"

/*
    ============================================================
    RULE 1: ASPXSpy Webshell Content Detection
    Confidence: High
    Description: Detects ASPXSpy webshell variants deployed by
                 Agrius and other threat actors. Matches on
                 server-side code patterns inherent to webshells.
    ============================================================
*/
rule ASPXSpy_Webshell {
    meta:
        description = "Detects ASPXSpy webshell content patterns used by Agrius/Pink Sandstorm and other APTs"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "7d39b861-644d-4f8b-bb19-4faae527a130"
        mitre_attack = "T1505.003"
        confidence = "high"
        threat_actor = "Agrius"
        reference = "https://attack.mitre.org/techniques/T1505/003/"

    strings:
        // ASP.NET page directives with dangerous imports
        $aspx_header = "<%@ Page Language" ascii nocase
        $import_diag = "Import Namespace=\"System.Diagnostics\"" ascii nocase
        $import_io = "Import Namespace=\"System.IO\"" ascii nocase

        // Common webshell code patterns (server-side execution)
        $runat = "runat=\"server\"" ascii nocase
        $process_start = "Process.Start" ascii nocase
        $cmd_exec = "cmd.exe" ascii nocase
        $powershell_exec = "powershell" ascii nocase

        // ASPXSpy-specific UI elements and function patterns
        $aspxspy_title = "ASPXSpy" ascii nocase
        $file_manager = "FileManager" ascii nocase
        $cmd_shell = "CmdShell" ascii nocase
        $sql_exec = "SqlExec" ascii nocase

        // Known Agrius webshell filenames embedded in content
        $agrius_name1 = "aspxspy" ascii nocase
        $agrius_name2 = "error5" ascii nocase

    condition:
        filesize < 500KB and
        $aspx_header and $runat and
        (
            // Classic ASPXSpy with dangerous imports
            ($import_diag and ($process_start or $cmd_exec or $powershell_exec))
            or
            // ASPXSpy-specific features
            (2 of ($aspxspy_title, $file_manager, $cmd_shell, $sql_exec))
            or
            // Agrius-specific naming in content
            ($agrius_name1 and ($import_diag or $import_io))
        )
}

/*
    ============================================================
    RULE 2: GMER64 Anti-Rootkit Driver (BYOVD)
    Confidence: High
    Description: Detects the GMER64.sys driver file which is a
                 legitimate anti-rootkit tool frequently abused by
                 attackers (including Agrius) to disable EDR at
                 the kernel level via Bring-Your-Own-Vulnerable-Driver.
    ============================================================
*/
rule GMER64_Driver_File {
    meta:
        description = "Detects GMER64.sys anti-rootkit driver abused by Agrius and other APTs for BYOVD EDR bypass"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "7d39b861-644d-4f8b-bb19-4faae527a130"
        mitre_attack = "T1562.001"
        confidence = "high"
        threat_actor = "Agrius"
        reference = "https://attack.mitre.org/techniques/T1562/001/"

    strings:
        // GMER driver identification strings
        $gmer_name = "GMER" ascii wide nocase
        $gmer_full = "GMER64" ascii wide nocase
        $gmer_desc = "GMER Driver" ascii wide nocase

        // Anti-rootkit driver internal strings
        $rootkit_scan = "RootkitScan" ascii wide
        $hidden_process = "HiddenProcess" ascii wide
        $hidden_driver = "HiddenDriver" ascii wide

        // Driver device names
        $device_gmer = "\\Device\\GMER" ascii wide
        $device_gmer2 = "\\DosDevices\\GMER" ascii wide

    condition:
        // Windows driver file
        (uint16(0) == 0x5A4D or uint32(0) == 0x00000000) and
        filesize < 2MB and
        (
            ($gmer_full) or
            ($gmer_name and any of ($rootkit_scan, $hidden_process, $hidden_driver)) or
            any of ($device_gmer, $device_gmer2)
        )
}

/*
    ============================================================
    RULE 3: MultiLayer Wiper I/O Marker Pattern
    Confidence: Medium
    Description: Detects files overwritten with the MultiLayer wiper
                 signature pattern: repeating 16-byte blocks starting
                 with DE AD BE EF followed by a block counter and
                 0xCC padding bytes.
    ============================================================
*/
rule Wiper_MultiLayer_IOPattern {
    meta:
        description = "Detects files overwritten by MultiLayer wiper using DE AD BE EF marker pattern with 0xCC padding"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "7d39b861-644d-4f8b-bb19-4faae527a130"
        mitre_attack = "T1485"
        confidence = "medium"
        threat_actor = "Agrius"
        reference = "https://attack.mitre.org/techniques/T1485/"

    strings:
        // MultiLayer wiper marker pattern: DEADBEEF + counter + CC padding
        // Repeats every 16 bytes
        $marker = { DE AD BE EF [4] CC CC CC CC CC CC CC CC }

    condition:
        // File starts with the marker pattern (MultiLayer overwrites from offset 0)
        $marker at 0 and
        // Multiple repetitions indicate bulk overwrite, not coincidence
        #marker > 3 and
        filesize > 64
}

/*
    ============================================================
    RULE 4: PartialWasher Header Corruption Pattern
    Confidence: Medium
    Description: Detects files with headers corrupted by the
                 PartialWasher wiper using alternating 512-byte
                 blocks of 0x00 and 0xFF.
    ============================================================
*/
rule Wiper_PartialWasher_Pattern {
    meta:
        description = "Detects files with headers corrupted by PartialWasher wiper using alternating 0x00/0xFF 512-byte blocks"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "7d39b861-644d-4f8b-bb19-4faae527a130"
        mitre_attack = "T1485"
        confidence = "medium"
        threat_actor = "Agrius"
        reference = "https://attack.mitre.org/techniques/T1485/"

    strings:
        // First 512-byte block is all zeros
        $null_block = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

        // Second 512-byte block starts at offset 512 with all 0xFF
        $ff_block = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
                      FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF }

    condition:
        filesize > 1024 and
        // First block at offset 0 is null
        $null_block at 0 and
        // Second block at offset 512 is 0xFF (alternating pattern)
        $ff_block at 512
}

/*
    ============================================================
    RULE 5: BFG Agonizer Multi-Pass Wipe Artifact
    Confidence: Medium
    Description: Detects files fully overwritten with Gutmann-derivative
                 pass patterns used by BFG Agonizer. The final pass
                 writes all zeros before deletion, but if deletion
                 fails, the file remains as all-zero.
    ============================================================
*/
rule Wiper_BFG_Agonizer_Gutmann {
    meta:
        description = "Detects residual artifacts of BFG Agonizer 7-pass Gutmann-derivative wiper"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "7d39b861-644d-4f8b-bb19-4faae527a130"
        mitre_attack = "T1485"
        confidence = "medium"
        threat_actor = "Agrius"
        reference = "https://attack.mitre.org/techniques/T1485/"

    strings:
        // Gutmann pass 5 equivalent pattern: repeating 92 49 24
        $gutmann5 = { 92 49 24 92 49 24 92 49 24 92 49 24 92 49 24 92
                      49 24 92 49 24 92 49 24 92 49 24 92 49 24 92 49 }

        // Alternating bits pattern 01010101 (pass 3)
        $alt_55 = { 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55
                    55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 }

        // Alternating bits pattern 10101010 (pass 4)
        $alt_AA = { AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA
                    AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA }

    condition:
        filesize > 32 and
        // File contains Gutmann-derivative patterns
        (
            $gutmann5 at 0 or
            ($alt_55 at 0 and filesize < 100KB) or
            ($alt_AA at 0 and filesize < 100KB)
        )
}

/*
    ============================================================
    RULE 6: Agrius Self-Deletion Batch Script (remover.bat)
    Confidence: High
    Description: Detects batch scripts with the Agrius self-deletion
                 pattern: ping-based delay followed by artifact
                 cleanup and self-deletion via %~f0.
    ============================================================
*/
rule Agrius_Remover_Batch {
    meta:
        description = "Detects Agrius-style self-deleting batch scripts with ping delay and artifact cleanup"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "7d39b861-644d-4f8b-bb19-4faae527a130"
        mitre_attack = "T1070.001"
        confidence = "high"
        threat_actor = "Agrius"
        reference = "https://attack.mitre.org/techniques/T1070/001/"

    strings:
        // Ping-based delay (Agrius signature pattern)
        $ping_delay = "ping 127.0.0.1" ascii nocase
        $ping_delay2 = "ping localhost" ascii nocase
        $ping_n = "ping" ascii nocase

        // Self-deletion patterns
        $self_delete1 = "del /f \"%~f0\"" ascii nocase
        $self_delete2 = "del \"%~f0\"" ascii nocase
        $self_delete3 = "del %~f0" ascii nocase

        // File/directory cleanup commands
        $rmdir = "rmdir /s /q" ascii nocase
        $del_force = "del /f" ascii nocase

        // Batch file header
        $batch_header = "@echo off" ascii nocase

    condition:
        filesize < 50KB and
        $batch_header and
        // Ping delay + self-deletion (core Agrius pattern)
        any of ($ping_delay, $ping_delay2) and
        any of ($self_delete1, $self_delete2, $self_delete3) and
        // Also performs cleanup
        ($rmdir or $del_force)
}

/*
    ============================================================
    RULE 7: EDR Service Tampering Script/Binary
    Confidence: High
    Description: Detects executables or scripts containing strings
                 that enumerate and target EDR service names for
                 disabling or stopping. Covers broad range of vendors.
    ============================================================
*/
rule EDR_Service_Tamper_Script {
    meta:
        description = "Detects binaries or scripts containing EDR service names targeted for tampering"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "7d39b861-644d-4f8b-bb19-4faae527a130"
        mitre_attack = "T1562.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1562/001/"

    strings:
        // sc.exe tampering commands
        $sc_config = "sc.exe\" config" ascii nocase
        $sc_stop = "sc.exe\" stop" ascii nocase
        $sc_delete = "sc.exe\" delete" ascii nocase
        $sc_config2 = "sc config" ascii nocase
        $sc_stop2 = "sc stop" ascii nocase

        // EDR/AV service names (at least 5 vendors = suspicious)
        $svc_defender = "WinDefend" ascii wide
        $svc_sense = "Sense" ascii wide
        $svc_cs = "CSFalconService" ascii wide
        $svc_s1 = "SentinelAgent" ascii wide
        $svc_cb = "CbDefense" ascii wide
        $svc_cylance = "CylanceSvc" ascii wide
        $svc_cortex = "CortexXDR" ascii wide
        $svc_sophos = "SAVService" ascii wide
        $svc_eset = "ekrn" ascii wide
        $svc_trend = "Ntrtscan" ascii wide
        $svc_elastic = "elastic-endpoint" ascii wide
        $svc_sep = "SepMasterService" ascii wide

        // Startup type modification
        $disable = "start= disabled" ascii nocase
        $disable2 = "start=disabled" ascii nocase

    condition:
        filesize < 10MB and
        (
            // Script or binary with sc.exe commands + multiple vendor services
            any of ($sc_config, $sc_stop, $sc_delete, $sc_config2, $sc_stop2) and
            5 of ($svc_*)
        )
        or
        (
            // Binary containing 8+ EDR service names (enumeration tool)
            8 of ($svc_*) and
            any of ($disable, $disable2)
        )
}

/*
    ============================================================
    RULE 8: Windows Event Log Clearing Script
    Confidence: High
    Description: Detects scripts or binaries that invoke wevtutil
                 to clear multiple event log channels -- a common
                 anti-forensics technique across many APT groups.
    ============================================================
*/
rule EventLog_Clearing_Script {
    meta:
        description = "Detects scripts clearing multiple Windows Event Log channels via wevtutil"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "7d39b861-644d-4f8b-bb19-4faae527a130"
        mitre_attack = "T1070.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1070/001/"

    strings:
        // wevtutil clear log command
        $wevtutil_cl = "wevtutil cl" ascii nocase
        $wevtutil_clear = "wevtutil.exe cl" ascii nocase

        // Alternative PowerShell log clearing
        $ps_clear1 = "Clear-EventLog" ascii nocase
        $ps_clear2 = "Remove-EventLog" ascii nocase
        $ps_wevtapi = "wevtapi" ascii nocase

        // Targeted log channels
        $log_security = "Security" ascii
        $log_system = "System" ascii
        $log_app = "Application" ascii
        $log_ps = "PowerShell" ascii
        $log_ps_op = "Microsoft-Windows-PowerShell" ascii

    condition:
        filesize < 5MB and
        (
            // wevtutil clearing multiple log channels
            ($wevtutil_cl or $wevtutil_clear) and
            3 of ($log_security, $log_system, $log_app, $log_ps, $log_ps_op)
        )
        or
        (
            // PowerShell clearing multiple log channels
            any of ($ps_clear1, $ps_clear2) and
            2 of ($log_security, $log_system, $log_app)
        )
}
