/*
    ============================================================
    YARA Rules: KslKatz BYOVD LSASS Credential Dumping Framework
    Test ID: 7ba6c119-df44-4cda-8045-b3700c31ba5e
    MITRE ATT&CK: T1543.003, T1112, T1068, T1003.001
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-06-01
    Source: https://detect.fyi/ghost-in-lsass-detecting-kslkatz-credential-dumping-framework-8645f246aec9
    ============================================================
    Scope:
      These rules target the underlying attack technique artifacts and tool
      characteristics of the kslkatz framework, NOT the F0RT1KA test scaffolding.
      Rules are designed to catch a real-world operator using kslkatz or any tool
      that replicates the same BYOVD TTP against the KslD Defender kernel driver.

    Notes on kslkatz PPL bypass:
      kslkatz reads LSASS memory from kernel mode via KslD.sys MmCopyMemory,
      bypassing LSA Protection (PPL) because the read originates in ring 0.
      User-mode YARA memory scanning of lsass.exe will NOT catch the actual
      credential read. The highest-value YARA signals are on the loader binary,
      the embedded KslD.sys driver, and the script/config artifacts.
    ============================================================
*/

import "pe"
import "hash"

// ============================================================
// Rule 1: KslKatz Loader Binary — String Indicators
// ============================================================
// Detects the kslkatz loader/orchestrator based on embedded string artifacts
// characteristic of the framework: the KslD device path, the AllowedProcessName
// value name, and GhostKatz/KslDump strings. Any tool implementing this BYOVD
// TTP against the KslD service will reference these identifiers.
// Confidence: HIGH
// ============================================================
rule KslKatz_Loader_Strings
{
    meta:
        description = "Detects kslkatz loader or any tool targeting KslD BYOVD via characteristic string artifacts"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-06-01"
        test_id = "7ba6c119-df44-4cda-8045-b3700c31ba5e"
        mitre_attack = "T1068, T1003.001, T1543.003"
        confidence = "high"
        reference = "https://detect.fyi/ghost-in-lsass-detecting-kslkatz-credential-dumping-framework-8645f246aec9"

    strings:
        // Core KslD device path — kslkatz must open this kernel device object.
        $device_path_a = "\\\\.\\KslD" ascii wide
        $device_path_b = "\\Device\\KslD" ascii wide

        // AllowedProcessName value name — the primary registry manipulation signal.
        $allowed_proc_name = "AllowedProcessName" ascii wide

        // KslDump/GhostKatz tool identification strings.
        $ksldump = "KslDump" ascii wide nocase
        $ghostkatz = "GhostKatz" ascii wide nocase
        $kslkatz = "KslKatz" ascii wide nocase

        // KslD service registry path — attacker must reference this to configure the service.
        $service_key_a = "Services\\KslD" ascii wide nocase
        $service_key_b = "CurrentControlSet\\Services\\KslD" ascii wide nocase

        // MmCopyMemory reference — the kernel API used for the PPL bypass read.
        $mmcopy = "MmCopyMemory" ascii wide

        // ImagePath redirect: KslD.sys loaded from outside protected path.
        $imagepath_redirect_a = "System32\\drivers\\KslD.sys" ascii wide nocase
        $imagepath_redirect_b = "\\SystemRoot\\System32\\drivers\\KslD.sys" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            // Device open + trust tampering = high confidence.
            ($device_path_a or $device_path_b) and $allowed_proc_name
        ) or (
            // Tool identification string + device or service path.
            ($ksldump or $ghostkatz or $kslkatz) and
            ($device_path_a or $device_path_b or $service_key_a or $service_key_b)
        ) or (
            // Registry service config + MmCopyMemory reference = BYOVD kernel read indicator.
            ($service_key_a or $service_key_b) and $mmcopy
        )
}

// ============================================================
// Rule 2: KslD Vulnerable Driver — File Characteristics
// ============================================================
// Detects the specific vulnerable KslD.sys driver (the 333KB Microsoft-signed build
// that is the BYOVD vehicle for kslkatz). The legitimate production version resides
// in System32\drivers\wd\ and has a different SHA256 than the vulnerable build.
// This rule matches on PE characteristics common to the vulnerable variant without
// relying on path — so it fires when the driver is dropped to any location.
//
// NOTE: Maintain the SHA256 of the known-vulnerable KslD.sys against the
// Microsoft Vulnerable Driver Blocklist. The hash below is illustrative; operators
// should populate from the Blocklist or threat intelligence.
//
// Confidence: HIGH (when hash matches); MEDIUM (PE characteristics only)
// ============================================================
rule KslD_VulnerableDriver_Characteristics
{
    meta:
        description = "Detects KslD.sys dropped outside Windows driver directories — potential BYOVD vehicle"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-06-01"
        test_id = "7ba6c119-df44-4cda-8045-b3700c31ba5e"
        mitre_attack = "T1068"
        confidence = "medium"
        note = "Update sha256_vulnerable_ksld with the specific vulnerable build hash from the Microsoft Vulnerable Driver Blocklist"

    strings:
        // KslD service / device name embedded in the driver binary.
        $driver_name_a = "KslD" ascii wide
        $driver_name_b = "\\Device\\KslD" ascii wide
        $driver_name_c = "\\DosDevices\\KslD" ascii wide

        // AllowedProcessName — the trust-check value the driver reads from registry.
        $allowed_proc_value = "AllowedProcessName" ascii wide

        // MmCopyMemory: kernel API for physical memory reads, the PPL bypass mechanism.
        $mmcopy_import = "MmCopyMemory" ascii wide

        // SubCmd 12 IOCTL handler marker (if present as debug string).
        $subcmd12 = "SubCmd" ascii wide

        // Typical Defender driver version strings.
        $defender_company = "Microsoft Corporation" ascii wide
        $defender_product = "Microsoft Defender" ascii wide nocase
        $ksld_desc = "Kernel Service Log Driver" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        // Driver image (has SYS extension characteristics).
        pe.characteristics & pe.DLL == 0 and
        // File size roughly matching the known-vulnerable KslD.sys (~333KB).
        filesize >= 300KB and filesize <= 400KB and
        // Must reference its own device name or the AllowedProcessName trust check.
        ($driver_name_b or $driver_name_c or $allowed_proc_value) and
        // Signed by Microsoft (Defender-associated driver — BYOVD exploits legitimately signed drivers).
        pe.number_of_signatures > 0 and
        // References the MmCopyMemory import (kernel physical read capability).
        $mmcopy_import
}

// ============================================================
// Rule 3: Process Memory — kslkatz Runtime Indicators (In-Memory Scan)
// ============================================================
// Targets kslkatz or any derivative tool running in memory based on the combination
// of the KslD device path string (needed for CreateFile) and LSASS targeting strings.
// Useful for memory forensics or EDR memory-scanning modules.
//
// CAVEAT: kslkatz performs the actual LSASS read from kernel mode (KslD driver
// MmCopyMemory). The credential material is NOT directly readable in the kslkatz
// usermode process memory after extraction. This rule catches the loader binary
// while it is in memory BEFORE the kernel read — useful for early interception.
//
// Confidence: HIGH
// ============================================================
rule KslKatz_InMemory_Loader
{
    meta:
        description = "Detects kslkatz loader in process memory by KslD device path and LSASS targeting indicators"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-06-01"
        test_id = "7ba6c119-df44-4cda-8045-b3700c31ba5e"
        mitre_attack = "T1068, T1003.001"
        confidence = "high"
        scan_context = "process_memory"

    strings:
        // Device path kslkatz opens via CreateFile to communicate with the kernel driver.
        $ksld_device = "\\\\.\\KslD" ascii wide

        // LSASS targeting string — kslkatz locates lsass.exe via Toolhelp snapshot.
        $lsass_target = "lsass.exe" ascii wide nocase

        // AllowedProcessName write — the trust bypass that makes the driver accept the caller.
        $allowed_proc = "AllowedProcessName" ascii wide

        // Service registry path kslkatz modifies to load the BYOVD driver.
        $ksld_service = "Services\\KslD" ascii wide nocase

        // GhostKatz parsed credentials output markers (if credential parsing is in the same binary).
        $ghostkatz_marker_a = "GhostKatz" ascii wide nocase
        $ghostkatz_marker_b = "KslDump" ascii wide nocase

    condition:
        // Must see KslD device path AND at least one of: LSASS target, registry tamper, or tool ID.
        $ksld_device and
        (
            $lsass_target or
            $allowed_proc or
            $ksld_service or
            $ghostkatz_marker_a or
            $ghostkatz_marker_b
        )
}

// ============================================================
// Rule 4: PowerShell / Script — KslKatz Invocation or Configuration
// ============================================================
// Detects PowerShell scripts or batch files that drive the kslkatz service
// configuration steps: registering the KslD service, setting ImagePath, or
// writing AllowedProcessName. Operators may script the prerequisite steps.
// Confidence: MEDIUM
// ============================================================
rule KslKatz_Script_ServiceConfig
{
    meta:
        description = "Detects scripts configuring the KslD service for BYOVD exploitation (ImagePath redirect, AllowedProcessName write)"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-06-01"
        test_id = "7ba6c119-df44-4cda-8045-b3700c31ba5e"
        mitre_attack = "T1543.003, T1112"
        confidence = "medium"

    strings:
        // Service configuration via sc.exe or PowerShell New-Service/Set-ItemProperty.
        $sc_config_a = "sc config KslD" ascii wide nocase
        $sc_config_b = "sc create KslD" ascii wide nocase
        $sc_binpath = "binpath" ascii wide nocase

        // PowerShell registry writes for the service config.
        $ps_setitem_a = "Set-ItemProperty" ascii wide nocase
        $ps_newitem = "New-ItemProperty" ascii wide nocase
        $ksld_regpath = "Services\\KslD" ascii wide nocase

        // AllowedProcessName value — must reference this for the trust bypass.
        $allowed_proc = "AllowedProcessName" ascii wide

        // Device path reference in scripts.
        $device_ksld = "KslD" ascii wide nocase

        // Start-Service / sc start invocations.
        $sc_start = "sc start KslD" ascii wide nocase
        $ps_start_service = "Start-Service" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            // sc.exe commands configuring KslD.
            ($sc_config_a or $sc_config_b) or
            // PowerShell registry writes to KslD service key.
            ($ps_setitem_a or $ps_newitem) and $ksld_regpath and $allowed_proc or
            // AllowedProcessName write via any mechanism combined with KslD reference.
            $allowed_proc and $device_ksld and ($sc_start or $ps_start_service)
        )
}

// ============================================================
// Rule 5: Broad BYOVD Pattern — Non-Protected-Path Driver + Kernel Device Targeting
// ============================================================
// Generalized rule catching the BYOVD pattern of loading a kernel driver from a
// non-standard path and opening a device object with a read/write handle. Intended
// as a low-noise broader net for kslkatz-derivative or similar BYOVD tools that
// use a different driver but the same access pattern.
// Confidence: MEDIUM (false positives possible from legitimate non-standard driver installs)
// ============================================================
rule BYOVD_KernelDriver_NonStandardPath_DeviceOpen
{
    meta:
        description = "Broad BYOVD pattern: binary referencing kernel driver outside system32 paths combined with device object access"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-06-01"
        test_id = "7ba6c119-df44-4cda-8045-b3700c31ba5e"
        mitre_attack = "T1068"
        confidence = "medium"
        note = "Tune to exclude known-good driver installation tools (WinPcap, VPN clients, etc.)"

    strings:
        // Generic device object open pattern (\\.\ prefix in user-mode CreateFile).
        $device_open_a = "\\\\.\\" ascii wide
        $device_open_b = "\\Device\\" ascii wide

        // Service registry key access (for driver configuration).
        $services_key = "\\Services\\" ascii wide

        // ImagePath or AllowedProcessName manipulation.
        $imagepath = "ImagePath" ascii wide
        $allowed_proc = "AllowedProcessName" ascii wide

        // .sys file reference outside system32.
        $sys_outside_a = "\\Users\\" ascii wide
        $sys_outside_b = "\\Temp\\" ascii wide
        $sys_outside_c = "\\ProgramData\\" ascii wide
        $sys_outside_d = "\\AppData\\" ascii wide

        // MmCopyMemory — the kernel physical read API (present in drivers, not loaders;
        // but may appear as a string in loader code that resolves it dynamically).
        $mmcopy = "MmCopyMemory" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        // Must reference a device object AND a service key.
        ($device_open_a or $device_open_b) and
        $services_key and
        // Must also show either: ImagePath/AllowedProcessName manipulation OR
        // .sys drop to a user-writable directory OR MmCopyMemory reference.
        (
            ($imagepath and $allowed_proc) or
            (($sys_outside_a or $sys_outside_b or $sys_outside_c or $sys_outside_d) and $mmcopy)
        )
}
