/*
    ============================================================
    YARA Rules: Security Service Stop / Impair Defenses
    Test ID: d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10
    MITRE ATT&CK: T1489, T1562.001
    Tactics: Impact, Defense Evasion
    Platform: Windows
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-03-14
    ============================================================
    DETECTION PHILOSOPHY:
    All rules below target the attack technique behaviors — the
    Windows service control API patterns, shell command sequences,
    and offensive-tool characteristics that ANY attacker using
    these techniques would produce. No F0RT1KA framework artifacts
    are included.
    ============================================================
*/


/*
    ============================================================
    Rule 1: Ransomware-Style Bulk Service Kill Script
    Confidence: High
    MITRE ATT&CK: T1489
    Description: Detects batch scripts or executables containing
    multiple service stop commands targeting security services —
    a characteristic pattern in ransomware pre-encryption scripts
    used by LockBit, Conti, REvil, and BlackCat.
    ============================================================
*/
rule ServiceStopBatchKillScript
{
    meta:
        description = "Detects scripts or binaries with bulk service stop commands targeting security and backup services"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10"
        mitre_attack = "T1489"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1489/"
        threat_actors = "LockBit, Conti, REvil, BlackCat/ALPHV"

    strings:
        // Service stop command patterns targeting security services
        $sc_stop_windefend   = "sc stop WinDefend" ascii wide nocase
        $sc_stop_wscsvc      = "sc stop wscsvc" ascii wide nocase
        $sc_stop_vss         = "sc stop VSS" ascii wide nocase
        $sc_stop_wbengine    = "sc stop wbengine" ascii wide nocase
        $sc_stop_msmpsvc     = "sc stop MsMpSvc" ascii wide nocase
        $sc_stop_sense       = "sc stop Sense" ascii wide nocase
        $sc_stop_mssec       = "sc stop SecurityHealthService" ascii wide nocase

        // net stop variants
        $net_stop_windefend  = "net stop WinDefend" ascii wide nocase
        $net_stop_vss        = "net stop VSS" ascii wide nocase
        $net_stop_wbengine   = "net stop wbengine" ascii wide nocase

        // sc config disable variants
        $sc_disable_1        = "sc config" ascii wide nocase
        $sc_disable_2        = "start= disabled" ascii wide nocase

        // VSS deletion (typically paired with service stop in ransomware)
        $vss_delete          = "vssadmin delete shadows" ascii wide nocase
        $vss_delete_wmic     = "shadowcopy delete" ascii wide nocase

    condition:
        (
            // Batch/script files with multiple service stop hits
            (uint8(0) == 0x40 or uint8(0) == 0x0D or uint8(0) == 0x0A) and
            filesize < 1MB and
            (
                (3 of ($sc_stop_*)) or
                (2 of ($sc_stop_*) and 1 of ($net_stop_*)) or
                ($vss_delete and 2 of ($sc_stop_*)) or
                ($vss_delete_wmic and 1 of ($sc_stop_*))
            )
        ) or
        (
            // PE with embedded service kill strings
            uint16(0) == 0x5A4D and
            filesize < 30MB and
            (
                (4 of ($sc_stop_*)) or
                (3 of ($sc_stop_*) and 1 of ($net_stop_*)) or
                ($vss_delete and 3 of ($sc_stop_*))
            )
        )
}


/*
    ============================================================
    Rule 2: Service Disable via Registry Modification Payload
    Confidence: Medium
    MITRE ATT&CK: T1562.001
    Description: Detects executables containing registry paths
    and values used to disable Windows security services by
    setting their Start type to 4 (disabled). Used by malware
    that modifies HKLM\SYSTEM\CurrentControlSet\Services directly.
    ============================================================
*/
rule SecurityServiceRegistryDisable
{
    meta:
        description = "Detects binaries modifying service Start registry values to disable security services"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10"
        mitre_attack = "T1562.001"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1562/001/"

    strings:
        // Registry path components for Windows services
        $reg_services_path   = "SYSTEM\\CurrentControlSet\\Services\\" ascii wide nocase
        $reg_start_val       = "Start" ascii wide

        // Security service registry names
        $svc_windefend       = "WinDefend" ascii wide
        $svc_wscsvc          = "wscsvc" ascii wide
        $svc_sense           = "Sense" ascii wide
        $svc_msmpsvc         = "MsMpSvc" ascii wide
        $svc_wbengine        = "wbengine" ascii wide

        // Start=4 (disabled) as DWORD — 04 00 00 00 in little-endian
        $start_disabled_le   = { 04 00 00 00 }

        // RegSetValueEx / NtSetValueKey API strings
        $api_regset1         = "RegSetValueEx" ascii wide
        $api_regset2         = "NtSetValueKey" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        $reg_services_path and
        $reg_start_val and
        (1 of ($svc_*)) and
        ($start_disabled_le or 1 of ($api_regset*))
}


/*
    ============================================================
    Rule 3: NetExec / CrackMapExec Service Enumeration Binary
    Confidence: High
    MITRE ATT&CK: T1489, T1021.002
    Description: Detects the NetExec (nxc) / CrackMapExec (cme)
    offensive tooling used for SMB-based remote service
    enumeration. Targets characteristic strings embedded in
    these tools that are inherent to their design, not any
    specific test framework.
    ============================================================
*/
rule NetExecServiceEnumeration
{
    meta:
        description = "Detects NetExec (nxc) or CrackMapExec binaries used for remote SMB service enumeration"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10"
        mitre_attack = "T1489,T1021.002"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1021/002/"
        note = "Detecting the tool itself; any use is suspicious outside authorized red team activity"

    strings:
        // NetExec-specific strings (inherent to the tool)
        $nxc_banner1         = "NetExec" ascii wide
        $nxc_banner2         = "Pennyw0rth" ascii wide
        $nxc_smb_module      = "nxc.protocols.smb" ascii wide
        $nxc_service_flag    = "--services" ascii wide
        $nxc_service_module  = "nxc.modules.winscp" ascii wide

        // CrackMapExec strings (predecessor, same capability)
        $cme_banner1         = "CrackMapExec" ascii wide
        $cme_banner2         = "byt3bl33d3r" ascii wide
        $cme_smb_services    = "cme.protocols.smb.services" ascii wide

        // SMB service enumeration API strings present in both tools
        $smb_svcctl          = "svcctl" ascii wide
        $smb_opensc          = "OpenSCManager" ascii wide
        $smb_enumsvc         = "EnumServicesStatus" ascii wide

        // Python frozen executable marker (both tools use PyInstaller)
        $pyinstaller_magic   = "PyInstaller" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100MB and
        (
            (1 of ($nxc_*) and $smb_svcctl) or
            (1 of ($cme_*) and $smb_svcctl) or
            (1 of ($nxc_banner*) and 1 of ($cme_banner*)) or
            ($nxc_service_flag and $smb_opensc and $smb_enumsvc)
        )
}


/*
    ============================================================
    Rule 4: In-Memory Service Control API Usage Pattern
    Confidence: Medium
    MITRE ATT&CK: T1489, T1562.001
    Description: Detects executables that import the Windows
    Service Control Manager API functions used to enumerate,
    stop, and delete services — specifically the combination
    of OpenSCManager, EnumServicesStatus, ControlService,
    and DeleteService in a single binary. This combination
    is characteristic of service-tampering malware.
    ============================================================
*/
rule ServiceControlManagerAPIAbuse
{
    meta:
        description = "Detects binaries importing SCM API functions characteristic of service stop/delete malware"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10"
        mitre_attack = "T1489,T1562.001"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1489/"
        false_positives = "Service management utilities, deployment tools, monitoring agents"

    strings:
        // Core SCM API imports
        $api_openscm         = "OpenSCManagerW" ascii wide
        $api_openscm_a       = "OpenSCManagerA" ascii
        $api_openservice     = "OpenServiceW" ascii wide
        $api_controlservice  = "ControlService" ascii wide
        $api_deleteservice   = "DeleteService" ascii wide
        $api_enumservices    = "EnumServicesStatusExW" ascii wide
        $api_changeconfig    = "ChangeServiceConfigW" ascii wide

        // Service stop control code as immediate value in code (0x00000001 = SERVICE_CONTROL_STOP)
        $stop_ctrl_code      = { 01 00 00 00 }

        // Advapi32.dll import (hosts all SCM APIs)
        $advapi32            = "advapi32.dll" ascii wide nocase

        // Security service names as embedded targets
        $target_windefend    = "WinDefend" ascii wide
        $target_wscsvc       = "wscsvc" ascii wide
        $target_vss          = { 56 00 53 00 53 00 00 00 }  // VSS in UTF-16LE
        $target_wbengine     = "wbengine" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        $advapi32 and
        $api_openscm and
        (
            ($api_controlservice and $api_deleteservice and 1 of ($target_*)) or
            ($api_enumservices and $api_controlservice and 2 of ($target_*)) or
            ($api_changeconfig and $api_controlservice and 2 of ($target_*))
        )
}


/*
    ============================================================
    Rule 5: PowerShell Service Disable Command Patterns
    Confidence: High
    MITRE ATT&CK: T1562.001, T1489
    Description: Detects PowerShell scripts or encoded commands
    that disable or stop Windows security services using
    Set-Service, Stop-Service, or Set-MpPreference (Windows
    Defender tamper via PowerShell). These are common
    living-off-the-land defense evasion techniques.
    ============================================================
*/
rule PowerShellServiceTampering
{
    meta:
        description = "Detects PowerShell scripts disabling or stopping security services via cmdlets"
        author = "F0RT1KA"
        date = "2026-03-14"
        test_id = "d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10"
        mitre_attack = "T1562.001,T1489"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1562/001/"

    strings:
        // Stop-Service targeting security services
        $ps_stop_defender    = "Stop-Service -Name WinDefend" ascii wide nocase
        $ps_stop_wscsvc      = "Stop-Service -Name wscsvc" ascii wide nocase
        $ps_stop_vss         = "Stop-Service -Name VSS" ascii wide nocase
        $ps_stop_wbengine    = "Stop-Service -Name wbengine" ascii wide nocase
        $ps_stop_generic     = "Stop-Service" ascii wide nocase

        // Set-Service disabled startup
        $ps_setservice_dis   = "Set-Service.*StartupType.*Disabled" ascii wide nocase
        $ps_setservice_dis2  = "StartupType = 'Disabled'" ascii wide nocase

        // Windows Defender specific tampering
        $ps_defender_dis1    = "Set-MpPreference -DisableRealtimeMonitoring $true" ascii wide nocase
        $ps_defender_dis2    = "Set-MpPreference -DisableRealtimeMonitoring 1" ascii wide nocase
        $ps_defender_dis3    = "Set-MpPreference -DisableIOAVProtection" ascii wide nocase
        $ps_defender_remove  = "Remove-MpPreference" ascii wide nocase
        $ps_defender_tamper  = "Set-MpPreference.*-DisableTamperProtection" ascii wide nocase

        // Security service names in PS context
        $svc_security1       = "WinDefend" ascii wide nocase
        $svc_security2       = "SecurityHealthService" ascii wide nocase
        $svc_security3       = "MsMpSvc" ascii wide nocase

        // Base64-encoded versions of common PS disable strings
        // "Stop-Service" Base64 encoded fragment in UTF-16LE
        $enc_stop_service    = "UwB0AG8AcAAtAFMAZQByAHYAaQBjAGUA" ascii

    condition:
        filesize < 5MB and
        (
            // Plain-text PS scripts
            (
                (uint8(0) == 0x23 or uint8(0) == 0x24 or uint8(0) == 0x5B) and  // PS script markers
                (
                    1 of ($ps_stop_defender, $ps_stop_wscsvc, $ps_stop_vss, $ps_stop_wbengine) or
                    (1 of ($ps_defender_dis*)) or
                    ($ps_setservice_dis and 1 of ($svc_security*))
                )
            ) or
            // PE with embedded PS commands
            (
                uint16(0) == 0x5A4D and
                (
                    (2 of ($ps_stop_*) and 1 of ($svc_security*)) or
                    (1 of ($ps_defender_dis*)) or
                    $enc_stop_service
                )
            )
        )
}
