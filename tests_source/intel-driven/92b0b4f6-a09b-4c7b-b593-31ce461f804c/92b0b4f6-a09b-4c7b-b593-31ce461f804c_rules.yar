/*
    ============================================================
    YARA Rules: APT42 TAMECAT Fileless Backdoor with Browser Credential Theft
    Test ID: 92b0b4f6-a09b-4c7b-b593-31ce461f804c
    MITRE ATT&CK: T1204.002, T1059.005, T1059.001, T1547.001, T1037.001, T1555.003, T1102
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    Version: 1.0.0
    ============================================================

    These rules detect technique-specific artifacts and behavioral patterns
    associated with APT42 TAMECAT attack chain. Rules target the underlying
    attack technique, NOT testing framework artifacts.
    ============================================================
*/


rule APT42_TAMECAT_LNK_Malicious_Shortcut {
    meta:
        description = "Detects malicious LNK shortcut files targeting cscript.exe or wscript.exe with VBScript arguments, a common APT42 delivery mechanism"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
        mitre_attack = "T1204.002"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1204/002/"

    strings:
        // MS-SHLLINK header CLSID {00021401-0000-0000-C000-000000000046}
        $lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        // Target paths -- the actual technique indicators
        $target_cscript = "cscript.exe" ascii wide nocase
        $target_wscript = "wscript.exe" ascii wide nocase
        $target_mshta = "mshta.exe" ascii wide nocase
        // VBScript file extensions in arguments
        $arg_vbs = ".vbs" ascii wide nocase
        $arg_vbe = ".vbe" ascii wide nocase
        $arg_wsf = ".wsf" ascii wide nocase
        // Suspicious argument patterns
        $arg_nologo = "//Nologo" ascii wide nocase
        $arg_b_flag = "//B" ascii wide nocase

    condition:
        uint32(0) == 0x0000004C and  // LNK header magic
        $lnk_clsid and
        (($target_cscript or $target_wscript or $target_mshta) and
         ($arg_vbs or $arg_vbe or $arg_wsf or $arg_nologo or $arg_b_flag))
}


rule APT42_TAMECAT_VBScript_WMI_AV_Enumeration {
    meta:
        description = "Detects VBScript files performing WMI AV product enumeration via SecurityCenter2 or Defender WMI namespace, matching APT42 TAMECAT reconnaissance behavior"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
        mitre_attack = "T1059.005"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1059/005/"

    strings:
        // WMI connection to SecurityCenter2
        $wmi_sc2 = "root\\SecurityCenter2" ascii wide nocase
        $wmi_sc2b = "root/SecurityCenter2" ascii wide nocase
        // WMI query for AV products
        $wmi_av_query = "AntiVirusProduct" ascii wide nocase
        // Defender-specific WMI namespace
        $wmi_defender = "root\\Microsoft\\Windows\\Defender" ascii wide nocase
        $wmi_defender2 = "root/Microsoft/Windows/Defender" ascii wide nocase
        // Defender status query
        $wmi_mpstatus = "MSFT_MpComputerStatus" ascii wide nocase
        // VBScript WMI connection pattern
        $vbs_getobject = "GetObject" ascii wide nocase
        $vbs_winmgmts = "winmgmts:" ascii wide nocase
        // System enumeration
        $wmi_computersystem = "Win32_ComputerSystem" ascii wide nocase
        $wmi_os = "Win32_OperatingSystem" ascii wide nocase

    condition:
        filesize < 100KB and
        $vbs_getobject and $vbs_winmgmts and
        (
            ($wmi_sc2 or $wmi_sc2b) and $wmi_av_query or
            ($wmi_defender or $wmi_defender2) and $wmi_mpstatus or
            (($wmi_sc2 or $wmi_sc2b) and ($wmi_computersystem or $wmi_os))
        )
}


rule APT42_TAMECAT_PowerShell_Encoded_Loader {
    meta:
        description = "Detects PowerShell scripts with TAMECAT-style environment fingerprinting patterns: AMSI detection, Defender process enumeration, beacon marker creation, and integrity level checks"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
        mitre_attack = "T1059.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        // AMSI detection check patterns
        $amsi_check1 = "GetAssemblies" ascii wide nocase
        $amsi_check2 = "amsi" ascii wide nocase
        // Defender process enumeration
        $def_proc1 = "MsMpEng" ascii wide nocase
        $def_proc2 = "MsSense" ascii wide nocase
        $def_proc3 = "SenseIR" ascii wide nocase
        $def_proc4 = "SenseCncProxy" ascii wide nocase
        // Integrity level check
        $integrity1 = "WindowsPrincipal" ascii wide nocase
        $integrity2 = "WindowsIdentity" ascii wide nocase
        $integrity3 = "IsInRole" ascii wide nocase
        // Beacon/C2 marker behavior
        $beacon1 = "beacon" ascii wide nocase
        $beacon2 = "ConvertTo-Json" ascii wide nocase
        // Environment fingerprinting
        $env_comp = "COMPUTERNAME" ascii wide nocase
        $env_user = "USERNAME" ascii wide nocase
        $env_domain = "USERDOMAIN" ascii wide nocase
        // Network enumeration
        $net_enum = "Get-NetIPAddress" ascii wide nocase

    condition:
        filesize < 500KB and
        (
            // AMSI evasion check + Defender enumeration
            ($amsi_check1 and $amsi_check2 and any of ($def_proc*)) or
            // Full fingerprinting pattern: identity + env + beacon
            (2 of ($integrity*) and 2 of ($env_*) and any of ($beacon*)) or
            // Defender enumeration + network recon + env fingerprinting
            (2 of ($def_proc*) and $net_enum and 2 of ($env_*))
        )
}


rule APT42_Registry_Dual_Persistence_Script {
    meta:
        description = "Detects scripts or binaries containing references to both Registry Run key persistence and UserInitMprLogonScript, matching APT42 dual persistence pattern"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
        mitre_attack = "T1547.001, T1037.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1547/001/"

    strings:
        // Registry Run key persistence
        $run_key1 = "CurrentVersion\\Run" ascii wide nocase
        $run_key2 = "CurrentVersion/Run" ascii wide nocase
        // UserInitMprLogonScript persistence
        $logon_script = "UserInitMprLogonScript" ascii wide nocase
        // APT42 specific IOC - "Renovation" value name
        $renovation = "Renovation" ascii wide

    condition:
        filesize < 5MB and
        ($run_key1 or $run_key2) and
        $logon_script
}


rule APT42_Browser_Credential_Theft_Tool {
    meta:
        description = "Detects tools or scripts designed to access browser credential databases (Login Data, Cookies, Web Data) combined with DPAPI decryption capability"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
        mitre_attack = "T1555.003"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1555/003/"

    strings:
        // Browser credential database paths
        $db_chrome = "Chrome\\User Data" ascii wide nocase
        $db_edge = "Edge\\User Data" ascii wide nocase
        $db_login = "Login Data" ascii wide nocase
        $db_cookies = "\\Cookies" ascii wide
        $db_webdata = "Web Data" ascii wide nocase
        $db_localstate = "Local State" ascii wide nocase
        // DPAPI decryption
        $dpapi1 = "CryptUnprotectData" ascii wide
        $dpapi2 = "crypt32.dll" ascii wide nocase
        $dpapi3 = "DPAPI" ascii wide
        // Chrome encryption version markers
        $chrome_enc1 = { 76 31 30 }  // "v10" prefix
        $chrome_enc2 = { 76 32 30 }  // "v20" prefix
        // SQLite signatures (browser databases are SQLite)
        $sqlite = "SQLite format 3" ascii
        $sqlite_api = "sqlite3_" ascii

    condition:
        filesize < 10MB and
        (
            // Browser path + Login Data + DPAPI
            (($db_chrome or $db_edge) and $db_login and ($dpapi1 or $dpapi2)) or
            // Multiple browser databases + DPAPI
            (2 of ($db_chrome, $db_edge, $db_login, $db_cookies, $db_webdata) and ($dpapi1 or $dpapi2)) or
            // Chrome encryption prefix + DPAPI call
            (($chrome_enc1 or $chrome_enc2) and $dpapi1 and ($db_chrome or $db_edge))
        )
}


rule APT42_Telegram_C2_Communication {
    meta:
        description = "Detects binaries or scripts containing Telegram Bot API endpoint strings used for C2 communication or data exfiltration, a known APT42/Magic Hound technique"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
        mitre_attack = "T1102"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1102/"

    strings:
        // Telegram Bot API endpoints
        $tg_api1 = "api.telegram.org/bot" ascii wide nocase
        $tg_api2 = "api.telegram.org" ascii wide nocase
        // Telegram API methods commonly abused
        $tg_send = "sendMessage" ascii wide
        $tg_doc = "sendDocument" ascii wide
        $tg_photo = "sendPhoto" ascii wide
        $tg_forward = "forwardMessage" ascii wide
        $tg_getme = "getMe" ascii wide
        // Chat ID parameter
        $tg_chatid = "chat_id" ascii wide

    condition:
        filesize < 50MB and
        ($tg_api1 or $tg_api2) and
        (any of ($tg_send, $tg_doc, $tg_photo, $tg_forward, $tg_getme)) and
        not (
            // Exclude legitimate Telegram clients
            for any section in pe.sections : (section.name == ".text" and section.raw_data_size > 10MB)
        )
}


rule APT42_Runs_DLL_Data_Chunking {
    meta:
        description = "Detects the APT42 Runs.dll data chunking pattern where stolen data is split into fixed-size chunks (typically 4KB) for staged exfiltration"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
        mitre_attack = "T1555.003, T1074.001"
        confidence = "medium"
        reference = "https://attack.mitre.org/groups/G1024/"

    strings:
        // Data chunking patterns
        $chunk1 = "chunk_" ascii wide
        $chunk2 = "chunk" ascii wide
        // Staging directory patterns
        $staging1 = "staging" ascii wide nocase
        $staging2 = "upload" ascii wide nocase
        // Credential-related strings
        $cred1 = "Login Data" ascii wide nocase
        $cred2 = "credential" ascii wide nocase
        $cred3 = "password" ascii wide nocase
        // Exfiltration indicators
        $exfil1 = "exfil" ascii wide nocase
        $exfil2 = "upload" ascii wide nocase

    condition:
        filesize < 10MB and
        uint16(0) == 0x5A4D and  // PE file
        ($chunk1 or $chunk2) and
        any of ($cred*) and
        any of ($staging*, $exfil*)
}


rule APT42_TAMECAT_Composite_Killchain {
    meta:
        description = "Composite rule detecting APT42 TAMECAT full kill chain: combines LNK delivery, VBScript WMI enumeration, PowerShell execution, persistence mechanisms, credential theft, and Telegram C2 indicators in a single binary or script"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
        mitre_attack = "T1204.002, T1059.001, T1547.001, T1555.003, T1102"
        confidence = "critical"

    strings:
        // Stage 1: LNK/VBScript indicators
        $s1_vbs = "SecurityCenter2" ascii wide nocase
        $s1_wmi = "AntiVirusProduct" ascii wide nocase
        // Stage 2: PowerShell patterns
        $s2_enc = "EncodedCommand" ascii wide nocase
        $s2_conhost = "conhost" ascii wide nocase
        // Stage 3: Persistence
        $s3_runkey = "CurrentVersion\\Run" ascii wide nocase
        $s3_logon = "UserInitMprLogonScript" ascii wide nocase
        // Stage 4: Credential theft
        $s4_logindata = "Login Data" ascii wide nocase
        $s4_dpapi = "CryptUnprotectData" ascii wide
        // Stage 5: C2/exfiltration
        $s5_telegram = "api.telegram.org" ascii wide nocase
        $s5_sendmsg = "sendMessage" ascii wide

    condition:
        filesize < 50MB and
        (
            // Any 3 stages present = high confidence
            (any of ($s1_*) and any of ($s2_*) and any of ($s3_*)) or
            (any of ($s2_*) and any of ($s3_*) and any of ($s4_*)) or
            (any of ($s3_*) and any of ($s4_*) and any of ($s5_*)) or
            (any of ($s1_*) and any of ($s4_*) and any of ($s5_*)) or
            // All 5 stages present = critical confidence
            (any of ($s1_*) and any of ($s2_*) and any of ($s3_*) and any of ($s4_*) and any of ($s5_*))
        )
}
