/*
    ============================================================
    YARA Rules: AMOS/Banshee macOS Infostealer Detection
    Test ID: 3e985e9e-8141-49d3-a23c-6c7f5e3282f5
    MITRE ATT&CK: T1059.002, T1555.001, T1056.002, T1005, T1560.001, T1041, T1027
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    ============================================================

    These rules detect behavioral artifacts of AMOS (Atomic Stealer),
    Banshee Stealer, and Cuckoo Stealer macOS infostealers.
    All detections target technique-level indicators, not test framework artifacts.
    ============================================================
*/

rule AMOS_Banshee_OsascriptPhishing_MacOS {
    meta:
        description = "Detects AppleScript credential phishing patterns used by AMOS, Banshee, and Cuckoo macOS stealers including fake system dialogs with hidden answer fields"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
        mitre_attack = "T1059.002, T1056.002"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1059/002/"

    strings:
        $dialog1 = "display dialog" ascii nocase
        $dialog2 = "display alert" ascii nocase
        $hidden = "hidden answer" ascii nocase
        $default_answer = "default answer" ascii nocase
        $pw1 = "password" ascii nocase
        $pw2 = "Password" ascii
        $pw3 = "Enter your password" ascii nocase
        $sys1 = "System Preferences" ascii
        $sys2 = "macOS wants" ascii
        $sys3 = "System Settings" ascii
        $icon_path = "/System/Library/PreferencePanes/" ascii
        $dscl_auth = "dscl" ascii
        $authonly = "-authonly" ascii
        $retry = "repeat while" ascii

    condition:
        filesize < 50KB and
        (($dialog1 or $dialog2) and ($hidden or $default_answer)) and
        (any of ($pw*) or any of ($sys*)) and
        (($dscl_auth and $authonly) or $icon_path or $retry)
}

rule AMOS_Banshee_DsclValidation_MacOS {
    meta:
        description = "Detects binaries containing dscl credential validation strings used by macOS stealers to verify phished passwords before keychain extraction"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
        mitre_attack = "T1059.002"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1059/002/"

    strings:
        $dscl = "dscl" ascii
        $local_default = "/Local/Default" ascii
        $authonly = "-authonly" ascii
        $list_users = "-list /Users" ascii
        $whoami = "whoami" ascii
        $shell_script = "do shell script" ascii

    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
         uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xBEBAFECA) and  // Mach-O or Universal binary
        filesize < 50MB and
        $dscl and $authonly and
        ($local_default or $list_users) and
        ($whoami or $shell_script)
}

rule AMOS_Banshee_KeychainTheft_MacOS {
    meta:
        description = "Detects Mach-O binaries containing Keychain credential extraction strings including Chainbreaker patterns and Chrome Safe Storage key theft"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
        mitre_attack = "T1555.001"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1555/001/"

    strings:
        $sec1 = "security" ascii
        $sec2 = "list-keychains" ascii
        $sec3 = "find-generic-password" ascii
        $sec4 = "find-internet-password" ascii
        $sec5 = "dump-keychain" ascii
        $chrome_safe = "Chrome Safe Storage" ascii
        $login_keychain = "login.keychain-db" ascii
        $system_keychain = "System.keychain" ascii
        $icloud_keychain = "iCloud.keychain" ascii
        $chainbreaker = "chainbreaker" ascii nocase
        $keychain_path = "Library/Keychains" ascii

    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
         uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xBEBAFECA) and
        filesize < 50MB and
        (
            ($sec1 and 2 of ($sec2, $sec3, $sec4, $sec5)) or
            ($chrome_safe and ($sec1 or $chainbreaker)) or
            ($chainbreaker and any of ($login_keychain, $system_keychain, $icloud_keychain)) or
            (3 of ($login_keychain, $system_keychain, $icloud_keychain, $keychain_path))
        )
}

rule AMOS_Banshee_MultiBrowserTheft_MacOS {
    meta:
        description = "Detects Mach-O binaries targeting multiple browser credential databases on macOS, characteristic of AMOS/Banshee stealer families"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
        mitre_attack = "T1005"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1005/"

    strings:
        $chrome = "Google/Chrome/Default/Login Data" ascii
        $chrome_cookies = "Google/Chrome/Default/Cookies" ascii
        $firefox = "Firefox/Profiles" ascii
        $firefox_key = "key4.db" ascii
        $safari = "Cookies.binarycookies" ascii
        $brave = "BraveSoftware/Brave-Browser" ascii
        $edge = "Microsoft Edge/Default/Login Data" ascii
        $opera = "com.operasoftware.Opera" ascii
        $vivaldi = "Vivaldi/Default/Login Data" ascii
        $chromium = "Chromium/Default/Login Data" ascii
        $arc = "Arc/User Data/Default" ascii
        $login_data = "Login Data" ascii
        $notestore = "NoteStore.sqlite" ascii
        $apple_notes = "group.com.apple.notes" ascii

    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
         uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xBEBAFECA) and
        filesize < 50MB and
        (
            4 of ($chrome, $firefox, $safari, $brave, $edge, $opera, $vivaldi, $chromium, $arc) or
            (3 of ($chrome, $firefox, $safari, $brave, $edge) and $login_data) or
            (2 of ($chrome, $firefox, $safari) and ($notestore or $apple_notes))
        )
}

rule AMOS_Banshee_CryptoWalletTheft_MacOS {
    meta:
        description = "Detects Mach-O binaries targeting multiple cryptocurrency wallet extension directories and application data, a signature pattern of AMOS/Banshee stealers"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
        mitre_attack = "T1005"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1005/"

    strings:
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii   // MetaMask extension ID
        $coinbase = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii   // Coinbase Wallet extension ID
        $phantom = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii    // Phantom extension ID
        $trust = "egjidjbpglichdcondbcbdnbeeppgdph" ascii      // Trust Wallet extension ID
        $exodus = "exodus.wallet" ascii
        $atomic = "atomic/Local Storage" ascii
        $electrum = ".electrum/wallets" ascii
        $bitwarden = "Bitwarden/data.json" ascii
        $wallet_generic1 = "Local Extension Settings" ascii
        $wallet_generic2 = "leveldb" ascii

    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
         uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xBEBAFECA) and
        filesize < 50MB and
        (
            3 of ($metamask, $coinbase, $phantom, $trust, $exodus, $atomic, $electrum, $bitwarden) or
            (2 of ($metamask, $coinbase, $phantom, $trust) and $wallet_generic1)
        )
}

rule AMOS_Banshee_XORObfuscation_MacOS {
    meta:
        description = "Detects Banshee Stealer XProtect-style XOR string obfuscation patterns used to evade AV signature detection for 2+ months"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
        mitre_attack = "T1027"
        confidence = "medium"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1027/"

    strings:
        // XOR decryption loop patterns in Mach-O
        $xor_loop1 = { 30 ?? 88 }         // xor reg, [mem]; mov [mem], reg
        $xor_loop2 = { 80 3? ?? 74 }      // cmp byte [reg], imm; jz
        // XProtect-related strings (would be present if partially decrypted)
        $xprotect1 = "XProtect" ascii nocase
        $xprotect2 = "xprotect" ascii
        // Common decryption key patterns
        $key_pattern = { [4-8] 00 [4-8] 00 [4-8] 00 [4-8] 00 }
        // Anti-analysis strings that remain unencrypted
        $anti1 = "VMware" ascii
        $anti2 = "VirtualBox" ascii
        $anti3 = "Parallels" ascii
        // Stealer behavior strings
        $tcc = "tccutil" ascii
        $osascript = "osascript" ascii

    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
         uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xBEBAFECA) and
        filesize < 50MB and
        (
            (any of ($xprotect*) and ($tcc or $osascript)) or
            (2 of ($anti1, $anti2, $anti3) and ($tcc or $osascript)) or
            (#xor_loop1 > 5 and ($tcc or $osascript))
        )
}

rule AMOS_Banshee_ExfilPayload_MacOS {
    meta:
        description = "Detects AMOS stealer exfiltration archive and staging artifacts containing stolen credential data bundles"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
        mitre_attack = "T1560.001, T1041"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1560/001/"

    strings:
        $zip_magic = { 50 4B 03 04 }   // ZIP magic bytes
        $hwid = "hwid" ascii
        $wid = "wid" ascii
        $sendlog = "sendlog" ascii
        $multipart = "multipart/form-data" ascii
        $out_zip = "out.zip" ascii
        $login_data = "Login Data" ascii
        $keychain = "keychain" ascii nocase
        $wallet = "wallet" ascii nocase

    condition:
        $zip_magic at 0 and
        filesize < 100MB and
        (
            (2 of ($hwid, $wid, $sendlog)) or
            ($multipart and ($out_zip or $hwid)) or
            ($login_data and $keychain and $wallet)
        )
}

rule AMOS_Banshee_CombinedIndicators_MacOS {
    meta:
        description = "Comprehensive detection for macOS infostealer binaries combining credential phishing, keychain access, browser theft, and exfiltration indicators in a single binary"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
        mitre_attack = "T1059.002, T1555.001, T1056.002, T1005, T1560.001, T1041, T1027"
        confidence = "critical"
        severity = "critical"

    strings:
        // Phase 1: Credential phishing
        $phish1 = "display dialog" ascii
        $phish2 = "hidden answer" ascii
        // Phase 2: Credential validation
        $dscl = "dscl" ascii
        $authonly = "-authonly" ascii
        // Phase 3: Keychain access
        $keychain1 = "list-keychains" ascii
        $keychain2 = "find-generic-password" ascii
        $keychain3 = "Chrome Safe Storage" ascii
        // Phase 4: Browser theft
        $browser1 = "Login Data" ascii
        $browser2 = "Cookies.binarycookies" ascii
        $browser3 = "key4.db" ascii
        // Phase 5: Crypto wallets
        $wallet1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii  // MetaMask
        $wallet2 = "exodus.wallet" ascii
        // Phase 6: TCC manipulation
        $tcc = "tccutil" ascii
        // Phase 8: Exfiltration
        $exfil1 = "hwid" ascii
        $exfil2 = "sendlog" ascii
        $exfil3 = "out.zip" ascii

    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
         uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xBEBAFECA) and
        filesize < 50MB and
        // Must match indicators from at least 3 attack phases
        (
            (1 of ($phish*) and 1 of ($keychain*) and 1 of ($browser*)) or
            (1 of ($keychain*) and 1 of ($browser*) and 1 of ($wallet*)) or
            ($dscl and $authonly and 1 of ($keychain*) and 1 of ($browser*)) or
            (1 of ($browser*) and 1 of ($wallet*) and 1 of ($exfil*)) or
            ($tcc and 1 of ($keychain*) and 1 of ($exfil*))
        )
}

rule Cuckoo_Stealer_HiddenDirectory_MacOS {
    meta:
        description = "Detects Cuckoo Stealer credential caching pattern using .local-UUID hidden directories with pw.dat password files"
        author = "F0RT1KA"
        date = "2026-03-13"
        test_id = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
        mitre_attack = "T1059.002"
        confidence = "high"
        severity = "critical"
        reference = "https://www.kandji.io/"

    strings:
        $local_prefix = ".local-" ascii
        $pw_dat = "pw.dat" ascii
        $credentials_cache = ".credentials_cache" ascii
        $dscl = "dscl" ascii
        $osascript = "osascript" ascii

    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
         uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xBEBAFECA) and
        filesize < 50MB and
        (
            ($local_prefix and $pw_dat) or
            ($credentials_cache and ($dscl or $osascript)) or
            ($pw_dat and $osascript and $dscl)
        )
}
