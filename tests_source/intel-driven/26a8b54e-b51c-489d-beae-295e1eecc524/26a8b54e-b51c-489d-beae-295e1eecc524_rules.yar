/*
   ============================================================
   Lumma-Style Infostealer Kill Chain — YARA Rules
   Test: 26a8b54e-b51c-489d-beae-295e1eecc524
   Techniques: T1204.002, T1059.001, T1055.003, T1555.003, T1555,
               T1005, T1041, T1071.001
   Actor: LummaC2 / Water Kurita (S1213; Microsoft: Storm-2477)
   Generated: 2026-11-02
   Scope: content/artifact signatures for REAL Lumma-class tradecraft —
          documented C2 protocol anchors (TeslaBrowser/5.5 UA, /c2sock,
          act=live), ClickFix cradle shapes, Chromium credential-theft
          toolkit strings, Chromium ABE elevator CLSIDs, browser-injector
          API/name combos. Behavior-only legs (cross-process injection
          telemetry, file-copy-then-read of locked stores) are covered by
          the KQL/Sigma/EQL/LC-D&R companion rule sets.
   Intel: NCC Group (fake-captcha-led-to-lumma), Netskope, ESET, Darktrace,
          Microsoft TI, malpedia win.lumma,
          xaitax/Chrome-App-Bound-Encryption-Decryption
   ============================================================
*/

rule Lumma_C2_Protocol_Artifacts
{
    meta:
        description = "Detects the documented LummaC2 hardcoded User-Agent combined with C2 protocol anchors (c2sock URI, act=live handshake, LID/HWID form parameters)"
        technique = "T1041, T1071.001"
        actor = "LummaC2"
        confidence = "high"
        false_positives = "None expected — UA + protocol anchor combination is actor-specific; security researchers storing samples"
        reference = "Darktrace PCAP analysis; malpedia win.lumma; ESET Lumma teardown"

    strings:
        $ua       = "TeslaBrowser/5.5" ascii wide
        $uri1     = "/c2sock" ascii wide
        $act1     = "act=live" ascii wide
        $form1    = "lid=" ascii wide
        $form2    = "hwid=" ascii wide
        $form3    = "b=chrome" ascii wide nocase
        $upload1  = "multipart/form-data" ascii wide
        $upload2  = "archive.zip" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $ua and
        1 of ($uri1, $act1, $form1, $form2, $upload1)
}

rule Lumma_ClickFix_Cradle_Script
{
    meta:
        description = "Detects ClickFix (fake CAPTCHA) delivery scripts: hidden encoded-command PowerShell cradle shapes with download/execution primitives, or mshta remote-fetch stubs planted on the clipboard"
        technique = "T1204.002, T1059.001"
        actor = "LummaC2 / Water Kurita (ClickFix campaigns)"
        confidence = "high"
        false_positives = "Legitimate encoded deploy scripts rarely combine hidden window + WebClient/IEX in the same artifact"
        reference = "https://www.ncc-group.com — fake-CAPTCHA clipboard-to-Win+R delivery; Seqrite mshta chain"

    strings:
        $enc1     = "-EncodedCommand" ascii wide nocase
        $enc2     = " -enc " ascii wide nocase
        $hid1     = "-WindowStyle Hidden" ascii wide nocase
        $hid2     = "-w hidden" ascii wide nocase
        $hid3     = "w 1" ascii wide nocase
        $wc1      = "Net.WebClient" ascii wide
        $dl1      = "DownloadData" ascii wide
        $dl2      = "DownloadFile" ascii wide
        $iex1     = "IEX(" ascii wide
        $iex2     = "Invoke-Expression" ascii wide
        $b64      = "FromBase64String" ascii wide
        $mshta1   = "mshta http" ascii wide nocase
        $clip1    = "Set-ClipboardData" ascii wide
        $clip2    = "SetClipboardData" ascii wide

    condition:
        filesize < 256KB and
        (
            ( uint16(0) != 0x5A4D and 1 of ($enc*) and 1 of ($hid*) and 1 of ($wc1, $dl1, $dl2, $iex*, $b64) ) or
            $mshta1 or
            ( 1 of ($clip*) and 1 of ($enc*, $mshta1, $wc1) )
        )
}

rule Infostealer_Chromium_Credential_Toolkit
{
    meta:
        description = "Detects stealer binaries embedding the Chromium credential-theft chain: profile store filenames, os_crypt key material fields, CryptUnprotectData/DPAPI-APPB prefixes, KeePass/Gecko stores and crypto-wallet extension identifiers"
        technique = "T1555.003, T1555, T1005"
        actor = "Lumma / StealC / Vidar infostealer class"
        confidence = "high"
        false_positives = "Enterprise password managers, browser-backup/migration tools and DFIR collectors embed some of these strings — verify signer and context"
        reference = "https://attack.mitre.org/techniques/T1555/003/; NCC Group Lumma analysis; ESET Lumma teardown"

    strings:
        $ls       = "Local State" ascii wide
        $ld       = "Login Data" ascii wide
        $ck       = "Network\\Cookies" ascii wide
        $wd       = "Web Data" ascii wide
        $osc      = "os_crypt" ascii wide
        $enckey   = "encrypted_key" ascii wide
        $dpapi    = "DPAPI" ascii wide
        $appb     = "APPB" ascii wide
        $v10      = "v10" ascii wide
        $crypt    = "CryptUnprotectData" ascii wide
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $key4     = "key4.db" ascii wide
        $logins   = "logins.json" ascii wide
        $kdbx     = ".kdbx" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            ( 2 of ($ls, $ld, $ck, $wd, $osc, $enckey) and 1 of ($crypt, $dpapi, $appb, $v10) ) or
            ( $metamask and 1 of ($ls, $ld, $ck, $wd) ) or
            ( 2 of ($kdbx, $key4, $logins) and 1 of ($ls, $ld, $ck, $wd) )
        )
}

rule Chromium_ABE_Elevator_CLSID_Abuse
{
    meta:
        description = "Detects binaries embedding the Chromium/Edge elevation-service COM elevator GUIDs (binary little-endian + string forms) used to bypass App-Bound Encryption via IElevator::DecryptData — CLSID 708860E0 (Chrome), 1FCBE96C (Edge) and their IIDs"
        technique = "T1555.003, T1555"
        actor = "Infostealers with ABE bypass (Lumma-class; Chrome elevation-service abuse)"
        confidence = "high"
        false_positives = "Chromium/Edge source builds, legit updater tooling and security research PoCs — verify signer"
        reference = "https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption; Chromium elevation_service elevator.idl"

    strings:
        // {708860E0-F641-4611-8895-7D867DD3675B} Chrome IElevator CLSID (LE binary form)
        $bin_clsid_chrome = { E0 60 88 70 41 F6 11 46 88 95 7D 86 7D D3 67 5B }
        // {463ABECF-410D-407F-8AF5-0DF35A005CC8} Chrome IElevator IID (LE binary form)
        $bin_iid_elevator = { CF BE 3A 46 0D 41 7F 40 8A F5 0D F3 5A 00 5C C8 }
        // {1FCBE96C-1697-43AF-9140-2897C7C69767} Edge elevator CLSID (LE binary form)
        $bin_clsid_edge = { 6C E9 CB 1F 97 16 AF 43 91 40 28 97 C7 C6 97 67 }
        // {C9C2B807-7731-4F34-81B7-44FF7779522B} Edge IEdgeElevatorFinal IID (LE binary form)
        $bin_iid_edge = { 07 B8 C2 C9 31 77 34 4F 81 B7 44 FF 77 79 52 2B }
        $str_clsid_chrome = "{708860E0-F641-4611-8895-7D867DD3675B}" ascii wide nocase
        $str_clsid_edge   = "{1FCBE96C-1697-43AF-9140-2897C7C69767}" ascii wide nocase
        $elev1   = "elevation_service" ascii wide nocase
        $elev2   = "IElevator" ascii wide
        $cloak   = "CoSetProxyBlanket" ascii wide
        $decrypt = "DecryptData" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            ( 1 of ($bin_clsid_*) and 1 of ($bin_iid_*, $str_clsid_*, $elev1, $elev2, $decrypt) ) or
            ( 1 of ($str_clsid_*) and 1 of ($elev1, $elev2, $cloak, $decrypt) )
        )
}

rule Browser_Injector_Masquerade_Toolkit
{
    meta:
        description = "Detects injector binaries combining the classic remote injection API set (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread + thread-hijack context APIs) with browser/updater process-name strings used as injection hosts — the Lumma MicrosoftEdgeUpdate.exe → chrome.exe pattern"
        technique = "T1055.003"
        actor = "LummaC2 (NCC Group / Gen Digital Remus research); generic browser injectors"
        confidence = "medium"
        false_positives = "Legitimate software injectors (AV shim DLLs, app compatibility) rarely ship browser-name strings plus the full hijack API set in one binary — review signer and prevalence"
        reference = "NCC Group fake-captcha-led-to-lumma; https://attack.mitre.org/techniques/T1055/003/"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "OpenProcess" ascii wide
        $api5 = "SuspendThread" ascii wide
        $api6 = "GetThreadContext" ascii wide
        $api7 = "SetThreadContext" ascii wide
        $api8 = "OpenThread" ascii wide
        $brow1 = "chrome.exe" ascii wide nocase
        $brow2 = "msedge.exe" ascii wide nocase
        $brow3 = "MicrosoftEdgeUpdate.exe" ascii wide nocase
        $brow4 = "firefox.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        3 of ($api*) and
        1 of ($brow*)
}
