/*
    ============================================================
    3CX 3CXDesktopApp Cascading Supply-Chain Compromise — YARA Rules
    Test ID: 56475cb3-febc-45ac-a0af-39bc5ca1c15f
    MITRE ATT&CK: T1195.002, T1574.002, T1497, T1027.003, T1071.001, T1555.003
    Threat Actor: Lazarus / UNC4736 (DPRK)
    Author: F0RT1KA Security Test Builder
    ============================================================

    These rules target technique-level, real-world 3CX/Lazarus artifacts:
    ICO steganography (config appended after the icon image), the side-loaded
    companion DLL names, and browser-stealer collection targets.

    They deliberately do NOT match F0RT1KA test scaffolding (test UUID,
    "F0RT1KA", "fortika-test", or the decoy sentinel strings). Detection is
    behavioral / adversary-artifact based.

    Usage:
        yara -r 56475cb3-febc-45ac-a0af-39bc5ca1c15f_rules.yar /path/to/scan
    ============================================================
*/


/*
    ============================================================
    Rule: ICO_Steganography_Appended_Encrypted_Payload
    Confidence: Medium-High
    Description: Detects a Windows .ico that carries a substantial blob of
                 high-entropy data appended AFTER the legitimate icon image —
                 the 3CX / ICONIC steganography technique (AES config hidden
                 behind the icon). Real icons rarely have large trailing data.
    ============================================================
*/
rule ICO_Steganography_Appended_Encrypted_Payload
{
    meta:
        description = "ICO file with appended data past the declared icon image (3CX-style stego)"
        mitre = "T1027.003"
        threat_actor = "Lazarus / UNC4736"
        confidence = "medium-high"
    condition:
        // ICONDIR: reserved=0x0000, type=0x0001 (icon)
        uint16(0) == 0x0000 and uint16(2) == 0x0001 and
        // exactly/at least one image entry
        uint16(4) >= 0x0001 and
        // legitimate icon region end = imageOffset(@18) + bytesInRes(@14)
        // flag when the file is meaningfully larger than the declared image region
        filesize > (uint32(18) + uint32(14) + 512) and
        // small icons with big trailing blobs are the tell
        uint32(14) < 65536
}


/*
    ============================================================
    Rule: ThreeCX_Sideload_Companion_DLL_Names
    Confidence: Medium
    Description: Flags the specific companion DLL filenames abused in the 3CX
                 side-load chain (d3dcompiler_47.dll / ffmpeg.dll) when found as
                 non-Microsoft-signed content with an MZ header in a scan target.
                 Pair with path context (user-writable app dir) for high fidelity.
    ============================================================
*/
rule ThreeCX_Sideload_Companion_DLL_Names
{
    meta:
        description = "Companion DLL names used in the 3CX side-load chain"
        mitre = "T1574.002"
        threat_actor = "Lazarus / UNC4736"
        confidence = "medium"
    strings:
        $mz = { 4D 5A }
        $d3d = "d3dcompiler_47.dll" ascii wide nocase
        $ffm = "ffmpeg.dll" ascii wide nocase
        // 3CX trojan strings historically embedded in the loader / config
        $ua  = "3CXDesktopApp" ascii wide
    condition:
        $mz at 0 and (any of ($d3d, $ffm)) and $ua
}


/*
    ============================================================
    Rule: Browser_Credential_Store_Stealer_Targets
    Confidence: Medium
    Description: Detects tooling that references the full set of cross-browser
                 credential/history store paths (Chrome/Edge/Brave/Firefox) —
                 characteristic of an ICONIC-class infostealer, not a benign app
                 which usually targets only its own store.
    ============================================================
*/
rule Browser_Credential_Store_Stealer_Targets
{
    meta:
        description = "References multiple browser credential-store paths (infostealer)"
        mitre = "T1555.003"
        threat_actor = "Lazarus / UNC4736"
        confidence = "medium"
    strings:
        $chrome = "\\Google\\Chrome\\User Data" ascii wide nocase
        $edge   = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        $brave  = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $ff     = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $login  = "Login Data" ascii wide nocase
        $key4   = "key4.db" ascii wide nocase
    condition:
        3 of ($chrome, $edge, $brave, $ff) and 1 of ($login, $key4)
}


/*
    ============================================================
    Rule: Sandbox_Evasion_Fingerprint_Strings
    Confidence: Low-Medium
    Description: Detects binaries that reference a broad set of hypervisor /
                 sandbox artifact identifiers together — a dormancy-and-evasion
                 stager checking whether it runs in an analyst VM before beaconing.
    ============================================================
*/
rule Sandbox_Evasion_Fingerprint_Strings
{
    meta:
        description = "Multiple hypervisor/sandbox artifact identifiers referenced together"
        mitre = "T1497"
        threat_actor = "Lazarus / UNC4736"
        confidence = "low-medium"
    strings:
        $vbox   = "VBoxGuest" ascii wide nocase
        $vmtool = "vmtools" ascii wide nocase
        $vmci   = "vmci" ascii wide nocase
        $qemu   = "qemu" ascii wide nocase
        $bios   = "SystemBiosVersion" ascii wide nocase
        $tick   = "GetTickCount64" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 4 of them
}
