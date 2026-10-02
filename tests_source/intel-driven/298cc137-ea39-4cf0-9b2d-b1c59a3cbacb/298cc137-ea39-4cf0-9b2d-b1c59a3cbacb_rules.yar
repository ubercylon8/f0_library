/*
   ============================================================
   LockBit 3.0 Double Extortion Kill Chain — YARA Rules
   Test: 298cc137-ea39-4cf0-9b2d-b1c59a3cbacb (SB-PC-2026-001)
   Techniques: T1486, T1059.001, T1562.001, T1490, T1070.001
   Generated: 2026-10-01
   Scope: content/artifact signatures (ransom note, tamper scripts,
          recon patterns). Behavior-only techniques (LSASS access,
          ADMIN$ sessions, exfil POSTs) are covered by the KQL/Sigma/
          EQL/LC-D&R companion rule sets.
   ============================================================
*/

rule LockBit3_RansomNote_RestoreMyFiles
{
    meta:
        description = "Detects LockBit 3.0 (LockBit Black) ransom note content"
        technique = "T1486"
        actor = "LockBit 3.0"
        confidence = "high"
        false_positives = "Rare — note text is actor-specific; security researchers storing samples"
        reference = "CISA AA23-075A / AA23-165A"

    strings:
        $name1 = "Restore-My-Files" ascii wide nocase
        $body1 = "Your data are stolen and encrypted" ascii wide nocase
        $body2 = "~~~ LockBit" ascii wide nocase
        $body3 = "lockbit" ascii wide nocase
        $tor1  = ".onion" ascii wide nocase
        $ext1  = "decryption" ascii wide nocase
        $ext2  = "restore" ascii wide nocase
        $extort1 = "published" ascii wide nocase
        $extort2 = "blog" ascii wide nocase

    condition:
        uint16(0) != 0x5A4D and
        filesize < 64KB and
        (
            $name1 or
            (2 of ($body*) and 1 of ($tor1, $ext1, $ext2)) or
            (1 of ($body*) and 1 of ($extort*) and $tor1)
        )
}

rule LockBit_Tamper_Script_Recovery_And_Defense
{
    meta:
        description = "Detects scripts/batch files combining defense-degradation and recovery-inhibition commands (ransomware pre-encryption tamper stage)"
        technique = "T1562.001, T1490, T1070.001"
        actor = "LockBit (generic ransomware tamper pattern)"
        confidence = "high"
        false_positives = "IT maintenance scripts rarely combine these exact primitives"

    strings:
        $vss1 = "vssadmin" ascii wide nocase
        $vss2 = "delete shadows" ascii wide nocase
        $vss3 = "shadowcopy delete" ascii wide nocase
        $bcd1 = "bcdedit" ascii wide nocase
        $bcd2 = "recoveryenabled" ascii wide nocase
        $wba1 = "wbadmin" ascii wide nocase
        $wba2 = "delete catalog" ascii wide nocase
        $evt1 = "wevtutil" ascii wide nocase
        $evt2 = " cl " ascii wide nocase
        $def1 = "Set-MpPreference" ascii wide nocase
        $def2 = "DisableRealtimeMonitoring" ascii wide nocase
        $sc1  = "stop WinDefend" ascii wide nocase
        $sc2  = "stop Sense" ascii wide nocase
        $sc3  = "stop EventLog" ascii wide nocase

    condition:
        uint16(0) != 0x5A4D and
        filesize < 256KB and
        2 of them
}

rule LockBit_PS_AV_Enumeration_Recon
{
    meta:
        description = "Detects PowerShell host-recon patterns used by ransomware operators (AV product enumeration + domain/system discovery)"
        technique = "T1059.001, T1518.001"
        actor = "LockBit affiliate tooling (generic)"
        confidence = "medium"
        false_positives = "Asset-inventory and compliance scripts; tune to interactive-user execution context"

    strings:
        $av1 = "root\\SecurityCenter2" ascii wide nocase
        $av2 = "AntiVirusProduct" ascii wide nocase
        $av3 = "Get-MpComputerStatus" ascii wide nocase
        $r1  = "whoami" ascii wide nocase
        $r2  = "Win32_ComputerSystem" ascii wide nocase
        $r3  = "Get-ADDomain" ascii wide nocase
        $r4  = "nltest" ascii wide nocase

    condition:
        uint16(0) != 0x5A4D and
        filesize < 128KB and
        1 of ($av*) and 2 of ($r*)
}
