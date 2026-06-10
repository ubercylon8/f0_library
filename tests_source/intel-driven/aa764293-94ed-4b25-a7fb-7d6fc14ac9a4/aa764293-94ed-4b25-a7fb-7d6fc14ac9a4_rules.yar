/*
   YARA rules — RoguePlanet Windows Defender Remediation TOCTOU LPE
   UUID: aa764293-94ed-4b25-a7fb-7d6fc14ac9a4
   Techniques: T1068, T1036.005, T1053.005

   These rules characterize the RoguePlanet PoC FAMILY by its intrinsic primitive
   composition (MpClient remediation abuse + junction/oplock + VSS + WER task +
   self-copy payload), not by the F0RT1KA orchestrator. They are written to match
   the exploit binary / its self-planted copy, independent of code signing.
*/

import "pe"

rule RoguePlanet_Defender_Remediation_LPE
{
    meta:
        description = "RoguePlanet-class Windows Defender remediation TOCTOU LPE PoC"
        author = "sectest-builder"
        uuid = "aa764293-94ed-4b25-a7fb-7d6fc14ac9a4"
        techniques = "T1068, T1036.005, T1053.005"
        severity = "critical"
        reference = "ROGUEPLANET_ANALYSIS.md"

    strings:
        // MpClient remediation-path RPC surface (analysis §7 signal 3)
        $mp1 = "MpClient.dll" ascii wide nocase
        $mp2 = "MpManagerOpen" ascii
        $mp3 = "MpScanStart" ascii
        $mp4 = "MpThreatOpen" ascii
        $mp5 = "MpCleanStart" ascii
        $mp6 = "MpCleanCallbackFunction called." ascii

        // WER task trigger (signal 8) + planted file target (signal 7)
        $wer1 = "QueueReporting" ascii wide
        $wer2 = "Windows Error Reporting" ascii wide
        $wer3 = "wermgr.exe" ascii wide nocase

        // Cross-privilege hand-off + the success marker the launcher prints
        $pipe = "\\\\.\\pipe\\RoguePlanet" ascii wide
        $marker = "Exploit succeeded." ascii wide
        $ads = "WDFOO" ascii wide

        // EICAR-as-payload (the file made to trip Defender's clean path)
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 8MB and
        (
            // remediation-path abuse: MpClient driver + clean callback
            (3 of ($mp*)) and
            // plus the WER/wermgr plant target
            (2 of ($wer*))
        )
        or
        // strong single-shot indicators unique to this PoC
        ($pipe and $marker)
        or
        (all of ($mp4, $mp5) and $ads and $wer3)
}

rule RoguePlanet_Junction_Oplock_VSS_Primitives
{
    meta:
        description = "Junction + oplock + VSS file-substitution primitive set (RoguePlanet-style remediation race)"
        author = "sectest-builder"
        uuid = "aa764293-94ed-4b25-a7fb-7d6fc14ac9a4"
        techniques = "T1068"
        severity = "high"

    strings:
        // Reparse/junction + oplock FSCTL usage indicators (string-level heuristics)
        $j1 = "FSCTL_SET_REPARSE_POINT" ascii wide
        $j2 = "IO_REPARSE_TAG_MOUNT_POINT" ascii wide
        $o1 = "FSCTL_REQUEST_OPLOCK" ascii wide
        $vss = "HarddiskVolumeShadowCopy" ascii wide
        $iso1 = "AttachVirtualDisk" ascii
        $iso2 = "OpenVirtualDisk" ascii
        $rename = "FileRenameInformationEx" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 8MB and
        (
            ($j1 or $j2) and $o1 and
            (1 of ($iso1, $iso2)) and
            ($vss or $rename)
        )
}
