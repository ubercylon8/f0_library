import "hash"

/*
    YARA Rule: Qilin_RWDRV_Vulnerable_Driver
    Test ID: 8f68dda1-94be-430f-8f35-d8af3f9b5d2e
    MITRE ATT&CK: T1211, T1562.001
    Confidence: High
    False Positives: None expected for an exact hash; a match can also be defensive research or an archived sample.
    Tuning: Treat presence on an endpoint as malicious or unauthorized regardless of filename and path.
*/
rule Qilin_RWDRV_Vulnerable_Driver {
    meta:
        description = "Exact SHA-256 and size of the vulnerable rwdrv.sys driver associated with Qilin BYOVD defense evasion"
        author = "F0RT1KA"
        date = "2026-11-02"
        test_id = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
        mitre_attack = "T1211, T1562.001"
        confidence = "high"
        false_positives = "Security research collections and malware archives; investigate any endpoint execution or service reference"
    condition:
        uint16(0) == 0x5A4D and
        filesize == 18688 and
        hash.sha256(0, filesize) == "ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3"
}

/*
    YARA Rule: Qilin_BYOVD_EDR_Killer_Toolset
    Test ID: 8f68dda1-94be-430f-8f35-d8af3f9b5d2e
    MITRE ATT&CK: T1211, T1562.001
    Confidence: High
    False Positives: Driver-development utilities and defensive proof-of-concept tools may contain similar API strings.
    Tuning: Require PE context and review signer, imports, embedded drivers, and service/device names; do not scan text logs as proof of execution.
*/
rule Qilin_BYOVD_EDR_Killer_Toolset {
    meta:
        description = "Native driver loading and process-termination primitives combined with Qilin driver/device or endpoint-security targets"
        author = "F0RT1KA"
        date = "2026-11-02"
        test_id = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
        mitre_attack = "T1211, T1562.001"
        confidence = "high"
        false_positives = "Driver utilities, EDR research tools, and security software with extensive product-name lists"
    strings:
        $api1 = "NtLoadDriver" ascii wide nocase
        $api2 = "NtUnloadDriver" ascii wide nocase
        $api3 = "NtTerminateProcess" ascii wide nocase
        $api4 = "SeLoadDriverPrivilege" ascii wide nocase
        $api5 = "DeviceIoControl" ascii wide nocase
        $drv1 = "rwdrv.sys" ascii wide nocase
        $drv2 = "hlpdrv.sys" ascii wide nocase
        $drv3 = "\\\\.\\hlpdrv" ascii wide nocase
        $ioctl = { 08 20 22 00 }
        $edr1 = "MsMpEng.exe" ascii wide nocase
        $edr2 = "CSFalconService.exe" ascii wide nocase
        $edr3 = "CrowdStrike.exe" ascii wide nocase
        $edr4 = "SentinelAgent" ascii wide nocase
        $edr5 = "SophosEndpointDefense" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        3 of ($api*) and
        (1 of ($drv*) or $ioctl or 2 of ($edr*))
}

/*
    YARA Rule: Qilin_Discovery_And_Foxit_Sideload_Toolset
    Test ID: 8f68dda1-94be-430f-8f35-d8af3f9b5d2e
    MITRE ATT&CK: T1518.001, T1082, T1574.002
    Confidence: High when both discovery and sideload strings occur; Medium for discovery-only variants
    False Positives: Inventory tools may contain the same CIM classes; repackaged Foxit software may reference a local msimg32.dll.
    Tuning: Validate PE structure and correlate with runtime image-load telemetry rather than treating string presence alone as execution.
*/
rule Qilin_Discovery_And_Foxit_Sideload_Toolset {
    meta:
        description = "SecurityCenter2 and OS discovery combined with the FoxitPDFReader msimg32 side-loading pattern"
        author = "F0RT1KA"
        date = "2026-11-02"
        test_id = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
        mitre_attack = "T1518.001, T1082, T1574.002"
        confidence = "high"
        false_positives = "System inventory software, Foxit installers, and portable application bundles"
    strings:
        $d1 = "root/SecurityCenter2" ascii wide nocase
        $d2 = "AntiVirusProduct" ascii wide nocase
        $d3 = "Win32_OperatingSystem" ascii wide nocase
        $d4 = "tasklist.exe" ascii wide nocase
        $s1 = "FoxitPDFReader.exe" ascii wide nocase
        $s2 = "msimg32.dll" ascii wide nocase
        $s3 = "LoadLibraryW" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (all of ($s*) or (2 of ($d*) and 2 of ($s*)) or 3 of ($d*))
}

/*
    YARA Rule: Qilin_Remote_LoadLibrary_Injection
    Test ID: 8f68dda1-94be-430f-8f35-d8af3f9b5d2e
    MITRE ATT&CK: T1055
    Confidence: High
    False Positives: Debuggers, profilers, modding frameworks, and injection research tools use the same API sequence.
    Tuning: Confirm cross-process runtime behavior and the target/module path; static strings alone do not establish a successful injection.
*/
rule Qilin_Remote_LoadLibrary_Injection {
    meta:
        description = "Remote allocation, memory write, LoadLibraryW and remote-thread APIs paired with Qilin injection artifacts"
        author = "F0RT1KA"
        date = "2026-11-02"
        test_id = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
        mitre_attack = "T1055"
        confidence = "high"
        false_positives = "Debuggers, profilers, game modding tools, and defensive injection proof of concepts"
    strings:
        $api1 = "VirtualAllocEx" ascii wide nocase
        $api2 = "WriteProcessMemory" ascii wide nocase
        $api3 = "CreateRemoteThread" ascii wide nocase
        $api4 = "NtCreateThreadEx" ascii wide nocase
        $api5 = "LoadLibraryW" ascii wide nocase
        $target1 = "svchost.exe" ascii wide nocase
        $target2 = "pwndll.dll" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        4 of ($api*) and
        1 of ($target*)
}

/*
    YARA Rule: Qilin_LSASS_Debug_Access_Toolset
    Test ID: 8f68dda1-94be-430f-8f35-d8af3f9b5d2e
    MITRE ATT&CK: T1003.001
    Confidence: High
    False Positives: Credential-dumping research, debugging tools, and security products may deliberately reference LSASS and SeDebugPrivilege.
    Tuning: Validate the requested access mask and source signer at runtime; do not treat a static match as evidence of a completed dump.
*/
rule Qilin_LSASS_Debug_Access_Toolset {
    meta:
        description = "Debug-privilege and process-opening capability directed at LSASS, consistent with credential-access tooling"
        author = "F0RT1KA"
        date = "2026-11-02"
        test_id = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
        mitre_attack = "T1003.001"
        confidence = "high"
        false_positives = "Debuggers, credential-security research tools, and endpoint protection products"
    strings:
        $s1 = "SeDebugPrivilege" ascii wide nocase
        $s2 = "OpenProcess" ascii wide nocase
        $s3 = "lsass.exe" ascii wide nocase
        $s4 = "ReadProcessMemory" ascii wide nocase
        $s5 = "MiniDumpWriteDump" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        all of ($s1, $s2, $s3) and
        1 of ($s4, $s5, $s1)
}

/*
    YARA Rule: Qilin_Ransomware_Impact_Toolset
    Test ID: 8f68dda1-94be-430f-8f35-d8af3f9b5d2e
    MITRE ATT&CK: T1486, T1490
    Confidence: High
    False Positives: Administrative scripts and backup utilities can contain recovery commands but rarely combine them with Qilin encryption artifacts.
    Tuning: Require the .qilin artifact plus multiple impact strings; validate runtime file modifications before declaring ransomware impact.
*/
rule Qilin_Ransomware_Impact_Toolset {
    meta:
        description = "Qilin encrypted-file and recovery-note artifacts combined with shadow-copy deletion or recovery-disable capability"
        author = "F0RT1KA"
        date = "2026-11-02"
        test_id = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
        mitre_attack = "T1486, T1490"
        confidence = "high"
        false_positives = "Ransomware research utilities and administrative tools mentioning recovery commands"
    strings:
        $ext = ".qilin" ascii wide nocase
        $impact1 = "vssadmin.exe" ascii wide nocase
        $impact2 = "shadows" ascii wide nocase
        $impact3 = "bcdedit.exe" ascii wide nocase
        $impact4 = "recoveryenabled" ascii wide nocase
        $impact5 = "README-RECOVER.txt" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $ext and
        2 of ($impact*)
}
