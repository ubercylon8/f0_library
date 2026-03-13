/*
    ============================================================
    ESXi Hypervisor Ransomware Kill Chain - YARA Rules
    Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
    MITRE ATT&CK: T1046, T1021.004, T1068, T1489, T1529, T1048, T1567.002, T1486
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    ============================================================

    These rules detect ESXi-targeting ransomware binaries, SSH-Snake,
    Rclone exfiltration tools, and ransomware encryption artifacts
    based on technique-specific behavioral patterns and file content.

    Platform: Linux / ELF binaries

    Usage:
        yara -r 25aafe2c-ec57-4a85-a26a-c3d7cf35620c_rules.yar /path/to/scan

    ============================================================
*/


/*
    ============================================================
    Rule: ESXi_Ransomware_VM_Kill_Tool
    Confidence: High
    Description: Detects ELF binaries designed to kill ESXi VMs and delete snapshots
    ============================================================
*/
rule ESXi_Ransomware_VM_Kill_Tool
{
    meta:
        description = "Detects tools designed to kill ESXi virtual machines and delete snapshots"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
        mitre_attack = "T1489,T1529"
        confidence = "high"
        threat_actor = "RansomHub,Akira,LockBit,BlackBasta"

    strings:
        // ESXi management commands
        $cmd1 = "esxcli vm process kill" ascii
        $cmd2 = "vim-cmd vmsvc/power.off" ascii
        $cmd3 = "vim-cmd vmsvc/snapshot.removeall" ascii
        $cmd4 = "vim-cmd vmsvc/getallvms" ascii
        $cmd5 = "esxcli vm process list" ascii
        $cmd6 = "vmdumper -l" ascii
        $cmd7 = "vim-cmd hostsvc/enable_ssh" ascii
        $cmd8 = "--type=force --world-id" ascii

        // ESXi service stop commands
        $svc1 = "/etc/init.d/hostd stop" ascii
        $svc2 = "/etc/init.d/vmware-vpxd stop" ascii
        $svc3 = "/etc/init.d/vmware-fdm stop" ascii

        // Kill patterns
        $kill1 = "vm process kill" ascii
        $kill2 = "power.off" ascii
        $kill3 = "snapshot.removeall" ascii

        // VM file targeting
        $ext1 = ".vmdk" ascii
        $ext2 = ".vmx" ascii
        $ext3 = ".vmsn" ascii
        $ext4 = "/vmfs/volumes/" ascii

    condition:
        uint32(0) == 0x464C457F and  // ELF magic
        filesize < 50MB and
        (
            // Definitive: Multiple ESXi management commands
            (3 of ($cmd*)) or
            // High confidence: VM kill + snapshot delete + file targets
            (any of ($kill*) and any of ($ext*) and any of ($cmd*)) or
            // Service disruption pattern
            (2 of ($svc*) and any of ($cmd*))
        )
}


/*
    ============================================================
    Rule: ESXi_Ransomware_Encryptor_Linux
    Confidence: High
    Description: Detects Linux ESXi ransomware encryptors targeting VMDK files
    ============================================================
*/
rule ESXi_Ransomware_Encryptor_Linux
{
    meta:
        description = "Detects Linux-based ransomware encryptors targeting VMware ESXi VMDK files"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
        mitre_attack = "T1486"
        confidence = "high"
        threat_actor = "RansomHub,Akira,LockBit"

    strings:
        // Encryption algorithm indicators
        $crypto1 = "chacha20" ascii nocase
        $crypto2 = "curve25519" ascii nocase
        $crypto3 = "ChaCha20-Poly1305" ascii
        $crypto4 = "Salsa20" ascii nocase
        $crypto5 = "aes-256" ascii nocase
        $crypto6 = "RSA-OAEP" ascii nocase

        // VM file extension targets
        $target1 = ".vmdk" ascii
        $target2 = ".vmx" ascii
        $target3 = ".vmsn" ascii
        $target4 = ".vmsd" ascii
        $target5 = ".nvram" ascii
        $target6 = ".vswp" ascii

        // ESXi datastore paths
        $path1 = "/vmfs/volumes/" ascii
        $path2 = "datastore" ascii

        // Ransomware extension appending
        $ransom1 = ".ransomhub" ascii
        $ransom2 = ".akira" ascii
        $ransom3 = ".lockbit" ascii
        $ransom4 = ".blackbasta" ascii
        $ransom5 = ".encrypted" ascii

        // Ransom note strings
        $note1 = "Your network has been breached" ascii nocase
        $note2 = "data was encrypted" ascii nocase
        $note3 = "DECRYPT" ascii
        $note4 = "pay the ransom" ascii nocase
        $note5 = "TOR Browser" ascii nocase
        $note6 = ".onion" ascii

        // Intermittent encryption pattern
        $skip1 = "skip" ascii
        $skip2 = "intermittent" ascii nocase

    condition:
        uint32(0) == 0x464C457F and  // ELF magic
        filesize < 50MB and
        (
            // Crypto + VM targets + ransomware extension
            (any of ($crypto*) and 2 of ($target*) and any of ($ransom*)) or
            // VM targets + ransom note content
            (2 of ($target*) and 2 of ($note*)) or
            // Datastore path + crypto + file targets
            (any of ($path*) and any of ($crypto*) and 2 of ($target*)) or
            // Ransomware extension + ransom note
            (any of ($ransom*) and 2 of ($note*) and any of ($target*))
        )
}


/*
    ============================================================
    Rule: SSH_Snake_Worm
    Confidence: High
    Description: Detects SSH-Snake self-modifying worm for lateral movement
    ============================================================
*/
rule SSH_Snake_Worm
{
    meta:
        description = "Detects SSH-Snake self-modifying worm used for SSH-based lateral movement"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
        mitre_attack = "T1021.004"
        confidence = "high"
        reference = "https://sysdig.com/blog/ssh-snake/"

    strings:
        // SSH-Snake specific identifiers
        $name1 = "ssh-snake" ascii nocase
        $name2 = "ssh_snake" ascii nocase
        $name3 = "SSH-Snake" ascii

        // SSH key harvesting patterns
        $key1 = ".ssh/id_rsa" ascii
        $key2 = ".ssh/id_ed25519" ascii
        $key3 = ".ssh/id_ecdsa" ascii
        $key4 = ".ssh/authorized_keys" ascii
        $key5 = ".ssh/known_hosts" ascii
        $key6 = ".ssh/config" ascii
        $key7 = "ssh_host_rsa_key" ascii
        $key8 = "ssh_host_ed25519_key" ascii

        // Self-propagation strings
        $prop1 = "self-modifying" ascii nocase
        $prop2 = "self-replicat" ascii nocase
        $prop3 = "propagat" ascii nocase
        $prop4 = "lateral" ascii nocase

        // Bash history parsing for SSH commands
        $hist1 = "bash_history" ascii
        $hist2 = ".bash_history" ascii
        $hist3 = "history" ascii

    condition:
        filesize < 5MB and
        (
            // Direct SSH-Snake identification
            any of ($name*) or
            // SSH key harvesting + self-propagation
            (3 of ($key*) and any of ($prop*)) or
            // Bulk SSH key access + history parsing (worm behavior)
            (4 of ($key*) and any of ($hist*))
        )
}


/*
    ============================================================
    Rule: Rclone_Exfiltration_Tool
    Confidence: High
    Description: Detects Rclone binary or renamed variants used for data exfiltration
    ============================================================
*/
rule Rclone_Exfiltration_Tool
{
    meta:
        description = "Detects Rclone data transfer tool commonly used for ransomware exfiltration"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
        mitre_attack = "T1048,T1567.002"
        confidence = "high"
        reference = "https://www.reliaquest.com/"

    strings:
        // Rclone identification strings
        $rclone1 = "rclone" ascii nocase
        $rclone2 = "github.com/rclone/rclone" ascii
        $rclone3 = "rclone/fs" ascii

        // Rclone command patterns
        $cmd1 = "--transfers" ascii
        $cmd2 = "--checkers" ascii
        $cmd3 = "--s3-chunk-size" ascii
        $cmd4 = "--config" ascii
        $cmd5 = "--progress" ascii

        // Cloud storage backend names
        $cloud1 = "mega" ascii nocase
        $cloud2 = "s3" ascii
        $cloud3 = "sftp" ascii
        $cloud4 = "drive" ascii
        $cloud5 = "dropbox" ascii nocase
        $cloud6 = "onedrive" ascii nocase
        $cloud7 = "backblaze" ascii nocase
        $cloud8 = "wasabi" ascii nocase

        // Configuration file patterns
        $conf1 = "rclone.conf" ascii
        $conf2 = ".config/rclone" ascii
        $conf3 = "type = mega" ascii
        $conf4 = "type = s3" ascii
        $conf5 = "type = sftp" ascii
        $conf6 = "access_key_id" ascii
        $conf7 = "secret_access_key" ascii

    condition:
        filesize < 100MB and
        (
            // Rclone source path (definitive for Go binary)
            $rclone2 or
            // Rclone name + cloud backends + commands
            (any of ($rclone*) and 2 of ($cloud*) and 2 of ($cmd*)) or
            // Configuration patterns (rclone.conf content)
            (2 of ($conf*) and any of ($cloud*))
        )
}


/*
    ============================================================
    Rule: Rclone_Config_File
    Confidence: High
    Description: Detects Rclone configuration files with exfiltration targets
    ============================================================
*/
rule Rclone_Config_File
{
    meta:
        description = "Detects Rclone configuration files containing cloud storage targets for exfiltration"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
        mitre_attack = "T1048,T1567.002"
        confidence = "high"

    strings:
        // Rclone config section headers
        $section1 = /\[[\w\-]+\]/ ascii
        $type1 = "type = mega" ascii
        $type2 = "type = s3" ascii
        $type3 = "type = sftp" ascii
        $type4 = "type = drive" ascii
        $type5 = "type = dropbox" ascii
        $type6 = "type = onedrive" ascii
        $type7 = "type = ftp" ascii
        $type8 = "type = azureblob" ascii

        // Credential indicators
        $cred1 = "access_key_id" ascii
        $cred2 = "secret_access_key" ascii
        $cred3 = "pass =" ascii
        $cred4 = "user =" ascii
        $cred5 = "key_file" ascii
        $cred6 = "token" ascii

    condition:
        filesize < 1MB and
        not uint32(0) == 0x464C457F and  // Not ELF
        not uint16(0) == 0x5A4D and      // Not PE
        (
            // Multiple remote type definitions (multi-target exfil)
            (2 of ($type*)) or
            // Remote type + credentials
            (any of ($type*) and 2 of ($cred*))
        )
}


/*
    ============================================================
    Rule: RansomHub_Ransom_Note
    Confidence: High
    Description: Detects RansomHub-style ransom notes
    ============================================================
*/
rule RansomHub_Ransom_Note
{
    meta:
        description = "Detects RansomHub ransomware ransom note content"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
        mitre_attack = "T1486"
        confidence = "high"
        threat_actor = "RansomHub"

    strings:
        // RansomHub specific strings
        $rh1 = "RANSOMHUB" ascii nocase
        $rh2 = "ransomhub" ascii

        // Common ransom note phrases
        $note1 = "Your network has been breached" ascii nocase
        $note2 = "data was encrypted" ascii nocase
        $note3 = "pay the ransom" ascii nocase
        $note4 = "data will be published" ascii nocase
        $note5 = "PERMANENTLY DAMAGE" ascii
        $note6 = "Contact law enforcement" ascii nocase
        $note7 = "data recovery companies" ascii nocase
        $note8 = "TOR Browser" ascii nocase

        // Onion URL pattern
        $onion = ".onion" ascii

        // Deadline language
        $deadline1 = "Deadline" ascii nocase
        $deadline2 = "72 HOURS" ascii nocase
        $deadline3 = "48 HOURS" ascii nocase

    condition:
        filesize < 100KB and
        not uint32(0) == 0x464C457F and  // Not ELF
        not uint16(0) == 0x5A4D and      // Not PE
        (
            // RansomHub branded
            (any of ($rh*) and 2 of ($note*)) or
            // Generic ransom note with onion link
            (3 of ($note*) and $onion) or
            // Deadline + extortion language
            (any of ($deadline*) and 2 of ($note*))
        )
}


/*
    ============================================================
    Rule: CVE_2024_37085_Exploit_Tool
    Confidence: Medium
    Description: Detects tools exploiting CVE-2024-37085 ESXi auth bypass
    ============================================================
*/
rule CVE_2024_37085_Exploit_Tool
{
    meta:
        description = "Detects tools exploiting CVE-2024-37085 for ESXi authentication bypass via AD group"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
        mitre_attack = "T1068"
        confidence = "medium"
        reference = "https://www.cve.org/CVERecord?id=CVE-2024-37085"

    strings:
        // CVE identifier
        $cve1 = "CVE-2024-37085" ascii
        $cve2 = "2024-37085" ascii

        // ESX Admins group creation
        $group1 = "ESX Admins" ascii nocase
        $group2 = "ESXAdmins" ascii nocase
        $group3 = "ESX_Admins" ascii nocase

        // AD group manipulation commands
        $ad1 = "net group" ascii nocase
        $ad2 = "/domain /add" ascii nocase
        $ad3 = "New-ADGroup" ascii nocase
        $ad4 = "dsadd group" ascii nocase

        // ESXi authentication context
        $esxi1 = "esxi" ascii nocase
        $esxi2 = "hypervisor" ascii nocase
        $esxi3 = "vmware" ascii nocase
        $esxi4 = "vcenter" ascii nocase

    condition:
        filesize < 50MB and
        (
            // CVE reference + ESX Admins group
            (any of ($cve*) and any of ($group*)) or
            // ESX Admins group + AD commands
            (any of ($group*) and any of ($ad*)) or
            // CVE reference + ESXi context
            (any of ($cve*) and any of ($esxi*))
        )
}


/*
    ============================================================
    Rule: CVE_2024_1086_Exploit_Tool
    Confidence: Medium
    Description: Detects tools exploiting CVE-2024-1086 nf_tables kernel exploit
    ============================================================
*/
rule CVE_2024_1086_Exploit_Tool
{
    meta:
        description = "Detects tools exploiting CVE-2024-1086 (Flipping Pages) for Linux kernel privilege escalation"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
        mitre_attack = "T1068"
        confidence = "medium"
        reference = "https://www.cve.org/CVERecord?id=CVE-2024-1086"

    strings:
        // CVE identifier
        $cve1 = "CVE-2024-1086" ascii
        $cve2 = "2024-1086" ascii
        $cve3 = "Flipping Pages" ascii

        // nf_tables exploit strings
        $nft1 = "nf_tables" ascii
        $nft2 = "nft_verdict_init" ascii
        $nft3 = "nftables" ascii
        $nft4 = "netfilter" ascii

        // Kernel exploit strings
        $kern1 = "use-after-free" ascii nocase
        $kern2 = "double-free" ascii nocase
        $kern3 = "heap spray" ascii nocase
        $kern4 = "page table" ascii nocase
        $kern5 = "PTE" ascii
        $kern6 = "privilege escalation" ascii nocase
        $kern7 = "kernel exploit" ascii nocase
        $kern8 = "modprobe_path" ascii

    condition:
        uint32(0) == 0x464C457F and  // ELF
        filesize < 10MB and
        (
            // CVE reference + nf_tables context
            (any of ($cve*) and any of ($nft*)) or
            // nf_tables + kernel exploit patterns
            (any of ($nft*) and 2 of ($kern*)) or
            // CVE reference + exploit primitives
            (any of ($cve*) and 2 of ($kern*))
        )
}


/*
    ============================================================
    Rule: ESXi_Network_Scanner
    Confidence: Medium
    Description: Detects network scanning tools targeting ESXi infrastructure ports
    ============================================================
*/
rule ESXi_Network_Scanner
{
    meta:
        description = "Detects network scanning tools targeting ESXi-specific ports and services"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
        mitre_attack = "T1046,T1018"
        confidence = "medium"

    strings:
        // ESXi port references
        $port1 = "443" ascii
        $port2 = "902" ascii
        $port3 = "5480" ascii
        $port4 = "8697" ascii

        // ESXi identification strings
        $esxi1 = "VMware ESXi" ascii
        $esxi2 = "esxi" ascii nocase
        $esxi3 = "vSphere" ascii nocase
        $esxi4 = "VAMI" ascii

        // Scanning tools / techniques
        $scan1 = "nmap" ascii nocase
        $scan2 = "fscan" ascii nocase
        $scan3 = "masscan" ascii nocase
        $scan4 = "port scan" ascii nocase

        // VMware service identifiers
        $svc1 = "VMware Authentication Daemon" ascii
        $svc2 = "vmware-hostd" ascii
        $svc3 = "vpxd" ascii

    condition:
        filesize < 50MB and
        (
            // Scanner + ESXi targets
            (any of ($scan*) and 2 of ($esxi*)) or
            // ESXi identification + port targeting
            (any of ($esxi*) and 2 of ($port*) and any of ($svc*))
        )
}
