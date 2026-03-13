/*
============================================================================
DEFENSE GUIDANCE: YARA Detection Rules
============================================================================
Test ID: 54a0bd24-d75a-4d89-8dce-c381d932ca97
Test Name: Perfctl/Symbiote LD_PRELOAD Hijacking with PAM Credential Harvesting
MITRE ATT&CK: T1574.006, T1003.008, T1548.001, T1014, T1059.004
Created: 2026-03-13
Author: F0RT1KA Defense Guidance Builder
============================================================================

TECHNIQUE-FOCUSED DETECTION PRINCIPLE:
These YARA rules detect the underlying Linux LD_PRELOAD hijacking, PAM
credential hooking, and userland rootkit techniques, NOT the F0RT1KA
testing framework. They will catch real Perfctl, Symbiote, Auto-Color,
WolfsBane, and similar malware using these same attack patterns.

============================================================================
*/


// ============================================================================
// RULE 1: Generic LD_PRELOAD Rootkit Shared Library
// Detects ELF shared libraries containing function hooking patterns
// used by Perfctl, Symbiote, Auto-Color, and WolfsBane
// ============================================================================

rule Linux_Rootkit_LD_PRELOAD_Hook_Library
{
    meta:
        description = "Detects ELF shared libraries with function hooking patterns for LD_PRELOAD-based rootkits"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "54a0bd24-d75a-4d89-8dce-c381d932ca97"
        mitre_attack = "T1574.006,T1014"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1574/006/"

    strings:
        // ELF magic header
        $elf_magic = { 7f 45 4c 46 }

        // Function hooking patterns - libc hooks
        $hook_open = "real_open" ascii
        $hook_stat = "real_stat" ascii
        $hook_readdir = "real_readdir" ascii
        $hook_read = "real_read" ascii
        $hook_write = "real_write" ascii
        $hook_fopen = "real_fopen" ascii
        $hook_access = "real_access" ascii
        $hook_lstat = "real_lstat" ascii

        // PAM hooking patterns
        $pam_hook1 = "pam_authenticate" ascii
        $pam_hook2 = "real_pam_authenticate" ascii
        $pam_hook3 = "pam_sm_authenticate" ascii
        $pam_hook4 = "pam_get_item" ascii

        // libpcap hooking patterns
        $pcap_hook1 = "pcap_loop" ascii
        $pcap_hook2 = "real_pcap_loop" ascii
        $pcap_hook3 = "pcap_dispatch" ascii
        $pcap_hook4 = "pcap_next" ascii

        // /proc filesystem filtering
        $proc_filter1 = "/proc/net/tcp" ascii
        $proc_filter2 = "/proc/net/tcp6" ascii
        $proc_filter3 = "/proc/self" ascii

        // dlsym usage for function resolution (common in LD_PRELOAD hooks)
        $dlsym1 = "dlsym" ascii
        $dlsym2 = "RTLD_NEXT" ascii
        $dlsym3 = "dlopen" ascii

    condition:
        $elf_magic at 0 and
        filesize < 5MB and
        (
            // Pattern 1: libc function hooking with dlsym (generic rootkit)
            (2 of ($hook_*) and 1 of ($dlsym*)) or
            // Pattern 2: PAM credential hooking
            (2 of ($pam_hook*) and 1 of ($dlsym*)) or
            // Pattern 3: Network traffic hiding
            (1 of ($pcap_hook*) and 1 of ($proc_filter*)) or
            // Pattern 4: Combined rootkit (Perfctl/Symbiote pattern)
            (1 of ($pam_hook*) and 1 of ($pcap_hook*) and 1 of ($hook_*))
        )
}


// ============================================================================
// RULE 2: Perfctl Malware Shared Library
// Detects Perfctl-specific patterns: libgcwrap naming, XOR key 0xAC,
// and combined PAM + pcap hooking
// ============================================================================

rule Linux_Malware_Perfctl_Library
{
    meta:
        description = "Detects Perfctl malware shared library with PAM and pcap hooking"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "54a0bd24-d75a-4d89-8dce-c381d932ca97"
        mitre_attack = "T1574.006,T1003.008"
        confidence = "high"
        severity = "critical"
        reference = "https://www.aquasec.com/blog/perfctl-malware/"

    strings:
        // ELF magic
        $elf_magic = { 7f 45 4c 46 }

        // Perfctl-specific library name
        $name1 = "libgcwrap" ascii nocase
        $name2 = "libgcwrap.so" ascii nocase

        // Perfctl watchdog binary name
        $watchdog1 = "wizlmsh" ascii
        $watchdog2 = "perfctl" ascii

        // PAM hooking strings
        $pam1 = "pam_authenticate" ascii
        $pam2 = "pam_handle_t" ascii

        // pcap hooking strings
        $pcap1 = "pcap_loop" ascii
        $pcap2 = "pcap_t" ascii

        // Mining pool references
        $mine1 = "supportxmr" ascii nocase
        $mine2 = "xmrig" ascii nocase
        $mine3 = "pool." ascii

        // Persistence indicators
        $persist1 = "ld.preload" ascii
        $persist2 = "ld.so.preload" ascii
        $persist3 = "systemctl" ascii
        $persist4 = "crontab" ascii

    condition:
        $elf_magic at 0 and
        filesize < 10MB and
        (
            // Perfctl naming + any hook
            (1 of ($name*) and (1 of ($pam*) or 1 of ($pcap*))) or
            // Watchdog + persistence
            (1 of ($watchdog*) and 2 of ($persist*)) or
            // Mining + hooks
            (1 of ($mine*) and (1 of ($pam*) or 1 of ($pcap*)))
        )
}


// ============================================================================
// RULE 3: Symbiote Rootkit Shared Library
// Detects Symbiote-specific patterns: libc + libpcap dual hooking,
// multi-protocol support, and network traffic filtering
// ============================================================================

rule Linux_Rootkit_Symbiote
{
    meta:
        description = "Detects Symbiote rootkit with libc and libpcap hooking for hiding network artifacts"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "54a0bd24-d75a-4d89-8dce-c381d932ca97"
        mitre_attack = "T1014,T1574.006"
        confidence = "high"
        severity = "critical"
        reference = "https://www.fortiguard.com/threat-signal-report/"

    strings:
        // ELF magic
        $elf_magic = { 7f 45 4c 46 }

        // libc function hooks
        $libc1 = "dlsym" ascii
        $libc2 = "RTLD_NEXT" ascii
        $libc3 = "real_read" ascii
        $libc4 = "real_open" ascii
        $libc5 = "real_readdir" ascii
        $libc6 = "real_fopen" ascii

        // libpcap hooks
        $pcap1 = "pcap_loop" ascii
        $pcap2 = "pcap_dispatch" ascii
        $pcap3 = "pcap_next_ex" ascii
        $pcap4 = "BPF" ascii

        // Network protocol hiding
        $net1 = "/proc/net/tcp" ascii
        $net2 = "/proc/net/tcp6" ascii
        $net3 = "/proc/net/udp" ascii
        $net4 = "SCTP" ascii nocase

        // Process/file hiding
        $hide1 = "is_hidden" ascii
        $hide2 = "hidden_port" ascii
        $hide3 = "hidden_process" ascii
        $hide4 = "/proc/self/maps" ascii

    condition:
        $elf_magic at 0 and
        filesize < 5MB and
        (
            // Dual libc + pcap hooking (Symbiote signature pattern)
            (2 of ($libc*) and 2 of ($pcap*)) or
            // Network hiding + process hiding
            (2 of ($net*) and 2 of ($hide*) and 1 of ($libc*)) or
            // Multi-protocol network hiding
            (3 of ($net*) and 1 of ($pcap*))
        )
}


// ============================================================================
// RULE 4: Auto-Color / WolfsBane LD Preload Rootkit
// Detects patterns specific to Auto-Color and WolfsBane: /etc/ld.preload
// manipulation, /proc/net/tcp scrubbing, and BEURK rootkit patterns
// ============================================================================

rule Linux_Rootkit_AutoColor_WolfsBane
{
    meta:
        description = "Detects Auto-Color or WolfsBane rootkits that manipulate /etc/ld.preload"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "54a0bd24-d75a-4d89-8dce-c381d932ca97"
        mitre_attack = "T1014,T1574.006"
        confidence = "high"
        severity = "critical"
        reference = "https://unit42.paloaltonetworks.com/"

    strings:
        // ELF magic
        $elf_magic = { 7f 45 4c 46 }

        // /etc/ld.preload manipulation
        $preload1 = "/etc/ld.preload" ascii
        $preload2 = "/etc/ld.so.preload" ascii
        $preload3 = "ld_preload" ascii nocase

        // /proc/net/tcp scrubbing (Auto-Color pattern)
        $scrub1 = "/proc/net/tcp" ascii
        $scrub2 = "open_scrubbed" ascii
        $scrub3 = "filter_tcp" ascii

        // BEURK rootkit patterns (WolfsBane base)
        $beurk1 = "BEURK" ascii nocase
        $beurk2 = "unhide" ascii
        $beurk3 = "is_hidden_file" ascii
        $beurk4 = "hide_tcp_port" ascii

        // Function hooking via dlsym
        $hook1 = "dlsym" ascii
        $hook2 = "RTLD_NEXT" ascii
        $hook3 = "real_open" ascii
        $hook4 = "real_stat" ascii
        $hook5 = "real_readdir" ascii

    condition:
        $elf_magic at 0 and
        filesize < 5MB and
        (
            // ld.preload + function hooking
            (1 of ($preload*) and 2 of ($hook*)) or
            // BEURK rootkit patterns
            (1 of ($beurk*) and 1 of ($hook*)) or
            // /proc/net/tcp scrubbing
            (1 of ($scrub*) and 1 of ($preload*))
        )
}


// ============================================================================
// RULE 5: Malicious PAM Module
// Detects shared libraries that contain PAM authentication hooking
// code for credential harvesting
// ============================================================================

rule Linux_Credential_PAM_Backdoor_Module
{
    meta:
        description = "Detects malicious PAM modules designed to capture credentials"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "54a0bd24-d75a-4d89-8dce-c381d932ca97"
        mitre_attack = "T1003.008"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1003/008/"

    strings:
        // ELF magic
        $elf_magic = { 7f 45 4c 46 }

        // PAM API function names (expected in PAM modules)
        $pam_api1 = "pam_sm_authenticate" ascii
        $pam_api2 = "pam_get_item" ascii
        $pam_api3 = "pam_get_authtok" ascii
        $pam_api4 = "PAM_AUTHTOK" ascii
        $pam_api5 = "pam_handle_t" ascii

        // Credential logging/exfiltration patterns
        $cred_log1 = "password" ascii nocase
        $cred_log2 = "credential" ascii nocase
        $cred_log3 = "/tmp/" ascii
        $cred_log4 = "fopen" ascii
        $cred_log5 = "fprintf" ascii

        // Suspicious strings in PAM context
        $sus1 = "capture" ascii nocase
        $sus2 = "harvest" ascii nocase
        $sus3 = "exfil" ascii nocase
        $sus4 = "backdoor" ascii nocase
        $sus5 = "keylog" ascii nocase

        // Network exfiltration patterns
        $net1 = "socket" ascii
        $net2 = "connect" ascii
        $net3 = "send" ascii
        $net4 = "curl" ascii

    condition:
        $elf_magic at 0 and
        filesize < 2MB and
        (
            // PAM module with credential logging
            (2 of ($pam_api*) and 2 of ($cred_log*) and 1 of ($sus*)) or
            // PAM module with network exfiltration
            (2 of ($pam_api*) and 2 of ($net*)) or
            // PAM module writing to suspicious paths
            (2 of ($pam_api*) and $cred_log3 and $cred_log4)
        )
}


// ============================================================================
// RULE 6: XOR-Encrypted C2 Configuration (Perfctl Pattern)
// Detects files with XOR encryption patterns matching Perfctl's key 0xAC
// applied to JSON-like C2 configuration data
// ============================================================================

rule Linux_Malware_XOR_Encrypted_C2_Config
{
    meta:
        description = "Detects XOR-encrypted C2 configuration files matching Perfctl encryption pattern"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "54a0bd24-d75a-4d89-8dce-c381d932ca97"
        mitre_attack = "T1059.004"
        confidence = "medium"
        severity = "high"
        reference = "https://www.aquasec.com/blog/perfctl-malware/"

    strings:
        // XOR-encrypted JSON structure markers with key 0xAC
        // '{' (0x7B) XOR 0xAC = 0xD7
        // '"' (0x22) XOR 0xAC = 0x8E
        // ':' (0x3A) XOR 0xAC = 0x96
        // '}' (0x7D) XOR 0xAC = 0xD1
        $xor_json_start = { D7 0A 8E }  // {<newline>"
        $xor_json_colon = { 8E 96 AC }  // ": (space)
        $xor_json_end = { D1 }          // }

        // XOR-encrypted common C2 config strings with key 0xAC
        // "pool" XOR 0xAC = DC C3 C0 C8
        $xor_pool = { DC C3 C0 C8 }
        // "http" XOR 0xAC = C4 D8 D8 DC
        $xor_http = { C4 D8 D8 DC }
        // "port" XOR 0xAC = DC C3 D8 D8  (wait: p=0x70->0xDC, o=0x6F->0xC3, r=0x72->0xDE, t=0x74->0xD8)
        $xor_port = { DC C3 DE D8 }

    condition:
        filesize < 100KB and
        filesize > 50 and
        (
            // XOR-encrypted JSON structure
            ($xor_json_start and $xor_json_end) or
            // XOR-encrypted C2 keywords
            (2 of ($xor_pool, $xor_http, $xor_port))
        )
}


// ============================================================================
// RULE 7: Suspicious LD_PRELOAD Configuration File Content
// Detects files that contain LD_PRELOAD configuration entries pointing
// to non-standard shared library paths
// ============================================================================

rule Linux_Persistence_LD_Preload_Config
{
    meta:
        description = "Detects suspicious ld.preload configuration files pointing to non-standard libraries"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "54a0bd24-d75a-4d89-8dce-c381d932ca97"
        mitre_attack = "T1574.006"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1574/006/"

    strings:
        // Suspicious library paths that should not be in ld.preload
        $path1 = "/tmp/" ascii
        $path2 = "/var/tmp/" ascii
        $path3 = "/dev/shm/" ascii
        $path4 = "/.hidden/" ascii
        $path5 = "/home/" ascii

        // Library file extension
        $so_ext = ".so" ascii

        // Known malicious library names
        $mal_lib1 = "libgcwrap" ascii nocase
        $mal_lib2 = "libsophos" ascii nocase
        $mal_lib3 = "libmodule.so" ascii
        $mal_lib4 = "libprocesshider" ascii nocase
        $mal_lib5 = "libkeyutils" ascii nocase

    condition:
        filesize < 1KB and
        (
            // File contains suspicious path + .so extension
            (1 of ($path*) and $so_ext) or
            // Known malicious library names
            (1 of ($mal_lib*))
        )
}


// ============================================================================
// RULE 8: Linux Credential Dump - Shadow File Copy
// Detects files that contain /etc/shadow formatted content outside
// the expected location
// ============================================================================

rule Linux_Credential_Shadow_Dump
{
    meta:
        description = "Detects copies of /etc/shadow content outside the expected location"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "54a0bd24-d75a-4d89-8dce-c381d932ca97"
        mitre_attack = "T1003.008"
        confidence = "medium"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1003/008/"

    strings:
        // Shadow file hash format patterns
        $sha512_hash = /\$6\$[a-zA-Z0-9.\/]{1,16}\$/ ascii
        $yescrypt_hash = /\$y\$[a-zA-Z0-9]{1,8}\$/ ascii
        $md5_hash = /\$1\$[a-zA-Z0-9.\/]{1,8}\$/ ascii
        $sha256_hash = /\$5\$[a-zA-Z0-9.\/]{1,16}\$/ ascii
        $bcrypt_hash = /\$2[aby]\$[0-9]{2}\$/ ascii

        // Shadow file structure (username:hash:lastchanged:min:max:warn:::)
        $shadow_format = /[a-z][a-z0-9_-]{0,30}:\$[156y]/ ascii

        // Multiple user entries
        $root_entry = "root:" ascii
        $daemon_entry = "daemon:" ascii
        $nobody_entry = "nobody:" ascii

    condition:
        filesize < 10MB and
        filesize > 50 and
        (
            // Multiple shadow hash formats in one file
            (2 of ($sha512_hash, $yescrypt_hash, $md5_hash, $sha256_hash, $bcrypt_hash) and $shadow_format) or
            // Shadow file structure with known system accounts
            ($shadow_format and 2 of ($root_entry, $daemon_entry, $nobody_entry))
        )
}
