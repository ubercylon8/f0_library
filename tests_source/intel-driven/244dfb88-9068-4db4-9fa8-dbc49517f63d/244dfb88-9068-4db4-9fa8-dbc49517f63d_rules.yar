/*
============================================================================
DEFENSE GUIDANCE: YARA Detection Rules
============================================================================
Test ID: 244dfb88-9068-4db4-9fa8-dbc49517f63d
Test Name: DPRK BlueNoroff Financial Sector Attack Chain
MITRE ATT&CK: T1553.001, T1543.004, T1059.002, T1555.001, T1056.002,
              T1071.001, T1573.002, T1071.004, T1041, T1567.002, T1560.001
Threat Actor: BlueNoroff/Lazarus (DPRK)
Target Platform: macOS
Created: 2026-03-13
Author: F0RT1KA Defense Guidance Builder
============================================================================

TECHNIQUE-FOCUSED DETECTION PRINCIPLE:
These YARA rules detect the underlying macOS attack technique artifacts
used by BlueNoroff/Lazarus campaigns, NOT the F0RT1KA testing framework.
They will catch real-world tools using the same persistence, credential
theft, C2, and exfiltration patterns.

============================================================================
*/


// ============================================================================
// RULE 1: BlueNoroff RustBucket LaunchAgent Persistence
// Detects plist files with RustBucket-pattern LaunchAgent configuration
// ============================================================================

rule BlueNoroff_RustBucket_LaunchAgent_Plist
{
    meta:
        description = "Detects LaunchAgent plist files matching RustBucket/BlueNoroff persistence pattern with com.apple masquerading"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1543.004"
        confidence = "high"
        severity = "critical"
        threat_actor = "BlueNoroff/Lazarus"
        reference = "https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/"

    strings:
        // Plist structure markers
        $plist_header = "<!DOCTYPE plist" ascii
        $plist_version = "<plist version=" ascii

        // Known BlueNoroff LaunchAgent labels
        $label1 = "com.apple.systemupdate" ascii
        $label2 = "com.avatar.update.wake" ascii
        $label3 = "com.apple.security.updateagent" ascii
        $label4 = "com.apple.Safari.helper" ascii

        // Persistence configuration keys
        $key_runatload = "<key>RunAtLoad</key>" ascii
        $key_keepalive = "<key>KeepAlive</key>" ascii

        // Suspicious program paths used by BlueNoroff
        $path1 = "/Users/Shared/.system/" ascii
        $path2 = "/Users/Shared/.invisible_ferret/" ascii
        $path3 = "/Library/Application Support/.security/" ascii
        $path4 = "/tmp/.sysupdate" ascii

    condition:
        $plist_header and $plist_version and
        (any of ($label*)) and
        ($key_runatload or $key_keepalive) and
        (any of ($path*))
}


// ============================================================================
// RULE 2: macOS .zshenv Persistence Payload (Hidden Risk Campaign)
// Detects .zshenv files containing C2 beacon or backdoor code
// ============================================================================

rule BlueNoroff_HiddenRisk_Zshenv_Persistence
{
    meta:
        description = "Detects .zshenv modifications containing C2 beacon code, matching Hidden Risk campaign persistence technique"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1543.004"
        confidence = "high"
        severity = "critical"
        threat_actor = "BlueNoroff Hidden Risk"
        reference = "https://www.sentinelone.com/labs/bluenoroff-hidden-risk/"

    strings:
        // C2 beacon patterns in shell config
        $c2_curl1 = /curl\s+-s\s+["']https?:\/\/[^"']+["']\s*\|\s*bash/ ascii
        $c2_curl2 = /curl\s+.*\|\s*sh/ ascii
        $c2_wget = /wget\s+-q.*-O\s*-\s*\|\s*bash/ ascii

        // Environment variable C2 patterns
        $env_c2 = /export\s+\w+_C2\s*=\s*["']https?:/ ascii
        $env_hwid = "IOPlatformUUID" ascii
        $env_ioreg = "ioreg -d2 -c IOPlatformExpertDevice" ascii

        // Beacon function patterns
        $func_beacon = /function\s+_?\w*update\w*\s*\(\)/ ascii
        $func_check = /function\s+_?\w*check\w*\s*\(\)/ ascii
        $background = "&>/dev/null &" ascii

        // Shell config file indicator
        $zshenv = ".zshenv" ascii

    condition:
        filesize < 100KB and
        $zshenv and
        (
            (any of ($c2_curl*, $c2_wget)) or
            ($env_c2 and ($env_hwid or $env_ioreg)) or
            (any of ($func_*) and $background and any of ($env_*))
        )
}


// ============================================================================
// RULE 3: macOS osascript Credential Phishing Script
// Detects AppleScript files with fake password dialog patterns
// ============================================================================

rule macOS_Credential_Phishing_AppleScript
{
    meta:
        description = "Detects AppleScript files containing fake password dialog patterns used by AMOS, Banshee, and BlueNoroff stealers"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1059.002, T1056.002"
        confidence = "high"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1059/002/"

    strings:
        // AppleScript password dialog patterns
        $dialog1 = "display dialog" ascii nocase
        $dialog2 = "with hidden answer" ascii nocase
        $dialog3 = "default answer" ascii nocase

        // Social engineering text patterns
        $lure1 = "needs your password" ascii nocase
        $lure2 = "System Preferences" ascii nocase
        $lure3 = "System Settings" ascii nocase
        $lure4 = "password to update" ascii nocase
        $lure5 = "password to continue" ascii nocase
        $lure6 = "macOS needs" ascii nocase
        $lure7 = "with icon caution" ascii nocase

        // Credential validation after capture
        $dscl = "dscl" ascii
        $authonly = "-authonly" ascii

        // Exfiltration of captured credential
        $exfil_curl = /curl\s+-X\s+POST/ ascii
        $exfil_pass = /pass=/ ascii

    condition:
        filesize < 50KB and
        $dialog1 and $dialog2 and
        (2 of ($lure*)) and
        (
            ($dscl and $authonly) or
            ($exfil_curl) or
            ($exfil_pass)
        )
}


// ============================================================================
// RULE 4: macOS Keychain Dumper Script
// Detects scripts that enumerate and dump macOS Keychain credentials
// ============================================================================

rule macOS_Keychain_Dumper_Script
{
    meta:
        description = "Detects scripts containing macOS Keychain enumeration and credential extraction commands"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1555.001"
        confidence = "high"
        severity = "high"

    strings:
        // Keychain CLI commands
        $cmd1 = "security dump-keychain" ascii
        $cmd2 = "security find-generic-password" ascii
        $cmd3 = "security find-internet-password" ascii
        $cmd4 = "security list-keychains" ascii
        $cmd5 = "security export" ascii

        // Password extraction flags
        $flag1 = "-ga" ascii
        $flag2 = "-w" ascii
        $flag3 = "-g" ascii

        // Chrome Safe Storage key extraction
        $chrome1 = "Chrome Safe Storage" ascii
        $chrome2 = "Chrome" ascii

        // Keychain database file
        $db1 = "login.keychain-db" ascii
        $db2 = "login.keychain" ascii

        // Crypto exchange targets
        $target1 = "coinbase" ascii nocase
        $target2 = "binance" ascii nocase
        $target3 = "kraken" ascii nocase
        $target4 = "metamask" ascii nocase

    condition:
        filesize < 500KB and
        (2 of ($cmd*)) and
        (any of ($flag*)) and
        (
            (any of ($chrome*)) or
            (any of ($target*)) or
            (any of ($db*))
        )
}


// ============================================================================
// RULE 5: Sliver C2 Beacon Configuration File
// Detects JSON configuration files for Sliver C2 framework
// ============================================================================

rule Sliver_C2_Beacon_Config
{
    meta:
        description = "Detects Sliver C2 framework beacon configuration files used for macOS implant communication"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1071.001, T1573.002"
        confidence = "high"
        severity = "critical"

    strings:
        // Sliver framework identifiers
        $fw1 = "Sliver" ascii nocase
        $fw2 = "sliver" ascii

        // C2 protocol configuration
        $proto1 = "mTLS" ascii
        $proto2 = "mtls" ascii
        $proto3 = "beacon_interval" ascii
        $proto4 = "reconnect_interval" ascii
        $proto5 = "jitter" ascii

        // Implant configuration
        $implant1 = "implant_config" ascii
        $implant2 = "obfuscation" ascii
        $implant3 = "sandbox_detect" ascii
        $implant4 = "debugger_detect" ascii

        // Certificate configuration
        $cert1 = "ca_cert" ascii
        $cert2 = "client_cert" ascii
        $cert3 = "client_key" ascii

        // C2 domains
        $domain1 = "linkpc.net" ascii
        $domain2 = "dnx.capital" ascii

    condition:
        filesize < 100KB and
        (any of ($fw*)) and
        (2 of ($proto*)) and
        (
            (any of ($implant*)) or
            (2 of ($cert*)) or
            (any of ($domain*))
        )
}


// ============================================================================
// RULE 6: macOS Crypto Wallet Data Staging
// Detects staged cryptocurrency wallet data for exfiltration
// ============================================================================

rule macOS_Crypto_Wallet_Staging
{
    meta:
        description = "Detects staged cryptocurrency wallet data files containing vault data, seed phrases, or private keys"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1555.001, T1005"
        confidence = "medium"
        severity = "critical"
        threat_actor = "BlueNoroff/Lazarus"

    strings:
        // Wallet identifiers
        $wallet1 = "MetaMask" ascii nocase
        $wallet2 = "Exodus" ascii nocase
        $wallet3 = "Coinbase Wallet" ascii nocase
        $wallet4 = "Phantom" ascii nocase
        $wallet5 = "Trust Wallet" ascii nocase

        // Vault/key data indicators
        $data1 = "vault_data" ascii
        $data2 = "seed_data" ascii
        $data3 = "seed_phrase" ascii
        $data4 = "recovery_phrase" ascii
        $data5 = "private_keys" ascii
        $data6 = "mnemonic" ascii

        // Browser extension paths
        $ext1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii  // MetaMask
        $ext2 = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii  // Coinbase Wallet
        $ext3 = "exodus.wallet" ascii

        // Encryption artifacts
        $enc1 = "\"iv\"" ascii
        $enc2 = "\"salt\"" ascii
        $enc3 = "\"data\"" ascii

    condition:
        filesize < 10MB and
        (any of ($wallet*)) and
        (any of ($data*) or 2 of ($enc*)) and
        (any of ($ext*))
}


// ============================================================================
// RULE 7: AMOS/NotLockBit Exfiltration Archive Pattern
// Detects zip archives containing credential and wallet staging data
// ============================================================================

rule macOS_Exfil_Archive_Credential_Staging
{
    meta:
        description = "Detects zip archives containing staged credential files and wallet data, matching AMOS stealer exfiltration pattern"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1560.001, T1041"
        confidence = "medium"
        severity = "high"

    strings:
        // ZIP magic bytes
        $zip_magic = { 50 4B 03 04 }

        // Credential-related filenames in archive
        $file1 = "keychain_dump" ascii
        $file2 = "browser_credentials" ascii
        $file3 = "harvested_credentials" ascii
        $file4 = "metamask_vault" ascii
        $file5 = "exodus_wallet" ascii
        $file6 = "coinbase_wallet" ascii
        $file7 = "chrome_login" ascii
        $file8 = "Login Data" ascii
        $file9 = "Cookies" ascii

    condition:
        $zip_magic at 0 and
        filesize < 100MB and
        3 of ($file*)
}


// ============================================================================
// RULE 8: AWS S3 Exfiltration Configuration (NotLockBit Pattern)
// Detects configuration files with hardcoded AWS credentials for exfiltration
// ============================================================================

rule AWS_S3_Exfil_Hardcoded_Credentials
{
    meta:
        description = "Detects files containing hardcoded AWS S3 credentials and upload configuration, matching macOS.NotLockBit exfiltration pattern"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1567.002"
        confidence = "high"
        severity = "critical"

    strings:
        // AWS credential patterns
        $aws_key = /AKIA[0-9A-Z]{16}/ ascii
        $aws_secret_key = "secret_key" ascii
        $aws_access_key = "access_key" ascii

        // S3 upload configuration
        $s3_1 = "s3.amazonaws.com" ascii
        $s3_2 = "bucket" ascii
        $s3_3 = "object_key" ascii
        $s3_4 = "upload" ascii

        // Exfiltration context
        $exfil1 = "exfil" ascii nocase
        $exfil2 = "hwid" ascii
        $exfil3 = "campaign" ascii
        $exfil4 = "victim" ascii nocase

    condition:
        filesize < 10KB and
        ($aws_key or ($aws_access_key and $aws_secret_key)) and
        (any of ($s3_*)) and
        (any of ($exfil*))
}


// ============================================================================
// RULE 9: Notarized Malware with Hijacked Developer ID
// Detects code signing metadata referencing known hijacked Apple Developer IDs
// ============================================================================

rule macOS_Hijacked_Developer_ID
{
    meta:
        description = "Detects files referencing Apple Developer IDs known to be hijacked by DPRK actors for malware notarization"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1553.001"
        confidence = "high"
        severity = "critical"
        threat_actor = "BlueNoroff/Lazarus"

    strings:
        // Known hijacked Apple Developer IDs used by BlueNoroff
        $devid1 = "Avantis Regtech Private Limited" ascii wide
        $devid2 = "2S8XHJ7948" ascii wide  // Team ID
        $devid3 = "Sawakami LLC" ascii wide
        $devid4 = "Northwest Tech-Con Systems Ltd" ascii wide

        // Code signing context
        $sign1 = "signing_identity" ascii
        $sign2 = "notarization" ascii nocase
        $sign3 = "com.apple.security.cs.disable-library-validation" ascii
        $sign4 = "com.apple.security.cs.allow-unsigned-executable-memory" ascii
        $sign5 = "Developer ID Application" ascii

    condition:
        filesize < 50MB and
        (any of ($devid*)) and
        (any of ($sign*))
}


// ============================================================================
// RULE 10: Mach-O Binary with BlueNoroff Campaign Indicators
// Detects Mach-O binaries containing strings associated with DPRK campaigns
// ============================================================================

rule macOS_BlueNoroff_MachO_Indicators
{
    meta:
        description = "Detects Mach-O binaries containing strings and patterns associated with BlueNoroff/Lazarus macOS campaigns"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
        mitre_attack = "T1553.001, T1543.004, T1071.001"
        confidence = "medium"
        severity = "critical"
        threat_actor = "BlueNoroff/Lazarus"

    strings:
        // Mach-O magic bytes (64-bit)
        $macho_magic1 = { CF FA ED FE }  // Little-endian
        $macho_magic2 = { FE ED FA CF }  // Big-endian
        $macho_fat = { CA FE BA BE }     // Universal binary

        // BlueNoroff C2 domain patterns
        $c2_1 = "linkpc.net" ascii wide
        $c2_2 = "dnx.capital" ascii wide
        $c2_3 = "swissborg.blog" ascii wide
        $c2_4 = "on-offx.com" ascii wide

        // Campaign-specific strings
        $camp1 = "RustBucket" ascii wide
        $camp2 = "HiddenRisk" ascii wide
        $camp3 = "KANDYKORN" ascii wide
        $camp4 = "TodoSwift" ascii wide
        $camp5 = "BeaverTail" ascii wide
        $camp6 = "InvisibleFerret" ascii wide

        // Persistence paths
        $persist1 = "com.apple.systemupdate" ascii wide
        $persist2 = "com.avatar.update.wake" ascii wide
        $persist3 = ".zshenv" ascii wide
        $persist4 = "/Users/Shared/.system/" ascii wide

        // Crypto targeting
        $crypto1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii  // MetaMask extension ID
        $crypto2 = "exodus.wallet" ascii
        $crypto3 = "Chrome Safe Storage" ascii

    condition:
        (any of ($macho_magic*, $macho_fat)) and
        filesize < 50MB and
        (
            (any of ($c2_*) and any of ($persist*)) or
            (any of ($camp*) and any of ($c2_*)) or
            (any of ($c2_*) and any of ($crypto*)) or
            (2 of ($camp*) and any of ($persist*))
        )
}
