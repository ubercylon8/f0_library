/*
    ============================================================
    YARA Rules: Webshell Post-Exploitation Simulation
    Test ID: c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09
    MITRE ATT&CK: T1190, T1059.003
    Platform: Windows
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-03-14
    ============================================================
    These rules detect attack technique behaviors:
      - Webshell script files containing reconnaissance command invocations
      - Batch/script files with webshell discovery command chains
      - Memory-resident strings associated with webshell C2 activity
      - Web-accessible script files with shell execution capabilities
    ============================================================
*/


/*
    ============================================================
    Rule: Webshell_ReconCommandChain_Script
    Confidence: High
    MITRE ATT&CK: T1059.003, T1190
    Description: Detects script files (ASP, ASPX, PHP, JSP, CFML) that contain
                 multiple Windows reconnaissance command strings. Any script file
                 accessible via a web server that can invoke whoami, systeminfo,
                 ipconfig, netstat, or tasklist is a strong webshell indicator.
    ============================================================
*/
rule Webshell_ReconCommandChain_Script
{
    meta:
        description = "Script file containing multiple Windows reconnaissance command invocations - webshell indicator"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09"
        mitre_attack = "T1059.003, T1190"
        confidence = "high"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1059/003/"

    strings:
        // Discovery command names
        $cmd_whoami     = "whoami" ascii wide nocase
        $cmd_systeminfo = "systeminfo" ascii wide nocase
        $cmd_ipconfig   = "ipconfig" ascii wide nocase
        $cmd_netstat    = "netstat" ascii wide nocase
        $cmd_tasklist   = "tasklist" ascii wide nocase
        $cmd_hostname   = "hostname" ascii wide nocase
        $cmd_net_user   = "net user" ascii wide nocase
        $cmd_net_group  = "net group" ascii wide nocase

        // Shell execution sinks in web scripts (hex-encoded to avoid hook false positives)
        // "WScript.Shell"
        $exec_wshell    = { 57 53 63 72 69 70 74 2E 53 68 65 6C 6C }
        // "Process.Start("
        $exec_process   = { 50 72 6F 63 65 73 73 2E 53 74 61 72 74 28 }
        // "cmd.exe /c"
        $exec_cmd_c     = { 63 6D 64 2E 65 78 65 20 2F 63 }
        // "shell_exec("
        $exec_shell_fn  = { 73 68 65 6C 6C 5F 65 78 65 63 28 }
        // "passthru("
        $exec_passthru  = { 70 61 73 73 74 68 72 75 28 }
        // "Runtime.exec("
        $exec_runtime   = { 52 75 6E 74 69 6D 65 2E 65 78 65 63 28 }

        // Web parameter input patterns
        $input_request  = "Request[" ascii wide nocase
        $input_get      = "$_GET[" ascii wide nocase
        $input_post     = "$_POST[" ascii wide nocase
        $input_param    = "getParameter" ascii wide nocase

    condition:
        filesize < 2MB and
        (
            // Web script with shell sink + recon commands + HTTP input
            (
                (any of ($exec_wshell, $exec_process, $exec_cmd_c, $exec_shell_fn, $exec_passthru, $exec_runtime)) and
                (2 of ($cmd_*)) and
                (1 of ($input_*))
            )
            or
            // Script containing 5+ distinct reconnaissance command names
            (
                5 of ($cmd_*)
            )
        )
}


/*
    ============================================================
    Rule: Webshell_CmdShell_InvocationPattern
    Confidence: High
    MITRE ATT&CK: T1059.003
    Description: Detects in-memory strings or script content where cmd.exe is
                 invoked to run reconnaissance tools with characteristic flags
                 (whoami /all, ipconfig /all, netstat -an). The combination of
                 cmd.exe /c with multiple discovery tool argument patterns is a
                 strong behavioral indicator of webshell command execution.
    ============================================================
*/
rule Webshell_CmdShell_InvocationPattern
{
    meta:
        description = "cmd.exe invocation with multiple Windows discovery commands and characteristic flags - webshell execution pattern"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09"
        mitre_attack = "T1059.003"
        confidence = "high"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1059/003/"

    strings:
        // "whoami /all"
        $whoami_all    = { 77 68 6F 61 6D 69 20 2F 61 6C 6C }
        // "whoami /priv"
        $whoami_priv   = { 77 68 6F 61 6D 69 20 2F 70 72 69 76 }
        // "ipconfig /all"
        $ipconfig_all  = { 69 70 63 6F 6E 66 69 67 20 2F 61 6C 6C }
        // "netstat -an"
        $netstat_an    = { 6E 65 74 73 74 61 74 20 2D 61 6E }
        // "netstat -ano"
        $netstat_ano   = { 6E 65 74 73 74 61 74 20 2D 61 6E 6F }
        // "tasklist /v"
        $tasklist_v    = { 74 61 73 6B 6C 69 73 74 20 2F 76 }
        // "tasklist /svc"
        $tasklist_svc  = { 74 61 73 6B 6C 69 73 74 20 2F 73 76 63 }
        // "systeminfo"
        $systeminfo    = "systeminfo" ascii wide nocase
        // "net localgroup administrators"
        $net_localgrp  = "net localgroup administrators" ascii wide nocase
        // "nltest /domain_trusts"
        $nltest_dom    = "nltest /domain_trusts" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            // Three or more specific reconnaissance command-with-flag patterns
            3 of ($whoami_all, $whoami_priv, $ipconfig_all, $netstat_an, $netstat_ano,
                  $systeminfo, $tasklist_v, $tasklist_svc, $nltest_dom, $net_localgrp)
        )
}


/*
    ============================================================
    Rule: Webshell_HTTP_C2_Beacon_Pattern
    Confidence: Medium
    MITRE ATT&CK: T1190
    Description: Detects memory-resident or file-resident strings characteristic
                 of webshell C2 beacon functionality: code that collects system
                 information (hostname, computername) and sends it via HTTP POST.
                 Targets the technique of HTTP POST with machine identification
                 data as beacon payload.
    ============================================================
*/
rule Webshell_HTTP_C2_Beacon_Pattern
{
    meta:
        description = "HTTP POST beacon with system identification payload - webshell C2 callback pattern"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09"
        mitre_attack = "T1190"
        confidence = "medium"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1190/"

    strings:
        // HTTP client types
        $http_webclient   = "WebClient" ascii wide nocase
        $http_httpclient  = "HttpClient" ascii wide nocase
        $http_webrequest  = "HttpWebRequest" ascii wide nocase
        $http_curl        = "curl_exec" ascii wide nocase

        // System identification environment variables
        $sys_computername = "COMPUTERNAME" ascii wide nocase
        $sys_hostname     = "gethostname" ascii wide nocase
        $sys_username     = "USERNAME" ascii wide nocase
        $sys_getenv       = "GetEnvironmentVariable" ascii wide nocase

        // Beacon identification strings
        $beacon_str   = "beacon" ascii wide nocase
        $callback_str = "callback" ascii wide nocase
        $checkin_str  = "checkin" ascii wide nocase
        $implant_str  = "implant" ascii wide nocase

        // Form-encoded content type - used by webshell C2 POST
        $content_form = "application/x-www-form-urlencoded" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            // HTTP client + system info + beacon identification
            (
                (any of ($http_webclient, $http_httpclient, $http_webrequest, $http_curl)) and
                (any of ($sys_computername, $sys_hostname, $sys_username, $sys_getenv)) and
                (any of ($beacon_str, $callback_str, $checkin_str, $implant_str))
            )
            or
            // Form-encoded POST with hostname exfiltration pattern
            (
                $content_form and
                (any of ($sys_computername, $sys_hostname, $sys_username)) and
                (any of ($http_webclient, $http_httpclient, $http_webrequest))
            )
        )
}


/*
    ============================================================
    Rule: Webshell_Generic_FileContent_Indicators
    Confidence: Medium
    MITRE ATT&CK: T1190, T1059.003
    Description: Broad detection for web-accessible files (by extension) that
                 contain command execution capabilities combined with OS
                 enumeration command references. Targets the common webshell
                 pattern of a script that accepts input, invokes OS commands,
                 and returns results to the attacker.
    ============================================================
*/
rule Webshell_Generic_FileContent_Indicators
{
    meta:
        description = "Web script file with OS command execution and enumeration capabilities - generic webshell indicator"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09"
        mitre_attack = "T1190, T1059.003"
        confidence = "medium"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1190/"

    strings:
        // OS command invocation patterns (hex-encoded to prevent hook false positives)
        // "system("
        $exec_system   = { 73 79 73 74 65 6D 28 }
        // "popen("
        $exec_popen    = { 70 6F 70 65 6E 28 }
        // "os.system("
        $exec_os_sys   = { 6F 73 2E 73 79 73 74 65 6D 28 }
        // "subprocess.call("
        $exec_sub_call = { 73 75 62 70 72 6F 63 65 73 73 2E 63 61 6C 6C 28 }
        // "Runtime.getRuntime().exec("
        $exec_java     = { 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 }
        // "Process.Start("
        $exec_proc_st  = { 50 72 6F 63 65 73 73 2E 53 74 61 72 74 28 }
        // "WScript.Shell"
        $exec_wscr     = { 57 53 63 72 69 70 74 2E 53 68 65 6C 6C }
        // "cmd /c "
        $exec_cmd      = { 63 6D 64 20 2F 63 20 }
        // "/bin/sh -c"
        $exec_sh_c     = { 2F 62 69 6E 2F 73 68 20 2D 63 }

        // Windows reconnaissance commands
        $win_recon_1 = "whoami" ascii wide nocase
        $win_recon_2 = "systeminfo" ascii wide nocase
        $win_recon_3 = "ipconfig" ascii wide nocase
        $win_recon_4 = "netstat" ascii wide nocase
        $win_recon_5 = "tasklist" ascii wide nocase
        $win_recon_6 = "net user" ascii wide nocase
        $win_recon_7 = "net group" ascii wide nocase

        // Linux reconnaissance
        $lin_recon_1 = "uname -a" ascii wide nocase
        $lin_recon_2 = "ifconfig" ascii wide nocase
        $lin_recon_3 = "cat /etc/passwd" ascii wide nocase
        $lin_recon_4 = "ps aux" ascii wide nocase

    condition:
        filesize < 1MB and
        (
            // Execution sink + multiple recon commands
            (
                (2 of ($exec_*)) and
                (3 of ($win_recon_*, $lin_recon_*))
            )
            or
            // Single execution sink + dense recon command set
            (
                (1 of ($exec_*)) and
                (4 of ($win_recon_*, $lin_recon_*))
            )
        )
}


/*
    ============================================================
    Rule: Webshell_Encoded_CmdExecution
    Confidence: Medium
    MITRE ATT&CK: T1059.003, T1190
    Description: Detects script files using base64 encoding or obfuscation
                 combined with command execution - a common webshell evasion
                 technique where the actual commands are encoded to avoid
                 simple string-based detection. Particularly relevant for
                 PowerShell-based webshells and PHP obfuscation.
    ============================================================
*/
rule Webshell_Encoded_CmdExecution
{
    meta:
        description = "Script with base64 encoding combined with command execution - obfuscated webshell indicator"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09"
        mitre_attack = "T1059.003"
        confidence = "medium"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1059/003/"

    strings:
        // Base64 decode functions
        $b64_php        = "base64_decode" ascii wide nocase
        $b64_java       = "Base64.decode" ascii wide nocase
        $b64_dotnet     = "Convert.FromBase64String" ascii wide nocase
        $b64_dotnet2    = "FromBase64String" ascii wide nocase
        $b64_ps         = "[System.Convert]::FromBase64String" ascii wide nocase
        $b64_certutil   = "certutil -decode" ascii wide nocase

        // Eval-style execution sinks (hex-encoded)
        // "eval("
        $eval_fn        = { 65 76 61 6C 28 }
        // "IEX"
        $iex_fn         = { 49 45 58 }
        // "Invoke-Expression"
        $invoke_expr    = "Invoke-Expression" ascii wide nocase

        // PowerShell encoded command flags
        $ps_enc1        = "-EncodedCommand" ascii wide nocase
        $ps_enc2        = "-enc " ascii wide nocase

    condition:
        filesize < 2MB and
        (
            // Decode + eval pattern (classic PHP/JS webshell)
            (
                (any of ($b64_php, $b64_java, $b64_dotnet, $b64_dotnet2, $b64_ps, $b64_certutil)) and
                $eval_fn
            )
            or
            // PowerShell encoded command execution
            (
                (any of ($ps_enc1, $ps_enc2)) and
                (any of ($iex_fn, $invoke_expr))
            )
            or
            // PowerShell IEX with base64 decode
            (
                ($iex_fn or $invoke_expr) and
                (any of ($b64_dotnet, $b64_dotnet2, $b64_ps))
            )
        )
}
