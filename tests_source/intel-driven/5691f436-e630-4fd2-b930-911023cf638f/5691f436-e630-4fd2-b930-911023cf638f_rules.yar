/*
    ============================================================
    APT34 Exchange Server Weaponization - YARA Rules
    Test ID: 5691f436-e630-4fd2-b930-911023cf638f
    MITRE ATT&CK: T1505.003, T1071.003, T1556.002, T1048.003
    Threat Actor: APT34 / OilRig / Hazel Sandstorm
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    ============================================================

    These rules detect APT34 tooling artifacts including CacheHttp.dll
    IIS backdoor modules, PowerExchange email-based C2 scripts,
    password filter DLLs, and STEALHOOK exfiltration patterns.

    FOCUS: Technique-inherent artifacts only. No test framework strings.

    Usage:
        yara -r 5691f436-e630-4fd2-b930-911023cf638f_rules.yar /path/to/scan

    ============================================================
*/


/*
    ============================================================
    Rule: APT34_CacheHttp_IIS_Backdoor
    Confidence: High
    Description: Detects CacheHttp.dll IIS backdoor module used by APT34.
                 Matches PE DLLs that export IIS CHttpModule interface
                 methods (RegisterModule, OnBeginRequest, etc.) and contain
                 IIS interception-related strings.
    ============================================================
*/
rule APT34_CacheHttp_IIS_Backdoor
{
    meta:
        description = "Detects APT34 CacheHttp.dll IIS backdoor module with CHttpModule exports"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "5691f436-e630-4fd2-b930-911023cf638f"
        mitre_attack = "T1505.003"
        confidence = "high"
        threat_actor = "APT34"
        reference = "https://attack.mitre.org/groups/G0049/"

    strings:
        // DLL name indicators
        $name1 = "CacheHttp.dll" ascii wide nocase
        $name2 = "CacheHttp" ascii wide

        // IIS CHttpModule interface exports
        $export1 = "RegisterModule" ascii
        $export2 = "OnBeginRequest" ascii
        $export3 = "OnEndRequest" ascii
        $export4 = "OnAuthenticateRequest" ascii
        $export5 = "OnSendResponse" ascii
        $export6 = "GetHttpModule" ascii

        // HTTP interception patterns characteristic of passive IIS backdoors
        $http1 = "X-Cache-Http" ascii wide
        $http2 = "/ews/exchange.asmx" ascii wide
        $http3 = "/owa/auth/logon.aspx" ascii wide
        $http4 = "CacheHttpModule" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 5MB and
        (
            // High confidence: DLL name + IIS module exports
            (any of ($name*) and 3 of ($export*)) or
            // High confidence: IIS exports + HTTP interception patterns
            (3 of ($export*) and any of ($http*)) or
            // Critical: Specific HTTP header used for command delivery
            ($http1 and any of ($export*))
        )
}


/*
    ============================================================
    Rule: APT34_IIS_Backdoor_Generic
    Confidence: Medium
    Description: Generic detection for IIS native module backdoors.
                 Detects PE DLLs with IIS module registration patterns
                 that are not legitimate Microsoft IIS components.
    ============================================================
*/
rule APT34_IIS_Backdoor_Generic
{
    meta:
        description = "Detects generic IIS native module backdoor patterns"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "5691f436-e630-4fd2-b930-911023cf638f"
        mitre_attack = "T1505.003"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1505/003/"

    strings:
        // IIS native module required exports
        $req1 = "RegisterModule" ascii
        $req2 = "GetHttpModule" ascii

        // IIS event handlers (CHttpModule interface)
        $handler1 = "OnBeginRequest" ascii
        $handler2 = "OnAuthenticateRequest" ascii
        $handler3 = "OnPostAuthenticateRequest" ascii
        $handler4 = "OnAuthorizeRequest" ascii
        $handler5 = "OnSendResponse" ascii
        $handler6 = "OnEndRequest" ascii
        $handler7 = "OnResolveRequestCache" ascii
        $handler8 = "OnMapRequestHandler" ascii

        // IIS API imports
        $api1 = "httpserv.h" ascii wide
        $api2 = "IHttpContext" ascii wide
        $api3 = "IHttpRequest" ascii wide
        $api4 = "IHttpResponse" ascii wide

        // Suspicious behavioral strings (command execution, data exfil)
        $sus1 = "cmd.exe" ascii wide
        $sus2 = "powershell" ascii wide nocase
        $sus3 = "base64" ascii wide nocase
        $sus4 = "WScript.Shell" ascii wide
        $sus5 = "exec" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        // Must have IIS registration export
        ($req1 or $req2) and
        // Must have at least 2 event handlers
        2 of ($handler*) and
        // And suspicious behavior indicators
        (any of ($sus*) or any of ($api*))
}


/*
    ============================================================
    Rule: APT34_PowerExchange_Script
    Confidence: High
    Description: Detects APT34 PowerExchange email-based C2 backdoor.
                 PowerExchange is a PowerShell script that monitors
                 Exchange mailboxes for emails with @@ subject markers.
    ============================================================
*/
rule APT34_PowerExchange_Script
{
    meta:
        description = "Detects APT34 PowerExchange email-based C2 PowerShell backdoor"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "5691f436-e630-4fd2-b930-911023cf638f"
        mitre_attack = "T1071.003"
        confidence = "high"
        threat_actor = "APT34"

    strings:
        // PowerExchange C2 marker pattern
        $marker1 = "@@" ascii wide
        $marker2 = "$C2_MARKER" ascii wide

        // EWS interaction patterns
        $ews1 = "Exchange.asmx" ascii wide nocase
        $ews2 = "ExchangeService" ascii wide
        $ews3 = "New-WebServiceProxy" ascii wide nocase
        $ews4 = "Get-MailboxMessage" ascii wide nocase
        $ews5 = "Search-Mailbox" ascii wide nocase
        $ews6 = "EWS" ascii wide

        // C2 behavioral patterns
        $c2_1 = "Start-Sleep" ascii wide nocase
        $c2_2 = "Invoke-Expression" ascii wide nocase
        $c2_3 = "while ($true)" ascii wide nocase
        $c2_4 = "Send-MailMessage" ascii wide nocase
        $c2_5 = "Subject" ascii wide

        // PowerExchange specific
        $pe1 = "PowerExchange" ascii wide nocase
        $pe2 = "poll" ascii wide nocase
        $pe3 = "mailbox" ascii wide nocase

    condition:
        filesize < 1MB and
        (
            // Definitive: PowerExchange name + C2 markers
            ($pe1 and $marker1) or
            // High confidence: @@ marker + EWS access + C2 loop
            ($marker1 and any of ($ews*) and any of ($c2*)) or
            // Medium confidence: EWS access + command execution + sleep loop
            (2 of ($ews*) and $c2_2 and $c2_3) or
            // High confidence: Email subject matching + command execution
            ($c2_5 and $marker1 and ($c2_2 or $c2_4))
        )
}


/*
    ============================================================
    Rule: APT34_PasswordFilter_DLL
    Confidence: High
    Description: Detects password filter DLLs designed to intercept
                 cleartext credentials during password change operations.
                 Password filters export InitializeChangeNotify,
                 PasswordChangeNotify, and PasswordFilter functions.
    ============================================================
*/
rule APT34_PasswordFilter_DLL
{
    meta:
        description = "Detects password filter DLLs for credential interception (T1556.002)"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "5691f436-e630-4fd2-b930-911023cf638f"
        mitre_attack = "T1556.002"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1556/002/"

    strings:
        // Required password filter exports (Windows LSA interface)
        $export1 = "InitializeChangeNotify" ascii
        $export2 = "PasswordChangeNotify" ascii
        $export3 = "PasswordFilter" ascii

        // Credential logging/exfiltration indicators
        $log1 = "password" ascii wide nocase
        $log2 = "credential" ascii wide nocase
        $log3 = "WriteFile" ascii wide
        $log4 = "CreateFile" ascii wide
        $log5 = "logfile" ascii wide nocase
        $log6 = "cleartext" ascii wide nocase

        // Network exfiltration indicators
        $net1 = "WinHttpOpen" ascii wide
        $net2 = "InternetOpen" ascii wide
        $net3 = "WSAStartup" ascii wide
        $net4 = "send" ascii wide
        $net5 = "socket" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        // Must export the password filter interface
        (2 of ($export*)) and
        // And have logging or exfiltration capability
        (any of ($log*) or any of ($net*))
}


/*
    ============================================================
    Rule: APT34_PasswordFilter_DLL_Simple
    Confidence: Medium
    Description: Simplified detection for DLLs that implement the password
                 filter interface without additional behavioral indicators.
                 Useful for catching minimalist implementations.
    ============================================================
*/
rule APT34_PasswordFilter_DLL_Simple
{
    meta:
        description = "Detects DLLs exporting password filter interface functions"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "5691f436-e630-4fd2-b930-911023cf638f"
        mitre_attack = "T1556.002"
        confidence = "medium"

    strings:
        $export1 = "InitializeChangeNotify" ascii
        $export2 = "PasswordChangeNotify" ascii
        $export3 = "PasswordFilter" ascii

        // Exclude known legitimate password filters
        $legit1 = "Microsoft Corporation" ascii wide
        $legit2 = "scecli" ascii wide
        $legit3 = "FVENOTIFY" ascii wide
        $legit4 = "kdcsvc" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        all of ($export*) and
        none of ($legit*)
}


/*
    ============================================================
    Rule: APT34_STEALHOOK_ExfilEmail
    Confidence: Medium
    Description: Detects STEALHOOK-style email artifacts used for data
                 exfiltration via email attachments. Matches .eml files
                 with multipart MIME structure and base64-encoded
                 attachment payloads following sequential naming patterns.
    ============================================================
*/
rule APT34_STEALHOOK_ExfilEmail
{
    meta:
        description = "Detects STEALHOOK-style exfiltration email artifacts with binary attachments"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "5691f436-e630-4fd2-b930-911023cf638f"
        mitre_attack = "T1048.003"
        confidence = "medium"
        threat_actor = "APT34"

    strings:
        // MIME multipart structure
        $mime1 = "MIME-Version: 1.0" ascii nocase
        $mime2 = "multipart/mixed" ascii nocase
        $mime3 = "Content-Transfer-Encoding: base64" ascii nocase

        // Sequential exfiltration subject patterns
        $subj1 = /Subject:.*Part \d+ of \d+/ ascii nocase
        $subj2 = /Subject:.*Report.*Part/ ascii nocase

        // Attachment patterns
        $attach1 = "application/octet-stream" ascii nocase
        $attach2 = "Content-Disposition: attachment" ascii nocase
        $attach3 = /filename="report_part_\d+/ ascii nocase

        // Service account sender patterns
        $sender1 = /From:.*svc-/ ascii nocase
        $sender2 = /From:.*service/ ascii nocase

    condition:
        filesize < 10MB and
        (
            // High confidence: Sequential subject + binary attachment
            (any of ($subj*) and $attach1 and $mime3) or
            // Medium confidence: Service account + binary attachment + MIME
            (any of ($sender*) and $attach2 and $mime1 and $mime3) or
            // High confidence: Report part filename pattern
            ($attach3 and $mime3)
        )
}


/*
    ============================================================
    Rule: APT34_PowerExchange_C2_Email
    Confidence: High
    Description: Detects C2 command emails with @@ subject markers,
                 the distinctive PowerExchange C2 communication pattern.
    ============================================================
*/
rule APT34_PowerExchange_C2_Email
{
    meta:
        description = "Detects PowerExchange C2 emails with @@ subject markers"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "5691f436-e630-4fd2-b930-911023cf638f"
        mitre_attack = "T1071.003"
        confidence = "high"
        threat_actor = "APT34"

    strings:
        // @@ C2 marker in subject line followed by base64
        $c2_subject = /Subject:.*@@[A-Za-z0-9+\/=]{4,}/ ascii

        // Reply pattern (C2 response)
        $reply = /Subject:.*Re:.*@@/ ascii

        // Email header structure
        $header1 = "From:" ascii
        $header2 = "To:" ascii
        $header3 = "Message-ID:" ascii

    condition:
        filesize < 5MB and
        ($header1 and $header2) and
        (any of ($c2_subject, $reply))
}


/*
    ============================================================
    Rule: IIS_Module_Registration_Config
    Confidence: Medium
    Description: Detects IIS module registration configuration files
                 (applicationHost.config fragments or XML configs)
                 that register suspicious native modules.
    ============================================================
*/
rule IIS_Module_Registration_Config
{
    meta:
        description = "Detects suspicious IIS module registration XML configuration"
        author = "F0RT1KA Defense Guidance Builder"
        date = "2026-03-13"
        test_id = "5691f436-e630-4fd2-b930-911023cf638f"
        mitre_attack = "T1505.003"
        confidence = "medium"

    strings:
        // IIS configuration elements
        $xml1 = "<system.webServer>" ascii wide nocase
        $xml2 = "<globalModules>" ascii wide nocase
        $xml3 = "<modules>" ascii wide nocase
        $xml4 = "install module" ascii wide nocase

        // Suspicious module names
        $mod1 = "CacheHttp" ascii wide nocase
        $mod2 = "HttpProxy" ascii wide nocase
        $mod3 = "WebCache" ascii wide nocase

        // appcmd.exe registration pattern
        $cmd1 = "appcmd.exe" ascii wide nocase
        $cmd2 = "/name:" ascii wide
        $cmd3 = "/image:" ascii wide

    condition:
        filesize < 1MB and
        (
            // XML config with suspicious module registration
            (any of ($xml*) and any of ($mod*)) or
            // appcmd.exe command with module installation
            ($cmd1 and $cmd2 and $cmd3)
        )
}
