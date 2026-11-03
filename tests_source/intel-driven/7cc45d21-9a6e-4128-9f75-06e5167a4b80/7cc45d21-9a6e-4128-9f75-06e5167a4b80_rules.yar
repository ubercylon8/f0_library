/*
    ============================================================
    The Gentlemen (GOLD SHERWOOD) — GPO-Driven LOLBin Intrusion
    YARA Rules — file/artifact content signatures
    Test ID: 7cc45d21-9a6e-4128-9f75-06e5167a4b80
    Techniques: T1518.001, T1087, T1036, T1219, T1484.001,
                T1053.005, T1136.001
    Actor: The Gentlemen (GOLD SHERWOOD) — ransomware operator
    Sources: Trend Micro, Sophos CTU, Huntress (2025)
    Generated: 2026-11-02
    Scope: content signatures for deployment artifacts (Velociraptor
           client config/writeback), GPO PReg policy abuse, actor-style
           recon/deployment scripts, and masqueraded scheduled-task XML.
           Pure process/network behaviors are covered by the KQL/Sigma/
           EQL/LC-D&R companion rule sets.
    ============================================================
*/

rule Gentlemen_Velociraptor_Client_Config
{
    meta:
        description = "Velociraptor client configuration file (client.config.yaml) — a deployment artifact of the Velociraptor DFIR client; The Gentlemen repurposes Velociraptor as its C2. Flag on endpoints with no sanctioned DFIR deployment."
        technique = "T1219"
        actor = "The Gentlemen (GOLD SHERWOOD)"
        confidence = "high"
        false_positives = "Sanctioned incident-response/DFIR Velociraptor deployments; allowlist approved hosts and operator accounts"
        reference = "Trend Micro: Unmasking The Gentlemen Ransomware (2025)"
        test_id = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
        date = "2026-11-02"
        author = "sectest-builder"

    strings:
        $client   = "Client:" ascii
        $nonce    = "nonce:" ascii
        $writeback = "writeback:" ascii
        $maxpoll  = "max_poll:" ascii
        $urls     = "server_urls:" ascii
        $ca       = "ca_certificate:" ascii
        $pem      = "-----BEGIN CERTIFICATE-----" ascii
        $pinned   = "pinned_server_name:" ascii
        $pinnedgw = "pinned_gw_name:" ascii
        $vrp      = "Velociraptor" ascii wide nocase

    condition:
        filesize < 64KB and
        uint16(0) != 0x5A4D and
        4 of them
}

rule Gentlemen_Velociraptor_Client_Writeback
{
    meta:
        description = "Velociraptor client.writeback state file — JSON carrying a C.<hex> client_id and last_server_pem/hunt fields; presence where no sanctioned Velociraptor deployment exists indicates an unsanctioned remote-access client."
        technique = "T1219"
        actor = "The Gentlemen (GOLD SHERWOOD)"
        confidence = "high"
        false_positives = "Sanctioned Velociraptor DFIR clients; allowlist approved hosts"
        reference = "Trend Micro: Unmasking The Gentlemen Ransomware (2025)"
        test_id = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
        date = "2026-11-02"
        author = "sectest-builder"

    strings:
        $id1 = "\"client_id\": \"C." ascii
        $id2 = "client_id" ascii
        $wb1 = "last_server_pem" ascii
        $wb2 = "last_hunt_timestamp" ascii
        $wb3 = "last_event_table_version" ascii
        $wb4 = "last_server_version" ascii
        $vrp = "Velociraptor" ascii wide nocase

    condition:
        filesize < 16KB and
        uint16(0) != 0x5A4D and
        1 of ($id1, $id2) and
        2 of ($wb1, $wb2, $wb3, $wb4)
}

rule Windows_GPO_PReg_Policy_Deployment_Abuse
{
    meta:
        description = "PReg-format Registry.pol (PReg header + UTF-16LE [key;value;type;size;data] records) whose policy content deploys payloads — Run-key persistence, NETLOGON script references, or Temp-path binaries inside Group Policy registry settings."
        technique = "T1484.001"
        actor = "The Gentlemen (GOLD SHERWOOD) — also SharpGPOAbuse/GPO abuse tooling generally"
        confidence = "medium"
        false_positives = "Legitimate GPOs do contain Run keys and NETLOGON script references; review fires on on-write events in SYSVOL from non-GPMC initiators"
        reference = "Trend Micro / Sophos CTU GPO deployment observations (2025)"
        test_id = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
        date = "2026-11-02"
        author = "sectest-builder"

    strings:
        $preg     = { 50 52 65 67 00 5B }                       // "PReg\x00["
        $runkey   = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide nocase
        $runonce  = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide nocase
        $netlogon = "NETLOGON" wide nocase
        $temp     = "C:\\Windows\\Temp" wide nocase
        $pubdir   = "\\Users\\Public" wide nocase

    condition:
        filesize < 1MB and
        $preg at 0 and
        1 of ($runkey, $runonce, $netlogon, $temp, $pubdir)
}

rule Gentlemen_Mass_Account_EDR_Recon_Script
{
    meta:
        description = "Actor-style mass-enumeration script (The Gentlemen's 1.bat shape): net user/group /domain sweeps over domain admins and enterprise admins, __vmware__ localgroup enumeration, tasklist|findstr EDR hunting and SecurityCenter2 AV queries in one script."
        technique = "T1087, T1518.001, T1082"
        actor = "The Gentlemen (GOLD SHERWOOD)"
        confidence = "high"
        false_positives = "VMware admin runbooks and AD audit scripts; __vmware__ group enumeration is near-zero in legitimate tooling"
        reference = "Trend Micro: Unmasking The Gentlemen Ransomware (2025)"
        test_id = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
        date = "2026-11-02"
        author = "sectest-builder"

    strings:
        $u1 = "net user" ascii wide nocase
        $u2 = "/domain" ascii wide nocase
        $g1 = "domain admins" ascii wide nocase
        $g2 = "Enterprise admins" ascii wide nocase
        $g3 = "localgroup administrators" ascii wide nocase
        $vm = "__vmware__" ascii wide nocase
        $t1 = "tasklist" ascii wide nocase
        $t2 = "findstr" ascii wide nocase
        $av1 = "SecurityCenter2" ascii wide nocase
        $av2 = "AntiVirusProduct" ascii wide nocase
        $d1 = "PDCEmulator" ascii wide nocase
        $d2 = "Get-ADDomain" ascii wide nocase

    condition:
        filesize < 256KB and
        uint16(0) != 0x5A4D and
        ( 3 of ($u1, $u2, $g1, $g2, $g3) or
          ( $vm and 1 of ($u1, $u2, $g1, $g2, $g3, $t1) ) or
          ( 1 of ($av1, $av2) and 2 of ($u1, $u2, $g1, $g2, $g3, $d1, $d2) ) )
}

rule Gentlemen_NETLOGON_Deployment_Script
{
    meta:
        description = "Domain-wide deployment/persistence script shape: launchers referencing the NETLOGON share with embedded --password keys (actor IO), avkill.bat references, service/task creation with /ru SYSTEM, or net user /add + localgroup administrators escalation."
        technique = "T1484.001, T1136.001, T1053.005, T1543.003"
        actor = "The Gentlemen (GOLD SHERWOOD)"
        confidence = "high"
        false_positives = "Legacy domain logon scripts — allowlist approved script names and deployment accounts"
        reference = "Trend Micro / Sophos CTU NETLOGON deployment observations (2025)"
        test_id = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
        date = "2026-11-02"
        author = "sectest-builder"

    strings:
        $nl  = "NETLOGON" ascii wide nocase
        $pw  = "--password" ascii wide nocase
        $av  = "avkill" ascii wide nocase
        $n1  = "net user" ascii wide nocase
        $n2  = "/add" ascii wide nocase
        $lg  = "localgroup administrators" ascii wide nocase
        $st  = "schtasks" ascii wide nocase
        $sys = "/ru SYSTEM" ascii wide nocase
        $sc  = "sc create" ascii wide nocase

    condition:
        filesize < 256KB and
        uint16(0) != 0x5A4D and
        $nl and
        ( $av or $pw or 2 of ($n1, $n2, $lg, $st, $sys, $sc) )
}

rule Gentlemen_Masqueraded_Scheduled_Task_XML
{
    meta:
        description = "Scheduled-task definition XML (C:\\Windows\\System32\\Tasks\\*) with masquerade indicators: the actor's fake Windows task name WindowsConnSvc, the fake binary name svchost32.exe, or a Temp/Public-path binary run as SYSTEM on a 1-2 minute interval."
        technique = "T1053.005"
        actor = "The Gentlemen (GOLD SHERWOOD)"
        confidence = "high"
        false_positives = "None expected — minute-frequency SYSTEM tasks launching from Temp are not legitimate IT practice"
        reference = "Huntress: The Gentlemen ransomware defense-evasion TTPs (2025)"
        test_id = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
        date = "2026-11-02"
        author = "sectest-builder"

    strings:
        $xml  = "<Task" ascii
        $xml2 = "</Task>" ascii
        $n1   = "WindowsConnSvc" ascii wide nocase      // actor masqueraded task name — not a real Windows task
        $b1   = "svchost32" ascii wide nocase           // actor masqueraded binary — not a real Windows binary
        $tmp  = "C:\\Windows\\Temp" ascii wide nocase
        $pub  = "\\Users\\Public" ascii wide nocase
        $sys1 = "S-1-5-18" ascii
        $sys2 = ">SYSTEM<" ascii
        $iv1  = "PT1M" ascii
        $iv2  = "PT2M" ascii

    condition:
        filesize < 128KB and
        2 of ($xml, $xml2) and
        ( $n1 or $b1 or
          ( 1 of ($tmp, $pub) and 1 of ($sys1, $sys2) and 1 of ($iv1, $iv2) ) )
}
