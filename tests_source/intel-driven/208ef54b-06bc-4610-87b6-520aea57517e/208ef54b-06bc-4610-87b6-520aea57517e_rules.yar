/*
    YARA Rules — ScreenConnect Unsanctioned RMM Abuse for Third-Party Access
    UUID:       208ef54b-06bc-4610-87b6-520aea57517e
    Techniques: T1199, T1219, T1543.003, T1567.002
    Actor:      Black Basta (RMM abuse; CVE-2024-1709 mass exploitation)

    IMPORTANT — presence != malice:
      ScreenConnect is a legitimate, vendor-signed RMM. These rules are for
      ASSET INVENTORY / UNSANCTIONED-RMM HUNTING, not for blocking the vendor
      product. A match means "a ScreenConnect access agent is present/staged
      here" — triage against your list of hosts sanctioned to run it. If this
      host is NOT authorized for ScreenConnect, treat as high-signal.

    These rules deliberately do NOT pin the vendor's Authenticode hash/cert.
*/

import "pe"


rule ScreenConnect_Access_Agent_Config
{
    meta:
        description = "ScreenConnect access agent binary/config markers (unsanctioned-RMM hunting)"
        author      = "sectest-builder"
        technique   = "T1219"
        uuid        = "208ef54b-06bc-4610-87b6-520aea57517e"
        severity    = "medium"
        note        = "Presence indicator only — triage against sanctioned-RMM inventory"

    strings:
        $s1 = "ScreenConnect Client" ascii wide
        $s2 = "ScreenConnect.ClientService" ascii wide
        $s3 = "ScreenConnect.WindowsClient" ascii wide
        $s4 = "e=Access&y=Guest" ascii wide          // access-agent relay session params
        $s5 = "&h=" ascii wide                        // relay host param in agent config
        $relay1 = "relay.screenconnect.com" ascii wide
        $relay2 = ".screenconnect.com" ascii wide

    condition:
        // Two agent markers, or an agent marker plus an embedded relay host.
        (2 of ($s*)) or (1 of ($s*) and 1 of ($relay*))
}


rule ScreenConnect_Client_Service_MSI
{
    meta:
        description = "ScreenConnect Client MSI installer package (RMM install artifact)"
        author      = "sectest-builder"
        technique   = "T1219, T1543.003"
        uuid        = "208ef54b-06bc-4610-87b6-520aea57517e"
        severity    = "medium"
        note        = "Flags a ScreenConnect access-agent MSI staged on disk (e.g. dropped to a scratch dir for silent install)"

    strings:
        $msi_magic = { D0 CF 11 E0 A1 B1 1A E1 }      // OLE/MSI compound-file header
        $sc1 = "ScreenConnect Client" ascii wide
        $sc2 = "ScreenConnect.ClientSetup" ascii wide
        $sc3 = "ScreenConnect" ascii wide

    condition:
        $msi_magic at 0 and 2 of ($sc*)
}


rule Unsanctioned_RMM_Staged_In_Scratch_Dir
{
    meta:
        description = "RMM installer staged in a non-standard scratch directory then silent-installed"
        author      = "sectest-builder"
        technique   = "T1219"
        uuid        = "208ef54b-06bc-4610-87b6-520aea57517e"
        severity    = "high"
        note        = "Behavioral: RMM package + msiexec /qn strings co-located (loader / drop scripts)"

    strings:
        $rmm1 = "ScreenConnect" ascii wide
        $rmm2 = "screenconnect-setup" ascii wide
        $silent1 = "msiexec" ascii wide
        $silent2 = "/qn" ascii wide
        $silent3 = "/quiet" ascii wide

    condition:
        1 of ($rmm*) and 2 of ($silent*)
}


rule RMM_Followon_Collection_Archive
{
    meta:
        description = "Collected-data archive staged for exfil over an RMM foothold (T1567.002)"
        author      = "sectest-builder"
        technique   = "T1567.002"
        uuid        = "208ef54b-06bc-4610-87b6-520aea57517e"
        severity    = "low"
        note        = "Generic collection-staging heuristic; tune to your environment. Low severity by design."

    strings:
        $zip_magic = { 50 4B 03 04 }
        $c1 = "collected_export" ascii wide
        $c2 = "shared_finance_export" ascii wide
        $c3 = "_DECOY" ascii wide                    // F0RT1KA lab decoy marker (test validation)

    condition:
        $zip_magic at 0 and 1 of ($c*)
}
