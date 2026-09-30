/*
    ============================================================
    F0RT1KA YARA Rules — Star Blizzard RedFlick / CosmicPulse chain
    Test ID: c3b4301e-b502-43a4-9f01-66a874239d1b
    Threat Actor: Star Blizzard (SEABORGIUM/Callisto, FSB-linked)
    MITRE ATT&CK: T1204.002, T1105, T1059.001, T1218.007,
                  T1053.005, T1218.011, T1071.001
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-09-30

    Technique-focused rules: every string below is an artifact of the
    ATTACK TECHNIQUE (LNK cradle construction, ssh LocalCommand abuse,
    cAB base64 embedding in PDFs, masquerading task names, CPL launch
    surface, /agent/poll beacon profile, .mollis registry staging) —
    none are test-framework artifacts.

    Threat-intel context: Microsoft Threat Intelligence, "Star Blizzard
    refines phishing and malware delivery with the RedFlick technique"
    (2026-09-29). Observed campaign C2/download infrastructure (for
    enrichment pivots only — rules are behavioral):
    etia[.]ca, groy[.]cc, muvb[.]net, matjk[.]click, bpdaersa[.]click,
    Itechx[.]tel, guach[.]net, byveo[.]org, cynra[.]top,
    gliderrompercycl[.]com, divekickspolic[.]org, stuseamandesilt[.]org,
    ruten[.]observer, secure-dns-hub[.]com, qumel[.]link, drasw[.]club
    ============================================================
*/

/*
    ============================================================
    YARA Rule: Star Blizzard RedFlick conhost LNK cradle
    Test ID: c3b4301e-b502-43a4-9f01-66a874239d1b
    MITRE ATT&CK: T1204.002 (User Execution: Malicious File)
    Confidence: High
    Description: Weaponized Windows shortcut (.lnk) whose target is
        conhost.exe with the --headless flag (no-window-flash execution of a
        hidden cmd.exe chain), typically icon-masqueraded as a PDF via
        shell32.dll and delivered as a double-extension lure
        (e.g. Event_Invitation.pdf.lnk) inside a password-protected archive.
    ============================================================
*/
rule Star_Blizzard_RedFlick_Conhost_LNK_Cradle
{
    meta:
        description = "RedFlick lure LNK targeting conhost.exe --headless with PDF icon masquerade"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-09-30"
        test_id = "c3b4301e-b502-43a4-9f01-66a874239d1b"
        mitre_attack = "T1204.002"
        confidence = "high"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/"

    strings:
        $conhost_a = "conhost.exe" ascii nocase
        $conhost_w = "conhost.exe" wide nocase
        $headless_a = "--headless" ascii nocase
        $headless_w = "--headless" wide nocase
        $cmd_a = "cmd.exe" ascii nocase
        $cmd_w = "cmd.exe" wide nocase
        $icon_a = "shell32.dll" ascii nocase
        $icon_w = "shell32.dll" wide nocase

    condition:
        // LNK header: HeaderSize 0x76 + LinkCLSID 00021401-...
        uint32(0) == 0x00000076 and
        uint32(4) == 0x00021401 and
        filesize < 1MB and
        // ShowCommand field (offset 60) == 7 (SW_SHOWMINNOACTIVE — hidden)
        uint32(60) == 7 and
        1 of ($conhost_*) and
        1 of ($headless_*) and
        (1 of ($cmd_*) or 1 of ($icon_*))
}

/*
    ============================================================
    YARA Rule: RedFlick weaponized PDF with cAB base64 payload
    Test ID: c3b4301e-b502-43a4-9f01-66a874239d1b
    MITRE ATT&CK: T1059.001 (PowerShell), T1204.002, T1027 (Obfuscation)
    Confidence: High
    Description: PDF document carrying an embedded base64 command after the
        'cAB' magic marker (base64 of 'p'), later extracted by PowerShell via
        regex, [Convert]::FromBase64String-decoded and Invoke-Expression'd.
        The July-variant RedFlick delivery format.
    ============================================================
*/
rule RedFlick_Weaponized_PDF_cAB_Base64_Payload
{
    meta:
        description = "Weaponized PDF embedding a cAB-marked base64 command for PowerShell extraction"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-09-30"
        test_id = "c3b4301e-b502-43a4-9f01-66a874239d1b"
        mitre_attack = "T1059.001,T1204.002"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $eof = "%%EOF" ascii
        // 'cAB' is base64 of the bytes 'p' + high-nibble start; a 24+ char
        // base64 run following it is the hidden command blob
        $b64_cab = /cAB[A-Za-z0-9+\/=]{24,}/ ascii
        $ps_read = "ReadAllText" ascii nocase
        $ps_iex = "Invoke-Expression" ascii nocase

    condition:
        uint32(0) == 0x46445025 and   // "%PDF"
        filesize < 10MB and
        $b64_cab and
        ($eof or $ps_read or $ps_iex)
}

/*
    ============================================================
    YARA Rule: RedFlick ssh.exe PermitLocalCommand transfer cradle
    Test ID: c3b4301e-b502-43a4-9f01-66a874239d1b
    MITRE ATT&CK: T1105 (Ingress Tool Transfer)
    Confidence: High
    Description: Scripts/droppers/build configs embedding the ssh.exe
        download-cradle flag surface: PermitLocalCommand=yes together with
        LocalCommand= carrying a download/execution command (curl.exe,
        certutil, msiexec ...). Catches droppers that build the January
        RedFlick transfer chain regardless of destination host.
    ============================================================
*/
rule RedFlick_SSH_PermitLocalCommand_Cradle
{
    meta:
        description = "ssh.exe PermitLocalCommand/LocalCommand download cradle embedded in dropper script or config"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-09-30"
        test_id = "c3b4301e-b502-43a4-9f01-66a874239d1b"
        mitre_attack = "T1105"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1105/"

    strings:
        $plc_a = "PermitLocalCommand=yes" ascii nocase
        $plc_w = "PermitLocalCommand=yes" wide nocase
        $plc2_a = "PermitLocalCommand yes" ascii nocase
        $lc_a = "LocalCommand=" ascii
        $lc_w = "LocalCommand=" wide
        $curl_a = "curl" ascii nocase
        $ssh_a = "ssh " ascii nocase
        $ssh_path_a = "openssh" ascii nocase

    condition:
        filesize < 2MB and
        1 of ($plc_*) and
        ($plc2_a or 1 of ($lc_*)) and
        ($curl_a or $ssh_a or $ssh_path_a)
}

/*
    ============================================================
    YARA Rule: RedFlick masquerading scheduled-task persistence installer
    Test ID: c3b4301e-b502-43a4-9f01-66a874239d1b
    MITRE ATT&CK: T1053.005 (Scheduled Task), T1036.004 (Masquerade Task Name)
    Confidence: High
    Description: Installers/scripts/batch files registering the RedFlick
        persistence task trio by their REAL adversarial names — "Internet
        Quality Test Connection", "Network Configuration Manager",
        "System Health Monitor" — masquerading as network components with
        DAILY/ONLOGON triggers. Two or more of the three names plus schtasks
        usage is a campaign signature.
    ============================================================
*/
rule RedFlick_Masquerading_Scheduled_Task_Installer
{
    meta:
        description = "Installer creating RedFlick persistence tasks disguised as network components"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-09-30"
        test_id = "c3b4301e-b502-43a4-9f01-66a874239d1b"
        mitre_attack = "T1053.005"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1053/005/"

    strings:
        $schtasks_a = "schtasks" ascii nocase
        $schtasks_w = "schtasks" wide nocase
        $task1 = "Internet Quality Test Connection" ascii wide nocase
        $task2 = "Network Configuration Manager" ascii wide nocase
        $task3 = "System Health Monitor" ascii wide nocase

    condition:
        filesize < 5MB and
        1 of ($schtasks*) and
        2 of ($task1, $task2, $task3)
}

/*
    ============================================================
    YARA Rule: CosmicPulse backdoor / installer markers
    Test ID: c3b4301e-b502-43a4-9f01-66a874239d1b
    MITRE ATT&CK: T1071.001 (Web Protocols), T1218.011
    Confidence: High
    Description: Binaries/scripts carrying the CosmicPulse backdoor profile:
        /agent/poll HTTP polling endpoint, HKCU\\...\\.mollis registry
        payload staging path (AES-ECB encrypted + base64 config), and/or
        staging of python38.zip / bootstrapper.zip archives. Two or more
        markers is a strong backdoor identification for any PE, script or
        config file — independent of build infrastructure.
    ============================================================
*/
rule CosmicPulse_Backdoor_Markers_Poll_Mollis_Py38
{
    meta:
        description = "CosmicPulse backdoor markers: /agent/poll endpoint, .mollis registry staging, python38/bootstrapper staging"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-09-30"
        test_id = "c3b4301e-b502-43a4-9f01-66a874239d1b"
        mitre_attack = "T1071.001,T1218.011"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1071/001/"

    strings:
        $poll_a = "/agent/poll" ascii nocase
        $poll_w = "/agent/poll" wide nocase
        $mollis_a = ".mollis" ascii nocase
        $mollis_w = ".mollis" wide nocase
        $py38_a = "python38.zip" ascii nocase
        $py38_w = "python38.zip" wide nocase
        $boot_a = "bootstrapper.zip" ascii nocase
        $boot_w = "bootstrapper.zip" wide nocase
        $ua_edg = "Edg/" ascii nocase

    condition:
        filesize < 20MB and
        2 of ($poll_*, $mollis_*, $py38_*, $boot_*, $ua_edg)
}

/*
    ============================================================
    YARA Rule: CosmicPulse CPL launch surface script
    Test ID: c3b4301e-b502-43a4-9f01-66a874239d1b
    MITRE ATT&CK: T1218.011 (Rundll32)
    Confidence: Medium
    Description: Scripts/tasks/installers invoking the Control Panel applet
        LOLBin launch surface — rundll32.exe shell32.dll,Control_RunDLL
        (or control.exe) against a .cpl file staged outside System32 — the
        CosmicPulse execution path driven by the "System Health Monitor"
        scheduled task, including WebDAV/UNC variants.
    ============================================================
*/
rule CosmicPulse_Control_RunDLL_CPL_Launcher
{
    meta:
        description = "Script invoking rundll32 shell32.dll,Control_RunDLL or control.exe against a non-System32 .cpl"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-09-30"
        test_id = "c3b4301e-b502-43a4-9f01-66a874239d1b"
        mitre_attack = "T1218.011"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1218/011/"

    strings:
        $crd_a = "Control_RunDLL" ascii nocase
        $crd_w = "Control_RunDLL" wide nocase
        $cpl_a = ".cpl" ascii nocase
        $cpl_w = ".cpl" wide nocase
        $rundll32_a = "rundll32" ascii nocase
        $control_a = "control.exe" ascii nocase
        $shell32_a = "shell32.dll" ascii nocase
        $userpath_a = "appdata" ascii nocase
        $userpath_b = "\\users\\" ascii nocase

    condition:
        filesize < 5MB and
        1 of ($crd_*) and
        1 of ($cpl_*) and
        ($rundll32_a or $control_a or $shell32_a or $userpath_a or $userpath_b)
}

/*
    ============================================================
    YARA Rule: RedFlick malicious MSI with LOLBin custom actions
    Test ID: c3b4301e-b502-43a4-9f01-66a874239d1b
    MITRE ATT&CK: T1218.007 (Msiexec), T1053.005
    Confidence: High
    Description: MSI package (OLE2 compound document) whose custom actions
        invoke command executors or LOLBins — the shape of the RedFlick
        payload MSI fetched by the ssh.exe/curl.exe cradle and installed
        silently with msiexec /q, whose custom actions create the
        persistence scheduled tasks. Legitimate installers rarely shell out
        from custom actions to schtasks/rundll32/script interpreters.
    ============================================================
*/
rule RedFlick_MSI_CustomAction_LOLBin_Executor
{
    meta:
        description = "MSI database with custom actions invoking command executors or LOLBins"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-09-30"
        test_id = "c3b4301e-b502-43a4-9f01-66a874239d1b"
        mitre_attack = "T1218.007,T1053.005"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1218/007/"

    strings:
        $schtasks = "schtasks" ascii wide nocase
        $rundll32 = "rundll32" ascii wide nocase
        $control_cpl = "control.exe" ascii wide nocase
        $cmd = "cmd.exe" ascii wide nocase
        $powershell = "powershell" ascii wide nocase
        $curl = "curl.exe" ascii wide nocase
        $sshcradle = "PermitLocalCommand" ascii wide nocase
        $regadd = "reg add" ascii wide nocase

    condition:
        // OLE2 compound file magic (MSI databases are OLE2 streams)
        uint32(0) == 0xE011CFD0 and
        filesize < 100MB and
        2 of ($schtasks, $rundll32, $control_cpl, $cmd, $powershell, $curl, $sshcradle, $regadd)
}

/*
    ============================================================
    YARA Rule: CosmicPulse registry-staged base64 AES payload blob
    Test ID: c3b4301e-b502-43a4-9f01-66a874239d1b
    MITRE ATT&CK: T1218.011, T1027 (Obfuscated Files or Information)
    Confidence: Medium
    Description: Data blobs exported from the HKCU\\Software\\Classes\\.mollis
        registry staging key (or recovered copies): a long pure-base64 string
        that decodes to AES-block-aligned ciphertext (multiple of 16 bytes,
        min 2 blocks) — the CosmicPulse bootstrapper's embedded-key
        encrypted configuration. Pure base64 of >= 88 chars mapping to a
        block-aligned ciphertext is the behavioral shape, with the .mollis
        reference as the campaign identifier.
    ============================================================
*/
rule CosmicPulse_Mollis_Registry_Base64_AES_Blob
{
    meta:
        description = "Base64-encoded AES-block-aligned payload as staged in the .mollis registry key"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-09-30"
        test_id = "c3b4301e-b502-43a4-9f01-66a874239d1b"
        mitre_attack = "T1218.011,T1027"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1218/011/"

    strings:
        // 88+ chars of pure base64 (decodes to >=64 bytes, i.e. >=4 AES blocks)
        $b64_blob = /[A-Za-z0-9+\/]{88,}={0,2}/ ascii
        $mollis_a = ".mollis" ascii nocase
        $mollis_w = ".mollis" wide nocase
        $classes_a = "Software\\Classes" ascii nocase

    condition:
        filesize < 2MB and
        $b64_blob and
        (1 of ($mollis_*) or $classes_a)
}
