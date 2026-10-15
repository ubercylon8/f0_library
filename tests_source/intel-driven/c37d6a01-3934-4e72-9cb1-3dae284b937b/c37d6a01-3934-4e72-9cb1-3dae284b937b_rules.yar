/*
    ============================================================
    YARA Rules: Kothamine Tailcat Encrypted C2 Channel & Exfiltration
    Test ID: c37d6a01-3934-4e72-9cb1-3dae284b937b
    MITRE ATT&CK: T1105, T1572, T1021.004, T1005, T1041
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-10-14
    ============================================================
    Technique-focus note: these rules identify the ABUSED THIRD-PARTY TOOL
    (tailcat / Tailscale components) and its distinctive dangerous
    capability (no-auth-ssh), not F0RT1KA test artifacts. No test paths,
    UUIDs, or harness strings are used. Hash-based identification of the
    pinned release binaries is included as a companion rule — it catches
    the exact tooling Kothamine variants are observed fetching, but must be
    paired with the usage-context rules in the other formats.
    ============================================================
*/

/*
    ============================================================
    YARA Rule: Kothamine_Tailcat_NoAuthSSH_Capability
    Test ID: c37d6a01-3934-4e72-9cb1-3dae284b937b
    MITRE ATT&CK: T1572, T1021.004
    Confidence: High
    Description: Detects binaries carrying tailcat's unauthenticated-SSH
    server capability ("no-auth-ssh") together with tailcat/DERP control
    strings. The no-auth-ssh subcommand exposes an internet-reachable shell
    with NO authentication — its presence in a binary on an endpoint is
    the highest-fidelity static signal of Kothamine C2 tooling.
    ============================================================
*/
rule Kothamine_Tailcat_NoAuthSSH_Capability {
    meta:
        description = "Detects tailcat binaries exposing the unauthenticated 'serve no-auth-ssh' SSH-over-DERP C2 listener capability"
        author = "F0RT1KA"
        date = "2026-10-14"
        test_id = "c37d6a01-3934-4e72-9cb1-3dae284b937b"
        mitre_attack = "T1572, T1021.004"
        confidence = "high"
        reference = "https://github.com/tailscale/tailcat"

    strings:
        $cap1 = "no-auth-ssh" ascii wide nocase
        $cap2 = "serve no-auth-ssh" ascii wide nocase
        $tc1  = "tailcat.dev" ascii wide nocase
        $tc2  = "derpmap.json" ascii wide nocase
        $tc3  = "tailscale/tailcat" ascii wide nocase
        $derp = "DERP" ascii

    condition:
        filesize < 64MB and
        1 of ($cap*) and
        1 of ($tc*)
}

/*
    ============================================================
    YARA Rule: Kothamine_Tailcat_Binary_Generic
    Test ID: c37d6a01-3934-4e72-9cb1-3dae284b937b
    MITRE ATT&CK: T1105
    Confidence: Medium
    Description: Generic identification of a tailcat Go binary (PE or ELF)
    by its embedded module path, CLI subcommand strings, and DERP bootstrap
    references. tailcat is a legitimate OSS tool — this rule should be
    deployed on hosts WITHOUT a sanctioned Tailscale/tailcat deployment,
    where the binary's mere presence indicates ingress tool transfer.
    ============================================================
*/
rule Kothamine_Tailcat_Binary_Generic {
    meta:
        description = "Identifies tailcat (Tailscale) standalone Go binaries by embedded module path, subcommands, and DERP bootstrap strings"
        author = "F0RT1KA"
        date = "2026-10-14"
        test_id = "c37d6a01-3934-4e72-9cb1-3dae284b937b"
        mitre_attack = "T1105"
        confidence = "medium"
        reference = "https://github.com/tailscale/tailcat"

    strings:
        $mod1 = "github.com/tailscale/tailcat" ascii
        $mod2 = "tailscale.com/" ascii
        $sub1 = "no-auth-ssh" ascii
        $sub2 = "recv" ascii
        $sub3 = "Server listening with new address" ascii wide nocase
        $net1 = "tailcat.dev" ascii nocase
        $net2 = "derp" ascii nocase
        $wg1  = "wireguard" ascii nocase

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and  // PE or ELF
        filesize < 64MB and
        (
            $mod1 or
            (1 of ($sub*) and 2 of ($net*, $wg*, $mod2))
        )
}

/*
    ============================================================
    YARA Rule: Kothamine_Tailcat_Pinned_Release_v0_7_0
    Test ID: c37d6a01-3934-4e72-9cb1-3dae284b937b
    MITRE ATT&CK: T1105
    Confidence: High (exact match) / version-fragile by design
    Description: Exact-hash identification of the pinned tailcat v0.7.0
    release binaries (Windows/Linux, amd64/arm64) observed fetched by
    Kothamine tooling. Fragile to version bumps — deploy alongside the
    behavioral rules, not instead of them.
    ============================================================
*/
rule Kothamine_Tailcat_Pinned_Release_v0_7_0 {
    meta:
        description = "Detects the exact pinned tailcat v0.7.0 release binaries by SHA256 (all four platform assets)"
        author = "F0RT1KA"
        date = "2026-10-14"
        test_id = "c37d6a01-3934-4e72-9cb1-3dae284b937b"
        mitre_attack = "T1105"
        confidence = "high"
        reference = "https://github.com/tailscale/tailcat/releases/tag/v0.7.0"
        hash_windows_amd64_archive = "f04cac07e3bf6c700b0b543df0d3315a3b312cd5a05ee76714e1cc848e9b2dff"
        hash_windows_arm64_archive = "1c2d081375ade2365402f9fcf611e89dbb2c5c5ee06936aaff2b205dbe427578"
        hash_linux_amd64_archive   = "23c0b1887a5ec422f0d18a9c52b4f5357815febdaae738a1eb54036d10bd9ee6"
        hash_linux_arm64_archive   = "bbb1ab50f24f00effe1e1fd86d0501803fb80793a90785a2a16ff3428f03d8ef"

    condition:
        hash.sha256(0, filesize) == "f04cac07e3bf6c700b0b543df0d3315a3b312cd5a05ee76714e1cc848e9b2dff" or
        hash.sha256(0, filesize) == "1c2d081375ade2365402f9fcf611e89dbb2c5c5ee06936aaff2b205dbe427578" or
        hash.sha256(0, filesize) == "23c0b1887a5ec422f0d18a9c52b4f5357815febdaae738a1eb54036d10bd9ee6" or
        hash.sha256(0, filesize) == "bbb1ab50f24f00effe1e1fd86d0501803fb80793a90785a2a16ff3428f03d8ef"
}
