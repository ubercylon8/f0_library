/*
   YARA Rules — Mini Shai-Hulud npm Supply Chain Kill Chain
   UUID: ae9002e4-3d82-4fcd-8b45-f7e0628f7375
   Platform: Linux (developer workstation / CI runner)

   These rules target REAL campaign indicators (obfuscated npm loaders, Bun
   staging scripts, exfil markers), not F0RT1KA test artifacts. The F0RT1KA
   simulation files carry an "F0RT1KA SIMULATION" marker and are excluded.
*/

rule ShaiHulud_NPM_Obfuscated_Loader
{
    meta:
        description = "Mini Shai-Hulud obfuscated npm preinstall loader (index.js)"
        author = "sectest-builder"
        technique = "T1195.002, T1059.007"
        reference = "https://socket.dev/blog/mini-shai-hulud-campaign-hits-red-hat-cloud-services-npm-packages"
        severity = "critical"
    strings:
        $charcode  = /\[\s*\d{1,3}\s*(,\s*\d{1,3}\s*){8,}\]\s*\.map\s*\(/
        $decipher  = "createDecipheriv" ascii
        $aesgcm    = "aes-128-gcm" ascii
        $authtag   = "setAuthTag" ascii
        $marker1   = "thebeautifulmarchoftime" ascii
        $marker2   = "f4abccab2" ascii
        $sim       = "F0RT1KA SIMULATION" ascii
    condition:
        not $sim and
        (($charcode and ($decipher or $aesgcm)) or $authtag and $aesgcm or any of ($marker*))
}

rule ShaiHulud_Bun_Runtime_Staging
{
    meta:
        description = "Mini Shai-Hulud Bun runtime download/extract staging"
        author = "sectest-builder"
        technique = "T1105, T1059.004"
        severity = "high"
    strings:
        $url    = "github.com/oven-sh/bun/releases/download" ascii
        $bunzip = /bun-(linux|darwin)-(x64|aarch64)\.zip/ ascii
        $curl   = "curl -sSL" ascii
        $unzip  = "unzip -j -o" ascii
        $tmpdir = /\/tmp\/b-[A-Za-z0-9]+/ ascii
        $sim    = "F0RT1KA SIMULATION" ascii
    condition:
        not $sim and (($url and ($curl or $unzip)) or ($bunzip and $tmpdir))
}

rule ShaiHulud_Credential_Harvester
{
    meta:
        description = "Mini Shai-Hulud credential/secret harvesting target list"
        author = "sectest-builder"
        technique = "T1552.001, T1552.004, T1552.005"
        severity = "critical"
    strings:
        $aws   = ".aws/credentials" ascii
        $ssh   = /\.ssh\/id_(rsa|ed25519)/ ascii
        $npm   = ".npmrc" ascii
        $gh     = "gh auth token" ascii
        $meta  = "169.254.169.254" ascii
        $ghtok = /gh[op]_[A-Za-z0-9]{20,}/ ascii
        $npmtok = /npm_[A-Za-z0-9]{20,}/ ascii
        $sim   = "F0RT1KA SIMULATION" ascii
        $decoy = "shaihulud_decoys" ascii
    condition:
        not ($sim or $decoy) and 4 of ($aws, $ssh, $npm, $gh, $meta, $ghtok, $npmtok)
}

rule ShaiHulud_Exfil_Markers
{
    meta:
        description = "Mini Shai-Hulud exfiltration channel + GitHub fallback markers"
        author = "sectest-builder"
        technique = "T1071.001, T1041, T1567.001"
        severity = "critical"
    strings:
        $c2     = "api.anthropic.com:443/v1/api" ascii
        $ua     = "python-requests/2.31.0" ascii
        $commit = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner" ascii
        $rsaoaep = "RSA_PKCS1_OAEP_PADDING" ascii
        $aes256 = "aes-256-gcm" ascii
        $sim    = "F0RT1KA SIMULATION" ascii
    condition:
        not $sim and ($commit or ($c2 and $ua) or ($rsaoaep and $aes256 and $ua))
}

rule ShaiHulud_Worm_Propagation
{
    meta:
        description = "Mini Shai-Hulud worm repo/workflow injection indicators"
        author = "sectest-builder"
        technique = "T1567.001, T1080"
        severity = "high"
    strings:
        $wf1   = ".github/workflows/codeql.yml" ascii
        $wf2   = ".github/setup.js" ascii
        $npmsearch = "registry.npmjs.org/-/v1/search?text=maintainer:" ascii
        $npmtok    = "registry.npmjs.org/-/npm/v1/tokens" ascii
        $oidc      = "/-/npm/v1/oidc/token/exchange/package/" ascii
        $sim   = "F0RT1KA SIMULATION" ascii
    condition:
        not $sim and 2 of ($wf1, $wf2, $npmsearch, $npmtok, $oidc)
}

rule ShaiHulud_Lockfile_Canary
{
    meta:
        description = "Mini Shai-Hulud duplicate-run canary + daemon marker"
        author = "sectest-builder"
        technique = "T1480.001, T1497.001"
        severity = "medium"
    strings:
        $lock   = "tmp.0987654321.lock" ascii
        $daemon = "__IS_DAEMON" ascii
        $miasma = "Miasma: The Spreading Blight" ascii
    condition:
        any of them
}
