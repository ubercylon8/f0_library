<#
.SYNOPSIS
    Installs Tailscale and enrolls a Windows endpoint into a tailnet from the command line.

.DESCRIPTION
    Idempotent enrollment helper:
      1. Self-elevates / verifies administrator context and bypasses execution policy.
      2. Detects an existing Tailscale install (skips download/install unless -Force).
      3. Downloads the Tailscale MSI (or uses a local copy) and installs it silently.
      4. Waits for the Tailscale service, then runs `tailscale up` with a caller-supplied
         auth key and any optional flags (login server, tags, routes, exit node, hostname).
      5. Verifies enrollment by confirming a 100.x CGNAT address is assigned.

    The auth key is REQUIRED and is never written to the log file.

.PARAMETER AuthKey
    Tailscale auth key (tskey-auth-...). Generate at:
    https://login.tailscale.com/admin/settings/keys   (or your Headscale server).
    Use a pre-authorized and/or ephemeral key for unattended fleet enrollment.

.PARAMETER Hostname
    Machine name to register in the tailnet. Defaults to the local computer name.

.PARAMETER LoginServer
    Coordination server URL. Set this ONLY for self-hosted control planes (Headscale),
    e.g. https://headscale.example.com . Omit for Tailscale's hosted infrastructure.

.PARAMETER AdvertiseTags
    Comma- or space-separated ACL tags to advertise, e.g. "tag:lab,tag:server".
    The auth key must be authorized to apply these tags.

.PARAMETER AdvertiseRoutes
    Subnet routes this node advertises (subnet-router mode), e.g. "192.168.4.0/24".

.PARAMETER ExitNode
    Tailscale IP or hostname of an exit node to route traffic through.

.PARAMETER MsiUrl
    Override the installer URL. Defaults to the current stable amd64 MSI.

.PARAMETER MsiPath
    Local path to an already-downloaded MSI. If present, no download occurs.

.PARAMETER AcceptDns
    Accept tailnet DNS (MagicDNS) settings. Default: off (-AcceptDns:$false).

.PARAMETER NoAcceptRoutes
    Do NOT accept subnet routes advertised by peers. By default routes ARE accepted.

.PARAMETER Force
    Reinstall the MSI even if Tailscale is already present, and re-run `up` with
    --reset to overwrite existing preferences.

.EXAMPLE
    .\Enroll-Tailscale.ps1 -AuthKey tskey-auth-xxxxx

.EXAMPLE
    .\Enroll-Tailscale.ps1 -AuthKey tskey-auth-xxxxx -Hostname lab-win11-01 `
        -AdvertiseTags "tag:lab" -AcceptDns

.EXAMPLE
    # Self-hosted Headscale
    .\Enroll-Tailscale.ps1 -AuthKey <headscale-key> -LoginServer https://headscale.example.com
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^tskey-')]
    [string]$AuthKey,

    [string]$Hostname    = $env:COMPUTERNAME,
    [string]$LoginServer,
    [string]$AdvertiseTags,
    [string]$AdvertiseRoutes,
    [string]$ExitNode,

    [string]$MsiUrl  = 'https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi',
    [string]$MsiPath,

    [switch]$AcceptDns,
    [switch]$NoAcceptRoutes,
    [switch]$Force
)

# ----------------------------------------------------------------------------
# Environment hardening (mandated by project PowerShell guidelines)
# ----------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
# Automatic execution-policy bypass for THIS process only (no machine change).
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch { }
# Tailscale endpoints require modern TLS for the MSI download.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$TailscaleCli = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
$LogDir       = 'C:\F0'
$LogFile      = Join-Path $LogDir 'tailscale_enroll.log'

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }
    try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch { }
}

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-IsAdministrator)) {
        Write-Log 'This script must run elevated (Administrator). Re-launch from an elevated prompt.' 'ERROR'
        Write-Log 'e.g.  Start-Process powershell -Verb RunAs' 'INFO'
        exit 5
    }
    Write-Log 'Administrator context confirmed.' 'OK'
}

function Get-TailscaleIPv4 {
    if (-not (Test-Path $TailscaleCli)) { return $null }
    try {
        $ip = & $TailscaleCli ip -4 2>$null | Select-Object -First 1
        if ($ip -and $ip -match '^100\.') { return $ip.Trim() }
    } catch { }
    return $null
}

# ----------------------------------------------------------------------------
# 1. Pre-flight
# ----------------------------------------------------------------------------
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
Write-Log "===== Tailscale enrollment started on $env:COMPUTERNAME ====="
Assert-Administrator

# Enable services the Tailscale installer/daemon depends on.
$requiredServices = 'iphlpsvc','Dnscache','netprofm','WinHttpAutoProxySvc'
foreach ($svc in $requiredServices) {
    try {
        Set-Service -Name $svc -StartupType Automatic -ErrorAction Stop
        Start-Service -Name $svc -ErrorAction SilentlyContinue
        Write-Log "Service ensured running: $svc"
    } catch {
        Write-Log "Could not configure service ${svc}: $($_.Exception.Message)" 'WARN'
    }
}

# ----------------------------------------------------------------------------
# 2. Install (skip if already present, unless -Force)
# ----------------------------------------------------------------------------
$alreadyInstalled = Test-Path $TailscaleCli
if ($alreadyInstalled -and -not $Force) {
    Write-Log 'Tailscale already installed; skipping download/install (use -Force to reinstall).' 'OK'
}
else {
    if (-not $MsiPath) {
        $MsiPath = Join-Path $LogDir 'tailscale-setup.msi'
        Write-Log "Downloading Tailscale MSI from $MsiUrl"
        try {
            Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing -TimeoutSec 180
        } catch {
            Write-Log "MSI download failed: $($_.Exception.Message)" 'ERROR'
            exit 2
        }
    }
    if (-not (Test-Path $MsiPath)) {
        Write-Log "MSI not found at $MsiPath" 'ERROR'
        exit 2
    }

    Write-Log "Installing Tailscale silently from $MsiPath"
    $msiArgs = @(
        '/i', "`"$MsiPath`"",
        '/quiet', '/norestart',
        'TS_NOLAUNCH=yes',          # do not launch the GUI
        'TS_UNATTENDEDMODE=always'  # keep tunnel up with no interactive user
    )
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Log "msiexec returned exit code $($proc.ExitCode)" 'ERROR'
        exit 3
    }

    # Wait for the Tailscale service to register and start.
    Write-Log 'Waiting for Tailscale service to start...'
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 3
        $svc = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue
    } while ((-not $svc -or $svc.Status -ne 'Running') -and (Get-Date) -lt $deadline)

    if (-not $svc -or $svc.Status -ne 'Running') {
        Write-Log 'Tailscale service did not reach Running state in time.' 'ERROR'
        exit 3
    }
    Write-Log 'Tailscale service installed and running.' 'OK'
}

if (-not (Test-Path $TailscaleCli)) {
    Write-Log "Tailscale CLI missing at $TailscaleCli after install." 'ERROR'
    exit 3
}

# ----------------------------------------------------------------------------
# 3. Enroll into the tailnet  (tailscale up)
# ----------------------------------------------------------------------------
$upArgs = @(
    'up',
    "--authkey=$AuthKey",
    "--hostname=$Hostname",
    '--unattended'                                  # survive logoff/reboot
)
if (-not $NoAcceptRoutes) { $upArgs += '--accept-routes' }
if ($AcceptDns)          { $upArgs += '--accept-dns=true' } else { $upArgs += '--accept-dns=false' }
if ($LoginServer)        { $upArgs += "--login-server=$LoginServer" }
if ($AdvertiseTags)      { $upArgs += "--advertise-tags=$(( $AdvertiseTags -split '[,\s]+' | Where-Object { $_ } ) -join ',')" }
if ($AdvertiseRoutes)    { $upArgs += "--advertise-routes=$AdvertiseRoutes" }
if ($ExitNode)           { $upArgs += "--exit-node=$ExitNode" }
if ($Force)              { $upArgs += '--reset' }

# Log the command WITHOUT the auth key.
$redacted = ($upArgs | ForEach-Object { $_ -replace '(--authkey=).*', '$1<redacted>' }) -join ' '
Write-Log "Running: tailscale $redacted"

$upOutput = & $TailscaleCli @upArgs 2>&1
$upExit   = $LASTEXITCODE
$upOutput | ForEach-Object { Write-Log "  tailscale: $_" }

if ($upExit -ne 0) {
    Write-Log "tailscale up failed (exit $upExit)." 'ERROR'
    exit 4
}

# ----------------------------------------------------------------------------
# 4. Verify enrollment
# ----------------------------------------------------------------------------
Write-Log 'Verifying tailnet connectivity...'
$ip = $null
$deadline = (Get-Date).AddSeconds(30)
do {
    Start-Sleep -Seconds 2
    $ip = Get-TailscaleIPv4
} while (-not $ip -and (Get-Date) -lt $deadline)

if (-not $ip) {
    Write-Log 'Enrolled but no 100.x address assigned yet — check the admin console / key authorization.' 'WARN'
    exit 4
}

Write-Log "SUCCESS: $Hostname enrolled. Tailscale IPv4 = $ip" 'OK'
& $TailscaleCli status 2>&1 | ForEach-Object { Write-Log "  status: $_" }
Write-Log "Log written to $LogFile"
exit 0
