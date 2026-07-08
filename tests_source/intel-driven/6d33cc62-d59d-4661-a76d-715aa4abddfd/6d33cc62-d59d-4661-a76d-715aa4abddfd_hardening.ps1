<#
    Hardening / Posture Audit — PII Exfiltration to External Inference Services
    Test ID: 6d33cc62-d59d-4661-a76d-715aa4abddfd
    MITRE ATT&CK: T1552.001, T1119, T1005, T1567
    Platform: Windows

    Focus: shadow-AI PII egress. The PRIMARY controls live in the network egress
    layer (forward proxy / CASB / DLP / protective DNS) — a host cannot fully
    substitute for them. This script AUDITS host-observable posture and can apply
    a compensating host-firewall egress block to AI vendors with -Apply.

    Usage:
      powershell -ExecutionPolicy Bypass -File .\6d33cc62-..._hardening.ps1          # audit only
      powershell -ExecutionPolicy Bypass -File .\6d33cc62-..._hardening.ps1 -Apply   # apply local egress blocks
#>

[CmdletBinding()]
param(
    [switch]$Apply
)

# ---- Required helpers (per CLAUDE.md PowerShell guidelines) ----

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Enable-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not set process execution policy: $($_.Exception.Message)"
    }
}

Enable-ExecutionPolicyBypass

$AIHosts = @(
    "api.openai.com","chatgpt.com","openai.com",
    "api.anthropic.com","claude.ai","anthropic.com",
    "generativelanguage.googleapis.com","gemini.google.com",
    "api.githubcopilot.com","copilot.microsoft.com"
)

Write-Host "==================================================================="
Write-Host " Shadow-AI PII Egress — Windows Posture Audit"
Write-Host "==================================================================="

# ---- 1. Proxy configuration (is egress even inspected?) ----
Write-Host "`n[1] WinHTTP / WinINET proxy configuration"
try { netsh winhttp show proxy } catch { Write-Warning $_ }
$inet = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($inet -and $inet.ProxyEnable -eq 1) {
    Write-Host "    ProxyEnable=1, ProxyServer=$($inet.ProxyServer)  (egress may be inspected)"
} else {
    Write-Warning "    No user proxy configured — direct egress to AI vendors is likely uninspected."
}

# ---- 2. DNS servers (protective DNS in place?) ----
Write-Host "`n[2] DNS servers (protective/AI-policy DNS recommended)"
Get-DnsClientServerAddress -AddressFamily IPv4 |
    Where-Object { $_.ServerAddresses } |
    Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize

# ---- 3. Can the AI vendor hosts be reached directly? ----
Write-Host "`n[3] Direct reachability of AI vendor hosts (a reachable host = potential leak path)"
foreach ($h in @("api.openai.com","api.anthropic.com","generativelanguage.googleapis.com","api.githubcopilot.com")) {
    try {
        $r = Test-NetConnection -ComputerName $h -Port 443 -WarningAction SilentlyContinue
        $state = if ($r.TcpTestSucceeded) { "REACHABLE (no egress control)" } else { "blocked/unreachable (good)" }
        Write-Host ("    {0,-40} {1}" -f $h, $state)
    } catch { Write-Host ("    {0,-40} test error" -f $h) }
}

# ---- 4. AI-service key exposure in common stores ----
Write-Host "`n[4] AI-service API-key exposure in common user stores"
$candidates = @(
    "$env:USERPROFILE\.env",
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.continue\config.json",
    "$env:APPDATA\github-copilot\hosts.json",
    "$env:APPDATA\Code\User\settings.json"
)
foreach ($c in $candidates) {
    if (Test-Path $c) {
        $hit = Select-String -Path $c -Pattern 'OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|sk-ant-|sk-proj-|AIza' -SimpleMatch:$false -ErrorAction SilentlyContinue
        if ($hit) { Write-Warning "    Possible AI key material in: $c" }
        else      { Write-Host    "    Present, no obvious AI key pattern: $c" }
    }
}
foreach ($e in (Get-ChildItem Env:)) {
    if ($e.Name -match 'OPENAI|ANTHROPIC|GEMINI|COPILOT|HUGGINGFACE|MISTRAL|COHERE') {
        Write-Warning "    AI-service key present in environment variable: $($e.Name) (value redacted)"
    }
}

# ---- 5. Optional compensating control: host firewall egress block ----
Write-Host "`n[5] Host-firewall compensating control"
if ($Apply) {
    if (-not (Test-IsAdmin)) {
        Write-Warning "    -Apply requires Administrator. Re-run elevated to add firewall rules."
    } else {
        Write-Host "    Resolving and blocking outbound 443 to AI vendor IPs (compensating control only)..."
        $ips = @()
        foreach ($h in $AIHosts) {
            try { $ips += (Resolve-DnsName -Name $h -Type A -ErrorAction SilentlyContinue).IPAddress } catch {}
        }
        $ips = $ips | Where-Object { $_ } | Sort-Object -Unique
        if ($ips.Count -gt 0) {
            New-NetFirewallRule -DisplayName "F0RT1KA-Block-ShadowAI-Egress" `
                -Direction Outbound -Action Block -RemoteAddress $ips -RemotePort 443 -Protocol TCP `
                -ErrorAction SilentlyContinue | Out-Null
            Write-Host "    Added block rule for $($ips.Count) resolved AI-vendor IP(s). NOTE: IPs rotate; the proxy/DNS layer is authoritative."
        } else {
            Write-Warning "    Could not resolve AI vendor IPs to block."
        }
    }
} else {
    Write-Host "    (audit only) Re-run with -Apply to add a local egress block. Prefer proxy/CASB/DNS controls as primary."
}

Write-Host "`n==================================================================="
Write-Host " Audit complete. PRIMARY control = forward proxy / CASB / DLP + protective DNS"
Write-Host " with TLS inspection and PII content policies on AI-vendor egress."
Write-Host "==================================================================="
