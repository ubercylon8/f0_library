param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('tls', 'chain')]
    [string]$Mode,
    [string]$ChainPath,
    [int]$Port,
    [string]$ServerName
)

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Host "[!] Failed to bypass execution policy: $_" -ForegroundColor Red
        return $false
    }
}

Set-ExecutionPolicyBypass | Out-Null

switch ($Mode) {
    'tls' {
        $script:PolicyErrors = [System.Net.Security.SslPolicyErrors]::None
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.ReceiveTimeout = 10000
            $client.SendTimeout = 10000
            $client.Connect('127.0.0.1', $Port)
            $callback = {
                param($sender, $certificate, $chain, $errors)
                $script:PolicyErrors = $errors
                return ($errors -eq [System.Net.Security.SslPolicyErrors]::None)
            }
            $stream = New-Object System.Net.Security.SslStream($client.GetStream(), $false, $callback)
            $stream.ReadTimeout = 10000
            $stream.WriteTimeout = 10000
            $stream.AuthenticateAsClient($ServerName)
            Write-Output "F0_ACCEPTED $($stream.SslProtocol)"
            $stream.Dispose()
            $client.Close()
        } catch {
            if ($script:PolicyErrors -ne [System.Net.Security.SslPolicyErrors]::None) {
                Write-Output "F0_REJECTED $script:PolicyErrors $($_.Exception.Message)"
                exit 2
            }
            Write-Output "F0_ERROR $($_.Exception.GetType().Name): $($_.Exception.Message)"
            exit 3
        }
    }
    'chain' {
        try {
            $text = [System.IO.File]::ReadAllText($ChainPath)
            $matches = [regex]::Matches($text, '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----')
            if ($matches.Count -lt 2) {
                Write-Output 'F0_ERROR certificate chain did not contain enough certificates'
                exit 3
            }
            $certificates = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            foreach ($match in $matches) {
                $der = [Convert]::FromBase64String(($match.Groups[1].Value -replace '\s', ''))
                $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$der)
                $certificates.Add($certificate) | Out-Null
            }
            $leaf = $certificates[0]
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.ExtraStore.AddRange($certificates)
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chain.ChainPolicy.VerificationTime = $leaf.NotBefore.AddDays(1)
            $valid = $chain.Build($leaf)
            if ($valid) {
                Write-Output 'F0_ACCEPTED X509Chain.Build succeeded'
                exit 0
            }
            $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() })
            $statusText = $statuses -join ','
            $safeStatuses = @('UntrustedRoot', 'Revoked', 'PartialChain', 'NotSignatureValid', 'InvalidBasicConstraints', 'ExplicitDistrust')
            $safe = $false
            foreach ($status in $statuses) {
                if ($safeStatuses -contains $status) { $safe = $true }
            }
            if ($safe) {
                Write-Output "F0_REJECTED $statusText"
                exit 2
            }
            Write-Output "F0_ERROR X509Chain rejected without recognized trust evidence: $statusText"
            exit 3
        } catch {
            Write-Output "F0_ERROR $($_.Exception.GetType().Name): $($_.Exception.Message)"
            exit 3
        }
    }
}
