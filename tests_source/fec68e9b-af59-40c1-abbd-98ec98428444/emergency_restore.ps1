# Emergency Restore Script for MDE Memory Patch Testing
# SECURITY TESTING ONLY - Manual recovery for memory patch restoration
#
# This script provides emergency recovery if:
# - Test crashes before restoring patches
# - Watchdog fails to restore automatically
# - User needs immediate restoration
#
# Usage: .\emergency_restore.ps1 [-Force]
#
# ⚠️ WARNING: Must be run as Administrator

param(
    [switch]$Force
)

# Required admin privilege check function
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Required execution policy bypass function
function Set-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Host "[!] Failed to bypass execution policy: $_" -ForegroundColor Red
        return $false
    }
}

# Initialize
Set-ExecutionPolicyBypass | Out-Null

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   MDE Memory Patch Emergency Restoration Tool" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Check admin privileges
if (-not (Test-Administrator)) {
    Write-Host "[ERROR] This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "Please run as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

Write-Host "[+] Running with Administrator privileges" -ForegroundColor Green

# Check for patch backup file
$backupPath = "C:\F0\patch_backup.json"

if (-not (Test-Path $backupPath)) {
    Write-Host ""
    Write-Host "[INFO] No patch backup file found at $backupPath" -ForegroundColor Yellow
    Write-Host "[INFO] This could mean:" -ForegroundColor Yellow
    Write-Host "  1. No patches were applied" -ForegroundColor Gray
    Write-Host "  2. Patches were already restored" -ForegroundColor Gray
    Write-Host "  3. Backup file was deleted" -ForegroundColor Gray
    Write-Host ""

    # Check watchdog state
    $watchdogStatePath = "C:\F0\watchdog_state.json"
    if (Test-Path $watchdogStatePath) {
        $watchdogState = Get-Content $watchdogStatePath | ConvertFrom-Json
        Write-Host "[INFO] Watchdog state:" -ForegroundColor Cyan
        Write-Host "  Status: $($watchdogState.status)" -ForegroundColor Gray
        Write-Host "  Patches Restored: $($watchdogState.patchesRestored)" -ForegroundColor Gray

        if ($watchdogState.patchesRestored -eq $true) {
            Write-Host ""
            Write-Host "[SUCCESS] Patches were already restored by watchdog!" -ForegroundColor Green
            exit 0
        }
    }

    Write-Host "[INFO] No restoration needed. System appears clean." -ForegroundColor Green
    exit 0
}

Write-Host "[!] Found patch backup file!" -ForegroundColor Yellow
Write-Host ""

# Read backup
try {
    $backup = Get-Content $backupPath | ConvertFrom-Json
} catch {
    Write-Host "[ERROR] Failed to read backup file: $_" -ForegroundColor Red
    exit 1
}

# Display patch information
Write-Host "Patch Information:" -ForegroundColor Cyan
Write-Host "  Target Process: $($backup.processName) (PID $($backup.processPid))" -ForegroundColor Gray
Write-Host "  Function Address: $($backup.functionAddress)" -ForegroundColor Gray
Write-Host "  Patch Size: $($backup.patchSize) bytes" -ForegroundColor Gray
Write-Host "  Applied: $($backup.timestamp)" -ForegroundColor Gray
Write-Host ""

# Check if process is still running
$process = Get-Process -Id $backup.processPid -ErrorAction SilentlyContinue

if (-not $process) {
    Write-Host "[WARNING] Target process (PID $($backup.processPid)) is not running!" -ForegroundColor Yellow
    Write-Host "[INFO] Patches may have been lost when process terminated" -ForegroundColor Yellow
    Write-Host "[INFO] No restoration possible - process must be restarted" -ForegroundColor Yellow
    Write-Host ""

    # Clean up backup file
    Remove-Item $backupPath -Force
    Write-Host "[INFO] Backup file removed" -ForegroundColor Green
    exit 0
}

Write-Host "[+] Target process is running (PID $($backup.processPid))" -ForegroundColor Green
Write-Host ""

# Confirm restoration
if (-not $Force) {
    Write-Host "Do you want to restore original bytes to $($backup.processName)?" -ForegroundColor Yellow
    $confirmation = Read-Host "Type 'YES' to continue"

    if ($confirmation -ne 'YES') {
        Write-Host "[CANCELLED] Restoration cancelled by user" -ForegroundColor Yellow
        exit 0
    }
}

Write-Host ""
Write-Host "[*] Starting restoration process..." -ForegroundColor Cyan

# P/Invoke signatures for memory operations
Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class MemoryAPI {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out int lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out int lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_READ = 0x0010;
    }
"@

try {
    # Open process
    $processAccess = [MemoryAPI]::PROCESS_VM_WRITE -bor [MemoryAPI]::PROCESS_VM_OPERATION -bor [MemoryAPI]::PROCESS_VM_READ
    $processHandle = [MemoryAPI]::OpenProcess($processAccess, $false, $backup.processPid)

    if ($processHandle -eq [IntPtr]::Zero) {
        throw "Failed to open process (Access Denied - EDR may be protecting the process)"
    }

    Write-Host "[+] Process handle acquired" -ForegroundColor Green

    # Parse function address
    $functionAddress = [IntPtr]([Convert]::ToInt64($backup.functionAddress, 16))

    # Convert hex string to bytes
    $originalBytes = @()
    for ($i = 0; $i -lt $backup.originalBytes.Length; $i += 2) {
        $byteHex = $backup.originalBytes.Substring($i, 2)
        $originalBytes += [Convert]::ToByte($byteHex, 16)
    }

    Write-Host "[*] Restoring $($originalBytes.Count) bytes to address $($backup.functionAddress)..." -ForegroundColor Cyan

    # Write original bytes
    $bytesWritten = 0
    $writeResult = [MemoryAPI]::WriteProcessMemory(
        $processHandle,
        $functionAddress,
        $originalBytes,
        $originalBytes.Count,
        [ref]$bytesWritten
    )

    if (-not $writeResult) {
        throw "WriteProcessMemory failed (EDR may have blocked the operation)"
    }

    if ($bytesWritten -ne $originalBytes.Count) {
        throw "Wrote $bytesWritten bytes, expected $($originalBytes.Count)"
    }

    Write-Host "[+] Original bytes written ($bytesWritten bytes)" -ForegroundColor Green

    # Verify restoration
    Write-Host "[*] Verifying restoration..." -ForegroundColor Cyan

    $verifyBytes = New-Object byte[] $originalBytes.Count
    $bytesRead = 0
    $readResult = [MemoryAPI]::ReadProcessMemory(
        $processHandle,
        $functionAddress,
        $verifyBytes,
        $originalBytes.Count,
        [ref]$bytesRead
    )

    if (-not $readResult) {
        throw "Verification read failed"
    }

    # Compare bytes
    $mismatch = $false
    for ($i = 0; $i -lt $originalBytes.Count; $i++) {
        if ($verifyBytes[$i] -ne $originalBytes[$i]) {
            Write-Host "[ERROR] Byte mismatch at offset $i" -ForegroundColor Red
            $mismatch = $true
        }
    }

    if ($mismatch) {
        throw "Restoration verification failed - bytes do not match"
    }

    Write-Host "[+] Restoration verified successfully!" -ForegroundColor Green

    # Clean up
    [MemoryAPI]::CloseHandle($processHandle) | Out-Null

    # Remove backup file
    Remove-Item $backupPath -Force
    Write-Host "[+] Backup file removed" -ForegroundColor Green

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "   Restoration Completed Successfully!" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Original function bytes have been restored." -ForegroundColor Green
    Write-Host "The system should now be in a clean state." -ForegroundColor Green

} catch {
    Write-Host ""
    Write-Host "[ERROR] Restoration failed: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Possible reasons:" -ForegroundColor Yellow
    Write-Host "  1. EDR is protecting the process" -ForegroundColor Gray
    Write-Host "  2. Process has terminated" -ForegroundColor Gray
    Write-Host "  3. Memory permissions changed" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Recommended actions:" -ForegroundColor Yellow
    Write-Host "  1. Restart the target service: Restart-Service -Name Sense" -ForegroundColor Gray
    Write-Host "  2. Reboot the system if needed" -ForegroundColor Gray
    Write-Host "  3. Verify MDE is functioning normally" -ForegroundColor Gray

    exit 1
}

# SIG # Begin signature block
# MIIIxQYJKoZIhvcNAQcCoIIItjCCCLICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA3kcd7UkGni0eA
# zcGeFzJEaalT9yfq3E2jRu78B39owKCCBSwwggUoMIIDEKADAgECAhA5oQfABFY7
# kUxr594dJ8foMA0GCSqGSIb3DQEBDQUAMCUxIzAhBgNVBAMMGkYwLUxvY2FsQ29k
# ZVNpZ25pbmctQ1NULVNCMB4XDTI1MDEyMzE1MjgyOFoXDTI2MDEyMzE1MzgyNlow
# JTEjMCEGA1UEAwwaRjAtTG9jYWxDb2RlU2lnbmluZy1DU1QtU0IwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQClHKCahGaIvtToI50C9GW7yv1dWPkaR0Ac
# H5Sm/7MUwA0+wSXYqStCM1o1PQF8d2OQwBxKVkQs8oZHlXGwaGoghaYzTeb5iDhn
# UkjwWh1sCyDa7fJlrQdBAbRatEawc3JJUFmqA+ABKwREeqHeEs4rhfF+W7HlNK44
# DmotuONJLE5ZM3ENk+pQoy7ZpGMbqJ/nyK4tAipcikeiavEvPatPREVRPljlgOMR
# laa070Ek/x2ndjwg9N8+JVPnQ3kaljzmnqQbF4fEG0g7NwBpDcXanANQg95ikob8
# zeQ2Xof9sLF+b3cygPkbR/YwODLpf0z3FhqGSi+4uu8E1fyMqKIZ6Y9UVWqM3akw
# 4oSoddO7vIZU0UyPRLWjCTBbl2kog/fXoMjDwOVNjh7fWSytS3Eovqvle+oK5sfj
# pM5mpVfnfBxmp8YBHxCTxunZ96R4RE2v1vFUZl3jFmV+SuNulqn8HGWv2PWUtEaJ
# 9SrKednbbw6rCAjGbih7UHXAK+VtYlxqxWvsnak85ns0ZLwjEume3QbctjxDV9eE
# uVrJslGhLat+BuE38MkUfmfoGK9YUOFX2oFh762BMS6C0GfnPjfHxUImCsh8XNLS
# 9bceOZfxBnINiVIMwYR2D+aXAj0TY/+HwSpLpBaEQiAwveuyRS3Hx1ldNQFqApZ5
# Npai8Fl4uQIDAQABo1QwUjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUzNqF6yRy1BO1ukBxwfmj2kgt
# 504wDQYJKoZIhvcNAQENBQADggIBAIxxf0J3gN9/wIDdCK0IuaZaLzLovPDYUQ80
# zHXHr6En+hLEqFHNI+eqk9et0YrO/9cpBfH4gar/FMf1AMWQQFoPTod5DJREo1iG
# nrew5d1gbMCCkA9DOhC/sOyvuNrd9ihV7okeUUP7fcnVkujlZE6YKEBxLMg1hmR2
# LDshrinINyKvt5tqsimee/w7GWHFv8XYPwEVEAjxJFWcmTFTKtAx16oS6Kj3Np4o
# CGgTFZzSzhaiQTvGBF7Xw4Tmbxcqk7RayrkdBdSOh3I8rey9mkluN7P7DJCfRes8
# F1NMoMuDzfNs/y3AND4cZGVNwkli8tv5MfUClSmef4LIEy9Y+Kdpdz09eVNjKu7X
# RFjg2ODeMBLHqWyuLY2FfpxflEwjEYpBGhbd7Z1xR7LVVK8prNWk63wVChLeY7o3
# 6i0Qs7MwueuVNMATf6VGULIN3sUnaih67NtAND3FpSF9+YUSHbqCMCjwmO7z6gB9
# AlKt497NQ1Fhd+35H59PqRIdSEeTxVQAyL5G433XZf70CHeg9pMn9JVsAaGgBe7y
# ME2C9hKg+QDZs6r4OH+n5b2efJAc+iDgesyvnhmZEupgxhVyUmrvb3NhWiPNdD1h
# 78cJUShggI6/oq4BI02H6m1q0kEijq5YI6sduYgkb7V3u7V3Q6oT2qer2OODXwRd
# rXKZHqh8MYIC7zCCAusCAQEwOTAlMSMwIQYDVQQDDBpGMC1Mb2NhbENvZGVTaWdu
# aW5nLUNTVC1TQgIQOaEHwARWO5FMa+feHSfH6DANBglghkgBZQMEAgEFAKCBiDAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgkqhkiG9w0BCQUxDxcNMjUxMDI0
# MTMyMTU3WjAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0B
# CQQxIgQgy0fBIKy6UBR2jiSOoXanpSJ22QSLpRXLoFlKrKrAgY0wDQYJKoZIhvcN
# AQEBBQAEggIAo/scLYwb5IWbtdpwXAaD6g9DBMQ8dWoqDwJXFFgWzvJcS8fssWLg
# dHbR9V5lJe5F+s0DiLZaPXJDAMxPmqUuqFr2TnF7hdserJeCEAwx1Rjh3dHS8Rer
# DqulnnYnmqGirFhwpshLZYSzUDoRGIP0jbC5KvgX6RDFa+fg3VMyetcbbPjTT7Cg
# 5pm+tQOOwdncZkq6Evqc8RApaFXoKSWx7/uBuvbGv89jNt0xbrcr9Ro0JDGUrPcZ
# ktq1X6AH5wZSguDQMWTyrwBCEL15A2s6FSzZ9MVnSDrQYVBG/T92pIXy47qQTNLH
# 780JL12I/SE7tT17Xmdfh8bvqFqGrC03dnXjxjSSgyG1W+oZBV3R+ROG+yqwi+Jq
# xaqEKmJtuHfp0xm9rRHBw8NvSNs9sPI2URGWx6Q0a0W4RY/yROdwg8jaLEjWvNad
# D1ljnwj1JYyYJPmK1XxkVH8O+U5NL+VP/H1WI0d0KzKipqcD5HHvDE2q1VV/r5UF
# O5lLsrFk4X2O5J6S/OQTYl3+W+tPUqYIzAzgByU72GpfTMO5WpPDM6urAmQTvS1c
# +VeNLM9x4KJKeXveOkJ9oQ/3JH289ib337umUtZHk0INt3kNSUtr5kiTKs2qTrUd
# V9CNbQ/OW/LYJFyxaBG1DAoASZFaKizFGQrq82l2FLf+dp99FM6KCcs=
# SIG # End signature block
