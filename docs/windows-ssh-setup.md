# Windows 11 SSH Key Authentication Setup

## Prerequisites
- Windows 11 Professional
- Administrator access on Windows
- SSH client on local machine (Mac/Linux)

## Steps

### 1. Generate SSH Key (on Mac/Linux)
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_win11
cat ~/.ssh/id_ed25519_win11.pub | pbcopy  # Copy public key to clipboard
```

### 2. Install OpenSSH Server (on Windows 11)
Open PowerShell as Administrator and run:
```powershell
# Install OpenSSH Server
Get-WindowsCapability -Online | Where Name -like 'OpenSSH.Server*' | Add-WindowsCapability -Online

# Start and enable SSH service
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Configure firewall
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 3. Configure SSH Keys (on Windows 11)

#### For Administrator Accounts:
```powershell
# Create authorized_keys file for administrators
New-Item -Path C:\ProgramData\ssh\administrators_authorized_keys -ItemType File -Force
notepad C:\ProgramData\ssh\administrators_authorized_keys
# Paste your public key from step 1 and save

# Set correct permissions (CRITICAL!)
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r
icacls C:\ProgramData\ssh\administrators_authorized_keys /grant "Administrators:F"
icacls C:\ProgramData\ssh\administrators_authorized_keys /grant "SYSTEM:F"

# Verify permissions
icacls C:\ProgramData\ssh\administrators_authorized_keys
```

#### For Standard User Accounts:
```powershell
# Create .ssh directory and authorized_keys file
cd $env:USERPROFILE
mkdir .ssh -ErrorAction SilentlyContinue
New-Item .ssh\authorized_keys -ItemType File -Force
notepad .ssh\authorized_keys
# Paste your public key and save

# Set permissions
icacls .ssh\authorized_keys /inheritance:r
icacls .ssh\authorized_keys /grant "$($env:USERNAME):F"
icacls .ssh\authorized_keys /grant "NT AUTHORITY\SYSTEM:F"
```

### 4. Verify SSH Configuration (on Windows 11)
```powershell
# Check if you're an administrator
net user $env:USERNAME

# Edit SSH config if needed
notepad C:\ProgramData\ssh\sshd_config
```

Ensure these lines are present and not commented:
```
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
```

For administrator accounts, this section should exist:
```
Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
```

### 5. Restart SSH Service (on Windows 11)
```powershell
Restart-Service sshd
```

### 6. Connect from Mac/Linux
```bash
# Test connection
ssh -i ~/.ssh/id_ed25519_win11 YourUsername@192.168.64.7

# Debug connection issues
ssh -vvv -i ~/.ssh/id_ed25519_win11 YourUsername@192.168.64.7
```

### 7. Optional: Configure SSH Client (on Mac/Linux)
Add to `~/.ssh/config`:
```
Host win11
    HostName 192.168.64.7
    User YourUsername
    IdentityFile ~/.ssh/id_ed25519_win11
```

Then connect simply with:
```bash
ssh win11
```

## Troubleshooting

### Common Issues:
1. **Permission denied** - Check if using administrator account and placing keys in correct location
2. **Still asking for password** - Verify permissions on authorized_keys file are correct
3. **Connection refused** - Check if SSH service is running and firewall rule is active

### Quick Checks:
```powershell
# Check SSH service status
Get-Service sshd

# Check firewall rule
Get-NetFirewallRule -Name sshd

# View SSH logs
Get-WinEvent -LogName OpenSSH/Admin -MaxEvents 20
```