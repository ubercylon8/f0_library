# Get active user session info for cross-session execution
try {
    # Get the active console session ID and username
    $sessions = qwinsta | Where-Object { $_ -match 'Active|Console' }
    $activeSession = $null
    $activeUser = $null
    
    foreach ($session in $sessions) {
        if ($session -match 'Active') {
            $parts = $session -split '\s+' | Where-Object { $_ -ne '' }
            if ($parts.Count -ge 3) {
                $activeUser = $parts[1]
                $activeSession = $parts[2]
                break
            }
        }
    }
    
    if (-not $activeUser) {
        # Fallback: try to get logged on users via WMI
        $loggedUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
        if ($loggedUsers) {
            $activeUser = $loggedUsers
            Write-Host "Found user via WMI: $activeUser"
        }
    }
    
    if ($activeUser) {
        Write-Host "Target user: $activeUser, Session: $activeSession"
        
        # Create scheduled task with S4U logon type for cross-session execution
        $action = New-ScheduledTaskAction -Execute "notepad.exe"
        
        # Use S4U (Service for User) logon type - allows SYSTEM to run as user with UI
        $principal = New-ScheduledTaskPrincipal -UserId $activeUser -LogonType S4U
        
        # Create task with highest privileges and interactive execution
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        $task = Register-ScheduledTask -TaskName "TempNotepad" -Action $action -Principal $principal -Settings $settings -Force
        Write-Host "Task registered successfully for user: $activeUser"
        
        # Start the task
        Start-ScheduledTask -TaskName "TempNotepad"
        Write-Host "Task started - Notepad should appear in user session"
        
        Start-Sleep -Seconds 3
        
        # Cleanup
        $existingTask = Get-ScheduledTask -TaskName "TempNotepad" -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName "TempNotepad" -Confirm:$false
            Write-Host "Task unregistered"
        }
    }
    else {
        Write-Error "Could not find active user session"
    }
}
catch {
    Write-Error "Error: $($_.Exception.Message)"
    Write-Host "Full error details: $($_.Exception)"
}