#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitors and displays recent registry changes on a Windows host.
.DESCRIPTION
    Provides multiple methods to track registry modifications including WMI events,
    audit logs, and snapshot comparisons.
.AUTHOR
    Security monitoring script for tracking registry changes.
#>

# Function to check if running with admin privileges
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to check and bypass execution policy
function Bypass-ExecutionPolicy {
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
    Write-Host "Current execution policy: $currentPolicy" -ForegroundColor Gray
    
    if ($currentPolicy -eq "Restricted" -or $currentPolicy -eq "AllSigned") {
        Write-Host "Restrictive execution policy detected. Attempting to bypass..." -ForegroundColor Yellow
        try {
            # Relaunch script with -ExecutionPolicy Bypass
            $scriptPath = $MyInvocation.MyCommand.Path
            if (-not $scriptPath) {
                Write-Host "Error: Script path not found. Save this script to a .ps1 file and run it again." -ForegroundColor Red
                exit 1
            }
            $bypassCommand = "powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`""
            Write-Host "Relaunching script with bypassed execution policy..." -ForegroundColor Yellow
            Invoke-Expression $bypassCommand
            exit 0  # Exit current session after relaunch
        }
        catch {
            Write-Host "Failed to bypass execution policy: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "Execution policy allows script execution. Proceeding..." -ForegroundColor Gray
    }
}

# Exit if not running as admin
if (-not (Test-Admin)) {
    Write-Host "This script requires administrative privileges. Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

# Check and bypass execution policy if needed
Bypass-ExecutionPolicy

Write-Host "`n=== Registry Change Monitor ===" -ForegroundColor Cyan
Write-Host "Choose monitoring method:`n" -ForegroundColor Yellow
Write-Host "1. Real-time WMI Event Monitoring (monitors changes as they happen)"
Write-Host "2. Windows Security Audit Log (requires audit policy enabled)"
Write-Host "3. Registry Snapshot Comparison (before/after comparison)"
Write-Host "4. Process Monitor Integration (requires ProcMon from Sysinternals)"

$choice = Read-Host "`nSelect option (1-4)"

switch ($choice) {
    "1" {
        # Method 1: WMI Event Monitoring
        Write-Host "`n=== Starting Real-time Registry Monitoring ===" -ForegroundColor Cyan
        Write-Host "Press Ctrl+C to stop monitoring..." -ForegroundColor Yellow
        Write-Host "Monitoring the following hives: HKLM, HKCU`n" -ForegroundColor Gray

        # Create WMI event query for registry changes
        $query = @"
SELECT * FROM RegistryTreeChangeEvent 
WHERE Hive='HKEY_LOCAL_MACHINE' OR Hive='HKEY_CURRENT_USER'
"@

        try {
            # Register WMI event
            Register-WmiEvent -Query $query -SourceIdentifier "RegistryChange" -Action {
                $event = $Event.SourceEventArgs.NewEvent
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Host "[$timestamp] Registry Change Detected:" -ForegroundColor Yellow
                Write-Host "  Hive: $($event.Hive)" -ForegroundColor Cyan
                Write-Host "  Root: $($event.RootPath)" -ForegroundColor Cyan
            }

            # Alternative: Monitor specific registry keys
            $keyWatchers = @()
            $keysToMonitor = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows Defender",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            )

            foreach ($key in $keysToMonitor) {
                Write-Host "Monitoring: $key" -ForegroundColor Gray
            }

            # Keep script running
            while ($true) {
                Start-Sleep -Seconds 1
            }
        }
        catch {
            Write-Host "Error setting up monitoring: $_" -ForegroundColor Red
        }
        finally {
            # Cleanup
            Unregister-Event -SourceIdentifier "RegistryChange" -ErrorAction SilentlyContinue
        }
    }
    
    "2" {
        # Method 2: Windows Security Audit Log
        Write-Host "`n=== Checking Windows Security Audit Log ===" -ForegroundColor Cyan
        Write-Host "Looking for registry audit events (Event ID 4657)...`n" -ForegroundColor Yellow

        # Check if auditing is enabled
        $auditPolicy = auditpol /get /subcategory:"Registry" 2>$null
        if ($auditPolicy -notmatch "Success|Failure") {
            Write-Host "WARNING: Registry auditing may not be enabled!" -ForegroundColor Red
            Write-Host "To enable: auditpol /set /subcategory:'Registry' /success:enable /failure:enable" -ForegroundColor Yellow
        }

        # Query recent registry events
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4657
                StartTime = (Get-Date).AddHours(-1)
            } -MaxEvents 50 -ErrorAction SilentlyContinue

            if ($events) {
                Write-Host "Found $($events.Count) registry change events in the last hour:`n" -ForegroundColor Green
                
                foreach ($event in $events) {
                    $xml = [xml]$event.ToXml()
                    $eventData = @{}
                    $xml.Event.EventData.Data | ForEach-Object {
                        $eventData[$_.Name] = $_.'#text'
                    }
                    
                    Write-Host "[$($event.TimeCreated)]" -ForegroundColor Yellow
                    Write-Host "  Process: $($eventData.ProcessName)" -ForegroundColor Cyan
                    Write-Host "  Object: $($eventData.ObjectName)" -ForegroundColor Cyan
                    Write-Host "  Operation: $($eventData.OperationType)" -ForegroundColor Cyan
                    Write-Host ""
                }
            }
            else {
                Write-Host "No registry audit events found in the last hour." -ForegroundColor Yellow
                Write-Host "This could mean no changes occurred or auditing is not properly configured." -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "Error querying audit log: $_" -ForegroundColor Red
            Write-Host "Ensure you have permission to read the Security log." -ForegroundColor Yellow
        }
    }
    
    "3" {
        # Method 3: Registry Snapshot Comparison
        Write-Host "`n=== Registry Snapshot Comparison ===" -ForegroundColor Cyan
        $snapshotPath = "$env:TEMP\RegistrySnapshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
        
        Write-Host "Creating initial registry snapshot..." -ForegroundColor Yellow
        Write-Host "Monitoring keys:" -ForegroundColor Gray
        
        $keysToSnapshot = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows Defender",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        
        $snapshot1 = @{}
        foreach ($key in $keysToSnapshot) {
            Write-Host "  - $key" -ForegroundColor Gray
            if (Test-Path $key) {
                $snapshot1[$key] = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            }
        }
        
        Write-Host "`nSnapshot created. Make your changes now." -ForegroundColor Green
        Write-Host "Press Enter when ready to compare..." -ForegroundColor Yellow
        Read-Host
        
        Write-Host "`nComparing registry changes..." -ForegroundColor Cyan
        
        $changes = @()
        foreach ($key in $keysToSnapshot) {
            if (Test-Path $key) {
                $snapshot2 = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                $original = $snapshot1[$key]
                
                if ($original) {
                    # Compare properties
                    $props1 = $original.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
                    $props2 = $snapshot2.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
                    
                    # Check for new or modified values
                    foreach ($prop in $props2) {
                        $oldValue = $props1 | Where-Object { $_.Name -eq $prop.Name }
                        if (-not $oldValue) {
                            $changes += "NEW: $key\$($prop.Name) = $($prop.Value)"
                        }
                        elseif ($oldValue.Value -ne $prop.Value) {
                            $changes += "MODIFIED: $key\$($prop.Name) changed from '$($oldValue.Value)' to '$($prop.Value)'"
                        }
                    }
                    
                    # Check for deleted values
                    foreach ($prop in $props1) {
                        if (-not ($props2 | Where-Object { $_.Name -eq $prop.Name })) {
                            $changes += "DELETED: $key\$($prop.Name)"
                        }
                    }
                }
                else {
                    $changes += "NEW KEY: $key"
                }
            }
        }
        
        if ($changes) {
            Write-Host "`nDetected Changes:" -ForegroundColor Yellow
            foreach ($change in $changes) {
                Write-Host "  $change" -ForegroundColor Cyan
            }
        }
        else {
            Write-Host "`nNo changes detected in monitored keys." -ForegroundColor Green
        }
    }
    
    "4" {
        # Method 4: Process Monitor
        Write-Host "`n=== Process Monitor Integration ===" -ForegroundColor Cyan
        
        $procmonPath = "C:\Tools\Procmon.exe"
        if (-not (Test-Path $procmonPath)) {
            Write-Host "Process Monitor not found at: $procmonPath" -ForegroundColor Red
            Write-Host "`nDownload Process Monitor from:" -ForegroundColor Yellow
            Write-Host "https://docs.microsoft.com/en-us/sysinternals/downloads/procmon" -ForegroundColor Cyan
            Write-Host "`nAlternatively, you can use the following PowerShell command:" -ForegroundColor Yellow
            Write-Host "Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/ProcessMonitor.zip' -OutFile '$env:TEMP\ProcMon.zip'" -ForegroundColor Gray
        }
        else {
            Write-Host "Starting Process Monitor with registry filter..." -ForegroundColor Yellow
            
            # Create ProcMon configuration for registry monitoring
            $configXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<procmon>
    <config>
        <filters>
            <filter>
                <column>Operation</column>
                <relation>contains</relation>
                <value>Reg</value>
                <action>Include</action>
            </filter>
        </filters>
    </config>
</procmon>
"@
            $configPath = "$env:TEMP\procmon_registry.pmc"
            $configXml | Out-File -FilePath $configPath -Encoding UTF8
            
            # Start Process Monitor
            Start-Process -FilePath $procmonPath -ArgumentList "/LoadConfig `"$configPath`"", "/Minimized"
            
            Write-Host "Process Monitor started with registry filter." -ForegroundColor Green
            Write-Host "Check the Process Monitor window for real-time registry activity." -ForegroundColor Cyan
        }
    }
    
    default {
        Write-Host "Invalid selection. Exiting." -ForegroundColor Red
    }
}

Write-Host "`nScript completed." -ForegroundColor Gray