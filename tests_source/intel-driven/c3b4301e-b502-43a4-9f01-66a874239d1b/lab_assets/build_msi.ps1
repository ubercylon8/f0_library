# build_msi.ps1 - authors the genuine RedFlick persistence MSI using only
# built-in Windows Installer COM automation (no WiX/msitools needed).
#
# The MSI's CustomActions create the three scheduled tasks from the Microsoft
# RedFlick disclosure, exactly as the real chain installs persistence via a
# silently-installed MSI. Actions point at inert decoy scripts in
# c:\Users\fortika-test\StarBlizzardInvite\ that must pre-exist (the
# orchestrator provisions them before msiexec runs).
#
# Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File build_msi.ps1 [out.msi]
# Output: redflick_persistence.msi (also prints the ProductCode for bookkeeping)

param(
    [string]$OutPath = "$PSScriptRoot\redflick_persistence.msi"
)

$ErrorActionPreference = 'Stop'

$productCode = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
$packageCode = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'

$actionDir = 'c:\Users\fortika-test\StarBlizzardInvite'
$tasks = @(
    @{ Name = 'Internet Quality Test Connection'; Extra = '/SC DAILY /ST 09:30'; Action = "$actionDir\task1_action.cmd" },
    @{ Name = 'Network Configuration Manager';    Extra = '/SC ONLOGON /RL LIMITED'; Action = "$actionDir\task2_action.cmd" },
    @{ Name = 'System Health Monitor';            Extra = '/SC ONLOGON /RL LIMITED'; Action = "$actionDir\task3_action.cmd" }
)

$installer = New-Object -ComObject WindowsInstaller.Installer
# 3 = msiOpenDatabaseModeCreate
$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($OutPath, 3))

function Invoke-Sql([string]$sql) {
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($sql))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
    $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
}

# --- schema ---
Invoke-Sql "CREATE TABLE ``Property`` (``Property`` CHAR(72) NOT NULL, ``Value`` CHAR(255) LOCALIZABLE PRIMARY KEY ``Property``)"
Invoke-Sql "CREATE TABLE ``Directory`` (``Directory`` CHAR(72) NOT NULL, ``Directory_Parent`` CHAR(72), ``DefaultDir`` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY ``Directory``)"
Invoke-Sql "CREATE TABLE ``Feature`` (``Feature`` CHAR(38) NOT NULL, ``Feature_Parent`` CHAR(38), ``Title`` CHAR(64), ``Description`` CHAR(255), ``Display`` SHORT, ``Level`` SHORT NOT NULL, ``Directory_`` CHAR(72), ``Attributes`` INTEGER NOT NULL PRIMARY KEY ``Feature``)"
Invoke-Sql "CREATE TABLE ``Component`` (``Component`` CHAR(72) NOT NULL, ``ComponentId`` CHAR(72), ``Directory_`` CHAR(72) NOT NULL, ``Attributes`` INTEGER NOT NULL, ``Condition`` CHAR(255), ``KeyPath`` CHAR(72) PRIMARY KEY ``Component``)"
Invoke-Sql "CREATE TABLE ``FeatureComponents`` (``Feature_`` CHAR(38) NOT NULL, ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Feature_``, ``Component_``)"
Invoke-Sql "CREATE TABLE ``CustomAction`` (``Action`` CHAR(72) NOT NULL, ``Type`` SHORT NOT NULL, ``Source`` CHAR(72), ``Target`` CHAR(255) PRIMARY KEY ``Action``)"
Invoke-Sql "CREATE TABLE ``InstallExecuteSequence`` (``Action`` CHAR(72), ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Sequence``)"
Invoke-Sql "CREATE TABLE ``InstallUISequence`` (``Action`` CHAR(72), ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Sequence``)"
Invoke-Sql "CREATE TABLE ``Media`` (``DiskId`` INTEGER NOT NULL, ``LastSequence`` INTEGER NOT NULL, ``DiskPrompt`` CHAR(64) LOCALIZABLE, ``Cabinet`` CHAR(255) LOCALIZABLE, ``VolumeLabel`` CHAR(32) LOCALIZABLE PRIMARY KEY ``DiskId``)"
Invoke-Sql "CREATE TABLE ``File`` (``File`` CHAR(72) NOT NULL, ``Component_`` CHAR(72) NOT NULL, ``FileName`` CHAR(255) NOT NULL LOCALIZABLE, ``FileSize`` LONG NOT NULL, ``Version`` CHAR(72), ``Language`` CHAR(20), ``Attributes`` INTEGER, ``Sequence`` INTEGER NOT NULL PRIMARY KEY ``File``)"
Invoke-Sql "INSERT INTO ``Media`` (``DiskId``,``LastSequence``) VALUES (1,0)"

# --- property rows ---
$props = @{
    'ProductCode'     = $productCode
    'ProductLanguage' = '1033'
    'ProductVersion'  = '1.0.0'
    'ProductName'     = 'RedFlick Persistence Package'
    'Manufacturer'    = 'F0RT1KA Lab'
    'ALLUSERS'        = ''
}
foreach ($k in $props.Keys) { if ($props[$k]) { Invoke-Sql "INSERT INTO ``Property`` (``Property``,``Value``) VALUES ('$k','$($props[$k])')" } }

# --- directory rows (System64Folder resolves to the 64-bit System32).
#     MSI SQL cannot take an empty value slot — omit nullable columns instead.
Invoke-Sql "INSERT INTO ``Directory`` (``Directory``,``DefaultDir``) VALUES ('TARGETDIR','SourceDir')"
Invoke-Sql "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('System64Folder','TARGETDIR','.')"
Invoke-Sql "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('ProgramFiles64Folder','TARGETDIR','.')"

# --- feature/component ---
Invoke-Sql "INSERT INTO ``Feature`` (``Feature``,``Title``,``Description``,``Display``,``Level``,``Directory_``,``Attributes``) VALUES ('F0Main','MainFeature','RedFlick persistence',1,1,'TARGETDIR',0)"
$componentId = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
Invoke-Sql "INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``) VALUES ('F0Comp','$componentId','TARGETDIR',0)"
Invoke-Sql "INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('F0Main','F0Comp')"

# --- standard actions (canonical sequence numbers, copied from a system MSI;
#     without them msiexec rejects the package) ---
$execStd = @(
    @('LaunchConditions', '', 400), @('CostInitialize', '', 800), @('FileCost', '', 900),
    @('CostFinalize', '', 1000), @('InstallValidate', '', 1400), @('InstallInitialize', '', 1500),
    @('ProcessComponents', '', 1600), @('InstallFiles', '', 4000), @('RegisterUser', '', 6000),
    @('RegisterProduct', '', 6100), @('PublishComponents', '', 6200), @('PublishProduct', '', 6400),
    @('InstallFinalize', '', 6600)
)
foreach ($a in $execStd) {
    if ($a[1]) {
        Invoke-Sql "INSERT INTO ``InstallExecuteSequence`` (``Action``,``Condition``,``Sequence``) VALUES ('$($a[0])','$($a[1])',$($a[2]))"
    } else {
        Invoke-Sql "INSERT INTO ``InstallExecuteSequence`` (``Action``,``Sequence``) VALUES ('$($a[0])',$($a[2]))"
    }
}
# UI-phase subset (silent installs skip it; kept for interactive completeness)
$uiStd = @(
    @('LaunchConditions', 400), @('CostInitialize', 800), @('FileCost', 900), @('CostFinalize', 1000)
)
foreach ($a in $uiStd) {
    Invoke-Sql "INSERT INTO ``InstallUISequence`` (``Action``,``Sequence``) VALUES ('$($a[0])',$($a[1]))"
}

# --- CustomActions: type 34 (command line with directory reference),
#     impersonated (default), creating the persistence task trio ---
$seq = 5101
for ($i = 0; $i -lt $tasks.Count; $i++) {
    $t = $tasks[$i]
    $cmdLine = "[System64Folder]cmd.exe /c schtasks.exe /Create /TN `"$($t.Name)`" /TR `"$($t.Action)`" $($t.Extra) /F"
    $actionId = "CreateRedFlickTask$($i + 1)"
    Invoke-Sql "INSERT INTO ``CustomAction`` (``Action``,``Type``,``Source``,``Target``) VALUES ('$actionId',34,'System64Folder','$cmdLine')"
    Invoke-Sql "INSERT INTO ``InstallExecuteSequence`` (``Action``,``Condition``,``Sequence``) VALUES ('$actionId','NOT Installed',$seq)"
    $seq++
}

# --- summary information: codepage FIRST, then required properties, then
#     Persist() — property sets are only written to the stream on Persist
#     (lab finding: without Persist the summary stays empty and msiexec
#     rejects the package with 1620 "could not be opened") ---
$si = $db.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null, $db, @(10))
$si.GetType().InvokeMember('Property', 'SetProperty', $null, $si, @(1,  1252)) | Out-Null
$si.GetType().InvokeMember('Property', 'SetProperty', $null, $si, @(2,  'Installation Database')) | Out-Null
$si.GetType().InvokeMember('Property', 'SetProperty', $null, $si, @(7,  ';1033')) | Out-Null
$si.GetType().InvokeMember('Property', 'SetProperty', $null, $si, @(9,  $packageCode)) | Out-Null
$si.GetType().InvokeMember('Property', 'SetProperty', $null, $si, @(14, 200)) | Out-Null
$si.GetType().InvokeMember('Property', 'SetProperty', $null, $si, @(15, 2)) | Out-Null

$si.GetType().InvokeMember('Persist', 'InvokeMethod', $null, $si, $null) | Out-Null

$db.GetType().InvokeMember('Commit', 'InvokeMethod', $null, $db, $null) | Out-Null

Write-Host "MSI authored: $OutPath"
Write-Host "ProductCode:  $productCode"
Write-Host "Size:         $((Get-Item $OutPath).Length) bytes"
