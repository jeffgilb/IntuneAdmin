
<#
.SYNOPSIS
    Performs full remediation for Windows Autopatch compliance issues.
    Helpful when migrating from ConfigMgr/WSUS to Autopatch to remove legacy registry settings.

.DESCRIPTION
    This script is designed to remediate issues related to Windows Autopatch on Intune-managed devices.
    It checks for required configurations, applies necessary fixes, and ensures the device meets
    compliance standards for Autopatch enrollment and patching.

.PARAMETER None
    This script does not require any parameters. All logic is handled internally.

.EXAMPLE
    PS C:\> .\Autopatch_Remediation.ps1
    Runs the remediation process on the local device.

.NOTES
    Author: Jeff Gilbert
    Created: 12.10.2025
    Version: 1.0
    File: Autopatch_Remediation.ps1
    Location: GitHub\IntuneRemediations\autopatchFullRemediation
        - PowerShell 5.1 or later
        - Device enrolled in Intune

.LINK
    https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/

#>
# ------------------------------ Configuration & Logging ------------------------------
# Logging optional for remediations because the script output is displayed in the Intune portal's device status for your remediation.
# IME diagnostics directory and transcript path
$logDir  = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\IntuneManagementExtension\Logs'# This path is pulled when Intune collects diagnostics.
$scriptName = "Autopatch_Remediation.log"
$logFile = Join-Path -Path $logDir -ChildPath $scriptName # Default log name is the name of this script.
write-host $logFile
#-------------------------------------- Functions -------------------------------------
function Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]    [ValidateNotNullOrEmpty()]  [string] $Message,
        [Parameter(Mandatory = $false, Position = 1)]   [string] $Component = 'Remediation',
        [Parameter(Mandatory = $false, Position = 2)]   [ValidateSet(1, 2, 3)]      [int] $Type = 1
    )
  # Capture once to avoid drift between Time/Date
    $now = Get-Date 
    $Time = $now.ToString('HH:mm:ss.ffffff', [System.Globalization.CultureInfo]::InvariantCulture)
    $Date = $now.ToString('MM-dd-yyyy',      [System.Globalization.CultureInfo]::InvariantCulture)
  # Escape message for CMTrace payload (XML-like). SecurityElement.Escape handles &, <, >, " (quotes) safely
    $escapedMessage = [System.Security.SecurityElement]::Escape($Message)
  # Identify if it was a function that called Log and make it the component; default is "Remediation"
    $scriptFullPath = $PSCommandPath ; $scriptName = Split-Path -Path $scriptFullPath -Leaf
    $caller = (Get-PSCallStack)[1].Command
    if (-not ($caller -eq $scriptName)){ $Component = $caller }  
  # Build CMTrace entry (keep empty attributes as per CMTrace spec)
    $logLine = ('<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">' `
                -f $escapedMessage, $Time, $Date, $Component, $Type)
    try { # Write the log entry
        $dir = Split-Path -Path $LogFile -Parent # Ensure directory exists
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -LiteralPath $LogFile -Value $logLine -Encoding UTF8
    }
    catch { # If writing fails write error
        Write-Error -Message ("Failed to write log to '{0}': {1}" -f $LogFile, $_.Exception.Message)
        return
    }
  # Write all log lines to console for interactive testing/transcript capture
    switch ($Type) {
        1 { Write-Host $Message -ForegroundColor Gray }
        2 { Write-Host $Message -ForegroundColor Yellow }
        3 { Write-Host $Message -ForegroundColor Red }
        default { Write-Host $Message }
    }
}

function Remove-RegistryKeys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]    [ValidateNotNullOrEmpty()]  [string[]] $Paths
    )

    foreach ($p in $Paths) {
        if ($p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'){
          # Remove all child registry keys under WindowsUpdate if present (ie AU)
            if ( Get-ChildItem -Path $p ){ 
                $global:regKeysRemoved++
                Log "  Removing child registry keys from WindowsUpdate" -Type 2
                Get-ChildItem -Path $p | Remove-Item -Recurse -Force
            }
          # Find the registry values present at Windows Update
            $item = Get-Item -Path $p -ErrorAction Stop
          # Keep list: '' (Default), 'AcceptTrustedPublisherCerts'
            $keep = @('', 'AcceptTrustedPublisherCerts')
            $allValues   = $item.Property
            $removeNames = $allValues | Where-Object { $_ -notin $keep }
            if ( $removeNames -or $removeNames.Count -gt 0) {
                Log "  Removing WSUS registry value: $($removeNames -join ', ')" -Type 2
                $global:regKeysRemoved++
                foreach ($name in $removeNames) {
                    try { Remove-ItemProperty -Path $p -Name $name -ErrorAction Stop } 
                    catch { Log "  Failed to remove '$name': $($_.Exception.Message)" -Type 3 }
                } 
            }
        } else { # Take out any cached GPUpdate registry values (non-blocking)
            try {
                if (Test-Path -LiteralPath $p) {
                    Log "  Removing registry path: $p" -Type 2
                    Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
                    if (-not (Test-Path -LiteralPath $p)) { Log "Removed: $p" } 
                    else { Log "  Unable to remove '$p'." -Type 3 }
                } 
            }
            catch { Log "  Failed to remove '$p': $($_.Exception.Message)" -Type 3 }    
        }
    } 
    
    return $global:regKeysRemoved
}

function Validate-RegistryKeys {
    <#

    EXAMPLE
                    
                $RegistryPath = "HKLM:\Software\MyApp"
                $ValueName = "Enabled"
                $ExpectedValue = 1

                if (Test-Path $RegistryPath) {
                    $currentValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
                    
                    if ($null -eq $currentValue) {
                        Write-Host "Registry value does not exist." -ForegroundColor Yellow
                    }
                    elseif ($currentValue -eq $ExpectedValue) {
                        Write-Host "Registry value is set correctly: $currentValue" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Registry value is NOT set correctly. Current value: $currentValue (expected: $ExpectedValue)" -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "Registry path does not exist." -ForegroundColor Yellow
                }



    If the update source or UseUpdateClassPolicySource keys are not set to 0, delete them. they'll come back with an WUFB scan:
    Ensure that HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState\PolicySources is set to 4
    Ensure these keys (if they exist) are set to -1 (4294967295) OR 0
    SetPolicyDrivenUpdateSourceForDriverUpdates
    SetPolicyDrivenUpdateSourceForFeatureUpdates
    SetPolicyDrivenUpdateSourceForOtherUpdates
    SetPolicyDrivenUpdateSourceForQualityUpdates


$RegistryPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState"
If ((Get-ItemProperty -Path $RegistryPath -Name "PolicySources").PolicySources -eq 4){Write-Host "Yepper"
} Else {Write-Host "Failed"}

$RegistryPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState"
If ((Get-ItemProperty -Path $RegistryPath -Name "SetPolicyDrivenUpdateSourceForDriverUpdates").SetPolicyDrivenUpdateSourceForDriverUpdates -eq 1){
    Remove-ItemProperty -Path $RegistryPath -Name "SetPolicyDrivenUpdateSourceForDriverUpdates"
    # Check to be sure it's gone
    (Get-ItemProperty -Path $RegistryPath).SetPolicyDrivenUpdateSourceForDriverUpdates
    Write-Host "Deleted key"
} Else {Write-Host "No issue"}


Get-ItemProperty -Path $RegistryPath


Set-ItemProperty -Path $RegistryPath -Name "SetPolicyDrivenUpdateSourceForDriverUpdates" -Value 0
Set-ItemProperty -Path $RegistryPath -Name "IsWUfBConfigured" -Value 0
Set-ItemProperty -Path $RegistryPath -Name "IsWUfBDualScanActive" -Value 0


Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"


SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState\PolicySources


    UseUpdateClassPolicySource should be 0





POLICIES TO CHECK
Windows-CSP-Remove Check for Updates Access








    #>
}
function Check-Tasks {
[CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]    [ValidateNotNullOrEmpty()]      [string] $TaskPath,
        [Parameter(Mandatory, Position = 1)]    [ValidateNotNullOrEmpty()]      [string] $TaskName
    )
  # Try to get the task if it exists
    try { $existing = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop } 
    catch { $existing = $null }

    if ($existing) { Log "  $TaskName is present." } 
    else {
        $global:taskNotFound++
        If ($taskName = 'Microsoft Compatibility Appraiser'){   
            Log "  Task not found. Creating $taskName ..." -Type 2
            $executePath = Join-Path $env:WINDIR "System32\sc.exe"
            # Action
            $action = New-ScheduledTaskAction -Execute $executePath -Argument 'start InventorySvc'
            function Get-Next3AM {
                $now = Get-Date
                $today3 = Get-Date -Hour 3 -Minute 0 -Second 0
                if ($now -lt $today3) { $today3 } else { $today3.AddDays(1) }
            }
            $t1 = New-ScheduledTaskTrigger -Once -At (Get-Next3AM)
            $t2 = New-ScheduledTaskTrigger -Once -At 03:00 `
                    -RepetitionInterval (New-TimeSpan -Hours 6) `
                    #-RepetitionDuration (New-TimeSpan -Hours 23 -Minutes 55)
            $t1.Repetition = $t2.Repetition
        # Run as LocalSystem with highest privileges
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        # Reasonable settings similar to built-in tasks
            $settings  = New-ScheduledTaskSettingsSet `
                        -AllowStartIfOnBatteries `
                        -DontStopIfGoingOnBatteries `
                        -StartWhenAvailable `
                        -Compatibility Win8
        # Register the task
            Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath `
                -Description "Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program." `
                -Action $action `
                -Trigger $t1 `
                -Principal $principal `
                -Settings $settings `
                -ErrorAction Stop `
                | Out-Null
            Log "  Created $taskName"
        }
    }

    # Enable (in case it’s disabled) and run the task now
    try {
            try { $existing = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop 
                if ($existing.State -eq 'Disabled') {
                Log "$taskName task is DISABLED." -Type 2
                $global:tasksChanged++
                Log "  Enabling $taskName."
                Enable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null }
            } catch { $existing = $null }
        Start-ScheduledTask  -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
        Log "  Triggered a run of $taskName"
    } catch {
        Write-Warning "  Could not start task: $($_.Exception.Message)"
    }
}

function Ensure-ServiceRunning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]            [ValidateNotNullOrEmpty()]  [string] $ServiceName,
        [Parameter(Mandatory = $false, Position = 1)]   [ValidateRange(5, 300)]     [int] $TimeoutSeconds = 60
    )

    try {  $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($svc.Status -eq 'Running') {
            Log "  $ServiceName is running; restarting to refresh state."
            Restart-Service -Name $ServiceName -ErrorAction Stop
        } else {
            Log "  $ServiceName is stopped; starting service." -Type 2
            Start-Service -Name $ServiceName -ErrorAction Stop
        }

        # Wait until running or timeout
        $elapsed = 0
        do {
            Start-Sleep -Seconds 1
            $elapsed++
            $svc.Refresh()
            if ($svc.Status -eq 'Running') { Log "  $ServiceName is running." ; break }
        } while ($elapsed -lt $TimeoutSeconds)

        if ($svc.Status -ne 'Running') {
            throw "Service '$ServiceName' failed to reach 'Running' within $TimeoutSeconds seconds."
        }
    }
    catch { Log "  Ensure-ServiceRunning error: $($_.Exception.Message)" -Type 3 ; throw }
}

function Invoke-UpdateScan {
    [CmdletBinding()]   
    param()

    try {
        $uso = Get-Command USOClient.exe -ErrorAction SilentlyContinue
        if ($uso) {
            Log "  Initiating update scan via USOClient..."
            & $uso.Source 'StartInteractiveScan'  # USOClient.exe StartInteractiveScan
            Log "  USOClient scan triggered."
        } else { Log "  USOClient.exe not found. Skipping interactive scan trigger." -Type 2 }
    }
    catch { Log "Invoke-UpdateScan error: $($_.Exception.Message)" -Type 3 }
}

# --------------------------------------- Main ----------------------------------------
$ErrorActionPreference = 'Stop'  # Ensure non-terminating errors become terminating for try/catch
$global:taskNotFound = 0
$global:tasksChanged = 0
$global:regKeysRemoved = 0
try {
    Log "----------------------------------- Begin Remediation ---------------------------------"
    # 1) Remove WSUS/GPO policy keys that can block WU/MU
        Log "Checking Windows Update registry key configuration."
        $regPaths = @(
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
            'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\GPCache'
        )
        $global:regKeysRemoved = Remove-RegistryKeys -Paths $regPaths
        
    # 2) Ensure Windows Update service is running
        Log "Checking Windows Update service is running."
        Ensure-ServiceRunning -ServiceName 'wuauserv' -TimeoutSeconds 60

    # 3) Ensure scheduled tasks are Ready  
        Log "Checking required scheduled tasks."
        $schTasks = @(
            @{ TaskPath = '\Microsoft\Windows\Application Experience\'; TaskName = 'Microsoft Compatibility Appraiser'},
            @{ TaskPath = '\Microsoft\Windows\Flighting\OneSettings\'; TaskName = 'RefreshCache'}
        )
        ForEach ($scTask in $schTasks){
             Check-Tasks -TaskPath $scTask.TaskPath -TaskName $scTask.TaskName    
        }

    # 4) Trigger an update scan
        Log "Initiating a Windows Updates scan."
        Invoke-UpdateScan

    # 5) Build remediation summary for in Intune admin center (Log function will also Write-Host )
        $summary = @()
        if ( $global:regKeysRemoved -gt 0 ){ $summary += "Registry updated ($global:regKeysRemoved)" }
        if ( $global:taskNotFound -gt 0 ){ $summary += "Tasks missing ($global:taskNotFound)" }
        if ( $global:tasksChanged -gt 0 ){ $summary += "Tasks enabled ($global:tasksChanged)" }
        
	if ($summary ){ Log "$($summary)" -Type 3 } # Remediation failed 
        else { Log "Healthy Autopatch configuration" } # Remediation successful
        } 

    catch {
        Log ("Error: $($_.Exception.Message)") -Type 3
    }
Exit


