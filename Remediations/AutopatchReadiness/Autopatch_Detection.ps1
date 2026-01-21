<#
.SYNOPSIS
    Validate Autopatch-related registry values and scheduled tasks.

.DESCRIPTION
    Looks for and counts incorrect registry value names present under specific keys and
    scheduled task issues (disabled or not found).

.EXAMPLE
    .\Autopatch_Detection.ps1

.NOTES
    Author: Jeff Gilbert
    Created: 12.10.2025
    Version: 1.0
    File: Autopatch_Detection.ps1
    Location: https://github.com/jeffgilb/IntuneAdmin/blob/main/Remediations/AutopatchReadiness/Autopatch_Detection.ps1
        - PowerShell 5.1 or later
        - Device enrolled in Intune
#>

#----------------------------------------------------- Script Variables -----------------------------------------------------
$script:taskIssues = 0
$script:regKeysFound = 0
#-------------------------------------------------------- Functions ---------------------------------------------------------
function Find-RegistryKeys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]    [ValidateNotNullOrEmpty()]  [string[]] $Paths
    )

    foreach ($key in $regPaths) {
        If (Test-Path $key){        
            # Find the registry values present at Windows Update
                $item = Get-Item -Path $key -ErrorAction Stop
            # Keep list: '' (Default), 'AcceptTrustedPublisherCerts'
                $keep = @('', 'AcceptTrustedPublisherCerts')
                $allValues = $item.Property
                $foundNames = $allValues | Where-Object { $_ -notin $keep }
                if ( $foundNames -or $foundNames.Count -gt 0) { 
                    $script:regKeysFound++ }
            # Look for child registry keys under WindowsUpdate if present (ie AU)
                $childKey = Get-ChildItem -Path $key
                if ( $childKey ){ $script:regKeysFound++ }
        } 
    }   
}

function Check-Tasks {
[CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]    [ValidateNotNullOrEmpty()]      [string] $TaskPath,
        [Parameter(Mandatory, Position = 1)]    [ValidateNotNullOrEmpty()]      [string] $TaskName
    )

    # Try to get the task if it exists
        $existing = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
        if ( $existing) { # Check to see if it's enabled
            if ($existing.State -eq 'Disabled') { $script:taskIssues++ } # Task is disabled
        } elseIf (!($existing)) { $script:taskIssues++ } # Task not found 
}

# --------------------------------------- Main ----------------------------------------
# No logging as output will be displayed in the Intune admin center.
$ErrorActionPreference = 'Stop'  # Ensure non-terminating errors become terminating for try/catch

try {
    # 1) Remove WSUS-related registry keys that block WU/MU
        $regPaths = @(
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        )    

        Find-RegistryKeys -Paths $regPaths
    
    # 2) Check if required scheduled tasks are enabled
        $schTasks = @(
            @{ TaskName = "Microsoft Compatibility Appraiser"; TaskPath = "\Microsoft\Windows\Application Experience\" },
            @{ TaskName = "RefreshCache"; TaskPath = "\Microsoft\Windows\Flighting\OneSettings\" }
        )

        ForEach ($scTask in $schTasks){ Check-Tasks -TaskPath $scTask.TaskPath -TaskName $scTask.TaskName }  

    # 3) Build remediation summary for in Intune admin center
      $summary = @()
      if ( $script:taskIssues -gt 0 ){ $summary += "Scheduled task issues ($script:taskIssues)" }
      if ( $script:regKeysFound -gt 0 ){ $summary += "Incorrect registry values ($script:regKeysFound)" }
      if ($summary ){ Write-Host $summary ; Exit 1 } # Remediate 
      else { Write-Host "Healthy Autopatch configuration" ; Exit 0 } # Remediation not needed

}catch { Write-Host "Error: $($_.Exception.Message)" }



