# This PowerShell script shows enabled users that have not logged in a certain amount of days and those that have never logged in.

# Verifies that the script is running as admin
function Check-IsElevated
{
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)

    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Output $true
    }            
    else
    {
        Write-Output $false
    }       
}

if (!(Check-IsElevated))
{
    throw "Please run this script from an elevated PowerShell prompt"            
}

import-module activedirectory 
$DaysInactive = Read-Host "Enter the max age in days [30]"
if ($DaysInactive -eq "") { $DaysInactive = 30 }
$time = (Get-Date).Adddays(-($DaysInactive))

Write-Host ""
Write-Host "List of users that have been inactive for at least $DaysInactive days:"
 
# Show users that have not logged in $DaysInactive
Get-ADUser -Filter {LastLogonTimeStamp -lt $time -and enabled -eq $true} -Properties LastLogonTimeStamp |
select-object Name,@{Name="Stamp"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}},DistinguishedName |
Sort -Property Stamp

# Show users that have never logged in (the Stamp will show "{}")
Get-ADUser -Filter {(lastlogontimestamp -notlike "*") -and (enabled -eq $true) -and (whencreated -lt $time)}
