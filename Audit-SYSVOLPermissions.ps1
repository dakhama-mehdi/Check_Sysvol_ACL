﻿<#
.SYNOPSIS
    Audits and reports unauthorized NTFS permissions on SYSVOL files.

.DESCRIPTION
    This script recursively scans the SYSVOL folder (\\domain\SYSVOL\domain\)
    and identifies any non-inherited NTFS permissions granted to accounts 
    outside of a trusted list (e.g., SYSTEM, Domain Admins, etc.).
    
    Any deviation is flagged as a potential security issue.

.AUTHOR
    Mehdi Dakhama

.VERSION
    1.0

.LAST UPDATED
    2025-06-10
#>

Write-Host "⏳ Start analyse : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
$startTime = Get-Date

#List domain
$dnsDomain = $env:USERDNSDOMAIN

$baseSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -replace '-\d+$',''

$sids = @(
    'S-1-5-32-544', # Administrators
    'S-1-5-18',     # SYSTEM
    'S-1-3-0',      # CREATOR
    'S-1-5-32-549', # Server Operator
    "$baseSID-512", # Domain Admins
    "$baseSID-519", # Entreprise Admins
    "$baseSID-520", # Creator GPO
    'S-1-5-9'       # Enterprise DCs
)

$Trustgroups = $sids | ForEach-Object {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($_)
    try {
        $sid.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $sid.value  # $sid.Value Check SID if not resolve by machine
    }
}

# Permission Trust
$droitsAutorises = @(
    '-1610612736'
    'ReadAndExecute', 'Read', 'Synchronize',
    'ReadAndExecute, Synchronize', 'Read, Synchronize',
    'ReadAttributes, ReadExtendedAttributes, ReadPermissions, Synchronize'
)

 Get-ChildItem -Path \\$dnsDomain\sysvol\$dnsDomain -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {

$fichier = $_.FullName
 
  try {
        $acl = Get-Acl -Path $fichier #-ErrorAction Stop
    } catch {
        Write-Warning "Impossible de lire les ACL de : $fichier"
        return
    }

$acl.Access | Where-Object {
    $_.IsInherited -eq $false -and
    $Trustgroups -notcontains $_.IdentityReference.Value -and
    $_.FileSystemRights -notin $droitsAutorises
} | ForEach-Object {
    Write-Host "⚠️ ALERT: $($_.IdentityReference) has  '$($_.FileSystemRights)' on $fichier" -ForegroundColor Cyan
}
}


$endTime = Get-Date
$elapsed = $endTime - $startTime
Write-Host "✅ End Analyse at : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
Write-Host "⏱️ Time : $($elapsed.Hours)h $($elapsed.Minutes)m $($elapsed.Seconds)s" -ForegroundColor Yellow
