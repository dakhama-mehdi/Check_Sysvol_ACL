
<#
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
    2025-07-10
#>

$Bannercolor = "Yellow"

function Show-HardenSysvolBanner {
   param (
        [string]$BannerColor
    )
Write-Host ""
Write-Host "╔═════════════════════════════════════════════════════╗" -ForegroundColor $Bannercolor
Write-Host "║ Welcome to Check_Sysvol_ACL v1.0                    ║" -ForegroundColor $Bannercolor
Write-Host "║ Auditing Active Directory SYSVOL & GPOs ACL         ║" -ForegroundColor $Bannercolor
Write-Host "║ Developed by HardenAD Community                     ║" -ForegroundColor $Bannercolor
Write-Host "╚═════════════════════════════════════════════════════╝" -ForegroundColor $Bannercolor
Write-Host ""
}

Show-HardenSysvolBanner -BannerColor $Bannercolor

Write-Host " Start analyse Sysvol at : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
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

$Scanfile  = 0
$Foundfile = 0

 Get-ChildItem -Path \\$dnsDomain\sysvol\$dnsDomain -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {

$file = $_.FullName
 
  try {
        $acl = Get-Acl -Path $file #-ErrorAction Stop
		$Scanfile++
    } catch {
        Write-Warning "Cannot read ACL of : $file"
        return
    }

$acl.Access | Where-Object {
    $_.IsInherited -eq $false -and
    $Trustgroups -notcontains $_.IdentityReference.Value -and
    $_.FileSystemRights -notin $droitsAutorises
} | ForEach-Object {
    Write-Host " Warning: $($_.IdentityReference) has '$($_.FileSystemRights)' on $file" -ForegroundColor Cyan
	$Foundfile++
}
}


$endTime = Get-Date
$elapsed = $endTime - $startTime
Write-Host " End Analyse at : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
Write-Host ("Scanned files: {0} - Incorrect ACL found: {1} - Elapsed: {2}h {3}m {4}s" -f $Scanfile, $Foundfile, $elapsed.Hours, $elapsed.Minutes, $elapsed.Seconds) -ForegroundColor Yellow
