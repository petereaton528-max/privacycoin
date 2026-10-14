[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('provider','client')][string]$Role,
 [string]$Distro='Ubuntu-24.04', [Parameter(Mandatory=$true)][string]$LinuxRoot,
 [Parameter(Mandatory=$true)][string]$Config)
$ErrorActionPreference='Stop'
if($Distro -notmatch '^[A-Za-z0-9._-]+$' -or $LinuxRoot -notmatch '^/[A-Za-z0-9_./-]+$' -or $Config -notmatch '^/[A-Za-z0-9_./-]+$') { throw 'Use absolute Linux paths without whitespace/dot traversal and a valid distro name.' }
if(($LinuxRoot -split '/') -contains '..' -or ($Config -split '/') -contains '..'){throw 'Dot traversal rejected.'}
if(-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)){throw 'WSL unavailable. Run CHECK_N2_DESKTOP.cmd and read WSL2_SETUP.md.'}
Write-Host 'DEVNET preparation only. Provider stays local; public onion activation is not implemented.'
& wsl.exe -d $Distro --cd $LinuxRoot -- python3 deploy/n2/common/role.py $Role --config $Config
if($LASTEXITCODE -ne 0){Write-Error 'Role rejected or stopped. Check private configuration, native build and loopback dependencies; no fallback/payment was started.'}
exit $LASTEXITCODE
