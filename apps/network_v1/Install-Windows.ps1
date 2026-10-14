param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [Parameter(Mandatory=$true)][string]$LinuxDestination,
    [string]$Distribution = 'Ubuntu-24.04'
)
$ErrorActionPreference = 'Stop'
# Windows delivery runs the POSIX wallet/node within the existing WSL distro.
# Never install a distro, alter N2 data, start mining or activate Tor here.
$archivePath = (Resolve-Path -LiteralPath $Archive).Path
$rootPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$linuxArchive = (& wsl -d $Distribution -- wslpath -a -u $archivePath).Trim()
if ($LASTEXITCODE -ne 0) { throw 'WSL archive path unavailable' }
$linuxSource = (& wsl -d $Distribution -- wslpath -a -u $rootPath).Trim()
if ($LASTEXITCODE -ne 0) { throw 'WSL source path unavailable' }
& wsl -d $Distribution --cd $linuxSource -- python3 -B -m apps.network_v1.release install --archive $linuxArchive --destination $LinuxDestination
if ($LASTEXITCODE -ne 0) { throw 'Private no-clobber installation failed; inspect partial destination, never reuse it' }
