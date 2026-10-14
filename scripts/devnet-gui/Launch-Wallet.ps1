param([int]$Port = 48081)
$ErrorActionPreference = 'Stop'
$walletPython = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\pythonw.exe'
if (-not (Test-Path -LiteralPath $walletPython)) { throw 'Install Windows Python 3.12 including Tcl/Tk, or run gui.py with your Tk-enabled Python.' }
$walletScript = Join-Path $PSScriptRoot 'gui.py'
Start-Process -FilePath $walletPython -ArgumentList @(('"' + $walletScript + '"'), '--port', "$Port") -WindowStyle Hidden
