@echo off
cd /d "%~dp0..\.."
python -B -m apps.network_v1.desktop %*
if errorlevel 1 pause
