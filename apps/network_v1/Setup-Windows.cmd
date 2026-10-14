@echo off
cd /d "%~dp0..\.."
pythonw -B -m apps.network_v1.setup
