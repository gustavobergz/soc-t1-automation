@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0VirtualBox.ps1" %*
if errorlevel 1 pause
