@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0VirtualBox.ps1" -LocalAI
if errorlevel 1 pause
