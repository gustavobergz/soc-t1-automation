@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0LocalAI.ps1" -Setup
if errorlevel 1 pause
