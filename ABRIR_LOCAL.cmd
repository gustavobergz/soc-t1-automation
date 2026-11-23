@echo off
cd /d "%~dp0"
start "SOC 205 mil - servidor local" /min node "%~dp0servidor-local.cjs"
start "" "http://127.0.0.1:8893/"
