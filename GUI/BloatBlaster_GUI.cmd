@echo off
rem Launches the BloatBlaster GUI (it asks for admin rights itself).
start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0BloatBlaster_GUI.ps1"
