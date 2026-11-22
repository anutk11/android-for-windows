@echo off
rem Double-click: runs the WRFSBASE experiment and keeps the window open.
cd /d "%~dp0"
fsbase_probe.exe
echo.
pause
