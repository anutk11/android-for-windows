@echo off
rem Double-click to run the M0 test. The window stays open so you can read it.
cd /d "%~dp0"
afw-loader.exe libhello.so
echo.
pause
