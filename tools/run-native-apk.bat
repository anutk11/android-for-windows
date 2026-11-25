@echo off
cd /d "%~dp0"
echo Running Android NativeActivity APK (native_demo.apk) on Windows...
echo Close the window to exit.
afw-loader.exe native_demo.apk
pause
