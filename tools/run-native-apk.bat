@echo off
cd /d "%~dp0"
if "%AFW_LIB_PATH%"=="" if exist "bionic\libc.so" set "AFW_LIB_PATH=%~dp0bionic"
if "%AFW_LIB_PATH%"=="" if exist "out\bionic\libc.so" set "AFW_LIB_PATH=%~dp0out\bionic"
echo Running Android NativeActivity APK (native_demo.apk) on Windows...
echo Close the window to exit.
afw-loader.exe native_demo.apk
pause
