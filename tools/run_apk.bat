@echo off
setlocal
cd /d "%~dp0"
if not exist "runtime\libc.so" (
    echo Android 14 runtime not set up yet. Running setup_runtime.bat...
    call "%~dp0setup_runtime.bat"
    if errorlevel 1 exit /b 1
)
set "APK=%~1"
if "%APK%"=="" set "APK=sample_music_app.apk"
if not exist "%APK%" (
    echo Usage: run_apk.bat ^<path\to\app.apk^>
    echo   Or drag-and-drop any .apk file onto run_apk.bat!
    pause
    exit /b 2
)
echo Launching %APK% on native Windows (Zero VM / real Android 14 ART)...
afw-loader.exe --apk "%APK%" --runtime-dir=. %2 %3 %4 %5 %6 %7 %8 %9
set rc=%errorlevel%
if not "%rc%"=="0" (
    echo.
    echo App exited with code %rc%.
    pause
)
exit /b %rc%
