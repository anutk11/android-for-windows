@echo off
setlocal
cd /d "%~dp0"
if exist "tools\fetch_bionic.py" (
    set "FETCH=tools\fetch_bionic.py"
) else if exist "fetch_bionic.py" (
    set "FETCH=fetch_bionic.py"
) else (
    echo ERROR: fetch_bionic.py not found!
    pause
    exit /b 1
)
echo === Android-for-Windows: One-time Android 14 ART Runtime Setup ===
echo Extracting real Android 14 x86_64 bionic + libart.so runtime locally into .\runtime ...
python -I "%FETCH%" runtime --art-full
if errorlevel 1 (
    echo.
    echo ERROR: Runtime setup failed. Make sure Python 3.9+ is installed and internet access is available.
    pause
    exit /b 1
)
echo.
echo === Runtime ready! ===
echo Double-click run_apk.bat (or drag any .apk onto run_apk.bat) to launch!
pause
