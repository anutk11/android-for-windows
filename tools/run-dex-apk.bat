@echo off
cd /d "%~dp0"
echo Running Android Java DEX + JNI APK (dex_jni_demo.apk) on Windows...
echo Close the window to exit.
afw-loader.exe dex_jni_demo.apk
pause
