@echo off
rem Build afw-loader.exe. Needs clang-cl (LLVM) and the MSVC/Windows SDK libraries.
rem Run from a "Developer Command Prompt" or after ilammy/msvc-dev-cmd in CI.

where clang-cl >nul 2>nul
if errorlevel 1 (
    echo clang-cl was not found. Install LLVM or the "C++ Clang tools" Visual Studio component.
    exit /b 1
)

if not exist out mkdir out
clang-cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS ^
    /Fe:out\afw-loader.exe /Foout\ ^
    src\main.c src\elf_loader.c src\bionic_shim.c src\platform.c src\tls_patch.c
if errorlevel 1 exit /b 1
echo Built out\afw-loader.exe
