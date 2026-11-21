@echo off
rem Build afw-loader.exe. Needs clang-cl (LLVM) and the MSVC/Windows SDK libraries.
rem Run from a "Developer Command Prompt" or after ilammy/msvc-dev-cmd in CI.

where clang-cl >nul 2>nul
if errorlevel 1 (
    echo clang-cl was not found. Install LLVM or the "C++ Clang tools" Visual Studio component.
    exit /b 1
)

if not exist out mkdir out

rem Zydis (x86 disassembler) as one generated C file
if not exist out\zydis-amalg\Zydis.c (
    pushd third_party\zydis
    python assets\amalgamate.py >nul || (popd & echo Zydis amalgamation failed - run "git submodule update --init --recursive" & exit /b 1)
    popd
    if not exist out\zydis-amalg mkdir out\zydis-amalg
    move /y third_party\zydis\amalgamated-dist\Zydis.c out\zydis-amalg\ >nul
    move /y third_party\zydis\amalgamated-dist\Zydis.h out\zydis-amalg\ >nul
    rmdir third_party\zydis\amalgamated-dist
)

clang-cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS -Wno-unused-function -Iout\zydis-amalg ^
    /Fe:out\afw-loader.exe /Foout\ ^
    src\main.c src\elf_loader.c src\bionic_shim.c src\platform.c src\tls_patch.c src\crash.c ^
    src\patch.c src\syscall.c src\funcs.c out\zydis-amalg\Zydis.c
if errorlevel 1 exit /b 1
echo Built out\afw-loader.exe
