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

rem /Z7 + /DEBUG: a PDB beside the exe, so the watchdog and crash reports can
rem name the loader's own functions (DbgHelp)
clang-cl /nologo /O2 /W3 /Z7 /D_CRT_SECURE_NO_WARNINGS -Wno-unused-function -Iout\zydis-amalg ^
    /Fe:out\afw-loader.exe /Foout\ ^
    src\main.c src\elf_loader.c src\bionic_shim.c src\platform.c src\tls_patch.c src\crash.c ^
    src\patch.c src\attest.c src\sha256.c src\syscall.c src\thread.c src\fd.c src\filemap.c src\funcs.c src\vma.c src\tls_layout.c src\tls_static.c src\loader_api.c src\callback_bridge.c ^
    src\axml.c src\apk.c src\win_gui.c src\android_native.c src\gles_bridge.c src\jni_bridge.c src\dex_vm.c src\apk_runner.c src\exec.c out\zydis-amalg\Zydis.c ^
    /link /DEBUG:FULL dbghelp.lib user32.lib gdi32.lib
if errorlevel 1 exit /b 1
echo Built out\afw-loader.exe
