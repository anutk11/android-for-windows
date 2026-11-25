# Android-for-Windows APK Runner (`exp/apk-runner`)

This experimental branch adds an end-to-end Android `.apk` runner on top of the `afw-loader` ELF/Bionic/C++ runtime (Gates `G1`, `G2a`, `G2b`).

## What Works

1. **Self-Contained APK Container Loader (`src/apk.c`, `src/axml.c`):**
   - Reads ZIP Central Directory entries, decompresses DEFLATE (RFC 1951 stored/fixed/dynamic Huffman) with CRC-32 verification, and extracts `lib/x86_64/*.so` safely (path-traversal guarded).
   - Parses real Android Binary XML (`AndroidManifest.xml`, both UTF-16LE and UTF-8 string pools) to resolve package name, version, `MAIN`/`LAUNCHER` activity, and `android.app.lib_name`.
2. **Android NativeActivity + Win32 GUI + EGL/GLES2 (`src/win_gui.c`, `src/android_native.c`, `src/gles_bridge.c`):**
   - Opens a real Win32 `HWND` window (or deterministic `--headless` framebuffer with BMP screenshot export).
   - Provides exact LP64 NDK ABI shims for `ANativeActivity`, `ANativeWindow`, `AAssetManager`, `ALooper`, `AInputQueue`, `AConfiguration`, `liblog`, and a self-contained EGL 1.4 + OpenGL ES 2.0 rasterizer.
   - Tested end-to-end by **`native_demo.apk`** (real NDK C++17 `NativeActivity` + compressed asset + `std::runtime_error` + Bionic `pthread_create` + `EGL/GLES2` RGB triangle).
3. **Android Dalvik DEX VM + Bidirectional JNI 1.6 (`src/dex_vm.c`, `src/jni_bridge.c`):**
   - Executes real `javac` + Android SDK `d8` `classes.dex` bytecode with built-in `Activity`/`View`/`Canvas`/`Paint`/`Color`/`Log`/`AssetManager` runtime.
   - Provides official JNI 1.6 `JavaVM` + `JNIEnv` System V ABI vtables (including `JNI_OnLoad`, `RegisterNatives`, `Call*Method` / `Call*MethodV` / `Call*MethodA`, strings, and int arrays).
   - Tested end-to-end by **`dex_jni_demo.apk`** (real `classes.dex` -> `System.loadLibrary` -> `JNI_OnLoad` -> C++17 `std::runtime_error` -> JNI callback into Java `MainActivity.javaCallback` -> `Canvas` UI rendering).

## Quick Start on Windows

1. Provide Android 14 x86_64 Bionic runtime libraries (`libc.so`, `libm.so`, `libdl.so`) in a local folder (not distributed in this repo due to licensing; can be extracted from an official Google Android 14 x86_64 system image using `python tools/fetch_bionic.py bionic`):
   ```cmd
   set AFW_LIB_PATH=bionic
   ```
2. Run either demo APK with a live Win32 window:
   ```cmd
   afw-loader.exe native_demo.apk
   afw-loader.exe dex_jni_demo.apk
   ```
   Or double-click `run-native-apk.bat` / `run-dex-apk.bat`.
3. Headless / CI screenshot mode:
   ```cmd
   afw-loader.exe native_demo.apk --headless --frames=5 --width=640 --height=480 --screenshot=native_demo.bmp
   afw-loader.exe dex_jni_demo.apk --headless --frames=3 --width=640 --height=480 --screenshot=dex_jni_demo.bmp
   ```
