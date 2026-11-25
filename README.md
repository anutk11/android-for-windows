# Android for Windows

הרצת אפליקציות אנדרואיד (`.apk`) על Windows **בלי אמולטור, בלי VM ובלי WSA** — תהליך Windows x64 טבעי שמטעין ומריץ ישירות את `libc.so`, `libc++_shared.so` ו-`libart.so` האמיתיים של Android 14, עם חלון Win32, אודיו WinMM (`waveOut`) וטעינת ספריות JNI טבעיות מתוך ה-APK.

Run real Android `.apk` apps natively on Windows x64 — **zero VM, zero emulator**. Runs real Android 14 Bionic `libc.so` and `libart.so` directly inside a native Windows process with Win32 GUI rendering, touch/mouse/keyboard input, WinMM PCM audio, and native `lib/x86_64/*.so` JNI execution.

## הפעלה מהירה ב-Windows (3 צעדים)

1. **הורדה:** הורידו את `android-for-windows-nightly.zip` מ-[Releases → nightly](../../releases/tag/nightly) (או את artifact `afw-windows` מ-GitHub Actions) וחלצו לתיקייה.
2. **התקנת סביבת הריצה (חד-פעמי):** הריצו את `setup_runtime.bat` (מוריד ומחלץ מקומית את קבצי Android 14 x86_64 Bionic + ART אל `runtime\`; נדרשת Python 3.9+).
3. **הרצת APK:**
   - לחצו פעמיים על `run_apk.bat` כדי להריץ את אפליקציית הדמו המובנית (`sample_music_app.apk` — סינתיסייזר ואוסצילוסקופ אודיו עם ספריית C++ JNI).
   - או גררו כל קובץ `.apk` אל `run_apk.bat`, או הריצו מהטרמינל:
     ```bat
     afw-loader.exe --apk my_app.apk
     ```

### דגלים שימושיים ל-CLI
```bat
afw-loader.exe --apk app.apk [--width=420] [--height=740] [--headless] [--screenshot=screen.bmp] [--inject-click=X,Y] [--auto-exit=MS]
```

## ארכיטקטורה וסטטוס שערים

| שער / שכבה | מימוש ב-Windows | סטטוס |
|---|---|---|
| **M0 / ELF Loader** | `src/elf_loader.c` (RELA, RELR, APS2, IFUNC, RELRO, `dlopen`/`dlsym`) | ✅ עבר ב-CI |
| **G1 / Bionic `libc.so`** | `src/syscall.c`, `src/fd.c`, `src/vma.c`, `src/tls_patch.c` (שכתוב `syscall` + `fs:`) | ✅ עבר ב-CI |
| **G2 / Pthreads + C++ + Dynamic TLS** | `src/thread.c`, `src/tls_static.c`, `src/callback_bridge.c` (`clone`, `libc++_shared.so`, `thread_local`, DTV) | ✅ עבר ב-CI |
| **G3 / Real Android 14 `libart.so`** | `--art-gs` (אמולציית `%gs:` ל-ART), BoringSSL FIPS HMAC, `JNI_CreateJavaVM`, ריבוי חוטים + GC + JNI | ✅ עבר ב-CI |
| **G4/G5 / Win32 GUI + Audio + APK Runner** | `src/win_host.c` (Win32 HWND/DIB + WinMM `waveOut`), `framework/java/` (`afw-framework.jar`), `test/afw_apk_launcher.cpp` | ✅ עבר ב-CI |

## איך זה עובד מתחת למכסה המנוע

1. **טוען ELF ושכתוב בזמן טעינה (`src/elf_loader.c`, `src/patch.c`, `src/tls_patch.c`):** טוען קבצי ELF x86_64 של אנדרואיד לזיכרון Windows, מנתח זרימת בקרה (CFG), משכתב הוראות `syscall`, `%fs:` ו-`%gs:` (ב-`libart.so`) ל-trampolines בטוחים, ומעדכן חתימת FIPS של BoringSSL `libcrypto.so`.
2. **שכבת Linux Syscall & Threads (`src/syscall.c`, `src/vma.c`, `src/fd.c`, `src/thread.c`):** ממפה `mmap`/`mprotect`/`madvise`, מערכת קבצים וירטואלית (`/proc/self/maps`, `/dev/null`), `futex` (כולל `FUTEX_REQUEUE`), `clone(56)` ו-`rt_sigtimedwait`/`tgkill` מעל Win32.
3. **ART + Android SDK (`test/afw_apk_launcher.cpp`, `framework/java/`):** מאתחל את `libart.so` האמיתי של Android 14, מפענח `AndroidManifest.xml` (AXML בינארי) ו-`resources.arsc`, מחלץ ספריות `lib/x86_64/*.so`, מריץ את מחזור החיים של `Application`/`Activity`/`View`/`Canvas`/`AudioTrack`, ומציג את הפריימים בחלון Windows טבעי עם אודיו WinMM.

## מגבלות ידועות (שלב הבא)

- **ארכיטקטורה:** כרגע מריץ אפליקציות עם קוד Java/Kotlin טהור או ספריות native של `x86_64` (תרגום ARM64-to-x86_64 ל-`.so` בינאריים מתוכנן בהמשך).
- **גרפיקה:** ציור `Canvas`/`View` בתוכנה מעל Win32 DIB; OpenGL ES / Vulkan (ANGLE → D3D11) ותמיכה רחבה יותר ב-AndroidX / Google Play Services (microG) נמצאים בהמשך מפת הדרכים.

## בנייה מקומית

נדרשים `clang-cl` ו-Windows SDK (הבנייה רצה אוטומטית בכל push ב-GitHub Actions):
```bat
build.bat
```
