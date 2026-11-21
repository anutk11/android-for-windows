# Android for Windows

הרצת אפליקציות אנדרואיד על ווינדוס **בלי אמולטור, בלי VM ובלי WSA**.
הקוד של אנדרואיד רץ כתהליך רגיל של ווינדוס, ורק השכבה התחתונה (libc, גרפיקה, אודיו) מוחלפת במימוש מעל Windows API.

Run Android apps on Windows natively — no emulator, no VM. Android code runs as a normal Windows process; only the bottom layer (libc, graphics, audio) is reimplemented on top of the Windows API.

## הורדה ובדיקה

1. היכנסו ל-[Releases → nightly](../../releases/tag/nightly) והורידו את `android-for-windows-nightly.zip`.
2. חלצו את הקבצים ולחצו פעמיים על `run-test.bat`.
3. אם ווינדוס מציג אזהרת SmartScreen, בחרו "More info" ואז "Run anyway". הקובץ לא חתום דיגיטלית.

## ארכיטקטורה

| שכבה באנדרואיד | מחליף בווינדוס | סטטוס |
|---|---|---|
| linker64 (טעינת `.so`) | `src/elf_loader.c` | ✅ M0 |
| bionic libc | `src/bionic_shim.c` ("bionic-win") | 🟡 התחלה |
| ART (Java/Kotlin) | ART מ-AOSP, מקומפל לווינדוס | ⏳ M1 |
| Binder | Binder במצב משתמש (shared memory + ALPC) | ⏳ M2 |
| SurfaceFlinger | חלון HWND לכל Activity + DirectComposition | ⏳ M3 |
| OpenGL ES | ANGLE → Direct3D | ⏳ M4 |
| קוד ARM | Windows on ARM: ישירות; x86: תרגום בינארי | ⏳ M5 |
| Google Play Services | microG | ⏳ M5 |

## אבני דרך

- **M0** ✅ טעינת ספריית `.so` אמיתית של אנדרואיד (נבנתה ב-NDK) בתוך תהליך ווינדוס, וקריאה לפונקציות שלה
- **M1** ART מריץ "Hello World" מקובץ DEX
- **M2** Binder ו-servicemanager
- **M3** Activity ראשונה מציירת בחלון ווינדוס
- **M4** גרפיקת GLES דרך ANGLE ואפליקציות פשוטות
- **M5** קוד ARM ו-microG

## איך M0 עובד

1. קורא את קובץ ה-ELF ומוודא שהוא ספרייה של x86_64.
2. מעתיק את הסגמנטים לזיכרון בעזרת `VirtualAlloc`.
3. מחבר כל פונקציה שהספרייה מייבאת (`malloc`, `puts`, `__android_log_write` ועוד) למימוש שלנו.
4. מחיל relocations: RELA, JUMP_SLOT ו-RELR.
5. קובע הרשאות זיכרון: קוד ניתן להרצה, ואזור RELRO לקריאה בלבד.
6. מריץ את ה-constructors של הספרייה.

**גשר ה-ABI:** אנדרואיד משתמשת ב-System V ABI, וווינדוס ב-Microsoft x64 ABI. כל פונקציה שעוברת בין העולמות מסומנת `SYSV` (`__attribute__((sysv_abi))`), וכך clang מייצר אוטומטית את קוד המעבר. לכן הפרויקט נבנה עם **clang-cl** ולא עם cl.exe.

**פונקציה חסרה:** אם קוד אנדרואיד קורא לפונקציה שעוד לא מימשנו, מוצגת הודעה עם שם הפונקציה, במקום קריסה. כך יודעים בדיוק מה לממש בשלב הבא.

## בעיות פתוחות

- **Stack protector:** ספריות אמיתיות של NDK קוראות את ה-guard מ-`fs:0x28` (TLS של לינוקס). בווינדוס x64 אין fs. רעיון לפתרון: לתקן את הקוד בזמן הטעינה, כך שיקרא מ-`gs:0x28`, שבווינדוס הוא `ArbitraryUserPointer` ב-TEB.
- **TLS** (`PT_TLS`), packed relocations מסוג APS2, ופונקציות varargs (`printf`, `__android_log_print`).

## בנייה

הבנייה מתבצעת אוטומטית ב-GitHub Actions בכל push. בנייה מקומית: `build.bat` (נדרשים clang-cl וה-Windows SDK).
