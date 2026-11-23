# תכנון Gate G2 (`G2a` / `G2b`): ריבוי חוטים (`pthreads` + `futex`), `MADV_DONTNEED` מקבילי, `filemap`, `dlopen`/TLS דינמי וחריגות C++

מצב: **גרסה 7 — שולב התיקון האחרון של בודק 2 (הפרדת בדיקת C11 data-race-free מ־probe אסמבלי ברמת פלטפורמה בסעיף 4.2) ונרשמה חתימתו בכתב על פיצול `G2a`/`G2b` והתחלת `G2-1`** (לפי [`docs/COLLABORATION.md`](../COLLABORATION.md), שורות 15, 77).
- **אישור התחלת `G2-1` (ניסוי מדידה בלבד):** מאושר ע"י **כל שלושת הבודקים** — **בודק 3** (Issue #19), **בודק 1** (`#issuecomment-7115807512`) ו**בודק 2** (ללא אישור מראש לארכיטקטורת `SYS_clone`).
- **פיצול `G2a`/`G2b` (כלל 6):** **הושגה הסכמה מלאה בכתב** של **המחבר הראשי**, **בודק 3**, **בודק 1** ו**בודק 2** (לפי 4 התנאים של בודק 1, רשום ב־[`docs/COLLABORATION.md`](../COLLABORATION.md)).

סימון לפי כלל 7: **[נמדד]** = מבוסס על קוד קיים או פלט CI מפורש, **[השערה]** = טענה שטרם נמדדה ותוכרע בניסוי (כלל 7א).

---

## 1. נקודת הפתיחה לאחר סגירת Gate G1 [נמדד]

`main` בקומיט `38d10ef` (ריצת CI [`45252862246`](https://github.com/anutk11/android-for-windows/actions/runs/45252862246) — 5/5 jobs ירוקים כולל `release`):

- **`libc.so` האמיתית** (Android 14 `sdk_phone64_x86_64`, Build ID `fa337969c798946280caa45e2d71a2e7`): נטענת ומתוקנת (`0 refused`), ששת הקונסטרקטורים שלה רצים, ו־`test/real_libc_test.c` עובר 11/11 ב־Windows CI (PR #11).
- **הרצת executable אמיתי עד `main()`:** `test/hello_exe.c` ו־`test/exec_min.c` עברו ב־Windows וב־Linux ASan; מחסנית התחלתית, `envp`, `auxv` מלא לפני קונסטרקטורים ואימות `e_entry` ב־`PT_LOAD` עם `PF_X` (PR #16).
- **שכבת קבצים מלאה ו־Gate G1:** `src/fd.c` + `src/platform.c` (`openat`, `read/write/readv/writev`, `lseek`, `fstat/stat/lstat/newfstatat`, `unlinkat`, `fcntl` כולל `F_GETFL`/`F_SETFL`, `O_APPEND` אטומי בקריאת מערכת יחידה בשתי הפלטפורמות, `O_NOFOLLOW`, והפרדת symlinks מול Windows junctions); `tools/fd_test.c` עובר 84/84 ב־Linux ASan ו־90/90 ב־Windows, ו־`test/g1_gate_exe.c` מדפיס `G1 GATE PASSED` ב־Windows CI (PR #17).
- **VMA על extents:** `src/vma.c` (`mmap`/`munmap`/`mprotect`/`madvise`, `afw_vma_adopt`, שריון 64GB בפחות מ־1MB מטא־דאטה — PR #10, PR #14).
- **מדידת `%gs:` ב־ART ל־G3 כבר נמדדת ב־CI [נמדד]:** [`docs/design/G3-GS.md`](G3-GS.md) ושלב `Measure: %gs: in ART - libart.so and the boot image` ב־`bionic-probe` מדדו 1,544 אתרי `%gs:` ב־`libart.so` ו־~250K ב־boot `.oat`. פריסת ה־TEB slots ב־G2 תשמור תאימות לתא ה־TEB הנוסף (`art::Thread*`) שמתוכנן ל־G3a.

### תנאי קדם חיצוניים לפני סגירת G2 (`COLLABORATION.md` שורה 77) [נמדד]

1. **9 אתרי `UNPROVEN`** (3 ב־`linker64`, 6 ב־`libc++`): פתוחים ב־PR #5 ו־PR #7.
   - **[נמדד — בודק 1, PR #5 / PR #7]:** בשש רשומות `libc++`, `movzx` הוא רק מקור האינדקס, בעוד הרשומות בטבלה הן 4 בתים (`movsxd`) וללא `cmp`/`ja` בפונקציה — לכן הרחבת המנתח ל־`movzx` אינה מוכיחה גבול. בהתאם, **נשארים עם ההצהרות המוצמדות־hash של PR #7** (כפוף לכלל 6 וחתימת כל הבודקים; בודק 1 יחתום על חלק `libc++` אחרי קריאת `attest-scan.txt` הנוכחי).
   - **תלות מפורשת:** 6 האתרים של `libc++` הם תנאי קדם ל־**`G2-5a`** (כי `G2a` טוען את `libc++_shared.so`).
2. **אורקל `libc_shared_globals` (`tools/oracle/` + `src/bionic_abi/shared_globals.h`):** נדרש לפני שממלאים שדות נוספים ב־`libc_shared_globals` מעבר למה שכבר נמדד ב־`tools/sg_uses.py`. (שימו לב: עבור TLS דינמי ב־`G2-5b`, החלטת בודק 3 היא DTV פנימי ב־`afw_tls_get_addr`, כך ש־`G2b` אינו תלוי ב־`tls_modules` של Bionic.)

---

## 2. הגדרת שער G2 ופיצול מפורש `G2a` / `G2b` (כלל 6)

כל ארבעת מרכיבי G2 המקוריים נשמרים במלואם — אף פריט אינו מושמט:

### תנאי הפיצול המחייבים (כלל 6 — תנאי בודק 1)
1. כל פריט מסעיף זה מופיע ב־`G2a` או ב־`G2b`; אף דרישה אינה נופלת.
2. **אין טענה "G2 עבר" ואין התחלת G3 (ART) לפני ש־`G2b` ירוק.** שלב הביניים נקרא **`G2a` בלבד** — ב־CI, בדוחות וב־README.
3. טבלת המימוש (סעיף 7) מפוצלת במפורש ל־`G2-5a` ול־`G2-5b`.
4. ההסכמה המפורשת בכתב של כל הבודקים נרשמת ב־[`docs/COLLABORATION.md`](../COLLABORATION.md).

### תכולת `G2a` (ננעלת ב־`G2-5a`)
1. **ריבוי חוטים (`pthreads` + `futex`):** יצירת חוטים רגילים ו־`detached` ב־`pthread_create`, בידוד `errno` ו־`thread_local`, סנכרון מלא ב־`pthread_mutex`, `pthread_cond`, `rwlock`, גישות `fs:` תקינות מחוטים משניים, ואיסוף מלא ב־`pthread_join` / ניקוי בטוח ב־`_exit_with_stack_teardown` בלי דליפת TLS/מחסניות.
2. **זיכרון מקבילי (`MADV_DONTNEED`, ללא VEH — סעיף 4):** `madvise(MADV_DONTNEED)` (`memset(0)` תחת `g_lock` על עמודים אנונימיים נגישים ב־`MEM_COMMIT`, `os_decommit` על `PROT_NONE`, no-op על `VMA_FILEMAP`/`MAP_SHARED`) תחת עומס רב־חוטי (בדיקת C11 נקייה מ־data races על עמודי שכנות + probe אסמבלי ברמת פלטפורמה לאימות היעדר חריגות על אותו עמוד) — **אפס קריסות, אפס חריגות VEH ואפס השחתת Red Zone**, אימות איפוס מלא לאפסים לאחר סיום הפעולה, ובדיקה שלילית שכתיבה לעמוד `PROT_READ` (שאינו בעיצומו של `MADV_DONTNEED`) עדיין חוטפת access violation.
3. **מיפוי קבצים לקריאה בלבד (`src/filemap.*`):** `mmap(NULL, len, PROT_READ, MAP_SHARED | MAP_PRIVATE, fd, offset)` — תמיכה מפורשת ב־**`MAP_SHARED | PROT_READ`** (עבור `map_fd_ro()` של `/dev/__properties__` ב־Bionic) וב־**`MAP_PRIVATE | PROT_READ`**, כולל היסטים מיושרים ל־4KB, קובץ בגודל 0, דף סופי חלקי מאופס, `munmap` מלא וחלקי טרנזקציוני (שמונע גישה לאזור ששוחרר), ודחיית `PROT_EXEC` ב־`-EACCES`.
4. **חריגות C++ חוצות־ספריות ELF:** נעילת `dl_iterate_phdr`, `thread_local` destructors (`__loader_add/remove_thread_local_dtor`), וזריקה/תפיסה של `std::runtime_error` בין שתי ספריות `.so` נפרדות שנטענות דרך `afw_load_with_deps` עם `libc.so` + `libc++_shared.so` (כולל מתוך חוט משני ב־`pthread_create`), בכפוף לסגירת 6 אתרי ה־`UNPROVEN` של `libc++` (PR #7).

### תכולת `G2b` (ננעלת ב־`G2-5b`, חובה לפני הכרזת "G2 עבר" ולפני G3)
5. **טעינה דינמית (`dlopen`) של ספרייה עם `PT_TLS`:** DTV פנימי ב־`afw_tls_get_addr` (סעיף 6.2.3).
6. **חריגת C++ חוצת־גשר callback של הטוען (סעיף 6.2.4):** בדיקה מדידה אחת שבה קוד אנדרואיד ב־DSO א' קורא לפונקציית גשר של הטוען שמפעילה callback ב־DSO ב', ה־callback זורק `std::runtime_error`, והחריגה חוצה את מסגרת הגשר (בעזרת DWARF `.eh_frame` תקני הרשום ב־`dl_iterate_phdr`, **לא** `RtlInstallFunctionTableCallback`) ונתפסת ב־DSO א' בלי להגיע ל־`std::terminate`.

---

## 3. זרם עבודה 1 — חוטים (`pthreads`: `SYS_clone` מול `pthread_create`) ו־`SYS_futex` [לבודק 3 ובודק 2]

### 3.1 שלב 0 — ניסוי מדיד לפני בחירת ארכיטקטורה (כלל 7א)

**חשוב:** השימוש במחסנית של Bionic (`child_stack`) מתוך חוט `CreateThread` מסומן כ־**[השערה]** ואינו ארכיטקטורה שנבחרה עד שיתקבלו תוצאות הניסוי המדיד ב־Windows CI (`G2-1`, `test/pthread_probe.c` — שלב אינפורמטיבי).

ניסוי שלב 0 ימדוד בפועל את כל 5 הסעיפים הבאים ב־Windows CI:
1. **פרופיל syscalls של Bionic:** אילו קריאות מערכת Bionic מבצעת בתוך `pthread_create` (רגיל ו־`detached`), `pthread_join`, `pthread_mutex`, ו־`pthread_cond_broadcast`:
   - רישום מדויק של כל דגלי `clone` (`56`) ש־Bionic מעבירה (כולל בדיקה אם `CLONE_SYSVSEM` מופיע — **[השערה של בודק 1]**; ה־whitelist ייבנה אך ורק מהמדידה ולא מהזיכרון!),
   - רישום מדויק של כל opcodes של `futex` (`202`), כולל שורה מפורשת: **`REQUEUE / CMP_REQUEUE: נראה / לא נראה`** ו־**`bitset חלקי: נראה / לא נראה`**,
   - רישום `mmap`, `mprotect`, `set_tid_address` (`218`), `rt_sigprocmask` (`14`), `set_robust_list` (`273`), `prctl` (`157`), ו־`munmap`+`exit` בחוט `detached`, ופריסת `newtls` בפועל.
2. **כניסה, המשך וחזרה של הילד מ־`clone` על מחסנית Bionic (`child_stack` — דיוק בודק 1):**
   - מכיוון שאתרי ה־`syscall` משוכתבים ל־`call afw_syscall_entry`, על `child_stack` **אין** כתובת חזרה של `afw_syscall_entry`. לכן הילד אינו יכול לחזור באמצעות `ret` רגיל: ה־trampoline של הילד חייב לשחזר את האוגרים ה־callee-saved של ההורה, להציב `rax = 0` ו־`rsp = child_stack`, ולבצע **`jmp` ישיר לכתובת החזרה של ה־stub (`rbp+16` של `afw_syscall_entry`)**!
   - ניסוי שלב 0 יתעד במפורש מה `__bionic_clone`/`clone` מכינה על `child_stack` (מצביע `fn` ו־`arg` ויישור 16 בתים) ויבדוק את מסלול ההמשך הזה מקצה לקצה.
3. **בדיקת גבולות stack ו־guard page:** אימות ש־`mprotect(PROT_NONE)` על ה־guard page בתחתית מחסנית Bionic אכן תופס גלישת מחסנית ומדווח קריסה (ולא משחית זיכרון או נתפס ב־VEH שגוי).
4. **בדיקת VEH, חריגת C++, unwinding וקריאת Win32 עמוקה מתוך החוט המשני על מחסנית Bionic:** הפעלת `fs:` read fault (VEH), זריקה ותפיסה של חריגת C++ (`libunwind` / `.eh_frame`), stack walk, ו**קריאה עמוקה ל־Win32 API** (`CreateFileW` / `VirtualQuery`) מתוך מחסנית Bionic כדי לוודא ש־`ntdll`/`__chkstk` אינם נכשלים על `NT_TIB` המותאם.
5. **בדיקת חזרה מסודרת ל־Windows thread exit:** שחזור `RSP` ו־`NT_TIB` (`StackBase`, `StackLimit`, `DeallocationStack`) לפני `ExitThread()`, ואימות ש־`FLS` callbacks ו־`DLL_THREAD_DETACH` רצים בלי קריסה גם אחרי `munmap` של מחסנית Bionic.

### 3.2 השוואת שתי אפשרויות ותנאי Fallback מפורש

| היבט | אפשרות א' **[השערה]**: מימוש `SYS_clone` (`56`) מעל `CreateThread` | אפשרות ב': יירוט סמל `pthread_create` (הצעת בודק 1) |
|---|---|---|
| תאימות ל־Bionic | מלאה — Bionic בונה `pthread_internal_t`, `bionic_tls`, guard page, `pthread_key`, ו־`pthread_join` בעצמה | חלקית — דורש חיקוי או השלמה של `pthread_internal_t` (עבור `errno`, `pthread_self`, `pthread_key`, `libc++`, `ART`) |
| שחרור TLS | **אסור** לרשום `FLS` release על `newtls` שהוקצה ע"י Bionic (מונע double-free על `mmap` של Bionic) | הטוען מנהל את הבלוק |
| מחסנית וחוטים מנותקים | דורש trampoline (`jmp` ל־stub return), עדכון/שחזור `NT_TIB`, וטיפול ב־`_exit_with_stack_teardown` | החוט רץ תמיד על מחסנית Windows המקורית (ללא החלפת `NT_TIB`) |

- **שער החלטה משלב 0 (תנאי Fallback ברור):** רק אם ניסוי שלב 0 עובר בהצלחה בכל 5 הסעיפים ב־Windows CI — מממשים את **אפשרות א' (`SYS_clone`)**. אם אחד מהסעיפים (המשך הילד, VEH/SEH, unwinding, guard page, קריאת `ntdll`/`__chkstk` או `DLL_THREAD_DETACH`) נכשל או דורש הסתמכות על מבנה Windows לא מתועד — **עוברים לאפשרות ב' (יירוט `pthread_create`)** ל־G2, בכפוף לאישור בודק 3.

### 3.3 הפרדה מפורשת בין Windows TLS לבין Android TLS ומסלול `newtls` **[השערה — לאימות בניסוי שלב 0]**

> **סיווג (כלל 7):** הטבלה להלן מציגה את תכנון המיפוי המוצע בין Windows TEB לבין Android TLS. הטענה ש־`TlsSetValue(g_slot[0], newtls)` + `t_block = newtls` מספקים את כל חוזה ה־TLS של Bionic (כולל כל גישות `fs:` וכל נתיבי `__tls_get_addr`) בחוט שנוצר ע"י `clone` היא **[השערה]** ותאומת ישירות בבדיקת שלב 0 (`G2-1`) לפני מימוש.

| ישות | מיקום פיזי | מי כותב אותה | מי קורא אותה | קשר ל־`newtls` ב־`clone(CLONE_SETTLS)` **[השערה]** |
|---|---|---|---|---|
| **Windows TEB `TlsSlots[g_slot[0]]`** | `gs:[0x1480 + 8*g_slot[0]]` (`g_slot[0] < 64`, נאכף ב־`afw_tls_init` **[נמדד]**) | `TlsSetValue(g_slot[0], tp)` | קוד Android משוכתב (`fs:[0]` -> `gs:[0x1480 + 8*g_slot[0]]`) וטרמפולינות `fs:[reg]` (`mov r11, gs:[...]`) | ב־`clone(CLONE_SETTLS)` ה־trampoline כותב `TlsSetValue(g_slot[0], newtls)` כדי שכל `fs:[0]` וכל `fs:[reg]` בחוט החדש יקבלו ישירות את `newtls`. |
| **Windows TEB `TlsSlots[g_slot[5]]`** | `gs:[0x1480 + 8*g_slot[5]]` | `TlsSetValue(g_slot[5], guard)` | קוד Android משוכתב (`fs:[0x28]` -> `gs:[0x1480 + 8*g_slot[5]]`) | נבדק בשלב 0 אם `((uintptr_t *)newtls)[5]` כבר מאותחל ע"י Bionic ל־stack guard (אם כן — מעתיקים אותו ל־`g_slot[5]`; אחרת `g_guard` התהליכי). |
| **מנגנון שכתוב `fs:` הקיים** (`src/patch.c`, `src/tls_patch.c`) | שכתוב סטטי בטעינה + `fs_handler` VEH **[נמדד]** | הטוען בזמן טעינה (פעם אחת לקוד משותף לכל החוטים) | כל החוטים בתהליך | `fs:` עצמו **אינו** משתנה ב־Windows (בסיס `fs` נשאר `0`); כל קריאת `fs:[0]`/`fs:[0x28]` וכל טרמפולינת `fs:[reg]` ניגשות דרך `gs:[TEB TlsSlots]`. |
| **מצביע `t_block` ב־`src/tls_patch.c`** | `_Thread_local uintptr_t *t_block` | `afw_tls_thread_init()` (בחוט הראשי) או `clone` trampoline (`t_block = newtls`) | `afw_tls_block()` -> `afw_tls_static_resolve()` -> `__tls_get_addr()` ו־`afw_l_dl_iterate_phdr()` | ה־trampoline מעדכן `t_block = (uintptr_t *)newtls` כך שגם `__tls_get_addr` וגם `dl_iterate_phdr` יראו את אותו `tp` כמו `gs:[TEB slot 0]`. |
| **בעלות שחרור (`t_alloc` / `FLS`)** | `_Thread_local void *t_alloc` + `FlsSetValue(g_fls, ...)` | הטוען **רק** עבור בלוקים שהטוען הקצה (`afw_tls_static_alloc`) | `fls_release` ביציאת החוט | בחוט `clone(CLONE_SETTLS)`: `t_alloc = NULL` ו־**אין** רישום `newtls` ל־`fls_release` (כי Bionic הקצתה את `newtls` ב־`mmap` ומשחררת אותו בעצמה). |

**מסלול מקצה לקצה בחוט `clone(CLONE_SETTLS)` [השערה לאימות בשלב 0]:**
```
Bionic pthread_create()
  └─> clone(CLONE_SETTLS, ..., newtls)
        └─> Windows CreateThread -> child trampoline:
              1. TlsSetValue(g_slot[0], newtls)   --> gs:[0x1480 + 8*g_slot[0]] == newtls
              2. TlsSetValue(g_slot[5], guard)    --> gs:[0x1480 + 8*g_slot[5]] == guard
              3. t_block = newtls; t_alloc = NULL --> __tls_get_addr & dl_iterate_phdr רואים newtls
              4. שחזור אוגרי ההורה, rax = 0, rsp = child_stack, jmp לכתובת החזרה של stub ה-clone
              5. קוד Android מבצע:
                   • mov rax, fs:[0]   (משוכתב ל-gs:[slot 0]) --> מקבל newtls (tp)
                   • mov rax, fs:[0x28](משוכתב ל-gs:[slot 5]) --> מקבל stack guard
                   • fs:[reg]          (טרמפולינה דרך slot 0) --> ניגש ל-[newtls + reg]
                   • __tls_get_addr()  (דרך t_block)          --> ניגש ל-newtls + tpoff
```

### 3.4 מוקש `_exit_with_stack_teardown` ומחזור החיים המלא של `clear_child_tid`

#### א. `_exit_with_stack_teardown` וסדר היציאה הבטוח ב־`SYS_exit(60)` (תוקן לפי חוסם בודק 3)
בחוט מנותק (`PTHREAD_CREATE_DETACHED`), Bionic קוראת ל־`_exit_with_stack_teardown(stack_base, stack_size)`: `SYS_munmap` על המחסנית הנוכחית ומיד `SYS_exit(0)` בלי לגעת במחסנית. בחוט `joinable`, ברגע ש־`clear_child_tid` מאופס ומוער, החוט המצטרף (`pthread_join`) עלול לקרוא מיד ל־`munmap` על המחסנית ועל `newtls` של החוט היוצא.

לכן הסדר המחייב הוא:
1. כל חוט `clone` שומר ב־`afw_thread_ctx` (מוקצה על ה־heap ורשום ב־`FLS` ייעודי נפרד משחרור TLS) את מצב המחסנית המקורית של Windows (`host_rsp`, `host_stack_base`, `host_stack_limit`, `host_dealloc_stack`).
2. אם `SYS_munmap(addr, len)` מזהה שהטווח `[addr, addr + len)` **מכיל את `RSP` הנוכחי של החוט הקורא**: מאמת את הטווח ב־VMA, דוחה את השחרור לשדה `ctx->pending_stack_unmap = {addr, len}` ומחזיר `0` — כך ש־`afw_syscall_entry` חוזר בבטחה להוראת `SYS_exit(0)`.
3. **בכניסה ל־`SYS_exit(code)` (`60`) — הסדר הקריטי (מונע UAF בחוט `joinable`):**
   1. **קודם כול:** מעבר בחזרה למחסנית Windows המקורית (`RSP = host_rsp`) ושחזור `NT_TIB` (`StackBase`, `StackLimit`, `DeallocationStack`).
   2. ביצוע `afw_munmap(ctx->pending_stack_unmap.addr, ctx->pending_stack_unmap.len)` (עבור חוט `detached`).
   3. **רק עכשיו** — לאחר שהחוט אינו נוגע עוד בשום זיכרון של Bionic — קריאה ל־`afw_thread_clear_tid_once(ctx, 0)` (מרגע זה `pthread_join` רשאי לשחרר את מחסנית הילד וה־`newtls` שלו בבטחה).
   4. קריאה ל־`ExitThread((DWORD)code)` — כל `FLS` callbacks ו־`DLL_THREAD_DETACH` רצים על מחסנית Windows חוקית.

#### ב. חוזה אטומי מדויק עבור `clear_child_tid` ודגלי `SYS_clone`
- **ייצוג בזיכרון (ללא `volatile`):** ב־`afw_thread_ctx` (מוקצה per-thread, מצביע אליו שמור ב־`_Thread_local` וב־`FlsSetValue(g_thread_ctx_fls, ctx)`):
  ```c
  _Atomic(uintptr_t) clear_child_tid_addr;  /* כתובת משתמש מיושרת ל-4 בתים, או 0 (מושבת) */
  _Atomic int        clear_tid_done;        /* 0 = טרם בוצע, 1 = בוצע (חד-פעמי) */
  ```
- **אימות יישור ל־4 בתים:** הן ב־`CLONE_CHILD_CLEARTID` והן ב־`SYS_set_tid_address(tidptr)`:
  - אם `tidptr != NULL` ו־`((uintptr_t)tidptr & 3u) != 0`: הכתובת אינה חוקית ל־futex 32-bit -> לא נרשמת (`0`), ומוחזר `-EINVAL` (ב־`clone`) או מושבת (ב־`set_tid_address`).
- **החלפת הכתובת במהלך חיי החוט (`SYS_set_tid_address(tidptr)` — syscall `218`):**
  - מבצע `atomic_store_explicit(&ctx->clear_child_tid_addr, (uintptr_t)tidptr, memory_order_release)` ומחזיר `sys_gettid()`.
  - אם `tidptr == NULL` (`0`): האיפוס וה־wake ביציאה מושבתים. אם `tidptr` היא כתובת חדשה מיושרת ל־4 בתים: ביציאה יאופס ויוער אך ורק ה־`tidptr` החדש (לעולם לא הישן).
- **איפוס אטומי וסדר זיכרון ביחס ל־wake (`afw_thread_clear_tid_once(ctx, int in_fls)`):**
  1. מחסום חד־פעמי: `if (atomic_exchange_explicit(&ctx->clear_tid_done, 1, memory_order_acq_rel) != 0) return;`
  2. שליפה וניקוי של הכתובת: `uintptr_t addr = atomic_exchange_explicit(&ctx->clear_child_tid_addr, 0, memory_order_acq_rel);`
  3. אם `addr != 0`:
     - **הגנה במסלול יציאה חריגה (`in_fls == 1`, הערת בודק 3):** במסלול `SYS_exit` רגיל `clear_tid_done` כבר `1` ולכן ה־FLS callback הוא no-op; אך אם חוט יוצא חריג דרך `FLS` (`LdrShutdownThread`), מוודאים קודם דרך `afw_vma_is_writable(addr, 4)` שהכתובת עדיין ממופה לקריאה/כתיבה ב־VMA לפני הכתיבה (מונע חריגה בתוך `LdrShutdownThread` אם הזיכרון כבר שוחרר).
     - **כתיבה אטומית (לא `volatile`):** `atomic_store_explicit((_Atomic int32_t *)addr, 0, memory_order_seq_cst);` (ב־Windows `platform.c` שקול ל־`InterlockedExchange((volatile LONG *)addr, 0)`).
     - **סדר זיכרון מפורש:** הכתיבה האטומית `seq_cst` (שכוללת `release`) **קודמת בסדר זיכרון (`happens-before`)** לקריאת `WakeByAddressAll((PVOID)addr)` (ב־Linux: `futex(FUTEX_WAKE, INT_MAX)`). לכן כל חוט ב־`pthread_join` שמתעורר מה־futex מובטח לראות `*addr == 0` וכן את כל כתיבות החוט שקדמו ליציאתו.
  4. **ביצוע פעם אחת בלבד:** נקראת (א) ב־`SYS_exit(60)` (אחרי החלפה ל־`host_rsp`), ו־(ב) ב־`FLS` callback של `g_thread_ctx_fls` שגם משחרר את `ctx`.
- **סנכרון התחלה, דגלי `clone` ואימות `tid` ב־`SYS_clone` (`56`):**
  - **בניית ה־whitelist מהמדידה (דיוק בודק 1):** רשימת דגלי ה־thread המותרים תיקבע **אך ורק מתוצאות מדידת שלב 0 (`G2-1`)** מול `pthread_create` של Bionic (כולל בדיקת `CLONE_SYSVSEM` — **[השערה]**), ולא מהזיכרון. כל דגל בלתי־נתמך וכן `fork` (בלי `CLONE_VM | CLONE_THREAD`) יידחו ב־`-ENOSYS` / `-EINVAL`.
  - מאמת שה־`tid` (`GetCurrentThreadId()`) חיובי בתחום `int32_t` (`tid > 0 && tid <= INT32_MAX`, הערת בודק 3), ונכתב **זהה** ל־`parent_tidptr`, ל־`child_tidptr`, לערך ההחזרה של `SYS_clone` ול־`SYS_gettid`.
  - ההורה ממתין על אירוע התחלה עד שהילד כותב `parent_tidptr`/`child_tidptr`, רושם `clear_child_tid_addr`, ומאתחל TEB + `t_block`.

### 3.5 תכנון מפורש ל־`SYS_futex` (`202`)

**קיים ונמדד ב־[`src/syscall.c`](../../src/syscall.c) (שורות 185–256) [נמדד]:**
- `FUTEX_WAIT` (`0`), `FUTEX_WAKE` (`1`), `FUTEX_WAIT_BITSET` (`9`, `val3 == 0xffffffffu`), `FUTEX_WAKE_BITSET` (`10`, `val3 == 0xffffffffu`) מעל `WaitOnAddress` / `WakeByAddressSingle` / `WakeByAddressAll`, עם `CLOCK_MONOTONIC` ו־`CLOCK_REALTIME` (`FUTEX_CLOCK_REALTIME`) ולולאת הגנה מפני התעוררות מוקדמת של טיימר Windows.

**החלטת תכנון ל־G2 (בהסכמת בודק 3 + דיוק בודק 1):**
- **[השערה של בודק 1 — תיבדק בשלב 0]:** ייתכן ש־`pthread_cond` ב־Bionic אינה משתמשת כלל ב־`FUTEX_REQUEUE`/`FUTEX_CMP_REQUEUE` (אלא ב־`WAIT`/`WAKE` עם counter). ניסוי שלב 0 (`G2-1`) ידפיס במפורש **`REQUEUE: נראה / לא נראה`**.
  - אם **לא נראה** — אין צורך לממש `REQUEUE` ב־G2 (דוחים עד צורך מדיד).
  - אם **נראה** — מממשים **חלופה 1 (`WaitOnAddress` + `WakeByAddressAll` אחרי בדיקת `*uaddr == val3`)** עבור `FUTEX_REQUEUE` (`3`) ו־`FUTEX_CMP_REQUEUE` (`4`) (אימות יישור 4 בתים ל־`uaddr` ו־`uaddr2`; ב־`CMP_REQUEUE` בדיקת `*uaddr == val3` אחרת `-EAGAIN`), בתנאי ששלב 0 מאמת ש־Bionic אינה שולחת bitset חלקי ואינה תלויה בספירת המועברים המדויקת. אחרת — חלופה 2 (טבלת waiters פנימית נעולה ב־`SRWLOCK`).
- **דיוק שעונים:** לשמור על סירוב `FUTEX_CLOCK_REALTIME` ב־`FUTEX_WAIT` רגיל (מותר רק ב־`FUTEX_WAIT_BITSET`, כמו בליבת Linux).

---

## 4. זרם עבודה 2 — `MADV_DONTNEED` מקבילי ובטוח לחוטים (`src/vma.c`) [ללא VEH — תוקן לפי בודק 3, בודק 2 ובודק 1]

### 4.1 למה בוטל מנגנון `decommit + recommit` + VEH [בודק 3]

ב־[`src/vma.c`](../../src/vma.c) (`do_dontneed`, שורות 614–643), `os_decommit` ואחריו `os_commit` פותחים חלון שבו העמוד הוא `MEM_RESERVE` (לא נגיש). **בודק 3 חשף סיבה עקרונית שפוסלת כל מנגנון VEH על גישות דאטה אקראיות של קוד אנדרואיד:**

- **השחתת Red Zone בקרנל Windows (`KiUserExceptionDispatcher`):** ברגע שמתרחשת `EXCEPTION_ACCESS_VIOLATION` ב־Windows x64, הקרנל כותב את `CONTEXT` ו־`EXCEPTION_RECORD` (~1.4KB) ישירות **מתחת ל־`RSP`** של החוט הנפגע — **לפני שה־VEH מתחיל לרוץ**. אם החוט מריץ פונקציית עלה של System V (ב־`libc.so` או `libc++_shared.so`) שמחזיקה משתנים חיים ב־128 הבתים של ה־Red Zone, החריגה משחיתה אותם בשקט; החזרת `EXCEPTION_CONTINUE_EXECUTION` ממשיכה ריצה עם מחסנית מושחתת.
- בנוסף, `MEM_RESET` / `DiscardVirtualMemory` אינם מבטיחים איפוס לאפסים (מפרים חוזה Linux של `MADV_DONTNEED`).

### 4.2 התכנון ל־G2 — `memset(0)` תחת `g_lock` + חוזה מקביליות מדויק ומגבלות מתועדות

1. **החזקת `g_lock` (`SRWLOCK`) של `src/vma.c`:** מסנכרנת פעולות VMA מתחרות (`mmap`/`munmap`/`mprotect`/`madvise`), אך **אינה עוצרת** חוטי יישום שקוראים או כותבים ישירות לאותו זיכרון.
2. **הגבלה קשיחה למיפויים פרטיים אנונימיים בלבד (`MAP_PRIVATE | MAP_ANONYMOUS`):** על `VMA_FILEMAP` או `MAP_SHARED`, `MADV_DONTNEED` הוא no-op בטוח (`return 0`), ולעולם אינו משנה נתוני קובץ/נתונים משותפים.
3. **טיפול לפי מצב ה־extent (`w->ext[i]`):**
   - **לא ב־`MEM_COMMIT` (`!(state & P_COMMIT)`):** נשאר `MEM_RESERVE` (כבר מאופס לוגית — ללא נגיעה בדפים).
   - **עמוד `PROT_NONE` ב־`MEM_COMMIT` (`prot == 0`):** מבצע `os_decommit(start, len)` כרגיל (`state = P_MAPPED`). גישה אליו ממילא אסורה וצריכה להפיל חריגה, כך שאין חריגות שווא ואין השחתת Red Zone — והזיכרון משתחרר מיד.
   - **עמוד נגיש עם `PROT_WRITE` (`(prot & PROT_WRITE) != 0`):** מבצע **`memset((void *)start, 0, len)`** ישירות במקום — אפס חריגות VEH, אפס השחתת Red Zone, ואפס `ERROR_NOACCESS` בגישת קרנל (`ReadFile`/`WriteFile`).
   - **עמוד `PROT_READ` אנונימי ללא `PROT_WRITE` (`prot != 0 && !(prot & PROT_WRITE)`):** תחת `g_lock` משנים זמנית ל־`PAGE_READWRITE` (או `PAGE_EXECUTE_READWRITE` אם `PROT_EXEC`), מאפסים ב־`memset((void *)start, 0, len)`, ומשחזרים את ההרשאה המקורית (`PAGE_READONLY` / `PAGE_EXECUTE_READ`). אם שינוי ההרשאה הזמני נכשל -> מחזירים `-ENOMEM` בלי לשנות מטא־דאטה (כלל 8).
4. **חוזה מקביליות מדויק ומגבלות מתועדות (תוקן לפי בודק 2 ובודק 1):**
   - **מה מובטח *במהלך* `MADV_DONTNEED`:** אפס קריסות, אפס חריגות VEH, אפס השחתת Red Zone, ואפס פגיעה בעמודים שמחוץ לטווח המבוקש.
   - **מה *אינו* מובטח במהלך `MADV_DONTNEED` (מגבלה מתועדת):** בניגוד ל־Linux (שם איפוס עמוד הוא אטומי ברמת ה־PTE), `memset(0)` הוא כתיבה לא־אטומית:
     - לפי מודל הזיכרון של C11, גישה מקבילית (אטומית או רגילה) מאפליקציה לאותו אובייקט בזמן `memset(0)` היא data race; ברמת החומרה, קורא מקביל עלול לראות ערך ביניים חלקי/מעורב וכתיבה מקבילית עלולה להתערב באיפוס.
     - בחלון הזמני של `PROT_READ -> PAGE_READWRITE -> PAGE_READONLY`, כתיבה מחוט אחר לעמוד `PROT_READ` תוך כדי `MADV_DONTNEED` עלולה להצליח בשקט במקום לחטוף fault.
   - **מה מובטח *לאחר* ש־`MADV_DONTNEED` חזר (ללא כותבים מקבילים):** כל הטווח המאושר מאופס כולו (`0x00`), והרשאות ה־`PROT_READ` שוחזרו במלואן.
5. **עלות זיכרון פיזי (Working Set / RSS) והחזקת `g_lock` — בדיקת מדידה חוסמת למיזוג `G2-3` (ממצא בודק 1):**
   - **[השערה — בודק 1]:** `memset(0)` על עמודי `MEM_COMMIT` שלא נגעו בהם (demand-zero) מכריח הקצאת עמוד פיזי (מעלה Working Set / RSS במקום לשחרר זיכרון), והחזקת `g_lock` למשך `memset` גדול חוסמת כל `mmap`/`munmap`/`mprotect` בשאר החוטים.
   - **חובה לפני מיזוג `G2-3`:** להוסיף בדיקת CI אינפורמטיבית שמקצה קטע `1GB` `MEM_COMMIT` לא נגוע -> מריצה `madvise(MADV_DONTNEED)` -> מודדת Working Set וזמן נעילת `g_lock`. אם נמדד ניפוח RSS או השהיית `g_lock` משמעותית — מטפלים בכך כבר ב־`G2-3` (למשל דילוג על עמודים שלא ב־working set דרך `QueryWorkingSetEx` או פיצול למקטעים עם שחרור `g_lock` ביניהם). שחרור Commit Charge מלא נשמר ל־G3 רק אם מדידה מול ART תדרוש זאת.
6. **בדיקות חובה (`tools/vma_test.c` — כלל 4, נקיות מ־C11 data race):**
   - **בדיקת עומס רב־חוטית נקייה מ־data race ב־C11:** חוטים מקבילים מבצעים קריאות, כתיבות ופעולות אטומיות ב־C11 על **עמודים שכנים נפרדים** באותה הקצאת VMA בזמן שחוט אחר מריץ `MADV_DONTNEED` על עמודי היעד, וחוט נוסף מריץ `mmap`/`mprotect`/`munmap` אך ורק על **טווחי VMA נפרדים שאינם בשימוש אף חוט בדיקה אחר** (לעולם אינו משחרר או משנה הרשאות של עמוד שחוטי הבדיקה ניגשים אליו) — מאמתת סנכרון `g_lock`, אפס קריסות, אפס hang, ואפס פגיעה בתוכן העמודים השכנים.
   - **probe פלטפורמה ברמת אסמבלי (אופציונלי ב־Windows, מתועד כלא־C11):** כדי לבדוק עמידות פלטפורמה (היעדר `EXCEPTION_ACCESS_VIOLATION` / VEH) כאשר בינארי אנדרואיד קורא מאותו עמוד בזמן `MADV_DONTNEED`, הקריאה המקבילית מאותו עמוד תבוצע מרוטינת x86-64 assembly ייעודית (ללא אטומיים של C11 על הטווח המאופס), ותתועד במפורש כבדיקת היעדר fault ברמת הפלטפורמה ולא כהוכחה לסמנטיקת C11.
   - **אימות פוסט־תנאי (אחרי מחסום ללא כותבים):** קריאה מלאה של הטווח אחרי `MADV_DONTNEED` מאמתת שכל בית הוא `0x00` (הן על `PROT_READ|PROT_WRITE` והן על `PROT_READ` אנונימי).
   - **`PROT_NONE` decommit:** אימות ש־`MADV_DONTNEED` על `PROT_NONE` ב־`MEM_COMMIT` עדיין משחרר commit (`os_decommit`) ומאפס עמוד חדש בעת `mprotect(PROT_READ|PROT_WRITE)`.
   - **שלילית (`PROT_READ`):** כתיבה לעמוד `PROT_READ` (שאינו בעיצומו של `MADV_DONTNEED`) חוטפת access violation.
   - **שלילית (`VMA_FILEMAP`):** `MADV_DONTNEED` על מיפוי קובץ אינו מאפס את תוכן הקובץ ומחזיר `0`.
   - **מדידת `1GB` demand-zero (חוסם מיזוג `G2-3`):** מדידת Working Set וזמן `g_lock` כמפורט בסעיף 5.

---

## 5. זרם עבודה 3 — מיפוי קבצים לקריאה בלבד (`src/filemap.*`) [לבודקים 2 ו־3]

לפי [`docs/COLLABORATION.md`](../COLLABORATION.md) שורה 16 ו־77: מיפוי קריאה בלבד עבור `/dev/__properties__` וקבצי נכסים, באחריות המחבר הראשי.

### 5.1 חוזה ABI חד־משמעי ל־G2 (ללא סתירה מול Bionic)

- **נתמך ללא תנאי ב־G2:**
  - **`MAP_SHARED | PROT_READ`** (נדרש ישירות ל־`map_fd_ro()` של `/dev/__properties__` ב־Bionic **[נמדד מ־AOSP / בודק 2]**) וגם **`MAP_PRIVATE | PROT_READ`** (וגם `PROT_NONE`).
  - ב־Windows, שני הדגלים הללו לקריאה בלבד ממופים זהה דרך `CreateFileMappingW(PAGE_READONLY)` + `MapViewOfFile(FILE_MAP_READ)`.
- **נדחה במפורש עם קוד שגיאה יחיד ודטרמיניסטי (דיוק בודק 1):**
  - `PROT_WRITE` על מיפוי קובץ -> `-ENOSYS` (מחוץ לטווח read-only של G2).
  - **`PROT_EXEC` על מיפוי קובץ -> `-EACCES`** (קוד שגיאה יחיד, נבדק בבדיקה שלילית!) כדי ש־`mmap` לא יעקוף את שער ה־patching (כלל 6). **מגבלה זו היא ל־G2 בלבד:** ב־G3, קבצי `.oat`/`.vdex` של ART עם `PROT_EXEC` יעברו דרך הטוען (patch ואז commit), לא דרך `mmap(PROT_EXEC)` ישיר.
  - `fd` שאינו `FD_FILE` פתוח לקריאה (`O_WRONLY` -> `-EACCES`, תיקייה -> `-ENODEV`, `fd` לא חוקי -> `-EBADF`).
  - `offset < 0` או `offset % 4096 != 0` או גלישה ב־`offset + len` -> `-EINVAL` (כלל 8).

### 5.2 אילוצי Windows, יישור 64KB, וטיפול אמיתי וטרנזקציוני ב־`munmap` חלקי

1. **יישור `offset` ל־64KB מול 4KB (הערת בודק 3 על `delta`):**
   - `aligned_off = offset & ~0xFFFFULL`, `delta = offset - aligned_off` (כפולה של `4KB`).
   - ממפים view מ־`aligned_off` ומחזירים למזמין `addr = view_base + delta` (מיושרת ל־4KB כנדרש ב־Linux).
   - **`mapped_bytes` סופר אך ורק את הטווח הלוגי `[addr, addr + len)`** (ולא את בתי ה־`delta`), כך ש־`munmap(addr, len)` מלא אכן מגיע ל־`mapped_bytes == 0` ומשחרר את ה־view ב־`UnmapViewOfFile(view_base)`.
   - אם `delta > 0`, מחילים `VirtualProtect(view_base, delta, PAGE_NOACCESS, &old)` על הקידומת שלפני `addr` כדי שלא תהיה נגישה.
2. **קובץ בגודל 0 ודף סופי חלקי:**
   - `CreateFileMappingW` נכשל על קובץ של **0 בתים** (`ERROR_FILE_INVALID`). בקובץ בגודל 0: מקצים טווח `PROT_NONE` בגודל `roundup(len, 4096)` (כמו Linux: `mmap` מצליח וכל גישה גורמת ל־fault/`SIGBUS`, בלי לקרוס ב־`CreateFileMappingW`).
   - דף סופי חלקי: ממפים עד `min(delta + len, file_size - aligned_off)`. ב־Windows, `MapViewOfFile` מאפס אוטומטית את הזנב מה־EOF עד סוף העמוד האחרון (4KB) — **נוסיף בדיקה מפורשת שמוודאת זאת ב־Windows CI**. בקשה לעמודים שלמים *מעבר* ל־`roundup(file_size, 4096)` תיענה בדחייה מתועדת (`-ENOSYS`) או תמומש כ־`PROT_NONE`.
3. **`munmap` חלקי אמיתי וטרנזקציוני ב־`VMA_FILEMAP` (תוקן לפי ממצאי בודק 2 ובודק 3):**
   - ב־`src/vma.c` מפרידים ב־`winalloc` בין `kind = VMA_ANON` (`VirtualAlloc`/`VirtualFree`) לבין `kind = VMA_FILEMAP` (`MapViewOfFile`/`UnmapViewOfFile`, שומר את `view_base` המקורי לפני `delta`).
   - **פרוטוקול טרנזקציוני תלת־שלבי (מונע מצב שבו `VirtualProtect` הצליח אבל הקצאת מטא־דאטה נכשלה):**
     1. **שלב 1 — הקצאת מטא־דאטה מראש לפני כל קריאת OS:** קוראים ל־`split_range(w, a, b, &i0, &i1)` (שמבצע `ensure_ext_cap(w, w->next + 2)` מראש; פיצול extent לשני חצאים שווי־מצב **אינו משנה את המצב הלוגי** של אף עמוד). אם הקצאת הזיכרון נכשלת -> מחזירים `-ENOMEM` מיד **בלי לקרוא ל־`VirtualProtect`**.
     2. **שלב 2 — קריאת OS:** קוראים דרך `src/platform.c` ל־`VirtualProtect(unmap_start, unmap_len, PAGE_NOACCESS, &old)` על הטווח המשוחרר (**יאומת במדידה מפורשת ב־Windows CI ש־`VirtualProtect(PAGE_NOACCESS)` מצליח על תת־טווח של `MapViewOfFile(FILE_MAP_READ)`**). אם `VirtualProtect` נכשל -> מריצים `coalesce_around(w, i0, i1)` (ללא הקצאה, אינו יכול להיכשל) ומחזירים `-ENOMEM` — המטא־דאטה וה־OS נשארים מסונכרנים ב־100%.
     3. **שלב 3 — עדכון מטא־דאטה (בלתי־נכשל, אפס הקצאות):** מסמנים את ה־extents `[i0, i1)` כ־`state = 0`, מפחיתים מ־`mapped_bytes`, ומריצים `coalesce_around` (ללא `malloc`, אינו יכול להיכשל). כל גישה עתידית ל־4KB ששוחררו חוטפת `EXCEPTION_ACCESS_VIOLATION` מיד (כמו `SIGSEGV` ב־Linux).
     4. כאשר `mapped_bytes == 0`, קוראים ל־`UnmapViewOfFile(view_base)` (דרך `src/platform.c`) ומשחררים את הרשומה.
     - **מגבלה מתועדת של `VMA_FILEMAP`:** `MAP_FIXED` המנסה למפות מחדש *לתוך* חור שנוצר ע"י `munmap` חלקי בתוך view חי של `MapViewOfFile` מחזיר `-ENOSYS` (כי Windows אינו מפצל view פתוח); `MADV_DONTNEED` על `VMA_FILEMAP` הוא no-op (`return 0`).
   - **בדיקת כשל מטא־דאטה (`tools/filemap_test.c`):** בדיקה שלילית המזריקה כשל הקצאה או כשל `VirtualProtect` ומוודאת שמטא־דאטה והנגישות בפועל נשארות עקביות.
4. **מחיקה של קובץ ממופה (`FILE_SHARE_DELETE`) וכלל 8:**
   - [`afw_os_open`](../../src/platform.c) (שורה 190) כבר פותח קבצים עם `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` **[נמדד]**.
   - **כלל 8:** כל קריאות Win32 (`CreateFileMappingW`, `MapViewOfFile`, `UnmapViewOfFile`, `VirtualProtect`) נשארות אך ורק ב־`src/platform.c`; `src/filemap.c` הוא C11 טהור, וכל שינוי במטא־דאטה קורה רק אחרי שהקריאה ל־OS הצליחה.
   - בדיקות חובה (`tools/filemap_test.c`, Linux ASan + Windows): `MAP_SHARED|PROT_READ`, `MAP_PRIVATE|PROT_READ`, היסט 4KB שאינו כפולת 64KB (כולל `PAGE_NOACCESS` על `delta` ו־`UnmapViewOfFile` ב־`munmap` מלא), קובץ 0 בתים, דף סופי חלקי מאופס, `munmap` חלקי (האמצע גורם ל־fault והצדדים נשארים קריאים), `unlink` בזמן מיפוי, ודחיית `PROT_EXEC` (`-EACCES`), `PROT_WRITE` (`-ENOSYS`), `O_WRONLY` (`-EACCES`).

---

## 6. זרם עבודה 4 — `dlopen` דינמי וחריגות C++ (`libc++_shared.so` + `dl_iterate_phdr`) [לבודק 1, בודק 2 ובודק 3]

### 6.1 מצב קיים [נמדד]

- [`afw_l_dl_iterate_phdr`](../../src/loader_api.c) (שורות 206–224) ממומשת ומחזירה `dlpi_addr`, `dlpi_name`, `dlpi_phdr`, `dlpi_phnum`, `dlpi_adds`, `dlpi_tls_modid`, `dlpi_tls_data`.
- `C++ exceptions: every landing pad found, nothing unproven (static)` (`test/cxx_exception_test.cpp`) עובר ב־CI; `Explore: load the NDK's real libc++_shared.so` רץ אינפורמטיבית.

### 6.2 רכיבי העבודה ותנאי קבלה מלאים ל־unwinder ול־`thread_local` destructors

1. **נעילת רישום הספריות (`dlopen` / `dl_iterate_phdr` / `afw_lib_at` — `G2-5a`):**
   - מנעול ייעודי (`SRWLOCK` / `pthread_rwlock`, נפרד לחלוטין מ־VMA lock ו־VEH) שמגן על `g_libs[]` כך ש־`dl_iterate_phdr` בזמן זריקת חריגה במקביל ל־`dlopen` לעולם לא קורא רשימה משתנה.
2. **`__loader_add_thread_local_dtor` / `__loader_remove_thread_local_dtor` (`G2-5a`):**
   - רשומים ב־[`G1-LIBC-INIT.md`](G1-LIBC-INIT.md) שורה 183; נדרשים ל־`__cxa_thread_atexit` ב־`libc++_shared.so`.
   - סדר teardown קשיח ביציאת חוט: רישום ה־dtors רץ **לפני** שחרור בלוקי ה־DTV וה־TLS של החוט (ולפני `clear_child_tid` wake / `ExitThread`), ובסדר LIFO כנדרש בתקן C++.
3. **טעינה דינמית (`dlopen`) של ספרייה עם `PT_TLS` — DTV פנימי ב־`afw_tls_get_addr` (`G2-5b`, החלטת בודק 3):**
   - טבלת DTV per-thread שמורה בתוך `afw_thread_ctx`, הקצאה עצלה בגישה ראשונה (העתקת `.tdata` ואיפוס `.tbss`), שחרור ב־FLS **אחרי** ריצת `thread_local` destructors, ודיווח `dlpi_tls_data` מתוך אותה טבלת DTV ב־`afw_l_dl_iterate_phdr` — מנתק את `G2b` מתלות ב־`libc_shared_globals->tls_modules`.
4. **חריגות C++ חוצות־ספריות (`G2-5a`) וחוצות־גשר callback (`G2-5b`):**
   - **תנאי קבלה מחייבים ל־unwinder ב־`G2-5a` (ממצא 6 של בודק 2 + דיוק בודק 1):**
     1. ה־unwinder (`libunwind` ב־`libc++_shared.so`) מאתר דרך `dl_iterate_phdr` את ה־ELF ו־program headers (`PT_GNU_EH_FRAME`) של **שתי** ספריות `.so` נפרדות (הזורקת והתופסת), **שנטענו דרך `afw_load_with_deps`** (לא נבנו סטטית יחד).
     2. מידע ה־unwind (`.eh_frame`) של הספרייה הזורקת נגיש בפועל בזמן ה־stack walk.
     3. `throw std::runtime_error("payload")` ב־DSO א' נתפס ע"י `catch (const std::runtime_error &e)` ב־DSO ב' עם תוכן הודעה מדויק (לא רק `catch (...)`).
     4. אותה חריגה חוצת־DSO עובדת גם מתוך חוט משני שנוצר ב־`pthread_create`.
     5. destructors של משתני `thread_local` נקראים **פעם אחת בדיוק** בסיום החוט, לפני שחרור ה־DTV/TLS והספרייה שאליהם הם מתייחסים (מאומת במונה + ASan/Windows).
   - **בדיקה מדידה ייעודית לחריגה חוצת־גשר callback ב־`G2-5b` (דיוק בודק 3 + בודק 1):**
     - `libunwind` שב־`libc++_shared.so` קוראת DWARF `.eh_frame` דרך `dl_iterate_phdr`, **ולא** `RtlInstallFunctionTableCallback` (שמיועדת ל־SEH של Windows בלבד).
     - בדיקה מדידה אחת: קוד ב־DSO א' קורא לפונקציית גשר של הטוען (trampoline המצייד את מסגרתו ב־DWARF `.eh_frame` תקני הרשום ב־`dl_iterate_phdr`), הגשר מפעיל callback ב־DSO ב', ה־callback זורק `std::runtime_error`, והחריגה עוברת דרך מסגרת הגשר ונתפסת ב־DSO א' (בלי `std::terminate`).
5. **6 אתרי ה־`UNPROVEN` ב־`libc++_shared.so` (תנאי קדם ל־`G2-5a`):**
   - נסגרים דרך ההצהרות המוצמדות־hash של **PR #7** (כפוף לכלל 6 — חתימת כל הבודקים; אם אי־פעם יורחב המנתח — רק תוך הוכחת גבול אמיתית, לעולם לא עקיפת שער).

---

## 7. סדר PR מוצע ל־G2 (`G2a` ו־`G2b`)

| שלב | PR / ענף | תוכן | שער | בודקים עיקריים |
|---|---|---|---|---|
| **G2-0** | PR #18 (`design/g2-plan`) | אישור מסמך התכנון לפני כתיבת קוד (**`G2-1` כבר אושר ע"י בודקים 3 ו־1**) | — | בודק 3, בודק 2, בודק 1 |
| **G2-1** | `exp/g2-pthread-probe` | ניסוי מדיד בלבד: syscalls ודגלי `clone` של `pthread_create`/`detached`/`cond_broadcast`, `REQUEUE: נראה/לא נראה`, חזרת הילד (`jmp` ל־stub return + מה `__bionic_clone` מכינה על `child_stack`), guard page, VEH + C++ unwind + קריאת Win32 עמוקה (`CreateFileW`/`VirtualQuery`) בחוט משני, ושחזור Windows stack לפני `ExitThread` | מדידה | בודק 3, בודק 2, בודק 1 |
| **G2-2** | `g2-filemap` | `src/filemap.*` + `src/platform.c` + `VMA_FILEMAP` ב־`src/vma.c` (`MAP_SHARED|PROT_READ` + `MAP_PRIVATE|PROT_READ`, `PROT_EXEC` -> `-EACCES`, 64KB/4KB + `delta` `PAGE_NOACCESS`, קובץ 0 בתים, `munmap` חלקי טרנזקציוני עם הקצאה מראש + `PAGE_NOACCESS`, `unlink` בזמן מיפוי) + בדיקות Linux ASan & Windows | `G2a` | בודק 2, בודק 3 |
| **G2-3** | `g2-vma-dontneed-mt` | `MADV_DONTNEED` מקבילי **ללא VEH** (`memset(0)` תחת `g_lock` על עמודים אנונימיים נגישים ב־`MEM_COMMIT`, `os_decommit` על `PROT_NONE`, no-op על `VMA_FILEMAP`/`MAP_SHARED`) + בדיקות עומס/פוסט־תנאי/שליליות + **בדיקת מדידת `1GB` Working Set וזמן `g_lock` (חוסם מיזוג `G2-3`)** | `G2a` | בודק 3, בודק 2, בודק 1 |
| **G2-4** | `g2-pthreads` | `SYS_clone` (whitelist מתוצאות `G2-1`, או Fallback ליירוט `pthread_create` לפי `G2-1`) + סדר `SYS_exit` בטוח (שחזור `host_rsp`/`NT_TIB` ו־`pending_stack_unmap` לפני `clear_child_tid`) + חוזה C11 אטומי ל־`clear_child_tid` + `SYS_futex` (לפי ממצא `REQUEUE` ב־`G2-1`) + בדיקת `pthreads` מול `libc.so` | `G2a` | בודק 3, בודק 2 |
| **G2-5a** | `g2a-cxx-gate` | נעילת `dl_iterate_phdr`, `thread_local` dtors, חריגות C++ חוצות־DSO (נטענות דרך `afw_load_with_deps`) + סגירת 6 אתרי `libc++` (PR #7) -> **סוגר Gate `G2a` בלבד** (לא "G2" ולא פותח G3!) | **`G2a`** | בודק 1, בודק 2, בודק 3 |
| **G2-5b** | `g2b-dlopen-callback-gate` | DTV פנימי ב־`afw_tls_get_addr` ל־`dlopen`+`PT_TLS`, ובדיקת חריגת C++ חוצת־גשר callback (`.eh_frame` ב־`dl_iterate_phdr`) -> **סוגר Gate `G2b` ואת G2 במלואו** | **`G2b` (G2 מלא)** | בודק 1, בודק 2, בודק 3 |

---

## 8. סטטוס אישורים (לסגירת `G2-0`)

| משתתף | אישור `G2-1` (ניסוי) | אישור `G2-PLAN.md` (`G2-0`) | הסכמה בכתב לפיצול `G2a`/`G2b` (כלל 6) |
|---|---|---|---|
| **המחבר הראשי** | מאשר | מאשר | מסכים בכתב |
| **בודק 3** | מאושר (Issue #19) | שני חוסמיו טופלו בגרסה 5–7 | מסכים בכתב (Issue #19) |
| **בודק 1** | מאושר (`#issuecomment-7115807512`) | מאושר מותנה בתיקוני ניסוח 1–4 (בוצעו בגרסה 6–7) | מסכים בכתב בתנאים 1–4 (`#issuecomment-7115807512`) |
| **בודק 2** | מאושר (ניסוי מדידה בלבד) | הסתייגות האטומיים מול `memset` תוקנה בסעיף 4.2(4)+(6) בגרסה 7 — מוכן לאישור סופי | **מסכים בכתב** בתנאים 1–4 |
