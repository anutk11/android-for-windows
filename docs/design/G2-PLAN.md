# תכנון Gate G2: ריבוי חוטים (`pthreads` + `futex`), `MADV_DONTNEED` מקבילי, `filemap`, `dlopen`/TLS דינמי וחריגות C++

מצב: **טיוטה מעודכנת (גרסה 4) — שולבו גם שלושת התיקונים מסבב ביקורת 2 של בודק 2 מול `dd3e4e8`** (לפי [`docs/COLLABORATION.md`](../COLLABORATION.md), שורות 15, 77).
מיועד לביקורת של **בודק 3** (זיכרון, TLS, חוטים, VEH), **בודק 2** (Linux ABI, `filemap`, `futex`, אורקל `libc_shared_globals`), ו**בודק 1** (שערי טעינה, 9 אתרי `UNPROVEN`, חריגות C++ / `libc++_shared.so`).

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

שני פריטים אלה אינם חוסמים את ביקורת התכנון, אך נדרשים לפני סגירת שער G2:
1. **9 אתרי `UNPROVEN`** (3 ב־`linker64`, 6 ב־`libc++`): פתוחים ב־PR #5 ו־PR #7. כפופים לכלל 6 — כל שינוי בשער דורש הסכמה מפורשת בכתב של כל הבודקים. עבור 6 האתרים ב־`libc++_shared.so`, אם יתאמת שמקורם בטבלאות `switch` של 1–2 בתים (`movzx`), **נעדיף להרחיב את המנתח לתמוך ב־`movzx`** במקום allowlist נעול־hash.
2. **אורקל `libc_shared_globals` (`tools/oracle/` + `src/bionic_abi/shared_globals.h`):** נדרש לפני שממלאים שדות נוספים ב־`libc_shared_globals` מעבר למה שכבר נמדד ב־`tools/sg_uses.py` (ובפרט `static_tls_layout` ו־`tls_modules` עבור `pthread_create` ו־DTV דינמי).

---

## 2. הגדרת שער G2 (יעד מדיד ושמירה על כלל 6)

שער G2 כולל את **כל** דרישות G2 המקוריות — ללא השמטה שקטה (כלל 6):

1. **ריבוי חוטים (`pthreads` + `futex`):** יצירת חוטים רגילים ו־`detached` ב־`pthread_create`, בידוד `errno` ו־`thread_local`, סנכרון מלא ב־`pthread_mutex`, `pthread_cond` (כולל `broadcast` / `FUTEX_CMP_REQUEUE`), `rwlock`, גישות `fs:` תקינות מחוטים משניים, ואיסוף מלא ב־`pthread_join` / ניקוי בטוח ב־`_exit_with_stack_teardown` בלי דליפת TLS/מחסניות.
2. **זיכרון מקבילי (`MADV_DONTNEED`):** עומס רב־חוטי של `madvise(MADV_DONTNEED)` מול קריאות/כתיבות/אטומיים על `MAP_PRIVATE | MAP_ANONYMOUS` — אפס קריסות, אפס deadlocks ב־VEH, איפוס מיידי לאפסים; ובדיקה שלילית שכתיבה ל־`PROT_READ` או כשל `MEM_COMMIT` ממשיכים לקריסה מדווחת ולא נתקעים בלולאת retry.
3. **מיפוי קבצים לקריאה בלבד (`src/filemap.*`):** `mmap(NULL, len, PROT_READ, MAP_SHARED | MAP_PRIVATE, fd, offset)` — תמיכה מפורשת ב־**`MAP_SHARED | PROT_READ`** (עבור `map_fd_ro()` של `/dev/__properties__` ב־Bionic) וב־**`MAP_PRIVATE | PROT_READ`**, כולל היסטים מיושרים ל־4KB, קובץ בגודל 0, דף סופי חלקי מאופס, `munmap` מלא וחלקי (שמונע גישה לאזור ששוחרר), ודחיית `PROT_EXEC`.
4. **טעינה דינמית (`dlopen` + TLS דינמי) וחריגות C++:**
   - `dlopen` של ספריית `.so` חדשה בזמן ריצה, כולל ספרייה עם `PT_TLS` (DTV / TLS דינמי).
   - חריגת C++ (`throw`/`catch`) חוצת־ספריות עם `libc++_shared.so` ו־`dl_iterate_phdr` תחת ריבוי חוטים, כולל בדיקות unwinder ו־`thread_local` destructors (סעיף 6.2).
   - חריגת C++ שחוצה מסגרת callback של Windows (`RtlInstallFunctionTableCallback` / תאימות unwind מול `.eh_frame`).

> **הערה לכלל 6 (פיצול אופציונלי ל־`G2a`/`G2b`):** אם הבודקים יעדיפו לנעול מוקדם את אבני הבניין היציבות (`G2a`: `pthreads` + `futex` + `MADV_DONTNEED` + `filemap` + `throw`/`catch` בין ספריות ELF) ולהפריד את `dlopen` עם `PT_TLS` דינמי + חריגה חוצת־callback של Windows לשלב `G2b`, **פיצול כזה ייעשה רק באישור מפורש בכתב של כל הבודקים** (כלל 6). בהיעדר הסכמה כזו, כל 4 הסעיפים נשארים חלק משער G2 המאוחד.

---

## 3. זרם עבודה 1 — חוטים (`pthreads`: `SYS_clone` מול `pthread_create`) ו־`SYS_futex` [לבודק 3 ובודק 2]

### 3.1 שלב 0 — ניסוי מדיד לפני בחירת ארכיטקטורה (כלל 7א)

**חשוב:** השימוש במחסנית של Bionic (`child_stack`) מתוך חוט `CreateThread` מסומן כרגע כ־**[השערה]** ואינו נחשב ארכיטקטורה שנבחרה עד שיתקבלו תוצאות הניסוי המדיד ב־Windows CI (`G2-1`, `test/pthread_probe.c` — שלב אינפורמטיבי).

ניסוי שלב 0 ימדוד בפועל את כל 5 הסעיפים הבאים ב־Windows CI:
1. **פרופיל syscalls של Bionic:** אילו קריאות מערכת Bionic מבצעת בתוך `pthread_create` (רגיל ו־`detached`), `pthread_join`, `pthread_mutex`, ו־`pthread_cond_broadcast` (`mmap`, `mprotect`, `clone` (`56`), `futex` (`202` — אילו opcodes בדיוק), `set_tid_address` (`218`), `rt_sigprocmask` (`14`), `set_robust_list` (`273`), `prctl` (`157`), ו־`munmap`+`exit` בחוט `detached`), ומהם דגלי `clone` ופריסת `newtls` בפועל.
2. **כניסה ויציאה מ־trampoline אסמבלי על מחסנית Bionic (`child_stack`):** מעבר בטוח ממחסנית `CreateThread` למחסנית שהוקצתה ב־`mmap` עם יישור ABI של 16 בתים, וחזרה מבוקרת למחסנית Windows המקורית.
3. **בדיקת גבולות stack ו־guard page:** אימות ש־`mprotect(PROT_NONE)` על ה־guard page בתחתית מחסנית Bionic אכן תופס גלישת מחסנית ומדווח קריסה (ולא משחית זיכרון או נתפס ב־VEH שגוי).
4. **בדיקת VEH, חריגת C++ ו־unwinding מתוך החוט המשני על מחסנית Bionic:** הפעלת `fs:` read fault (VEH), זריקה ותפיסה של חריגת C++ (`libunwind` / `.eh_frame`), ו־stack walk מתוך החוט המשני.
5. **בדיקת חזרה מסודרת ל־Windows thread exit:** שחזור `RSP` ו־`NT_TIB` (`StackBase`, `StackLimit`, `DeallocationStack`) לפני `ExitThread()`, ואימות ש־`FLS` callbacks ו־`DLL_THREAD_DETACH` רצים בלי קריסה גם אחרי `munmap` של מחסנית Bionic.

### 3.2 השוואת שתי אפשרויות ותנאי Fallback מפורש

| היבט | אפשרות א' **[השערה]**: מימוש `SYS_clone` (`56`) מעל `CreateThread` | אפשרות ב': יירוט סמל `pthread_create` (הצעת בודק 1) |
|---|---|---|
| תאימות ל־Bionic | מלאה — Bionic בונה `pthread_internal_t`, `bionic_tls`, guard page, `pthread_key`, ו־`pthread_join` בעצמה | חלקית — דורש חיקוי או השלמה של `pthread_internal_t` (עבור `errno`, `pthread_self`, `pthread_key`, `libc++`, `ART`) |
| שחרור TLS | **אסור** לרשום `FLS` release על `newtls` שהוקצה ע"י Bionic (מונע double-free על `mmap` של Bionic) | הטוען מנהל את הבלוק |
| מחסנית וחוטים מנותקים | דורש trampoline, עדכון/שחזור `NT_TIB`, וטיפול ב־`_exit_with_stack_teardown` | החוט רץ תמיד על מחסנית Windows המקורית (ללא החלפת `NT_TIB`) |

- **שער החלטה משלב 0 (תנאי Fallback ברור):** רק אם ניסוי שלב 0 עובר בהצלחה בכל 5 הסעיפים ב־Windows CI — מממשים את **אפשרות א' (`SYS_clone`)**. אם אחד מהסעיפים (VEH/SEH, unwinding, guard page או `DLL_THREAD_DETACH`) נכשל או דורש הסתמכות על מבנה Windows לא מתועד — **עוברים לאפשרות ב' (יירוט `pthread_create`)** ל־G2, בכפוף לאישור בודק 3.

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
              4. קוד Android מבצע:
                   • mov rax, fs:[0]   (משוכתב ל-gs:[slot 0]) --> מקבל newtls (tp)
                   • mov rax, fs:[0x28](משוכתב ל-gs:[slot 5]) --> מקבל stack guard
                   • fs:[reg]          (טרמפולינה דרך slot 0) --> ניגש ל-[newtls + reg]
                   • __tls_get_addr()  (דרך t_block)          --> ניגש ל-newtls + tpoff
```

### 3.4 מוקש `_exit_with_stack_teardown` ומחזור החיים המלא של `clear_child_tid`

#### א. `_exit_with_stack_teardown` (חוטים מנותקים `PTHREAD_CREATE_DETACHED`)
בחוט מנותק, Bionic קוראת ל־`_exit_with_stack_teardown(stack_base, stack_size)`: `SYS_munmap` על המחסנית הנוכחית ומיד `SYS_exit(0)` בלי לגעת במחסנית.
1. כל חוט `clone` שומר במבנה per-thread (`afw_thread_ctx`, מוקצה על ה־heap ורשום ב־`FLS` ייעודי נפרד משחרור TLS!) את מצב המחסנית המקורית של Windows (`host_rsp`, `host_stack_base`, `host_stack_limit`, `host_dealloc_stack`).
2. אם `SYS_munmap(addr, len)` מזהה שהטווח `[addr, addr + len)` **מכיל את `RSP` הנוכחי של החוט הקורא**: מאמת את הטווח ב־VMA, דוחה את השחרור לשדה `ctx->pending_stack_unmap = {addr, len}` ומחזיר `0` — כך ש־`afw_syscall_entry` חוזר בבטחה להוראת `SYS_exit(0)`.
3. בכניסה ל־`SYS_exit(code)` (`60`):
   - מפעיל `afw_thread_clear_tid_once(ctx)` (איפוס אטומי + `WakeByAddressAll`),
   - **עובר בחזרה למחסנית Windows המקורית** (`RSP = host_rsp`) **ומשחזר את `NT_TIB` המקורי**,
   - מבצע `afw_munmap(ctx->pending_stack_unmap.addr, ctx->pending_stack_unmap.len)` אם קיים,
   - קורא `ExitThread((DWORD)code)` — כך ש־`FLS` callbacks ו־`DLL_THREAD_DETACH` רצים על מחסנית Windows חוקית.

#### ב. חוזה אטומי מדויק עבור `clear_child_tid` (כולל `SYS_set_tid_address` ויציאה חריגה)
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
- **איפוס אטומי וסדר זיכרון ביחס ל־wake (`afw_thread_clear_tid_once(ctx)`):**
  1. מחסום חד־פעמי: `if (atomic_exchange_explicit(&ctx->clear_tid_done, 1, memory_order_acq_rel) != 0) return;`
  2. שליפה וניקוי של הכתובת: `uintptr_t addr = atomic_exchange_explicit(&ctx->clear_child_tid_addr, 0, memory_order_acq_rel);`
  3. אם `addr != 0`:
     - **כתיבה אטומית (לא `volatile`!):** `atomic_store_explicit((_Atomic int32_t *)addr, 0, memory_order_seq_cst);` (ב־Windows `platform.c` שקול ל־`InterlockedExchange((volatile LONG *)addr, 0)`).
     - **סדר זיכרון מפורש:** הכתיבה האטומית `seq_cst` (שכוללת `release`) **קודמת בסדר זיכרון (`happens-before`)** לקריאת `WakeByAddressAll((PVOID)addr)` (ב־Linux: `futex(FUTEX_WAKE, INT_MAX)`). לכן כל חוט ב־`pthread_join` שמתעורר מה־futex מובטח לראות `*addr == 0` וכן את כל כתיבות החוט שקדמו ליציאתו.
  4. **ביצוע פעם אחת בלבד גם במסלול יציאה חריג:** הפונקציה נקראת (א) במסלול הרגיל ב־`SYS_exit(60)`, ו־(ב) ב־`FLS` callback של `g_thread_ctx_fls` כרשת ביטחון לכל יציאה חריגה (למשל `ExitThread` ישיר), שגם משחרר את `ctx`. בזכות `atomic_exchange(&ctx->clear_tid_done, 1)`, האיפוס וה־wake רצים **פעם אחת בדיוק**.
- **סנכרון התחלה ב־`SYS_clone` (`56`):** מאשר רק דגלי thread נתמכים (`CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FILES | CLONE_FS` + `CLONE_SETTLS`/`CLONE_PARENT_SETTID`/`CLONE_CHILD_SETTID`/`CLONE_CHILD_CLEARTID`; `fork` נדחה ב־`-ENOSYS`). ההורה ממתין על אירוע התחלה עד שהילד קורא `GetCurrentThreadId()`, כותב `parent_tidptr`/`child_tidptr`, רושם `clear_child_tid_addr`, ומאתחל TEB + `t_block`.

### 3.5 תכנון מפורש ל־`SYS_futex` (`202`)

**קיים ונמדד ב־[`src/syscall.c`](../../src/syscall.c) (שורות 185–256) [נמדד]:**
- `FUTEX_WAIT` (`0`), `FUTEX_WAKE` (`1`), `FUTEX_WAIT_BITSET` (`9`, `val3 == 0xffffffffu`), `FUTEX_WAKE_BITSET` (`10`, `val3 == 0xffffffffu`) מעל `WaitOnAddress` / `WakeByAddressSingle` / `WakeByAddressAll`, עם `CLOCK_MONOTONIC` ו־`CLOCK_REALTIME` (`FUTEX_CLOCK_REALTIME`) ולולאת הגנה מפני התעוררות מוקדמת של טיימר Windows.

**נדרש להוסיף ב־G2 עבור `pthreads` (`pthread_mutex`, `pthread_cond`, `pthread_rwlock`, `pthread_once`, `pthread_join`):**
- **`FUTEX_REQUEUE` (`3`) ו־`FUTEX_CMP_REQUEUE` (`4`)** (ל־`pthread_cond_broadcast` ב־Bionic — יאומת בשלב 0):
  - אימות יישור 4 בתים ל־`uaddr` ו־`uaddr2`; ב־`CMP_REQUEUE` בדיקת `*uaddr == val3` (אחרת `-EAGAIN`).
  - **שתי חלופות להכרעת בודקים 2 ו־3:**
    - **חלופה 1 (מעל `WaitOnAddress`):** אחרי בדיקת `*uaddr == val3`, מעיר `WakeByAddressAll(uaddr)` (כך שה־waiters מתעוררים ומתחרים מחדש על `uaddr2` בתוך Bionic). מהיר ופשוט ל־`WAIT`/`WAKE`, אך אינו תומך ב־bitset חלקי ויוצר thundering herd ב־`broadcast`.
    - **חלופה 2 (טבלת waiters פנימית נעולה ב־`SRWLOCK`):** העברת צמתי waiter אמיתית מדלי `uaddr` לדלי `uaddr2`, תמיכה ב־bitset חלקי וספירת woken מדויקת.
- **דיוק שעונים:** לשמור על סירוב `FUTEX_CLOCK_REALTIME` ב־`FUTEX_WAIT` רגיל (מותר רק ב־`FUTEX_WAIT_BITSET`, כמו בליבת Linux).

---

## 4. זרם עבודה 2 — `MADV_DONTNEED` מקבילי ובטוח לחוטים (`src/vma.c`) [לבודק 3 ובודק 2]

### 4.1 הבעיה הקיימת [נמדד]

ב־[`src/vma.c`](../../src/vma.c) (`do_dontneed`, שורות 614–643), `os_decommit` ואחריו `os_commit` פותחים חלון קצר שבו העמוד הוא `MEM_RESERVE`. בחוט יחיד (G1) זה תקין; בריבוי חוטים (G2, ובפרט Scudo), חוט אחר שניגש לעמוד בחלון חוטף `EXCEPTION_ACCESS_VIOLATION`.

`MEM_RESET` / `DiscardVirtualMemory` אינם מבטיחים איפוס לאפסים (מפרים חוזה Linux של `MADV_DONTNEED`), ו־`memset(0)` אינו עובד על `PROT_READ` ואינו משחרר commit.

### 4.2 פרוטוקול C11 אטומי חסר־מרוצים (Double-Buffered Active Window) + המתנת קרנל בטוחה תחת Preemption

**כללי ברזל (מסקנות PR #11 וביקורת בודק 2 על `42c9b2e` ו־`dd3e4e8`):**
1. **ללא `volatile` וללא C11 data races:** כל משתנה משותף בין הכותב לקורא ה־VEH הוא `_Atomic` (`<stdatomic.h>`) ונקרא/נכתב אך ורק דרך פעולות אטומיות מפורשות (`atomic_load_explicit` / `atomic_store_explicit`).
2. **ללא נעילות user-mode בתוך ה־VEH:** ה־VEH לעולם אינו נועל את `g_lock` (`SRWLOCK`), אינו קורא ל־`malloc`, אינו נוגע ב־Loader Lock, ואינו משתמש ב־`SwitchToThread()` או במגבלת `retry` קצרה שעלולה לקרוס שגוית תחת preemption של הכותב.

#### מבנה הנתונים האטומי (2 תאים + Event קרנל מוקצה מראש)
```c
#include <stdatomic.h>

typedef struct {
    _Atomic uint64_t start;
    _Atomic uint64_t end;
} afw_dn_range;

/* שני תאים מתחלפים: הכותב לעולם אינו כותב לתא שאליו g_dn_state מצביע כרגע. */
static afw_dn_range     g_dn_slot[2];
/* פריסת g_dn_state:
 *   bit 0:     active (1 = בתוך decommit->commit, 0 = לא פעיל)
 *   bit 1:     slot index (0 או 1)
 *   bits 2..63: מונה דור (generation) מונוטוני עולה */
static _Atomic uint64_t g_dn_state;
/* Windows: manual-reset Event שמוקצה פעם אחת באתחול ה-VMA (CreateEventW(NULL, TRUE, TRUE, NULL)):
 *          המתנה עליו ב-WaitForSingleObject היא קריאת קרנל ישירה (NtWaitForSingleObject)
 *          בלי אף נעילת user-mode, בלי הקצאות heap, ובלי Loader Lock. */
```

#### פרוטוקול הכותב (`do_dontneed`, תחת `g_lock` לכל אורך החלון)
1. **החזקת `g_lock` (`SRWLOCK`) לכל אורך `decommit -> recommit`:** מונעת מחוט אחר לבצע `mprotect(PROT_NONE)` או `munmap` באמצע החלון (אין בלבול בין דף שפורק זמנית ל־`PROT_NONE` לוגי).
2. **הגבלה קשיחה למיפויים פרטיים אנונימיים בלבד (`MAP_PRIVATE | MAP_ANONYMOUS`):** `do_dontneed` לעולם אינו מבצע `decommit+recommit` על `VMA_FILEMAP` או `MAP_SHARED` (מחזיר `0` ללא שינוי נתונים).
3. **מדוע הכותב לעולם אינו יכול להיחסם מול נעילה שמחזיק החוט הנפגע (הוכחת אי־deadlock):** כל עוד `active == 1`, הכותב מבצע **אך ורק** `VirtualFree(MEM_DECOMMIT)` ו־`VirtualAlloc(MEM_COMMIT)` — הוא לעולם אינו רוכש נעילת אפליקציה, Loader Lock, heap lock, או futex. לכן הסיבה היחידה שחלון `active == 1` מתארך היא השהיה זמנית (preemption) של הכותב ע"י מתזמן מערכת ההפעלה.
4. **פרסום הטווח (כותב יחיד תחת `g_lock`):**
   - `uint64_t cur = atomic_load_explicit(&g_dn_state, memory_order_relaxed);`
   - `uint64_t next_gen = (cur >> 2) + 1;`
   - `unsigned next_slot = (unsigned)(next_gen & 1u);` *(התא הלא־פעיל! אף קורא בדור `cur >> 2` לא קורא ממנו.)*
   - `atomic_store_explicit(&g_dn_slot[next_slot].start, ext.start, memory_order_relaxed);`
   - `atomic_store_explicit(&g_dn_slot[next_slot].end,   ext.end,   memory_order_relaxed);`
   - `ResetEvent(g_dn_event);` *(מכבה את האירוע **לפני** פרסום `active = 1` — מבטל missed-wakeup!)*
   - `uint64_t active_st = (next_gen << 2) | ((uint64_t)next_slot << 1) | 1u;`
   - `atomic_store_explicit(&g_dn_state, active_st, memory_order_release);` *(מפרסם `start`/`end` + `active=1` אטומית.)*
5. מבצע `os_decommit(ext.start, len)` ואז `os_commit(ext.start, len, prot)`.
6. **סגירת החלון בכל מסלול יציאה (כולל כשל `MEM_COMMIT` / OOM!):**
   - `uint64_t idle_st = (next_gen << 2) | ((uint64_t)next_slot << 1) | 0u;`
   - `atomic_store_explicit(&g_dn_state, idle_st, memory_order_release);`
   - `SetEvent(g_dn_event);` *(מעיר בקרנל כל חוט VEH שממתין — תמיד **אחרי** `active=0`!)*
   - מתבצע **לפני** החזרת `-ENOMEM` ולפני שחרור `g_lock`.

#### הוכחת אי־ערבוב ופרוטוקול הקורא (`vma_dontneed_veh`, חסר נעילות user-mode, עמיד ל־Preemption)
1. מסנן מיד: `ExceptionCode == EXCEPTION_ACCESS_VIOLATION`, `NumberParameters >= 2`, `fault_addr >= 0x10000`.
2. קורא snapshot אטומי:
   - `uint64_t st1 = atomic_load_explicit(&g_dn_state, memory_order_acquire);`
   - אם `st1 == 0`: לא רץ `dontneed` מעולם -> `EXCEPTION_CONTINUE_SEARCH`.
   - `unsigned slot = (unsigned)((st1 >> 1) & 1u);`
   - `uint64_t lo = atomic_load_explicit(&g_dn_slot[slot].start, memory_order_relaxed);`
   - `uint64_t hi = atomic_load_explicit(&g_dn_slot[slot].end,   memory_order_relaxed);`
   - `uint64_t st2 = atomic_load_explicit(&g_dn_state, memory_order_acquire);`
   - **למה `(lo, hi)` לעולם אינו מעורבב משתי פעולות שונות:** הכותב לעולם אינו נוגע ב־`g_dn_slot[slot]` כל עוד `g_dn_state` נמצא בדור `st1 >> 2`; הוא כותב לתא `slot ^ 1` רק בדור `(st1 >> 2) + 1`, ויחזור לכתוב ל־`slot` רק בדור `(st1 >> 2) + 2`. לכן כל עוד `(st2 >> 2) <= (st1 >> 2) + 1`, הזוג `(lo, hi)` שייך **במלואו** לדור `st1 >> 2`; ואם `(st2 >> 2) >= (st1 >> 2) + 2`, הפעולה של `st1` כבר הסתיימה מזמן.
3. **המתנה עמידה ל־Preemption (ללא קריסה שגויה וללא לולאה אינסופית):**
   - **מקרה א' (`(st1 & 1) == 1` — `dontneed` פעיל כרגע) ו־`fault_addr` ב־`[lo, hi)` (או `st2 != st1`):**
     - **מסלול מהיר (ללא syscall):** עד `256` מחזורי `_mm_pause()` בבדיקה `atomic_load_acquire(&g_dn_state) != st1` (מכסה מיקרו־שניות כשהכותב רץ על ליבה אחרת).
     - **מסלול Preemption (המתנה אמיתית בקרנל):** אם `atomic_load_acquire(&g_dn_state) == st1` עדיין מתקיים (הכותב הושעה ע"י המתזמן!), קוראים ל־`WaitForSingleObject(g_dn_event, 5000)` *(קריאת קרנל ישירה, מפנה את ה־CPU מיד לחוט הכותב, אפס נעילות user-mode; **[השערה — תאומת בניסוי ייעודי ב־Windows CI ב־G2-3]**)*.
     - **אין missed-wakeup:** כי הכותב קורא `ResetEvent` לפני פרסום `active_st`, וקורא `SetEvent` אחרי פרסום `idle_st`. גם אם כותב חדש הספיק להריץ `ResetEvent` לדור `g+1`, ההמתנה מתעוררת מיד בסיום `g+1` ורואה `g_dn_state != st1`.
     - **מה קורה אם הכותב נתקע או מת קטסטרופלית?** אם חלפו `5000 ms` (`WAIT_TIMEOUT`) ו־`atomic_load_acquire(&g_dn_state) == st1` עדיין פעיל — ה־VEH רושם אבחון שגיאה ומחזיר `EXCEPTION_CONTINUE_SEARCH` (קריסה מדווחת, **לעולם לא hang שקט**).
     - **מה קורה אם הכותב הסתיים (או נכשל ב־OOM וסגר את החלון ל־`active=0`)?** ה־VEH בודק תקרת retry של **פעם אחת בלבד** לכל `(fault_addr, st1 >> 2)` (`t_dn_retry_addr`, `t_dn_retry_gen`) ומחזיר `EXCEPTION_CONTINUE_EXECUTION`. אם העמוד באמת חזר — ההוראה מצליחה; אם `os_commit` נכשל (OOM) או שהייתה כתיבה ל־`PROT_READ`, הפגיעה השנייה רואה `active == 0` ו־`(fault_addr, gen)` שכבר נוסה פעם אחת -> `EXCEPTION_CONTINUE_SEARCH` -> קריסה תקינה!
   - **מקרה ב' (`(st1 & 1) == 0` — `dontneed` בדיוק הסתיים לפני כניסת ה־VEH) ו־`fault_addr` ב־`[lo, hi)`:**
     - אם `(t_dn_retry_addr != fault_addr || t_dn_retry_gen != (st1 >> 2))`: רושמים אותם ומחזירים `EXCEPTION_CONTINUE_EXECUTION` **פעם אחת בדיוק**.
     - בכל פגיעה חוזרת באותו `(fault_addr, gen)` -> `EXCEPTION_CONTINUE_SEARCH`.
4. **מגבלה מתועדת:** גישה ממצב קרנל (כמו `ReadFile`/`WriteFile` ישירות לבאפר שעובר `MADV_DONTNEED` במקביל) אינה עוברת ב־user-mode VEH ועלולה להחזיר `ERROR_NOACCESS` (`EFAULT`).
5. **בדיקות חובה (`tools/vma_test.c` — כלל 4):**
   - **עומס רב־חוטי + בדיקת Preemption מכוונת (חובה):** (א) 8 חוטי קוראים/כותבים/אטומיים מול חוט `MADV_DONTNEED` — 0 קריסות, ערכים תקינים בלבד; (ב) **הדמיית Preemption ארוכה (`#ifdef AFW_TEST`):** השהיה מכוונת של `50 ms` בתוך חלון `decommit -> commit` (ארוכה מקוונטת מתזמן Windows) בזמן שחוט קורא פוגע בדף — חייב להמתין ב־`g_dn_event`, להמשיך בהצלחה עם **0 קריסות שגויות**!
   - **שלילית (`PROT_READ`):** כתיבה לדף `PROT_READ` תוך כדי `MADV_DONTNEED` אינה נתקעת ב־retry וממשיכה ל־fault report.
   - **שלילית OOM:** כשל מוזרק ב־`os_commit` (`afw_vma_test_fail_os`) סוגר את `g_dn_state` ל־`active=0` ומעיר `g_dn_event`, והקורא מדווח fault נקי (ללא hang).
   - **שלילית timeout:** בדיקה ייעודית (עם timeout קצר בבדיקה) שהכותב תקוע בחלון -> `WAIT_TIMEOUT` -> `EXCEPTION_CONTINUE_SEARCH`, לא hang.

---

## 5. זרם עבודה 3 — מיפוי קבצים לקריאה בלבד (`src/filemap.*`) [לבודקים 2 ו־3]

לפי [`docs/COLLABORATION.md`](../COLLABORATION.md) שורה 16 ו־77: מיפוי קריאה בלבד עבור `/dev/__properties__` וקבצי נכסים, באחריות המחבר הראשי.

### 5.1 חוזה ABI חד־משמעי ל־G2 (ללא סתירה מול Bionic)

- **נתמך ללא תנאי ב־G2:**
  - **`MAP_SHARED | PROT_READ`** (נדרש ישירות ל־`map_fd_ro()` של `/dev/__properties__` ב־Bionic **[נמדד מ־AOSP / בודק 2]**) וגם **`MAP_PRIVATE | PROT_READ`** (וגם `PROT_NONE`).
  - ב־Windows, שני הדגלים הללו לקריאה בלבד ממופים זהה דרך `CreateFileMappingW(PAGE_READONLY)` + `MapViewOfFile(FILE_MAP_READ)`.
- **נדחה במפורש:**
  - `PROT_WRITE` על מיפוי קובץ -> `-ENOSYS` (מחוץ לטווח read-only של G2).
  - **`PROT_EXEC` על מיפוי קובץ -> נדחה במפורש (`-EACCES` / `-ENOSYS`)** כדי ש־`mmap` לא יעקוף את שער ה־patching (כלל 6).
  - `fd` שאינו `FD_FILE` פתוח לקריאה (`O_WRONLY` -> `-EACCES`, תיקייה -> `-ENODEV`, `fd` לא חוקי -> `-EBADF`).
  - `offset < 0` או `offset % 4096 != 0` או גלישה ב־`offset + len` -> `-EINVAL` (כלל 8).

### 5.2 אילוצי Windows, יישור 64KB, וטיפול אמיתי ב־`munmap` חלקי

1. **יישור `offset` ל־64KB מול 4KB:**
   - `aligned_off = offset & ~0xFFFFULL`, `delta = offset - aligned_off` (כפולה של `4KB`).
   - ממפים view מ־`aligned_off` ומחזירים למזמין `view_base + delta` (מיושרת ל־4KB כנדרש ב־Linux).
2. **קובץ בגודל 0 ודף סופי חלקי:**
   - `CreateFileMappingW` נכשל על קובץ של **0 בתים** (`ERROR_FILE_INVALID`). בקובץ בגודל 0: מקצים טווח `PROT_NONE` בגודל `roundup(len, 4096)` (כמו Linux: `mmap` מצליח וכל גישה גורמת ל־fault/`SIGBUS`, בלי לקרוס ב־`CreateFileMappingW`).
   - דף סופי חלקי: ממפים עד `min(delta + len, file_size - aligned_off)`. ב־Windows, `MapViewOfFile` מאפס אוטומטית את הזנב מה־EOF עד סוף העמוד האחרון (4KB) — **נוסיף בדיקה מפורשת שמוודאת זאת ב־Windows CI**. בקשה לעמודים שלמים *מעבר* ל־`roundup(file_size, 4096)` תיענה בדחייה מתועדת (`-ENOSYS`) או תמומש כ־`PROT_NONE` (יוכרע לפי הערת בודק 2).
3. **`munmap` חלקי אמיתי וטרנזקציוני ב־`VMA_FILEMAP` (תוקן לפי ממצאים של בודק 2!):**
   - ב־`src/vma.c` מפרידים ב־`winalloc` בין `kind = VMA_ANON` (`VirtualAlloc`/`VirtualFree`) לבין `kind = VMA_FILEMAP` (`MapViewOfFile`/`UnmapViewOfFile`, שומר את `view_base` המקורי לפני `delta`).
   - **פרוטוקול טרנזקציוני תלת־שלבי (מונע מצב שבו `VirtualProtect` הצליח אבל הקצאת מטא־דאטה נכשלה!):**
     1. **שלב 1 — הקצאת מטא־דאטה מראש לפני כל קריאת OS:** קוראים ל־`split_range(w, a, b, &i0, &i1)` (שמבצע `ensure_ext_cap(w, w->next + 2)` מראש; פיצול extent לשני חצאים שווי־מצב **אינו משנה את המצב הלוגי** של אף עמוד). אם הקצאת הזיכרון נכשלת -> מחזירים `-ENOMEM` מיד **בלי לקרוא ל־`VirtualProtect`**.
     2. **שלב 2 — קריאת OS:** קוראים דרך `src/platform.c` ל־`VirtualProtect(unmap_start, unmap_len, PAGE_NOACCESS, &old)` על הטווח המשוחרר. אם `VirtualProtect` נכשל -> מריצים `coalesce_around(w, i0, i1)` (ללא הקצאה, אינו יכול להיכשל) ומחזירים `-ENOMEM` — המטא־דאטה וה־OS נשארים מסונכרנים ב־100%!
     3. **שלב 3 — עדכון מטא־דאטה (בלתי־נכשל, אפס הקצאות):** מסמנים את ה־extents `[i0, i1)` כ־`state = 0`, מפחיתים מ־`mapped_bytes`, ומריצים `coalesce_around` (ללא `malloc`, אינו יכול להיכשל). כל גישה עתידית ל־4KB ששוחררו חוטפת `EXCEPTION_ACCESS_VIOLATION` מיד (כמו `SIGSEGV` ב־Linux).
     4. כאשר `mapped_bytes == 0`, קוראים ל־`UnmapViewOfFile(view_base)` (דרך `src/platform.c`) ומשחררים את הרשומה.
     - **מגבלה מתועדת של `VMA_FILEMAP`:** `MAP_FIXED` המנסה למפות מחדש *לתוך* חור שנוצר ע"י `munmap` חלקי בתוך view חי של `MapViewOfFile` מחזיר `-ENOSYS` (כי Windows אינו מפצל view פתוח); `MADV_DONTNEED` על `VMA_FILEMAP` הוא no-op (`return 0`).
   - **בדיקת כשל מטא־דאטה (`tools/filemap_test.c`):** בדיקה שלילית המזריקה כשל הקצאה או כשל `VirtualProtect` ומוודאת שמטא־דאטה והנגישות בפועל נשארות עקביות.
4. **מחיקה של קובץ ממופה (`FILE_SHARE_DELETE`) וכלל 8:**
   - [`afw_os_open`](../../src/platform.c) (שורה 190) כבר פותח קבצים עם `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` **[נמדד]**.
   - **כלל 8:** כל קריאות Win32 (`CreateFileMappingW`, `MapViewOfFile`, `UnmapViewOfFile`, `VirtualProtect`) נשארות אך ורק ב־`src/platform.c`; `src/filemap.c` הוא C11 טהור, וכל שינוי במטא־דאטה קורה רק אחרי שהקריאה ל־OS הצליחה.
   - בדיקות חובה (`tools/filemap_test.c`, Linux ASan + Windows): `MAP_SHARED|PROT_READ`, `MAP_PRIVATE|PROT_READ`, היסט 4KB שאינו כפולת 64KB, קובץ 0 בתים, דף סופי חלקי מאופס, `munmap` חלקי (בדיקה שהאמצע גורם ל־fault והצדדים נשארים קריאים!), `unlink` בזמן מיפוי, ודחיית `PROT_EXEC`/`PROT_WRITE`/`O_WRONLY`.

---

## 6. זרם עבודה 4 — `dlopen` דינמי וחריגות C++ (`libc++_shared.so` + `dl_iterate_phdr`) [לבודק 1, בודק 2 ובודק 3]

### 6.1 מצב קיים [נמדד]

- [`afw_l_dl_iterate_phdr`](../../src/loader_api.c) (שורות 206–224) ממומשת ומחזירה `dlpi_addr`, `dlpi_name`, `dlpi_phdr`, `dlpi_phnum`, `dlpi_adds`, `dlpi_tls_modid`, `dlpi_tls_data`.
- `C++ exceptions: every landing pad found, nothing unproven (static)` (`test/cxx_exception_test.cpp`) עובר ב־CI; `Explore: load the NDK's real libc++_shared.so` רץ אינפורמטיבית.

### 6.2 רכיבי העבודה ותנאי קבלה מלאים ל־unwinder ול־`thread_local` destructors

1. **נעילת רישום הספריות (`dlopen` / `dl_iterate_phdr` / `afw_lib_at`):**
   - מנעול ייעודי (`SRWLOCK` / `pthread_rwlock`, נפרד לחלוטין מ־VMA lock ו־VEH) שמגן על `g_libs[]` כך ש־`dl_iterate_phdr` בזמן זריקת חריגה במקביל ל־`dlopen` לעולם לא קורא רשימה משתנה.
2. **`__loader_add_thread_local_dtor` / `__loader_remove_thread_local_dtor`:**
   - רשומים ב־[`G1-LIBC-INIT.md`](G1-LIBC-INIT.md) שורה 183; נדרשים ל־`__cxa_thread_atexit` ב־`libc++_shared.so`.
   - סדר teardown קשיח ביציאת חוט: רישום ה־dtors רץ **לפני** שחרור בלוק ה־TLS של החוט (ולפני `clear_child_tid` wake / `ExitThread`), ובסדר LIFO כנדרש בתקן C++.
3. **טעינה דינמית (`dlopen`) של ספרייה עם `PT_TLS` (DTV / TLS דינמי):**
   - הרחבת `afw_tls_get_addr` לטבלת DTV per-thread (או מילוי `libc_shared_globals->tls_modules` לאחר האורקל של בודק 2).
4. **חריגות C++ חוצות־ספריות וחריגה חוצת־callback של Windows:**
   - **תנאי קבלה מחייבים לבדיקת ה־unwinder (ממצא 6 של בודק 2):**
     1. ה־unwinder (`libunwind` ב־`libc++_shared.so`) מאתר דרך `dl_iterate_phdr` את ה־ELF ו־program headers (`PT_GNU_EH_FRAME`) של **שתי** הספריות (הזורקת והתופסת).
     2. מידע ה־unwind (`.eh_frame`) של הספרייה הזורקת נגיש בפועל בזמן ה־stack walk.
     3. `throw std::runtime_error("payload")` ב־DSO א' נתפס ע"י `catch (const std::runtime_error &e)` ב־DSO ב' עם תוכן הודעה מדויק (לא רק `catch (...)`).
     4. אותה חריגה חוצת־DSO עובדת גם מתוך חוט משני שנוצר ב־`pthread_create`.
     5. destructors של משתני `thread_local` נקראים **פעם אחת בדיוק** בסיום החוט, לפני שחרור ה־TLS והספרייה שאליהם הם מתייחסים (מאומת במונה + ASan/Windows).
   - **חריגה חוצת־callback של Windows:** ניסוי מדיד של חריגת C++ העוברת דרך גשר callback של הטוען (`.eh_frame` תקני לגשרים + בחינת `RtlInstallFunctionTableCallback` במקרה של SEH).
5. **6 אתרי ה־`UNPROVEN` ב־`libc++_shared.so`:**
   - סגירתם תנאי חוסם לטעינת `libc++_shared.so` בשער G2; עדיפות להרחבת המנתח לתמיכה ב־`movzx` jump tables על פני allowlist נעול־hash, ובכל מקרה כפוף להסכמה בכתב של כל הבודקים (כלל 6).

---

## 7. סדר PR מוצע ל־G2

| שלב | PR / ענף | תוכן | בודקים עיקריים |
|---|---|---|---|
| **G2-0** | PR #18 (`design/g2-plan`) | אישור מסמך התכנון לפני כתיבת קוד | בודק 3, בודק 2, בודק 1 |
| **G2-1** | `exp/g2-pthread-probe` | ניסוי מדיד בלבד: syscalls של `pthread_create`/`detached`/`cond_broadcast`, trampoline אסמבלי על מחסנית Bionic, guard page, VEH + C++ unwind בחוט משני, וחזרה ל־Windows stack לפני `ExitThread` | בודק 3, בודק 2 |
| **G2-2** | `g2-filemap` | `src/filemap.*` + `src/platform.c` + `VMA_FILEMAP` ב־`src/vma.c` (`MAP_SHARED|PROT_READ` + `MAP_PRIVATE|PROT_READ`, 64KB/4KB, קובץ 0 בתים, `munmap` חלקי טרנזקציוני עם הקצאה מראש + `PAGE_NOACCESS`, `unlink` בזמן מיפוי) + בדיקות Linux ASan & Windows | בודק 2, בודק 3 |
| **G2-3** | `g2-vma-dontneed-mt` | `MADV_DONTNEED` מקבילי (C11 `_Atomic` double-buffered active window + Event קרנל מוקצה מראש `WaitForSingleObject(g_dn_event, 5000)` לעמידות מלאה ל־preemption + `g_lock` סביב כל החלון + שחרור חלון ב־OOM + הגבלה ל־`MAP_PRIVATE|MAP_ANONYMOUS`) + בדיקת עומס, הדמיית preemption של 50ms ובדיקות שליליות ב־`tools/vma_test.c` | בודק 3, בודק 2 |
| **G2-4** | `g2-pthreads` | `SYS_clone` (או Fallback ליירוט `pthread_create` לפי G2-1) + `_exit_with_stack_teardown` + `SYS_set_tid_address` + חוזה C11 אטומי ל־`clear_child_tid` + הרחבת `SYS_futex` (`CMP_REQUEUE`/`REQUEUE`) + בדיקת `pthreads` מול `libc.so` | בודק 3, בודק 2 |
| **G2-5** | `g2-cxx-dlopen-gate` | נעילת `dl_iterate_phdr`, `thread_local` dtors, `dlopen` עם `PT_TLS` דינמי, חריגות C++ חוצות־ספריות וחוצות־callback, ו־Gate G2 ב־Windows CI (או `G2a`/`G2b` אם יאושר בכתב לפי כלל 6) | בודק 1, בודק 2, בודק 3 |

---

## 8. שאלות ממוקדות לאישור הבודקים

### לבודק 3 (זיכרון, TLS, חוטים, VEH)
1. **פרוטוקול `MADV_DONTNEED` האטומי ועמידות ל־Preemption (סעיף 4.2):** האם ה־double-buffered `_Atomic` state (`g_dn_slot[2]` + `g_dn_state`) + Event קרנל מוקצה מראש (`ResetEvent -> active_st -> decommit/commit -> idle_st -> SetEvent`, המתנת `WaitForSingleObject(g_dn_event, 5000)` ב־VEH ללא אף נעילת user-mode, עם `g_lock` סביב כל חלון הכותב וסגירה גם ב־OOM) עונה על כל דרישות הבטיחות שלך?
2. **`SYS_clone`, `_exit_with_stack_teardown` ו־`clear_child_tid` (סעיפים 3.1–3.4):** האם 5 מדידות שלב 0, סימון מסלול ה־TLS כ־`[השערה]` עד שלב 0, חוזה ה־C11 האטומי ל־`clear_child_tid`, ותנאי ה־Fallback ליירוט `pthread_create` סוגרים את הסיכונים?
3. **`SYS_futex` (`REQUEUE`/`CMP_REQUEUE`) ו־TLS דינמי:** האם להעדיף `WaitOnAddress` (חלופה 1) או טבלת waiters פנימית (חלופה 2), וב־TLS דינמי — DTV ב־`afw_tls_get_addr` או מילוי `libc_shared_globals->tls_modules` אחרי האורקל?

### לבודק 2 (Linux ABI, `filemap`, `futex`, אורקל `libc_shared_globals`)
4. **בדיקה חוזרת של שלושת התיקונים מסבב `dd3e4e8`:** (1) המתנת `MADV_DONTNEED` ב־VEH מעל Event קרנל מוקצה מראש (עמיד ל־preemption, 0 נעילות user-mode, 5000ms watchdog, + הדמיית preemption של 50ms בבדיקה), (2) `munmap` חלקי טרנזקציוני (`split_range`/`ensure_ext_cap` לפני `VirtualProtect(PAGE_NOACCESS)`), (3) חוזה C11 אטומי מפורש ל־`clear_child_tid` (יישור 4 בתים, `atomic_store(..., seq_cst)` לפני `wake`, והחלפה ב־`SYS_set_tid_address`) + סימון מסלול `TlsSetValue` כ־`[השערה]` — האם הגרסה הזו סוגרת את כל הממצאים שלך לאישור `G2-PLAN.md`?
5. **סטטוס אורקל `libc_shared_globals` ופיצול `G2a`/`G2b`:** מה מצב `tools/oracle/`, והאם לשמור על G2 מאוחד או להציע פיצול `G2a`/`G2b` בכתב לפי כלל 6?

### לבודק 1 (שערי טעינה, 9 אתרי `UNPROVEN`, חריגות C++)
6. **6 אתרי `UNPROVEN` ב־`libc++_shared.so` (PR #5 / PR #7):** האם אתה מסכים להעדיף תמיכה במנתח ב־`movzx` jump tables על פני allowlist נעול־hash לסגירת ה־6 ב־`libc++` תחת כלל 6?
7. **שער `PROT_EXEC` ב־`filemap`, חריגות C++ ופיצול `G2a`/`G2b`:** האם דחיית `PROT_EXEC` על `filemap` ותנאי הקבלה של ה־unwinder בסעיף 6.2 תואמים את דרישות השער שלך?
