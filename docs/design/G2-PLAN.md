# תכנון Gate G2: ריבוי חוטים (`pthreads`), `MADV_DONTNEED` מקבילי, `filemap` וחריגות C++

מצב: **טיוטה לביקורת תכנון לפני כתיבת קוד** (לפי [`docs/COLLABORATION.md`](../COLLABORATION.md), שורות 15, 77).
מיועד לביקורת של **בודק 3** (זיכרון, TLS, חוטים, VEH), **בודק 2** (Linux ABI, `filemap`, קריאות מערכת, אורקל `libc_shared_globals`), ו**בודק 1** (שערי טעינה, 9 אתרי `UNPROVEN`, חריגות C++ / `libc++_shared.so`).

סימון לפי כלל 7: **[נמדד]** = מבוסס על קוד קיים או פלט CI מפורש, **[השערה]** = טענה שטרם נמדדה ותוכרע בניסוי (כלל 7א).

---

## 1. נקודת הפתיחה לאחר סגירת Gate G1 [נמדד]

`main` בקומיט `38d10ef` (ריצת CI [`45252862246`](https://github.com/anutk11/android-for-windows/actions/runs/45252862246) — 5/5 jobs ירוקים כולל `release`):

- **`libc.so` האמיתית** (Android 14 `sdk_phone64_x86_64`, Build ID `fa337969c798946280caa45e2d71a2e7`): נטענת ומתוקנת (`0 refused`), ששת הקונסטרקטורים שלה רצים, ו־`test/real_libc_test.c` עובר 11/11 ב־Windows CI (PR #11).
- **הרצת executable אמיתי עד `main()`:** `test/hello_exe.c` ו־`test/exec_min.c` עברו ב־Windows וב־Linux ASan; מחסנית התחלתית, `envp`, `auxv` מלא לפני קונסטרקטורים ואימות `e_entry` ב־`PT_LOAD` עם `PF_X` (PR #16).
- **שכבת קבצים מלאה ו־Gate G1:** `src/fd.c` + `src/platform.c` (`openat`, `read/write/readv/writev`, `lseek`, `fstat/stat/lstat/newfstatat`, `unlinkat`, `fcntl` כולל `F_GETFL`/`F_SETFL`, `O_APPEND` אטומי בקריאת מערכת יחידה בשתי הפלטפורמות, `O_NOFOLLOW`, והפרדת symlinks מול Windows junctions); `tools/fd_test.c` עובר 84/84 ב־Linux ASan ו־90/90 ב־Windows, ו־`test/g1_gate_exe.c` מדפיס `G1 GATE PASSED` ב־Windows CI (PR #17).
- **VMA על extents:** `src/vma.c` (`mmap`/`munmap`/`mprotect`/`madvise`, `afw_vma_adopt`, שריון 64GB בפחות מ־1MB מטא־דאטה — PR #10, PR #14).

### תנאי קדם חיצוניים לפני סגירת G2 (`COLLABORATION.md` שורה 77) [נמדד]

שני פריטים אלה אינם חוסמים את ביקורת התכנון של G2, אך צריכים להיסגר לפני סגירת שער G2:
1. **9 אתרי `UNPROVEN`** (3 ב־`linker64`, 6 ב־`libc++`): פתוחים ב־PR #5 ו־PR #7. כפופים לכלל 6 — כל שינוי בשער דורש הסכמה מפורשת בכתב של כל הבודקים.
2. **אורקל `libc_shared_globals` (`tools/oracle/` + `src/bionic_abi/shared_globals.h`):** נדרש לפני שממלאים שדות נוספים ב־`libc_shared_globals` מעבר למה שכבר נמדד ב־`tools/sg_uses.py` (ובפרט לפני שמאפשרים ל־Bionic לקרוא `static_tls_layout` / `tls_modules` עבור TLS דינמי).

---

## 2. הגדרת שער G2 (יעד מדיד)

שער G2 ייחשב סגור כאשר תוכנית NDK אמיתית ב־C++ תרוץ ב־Windows CI כשלב חובה עם `libc.so` ו־`libc++_shared.so` האמיתיות ותוכיח את ארבעת הרכיבים הבאים:

1. **ריבוי חוטים (`pthreads`):** יצירת מספר חוטים ב־`pthread_create`, בידוד `errno` ו־`thread_local` לכל חוט, סנכרון עם `pthread_mutex` + `pthread_cond` (מעל `futex`), גישות `fs:` תקינות מחוטים משניים, ואיסוף מלא ב־`pthread_join` בלי דליפת TLS/מחסניות.
2. **זיכרון מקבילי (`MADV_DONTNEED`):** חוט אחד מריץ `madvise(MADV_DONTNEED)` בלולאה על אזור `PROT_READ|PROT_WRITE` בזמן שחוטים אחרים ניגשים לאותו אזור — אפס קריסות, אפס deadlocks ב־VEH, ואימות איפוס לאפסים; ובדיקה שלילית ש־fault אמיתי (כתיבה ל־`PROT_READ`) עדיין מדווח כקריסה ולא נתקע בלולאה.
3. **מיפוי קבצים לקריאה בלבד (`src/filemap.*`):** `mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, offset)` קורא תוכן קובץ (תשתית ל־`/dev/__properties__` וקבצי נכסים), עם `munmap` מלא/חלקי ובדיקות שליליות (דגלים/הרשאות אסורים).
4. **חריגות C++ חוצות־ספריות:** זריקת `std::runtime_error` (ותפיסתה) מתוך `.so` עם `libc++_shared.so` ו־`dl_iterate_phdr` תחת ריבוי חוטים.

---

## 3. זרם עבודה 1 — חוטים (`pthreads`: `SYS_clone` מול יירוט `pthread_create`) [לבודק 3]

### 3.1 שלב 0 — ניסוי מדיד לפני מימוש (כלל 7א)

לפני כתיבת קוד ייצור, נריץ ניסוי קטן ומדיד ב־Windows CI (`test/pthread_probe.c` — שלב אינפורמטיבי) שקורא ל־`pthread_create` + `pthread_join` מול `libc.so` האמיתית ומתעד מלוג `syscall.c`:
1. אילו קריאות מערכת Bionic מבצעת בתוך `pthread_create` (השערה: `mmap` למחסנית+TLS, `mprotect` ל־guard page, `clone` (`56`), `set_tid_address` (`218`), `rt_sigprocmask` (`14`), `set_robust_list` (`273`), `prctl` (`157`)).
2. מהם בדיוק הדגלים והפרמטרים של `clone(flags, child_stack, parent_tidptr, child_tidptr, newtls)` [השערה: `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID`].
3. **ניסוי Windows קריטי — `NT_TIB` ו־VEH על מחסנית משנית:** חוט Windows שנוצר ב־`CreateThread` ומעביר את `RSP` למחסנית שהוקצתה ב־`mmap` (מחוץ לטווח `TEB->StackBase..StackLimit` המקורי) גורם במכוון ל־`fs:` read fault ול־access violation. בודקים במדידה ישירה ב־Windows CI האם `AddVectoredExceptionHandler` (`RtlDispatchException`) מופעל תקין כאשר `RSP` מחוץ ל־`NT_TIB`, או ש־Windows דורש עדכון של `NT_TIB.StackBase`/`StackLimit` (או שימוש במחסנית ה־`CreateThread`).

### 3.2 השוואת שתי אפשרויות מימוש

| היבט | אפשרות א': מימוש `SYS_clone` (`56`) מעל `CreateThread` | אפשרות ב': יירוט סמל `pthread_create` |
|---|---|---|
| תאימות ל־Bionic | מלאה — Bionic בונה `pthread_internal_t`, `bionic_tls`, guard page, `pthread_key`, ו־`pthread_join` בעצמה | חלקית — שובר כל קוד פנימי של Bionic/ART/libc++ שתלוי ב־`pthread_internal_t` אמיתי |
| ניהול TLS (`newtls`) | `CLONE_SETTLS` מעביר `tp` ש־Bionic הכינה; הטוען כותב אותו ל־TEB `g_slot[0]` וכותב `guard` ל־`g_slot[5]` | הטוען נאלץ לשכפל את כל מבנה ה־`pthread_internal_t` של Bionic |
| שחרור זיכרון | **אסור** לרשום `FLS` release על `newtls` שהוקצה ע"י Bionic (מונע double-free על `mmap` של Bionic!) | הטוען מנהל שחרור, אבל אין סנכרון מול `pthread_detach`/`pthread_join` |
| מורכבות Windows | דורש פתרון מאומת ל־`child_stack` מול `NT_TIB`/VEH ולמילוי `static_tls_layout` ב־`libc_shared_globals` | פשוטה לניסוי קצר, יקרה לתחזוקה ב־G3 (ART) |

**המלצה ראשונית [השערה]:** **אפשרות א' (`SYS_clone`)**, בכפוף לשתי תוצאות של ניסוי שלב 0:
1. אימות התנהגות VEH עם `child_stack` / `NT_TIB` על Windows.
2. אימות שדות `static_tls_layout` ב־`libc_shared_globals` (מול האורקל של בודק 2) כדי ש־Bionic תקצה את הבלוק ה־TLS הסטטי הנכון לכל חוט חדש.

### 3.3 מחזור חיים מדויק של חוט באפשרות א'

1. **כניסה ל־`SYS_clone` (`56`):**
   - מאשר רק דגלי thread נתמכים (חובה `CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FILES | CLONE_FS`; דגלים לא נתמכים או `fork` בלי `CLONE_THREAD` נדחים ב־`-ENOSYS` / `-EINVAL`).
   - שומר את מצב הרגיסטרים ה־callee-saved ואת כתובת החזרה (`rip` ב־`rbp+16` מ־`afw_syscall_entry`) עבור הילד; `rax = 0` בילד, `rax = child_tid` בהורה.
   - יוצר חוט Windows עם `CreateThread` וממתין על אירוע התחלה קצר (`startup_done`) עד שהילד:
     - מקבל את ה־`tid` שלו (`GetCurrentThreadId()`),
     - כותב `*parent_tidptr = tid` (אם `CLONE_PARENT_SETTID`) ו־`*child_tidptr = tid` (אם `CLONE_CHILD_SETTID`),
     - רושם `t_clear_child_tid = child_tidptr` (אם `CLONE_CHILD_CLEARTID`),
     - מאתחל TEB slots (`TlsSetValue(g_slot[0], newtls)` ו־`TlsSetValue(g_slot[5], stack_guard)` — **בלי** רישום `FLS` release על `newtls` של Bionic!).
   - רק לאחר מכן ההורה חוזר עם `child_tid` — מונע race שבו ההורה רואה `tid == 0` או קורא `pthread_join` לפני שה־`clear_child_tid` נרשם.
2. **יציאת חוט ב־`SYS_exit` (`60`):**
   - אם `t_clear_child_tid != NULL`: מאפס אטומית `*t_clear_child_tid = 0` (`InterlockedExchange` / `atomic_store`) וקורא `WakeByAddressAll(t_clear_child_tid)` (ב־Linux: `futex(FUTEX_WAKE)`), ורק אז קורא `ExitThread`.
   - `SYS_set_tid_address` (`218`) מעדכן את `t_clear_child_tid` ומחזיר `sys_gettid()`.
3. **`afw_tls_block()` ו־`__tls_get_addr`:**
   - בחוט שנוצר ע"י `clone(CLONE_SETTLS)`, `t_block` יעודכן ל־`newtls` (או ייקרא ישירות מ־`TlsGetValue(g_slot[0])`), כך שגם `afw_tls_static_resolve` וגם `dl_iterate_phdr` יראו את ה־`tp` האמיתי של החוט.
   - **[פתוח לבודקים 2 ו־3]:** האם ב־G2 נמלא את `libc_shared_globals->static_tls_layout` + `tls_modules` (לאחר האורקל) ונעבור ל־DTV אמיתי, או שב־G2 נשאר עם `afw_tls_get_addr` סטטי (ולוח זמנים נפרד ל־dynamic `dlopen` TLS)?

---

## 4. זרם עבודה 2 — `MADV_DONTNEED` מקבילי ובטוח לחוטים (`src/vma.c`) [לבודק 3 ובודק 2]

### 4.1 הבעיה הקיימת [נמדד]

ב־[`src/vma.c`](../../src/vma.c) (`do_dontneed`, שורות 614–643):
```c
os_decommit(start, len);          /* VirtualFree(MEM_DECOMMIT) -> MEM_RESERVE */
w->ext[i].state = P_MAPPED;
if (prot) {
    os_commit(start, len, prot);  /* VirtualAlloc(MEM_COMMIT) -> zeros */
    w->ext[i].state = P_MAPPED | P_COMMIT | prot;
}
```
בין `os_decommit` ל־`os_commit` העמוד הוא `MEM_RESERVE` (לא נגיש). בחוט יחיד (G1) אף קוד אחר לא נוגע בו. בריבוי חוטים (G2 — בפרט Scudo allocator), חוט אחר שנוגע באותו טווח במהלך החלון יחטוף `EXCEPTION_ACCESS_VIOLATION` ויקרס.

למה לא `MEM_RESET` / `DiscardVirtualMemory`? [נמדד מתיעוד Win32]:
- `MEM_RESET` / `DiscardVirtualMemory` אינם מבטיחים שהתוכן יאופס (Windows רשאי להשאיר נתונים ישנים) — וזה מפר את חוזה Linux של `MADV_DONTNEED` (שהבדיקות ב־`tools/vma_test.c` ו־Scudo/ART מסתמכות עליו: אפסים מיידיים).
- `memset(0)` אינו עובד על דפי `PROT_READ` / `PROT_READ|PROT_EXEC` ואינו משחרר commit.

### 4.2 התכנון המוצע — Lock-Free Active Window + VEH Retry

**כלל ברזל (לקח PR #11 ו־`G1-TLS.md`):** ה־VEH handler **לעולם לא נועל** את ה־`SRWLOCK` של `src/vma.c` (`g_lock`), ולא קורא ל־`malloc` או ל־Win32 Loader Lock.

1. **מצב גלובלי סטטי ב־`src/vma.c`** (גודל 24 בתים; נכתב רק תחת `g_lock`, כך שיש לכל היותר כותב אחד בכל רגע):
   ```c
   static volatile uint64_t g_dn_seq;     /* זוגי = לא פעיל, אי-זוגי = בתוך decommit->commit */
   static volatile uint64_t g_dn_start;
   static volatile uint64_t g_dn_end;
   ```
2. **צד הכותב (`do_dontneed`, תחת `g_lock`, רק כאשר `prot != 0`):**
   - כותב `g_dn_start = ext.start`, `g_dn_end = ext.end`.
   - מקדם אטומית `g_dn_seq` מ־`2k` ל־`2k + 1` (release barrier).
   - מבצע `os_decommit(ext.start, len)` ואז `os_commit(ext.start, len, prot)`.
   - מקדם אטומית `g_dn_seq` מ־`2k + 1` ל־`2k + 2` (release barrier) — **גם אם `os_commit` נכשל**!
3. **צד ה־VEH (`vma_dontneed_veh`, מותקן בעדיפות לאחר `fs_handler` ולפני `crash`):**
   - מסנן מיד: רק `EXCEPTION_ACCESS_VIOLATION` עם `NumberParameters >= 2` (ו־`fault_addr >= 0x10000`, לא קריאה מתחת ל־64KB ששייכת ל־`fs:`).
   - קורא `s1 = atomic_load_acquire(&g_dn_seq)`:
     - אם `(s1 & 1) == 0` **וגם** `s1 == t_last_seen_seq` -> לא היה `dontneed` פעיל -> `EXCEPTION_CONTINUE_SEARCH` (מסלול מהיר ללא נעילות).
   - **טיפול ב־race שבו `dontneed` בדיוק הסתיים לפני שה־VEH רץ:**
     - אם חוט ב' חטף fault בזמן `s = 2k + 1`, ועד שה־VEH של חוט ב' נכנס `g_dn_seq` כבר הפך ל־`2k + 2`, חוט ב' עדיין יראה `s1` זוגי!
     - פתרון: שומרים גם את הטווח האחרון (`g_dn_prev_start`, `g_dn_prev_end`, `g_dn_prev_seq`) — או פשוט בודקים תמיד מול `[g_dn_start, g_dn_end)` עם תקרת retry של **פעם אחת בלבד** לכל `(fault_addr, s1)` ב־`_Thread_local` (`t_retry_addr`, `t_retry_seq`)!
     - פירוט:
       - קוראים `(s1, lo, hi, s2)` עם acquire barriers (seqlock-style snapshot).
       - אם `s1` אי-זוגי: אם `fault_addr` ב־`[lo, hi)` (או `s2 != s1`), ממתינים בלולאת `YieldProcessor()` / `SwitchToThread()` עד ש־`g_dn_seq != s1`, ואז מחזירים `EXCEPTION_CONTINUE_EXECUTION` (עד retry אחד ל־`(fault_addr, s1)`).
       - אם `s1` זוגי (גדול מ־0) ו־`s1 == s2` ו־`fault_addr` ב־`[lo, hi)` ו־`(t_retry_addr != fault_addr || t_retry_seq != s1)`: רושמים `t_retry_addr = fault_addr; t_retry_seq = s1;` ומחזירים `EXCEPTION_CONTINUE_EXECUTION` **פעם אחת בלבד** (מכסה בדיוק את המקרה שה־`os_commit` הסתיים מיקרו־שנייה לפני כניסת ה־VEH!).
       - אם אותה הוראה חוטפת fault שוב באותו `(fault_addr, s1)` (למשל כתיבה לדף `PROT_READ`, או ש־`os_commit` נכשל ב־OOM): התנאי נכשל -> `EXCEPTION_CONTINUE_SEARCH` -> דוח הקריסה רץ, **לעולם לא לולאה אינסופית**!
4. **בדיקות חובה (`tools/vma_test.c` — כלל 4):**
   - **חיובית (מקבילית):** חוט 1 מריץ אלפי קריאות `MADV_DONTNEED` על טווח `PROT_READ|PROT_WRITE` בזמן שחוט 2 קורא ממנו ברציפות — 0 קריסות; כל מילה שנקראת היא או הערך שנכתב או `0`.
   - **שלילית (ללא hang):** כתיבה לדף `PROT_READ` תוך כדי `MADV_DONTNEED` חייבת להמשיך לקריסה (או להיתפס ב־SEH/VEH של הבדיקה) ולא להיתקע ב־retry אינסופי.
   - **שלילית OOM:** כשל מוזרק ב־`os_commit` (`afw_vma_test_fail_os`) חייב להחזיר `g_dn_seq` לזוגי ולדווח על fault אמיתי בגישה מאוחרת.

---

## 5. זרם עבודה 3 — מיפוי קבצים לקריאה בלבד (`src/filemap.*`) [לבודקים 2 ו־3]

לפי [`docs/COLLABORATION.md`](../COLLABORATION.md) שורה 16 ו־77: מיפוי קריאה בלבד (`MAP_PRIVATE`, `PROT_READ`) עבור `/dev/__properties__` וקבצי נכסים, באחריות המחבר הראשי.

### 5.1 דרישות Linux ABI וגבולות G2

- **נתמך ב־G2:**
  - `mmap(addr, len, prot, flags, fd, offset)` כאשר `!(flags & MAP_ANONYMOUS)`:
  - `flags`: חובה `MAP_PRIVATE` (ודגלים אופציונליים מותרים כמו `MAP_FIXED` רק אם יידרש — ברירת מחדל לדחות `MAP_FIXED` על קובץ ב־`-ENOSYS` אלא אם יימדד צורך). `MAP_SHARED` יידחה ב־`-ENOSYS` (למעט אם מדידה של `/dev/__properties__` תראה ש־Bionic מעבירה `MAP_SHARED | PROT_READ` — **נבדוק זאת במדידה מול `libc.so`!**).
  - `prot`: `PROT_READ` או `PROT_NONE` בלבד. `PROT_WRITE` -> `-ENOSYS` (לא נדרש ל־read-only filemap ב־G2); `PROT_EXEC` -> **נדחה במפורש (`-EACCES` / `-ENOSYS`)** כדי ש־`mmap` לא יוכל לעקוף את שער ה־patching (כלל 6).
  - `fd`: קובץ פתוח חוקי ב־`src/fd.c` (`FD_FILE`, לא `FD_STDIO`, לא תיקייה -> `-ENODEV`/`-EACCES`, לא `O_WRONLY` -> `-EACCES`).
  - `offset`: חייב להיות `>= 0` ומיושר ל־`4096` (אחרת `-EINVAL`), ובדיקת גלישה ל־`offset + len` (כלל 8).
- **כלל 8 (בידוד Win32):** כל קריאות Win32 (`CreateFileMappingW`, `MapViewOfFile`, `UnmapViewOfFile`, או `afw_os_pread`) נמצאות **אך ורק** ב־`src/platform.c`; `src/filemap.c` הוא C11 טהור.

### 5.2 בחירת ארכיטקטורה ב־Windows (שאלה פתוחה לבודקים 2 ו־3)

על Windows יש שתי מגבלות ידועות של `MapViewOfFile`:
1. היסט (`dwFileOffsetLow`) חייב להיות כפולה של **64KB** (`dwAllocationGranularity`), בעוד Linux מאפשר כפולה של **4KB**.
2. `UnmapViewOfFile` משחרר את **כל** ה־view בבת אחת (אין partial unmap), ו־`MapViewOfFile` אינו מאפשר למפות מעבר לסוף הקובץ (ב־Linux העמוד האחרון מרופד באפסים עד גבול 4KB).

שתי החלופות לדיון:

| חלופה | איך עובד | יתרונות | חסרונות |
|---|---|---|---|
| **א': `CreateFileMappingW` + `MapViewOfFile` (אפס עותק)** | ממפה view מ־`rounddown(offset, 64KB)` עם `FILE_MAP_READ`, מחזיר `view + (offset & 0xFFFF)`, ועוקב אחרי ה־view ב־`src/vma.c` (`kind = VMA_FILEMAP`). ב־`munmap` משחרר את ה־view רק כשכל הטווח שלו שוחרר (`mapped_bytes == 0`) | אפס עותק, חסכוני בזיכרון לקבצים גדולים (APK/assets/properties), רואה עדכונים חיצוניים אם נדרש `MAP_SHARED` בעתיד | דורש טיפול מיוחד כש־`offset + len > file_size` (ריפוד עמוד אחרון) ו־`mprotect` מוגבל ל־`PAGE_READONLY`/`PAGE_NOACCESS` |
| **ב': העתקה לתוך VMA אנונימי (`VirtualAlloc` + `pread` + `PAGE_READONLY`)** | מקצה ב־VMA רגיל, קורא `[offset, min(offset+len, file_size))` ב־`pread`, משאיר שארית מאופסת, ומגדיר `PAGE_READONLY` | עובד לכל `offset` מיושר ל־`4KB`, תומך אוטומטית ב־`munmap` חלקי, `mprotect`, `MADV_DONTNEED`, ובדיקות ASan זהות | צורך commit מלא בגודל המיפוי; לא מתאים ל־`MAP_SHARED` ולא יעיל לקבצים של עשרות MB |

**המלצה להכרעת הבודקים:**
- אם `/dev/__properties__` ב־Bionic ממופה ב־`MAP_SHARED | PROT_READ` או קבצים גדולים — **אפשרות א'** (עם fallback נקי או דחייה מתועדת עבור `offset + len > roundup(file_size, 4096)`).
- אם G2 מתמקד ב־`MAP_PRIVATE | PROT_READ` בלבד (ככתוב ב־`COLLABORATION.md` שורה 16) — נכריע בין א' ל־ב' לפי הערות בודקים 2 ו־3.

---

## 6. זרם עבודה 4 — חריגות C++ (`libc++_shared.so` + `dl_iterate_phdr`) [לבודק 1 ובודק 2]

### 6.1 מצב קיים [נמדד]

- [`afw_l_dl_iterate_phdr`](../../src/loader_api.c) (שורות 206–224) כבר ממומשת ומחזירה `dlpi_addr`, `dlpi_name`, `dlpi_phdr`, `dlpi_phnum`, `dlpi_adds`, `dlpi_tls_modid`, `dlpi_tls_data`.
- ב־CI קיימים כרגע:
  - `C++ exceptions: every landing pad found, nothing unproven (static)` (`test/cxx_exception_test.cpp`) — עובר.
  - `Explore: load the NDK's real libc++_shared.so` — רץ אינפורמטיבית.

### 6.2 מה חסר ל־G2

1. **בטיחות חוטים ב־`loader_api.c` (`dlopen` / `dl_iterate_phdr` / `afw_lib_at`):**
   - כרגע `g_libs[]` ב־`src/elf_loader.c` אינו נעול; בריבוי חוטים, חוט אחד שזורק חריגה (`dl_iterate_phdr`) בזמן שחוט אחר מבצע `dlopen` עלול לקרוא רשימה משתנה. נדרש מנעול (`SRWLOCK` / `pthread_rwlock`, נפרד לחלוטין מ־VMA lock ו־VEH!) המגן על רישום הספריות וה־iteration.
2. **`__loader_add_thread_local_dtor` / `__loader_remove_thread_local_dtor`:**
   - רשומים כפתוחים ב־[`G1-LIBC-INIT.md`](G1-LIBC-INIT.md) שורה 183; נדרשים עבור destructors של משתני C++ `thread_local` שנטענים דרך `libc++_shared.so` (ב־`__cxa_thread_atexit`).
3. **קידום בדיקת `throw`/`catch` אמיתית ל־required CI step:**
   - הרצת `test/cxx_exception_test.cpp` (ועדכונו כך שיעבוד מול `libc.so` + `libc++_shared.so` האמיתיות ומתוך חוט משני ב־`pthread_create`) כשלב חובה ב־Windows CI.
4. **סגירת 6 אתרי ה־`UNPROVEN` ב־`libc++`:**
   - מתואמת מול PR #5 ו־PR #7 של בודק 1, תחת כלל 6 (הסכמה מפורשת של כל הבודקים לפני כל שינוי בשער).

---

## 7. סדר PR מוצע ל־G2

כל שלב יוגש כ־PR קטן, עצמאי ומכוסה בבדיקה שנכשלת בלעדיו (כלל 4):

| שלב | PR / ענף | תוכן | בודקים עיקריים |
|---|---|---|---|
| **G2-0** | PR זה (`design/g2-plan`) | אישור מסמך התכנון לפני כתיבת קוד | בודק 3, בודק 2, בודק 1 |
| **G2-1** | `exp/g2-pthread-probe` | ניסוי מדיד בלבד: אילו syscalls `pthread_create` קוראת + בדיקת VEH/`NT_TIB` על מחסנית `mmap` ב־Windows CI | בודק 3, בודק 2 |
| **G2-2** | `g2-filemap` | מימוש `src/filemap.*` + `src/platform.c` + שילוב `src/vma.c` + בדיקות יחידה (Linux ASan + Windows) | בודק 2, בודק 3 |
| **G2-3** | `g2-vma-dontneed-mt` | `MADV_DONTNEED` מקבילי (lock-free active window + VEH retry) + בדיקת עומס ובדיקה שלילית ב־`tools/vma_test.c` | בודק 3, בודק 2 |
| **G2-4** | `g2-pthreads` | מימוש `SYS_clone` + `SYS_set_tid_address` + `SYS_exit` futex wake + תיאום `NT_TIB`/TLS + בדיקת `pthreads` מול `libc.so` האמיתית | בודק 3, בודק 2 |
| **G2-5** | `g2-cxx-gate` | נעילת `dl_iterate_phdr`, `thread_local` dtors, ובדיקת שער G2 מלאה ב־Windows CI (`pthreads` + `filemap` + `MADV_DONTNEED` + C++ exceptions עם `libc.so` + `libc++_shared.so`) | בודק 1, בודק 2, בודק 3 |

---

## 8. שאלות ממוקדות לאישור הבודקים

### לבודק 3 (זיכרון, TLS, חוטים, VEH)
1. **`SYS_clone` מול `NT_TIB`:** האם מתווה ניסוי שלב 0 (מדידת `RtlDispatchException` / VEH על מחסנית `mmap`) והעדפת `SYS_clone` (אפשרות א') ללא `FLS` release על `newtls` שהוקצה ע"י Bionic נראים נכונים, או שיש סיכונים נוספים ב־TEB/FLS שצריך לבדוק בניסוי?
2. **`MADV_DONTNEED` מקבילי (סעיף 4.2):** האם מנגנון ה־lock-free sequence (`g_dn_seq` + טווח `[start, end)` + תקרת retry אחת לכל `(fault_addr, seq)` ב־VEH, בלי לנעול לעולם את `g_lock`) סוגר את כל חלונות ה־race וה־deadlock? האם יש מקרה קצה שבו `SwitchToThread()` בתוך VEH מסוכן?
3. **TLS דינמי ב־G2:** האם ב־G2 להשאיר `afw_tls_get_addr` סטטי ולדחות DTV דינמי (`dlopen` של `.so` עם `PT_TLS`), או למלא `static_tls_layout` ב־`libc_shared_globals` מיד עם כניסת האורקל?

### לבודק 2 (Linux ABI, `filemap`, אורקל `libc_shared_globals`)
4. **`src/filemap.*` (סעיף 5.2):** האם להעדיף אפשרות א' (`CreateFileMappingW` + `MapViewOfFile` עם תמיכה ב־64KB alignment) או אפשרות ב' (`VirtualAlloc` + `pread` + `PAGE_READONLY`) עבור G2?
5. **סטטוס אורקל `libc_shared_globals`:** מה מצב `tools/oracle/`, ואיזה חלק מ־`src/bionic_abi/shared_globals.h` כדאי שנתחיל להכין כבר עכשיו בצד הטוען כדי שלא יעכב את G2-4 (`pthreads`)?
6. **קריאות מערכת נוספות ב־G2:** אילו בדיקות ABI שליליות חשוב לדרוש מראש ב־`SYS_clone`, `SYS_set_tid_address` ו־`filemap`?

### לבודק 1 (שערי טעינה, 9 אתרי `UNPROVEN`, חריגות C++)
7. **PR #5 ו־PR #7 (`UNPROVEN`):** מה חסר כדי להביא את 9 האתרים (בפרט 6 האתרים ב־`libc++`) להסכמה משותפת תחת כלל 6 לצורך שער G2?
8. **שער `PROT_EXEC` ב־`filemap` וחריגות C++:** האם דחיית `PROT_EXEC` על `mmap` קבצים ודרישת `test/cxx_exception_test.cpp` חוצה־ספריות עם `libc++_shared.so` תואמים את דרישות השער שלך ל־G2?
