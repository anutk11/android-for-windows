# תכנון Gate G2: ריבוי חוטים (`pthreads` + `futex`), `MADV_DONTNEED` מקבילי, `filemap`, `dlopen`/TLS דינמי וחריגות C++

מצב: **טיוטה מעודכנת (גרסה 2) לביקורת תכנון לפני כתיבת קוד** (לפי [`docs/COLLABORATION.md`](../COLLABORATION.md), שורות 15, 77).
מיועד לביקורת של **בודק 3** (זיכרון, TLS, חוטים, VEH), **בודק 2** (Linux ABI, `filemap`, `futex`, אורקל `libc_shared_globals`), ו**בודק 1** (שערי טעינה, 9 אתרי `UNPROVEN`, חריגות C++ / `libc++_shared.so`).

סימון לפי כלל 7: **[נמדד]** = מבוסס על קוד קיים או פלט CI מפורש, **[השערה]** = טענה שטרם נמדדה ותוכרע בניסוי (כלל 7א).

---

## 1. נקודת הפתיחה לאחר סגירת Gate G1 [נמדד]

`main` בקומיט `38d10ef` (ריצת CI [`45252862246`](https://github.com/anutk11/android-for-windows/actions/runs/45252862246) — 5/5 jobs ירוקים כולל `release`):

- **`libc.so` האמיתית** (Android 14 `sdk_phone64_x86_64`, Build ID `fa337969c798946280caa45e2d71a2e7`): נטענת ומתוקנת (`0 refused`), ששת הקונסטרקטורים שלה רצים, ו־`test/real_libc_test.c` עובר 11/11 ב־Windows CI (PR #11).
- **הרצת executable אמיתי עד `main()`:** `test/hello_exe.c` ו־`test/exec_min.c` עברו ב־Windows וב־Linux ASan; מחסנית התחלתית, `envp`, `auxv` מלא לפני קונסטרקטורים ואימות `e_entry` ב־`PT_LOAD` עם `PF_X` (PR #16).
- **שכבת קבצים מלאה ו־Gate G1:** `src/fd.c` + `src/platform.c` (`openat`, `read/write/readv/writev`, `lseek`, `fstat/stat/lstat/newfstatat`, `unlinkat`, `fcntl` כולל `F_GETFL`/`F_SETFL`, `O_APPEND` אטומי בקריאת מערכת יחידה בשתי הפלטפורמות, `O_NOFOLLOW`, והפרדת symlinks מול Windows junctions); `tools/fd_test.c` עובר 84/84 ב־Linux ASan ו־90/90 ב־Windows, ו־`test/g1_gate_exe.c` מדפיס `G1 GATE PASSED` ב־Windows CI (PR #17).
- **VMA על extents:** `src/vma.c` (`mmap`/`munmap`/`mprotect`/`madvise`, `afw_vma_adopt`, שריון 64GB בפחות מ־1MB מטא־דאטה — PR #10, PR #14).
- **מדידת `%gs:` ב־ART ל־G3 כבר נמדדת ב־CI [נמדד]:** [`docs/design/G3-GS.md`](G3-GS.md) ושלב `Measure: %gs: in ART - libart.so and the boot image` ב־`bionic-probe` מדדו 1,544 אתרי `%gs:` ב־`libart.so` ו־~250K ב־boot `.oat`. פריסת ה־TEB slots שתיבנה ב־G2 תשמור תאימות לתא ה־TEB הנוסף (`art::Thread*`) שמתוכנן ל־G3a.

### תנאי קדם חיצוניים לפני סגירת G2 (`COLLABORATION.md` שורה 77) [נמדד]

שני פריטים אלה אינם חוסמים את ביקורת התכנון, אך נדרשים לפני סגירת שער G2:
1. **9 אתרי `UNPROVEN`** (3 ב־`linker64`, 6 ב־`libc++`): פתוחים ב־PR #5 ו־PR #7. כפופים לכלל 6 — כל שינוי בשער דורש הסכמה מפורשת בכתב של כל הבודקים. עבור 6 האתרים ב־`libc++_shared.so`, אם יתאמת שמקורם בטבלאות `switch` של 1–2 בתים (`movzx`), **נעדיף להרחיב את המנתח לתמוך ב־`movzx`** במקום allowlist נעול־hash.
2. **אורקל `libc_shared_globals` (`tools/oracle/` + `src/bionic_abi/shared_globals.h`):** נדרש לפני שממלאים שדות נוספים ב־`libc_shared_globals` מעבר למה שכבר נמדד ב־`tools/sg_uses.py` (ובפרט `static_tls_layout` ו־`tls_modules` עבור `pthread_create` ו־DTV דינמי).

---

## 2. הגדרת שער G2 (יעד מדיד ושמירה על כלל 6)

שער G2 כולל את **כל** דרישות G2 המקוריות — ללא השמטה שקטה (כלל 6):

1. **ריבוי חוטים (`pthreads` + `futex`):** יצירת חוטים רגילים ו־`detached` ב־`pthread_create`, בידוד `errno` ו־`thread_local`, סנכרון מלא ב־`pthread_mutex`, `pthread_cond` (כולל `broadcast` / `FUTEX_CMP_REQUEUE`), `rwlock`, גישות `fs:` תקינות מחוטים משניים, ואיסוף מלא ב־`pthread_join` / ניקוי בטוח ב־`_exit_with_stack_teardown` בלי דליפת TLS/מחסניות.
2. **זיכרון מקבילי (`MADV_DONTNEED`):** עומס רב־חוטי של `madvise(MADV_DONTNEED)` מול קריאות/כתיבות/אטומיים על `MAP_PRIVATE | MAP_ANONYMOUS` — אפס קריסות, אפס deadlocks ב־VEH, איפוס מיידי לאפסים; ובדיקה שלילית שכתיבה ל־`PROT_READ` או כשל `MEM_COMMIT` ממשיכים לקריסה מדווחת ולא נתקעים בלולאת retry.
3. **מיפוי קבצים לקריאה בלבד (`src/filemap.*`):** `mmap(NULL, len, PROT_READ, MAP_PRIVATE | MAP_SHARED, fd, offset)` עבור `/dev/__properties__` וקבצי נכסים — כולל היסטים מיושרים ל־4KB, קובץ בגודל 0, דף סופי חלקי מאופס, `munmap` מלא/חלקי, ודחיית `PROT_EXEC`.
4. **טעינה דינמית (`dlopen` + TLS דינמי) וחריגות C++:**
   - `dlopen` של ספריית `.so` חדשה בזמן ריצה, כולל ספרייה עם `PT_TLS` (DTV / TLS דינמי).
   - חריגת C++ (`throw`/`catch`) חוצת־ספריות עם `libc++_shared.so` + `dl_iterate_phdr` תחת ריבוי חוטים.
   - חריגת C++ שחוצה מסגרת callback של Windows (`RtlInstallFunctionTableCallback` / תאימות unwind מול `.eh_frame`).

> **הערה לכלל 6 (הצעת פיצול אופציונלית ל־`G2a`/`G2b`):** אם הבודקים יעדיפו לנעול מוקדם את אבני הבניין היציבות (`G2a`: `pthreads` + `futex` + `MADV_DONTNEED` + `filemap` + `throw`/`catch` בין ספריות ELF) ולהפריד את `dlopen` עם `PT_TLS` דינמי + חריגה חוצת־callback של Windows לשלב `G2b`, **פיצול כזה ייעשה רק באישור מפורש בכתב של כל הבודקים** (כלל 6). בהיעדר הסכמה כזו, כל 4 הסעיפים נשארים חלק משער G2 המאוחד.

---

## 3. זרם עבודה 1 — חוטים (`pthreads`: `SYS_clone` מול `pthread_create`) ו־`SYS_futex` [לבודק 3 ובודק 2]

### 3.1 שלב 0 — ניסוי מדיד לפני מימוש (כלל 7א)

לפני כתיבת קוד ייצור, נריץ ניסוי מדיד ב־Windows CI (`test/pthread_probe.c` — שלב אינפורמטיבי) שמפעיל `pthread_create` (רגיל ו־`detached`), `pthread_join`, `pthread_mutex`, ו־`pthread_cond_broadcast` מול `libc.so` האמיתית ומתעד:
1. אילו קריאות מערכת Bionic מבצעת בפועל (`mmap`, `mprotect`, `clone` (`56`), `futex` (`202` — אילו opcodes בדיוק!), `set_tid_address` (`218`), `rt_sigprocmask` (`14`), `set_robust_list` (`273`), `prctl` (`157`), ו־`munmap`+`exit` בחוט `detached`).
2. דגלי `clone` ופריסת `newtls` ש־Bionic בונה בפועל.
3. **ניסוי Windows קריטי (`NT_TIB` + VEH + SEH על מחסנית `mmap`):** חוט Windows מ־`CreateThread` שמעביר `RSP` למחסנית שהוקצתה ב־`mmap` גורם במכוון ל־`fs:` read fault ול־access violation, ואז חוזר למחסנית Windows המקורית וקורא `ExitThread()`. בודקים במדידה ישירה אם `RtlDispatchException` / VEH / `FLS` / `DLL_THREAD_DETACH` עובדים תקין עם עדכון `NT_TIB` (`StackBase`, `StackLimit`, `DeallocationStack`).

### 3.2 השוואת שתי אפשרויות ותנאי Fallback מפורש

| היבט | אפשרות א': מימוש `SYS_clone` (`56`) מעל `CreateThread` | אפשרות ב': יירוט סמל `pthread_create` (הצעת בודק 1) |
|---|---|---|
| תאימות ל־Bionic | מלאה — Bionic בונה `pthread_internal_t`, `bionic_tls`, guard page, `pthread_key`, ו־`pthread_join` בעצמה | חלקית — דורש חיקוי או השלמה של `pthread_internal_t` (עבור `errno`, `pthread_self`, `pthread_key`, `libc++`, `ART`) |
| שחרור TLS | **אסור** לרשום `FLS` release על `newtls` שהוקצה ע"י Bionic (מונע double-free על `mmap` של Bionic) | הטוען מנהל את הבלוק |
| מחסנית וחוטים מנותקים | דורש טיפול ייעודי ב־`_exit_with_stack_teardown` ובשחזור `NT_TIB` לפני `ExitThread` | החוט רץ תמיד על מחסנית Windows המקורית (ללא החלפת `NT_TIB`) |

- **המלצה ראשונית [השערה]:** **אפשרות א' (`SYS_clone`)**.
- **תנאי Fallback ברור (שער החלטה משלב 0):** אם ניסוי שלב 0 מראה שהחלפת `RSP`/`NT_TIB` למחסנית של Bionic שוברת SEH / VEH / unwind או `DLL_THREAD_DETACH` על Windows (או דורשת הסתמכות על פרט פנימי לא מתועד של Windows), **עוברים לאפשרות ב' (יירוט `pthread_create`)** ל־G2, בכפוף לאישור בודק 3.

### 3.3 מוקש `_exit_with_stack_teardown` (חוטים מנותקים `PTHREAD_CREATE_DETACHED`)

בחוט מנותק (`detached`), Bionic מסיימת את החוט דרך פונקציית אסמבלי `_exit_with_stack_teardown(stack_base, stack_size)`:
1. קוראת `SYS_munmap(stack_base, stack_size)` — **המשחרר את המחסנית שעליה החוט רץ כרגע**,
2. ומיד מבצעת `SYS_exit(0)` **בלי לגעת במחסנית** (לא `call`, לא `ret`, לא `push`).

ב־Windows יש כאן **שני מוקשים קריטיים** שחייבים להיפתר בתכנון:
1. **`afw_syscall_entry` רץ על המחסנית הנוכחית (`RSP`)!** כרגע [`afw_syscall_entry`](../../src/syscall.c) שומר רגיסטרים וכתובת חזרה (`rbp+16`) על המחסנית של הקורא. אם `SYS_munmap` משחרר מיד את המחסנית המכילה את `RSP`, פקודת ה־`ret` בסוף `afw_syscall_entry` תתרסק מיד!
   - **פתרון מתוכנן:** כל חוט שנוצר ב־`SYS_clone` שומר ב־`_Thread_local` את מצב המחסנית המקורית של Windows (`host_rsp`, `host_stack_base`, `host_stack_limit`, `host_dealloc_stack`).
   - אם `SYS_munmap(addr, len)` מזהה שהטווח `[addr, addr + len)` **מכיל את `RSP` הנוכחי של החוט הקורא**:
     - מאמת את הטווח ב־VMA, אך **דוחה את ה־`VirtualFree` עצמו** לשדה per-thread `t_pending_stack_unmap = {addr, len}` ומחזיר `0` מ־`SYS_munmap` — כך ש־`afw_syscall_entry` חוזר בבטחה להוראה הבאה (`SYS_exit(0)`)!
2. **`ExitThread()` מריץ `FLS` callbacks ו־`DLL_THREAD_DETACH` על המחסנית הנוכחית:**
   - בכניסה ל־`SYS_exit(code)` (`60`), לפני `ExitThread()`:
     1. מאפס אטומית `*t_clear_child_tid = 0` ומעיר `WakeByAddressAll(t_clear_child_tid)` (עבור `pthread_join`).
     2. **עובר בחזרה למחסנית המקורית של Windows** (`RSP = host_rsp`) **ומשחזר את `NT_TIB.StackBase`, `StackLimit`, `DeallocationStack` המקוריים**.
     3. כעת, כשהחוט רץ בבטחה על מחסנית Windows המקורית, מבצע את `afw_munmap(t_pending_stack_unmap.addr, t_pending_stack_unmap.len)` אם קיים.
     4. קורא `ExitThread((DWORD)code)` — כל ה־`FLS` callbacks ו־`DLL_THREAD_DETACH` רצים על מחסנית Windows חוקית!

### 3.4 מחזור חיים של `SYS_clone` (`56`) ו־`SYS_set_tid_address` (`218`)

- **`SYS_clone`:** מאשר רק דגלי thread נתמכים (`CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FILES | CLONE_FS`, ובנוסף דגלים אופציונליים `CLONE_SETTLS`, `CLONE_PARENT_SETTID`, `CLONE_CHILD_SETTID`, `CLONE_CHILD_CLEARTID`); כל שילוב אחר (כולל `fork`) נדחה ב־`-ENOSYS` / `-EINVAL`.
- **סנכרון התחלה (מניעת race):** ההורה ממתין על אירוע התחלה עד שהילד: (א) קורא `GetCurrentThreadId()`, (ב) כותב `parent_tidptr`/`child_tidptr`, (ג) רושם `t_clear_child_tid`, ו־(ד) מאתחל `TlsSetValue(g_slot[0], newtls)` ו־`g_slot[5] = stack_guard` (בלי רישום `FLS` release על `newtls` של Bionic). רק אז ההורה חוזר עם `child_tid`.
- **`SYS_set_tid_address` (`218`):** שומר `t_clear_child_tid = tidptr` ומחזיר `sys_gettid()`.

### 3.5 תכנון מפורש ל־`SYS_futex` (`202`)

**מה כבר קיים ונמדד ב־[`src/syscall.c`](../../src/syscall.c) (שורות 185–256) [נמדד]:**
- `FUTEX_WAIT` (`0`) ו־`FUTEX_WAKE` (`1`) (עם ובלי `FUTEX_PRIVATE_FLAG`) מעל `WaitOnAddress` / `WakeByAddressSingle` / `WakeByAddressAll`, עם שעון `CLOCK_MONOTONIC` יחסי.
- `FUTEX_WAIT_BITSET` (`9`) ו־`FUTEX_WAKE_BITSET` (`10`) עבור `val3 == 0xffffffffu` (`FUTEX_BITSET_MATCH_ANY`), עם `CLOCK_MONOTONIC` או `CLOCK_REALTIME` (deadline אבסולוטי, כולל לולאת הגנה מפני התעוררות מוקדמת של טיימר Windows שנמדדה ב־CI).
- כל opcode אחר (או bitset חלקי) מחזיר `-ENOSYS`.

**מה נדרש להוסיף ב־G2 עבור `pthreads` (`pthread_mutex`, `pthread_cond`, `pthread_rwlock`, `pthread_once`, `pthread_join`):**
1. **`FUTEX_REQUEUE` (`3`) ו־`FUTEX_CMP_REQUEUE` (`4`)** — נדרש ל־`pthread_cond_broadcast` ב־Bionic [השערה, יאומת בשלב 0]:
   - `FUTEX_CMP_REQUEUE(uaddr, op, val=wake_n, val2=requeue_n, uaddr2, val3=expected)`:
     - מאמת יישור 4 בתים ל־`uaddr` ו־`uaddr2`; ב־`CMP_REQUEUE` בודק `*uaddr == val3` (אחרת `-EAGAIN`).
   - **בחירת מימוש (שאלה פתוחה לבודקים 2 ו־3):**
     - **חלופה 1 (מעל `WaitOnAddress` הקיים):** ב־`REQUEUE`/`CMP_REQUEUE`, אחרי בדיקת `*uaddr == val3`, מעיר `WakeByAddressAll(uaddr)` (כך שכל ה־waiters מתעוררים ובודקים מחדש את המנעול `uaddr2` בתוך Bionic). יתרון: אפס מבני נתונים חדשים ושומר על מהירות `WaitOnAddress` ב־`WAIT`/`WAKE`. חיסרון: thundering herd תחת `broadcast` כבד, ואינו תומך ב־bitset חלקי או `FUTEX_WAKE_OP`.
     - **חלופה 2 (טבלת waiters פנימית נעולה ב־`SRWLOCK` + `CONDITION_VARIABLE` / `WaitOnAddress` לכל waiter):** מאפשרת `REQUEUE`/`CMP_REQUEUE` אמיתי (העברת צמתי waiter מדלי `uaddr` לדלי `uaddr2` בלי להעיר אותם!), bitset חלקי מדויק, והחזרת ספירת woken מדויקת.
   - **המלצה ראשונית:** לבדוק בשלב 0 אילו opcodes בדיוק Bionic קוראת ב־`mutex`/`cond`/`rwlock`/`once`/`join`; אם רק `WAIT`/`WAKE`/`WAIT_BITSET(ANY)`/`CMP_REQUEUE` — להכריע בין חלופה 1 ל־2 לפי חוות דעת בודקים 2 ו־3.
2. **שעונים ו־timeouts:** לשמור על תמיכה ב־`CLOCK_MONOTONIC` (יחסי ב־`FUTEX_WAIT`, אבסולוטי ב־`FUTEX_WAIT_BITSET`) ו־`CLOCK_REALTIME` (`FUTEX_CLOCK_REALTIME`), ולוודא ש־`FUTEX_WAIT` עם `FUTEX_CLOCK_REALTIME` (אם Bionic שולחת — ב־Linux זה `-ENOSYS` ב־`WAIT` ומותר רק ב־`WAIT_BITSET`) מתנהג בדיוק כמו ליבת Linux.

---

## 4. זרם עבודה 2 — `MADV_DONTNEED` מקבילי ובטוח לחוטים (`src/vma.c`) [לבודק 3 ובודק 2]

### 4.1 הבעיה הקיימת [נמדד]

ב־[`src/vma.c`](../../src/vma.c) (`do_dontneed`, שורות 614–643), ביצוע `os_decommit` ואחריו `os_commit` משאיר חלון קצר שבו העמוד הוא `MEM_RESERVE`. בחוט יחיד (G1) זה תקין; בריבוי חוטים (G2, ובפרט Scudo), חוט אחר שניגש לאותו עמוד בחלון הזה חוטף `EXCEPTION_ACCESS_VIOLATION`.

`MEM_RESET` / `DiscardVirtualMemory` אינם מבטיחים איפוס לאפסים (מפרים חוזה Linux של `MADV_DONTNEED`), ו־`memset(0)` אינו עובד על `PROT_READ` ואינו משחרר commit.

### 4.2 התכנון המוצע — Lock-Free Active Window + VEH Retry + שלושת מקרי הקצה

**כלל ברזל (לקח PR #11 ו־`G1-TLS.md`):** ה־VEH handler **לעולם לא נועל** את `g_lock` (`SRWLOCK`) של `src/vma.c`, ולא קורא ל־`malloc` או ל־Loader Lock.

1. **החזקת `g_lock` לכל אורך חלון ה־`decommit -> recommit`:**
   - `afw_madvise` כבר מחזיקה את `g_lock` (`AcquireSRWLockExclusive`) סביב `each(..., do_dontneed, ...)`.
   - **שומרים על החזקת `g_lock` לכל אורך ה־`decommit -> recommit`!** כך חוט אחר שקורא ל־`mprotect(PROT_NONE)` או `munmap` על אותו אזור נחסם ב־`g_lock` עד שהחלון נסגר, ולעולם לא מבלבל בין דף שפורק זמנית לבין `PROT_NONE` לוגי ולא משאיר הרשאות שגויות.
2. **מצב גלובלי סטטי ב־`src/vma.c`** (נכתב אך ורק תחת `g_lock`, כך שיש לכל היותר כותב אחד):
   ```c
   static volatile uint64_t g_dn_seq;     /* זוגי = לא פעיל, אי-זוגי = בתוך decommit->commit */
   static volatile uint64_t g_dn_start;
   static volatile uint64_t g_dn_end;
   ```
3. **טיפול דטרמיניסטי בכשל `MEM_COMMIT` (מגבלת commit / OOM):**
   - לפני `os_decommit(ext.start, len)` (רק כש־`prot != 0`): מעדכנים `g_dn_start`, `g_dn_end`, ומקדמים `g_dn_seq` לאי־זוגי (`2k + 1`, release).
   - מבצעים `os_decommit` ואז `os_commit(ext.start, len, prot)`.
   - **בכל מסלול יציאה — כולל כשל `os_commit` (OOM)!** — מאפסים/מקדמים את `g_dn_seq` מיד לזוגי (`2k + 2`, release) **לפני** החזרת `-ENOMEM` ולפני שחרור `g_lock`. כך חוט שממתין ב־VEH retry לעולם אינו נתקע בלולאה אינסופית.
4. **צד ה־VEH (`vma_dontneed_veh`, בעדיפות אחרי `fs_handler` ולפני `crash`):**
   - מסנן מיד: רק `EXCEPTION_ACCESS_VIOLATION` עם `NumberParameters >= 2` ו־`fault_addr >= 0x10000`.
   - קורא snapshot עם acquire barriers `(s1, lo, hi, s2)`:
     - אם `s1` אי־זוגי ו־(`fault_addr` ב־`[lo, hi)` או `s2 != s1`): ממתין ב־`YieldProcessor()`/`SwitchToThread()` עד ש־`g_dn_seq != s1`, רושם `(t_retry_addr = fault_addr, t_retry_seq = s1)`, ומחזיר `EXCEPTION_CONTINUE_EXECUTION` (**לכל היותר פעם אחת לכל `(fault_addr, s1)`**).
     - אם `s1` זוגי (`> 0`) ו־`s1 == s2` ו־`fault_addr` ב־`[lo, hi)` ו־`(t_retry_addr != fault_addr || t_retry_seq != s1)`: מכסה את ה־race שבו `os_commit` הסתיים מיקרו־שנייה לפני כניסת ה־VEH — רושם `(t_retry_addr, t_retry_seq)` ומחזיר `EXCEPTION_CONTINUE_EXECUTION` **פעם אחת בלבד**.
     - בכל פגיעה חוזרת באותו `(fault_addr, s1)` (כגון כתיבה ל־`PROT_READ` או כישלון `os_commit` ב־OOM): מחזיר `EXCEPTION_CONTINUE_SEARCH` -> דוח קריסה תקין.
5. **הגבלה קשיחה למיפויים פרטיים אנונימיים בלבד (`MAP_PRIVATE | MAP_ANONYMOUS`) + מגבלת קרנל מתועדת:**
   - `do_dontneed` **לעולם לא יבצע `decommit + recommit`** על מיפוי קובץ (`VMA_FILEMAP`) או `MAP_SHARED` (שיאפס נתוני קובץ/נתונים משותפים!): על `VMA_FILEMAP` לקריאה בלבד, `MADV_DONTNEED` הוא no-op בטוח (מחזיר `0` בלי לשנות נתונים).
   - **מגבלה ידועה ומתועדת:** אם חוט א' מעביר באפר ל־syscall של Windows (כגון `ReadFile`/`WriteFile`) בזמן שחוט ב' מריץ `MADV_DONTNEED` על אותו דף, גישת הקרנל של Windows אינה עוברת דרך user-mode VEH ועלולה להחזיר `ERROR_NOACCESS` (`EFAULT`). זהו מקרה קצה חריג (באפר I/O פעיל שנזרק במקביל), אך הוא מתועד במפורש.
6. **בדיקות חובה (`tools/vma_test.c` — כלל 4):**
   - **בדיקת עומס רב־חוטית (חובה):** חוט א' מריץ אלפי `MADV_DONTNEED` על טווח `PROT_READ|PROT_WRITE` במקביל לחוטים ב'/ג' שמבצעים קריאות, כתיבות ופעולות אטומיות (`InterlockedIncrement` / `__atomic_fetch_add`) על אותו טווח — 0 קריסות, וערכים תקינים בלבד.
   - **שלילית (ללא hang):** כתיבה לדף `PROT_READ` תוך כדי `MADV_DONTNEED` אינה נתקעת ב־retry אינסופי ומגיעה למטפל השגיאה.
   - **שלילית OOM:** כשל מוזרק ב־`os_commit` (`afw_vma_test_fail_os`) סוגר את חלון ה־`g_dn_seq` לזוגי ומאפשר דיווח fault נקי.

---

## 5. זרם עבודה 3 — מיפוי קבצים לקריאה בלבד (`src/filemap.*`) [לבודקים 2 ו־3]

לפי [`docs/COLLABORATION.md`](../COLLABORATION.md) שורה 16 ו־77: מיפוי קריאה בלבד עבור `/dev/__properties__` וקבצי נכסים, באחריות המחבר הראשי.

### 5.1 דרישות Linux ABI ו־4 אילוצי Windows קריטיים

1. **`PROT_READ` גם ל־`MAP_SHARED` וגם ל־`MAP_PRIVATE`:**
   - ב־Bionic, מערכת ה־properties (`/dev/__properties__`) ממפה קבצים לרוב עם **`PROT_READ | MAP_SHARED`**.
   - ב־Windows, שני המצבים (לקריאה בלבד!) מתמפים זהה ל־`CreateFileMappingW(PAGE_READONLY)` + `MapViewOfFile(FILE_MAP_READ)` בעלות קוד אפסית — ולכן G2 יתמוך ב־`PROT_READ` (ו־`PROT_NONE`) הן עם `MAP_PRIVATE` והן עם `MAP_SHARED`.
   - `PROT_WRITE` על קובץ -> `-ENOSYS` (מחוץ לטווח G2 read-only); **`PROT_EXEC` על קובץ -> נדחה במפורש (`-EACCES` / `-ENOSYS`)** כדי ש־`mmap` לא יעקוף את שער ה־patching (כלל 6).
   - `fd` חייב להיות קובץ רגיל פתוח ב־`src/fd.c` שאינו `O_WRONLY` (`-EACCES`), אינו `FD_STDIO`, ואינו תיקייה (`-ENODEV`).
2. **יישור `offset` ל־64KB מול 4KB:**
   - Linux מתיר `offset >= 0` בכפולות של **4KB** (ובדיקת גלישה ל־`offset + len` — כלל 8).
   - `MapViewOfFile` ב־Windows דורש ש־`dwFileOffsetLow` יהיה כפולה של **64KB** (`dwAllocationGranularity`).
   - **תכנון מפורש:**
     - **מסלול ראשי (`MapViewOfFile`, אפס עותק):** ממפים מ־`aligned_off = offset & ~0xFFFFULL` ומחזירים למזמין `view_base + (offset - aligned_off)` (כאשר `delta = offset - aligned_off` הוא כפולה של `4KB`, כך שהכתובת המוחזרת מיושרת ל־4KB כנדרש ב־Linux!).
     - **זנב ודף סופי חלקי:** אם `offset < file_size` ו־`offset + len > file_size`: ממפים `min(aligned_len, file_size - aligned_off)`. ב־Windows, `MapViewOfFile` מאפס אוטומטית את הזנב מה־EOF עד סוף העמוד האחרון (4KB) — **נבדוק זאת במדידה ב־Windows CI!** אם המזמין ביקש עמודים שלמים *מעבר* ל־`roundup(file_size, 4096)` (ב־Linux גישה אליהם נותנת `SIGBUS`), נתעד ונטפל במפורש (דחייה ב־`-ENOSYS` או fallback ב־`MAP_PRIVATE`).
     - **חלופת Fallback עבור `MAP_PRIVATE` בלבד** (אם בודקים 2/3 יעדיפו אחידות מוחלטת עם `munmap` חלקי): הקצאת `VirtualAlloc` + `afw_os_pread` + `VirtualProtect(PAGE_READONLY)` עבור קבצים קטנים או היסטים שאינם כפולת 64KB (לא עבור `MAP_SHARED`, שחייב לראות עדכונים).
3. **קבצים בגודל 0 והפרדת `VMA_ANON` מ־`VMA_FILEMAP` ב־`src/vma.c`:**
   - `CreateFileMappingW` נכשל על קובץ של **0 בתים** (`ERROR_FILE_INVALID`). ב־Linux, `mmap` של קובץ בגודל 0 מצליח (וחוטף `SIGBUS` בכל גישה): ב־`filemap` נטפל במפורש בקובץ בגודל 0 (הזמנת טווח `PROT_NONE` ב־VMA או מיפוי שמדווח fault בגישה, בלי ליפול על `ERROR_FILE_INVALID`).
   - `UnmapViewOfFile` **אינו תומך בשחרור חלקי** (`munmap` חלקי). לכן ב־`src/vma.c` נפריד במפורש ב־`winalloc` בין `kind = VMA_ANON` (`VirtualAlloc`/`VirtualFree`) לבין `kind = VMA_FILEMAP` (`MapViewOfFile`/`UnmapViewOfFile`, שומר `view_base` המקורי לפני ה־`delta`!). ב־`munmap` על `VMA_FILEMAP`:
     - כל עוד נותרו עמודים ממופים ב־`winalloc`, מסמנים את הטווח כלא־ממופה במטא־דאטה (ואופציונלית `PAGE_NOACCESS` על עמודים ששוחררו);
     - רק כש־`mapped_bytes == 0` קוראים ל־`UnmapViewOfFile(view_base)` ומשחררים את הרשומה — בדיוק כמו שאנחנו כבר עושים ל־`MEM_RELEASE` ב־`VMA_ANON`!
     - `MADV_DONTNEED` על `VMA_FILEMAP` הוא no-op (`return 0`), לעולם לא `MEM_DECOMMIT`.
4. **מחיקה / שינוי שם של קובץ ממופה (`FILE_SHARE_DELETE`):**
   - [`afw_os_open`](../../src/platform.c) (שורה 190) כבר פותח קבצים ב־Windows עם `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` **[נמדד]**.
   - **כלל 8:** כל קריאות Win32 (`CreateFileMappingW`, `MapViewOfFile`, `UnmapViewOfFile`) יישארו אך ורק ב־`src/platform.c`; `src/filemap.c` יהיה C11 טהור.
   - נתעד ונוסיף בדיקה של `unlink` על קובץ בזמן שהוא ממופה (מוודא ש־`unlink` אינו מחזיר `EACCES`, תוך תיעוד סמנטיקת delete-pending של Windows עד לסגירת ה־view).

---

## 6. זרם עבודה 4 — `dlopen` דינמי וחריגות C++ (`libc++_shared.so` + `dl_iterate_phdr`) [לבודק 1, בודק 2 ובודק 3]

### 6.1 מצב קיים [נמדד]

- [`afw_l_dl_iterate_phdr`](../../src/loader_api.c) (שורות 206–224) כבר ממומשת ומחזירה `dlpi_addr`, `dlpi_name`, `dlpi_phdr`, `dlpi_phnum`, `dlpi_adds`, `dlpi_tls_modid`, `dlpi_tls_data`.
- `C++ exceptions: every landing pad found, nothing unproven (static)` (`test/cxx_exception_test.cpp`) עובר ב־CI; `Explore: load the NDK's real libc++_shared.so` רץ אינפורמטיבית.

### 6.2 רכיבי העבודה ל־G2

1. **נעילת רישום הספריות (`dlopen` / `dl_iterate_phdr` / `afw_lib_at`):**
   - מנעול ייעודי (`SRWLOCK` / `pthread_rwlock`, נפרד לחלוטין מ־VMA lock ו־VEH) שמגן על `g_libs[]` כך שחוט שזורק חריגה (`dl_iterate_phdr`) במקביל ל־`dlopen` בחוט אחר לעולם לא קורא רשימה במצב ביניים.
2. **`__loader_add_thread_local_dtor` / `__loader_remove_thread_local_dtor`:**
   - נדרשים עבור destructors של משתני C++ `thread_local` דרך `__cxa_thread_atexit` ב־`libc++_shared.so` (רשומים ב־[`G1-LIBC-INIT.md`](G1-LIBC-INIT.md) שורה 183).
3. **טעינה דינמית (`dlopen`) של ספרייה עם `PT_TLS` (DTV / TLS דינמי):**
   - ב־G1 (`G1-TLS.md` שורה 43), `afw_tls_static_register` דוחה במפורש `dlopen` של `.so` עם `PT_TLS` אחרי `g_finished`.
   - ב־G2 (לאחר האורקל של בודק 2), נרחיב את `afw_tls_get_addr` לטבלת DTV per-thread (הקצאה עצלה של מודול TLS דינמי לפי `generation`, ושחרור כל בלוקי ה־DTV ביציאת החוט דרך ה־FLS / `SYS_exit` teardown), או נמלא את `libc_shared_globals->tls_modules` ונעביר ל־Bionic — לפי החלטת בודקים 2 ו־3.
4. **חריגות C++ חוצות־ספריות וחריגה חוצת־callback של Windows:**
   - **בין ספריות ELF:** קידום `test/cxx_exception_test.cpp` (זריקת `std::runtime_error` ותפיסתה חוצת־`.so` עם `libc.so` + `libc++_shared.so` האמיתיות, גם מתוך חוט `pthread_create`) ל־required CI step.
   - **חוצה מסגרת callback של Windows:** כאשר קוד Android קורא לפונקציית host ב־Windows (או trampoline של הטוען) שקוראת בחזרה ל־callback של Android שזורק חריגת C++, `libunwind` של `libc++_shared.so` הולך במעלה המחסנית דרך `.eh_frame` (דרך `dl_iterate_phdr`).
     - אם מסגרת ה־Windows שבאמצע אינה רשומה ב־`.eh_frame`, ה־unwinder של LLVM נעצר עם `std::terminate`!
     - **פתרון לבחינה:** בניסוי מדיד נבדוק שתי אפשרויות: (א) רישום טבלת `.eh_frame` / unwind info סינתטית עבור הגשרים של הטוען שדרכם חוצים callbacks (או הרצת callbacks דרך trampoline אסמבלי עם `.eh_frame` תקני), ו־(ב) רישום `RtlInstallFunctionTableCallback` בצד Windows במידה ו־SEH של Windows נדרש ללכת מעל מסגרות ELF.
5. **6 אתרי ה־`UNPROVEN` ב־`libc++_shared.so`:**
   - סגירתם היא תנאי חוסם לטעינת `libc++_shared.so` בשער G2. כאמור בסעיף 1, נעדיף תמיכה במנתח ב־`movzx` jump tables (אם זה אכן הדפוס בדו"ח בודק 1 ב־PR #5) על פני allowlist נעול־hash, ובכל מקרה כל שינוי בשער כפוף להסכמה בכתב של כל הבודקים (כלל 6).

---

## 7. סדר PR מוצע ל־G2

כל שלב יוגש כ־PR קטן, עצמאי ומכוסה בבדיקה שנכשלת בלעדיו (כלל 4):

| שלב | PR / ענף | תוכן | בודקים עיקריים |
|---|---|---|---|
| **G2-0** | PR #18 (`design/g2-plan`) | אישור מסמך התכנון לפני כתיבת קוד | בודק 3, בודק 2, בודק 1 |
| **G2-1** | `exp/g2-pthread-probe` | ניסוי מדיד בלבד: syscalls של `pthread_create`/`detached`/`cond_broadcast` + בדיקת VEH/`NT_TIB` על מחסנית `mmap` + חזרה ל־Windows stack לפני `ExitThread` | בודק 3, בודק 2 |
| **G2-2** | `g2-filemap` | מימוש `src/filemap.*` + `src/platform.c` + הפרדת `VMA_FILEMAP` ב־`src/vma.c` (`PROT_READ` ל־`MAP_PRIVATE` ו־`MAP_SHARED`, 64KB/4KB, קובץ 0 בתים, `unlink` של קובץ ממופה) + בדיקות Linux ASan & Windows | בודק 2, בודק 3 |
| **G2-3** | `g2-vma-dontneed-mt` | `MADV_DONTNEED` מקבילי (lock-free active window + `g_lock` סביב כל החלון + שחרור חלון ב־OOM + הגבלה ל־`MAP_PRIVATE|MAP_ANONYMOUS` + VEH retry) + בדיקת עומס רב־חוטית ובדיקות שליליות ב־`tools/vma_test.c` | בודק 3, בודק 2 |
| **G2-4** | `g2-pthreads` | מימוש `SYS_clone` (או Fallback ליירוט `pthread_create` לפי תוצאות G2-1) + `_exit_with_stack_teardown` + `SYS_set_tid_address` + הרחבת `SYS_futex` (`CMP_REQUEUE`/`REQUEUE`) + בדיקת `pthreads` מלאה מול `libc.so` האמיתית | בודק 3, בודק 2 |
| **G2-5** | `g2-cxx-dlopen-gate` | נעילת `dl_iterate_phdr`, `thread_local` dtors, `dlopen` עם `PT_TLS` דינמי, חריגות C++ חוצות־ספריות וחוצות־callback, ובדיקת שער G2 מלאה ב־Windows CI (או `G2a`/`G2b` אם יאושר בכתב לפי כלל 6) | בודק 1, בודק 2, בודק 3 |

---

## 8. שאלות ממוקדות לאישור הבודקים

### לבודק 3 (זיכרון, TLS, חוטים, VEH)
1. **`SYS_clone`, `_exit_with_stack_teardown` ו־`NT_TIB`:** האם מנגנון דחיית ה־`munmap` על המחסנית הנוכחית + חזרה ל־Windows stack המקורי ושחזור `NT_TIB` לפני `ExitThread()` (סעיף 3.3), יחד עם תנאי ה־Fallback ליירוט `pthread_create` (סעיף 3.2), סוגר את סיכוני מחזור החיים של החוט?
2. **`SYS_futex` (`REQUEUE`/`CMP_REQUEUE`):** האם להעדיף המרה פשוטה מעל `WaitOnAddress` (חלופה 1 בסעיף 3.5) או טבלת waiters פנימית אמיתית (חלופה 2)?
3. **`MADV_DONTNEED` מקבילי (סעיף 4.2):** האם החזקת `g_lock` לאורך כל החלון + ניקוי `g_dn_seq` גם בכשל `MEM_COMMIT` + הגבלה ל־`MAP_PRIVATE|MAP_ANONYMOUS` + תקרת retry אחת לכל `(fault_addr, seq)` ב־VEH מספקים?
4. **TLS דינמי (`dlopen` עם `PT_TLS`):** האם לבנות DTV עצמאי ב־`afw_tls_get_addr` או למלא `libc_shared_globals->tls_modules` אחרי האורקל של בודק 2?

### לבודק 2 (Linux ABI, `filemap`, `futex`, אורקל `libc_shared_globals`)
5. **`src/filemap.*` (סעיף 5.1):** האם `MapViewOfFile` מיושר ל־64KB (`view + delta`) עבור `PROT_READ` (`MAP_PRIVATE` ו־`MAP_SHARED`), עם טיפול מפורש בקובץ 0 בתים ודף סופי חלקי והפרדת `VMA_FILEMAP` ב־`src/vma.c`, מתאים ל־ABI?
6. **סטטוס אורקל `libc_shared_globals`:** מה מצב `tools/oracle/`, ואיזה חלק מ־`src/bionic_abi/shared_globals.h` כדאי שנתחיל להכין כבר עכשיו כדי שלא יעכב את G2-4 (`pthreads`)?
7. **פיצול `G2a`/`G2b` (כלל 6):** האם לשמור את שער G2 כיחידה אחת הכוללת `dlopen`+`PT_TLS` וחריגה חוצת־callback, או שאתה מעדיף פיצול מפורש `G2a`/`G2b` באישור כתוב?

### לבודק 1 (שערי טעינה, 9 אתרי `UNPROVEN`, חריגות C++)
8. **6 אתרי `UNPROVEN` ב־`libc++_shared.so` (PR #5 / PR #7):** האם אתה מסכים להעדפת תמיכה במנתח ב־`movzx` jump tables על פני allowlist נעול־hash כדי לסגור את ה־6 ב־`libc++` תחת כלל 6?
9. **שער `PROT_EXEC` ב־`filemap`, חריגה חוצת־callback, ופיצול `G2a`/`G2b`:** האם דחיית `PROT_EXEC` על מיפויי קבצים ותכנון חריגות C++ בסעיף 6.2 תואמים את דרישות השער שלך, ומה עמדתך לגבי שער G2 מאוחד מול פיצול `G2a`/`G2b`?
