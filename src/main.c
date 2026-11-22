/*
 * main.c - afw-loader: Milestone M0 of Android-for-Windows.
 *
 *   afw-loader <library.so>          load a library and show what is inside
 *   afw-loader <library.so> -v       also list every linked import
 *
 * If the library is test/hello.c (libhello.so), the M0 tests run as well.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bionic_shim.h"
#include "elf_loader.h"
#include "platform.h"
#include "tls_patch.h"
#include "crash.h"
#include "syscall.h"
#include "tls_static.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <pthread.h>
#endif

#define AFW_VERSION "0.2.0-M1-dev"

/* Signatures of the test library's functions (Android = System V ABI). */
typedef const char *(SYSV *greeting_fn)(void);
typedef int (SYSV *add_fn)(int, int);
typedef int (SYSV *init_value_fn)(void);
typedef void (SYSV *say_fn)(const char *);
typedef int (SYSV *callback_fn)(int);
typedef int (SYSV *apply_fn)(callback_fn, int);
typedef int (SYSV *stack_test_fn)(int);

/* A Windows function that Android code will call back into. */
static SYSV int times_ten(int x) { return x * 10; }

static int g_failed;
static void check(const char *what, int ok) {
    printf("  [%s] %s\n", ok ? " OK " : "FAIL", what);
    if (!ok) g_failed++;
}

static int run_m0_tests(const afw_lib *lib) {
    greeting_fn greeting = (greeting_fn)afw_sym(lib, "afw_greeting");
    add_fn add = (add_fn)afw_sym(lib, "afw_add");
    init_value_fn init_value = (init_value_fn)afw_sym(lib, "afw_init_value");
    say_fn say = (say_fn)afw_sym(lib, "afw_say");
    apply_fn apply = (apply_fn)afw_sym(lib, "afw_apply");
    stack_test_fn stack_test = (stack_test_fn)afw_sym(lib, "afw_stack_test");

    printf("\n=== M0 tests: calling Android code from Windows ===\n");
    check("exported functions found", greeting && add && init_value && say && apply);
    if (g_failed) return 1;

    {
        const char *g = greeting();
        printf("  afw_greeting()   -> \"%s\"\n", g);
        check("string returned from Android code", strcmp(g, "Hello from Android code!") == 0);
    }
    {
        int r = add(2, 3);
        printf("  afw_add(2, 3)    -> %d\n", r);
        check("arguments passed across ABIs", r == 5);
    }
    {
        int r = init_value();
        printf("  afw_init_value() -> %d\n", r);
        check("library constructor ran (init_array)", r == 42);
    }
    {
        int r = apply(times_ten, 7);
        printf("  afw_apply(times_ten, 7) -> %d\n", r);
        check("Android code called back into Windows code", r == 70);
    }
    if (stack_test) {
        int r = stack_test(4);
        printf("  afw_stack_test(4) -> %d  (fs: instructions rewritten: %ld)\n",
               r, afw_tls_patch_count());
        check("stack protector works (fs:[0x28] TLS emulation)", r == 96);
    }
    printf("  afw_say(\"Windows\") prints:\n");
    say("Windows");
    check("Android code used malloc/strcpy/puts/logcat via bionic-win", 1);

    printf("\n%s\n", g_failed ? "M0 FAILED" : "M0 PASSED - Android code runs natively on this machine!");
    return g_failed ? 1 : 0;
}

/* ---- G1: load-time syscall patching ---- */
typedef long (SYSV *getpid_fn)(void);
typedef long (SYSV *write_fn)(int, const void *, size_t);
typedef double (SYSV *xmm_fn)(double);

#if defined(_WIN32)
#include <process.h>
#define host_pid() ((long)_getpid())
#else
#include <unistd.h>
#define host_pid() ((long)getpid())
#endif

static int run_syscall_tests(const afw_lib *lib) {
    getpid_fn gp = (getpid_fn)afw_sym(lib, "afw_sys_getpid");
    write_fn wr = (write_fn)afw_sym(lib, "afw_sys_write");
    getpid_fn unk = (getpid_fn)afw_sym(lib, "afw_sys_unknown");
    xmm_fn xmm = (xmm_fn)afw_sym(lib, "afw_sys_keeps_xmm");
    static const char msg[] = "  (this line was written by a Linux write() syscall)\n";
    long before, r;

    printf("\n=== G1 tests: Linux syscalls rewritten at load time ===\n");
    check("test functions found", gp && wr && unk && xmm);
    if (g_failed) return 1;
    check("every safe 'mov eax; syscall' site was patched (6, one behind a switch table)",
          lib->patch.sys_patched == 6);
    /* "jmp reg" without a switch table is usually a tail call through a
     * function pointer (afw_apply, crtbegin): undecided, but harmless as long
     * as no syscall/fs: look-alike sits in the bytes nothing reaches. */
    check("no unproven syscall/fs: look-alikes left", lib->patch.unproven == 0);
    check("both other sites patched by moving instructions (generic syscall, mov rax)",
          lib->patch.sys_patched_moved == 2);
    check("the site with a branch into its middle was REFUSED", lib->patch.sys_refused_branch == 1);
    {
        const unsigned char *f = (const unsigned char *)afw_sym(lib, "afw_sys_branch_into_site");
        int k, found = 0;
        for (k = 0; f && k < 32; k++)
            if (f[k] == 0x0F && f[k + 1] == 0x0B) found = 1;
        check("...and its syscall became ud2 (a loud trap, not a Windows kernel call)",
              lib->patch.sys_trapped == 1 && found);
    }

    before = afw_syscall_counts[39];
    r = gp();
    printf("  getpid() -> %ld (host pid %ld)\n", r, host_pid());
    check("getpid went through our dispatcher", afw_syscall_counts[39] == before + 1 && r == host_pid());

    r = wr(1, msg, sizeof msg - 1);
    check("write(1, ...) returned the byte count", r == (long)(sizeof msg - 1));

    r = unk();
    printf("  reboot() -> %ld\n", r);
    check("unimplemented syscall returns -ENOSYS", r == -38);

    check("xmm registers survive a syscall", xmm(3.25) == 3.25);
    {
        typedef int (SYSV *flags_fn)(void);
        flags_fn fl = (flags_fn)afw_sym(lib, "afw_sys_keeps_flags");
        if (fl) check("RFLAGS (CF, ZF) survive a syscall, as with sysret", fl() == 3);
    }

    {
        typedef long (SYSV *gen_fn)(long, long, long, long, long, long, long);
        gen_fn gen = (gen_fn)afw_sym(lib, "afw_generic_syscall");
        getpid_fn rax = (getpid_fn)afw_sym(lib, "afw_sys_getpid_rax");
        check("form B functions found", gen && rax);
        if (gen && rax) {
            before = afw_syscall_counts[39];
            r = gen(39, 0, 0, 0, 0, 0, 0);
            printf("  generic syscall(39) -> %ld\n", r);
            check("generic syscall(): number passed at run time reached the dispatcher",
                  r == host_pid() && afw_syscall_counts[39] == before + 1);
            r = gen(1, 1, (long)(uintptr_t)msg, (long)(sizeof msg - 1), 0, 0, 0);
            check("generic syscall(): 3 arguments shifted correctly (write)", r == (long)(sizeof msg - 1));
            r = rax();
            check("'mov rax, 39; syscall' (the __restore_rt form) works", r == host_pid());
        }
        if (gen && afw_sym(lib, "afw_sys_bss_page")) {
            /* libc's WriteProtected<libc_globals> (issue #12): mprotect on the
             * library's own .bss, through a patched site, as libc does it */
            volatile char *pg = (volatile char *)afw_sym(lib, "afw_sys_bss_page");
            long a = (long)(uintptr_t)pg;
            long mr;
            pg[0] = 5;
            mr = gen(10, a, 4096, 1, 0, 0, 0);
            printf("  mprotect(.bss page at image+0x%llx, PROT_READ) -> %ld\n",
                   (unsigned long long)((uintptr_t)pg - (uintptr_t)lib->base), mr);
            check("mprotect(PROT_READ) on the library's own .bss succeeds", mr == 0);
            check("... the contents are kept", pg[0] == 5);
            check("mprotect(PROT_READ|PROT_WRITE) back succeeds, and the page is writable",
                  gen(10, a, 4096, 3, 0, 0, 0) == 0 && (pg[0] = 6, pg[0] == 6));
            check("mprotect on the stub area after the image -> -ENOMEM (not Linux memory)",
                  gen(10, (long)(uintptr_t)lib->stub_area, 4096, 7, 0, 0, 0) == -12);
        }
    }

    {
        static const unsigned char want[16] = {0xb8, 0x27, 0, 0, 0, 0x0f, 0x05,
                                               0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0};
        const unsigned char *b = (const unsigned char *)afw_sym(lib, "afw_fake_site_bytes");
        getpid_fn fake = (getpid_fn)afw_sym(lib, "afw_fake_site");
        check("never-executed syscall/fs: look-alikes left byte for byte", b && memcmp(b, want, 16) == 0);
        check("...and counted by the audit as unreachable", lib->patch.unreachable_ignored >= 2);
        check("the function around them still works", fake && fake() == 7);
    }
    {
        typedef long (SYSV *sw_fn)(int);
        sw_fn sw = (sw_fn)afw_sym(lib, "afw_switch_syscall");
        long v;
        before = afw_syscall_counts[39];
        v = sw ? sw(4) : 0;
        check("syscall reached only through a switch table was patched and works",
              sw && v == host_pid() && afw_syscall_counts[39] == before + 1 && sw(6) == 16);
    }

    {   /* writev: libc's abort message goes through it (measured on Windows, PR #11) */
        static const char p1[] = "  writev: ", p2[] = "two parts\n";
        uint64_t iov[6] = {(uint64_t)(uintptr_t)p1, sizeof p1 - 1, 0, 0, (uint64_t)(uintptr_t)p2, sizeof p2 - 1};
        int64_t a[6] = {1, (int64_t)(uintptr_t)iov, 3, 0, 0, 0};
        int64_t bad[6] = {1, (int64_t)(uintptr_t)iov, 1025, 0, 0, 0};
        int64_t badfd[6] = {7, (int64_t)(uintptr_t)iov, 3, 0, 0, 0};
        fflush(stdout);
        check("writev writes every iovec (an empty one included) and returns the total",
              afw_syscall_dispatch(20, a) == (int64_t)(sizeof p1 - 1 + sizeof p2 - 1));
        check("writev: more than IOV_MAX iovecs -> -EINVAL", afw_syscall_dispatch(20, bad) == -22);
        check("writev: unknown fd -> -EBADF", afw_syscall_dispatch(20, badfd) == -9)   /* EBADF */;
    }

    printf("\n");
    afw_syscall_report();
    printf("\n%s\n", g_failed ? "G1 SYSCALL TESTS FAILED" : "G1 SYSCALL TESTS PASSED");
    return g_failed ? 1 : 0;
}


/* ---- G1-TLS (docs/design/G1-TLS.md, section 5) ---------------------- */
typedef int (SYSV *tls_int_fn)(void);
typedef long (SYSV *tls_long_fn)(void);
typedef uintptr_t (SYSV *tls_uptr_fn)(void);
typedef int *(SYSV *tls_ptr_fn)(void);
typedef SYSV void (*tls_wait_fn)(void);
typedef int (SYSV *tls_worker_fn)(int, tls_wait_fn, int);

/* Barrier state: every read and write is atomic (reviewer 2, PR #6 A3). */
static long g_arrived, g_barrier_open;
#if defined(_WIN32)
static long ld(long *p) { return InterlockedCompareExchange(p, 0, 0); }
static void st(long *p, long v) { InterlockedExchange(p, v); }
static void inc(long *p) { InterlockedIncrement(p); }
#else
static long ld(long *p) { return __atomic_load_n(p, __ATOMIC_SEQ_CST); }
static void st(long *p, long v) { __atomic_store_n(p, v, __ATOMIC_SEQ_CST); }
static void inc(long *p) { __atomic_add_fetch(p, 1, __ATOMIC_SEQ_CST); }
#endif
static SYSV void tls_barrier(void) {          /* two threads meet here, unless the barrier was opened */
    inc(&g_arrived);
    while (ld(&g_arrived) < 2 && !ld(&g_barrier_open)) {}
}

typedef struct { tls_worker_fn fn; int id, use_ie, rc; } tls_job;
#if defined(_WIN32)
static DWORD WINAPI tls_thread(LPVOID p) {
#else
static void *tls_thread(void *p) {
#endif
    tls_job *j = (tls_job *)p;
    if (afw_tls_thread_init() != 0) { j->rc = -2; tls_barrier(); return 0; }   /* no partial state */
    j->rc = j->fn(j->id, tls_barrier, j->use_ie);
    return 0;
}

/* Every creation and wait is checked (reviewer 2, PR #6 A3). If a thread
 * cannot be created, the barrier is opened so the other one cannot hang,
 * and the run reports failure. fail_second simulates that (negative test). */
static int run_tls_threads(tls_worker_fn fn, int use_ie, int fail_second) {
    tls_job j[2] = {{fn, 1, use_ie, -1}, {fn, 2, use_ie, -1}};
    int k, created[2] = {0, 0}, ok = 1;
    st(&g_arrived, 0); st(&g_barrier_open, 0);
#if defined(_WIN32)
    HANDLE h[2] = {NULL, NULL};
    for (k = 0; k < 2; k++) {
        h[k] = (k == 1 && fail_second) ? NULL : CreateThread(NULL, 0, tls_thread, &j[k], 0, NULL);
        created[k] = h[k] != NULL;
        if (!created[k]) { ok = 0; st(&g_barrier_open, 1); printf("    thread %d could not be created\n", k + 1); }
    }
    for (k = 0; k < 2; k++)
        if (created[k]) {
            DWORD w = WaitForSingleObject(h[k], 30000);
            if (w == WAIT_TIMEOUT) {          /* open the barrier, then wait for real: j is on our stack */
                ok = 0; st(&g_barrier_open, 1);
                printf("    thread %d did not finish in 30 s\n", k + 1);
                w = WaitForSingleObject(h[k], INFINITE);
            }
            if (w != WAIT_OBJECT_0) {
                printf("    waiting for thread %d failed (error %lu): stopping, its data is on this stack\n",
                       k + 1, GetLastError());
                abort();
            }
            CloseHandle(h[k]);
        }
#else
    pthread_t t[2];
    for (k = 0; k < 2; k++) {
        created[k] = !(k == 1 && fail_second) && pthread_create(&t[k], NULL, tls_thread, &j[k]) == 0;
        if (!created[k]) { ok = 0; st(&g_barrier_open, 1); printf("    thread %d could not be created\n", k + 1); }
    }
    for (k = 0; k < 2; k++)
        if (created[k] && pthread_join(t[k], NULL) != 0) {
            printf("    thread %d could not be joined: stopping, its data is on this stack\n", k + 1);
            abort();
        }
#endif
    if (j[0].rc || j[1].rc) printf("    worker results: thread 1 -> %d, thread 2 -> %d\n", j[0].rc, j[1].rc);
    return ok && j[0].rc == 0 && j[1].rc == 0;
}

/* A new thread whose very first publish fails half way: afterwards it must
 * have no block and nothing published (all its slots still zero). */
static int g_init_fail_ok;
/* p != NULL: go through afw_tls_init(), the entry point a new thread uses
 * first, and retry through it as well */
#if defined(_WIN32)
static DWORD WINAPI init_fail_thread(LPVOID p) {
#else
static void *init_fail_thread(void *p) {
#endif
    int i, clean = 1, via_init = p != NULL;
    afw_tls_test_fail_publish(3);
    if ((via_init ? afw_tls_init() : afw_tls_thread_init()) != -1) clean = 0;
    if (afw_tls_block() != NULL) clean = 0;
#if defined(_WIN32)
    for (i = 0; i < 16; i++) if (afw_tls_published_slot(i) != 0) clean = 0;
#else
    (void)i;
#endif
    if ((via_init ? afw_tls_init() : afw_tls_thread_init()) != 0 || afw_tls_block() == NULL ||
        afw_tls_published_slot(0) != (uintptr_t)afw_tls_block())
        clean = 0;   /* the retry really sets the thread up, not just reports success */
    g_init_fail_ok = clean;
    return 0;
}
static int run_fail_init_thread(int via_init) {
    g_init_fail_ok = 0;
#if defined(_WIN32)
    HANDLE h = CreateThread(NULL, 0, init_fail_thread, via_init ? (LPVOID)1 : NULL, 0, NULL);
    if (!h || WaitForSingleObject(h, INFINITE) != WAIT_OBJECT_0) return 0;
    CloseHandle(h);
#else
    pthread_t t;
    if (pthread_create(&t, NULL, init_fail_thread, via_init ? (void *)1 : NULL) != 0 || pthread_join(t, NULL) != 0)
        return 0;
#endif
    return g_init_fail_ok;
}

static int run_tls_tests(const afw_lib *lib) {
    tls_int_fn tdata = (tls_int_fn)afw_sym(lib, "afw_tls_tdata");
    tls_int_fn tbss = (tls_int_fn)afw_sym(lib, "afw_tls_tbss");
    tls_long_fn local = (tls_long_fn)afw_sym(lib, "afw_tls_local");
    tls_uptr_fn aligned = (tls_uptr_fn)afw_sym(lib, "afw_tls_aligned_addr");
    tls_int_fn first = (tls_int_fn)afw_sym(lib, "afw_tls_aligned_first");
    tls_ptr_fn gd = (tls_ptr_fn)afw_sym(lib, "afw_tls_addr_gd");
    tls_ptr_fn ie = (tls_ptr_fn)afw_sym(lib, "afw_tls_addr_ie");
    tls_worker_fn worker = (tls_worker_fn)afw_sym(lib, "afw_tls_worker");
    printf("\nG1-TLS tests (ELF thread-local storage):\n");
    check(".tdata variable has its initial value", tdata() == 0x5eed1234);
    check(".tbss variable starts at zero", tbss() == 0);
    check("static __thread (relocation with symbol 0)", local() == 77);
    check("aligned(64) variable is 64-byte aligned", (aligned() & 63) == 0);
    check("aligned variable has its initial value", first() == 7);
    check("general-dynamic address lies below tp", (uintptr_t)gd() < (uintptr_t)afw_tls_block());
    {   /* what bionic's __errno does (measured): [[tp] + 8] + 0x300; gettid reads +0x10 */
        uintptr_t *tp = afw_tls_block();
        unsigned char *pti = (unsigned char *)tp[TLS_SLOT_THREAD_ID];
        int32_t tid;
        check("tp[1] points at this thread's pthread_internal_t, inside its allocation",
              pti && (uintptr_t)pti > (uintptr_t)tp && tp[TLS_SLOT_BIONIC_TLS] == (uintptr_t)(pti + AFW_BIONIC_TLS_OFF));
        memcpy(&tid, pti + AFW_PTI_TID, 4);
        check("pthread_internal_t holds the thread id where gettid reads it", tid != 0);
        *(volatile int *)(pti + 0x300) = 34;
        check("errno, written the way bionic writes it, reads back", *(volatile int *)(pti + 0x300) == 34);
    }
#if defined(_WIN32)
    check("initial-exec (fs:[0] + TPOFF64) == general-dynamic", ie() == gd());
    check("two threads, initial-exec: private copies", run_tls_threads(worker, 1, 0));
#else
    (void)ie;   /* on Linux fs: belongs to the host C library: initial-exec runs only on Windows */
#endif
    check("two threads, general-dynamic: private copies", run_tls_threads(worker, 0, 0));
    printf("  negative tests (failures must be reported, never hidden or hung):\n");
    check("second thread cannot be created: reported, no hang", run_tls_threads(worker, 0, 1) == 0);
    {
        int *v = gd();
        int before = *v;
        uintptr_t *tp_before = afw_tls_block();
        afw_tls_test_fail_publish(3);           /* fails after 3 slots were already set */
        check("rebuild whose publish fails after 3 slots returns -1", afw_tls_thread_rebuild() == -1);
        check("... every slot the CPU sees names the old block again",
              afw_tls_published_slot(0) == (uintptr_t)tp_before && afw_tls_published_slot(2) == tp_before[2] &&
              afw_tls_published_slot(5) == tp_before[5]);
        check("... and the thread keeps its old block and values", afw_tls_block() == tp_before && *gd() == before);
        afw_tls_test_fail_publish(16);          /* fails at the very last step (FLS) */
        check("rebuild whose publish fails at the last step returns -1, old block published",
              afw_tls_thread_rebuild() == -1 && afw_tls_published_slot(0) == (uintptr_t)tp_before);
        check("new thread whose publish fails after 3 slots: nothing left published", run_fail_init_thread(0));
        check("... the same through afw_tls_init(): fails, then a retry really sets the thread up",
              run_fail_init_thread(1));
        check("a rebuild that succeeds still works afterwards", afw_tls_thread_rebuild() == 0 && *gd() == before);
        {   /* the old allocation is freed by now: slots 1 and 9 must name the new one */
            uintptr_t *tp = afw_tls_block();
            unsigned char *pti = (unsigned char *)tp[TLS_SLOT_THREAD_ID];
            check("... tp[1] moved with the block (not into the freed one) and errno carried over",
                  (uintptr_t)pti > (uintptr_t)tp && *(volatile int *)(pti + 0x300) == 34 &&
                  afw_tls_published_slot(TLS_SLOT_THREAD_ID) == (uintptr_t)pti);
        }
    }
    {
        afw_tls_index bad;
        uint64_t memsz = 0;
        int m = lib->tls_module;
        (void)bad;
        memsz = afw_tls_static_memsz(m);
        check("__tls_get_addr: last byte of the module resolves", afw_tls_static_resolve((uint64_t)m, memsz - 1) != NULL);
        check("__tls_get_addr: offset == p_memsz refused", afw_tls_static_resolve((uint64_t)m, memsz) == NULL);
        check("__tls_get_addr: offset > p_memsz refused", afw_tls_static_resolve((uint64_t)m, memsz + 64) == NULL);
        check("__tls_get_addr: offset near 2^64 refused", afw_tls_static_resolve((uint64_t)m, ~(uint64_t)0) == NULL);
        check("__tls_get_addr: module 0 / unknown module refused",
              afw_tls_static_resolve(0, 0) == NULL && afw_tls_static_resolve((uint64_t)m + 1, 0) == NULL);
    }
    printf("%s\n", g_failed ? "G1-TLS TESTS FAILED" : "G1-TLS TESTS PASSED");
    return g_failed ? 1 : 0;
}

/* fs:[reg] ELF TLS through trampolines (G1-TLS design, section 6) */
typedef int (SYSV *ie_int_fn)(void);
typedef void (SYSV *ie_set_fn)(int);
typedef int (SYSV *ie_and_fn)(int);
typedef int *(SYSV *ie_ptr_fn)(void);
static ie_int_fn g_ie_read_b;
#if defined(_WIN32)
static DWORD WINAPI ie_thread(LPVOID p) {
    int *out = (int *)p;
    if (afw_tls_thread_init() != 0) { *out = -2; return 0; }
    *out = g_ie_read_b();                    /* this thread's own copy: initial value */
    return 0;
}
#endif
static int run_ie_tests(const afw_lib *lib) {
    ie_int_fn read_b = (ie_int_fn)afw_sym(lib, "afw_ie_read_b");
    ie_set_fn write_a = (ie_set_fn)afw_sym(lib, "afw_ie_write_a");
    ie_and_fn and_b = (ie_and_fn)afw_sym(lib, "afw_ie_and_b");
    ie_ptr_fn addr = (ie_ptr_fn)afw_sym(lib, "afw_ie_addr");
    ie_set_fn store_ret = (ie_set_fn)afw_sym(lib, "afw_ie_store_ret");
    ie_int_fn test_flags = (ie_int_fn)afw_sym(lib, "afw_ie_test_flags");
    ie_and_fn branch_after = (ie_and_fn)afw_sym(lib, "afw_ie_branch_after");
    ie_set_fn incr_a_dummy = NULL;
    typedef void (SYSV *ie_void_fn)(void);
    ie_void_fn incr_a = (ie_void_fn)afw_sym(lib, "afw_ie_incr_a");
    g_ie_read_b = read_b;
    printf("\nG1-TLS fs:[reg] tests (%d accesses rewritten through trampolines):\n", lib->patch.fs_reg_trampolined);
    (void)incr_a_dummy;
    check("all 8 fs:[reg] accesses rewritten", lib->patch.fs_reg_trampolined == 8);
    check("read fs:[reg+4] (initial value)", read_b() == 22);
    write_a(5);
    check("write fs:[reg] lands where tp + TPOFF points", addr()[0] == 5);
    check("and eax, fs:[reg+4]", and_b(0xF0) == (22 & 0xF0));
    store_ret(77);
    check("store right before ret (moved rip-relative mov re-based)", addr()[0] == 77);
    check("flags from test after the stub (b=22: bit 0 clear)", test_flags() == 1);
    addr()[1] = 23;
    check("flags change with the value (b=23)", test_flags() == 0 && read_b() == 23);
    check("branch target right after the access: predecessor moved instead", branch_after(0) == 24);
    check("... and the branch to that target still works", branch_after(7) == 1);
    addr()[0] = 41; incr_a();
    check("two sites sharing an instruction: read, add, write back", addr()[0] == 42);
#if defined(_WIN32)
    {
        int other = -1;
        HANDLE t = CreateThread(NULL, 0, ie_thread, &other, 0, NULL);
        WaitForSingleObject(t, INFINITE); CloseHandle(t);
        check("another thread reads its own copy (22, not 23)", other == 22);
    }
#endif
    printf("%s\n", g_failed ? "G1-TLS fs:[reg] TESTS FAILED" : "G1-TLS fs:[reg] TESTS PASSED");
    return g_failed ? 1 : 0;
}

static int run_redzone_tests(const afw_lib *lib) {
    getpid_fn safe = (getpid_fn)afw_sym(lib, "afw_rz_safe");
    printf("\n=== G1 negative test: red zone ===\n");
    check("all 4 red zone sites were REFUSED (incl. lea reg, [rsp-16])", lib->patch.sys_refused_redzone == 4);
    check("every refused site now traps with ud2", lib->patch.sys_trapped == 4);
    check("only the safe site was patched", lib->patch.sys_patched == 1);
    check("the safe site works", safe && safe() == host_pid());
    printf("\n%s\n", g_failed ? "RED ZONE TEST FAILED" : "RED ZONE TEST PASSED");
    return g_failed ? 1 : 0;
}

int main(int argc, char **argv) {
    afw_lib lib;
    int verbose = 1, rc = 0, strict = 0, min_pads = 0, call_trap = 0;
    const char *preload_fail = NULL;
    int with_deps = 0;
    static afw_lib deps[32];
    int ndeps = 0;

    setvbuf(stdout, NULL, _IONBF, 0); /* never lose output on a crash */
    afw_crash_init();
    printf("Android-for-Windows loader %s\n", AFW_VERSION);
    printf("bionic-win provides %d functions\n\n", afw_shim_count());

    if (argc < 2) {
        printf("usage: %s <library.so> [-v]\n", argv[0]);
        return 2;
    }
    if (argc > 2 && strcmp(argv[2], "-v") == 0) verbose = 2;
    if (argc > 2 && strcmp(argv[2], "--patch-report") == 0) afw_load_patch_only = 1;
    {
        int a;
        for (a = 2; a < argc; a++) {
            if (strcmp(argv[a], "--strict") == 0) strict = 1;
            else if (strcmp(argv[a], "--allow-unproven") == 0) afw_load_allow_unproven = 1;
            else if (strcmp(argv[a], "--call-trap") == 0) call_trap = 1;
            else if (strncmp(argv[a], "--min-landing-pads=", 19) == 0) min_pads = atoi(argv[a] + 19);
            else if (strncmp(argv[a], "--preload-fail=", 15) == 0) preload_fail = argv[a] + 15;
            else if (strcmp(argv[a], "--with-deps") == 0) with_deps = 1;
        }
    }
    if (afw_check_security() != 0) return 1;
    if (afw_tls_init() != 0) return 1;

    /* test: a library that must FAIL to load leaves nothing behind - not in
     * the library list, and its TLS module does not block the next library */
    if (preload_fail) {
        static afw_lib failed;
        int before = afw_loaded_count();
        printf("Loading %s, which must be refused...\n", preload_fail);
        if (afw_load(preload_fail, &failed, 0) == 0) { printf("FAIL: it loaded\n"); return 1; }
        if (afw_loaded_count() != before || failed.base != NULL || failed.tls_module != 0) {
            printf("FAIL: the failed load left state behind\n"); return 1;
        }
        printf("  [ OK ] refused, and nothing left behind (libraries registered: %d)\n", afw_loaded_count());
    }

    if ((with_deps ? afw_load_with_deps(argv[1], &lib, deps, 32, &ndeps, verbose)
                   : afw_load(argv[1], &lib, verbose)) != 0) {
        printf("\nLoad failed.\n");
        return 1;
    }

    printf("\nLoaded at %p (%zu KB)\n", (void *)lib.base, lib.size / 1024);
    printf("  relocations applied: %d\n", lib.nrelocs);
    printf("  exports:             %d\n", lib.nexports);
    printf("  imports linked:      %d (to bionic-win), %d (to other loaded libraries)\n", lib.nimports_shimmed, lib.nimports_linked);
    printf("  imports missing:     %d\n", lib.nimports_missing);
    printf("  weak imports empty:  %d\n", lib.nimports_weak_null);

    printf("  syscall sites patched: %d + %d moved (refused: %d branch, %d red zone, %d unknown)\n",
           lib.patch.sys_patched, lib.patch.sys_patched_moved, lib.patch.sys_refused_branch,
           lib.patch.sys_refused_redzone, lib.patch.sys_refused_unknown);
    printf("  fs: accesses patched:  %d (fs:[reg]: %d real, %d data)\n", lib.patch.fs_patched,
           lib.patch.fs_reg_in_func, lib.patch.fs_reg_outside);

    printf("  C++ landing pads followed: %d (exception tables not decodable: %d)\n",
           lib.patch.landing_pads, lib.patch.lsda_failures);
    printf("  audit: %d unreachable look-alikes left alone, %d UNPROVEN (in %d functions with unresolved "
           "indirect jumps); outside .eh_frame: %d syscall, %d fs:\n",
           lib.patch.unreachable_ignored, lib.patch.unproven, lib.patch.funcs_undecided,
           lib.patch.sys_outside_functions, lib.patch.fs_outside_functions);
    if (lib.patch.sys_refused_redzone)
        printf("  red zone refusals: %d [rsp-N], %d [frame reg - N] beyond sub rsp\n",
               lib.patch.redzone_direct, lib.patch.redzone_via_copy);
    if (afw_load_patch_only)
        printf("GATE %s: %s\n", lib.soname ? lib.soname : argv[1],
               afw_gate_ok(&lib) ? "would RUN" : "would REFUSE");
    if (afw_load_patch_only && strict) {
        int bad = lib.patch.unproven || lib.patch.lsda_failures ||
                  lib.patch.landing_pads < min_pads;
        printf("STRICT: %s (unproven %d, undecodable exception tables %d, landing pads %d, required >= %d)\n",
               bad ? "FAILED" : "PASSED", lib.patch.unproven, lib.patch.lsda_failures,
               lib.patch.landing_pads, min_pads);
        if (bad) return 1;
    }
    if (afw_load_patch_only) {
        int total = lib.patch.sys_patched + lib.patch.sys_patched_moved + lib.patch.sys_refused_branch +
                    lib.patch.sys_refused_redzone + lib.patch.sys_refused_unknown;
        printf("\nPATCH REPORT %s: %d syscall sites: %d patched (A), %d patched (B), refused %d "
               "(branch %d, red zone %d, unknown %d); fs:[disp32] %d reachable, %d patched\n",
               lib.soname ? lib.soname : argv[1], total, lib.patch.sys_patched, lib.patch.sys_patched_moved,
               total - lib.patch.sys_patched - lib.patch.sys_patched_moved, lib.patch.sys_refused_branch,
               lib.patch.sys_refused_redzone, lib.patch.sys_refused_unknown, lib.patch.fs_disp_seen,
               lib.patch.fs_patched);
        {
            int q;
            printf("fs:[disp32] by kind (offset, instruction, access, count):\n");
            for (q = 0; q < lib.patch.nfs_kind; q++)
                printf("  FSKIND fs:[0x%llx] %-8s %s %d\n", (long long)lib.patch.fs_kind[q].disp,
                       afw_mnemonic_name(lib.patch.fs_kind[q].mnemonic),
                       lib.patch.fs_kind[q].write ? "WRITE" : "read ", lib.patch.fs_kind[q].count);
        }
        return 0;
    }

    if (afw_sym(&lib, "afw_add")) rc = run_m0_tests(&lib);
    if (afw_sym(&lib, "afw_sys_getpid")) rc |= run_syscall_tests(&lib);
    if (afw_sym(&lib, "afw_rz_safe")) rc |= run_redzone_tests(&lib);
    if (afw_sym(&lib, "afw_tls_worker")) rc |= run_tls_tests(&lib);
    if (afw_sym(&lib, "afw_ie_read_b")) rc |= run_ie_tests(&lib);
    if (afw_sym(&lib, "afw_deps_check")) {
        typedef int (SYSV *dfn)(void);
        printf("\nDependency test (--with-deps):\n");
        check("imports, an imported IFUNC and TLS: 30 + 5 + 7, constructor of the dependency first",
              ((dfn)afw_sym(&lib, "afw_deps_check"))() == 42);
        check("it was linked to a library, not to bionic-win", lib.nimports_linked >= 3);
        check("it has TLS although the dependency loaded first has none", lib.tls_module >= 1);
        printf("%s\n", g_failed ? "DEPS TEST FAILED" : "DEPS TEST PASSED");
        rc |= g_failed;
    }
    if (afw_sym(&lib, "afw_ifunc_call")) {
        typedef int (SYSV *ifn)(void);
        printf("\nIFUNC test (resolver runs after patching, reads the stack guard):\n");
        check("IFUNC symbol (JUMP_SLOT) returns the resolved function's value", ((ifn)afw_sym(&lib, "afw_ifunc_call"))() == 42);
        check("hidden IFUNC (IRELATIVE) returns the resolved function's value",
              ((ifn)afw_sym(&lib, "afw_ifunc_call_hidden"))() == 42);
        printf("%s\n", g_failed ? "IFUNC TEST FAILED" : "IFUNC TEST PASSED");
        rc |= g_failed;
    }
    if (call_trap) {
        typedef long (SYSV *f1)(int);
        f1 f = (f1)afw_sym(&lib, "afw_sys_branch_into_site");
        printf("\nCalling a REFUSED site on purpose (expect a clear crash report)...\n");
        if (f) f(0);
        printf("ERROR: the refused site did not trap\n");
        return 99;
    }

    afw_unload(&lib);
    return rc;
}
