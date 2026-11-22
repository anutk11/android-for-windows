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
    check("every safe 'mov eax; syscall' site was patched (5, one behind a switch table)",
          lib->patch.sys_patched == 5);
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

static volatile long g_arrived;
static SYSV void tls_barrier(void) {          /* two threads meet here */
#if defined(_WIN32)
    InterlockedIncrement(&g_arrived);
#else
    __atomic_add_fetch(&g_arrived, 1, __ATOMIC_SEQ_CST);
#endif
    while (g_arrived < 2) {}
}

typedef struct { tls_worker_fn fn; int id, use_ie, rc; } tls_job;
#if defined(_WIN32)
static DWORD WINAPI tls_thread(LPVOID p) {
#else
static void *tls_thread(void *p) {
#endif
    tls_job *j = (tls_job *)p;
    afw_tls_thread_init();                     /* every thread that runs Android code */
    j->rc = j->fn(j->id, tls_barrier, j->use_ie);
    return 0;
}

static int run_tls_threads(tls_worker_fn fn, int use_ie) {
    tls_job j[2] = {{fn, 1, use_ie, -1}, {fn, 2, use_ie, -1}};
    int k;
    g_arrived = 0;
#if defined(_WIN32)
    HANDLE h[2];
    for (k = 0; k < 2; k++) h[k] = CreateThread(NULL, 0, tls_thread, &j[k], 0, NULL);
    WaitForMultipleObjects(2, h, TRUE, INFINITE);
    for (k = 0; k < 2; k++) CloseHandle(h[k]);
#else
    pthread_t t[2];
    for (k = 0; k < 2; k++) pthread_create(&t[k], NULL, tls_thread, &j[k]);
    for (k = 0; k < 2; k++) pthread_join(t[k], NULL);
#endif
    if (j[0].rc || j[1].rc) printf("    worker results: thread 1 -> %d, thread 2 -> %d\n", j[0].rc, j[1].rc);
    return j[0].rc == 0 && j[1].rc == 0;
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
#if defined(_WIN32)
    check("initial-exec (fs:[0] + TPOFF64) == general-dynamic", ie() == gd());
    check("two threads, initial-exec: private copies", run_tls_threads(worker, 1));
#else
    (void)ie;   /* on Linux fs: belongs to the host C library: initial-exec runs only on Windows */
#endif
    check("two threads, general-dynamic: private copies", run_tls_threads(worker, 0));
    printf("%s\n", g_failed ? "G1-TLS TESTS FAILED" : "G1-TLS TESTS PASSED");
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
        }
    }
    if (afw_check_security() != 0) return 1;
    if (afw_tls_init() != 0) return 1;

    if (afw_load(argv[1], &lib, verbose) != 0) {
        printf("\nLoad failed.\n");
        return 1;
    }

    printf("\nLoaded at %p (%zu KB)\n", (void *)lib.base, lib.size / 1024);
    printf("  relocations applied: %d\n", lib.nrelocs);
    printf("  exports:             %d\n", lib.nexports);
    printf("  imports linked:      %d\n", lib.nimports_shimmed);
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
