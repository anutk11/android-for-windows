/*
 * bionic_shim.c - First functions of "bionic-win".
 *
 * Each shim is marked SYSV: it receives arguments the Android (System V) way,
 * then calls the normal Windows C runtime.
 */
#include "bionic_shim.h"
#include "platform.h"
#include "tls_static.h"
#include "loader_api.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* libc: strings and memory                                            */
/* ------------------------------------------------------------------ */

static SYSV size_t s_strlen(const char *s) { return strlen(s); }
static SYSV int s_strcmp(const char *a, const char *b) { return strcmp(a, b); }
static SYSV int s_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
static SYSV char *s_strcpy(char *d, const char *s) { return strcpy(d, s); }
static SYSV char *s_strncpy(char *d, const char *s, size_t n) { return strncpy(d, s, n); }
static SYSV char *s_strcat(char *d, const char *s) { return strcat(d, s); }
static SYSV char *s_strchr(const char *s, int c) { return strchr(s, c); }
static SYSV char *s_strrchr(const char *s, int c) { return strrchr(s, c); }
static SYSV char *s_strstr(const char *h, const char *n) { return strstr(h, n); }
static SYSV char *s_stpcpy(char *d, const char *s) {
    size_t n = strlen(s);
    memcpy(d, s, n + 1);
    return d + n;
}
static SYSV char *s_strdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static SYSV void *s_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
static SYSV void *s_memmove(void *d, const void *s, size_t n) { return memmove(d, s, n); }
static SYSV void *s_memset(void *d, int c, size_t n) { return memset(d, c, n); }
static SYSV int s_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
static SYSV void *s_memchr(const void *s, int c, size_t n) { return memchr(s, c, n); }

/* FORTIFY versions (bionic adds a buffer size argument) */
static SYSV size_t s_strlen_chk(const char *s, size_t sz) { (void)sz; return strlen(s); }
static SYSV char *s_strcpy_chk(char *d, const char *s, size_t sz) { (void)sz; return strcpy(d, s); }
static SYSV char *s_strcat_chk(char *d, const char *s, size_t sz) { (void)sz; return strcat(d, s); }
static SYSV void *s_memcpy_chk(void *d, const void *s, size_t n, size_t sz) { (void)sz; return memcpy(d, s, n); }
static SYSV void *s_memmove_chk(void *d, const void *s, size_t n, size_t sz) { (void)sz; return memmove(d, s, n); }
static SYSV void *s_memset_chk(void *d, int c, size_t n, size_t sz) { (void)sz; return memset(d, c, n); }

/* ------------------------------------------------------------------ */
/* libc: heap                                                          */
/* ------------------------------------------------------------------ */

static SYSV void *s_malloc(size_t n) { return malloc(n); }
static SYSV void *s_calloc(size_t a, size_t b) { return calloc(a, b); }
static SYSV void *s_realloc(void *p, size_t n) { return realloc(p, n); }
static SYSV void s_free(void *p) { free(p); }

/* ------------------------------------------------------------------ */
/* libc: output, errors, process                                       */
/* ------------------------------------------------------------------ */

static SYSV int s_puts(const char *s) {
    int r = puts(s);
    fflush(stdout);
    return r;
}
static SYSV int s_putchar(int c) { return putchar(c); }

static _Thread_local int t_errno;
static SYSV int *s_errno_location(void) { return &t_errno; }

static SYSV void s_abort(void) {
    fprintf(stderr, "[bionic-win] Android code called abort()\n");
    exit(134);
}
static SYSV void s_exit(int code) { exit(code); }

/* Stack protector. Android libs compiled with -fstack-protector read the
 * guard from TLS (fs:0x28), which does not exist on Windows - see README. */
static uintptr_t g_stack_chk_guard = 0x5afe5afe5afe5afeULL;
static SYSV void s_stack_chk_fail(void) {
    fprintf(stderr, "[bionic-win] stack corruption detected (__stack_chk_fail)\n");
    exit(134);
}

/* C++ runtime hooks that every NDK library references (crtbegin_so.o) */
typedef SYSV void (*atexit_fn)(void *);
static struct { atexit_fn fn; void *arg; } g_atexit[64];
static int g_atexit_count;

static SYSV int s_cxa_atexit(atexit_fn fn, void *arg, void *dso) {
    (void)dso;
    if (g_atexit_count >= 64) return -1;
    g_atexit[g_atexit_count].fn = fn;
    g_atexit[g_atexit_count].arg = arg;
    g_atexit_count++;
    return 0;
}
static SYSV void s_cxa_finalize(void *dso) { (void)dso; }

/* pthread_atfork, registered by crtbegin_so.o. Windows has no fork(), so
 * these handlers can never run. */
typedef SYSV void (*fork_fn)(void);
static SYSV int s_register_atfork(fork_fn prepare, fork_fn parent, fork_fn child, void *dso) {
    (void)prepare; (void)parent; (void)child; (void)dso;
    return 0;
}

void afw_shim_run_atexit(void) {
    while (g_atexit_count > 0) {
        g_atexit_count--;
        g_atexit[g_atexit_count].fn(g_atexit[g_atexit_count].arg);
    }
}

/* ------------------------------------------------------------------ */
/* liblog: Android logging -> console                                  */
/* ------------------------------------------------------------------ */

static SYSV int s_android_log_write(int prio, const char *tag, const char *text) {
    static const char levels[] = "??VDIWEF";
    char lv = (prio >= 0 && prio < 8) ? levels[prio] : '?';
    printf("[logcat %c/%s] %s\n", lv, tag ? tag : "", text ? text : "");
    fflush(stdout);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Symbol table                                                        */
/* ------------------------------------------------------------------ */

typedef struct { const char *name; void *addr; } shim_entry;

#define S(n, f) { n, (void *)(f) }

/* ---- libc_shared_globals (G1: the real libc.so's constructors) -------
 * The struct the Android linker shares with libc.so. Its layout is that of
 * ONE libc build (Build ID AFW_SHARED_GLOBALS_BUILD_ID; the loader refuses
 * any other), measured from that build's own code (tools/sg_uses.py) and
 * matched against the AOSP field order (docs/design/G1-LIBC-INIT.md). Every
 * field not set here is zero, as the linker's constexpr constructor leaves
 * it: an empty fd table, an unlocked abort-message mutex, no TLS modules. */
#define SG_SIZE              0x1000   /* last field measured: 0x680 */
#define SG_AUXV              0x418
/* StaticTlsLayout inside libc_shared_globals (pinned Build ID fa337969c798946280caa45e2d71a2e7):
 * Measured directly from libc.so + linker64 disassembly in bionic-probe:
 *   0x450 (+0x00): size_                  (__allocate_thread_mapping, __libc_get_static_tls_bounds, finish_layout)
 *   0x458 (+0x08): align_                 (linker64 StaticTlsLayout::reserve / finish_layout)
 *   0x460 (+0x10): overflowed_            (bool + 7B pad: linker64 0x146048/0x1460da; MUST be 0)
 *   0x468 (+0x18): offset_thread_pointer_ (linker64 0x97370, pthread_create, __libc_get_static_tls_bounds)
 *   0x470 (+0x20): offset_bionic_tls_     (linker64 0x1460ac, pthread_create)
 * Followed immediately by tls_modules.generation at 0x478 (measured: __libc_preinit_impl). */
#define SG_STL_SIZE                  0x450
#define SG_STL_ALIGN                 0x458
#define SG_STL_OVERFLOWED            0x460
#define SG_STL_OFFSET_THREAD_POINTER 0x468
#define SG_STL_OFFSET_BIONIC_TLS     0x470
#define SG_INIT_PROGNAME     0x630
#define SG_INIT_ENVIRON      0x638
#define AT_NULL_    0
#define AT_PAGESZ_  6
#define AT_UID_     11
#define AT_EUID_    12
#define AT_GID_     13
#define AT_EGID_    14
#define AT_HWCAP_   16
#define AT_SECURE_  23
#define AT_RANDOM_  25
#define AT_HWCAP2_  26

static uint64_t g_sg_mem[SG_SIZE / 8];
static uint64_t g_auxv[2 * 12];
static unsigned char g_at_random[16];
static char *g_environ[1];
static int g_sg_ready;

static void put_auxv(int *k, uint64_t type, uint64_t val) { g_auxv[(*k)++] = type; g_auxv[(*k)++] = val; }

void *afw_shared_globals(void) {
    unsigned char *sg = (unsigned char *)g_sg_mem;
    if (!g_sg_ready) {
        int k = 0;
        uint64_t p;
        if (afw_random_bytes(g_at_random, sizeof g_at_random) != 0) {
            fprintf(stderr, "[bionic-win] no random bytes for AT_RANDOM (the stack guard's seed)\n");
            exit(3);
        }
        put_auxv(&k, AT_PAGESZ_, 4096);
        put_auxv(&k, AT_UID_, 10000); put_auxv(&k, AT_EUID_, 10000);   /* an app's uid range */
        put_auxv(&k, AT_GID_, 10000); put_auxv(&k, AT_EGID_, 10000);
        put_auxv(&k, AT_HWCAP_, 0); put_auxv(&k, AT_HWCAP2_, 0);
        put_auxv(&k, AT_SECURE_, 0);
        put_auxv(&k, AT_RANDOM_, (uint64_t)(uintptr_t)g_at_random);
        put_auxv(&k, AT_NULL_, 0);
        p = (uint64_t)(uintptr_t)g_auxv;           memcpy(sg + SG_AUXV, &p, 8);
        p = (uint64_t)(uintptr_t)g_environ;        memcpy(sg + SG_INIT_ENVIRON, &p, 8);
        p = (uint64_t)(uintptr_t)"android-for-windows"; memcpy(sg + SG_INIT_PROGNAME, &p, 8);
        g_sg_ready = 1;
    }
    return sg;
}
static SYSV void *s_loader_shared_globals(void) { return afw_shared_globals(); }

const unsigned char *afw_shared_globals_random(void) {
    (void)afw_shared_globals();
    return g_at_random;
}

/* An executable's own auxv, environment and name (exec.c), as the linker
 * sets them for libc before entering a program. Non-NULL fields are updated;
 * envp and progname are set before libc.so constructors run so constructors
 * and main() observe the same environment, program name, and AT_RANDOM seed. */
void afw_shared_globals_set_process(const uint64_t *auxv, char **envp, const char *progname) {
    unsigned char *sg = (unsigned char *)afw_shared_globals();
    uint64_t p;
    if (auxv)     { p = (uint64_t)(uintptr_t)auxv;     memcpy(sg + SG_AUXV, &p, 8); }
    if (envp)     { p = (uint64_t)(uintptr_t)envp;     memcpy(sg + SG_INIT_ENVIRON, &p, 8); }
    if (progname) { p = (uint64_t)(uintptr_t)progname; memcpy(sg + SG_INIT_PROGNAME, &p, 8); }
}

void afw_shared_globals_set_static_tls(const afw_bionic_static_tls *stl) {
    unsigned char *sg;
    if (!stl) return;
    sg = (unsigned char *)afw_shared_globals();
    memcpy(sg + SG_STL_SIZE,                  &stl->size,                  8);
    memcpy(sg + SG_STL_ALIGN,                 &stl->align,                 8);
    memcpy(sg + SG_STL_OVERFLOWED,            &stl->overflowed,            8);
    memcpy(sg + SG_STL_OFFSET_THREAD_POINTER, &stl->offset_thread_pointer, 8);
    memcpy(sg + SG_STL_OFFSET_BIONIC_TLS,     &stl->offset_bionic_tls,     8);
}

static const shim_entry g_shims[] = {
    S("strlen", s_strlen), S("strcmp", s_strcmp), S("strncmp", s_strncmp),
    S("strcpy", s_strcpy), S("strncpy", s_strncpy), S("strcat", s_strcat),
    S("strchr", s_strchr), S("strrchr", s_strrchr), S("strstr", s_strstr),
    S("stpcpy", s_stpcpy), S("strdup", s_strdup),
    S("memcpy", s_memcpy), S("memmove", s_memmove), S("memset", s_memset),
    S("memcmp", s_memcmp), S("memchr", s_memchr),
    S("__strlen_chk", s_strlen_chk), S("__strcpy_chk", s_strcpy_chk),
    S("__strcat_chk", s_strcat_chk), S("__memcpy_chk", s_memcpy_chk),
    S("__memmove_chk", s_memmove_chk), S("__memset_chk", s_memset_chk),
    S("malloc", s_malloc), S("calloc", s_calloc), S("realloc", s_realloc),
    S("free", s_free),
    S("puts", s_puts), S("putchar", s_putchar),
    S("__errno", s_errno_location),
    S("abort", s_abort), S("exit", s_exit),
    S("__stack_chk_fail", s_stack_chk_fail),
    S("__stack_chk_guard", &g_stack_chk_guard),
    S("__cxa_atexit", s_cxa_atexit), S("__cxa_finalize", s_cxa_finalize),
    S("__register_atfork", s_register_atfork),
    S("__android_log_write", s_android_log_write),
    /* TEMPORARY for G1: ahead of libc's own, until bionic's DTV is built (G2) */
    S("__tls_get_addr", afw_tls_get_addr),
    S("__loader_shared_globals", s_loader_shared_globals),
    /* the linker's API, which libdl.so forwards to (loader_api.c) */
    S("__loader_dlopen", afw_l_dlopen),
    S("__loader_android_dlopen_ext", afw_l_android_dlopen_ext),
    S("__loader_dlsym", afw_l_dlsym),
    S("__loader_dlvsym", afw_l_dlvsym),
    S("__loader_dlerror", afw_l_dlerror),
    S("__loader_dlclose", afw_l_dlclose),
    S("__loader_dladdr", afw_l_dladdr),
    S("__loader_dl_iterate_phdr", afw_l_dl_iterate_phdr),
    S("__loader_android_get_LD_LIBRARY_PATH", afw_l_android_get_LD_LIBRARY_PATH),
    S("__loader_android_get_application_target_sdk_version", afw_l_android_get_application_target_sdk_version),
    S("__loader_android_handle_signal", afw_l_android_handle_signal),
    S("__loader_cfi_fail", afw_l_cfi_fail),
};
#undef S

int afw_shim_count(void) { return (int)(sizeof(g_shims) / sizeof(g_shims[0])); }

void *afw_shim_lookup(const char *name) {
    int i, n = afw_shim_count();
    for (i = 0; i < n; i++)
        if (strcmp(g_shims[i].name, name) == 0) return g_shims[i].addr;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Stubs for missing symbols                                           */
/* ------------------------------------------------------------------ */

static SYSV void missing_handler(const char *name) {
    fprintf(stderr,
            "\n[bionic-win] NOT IMPLEMENTED: Android code called '%s'.\n"
            "             Add it to src/bionic_shim.c and try again.\n", name);
    exit(3);
}

/*
 * Each stub is 22 bytes of x86_64 machine code:
 *     mov rdi, <pointer to name>      ; first argument (System V)
 *     mov rax, <missing_handler>
 *     jmp rax
 */
#define STUB_SIZE 22
#define STUB_AREA (64 * 1024)
static unsigned char *g_stub_area;
static size_t g_stub_used;

void *afw_shim_missing_stub(const char *name) {
    unsigned char *p;
    uint64_t name_ptr = (uint64_t)(uintptr_t)name;
    uint64_t handler = (uint64_t)(uintptr_t)missing_handler;

    if (!g_stub_area) {
        g_stub_area = (unsigned char *)afw_mem_alloc(STUB_AREA);
        if (!g_stub_area) return NULL;
        afw_mem_protect(g_stub_area, STUB_AREA,
                        AFW_PROT_R | AFW_PROT_W | AFW_PROT_X);
    }
    if (g_stub_used + STUB_SIZE > STUB_AREA) return NULL;

    p = g_stub_area + g_stub_used;
    p[0] = 0x48; p[1] = 0xBF; memcpy(p + 2, &name_ptr, 8);   /* mov rdi, imm64 */
    p[10] = 0x48; p[11] = 0xB8; memcpy(p + 12, &handler, 8); /* mov rax, imm64 */
    p[20] = 0xFF; p[21] = 0xE0;                              /* jmp rax */
    g_stub_used += STUB_SIZE;
    afw_flush_icache(p, STUB_SIZE);
    return p;
}
