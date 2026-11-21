/*
 * bionic_shim.c - First functions of "bionic-win".
 *
 * Each shim is marked SYSV: it receives arguments the Android (System V) way,
 * then calls the normal Windows C runtime.
 */
#include "bionic_shim.h"
#include "platform.h"

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
    S("__android_log_write", s_android_log_write),
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
