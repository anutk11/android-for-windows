/*
 * vma_test.c - unit tests for the VMA layer (src/vma.c), driven through the
 * syscall dispatcher, the same path Android code takes. On Windows the state
 * of every page is also checked with VirtualQuery.
 * Cases from reviewers 2 and 3 (round 7).
 */
#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#endif

#include "../src/platform.h"
#include "../src/syscall.h"
#include "../src/vma.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

static void     a_store_u64(uint64_t *p, uint64_t v)     { InterlockedExchange64((volatile LONG64 *)p, (LONG64)v); }
static uint64_t a_fetch_add_u64(uint64_t *p, uint64_t v) { return (uint64_t)InterlockedExchangeAdd64((volatile LONG64 *)p, (LONG64)v); }
static int      a_load_i32(int *p)                       { return (int)InterlockedCompareExchange((volatile LONG *)p, 0, 0); }
static void     a_store_i32(int *p, int v)               { InterlockedExchange((volatile LONG *)p, (LONG)v); }
static int      a_fetch_add_i32(int *p, int v)           { return (int)InterlockedExchangeAdd((volatile LONG *)p, (LONG)v); }
static void     vma_yield(void)                          { Sleep(0); }

extern char vma_write_fault[], vma_write_recover[];
int vma_probe_write(volatile unsigned char *p, unsigned char val);
void g23_asm_read_loop(const uint64_t *p, const int *stop, uint64_t *iters_out);

__asm__(
    ".att_syntax prefix\n"
    ".text\n"
    ".globl vma_probe_write\n"
    ".globl vma_write_fault\n"
    ".globl vma_write_recover\n"
    "vma_probe_write:\n\t"
    "vma_write_fault:\n\t"
    "movb %dl, (%rcx)\n\t"
    "xor %eax, %eax\n\t"
    "ret\n"
    "vma_write_recover:\n\t"
    "mov $1, %eax\n\t"
    "ret\n"

    /* Platform-level assembly same-page resilience reader (NOT C11 memory model):
     * rcx = target qword ptr, rdx = stop flag ptr, r8 = iters_out ptr */
    ".globl g23_asm_read_loop\n"
    "g23_asm_read_loop:\n\t"
    "xor %r9d, %r9d\n"
    "g23_asm_loop:\n\t"
    "movq (%rcx), %rax\n\t"
    "inc %r9\n\t"
    "movl (%rdx), %eax\n\t"
    "test %eax, %eax\n\t"
    "jz g23_asm_loop\n\t"
    "movq %r9, (%r8)\n\t"
    "ret\n"
    ".intel_syntax noprefix\n"
);

static volatile LONG64 g_g23_watch_lo, g_g23_watch_hi;
static volatile LONG   g_g23_faults;

static LONG CALLBACK vma_test_veh(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    uint64_t lo, hi;
    if (code != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ContextRecord->Rip == (DWORD64)(uintptr_t)vma_write_fault) {
        ep->ContextRecord->Rip = (DWORD64)(uintptr_t)vma_write_recover;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    lo = (uint64_t)InterlockedCompareExchange64(&g_g23_watch_lo, 0, 0);
    hi = (uint64_t)InterlockedCompareExchange64(&g_g23_watch_hi, 0, 0);
    if (lo && ep->ExceptionRecord->NumberParameters >= 2) {
        uint64_t fa = (uint64_t)ep->ExceptionRecord->ExceptionInformation[1];
        if (fa >= lo && fa < hi)
            InterlockedIncrement(&g_g23_faults);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int vma_try_write_byte(volatile unsigned char *p, unsigned char val) {
    return vma_probe_write(p, val);
}

static const char *state(uint64_t a) {
    MEMORY_BASIC_INFORMATION mi;
    if (!VirtualQuery((void *)(uintptr_t)a, &mi, sizeof mi)) return "?";
    if (mi.State == MEM_FREE) return "free";
    if (mi.State == MEM_RESERVE) return "reserved";
    if (mi.Protect == PAGE_READWRITE) return "commit-rw";
    if (mi.Protect == PAGE_NOACCESS) return "commit-none";
    if (mi.Protect == PAGE_READONLY) return "commit-r";
    if (mi.Protect == PAGE_EXECUTE_READ) return "commit-rx";
    return "commit-other";
}
static double now_ms(void) {
    LARGE_INTEGER f, t;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1000.0 / (double)f.QuadPart;
}
#define WIN_CHECK(what, a, want) check(what, strcmp(state(a), want) == 0)
#else
static void     a_store_u64(uint64_t *p, uint64_t v)     { __atomic_store_n(p, v, __ATOMIC_RELAXED); }
static uint64_t a_fetch_add_u64(uint64_t *p, uint64_t v) { return __atomic_fetch_add(p, v, __ATOMIC_RELAXED); }
static int      a_load_i32(int *p)                       { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
static void     a_store_i32(int *p, int v)               { __atomic_store_n(p, v, __ATOMIC_RELEASE); }
static int      a_fetch_add_i32(int *p, int v)           { return __atomic_fetch_add(p, v, __ATOMIC_RELEASE); }
static void     vma_yield(void)                          { sched_yield(); }

static sigjmp_buf g_vma_jmp;
static volatile sig_atomic_t g_vma_armed;
static void vma_sig_handler(int sig) {
    (void)sig;
    if (g_vma_armed) { g_vma_armed = 0; siglongjmp(g_vma_jmp, 1); }
    _exit(128 + sig);
}
static int vma_try_write_byte(volatile unsigned char *p, unsigned char val) {
    struct sigaction sa, old_segv, old_bus;
    int faulted = 0;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = vma_sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);
    if (sigsetjmp(g_vma_jmp, 1) == 0) {
        g_vma_armed = 1;
        *p = val;
        g_vma_armed = 0;
    } else {
        faulted = 1;
    }
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    return faulted;
}
static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}
#define WIN_CHECK(what, a, want) ((void)0)
#endif

#define K 1024ull
static int failed;
static void check(const char *what, int ok) {
    printf("  [%s] %s\n", ok ? " OK " : "FAIL", what);
    if (!ok) failed++;
}
static int64_t sc(int64_t nr, int64_t a0, int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5) {
    int64_t a[6];
    a[0] = a0; a[1] = a1; a[2] = a2; a[3] = a3; a[4] = a4; a[5] = a5;
    return afw_syscall_dispatch(nr, a);
}
#define MMAP(addr, len, prot, flags) sc(9, (int64_t)(addr), (int64_t)(len), prot, flags, -1, 0)
#define MUNMAP(addr, len) sc(11, (int64_t)(addr), (int64_t)(len), 0, 0, 0, 0)
#define MPROTECT(addr, len, prot) sc(10, (int64_t)(addr), (int64_t)(len), prot, 0, 0, 0)
#define MADVISE(addr, len, adv) sc(28, (int64_t)(addr), (int64_t)(len), adv, 0, 0, 0)
#define ANON (LNX_MAP_PRIVATE | LNX_MAP_ANONYMOUS)
#define RW (LNX_PROT_READ | LNX_PROT_WRITE)

static int all_zero(const unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

/* ---- Test 17: C11 data-race-free MT stress workers ---- */
typedef struct {
    uint64_t *slots;      /* disjoint neighbor pages inside the same VMA */
    size_t    nslots;
    int      *ready;
    int      *stop;
    uint64_t  iters;
    int       ok;
} mt_neighbor_arg;

static void mt_neighbor_worker(void *arg) {
    mt_neighbor_arg *a = (mt_neighbor_arg *)arg;
    uint64_t it = 0;
    size_t i;
    int signaled = 0;
    a->ok = 1;
    for (i = 0; i < a->nslots; i++) a_store_u64(&a->slots[i], 0x10000000ULL + i);
    for (;;) {
        size_t idx = (size_t)(it % a->nslots);
        uint64_t expect = 0x10000000ULL + idx + (it / a->nslots);
        uint64_t prev = a_fetch_add_u64(&a->slots[idx], 1ULL);
        if (prev != expect) { a->ok = 0; break; }
        it++;
        if (!signaled) { a_fetch_add_i32(a->ready, 1); signaled = 1; }
        if (a_load_i32(a->stop)) break;
    }
    if (!signaled) a_fetch_add_i32(a->ready, 1);
    a->iters = it;
}

typedef struct {
    int *ready;
    int *stop;
    int  iters;
    int  ok;
} mt_churn_arg;

/* Operates strictly on its own disjoint VMA allocations (never touched by other workers). */
static void mt_disjoint_churn_worker(void *arg) {
    mt_churn_arg *a = (mt_churn_arg *)arg;
    int signaled = 0;
    a->ok = 1;
    a->iters = 0;
    for (;;) {
        int64_t m = MMAP(0, 16 * K, RW, ANON);
        if (m <= 0) { a->ok = 0; break; }
        memset((void *)(uintptr_t)m, 0x5c, 16 * K);
        if (MPROTECT(m, 8 * K, LNX_PROT_READ) != 0 ||
            MADVISE(m, 16 * K, LNX_MADV_DONTNEED) != 0 ||
            !all_zero((const unsigned char *)(uintptr_t)m, 16 * K) ||
            MPROTECT(m, 8 * K, RW) != 0 ||
            MUNMAP(m, 16 * K) != 0) {
            MUNMAP(m, 16 * K);
            a->ok = 0;
            break;
        }
        a->iters++;
        if (!signaled) { a_fetch_add_i32(a->ready, 1); signaled = 1; }
        if (a_load_i32(a->stop)) break;
    }
    if (!signaled) a_fetch_add_i32(a->ready, 1);
}

#if defined(_WIN32)
typedef struct {
    const uint64_t *target;
    int *started;
    const int *stop;
    uint64_t iters;
} g23_asm_arg;

static void g23_asm_worker(void *arg) {
    g23_asm_arg *a = (g23_asm_arg *)arg;
    a_store_i32(a->started, 1);
    g23_asm_read_loop(a->target, a->stop, &a->iters);
}
#endif

int main(void) {
    int64_t b;
    unsigned char *p;
#if defined(_WIN32)
    PVOID veh = AddVectoredExceptionHandler(1, vma_test_veh);
    if (!veh) { printf("ERROR: AddVectoredExceptionHandler failed\n"); return 1; }
    (void)veh;
#endif
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== VMA tests ===\n");

    printf("1. Scudo pattern: reserve 2MB, trim both edges, use the middle\n");
    b = MMAP(0, 2048 * K, 0, ANON | LNX_MAP_NORESERVE);
    check("mmap 2MB PROT_NONE", b > 0);
    WIN_CHECK("PROT_NONE pages are only reserved (no commit charge)", (uint64_t)b, "reserved");
    check("munmap first 64KB", MUNMAP(b, 64 * K) == 0);
    check("munmap last 64KB", MUNMAP(b + 2048 * K - 64 * K, 64 * K) == 0);
    check("mprotect the middle RW", MPROTECT(b + 64 * K, 1920 * K, RW) == 0);
    p = (unsigned char *)(uintptr_t)(b + 64 * K);
    memset(p, 0x5a, 1920 * K);
    check("write and read back the middle", p[0] == 0x5a && p[1920 * K - 1] == 0x5a);
    WIN_CHECK("trimmed edge is decommitted", (uint64_t)b, "reserved");
#if defined(_WIN32)
    {
        uint64_t q;
        int all = 1;
        for (q = (uint64_t)b + 64 * K; q < (uint64_t)b + 1984 * K; q += 4 * K)
            if (strcmp(state(q), "commit-rw") != 0) all = 0;
        check("EVERY page of the middle is committed RW (all 480 checked)", all);
    }
#endif
    check("munmap the middle", MUNMAP(b + 64 * K, 1920 * K) == 0);
    check("whole Windows allocation released", afw_vma_alloc_count() == 0);
    WIN_CHECK("address range is free again", (uint64_t)b, "free");

    printf("2. Guard pages around an active page\n");
    b = MMAP(0, 256 * K, 0, ANON);
    check("mprotect one middle page RW", MPROTECT(b + 128 * K, 4 * K, RW) == 0);
    WIN_CHECK("middle page committed RW", (uint64_t)b + 128 * K, "commit-rw");
    WIN_CHECK("page before stays reserved", (uint64_t)b + 124 * K, "reserved");
    WIN_CHECK("page after stays reserved", (uint64_t)b + 132 * K, "reserved");
    MUNMAP(b, 256 * K);

    printf("3. MADV_DONTNEED reads back zeros, mapping stays\n");
    b = MMAP(0, 64 * K, RW, ANON);
    p = (unsigned char *)(uintptr_t)b;
    memset(p, 0xab, 64 * K);
    check("madvise(DONTNEED)", MADVISE(b, 64 * K, LNX_MADV_DONTNEED) == 0);
    check("all bytes are zero", all_zero(p, 64 * K));
    p[100] = 7;
    check("still mapped and writable", p[100] == 7);
    check("other advice (MADV_WILLNEED) accepted", MADVISE(b, 64 * K, 3) == 0);
    MUNMAP(b, 64 * K);

    printf("4. MAP_FIXED over part of a reservation\n");
    b = MMAP(0, 128 * K, 0, ANON);
    check("MAP_FIXED one RW page at +4KB", MMAP(b + 4 * K, 4 * K, RW, ANON | LNX_MAP_FIXED) == b + 4 * (int64_t)K);
    p = (unsigned char *)(uintptr_t)(b + 4 * K);
    check("the page is zeroed and usable", all_zero(p, 4 * K) && (p[0] = 1, p[0] == 1));
    WIN_CHECK("the rest stays reserved", (uint64_t)b + 64 * K, "reserved");
    MUNMAP(b, 128 * K);

    printf("5. Partial munmap at start / middle / end, then remap the hole\n");
    b = MMAP(0, 64 * K, RW, ANON);
    p = (unsigned char *)(uintptr_t)b;
    memset(p, 0x11, 64 * K);
    check("munmap first page", MUNMAP(b, 4 * K) == 0);
    check("munmap a middle page", MUNMAP(b + 32 * K, 4 * K) == 0);
    check("munmap last page", MUNMAP(b + 60 * K, 4 * K) == 0);
    WIN_CHECK("middle hole is decommitted", (uint64_t)b + 32 * K, "reserved");
    check("neighbours keep their data", p[4 * K] == 0x11 && p[36 * K] == 0x11 && p[59 * K] == 0x11);
    check("MAP_FIXED into the middle hole", MMAP(b + 32 * K, 4 * K, RW, ANON | LNX_MAP_FIXED) == b + 32 * (int64_t)K);
    check("remapped hole is zeroed", all_zero(p + 32 * K, 4 * K));
    check("mprotect over a hole fails with ENOMEM", MPROTECT(b, 8 * K, RW) == -12);
    MUNMAP(b, 64 * K);
    check("allocation released after everything is unmapped", afw_vma_alloc_count() == 0);

    printf("6. PROT_NONE keeps contents (it is not a decommit)\n");
    b = MMAP(0, 16 * K, RW, ANON);
    p = (unsigned char *)(uintptr_t)b;
    memset(p, 0x77, 16 * K);
    check("mprotect PROT_NONE", MPROTECT(b, 16 * K, 0) == 0);
    WIN_CHECK("pages committed but inaccessible", (uint64_t)b, "commit-none");
    check("mprotect back to RW", MPROTECT(b, 16 * K, RW) == 0);
    check("data survived", p[0] == 0x77 && p[16 * K - 1] == 0x77);
    check("partial mprotect read-only", MPROTECT(b + 4 * K, 4 * K, LNX_PROT_READ) == 0);
    WIN_CHECK("only that page is read-only", (uint64_t)b + 4 * K, "commit-r");
    WIN_CHECK("its neighbour stays RW", (uint64_t)b, "commit-rw");
    MUNMAP(b, 16 * K);

    printf("7. MAP_FIXED over a page that has content\n");
    b = MMAP(0, 16 * K, RW, ANON);
    p = (unsigned char *)(uintptr_t)b;
    memset(p, 0xaa, 16 * K);
    check("MAP_FIXED over the second page", MMAP(b + 4 * K, 4 * K, RW, ANON | LNX_MAP_FIXED) == b + 4 * (int64_t)K);
    check("that page is zeroed", all_zero(p + 4 * K, 4 * K));
    check("neighbours unchanged", p[0] == 0xaa && p[4 * K - 1] == 0xaa && p[8 * K] == 0xaa);
    MUNMAP(b, 16 * K);

    printf("8. PROT_NONE page, then MADV_DONTNEED, then RW again\n");
    b = MMAP(0, 8 * K, RW, ANON);
    p = (unsigned char *)(uintptr_t)b;
    memset(p, 0x33, 8 * K);
    MPROTECT(b, 8 * K, 0);
    check("madvise(DONTNEED) on PROT_NONE pages", MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0);
    WIN_CHECK("page dropped back to reserved (no commit charge)", (uint64_t)b, "reserved");
    check("mprotect RW again", MPROTECT(b, 8 * K, RW) == 0);
    check("contents are zero, not the old 0x33", all_zero(p, 8 * K));
    MUNMAP(b, 8 * K);

    printf("9. Small mapping: the rest of Windows' 64KB granule is not exposed\n");
    b = MMAP(0, 4 * K, RW, ANON);
    WIN_CHECK("the mapped page is committed", (uint64_t)b, "commit-rw");
    WIN_CHECK("the next 4KB is not part of any reservation", (uint64_t)b + 4 * K, "free");
    MUNMAP(b, 4 * K);

    printf("10. Arguments\n");
    check("length overflow -> EINVAL (munmap, mprotect, madvise)",
          MUNMAP(0x10000, (int64_t)(UINT64_MAX - 100)) == -22 &&
          MPROTECT(0x10000, (int64_t)(UINT64_MAX - 100), RW) == -22 &&
          MADVISE(0x10000, (int64_t)(UINT64_MAX - 100), LNX_MADV_DONTNEED) == -22);
    check("address + length overflow -> EINVAL", MUNMAP((int64_t)(UINT64_MAX - 0xfff), 0x2000) == -22);
    check("unaligned address -> EINVAL", MUNMAP(4097, 4096) == -22 && MPROTECT(4097, 4096, RW) == -22);
    check("zero length mmap -> EINVAL", MMAP(0, 0, RW, ANON) == -22);
    b = MMAP(0, 100, RW, ANON);
    check("length rounded up to a page", b > 0 && (((unsigned char *)(uintptr_t)b)[4095] = 1) == 1);
    MUNMAP(b, 100);
    check("filemap rejects PROT_WRITE -> ENOSYS, PROT_EXEC -> EACCES, bad fd -> EBADF",
          sc(9, 0, 4096, RW, LNX_MAP_PRIVATE, 3, 0) == -38 &&
          sc(9, 0, 4096, LNX_PROT_READ | LNX_PROT_EXEC, LNX_MAP_PRIVATE, 3, 0) == -13 &&
          sc(9, 0, 4096, LNX_PROT_READ, LNX_MAP_PRIVATE, 3, 0) == -9);
    check("prctl(PR_SET_VMA) accepted", sc(157, 0x53564d41, 0, 0, 0, 0, 0) == 0);

    printf("11. 64GB PROT_NONE reservation (Scudo arena scale: <1s, <1MB metadata)\n");
    {
        uint64_t g64 = 64ull * 1024 * 1024 * 1024;
        uint64_t g16 = 16ull * 1024 * 1024 * 1024;
        uint64_t g32 = 32ull * 1024 * 1024 * 1024;
        double t0 = now_ms(), dt;
        size_t meta;
        b = MMAP(0, g64, 0, ANON | LNX_MAP_NORESERVE);
        dt = now_ms() - t0;
        meta = afw_vma_meta_bytes();
        printf("    64GB PROT_NONE: %.2f ms, metadata %zu bytes, extents %zu\n",
               dt, meta, afw_vma_extent_count());
        check("mmap 64GB PROT_NONE succeeded", b > 0);
        check("completed in < 1000 ms", dt < 1000.0);
        check("metadata < 1MB", meta < 1024 * 1024);
        check("represented as a single extent", afw_vma_extent_count() == 1);
        if (b > 0) {
            WIN_CHECK("start is reserved", (uint64_t)b, "reserved");
            WIN_CHECK("middle is reserved", (uint64_t)b + g32, "reserved");
            check("mprotect 64KB slice at +32GB RW", MPROTECT((uint64_t)b + g32, 64 * K, RW) == 0);
            p = (unsigned char *)(uintptr_t)((uint64_t)b + g32);
            p[0] = 0x5c; p[64 * K - 1] = 0x3d;
            check("slice at +32GB is writable", p[0] == 0x5c && p[64 * K - 1] == 0x3d);
            WIN_CHECK("slice at +32GB is committed RW", (uint64_t)b + g32, "commit-rw");
            WIN_CHECK("neighbour page stays reserved", (uint64_t)b + g32 - 4 * K, "reserved");
            check("trim first 16GB and last 16GB",
                  MUNMAP(b, g16) == 0 && MUNMAP((uint64_t)b + g64 - g16, g16) == 0);
            t0 = now_ms();
            check("munmap over 16GB already-unmapped hole succeeds quickly",
                  MUNMAP(b, g16) == 0 && (now_ms() - t0) < 1000.0);
            check("metadata still < 1MB after slicing", afw_vma_meta_bytes() < 1024 * 1024);
            check("munmap remaining middle 32GB", MUNMAP((uint64_t)b + g16, g32) == 0);
            check("64GB allocation fully released", afw_vma_alloc_count() == 0 && afw_vma_extent_count() == 0);
            WIN_CHECK("64GB range is free again", (uint64_t)b, "free");
        }
    }

    printf("12. Coalescing of OS calls and extents\n");
    {
        uint64_t c0, c1;
        c0 = afw_vma_os_call_count();
        b = MMAP(0, 2048 * K, 0, ANON);
        c1 = afw_vma_os_call_count();
        check("2MB PROT_NONE: 1 OS call (reserve) and 1 extent",
              b > 0 && (c1 - c0) == 1 && afw_vma_extent_count() == 1);
        c0 = afw_vma_os_call_count();
        check("mprotect 480 pages (1920KB) RW succeeds", MPROTECT(b + 64 * K, 1920 * K, RW) == 0);
        c1 = afw_vma_os_call_count();
        printf("    480-page mprotect used %llu OS call(s)\n", (unsigned long long)(c1 - c0));
        check("480-page mprotect coalesced into 1 OS call", (c1 - c0) == 1);
        check("split into 3 extents [res, RW, res]", afw_vma_extent_count() == 3);
        c0 = afw_vma_os_call_count();
        check("redundant mprotect with same prot makes 0 OS calls",
              MPROTECT(b + 64 * K, 1920 * K, RW) == 0 && afw_vma_os_call_count() == c0);
        check("sub-range mprotect RO creates 5 extents",
              MPROTECT(b + 128 * K, 64 * K, LNX_PROT_READ) == 0 && afw_vma_extent_count() == 5);
        check("restoring RW coalesces back to 3 extents",
              MPROTECT(b + 128 * K, 64 * K, RW) == 0 && afw_vma_extent_count() == 3);
        c0 = afw_vma_os_call_count();
        check("munmap whole 2MB releases allocation in <= 2 OS calls",
              MUNMAP(b, 2048 * K) == 0 && (afw_vma_os_call_count() - c0) <= 2 &&
              afw_vma_alloc_count() == 0 && afw_vma_extent_count() == 0);
    }

    printf("13. OS failure injection and MAP_FIXED_NOREPLACE\n");
    {
#ifdef AFW_TEST
        /* 13a: commit fails on a fresh mmap(RW) -> reservation rolled back */
        afw_vma_test_fail_os(2);   /* 1 = os_reserve succeeds, 2 = os_commit fails */
        check("mmap(RW) rolls back reservation when commit fails",
              MMAP(0, 64 * K, RW, ANON) == -12 && afw_vma_alloc_count() == 0);
        afw_vma_test_fail_os(0);

        /* 13b: multi-extent mprotect fails on 2nd OS call */
        b = MMAP(0, 16 * K, 0, ANON);
        check("prepare [RO, reserved, reserved, reserved]", MPROTECT(b, 4 * K, LNX_PROT_READ) == 0);
        afw_vma_test_fail_os(2);   /* 1 = os_protect(RO->RW) ok, 2 = os_commit(res->RW) fails */
        check("mprotect across [RO, reserved] returns ENOMEM on 2nd OS call",
              MPROTECT(b, 8 * K, RW) == -12);
        afw_vma_test_fail_os(0);
        p = (unsigned char *)(uintptr_t)b;
        p[0] = 0x42;
        check("first extent truthfully became RW", p[0] == 0x42);
        WIN_CHECK("first extent is commit-rw", (uint64_t)b, "commit-rw");
        WIN_CHECK("second extent stayed reserved", (uint64_t)b + 4 * K, "reserved");
        check("retry mprotect(8K, RW) commits second extent cleanly", MPROTECT(b, 8 * K, RW) == 0);
        check("first extent kept 0x42, second extent is zeroed", p[0] == 0x42 && all_zero(p + 4 * K, 4 * K));
        MUNMAP(b, 16 * K);

        /* 13c: MADV_DONTNEED fault injection (G2-3):
         *  - PROT_READ upgrade fail -> stays RO & untouched
         *  - PROT_READ restore fail -> zeroed, metadata truthfully stays RW until mprotect(RO)
         *  - PROT_NONE decommit fail -> stays committed PROT_NONE, retry decommits */
        b = MMAP(0, 8 * K, RW, ANON);
        p = (unsigned char *)(uintptr_t)b;
        memset(p, 0x99, 8 * K);
        MPROTECT(b, 8 * K, LNX_PROT_READ);
        afw_vma_test_fail_os(1);
        check("madvise(DONTNEED) on PROT_READ returns ENOMEM when RW upgrade fails (stays RO & 0x99)",
              MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == -12 && p[0] == 0x99 &&
              vma_try_write_byte((volatile unsigned char *)p, 0x11) == 1);
        afw_vma_test_fail_os(0);
        WIN_CHECK("stayed commit-r after upgrade failure", (uint64_t)b, "commit-r");

        afw_vma_test_fail_os(2);   /* 1 = upgrade RW ok, memset(0) runs, 2 = restore RO fails */
        check("madvise(DONTNEED) on PROT_READ returns ENOMEM when RO restore fails (zeroed, metadata truthful)",
              MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == -12 && all_zero(p, 8 * K));
        afw_vma_test_fail_os(0);
        WIN_CHECK("metadata & OS truthfully commit-rw after restore failure", (uint64_t)b, "commit-rw");
        check("mprotect(PROT_READ) afterwards restores read-only cleanly",
              MPROTECT(b, 8 * K, LNX_PROT_READ) == 0 &&
              vma_try_write_byte((volatile unsigned char *)p, 0x22) == 1);
        WIN_CHECK("restored to commit-r", (uint64_t)b, "commit-r");
        MUNMAP(b, 8 * K);

        b = MMAP(0, 8 * K, RW, ANON);
        p = (unsigned char *)(uintptr_t)b;
        memset(p, 0x88, 8 * K);
        MPROTECT(b, 8 * K, 0);
        afw_vma_test_fail_os(1);
        check("madvise(DONTNEED) on PROT_NONE returns ENOMEM when os_decommit fails",
              MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == -12);
        afw_vma_test_fail_os(0);
        WIN_CHECK("stayed commit-none after decommit failure", (uint64_t)b, "commit-none");
        check("retry madvise(DONTNEED) on PROT_NONE decommits cleanly and zeroes on recommit",
              MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0 && MPROTECT(b, 8 * K, RW) == 0 && all_zero(p, 8 * K));
        MUNMAP(b, 8 * K);
#endif

        /* 13d: MAP_FIXED_NOREPLACE rejects mapped ranges and accepts holes */
        b = MMAP(0, 16 * K, RW, ANON);
        check("MAP_FIXED_NOREPLACE over mapped page -> EEXIST",
              MMAP(b + 4 * K, 4 * K, RW, ANON | LNX_MAP_FIXED_NOREPLACE) == -17);
        check("munmap hole, then MAP_FIXED_NOREPLACE succeeds",
              MUNMAP(b + 4 * K, 4 * K) == 0 &&
              MMAP(b + 4 * K, 4 * K, RW, ANON | LNX_MAP_FIXED_NOREPLACE) == b + 4 * (int64_t)K);
        MUNMAP(b, 16 * K);

#ifdef AFW_TEST
        /* 13e: MAP_FIXED over committed page where decommit succeeds and commit fails */
        b = MMAP(0, 8 * K, RW, ANON);
        p = (unsigned char *)(uintptr_t)b;
        memset(p, 0xdd, 8 * K);
        afw_vma_test_fail_os(2);   /* 1 = os_decommit ok, 2 = os_commit fails */
        check("MAP_FIXED over live page returns ENOMEM when recommit fails",
              MMAP(b, 4 * K, RW, ANON | LNX_MAP_FIXED) == -12);
        afw_vma_test_fail_os(0);
        WIN_CHECK("first page truthfully dropped to reserved", (uint64_t)b, "reserved");
        WIN_CHECK("second page stayed committed RW", (uint64_t)b + 4 * K, "commit-rw");
        check("second page kept its data", p[4 * K] == 0xdd);
        check("retry MAP_FIXED succeeds and zeroes first page",
              MMAP(b, 4 * K, RW, ANON | LNX_MAP_FIXED) == b && all_zero(p, 4 * K) && p[4 * K] == 0xdd);
        MUNMAP(b, 8 * K);
#endif
        check("all test-13 allocations released", afw_vma_alloc_count() == 0);
    }

    printf("14. Multiple allocations: sorted lookup and hole validation\n");
    {
        uint64_t s[3], tmp;
        int i, j;
        int64_t a1 = MMAP(0, 16 * K, RW, ANON);
        int64_t a2 = MMAP(0, 16 * K, RW, ANON);
        int64_t a3 = MMAP(0, 16 * K, RW, ANON);
        check("three allocations live", a1 > 0 && a2 > 0 && a3 > 0 && afw_vma_alloc_count() == 3);
        s[0] = (uint64_t)a1; s[1] = (uint64_t)a2; s[2] = (uint64_t)a3;
        for (i = 0; i < 3; i++)
            for (j = i + 1; j < 3; j++)
                if (s[j] < s[i]) { tmp = s[i]; s[i] = s[j]; s[j] = tmp; }
        /* Unmap the middle allocation to guarantee a gap between s[0] and s[2]. */
        check("unmap middle allocation to create a guaranteed gap", MUNMAP(s[1], 16 * K) == 0);
        check("mprotect spanning gap between s[0] and s[2] fails with ENOMEM",
              MPROTECT(s[0], (s[2] - s[0]) + 4 * K, LNX_PROT_READ) == -12);
        ((unsigned char *)(uintptr_t)s[0])[0] = 0x7e;
        check("s[0] stayed writable (not partially mutated)",
              ((unsigned char *)(uintptr_t)s[0])[0] == 0x7e);
        check("munmap remaining two allocations",
              MUNMAP(s[2], 16 * K) == 0 && MUNMAP(s[0], 16 * K) == 0);
        check("zero allocations and extents remain",
              afw_vma_alloc_count() == 0 && afw_vma_extent_count() == 0);
    }

    printf("15. Adopted ELF library (issue #12): WriteProtected mprotect, RELRO, stub isolation\n");
    {
        /* Simulate elf_loader: 4-page image [R, RX, RW (GOT/RELRO), RW (.bss)] + 64KB RX stub reserve */
        size_t img_sz = 16 * K, stub_sz = 64 * K;
        unsigned char *img = (unsigned char *)afw_mem_alloc(img_sz + stub_sz);
        uint64_t ibase = (uint64_t)(uintptr_t)img;
        uint64_t bss = ibase + 12 * K;
        uint64_t stub = ibase + img_sz;
        unsigned char lnx_prot[4] = {
            LNX_PROT_READ,
            LNX_PROT_READ | LNX_PROT_EXEC,
            RW,
            RW
        };
        uint64_t c0;
        check("allocated simulated library + stub reserve", img != NULL);
        if (img) {
            img[12 * K] = 0x55;
            img[12 * K + 4095] = 0x66;
            check("loader set initial segment and stub protections",
                  afw_mem_protect(img, 4 * K, AFW_PROT_R) == 0 &&
                  afw_mem_protect(img + 4 * K, 4 * K, AFW_PROT_R | AFW_PROT_X) == 0 &&
                  afw_mem_protect(img + 8 * K, 8 * K, AFW_PROT_R | AFW_PROT_W) == 0 &&
                  afw_mem_protect(img + img_sz, stub_sz, AFW_PROT_R | AFW_PROT_X) == 0);

            /* Before adopt: exact failure from issue #12 */
            check("before adopt: mprotect on .bss fails with ENOMEM",
                  MPROTECT(bss, 4 * K, LNX_PROT_READ) == -12);

            c0 = afw_vma_os_call_count();
            check("afw_vma_adopt succeeds with 0 OS calls and 3 normalized extents [R, RX, RW]",
                  afw_vma_adopt(ibase, img_sz, lnx_prot) == 0 &&
                  afw_vma_os_call_count() == c0 &&
                  afw_vma_alloc_count() == 1 && afw_vma_extent_count() == 3);

            /* Re-adopt after RELRO (page 2 RW -> R) BEFORE any Linux VMA call succeeds */
            check("loader applies RELRO to page 2", afw_mem_protect(img + 8 * K, 4 * K, AFW_PROT_R) == 0);
            lnx_prot[2] = LNX_PROT_READ;
            c0 = afw_vma_os_call_count();
            check("re-adopt after RELRO (before Linux VMA calls) updates extents to 4 [R, RX, R, RW]",
                  afw_vma_adopt(ibase, img_sz, lnx_prot) == 0 &&
                  afw_vma_os_call_count() == c0 && afw_vma_extent_count() == 4);

            /* libc WriteProtected<libc_globals>: partial mprotect RW -> RO on .bss
             * (all pages stay mapped and committed), then re-adopt MUST be refused. */
            check("WriteProtected lock: mprotect(.bss, PROT_READ) succeeds",
                  MPROTECT(bss, 4 * K, LNX_PROT_READ) == 0);
            WIN_CHECK(".bss is now commit-r", bss, "commit-r");
            check("page 2 + .bss coalesced to 3 extents [R, RX, R]", afw_vma_extent_count() == 3);
            check("re-adopt after partial Linux mprotect is refused with -EINVAL (reviewer 2)",
                  afw_vma_adopt(ibase, img_sz, lnx_prot) == -22);
            c0 = afw_vma_os_call_count();
            check("refused re-adopt left metadata intact (3 extents, .bss still PROT_READ -> 0 OS calls)",
                  afw_vma_extent_count() == 3 &&
                  MPROTECT(bss, 4 * K, LNX_PROT_READ) == 0 &&
                  afw_vma_os_call_count() == c0);
            WIN_CHECK(".bss stayed commit-r after refused re-adopt", bss, "commit-r");

            check("WriteProtected unlock: mprotect(.bss, RW) succeeds",
                  MPROTECT(bss, 4 * K, RW) == 0);
            WIN_CHECK(".bss is back to commit-rw", bss, "commit-rw");
            check(".bss contents survived RO->RW and are writable",
                  img[12 * K] == 0x55 && img[12 * K + 4095] == 0x66 && ((img[12 * K] = 0x77) == 0x77));

            /* Stub reserve stays invisible and protected from Linux syscalls */
            check("mprotect on stub area fails with ENOMEM", MPROTECT(stub, 4 * K, RW) == -12);
            check("mprotect spanning image end + stub area fails with ENOMEM (no partial change)",
                  MPROTECT(bss, 8 * K, LNX_PROT_READ) == -12);
            WIN_CHECK(".bss stayed commit-rw", bss, "commit-rw");
            WIN_CHECK("stub area stayed commit-rx", stub, "commit-rx");

            /* Decommit via PROT_NONE + MADV_DONTNEED: still mapped, not committed -> re-adopt refused */
            check("decommit .bss via PROT_NONE + MADV_DONTNEED",
                  MPROTECT(bss, 4 * K, 0) == 0 && MADVISE(bss, 4 * K, LNX_MADV_DONTNEED) == 0);
            WIN_CHECK(".bss dropped to reserved", bss, "reserved");
            check("re-adopt after decommit is refused with -EINVAL (reviewer 2 contract)",
                  afw_vma_adopt(ibase, img_sz, lnx_prot) == -22);

            /* Even full munmap of image (+ overshoot into stub) must NOT release VirtualAlloc or touch stub */
            check("munmap across image + stub decommits image only", MUNMAP(ibase, img_sz + stub_sz) == 0);
            WIN_CHECK("image page is decommitted (reserved)", ibase, "reserved");
            WIN_CHECK("stub area is STILL commit-rx after full image munmap", stub, "commit-rx");
            check("re-adopt after munmap is refused with -EINVAL (reviewer 2 contract)",
                  afw_vma_adopt(ibase, img_sz, lnx_prot) == -22);
            check("mprotect on unmapped image still fails with -ENOMEM after refused re-adopt",
                  MPROTECT(ibase, 4 * K, RW) == -12);

            /* Interior forget and partial-overlap adopt must be refused */
            check("partial-overlap adopt refused with -EEXIST",
                  afw_vma_adopt(ibase + 4 * K, 4 * K, lnx_prot) == -17);
            check("forget on interior address refused with -EINVAL",
                  afw_vma_forget(ibase + 4 * K) == -22 && afw_vma_alloc_count() == 1);

            /* Discard/unload: afw_vma_forget removes tracking with 0 OS calls, idempotent */
            c0 = afw_vma_os_call_count();
            check("afw_vma_forget removes adopted entry with 0 OS calls",
                  afw_vma_forget(ibase) == 0 && afw_vma_os_call_count() == c0 &&
                  afw_vma_alloc_count() == 0 && afw_vma_extent_count() == 0);
            check("second afw_vma_forget is a safe no-op", afw_vma_forget(ibase) == 0);
            WIN_CHECK("stub area still exists until loader calls afw_mem_free", stub, "commit-rx");
            afw_mem_free(img, img_sz + stub_sz);
            WIN_CHECK("whole allocation free after loader afw_mem_free", ibase, "free");
        }

        /* Argument & ownership guards */
        check("adopt rejects bad args (null, unaligned, zero, overflow)",
              afw_vma_adopt(0, 4 * K, lnx_prot) == -22 &&
              afw_vma_adopt(0x10001, 4 * K, lnx_prot) == -22 &&
              afw_vma_adopt(0x10000, 0, lnx_prot) == -22 &&
              afw_vma_adopt(0x10000, 100, lnx_prot) == -22 &&
              afw_vma_adopt(0x10000, 4 * K, NULL) == -22 &&
              afw_vma_adopt(UINT64_MAX - 0xfff, 8 * K, lnx_prot) == -22);
        b = MMAP(0, 8 * K, RW, ANON);
        check("adopt rejects overlapping a VMA-owned mmap (-EEXIST)",
              afw_vma_adopt((uint64_t)b, 8 * K, lnx_prot) == -17);
        check("forget refuses to drop a VMA-owned mmap (-EINVAL)",
              afw_vma_forget((uint64_t)b) == -22 && afw_vma_alloc_count() == 1);
        MUNMAP(b, 8 * K);
        check("zero allocations remain after test 15", afw_vma_alloc_count() == 0);
    }

    printf("16. G2-3 MADV_DONTNEED semantics (RW in-place zero, PROT_READ, PROT_NONE, reserve, MAP_SHARED)\n");
    {
        uint64_t c0;

        /* 16a: Writable private anon -> in-place memset(0), 0 OS calls (no decommit window) */
        b = MMAP(0, 16 * K, RW, ANON);
        p = (unsigned char *)(uintptr_t)b;
        memset(p, 0xab, 16 * K);
        c0 = afw_vma_os_call_count();
        check("RW MADV_DONTNEED zeroes in place with 0 OS calls",
              MADVISE(b, 16 * K, LNX_MADV_DONTNEED) == 0 &&
              afw_vma_os_call_count() == c0 &&
              all_zero(p, 16 * K));
        WIN_CHECK("RW stayed commit-rw after MADV_DONTNEED", (uint64_t)b, "commit-rw");
        MUNMAP(b, 16 * K);

        /* 16b: Anonymous PROT_READ -> temporary RW upgrade, zero, restore RO + write faults */
        b = MMAP(0, 8 * K, RW, ANON);
        p = (unsigned char *)(uintptr_t)b;
        memset(p, 0xcd, 8 * K);
        check("mprotect anonymous to PROT_READ and verify write faults",
              MPROTECT(b, 8 * K, LNX_PROT_READ) == 0 &&
              vma_try_write_byte((volatile unsigned char *)p, 0x01) == 1);
        check("PROT_READ MADV_DONTNEED zeroes range and restores write protection",
              MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0 &&
              all_zero(p, 8 * K) &&
              vma_try_write_byte((volatile unsigned char *)p, 0x02) == 1);
        WIN_CHECK("PROT_READ stayed commit-r after MADV_DONTNEED", (uint64_t)b, "commit-r");
        MUNMAP(b, 8 * K);

        /* 16c: Committed PROT_NONE -> os_decommit drops back to reserved, recommit reads zeros */
        b = MMAP(0, 8 * K, RW, ANON);
        p = (unsigned char *)(uintptr_t)b;
        memset(p, 0xef, 8 * K);
        check("mprotect RW -> PROT_NONE keeps commit", MPROTECT(b, 8 * K, 0) == 0);
        WIN_CHECK("PROT_NONE is commit-none before MADV_DONTNEED", (uint64_t)b, "commit-none");
        check("MADV_DONTNEED on committed PROT_NONE succeeds",
              MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0);
        WIN_CHECK("PROT_NONE dropped to reserved after MADV_DONTNEED", (uint64_t)b, "reserved");
        check("mprotect PROT_NONE -> RW recommits fresh zeros",
              MPROTECT(b, 8 * K, RW) == 0 && all_zero(p, 8 * K));
        WIN_CHECK("recommitted back to commit-rw", (uint64_t)b, "commit-rw");
        MUNMAP(b, 8 * K);

        /* 16d: Uncommitted MEM_RESERVE -> 0 OS calls, stays reserved */
        b = MMAP(0, 16 * K, 0, ANON | LNX_MAP_NORESERVE);
        WIN_CHECK("fresh PROT_NONE is reserved", (uint64_t)b, "reserved");
        c0 = afw_vma_os_call_count();
        check("MADV_DONTNEED on reserved range is a 0-OS-call no-op",
              MADVISE(b, 16 * K, LNX_MADV_DONTNEED) == 0 &&
              afw_vma_os_call_count() == c0);
        WIN_CHECK("still reserved after MADV_DONTNEED", (uint64_t)b, "reserved");
        MUNMAP(b, 16 * K);

        /* 16e: MAP_SHARED | MAP_ANONYMOUS -> MADV_DONTNEED is a safe no-op (never zeroes) */
        b = MMAP(0, 8 * K, RW, LNX_MAP_SHARED | LNX_MAP_ANONYMOUS);
        check("MAP_SHARED | MAP_ANONYMOUS succeeds", b > 0);
        if (b > 0) {
            p = (unsigned char *)(uintptr_t)b;
            memset(p, 0x77, 8 * K);
            c0 = afw_vma_os_call_count();
            check("MADV_DONTNEED on MAP_SHARED anon RW returns 0 and preserves bytes",
                  MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0 &&
                  afw_vma_os_call_count() == c0 &&
                  p[0] == 0x77 && p[8 * K - 1] == 0x77);
            check("MADV_DONTNEED on MAP_SHARED anon after mprotect(RO) still preserves bytes",
                  MPROTECT(b, 8 * K, LNX_PROT_READ) == 0 &&
                  MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0 &&
                  p[0] == 0x77 && p[8 * K - 1] == 0x77);
            MUNMAP(b, 8 * K);
        }
        check("anon mmap rejects missing or conflicting MAP_SHARED/MAP_PRIVATE (-EINVAL)",
              MMAP(0, 4 * K, RW, LNX_MAP_ANONYMOUS) == -22 &&
              MMAP(0, 4 * K, RW, LNX_MAP_SHARED | LNX_MAP_PRIVATE | LNX_MAP_ANONYMOUS) == -22);

        /* 16f: Single MADV_DONTNEED across mixed states [res, PROT_NONE(commit), RO, RX, RW, SHARED] */
        b = MMAP(0, 24 * K, 0, ANON | LNX_MAP_NORESERVE);
        p = (unsigned char *)(uintptr_t)b;
        check("16f: setup 6-page mixed-state allocation",
              b > 0 &&
              MPROTECT(b + 4 * K, 16 * K, RW) == 0 &&
              (memset(p + 4 * K, 0x44, 16 * K), 1) &&
              MPROTECT(b + 4 * K, 4 * K, 0) == 0 &&
              MPROTECT(b + 8 * K, 4 * K, LNX_PROT_READ) == 0 &&
              MPROTECT(b + 12 * K, 4 * K, LNX_PROT_READ | LNX_PROT_EXEC) == 0 &&
              MMAP(b + 20 * K, 4 * K, RW, LNX_MAP_SHARED | LNX_MAP_ANONYMOUS | LNX_MAP_FIXED) == b + 20 * (int64_t)K &&
              (memset(p + 20 * K, 0x99, 4 * K), 1));
        check("16f: private RW page 4 and shared RW page 5 did NOT coalesce (6 extents)",
              afw_vma_extent_count() == 6);
        check("16f: single MADV_DONTNEED across all 6 mixed pages succeeds",
              MADVISE(b, 24 * K, LNX_MADV_DONTNEED) == 0);
        WIN_CHECK("16f: page 0 stayed reserved", (uint64_t)b, "reserved");
        WIN_CHECK("16f: page 1 (PROT_NONE) dropped to reserved", (uint64_t)b + 4 * K, "reserved");
        WIN_CHECK("16f: page 2 stayed commit-r", (uint64_t)b + 8 * K, "commit-r");
        WIN_CHECK("16f: page 3 stayed commit-rx", (uint64_t)b + 12 * K, "commit-rx");
        WIN_CHECK("16f: page 4 stayed commit-rw", (uint64_t)b + 16 * K, "commit-rw");
        WIN_CHECK("16f: page 5 (MAP_SHARED) stayed commit-rw", (uint64_t)b + 20 * K, "commit-rw");
        check("16f: private RO/RX/RW pages zeroed, RO/RX write-fault, shared page kept 0x99",
              all_zero(p + 8 * K, 12 * K) &&
              vma_try_write_byte((volatile unsigned char *)(p + 8 * K), 1) == 1 &&
              vma_try_write_byte((volatile unsigned char *)(p + 12 * K), 1) == 1 &&
              p[20 * K] == 0x99 && p[24 * K - 1] == 0x99);
        MUNMAP(b, 24 * K);

#if defined(_WIN32) && defined(AFW_TEST)
        /* 16g: Windows MEM_WRITE_WATCH integration (Reviewer 2 & Reviewer 3 conditions) */
        {
            /* Scope: owned VMA_ANON has WW=1; adopted region has WW=0 */
            unsigned char *adp = (unsigned char *)afw_mem_alloc(4 * K);
            unsigned char aprot[1] = { RW };
            int adp_ok = (adp != NULL && afw_vma_adopt((uint64_t)(uintptr_t)adp, 4 * K, aprot) == 0);
            int adp_ww = adp_ok ? afw_vma_test_ww_active((uint64_t)(uintptr_t)adp) : -1;
            int adp_fg = adp_ok ? afw_vma_forget((uint64_t)(uintptr_t)adp) : -1;
            check("16g: adopted allocation does NOT enable write_watch",
                  adp_ok && adp_ww == 0 && adp_fg == 0);
            if (adp) afw_mem_free(adp, 4 * K);

            /* Untouched 32MB RW VMA: MADV_DONTNEED keeps Working Set flat (<2MB delta) */
            {
                const uint64_t SZ32 = 32ULL * 1024ULL * 1024ULL;
                PROCESS_MEMORY_COUNTERS_EX pm1, pm2;
                int64_t ws_delta;
                memset(&pm1, 0, sizeof pm1); pm1.cb = sizeof pm1;
                memset(&pm2, 0, sizeof pm2); pm2.cb = sizeof pm2;
                b = MMAP(0, SZ32, RW, ANON);
                check("16g: 32MB owned VMA_ANON has write_watch active",
                      b > 0 && afw_vma_test_ww_active((uint64_t)b) == 1);
                GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pm1, sizeof pm1);
                check("16g: MADV_DONTNEED on untouched 32MB succeeds",
                      MADVISE(b, SZ32, LNX_MADV_DONTNEED) == 0);
                GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pm2, sizeof pm2);
                ws_delta = (int64_t)pm2.WorkingSetSize - (int64_t)pm1.WorkingSetSize;
                printf("  [info] 16g untouched 32MB delta_WS = %lld bytes\n", (long long)ws_delta);
                check("16g: untouched 32MB MADV_DONTNEED did not inflate Working Set (<2MB)",
                      ws_delta < (int64_t)(2ULL * 1024ULL * 1024ULL));
                MUNMAP(b, SZ32);
            }

            /* Evicted dirty pages (EmptyWorkingSet -> QueryWorkingSetEx Valid=0) still zeroed */
            {
                PSAPI_WORKING_SET_EX_INFORMATION wsi[16];
                int i, valid_cnt = 0;
                b = MMAP(0, 64 * K, RW, ANON);
                p = (unsigned char *)(uintptr_t)b;
                for (i = 0; i < 16; i++) p[(size_t)i * 4 * K] = 0x5a;
                EmptyWorkingSet(GetCurrentProcess());
                memset(wsi, 0, sizeof wsi);
                for (i = 0; i < 16; i++) wsi[i].VirtualAddress = p + (size_t)i * 4 * K;
                if (QueryWorkingSetEx(GetCurrentProcess(), wsi, sizeof wsi)) {
                    for (i = 0; i < 16; i++) if (wsi[i].VirtualAttributes.Valid) valid_cnt++;
                }
                check("16g: EmptyWorkingSet evicted dirty pages (QueryWorkingSetEx Valid == 0)",
                      valid_cnt == 0);
                check("16g: MADV_DONTNEED still zeroes all 16 evicted dirty pages via write_watch",
                      MADVISE(b, 64 * K, LNX_MADV_DONTNEED) == 0 && all_zero(p, 64 * K));
                MUNMAP(b, 64 * K);
            }

            /* Lifecycle: MAP_FIXED + partial munmap + PROT_READ|PROT_EXEC + PROT_NONE decommit */
            b = MMAP(0, 16 * K, RW, ANON);
            p = (unsigned char *)(uintptr_t)b;
            memset(p, 0x33, 16 * K);
            check("16g: MAP_FIXED over dirty page 1 zeroes page 1 and keeps write_watch active",
                  MMAP(b + 4 * K, 4 * K, RW, ANON | LNX_MAP_FIXED) == b + 4 * (int64_t)K &&
                  all_zero(p + 4 * K, 4 * K) && p[0] == 0x33 && p[8 * K] == 0x33 &&
                  afw_vma_test_ww_active((uint64_t)b) == 1);
            check("16g: partial munmap + MAP_FIXED remap on page 2 keeps write_watch active",
                  MUNMAP(b + 8 * K, 4 * K) == 0 &&
                  MMAP(b + 8 * K, 4 * K, RW, ANON | LNX_MAP_FIXED) == b + 8 * (int64_t)K &&
                  all_zero(p + 8 * K, 4 * K) && afw_vma_test_ww_active((uint64_t)b) == 1);
            check("16g: mprotect(PROT_READ|PROT_EXEC) on MEM_WRITE_WATCH page succeeds (Reviewer 3)",
                  MPROTECT(b, 4 * K, LNX_PROT_READ | LNX_PROT_EXEC) == 0);
            WIN_CHECK("16g: page 0 is commit-rx under MEM_WRITE_WATCH", (uint64_t)b, "commit-rx");
            check("16g: MADV_DONTNEED across RX + RW zeroes all pages and preserves RX",
                  MADVISE(b, 16 * K, LNX_MADV_DONTNEED) == 0 && all_zero(p, 16 * K));
            WIN_CHECK("16g: page 0 stayed commit-rx after MADV_DONTNEED", (uint64_t)b, "commit-rx");
            p[12 * K] = 0x88;
            check("16g: PROT_NONE + MADV_DONTNEED decommits & resets WW, recommit is zeroed",
                  MPROTECT(b + 12 * K, 4 * K, 0) == 0 &&
                  MADVISE(b + 12 * K, 4 * K, LNX_MADV_DONTNEED) == 0 &&
                  afw_vma_test_ww_active((uint64_t)b) == 1 &&
                  MPROTECT(b + 12 * K, 4 * K, RW) == 0 &&
                  all_zero(p + 12 * K, 4 * K));
            MUNMAP(b, 16 * K);

            /* Fail-closed: GetWriteWatch failure MUST still zero pages and disable WW */
            b = MMAP(0, 8 * K, RW, ANON);
            p = (unsigned char *)(uintptr_t)b;
            memset(p, 0x77, 8 * K);
            afw_vma_test_fail_ww(1);
            check("16g: GetWriteWatch failure falls back to memset(0) and disables WW",
                  MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0 &&
                  all_zero(p, 8 * K) &&
                  afw_vma_test_ww_active((uint64_t)b) == 0);
            afw_vma_test_fail_ww(0);
            memset(p, 0x78, 8 * K);
            check("16g: subsequent MADV_DONTNEED after WW disable still zeroes cleanly",
                  MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0 && all_zero(p, 8 * K));
            MUNMAP(b, 8 * K);

            /* Fail-closed: ResetWriteWatch failure on recommit disables WW cleanly */
            b = MMAP(0, 8 * K, RW, ANON);
            p = (unsigned char *)(uintptr_t)b;
            memset(p, 0x66, 8 * K);
            MPROTECT(b, 8 * K, 0);
            check("16g: PROT_NONE + MADV_DONTNEED decommits cleanly and keeps WW active",
                  MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0 &&
                  afw_vma_test_ww_active((uint64_t)b) == 1);
            WIN_CHECK("16g: dropped to reserved before recommit", (uint64_t)b, "reserved");
            afw_vma_test_fail_ww(1);
            check("16g: ResetWriteWatch failure on recommit disables WW fail-closed",
                  MPROTECT(b, 8 * K, RW) == 0 &&
                  afw_vma_test_ww_active((uint64_t)b) == 0);
            afw_vma_test_fail_ww(0);
            check("16g: dirty + MADV_DONTNEED still zeroes after ResetWriteWatch disable",
                  (memset(p, 0x55, 8 * K), 1) &&
                  MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == 0 && all_zero(p, 8 * K));
            MUNMAP(b, 8 * K);
        }
#endif

        check("zero allocations remain after test 16", afw_vma_alloc_count() == 0);
    }

    printf("17. G2-3 C11 data-race-free MT stress (disjoint neighbor pages + VMA churn under g_lock)\n");
    {
        afw_os_thread t1, t2, t3;
        mt_neighbor_arg n1, n2;
        mt_churn_arg ch;
        int ready = 0, stop = 0;
        int iter, main_ok = 1, slots_ok = 1;
        size_t i, nslots = (16 * K) / sizeof(uint64_t);
        double t0 = now_ms(), elapsed;

        b = MMAP(0, 64 * K, RW, ANON);
        p = (unsigned char *)(uintptr_t)b;
        check("allocated 64KB (16-page) VMA for MT stress", b > 0);

        n1.slots = (uint64_t *)(uintptr_t)b;                 /* pages 0..3 */
        n1.nslots = nslots;
        n1.ready = &ready;
        n1.stop = &stop;
        n1.iters = 0;
        n1.ok = 0;

        n2.slots = (uint64_t *)(uintptr_t)(b + 48 * K);      /* pages 12..15 */
        n2.nslots = nslots;
        n2.ready = &ready;
        n2.stop = &stop;
        n2.iters = 0;
        n2.ok = 0;

        ch.ready = &ready;
        ch.stop = &stop;
        ch.iters = 0;
        ch.ok = 0;

        check("spawned 2 neighbor workers + 1 disjoint VMA churn worker",
              afw_os_thread_start(mt_neighbor_worker, &n1, &t1) == 0 &&
              afw_os_thread_start(mt_neighbor_worker, &n2, &t2) == 0 &&
              afw_os_thread_start(mt_disjoint_churn_worker, &ch, &t3) == 0);

        while (a_load_i32(&ready) < 3) vma_yield();

        /* Main thread exclusively touches middle pages 4..11 (never 0..3 or 12..15). */
        for (iter = 0; iter < 200; iter++) {
            memset(p + 16 * K, 0xa5, 32 * K);
            if ((iter % 10) == 0) {
                int64_t r1 = MPROTECT(b + 16 * K, 32 * K, LNX_PROT_READ);
                int64_t r2 = (r1 == 0) ? MADVISE(b + 16 * K, 32 * K, LNX_MADV_DONTNEED) : -1;
                int z = (r2 == 0) ? all_zero(p + 16 * K, 32 * K) : 0;
                int64_t r3 = (r1 == 0) ? MPROTECT(b + 16 * K, 32 * K, RW) : -1;
                if (r1 != 0 || r2 != 0 || !z || r3 != 0) {
                    printf("  [diag] Test 17 RO iter=%d r1=%lld r2=%lld z=%d r3=%lld b0=0x%02x\n",
                           iter, (long long)r1, (long long)r2, z, (long long)r3, p[16 * K]);
                    main_ok = 0;
                    break;
                }
            } else {
                int64_t r2 = MADVISE(b + 16 * K, 32 * K, LNX_MADV_DONTNEED);
                int z = (r2 == 0) ? all_zero(p + 16 * K, 32 * K) : 0;
                if (r2 != 0 || !z) {
                    printf("  [diag] Test 17 RW iter=%d r2=%lld z=%d b0=0x%02x\n",
                           iter, (long long)r2, z, p[16 * K]);
                    main_ok = 0;
                    break;
                }
            }
        }

        a_store_i32(&stop, 1);
        check("all 3 worker threads joined cleanly",
              afw_os_thread_join(t1) == 0 &&
              afw_os_thread_join(t2) == 0 &&
              afw_os_thread_join(t3) == 0);
        elapsed = now_ms() - t0;

        for (i = 0; i < nslots; i++) {
            uint64_t exp1 = 0x10000000ULL + i + (n1.iters / nslots) + (i < (n1.iters % nslots) ? 1ULL : 0ULL);
            uint64_t exp2 = 0x10000000ULL + i + (n2.iters / nslots) + (i < (n2.iters % nslots) ? 1ULL : 0ULL);
            if (n1.slots[i] != exp1 || n2.slots[i] != exp2) {
                slots_ok = 0;
                break;
            }
        }

        printf("  [info] MT stress: %.1f ms, n1=%llu iters, n2=%llu iters, churn=%d iters\n",
               elapsed, (unsigned long long)n1.iters, (unsigned long long)n2.iters, ch.iters);
        check("main MADV_DONTNEED loop (RW + PROT_READ) passed 200 iterations", main_ok);
        check("neighbor workers ran with 0 corruption on adjacent pages",
              n1.ok && n2.ok && n1.iters > 0 && n2.iters > 0 && slots_ok);
        check("disjoint VMA churn worker ran cleanly under g_lock contention",
              ch.ok && ch.iters > 0);
        check("middle pages are zeroed and cleanup leaves 0 allocations",
              all_zero(p + 16 * K, 32 * K) && MUNMAP(b, 64 * K) == 0 && afw_vma_alloc_count() == 0);
    }

#if defined(_WIN32)
    printf("18. G2-3 Windows platform assembly same-page fault-absence probe (NOT C11 memory model)\n");
    {
        afw_os_thread tr;
        g23_asm_arg arg;
        int started = 0, stop = 0;
        int iter, madv_ok = 1;
        double t0 = now_ms(), elapsed;

        b = MMAP(0, 16 * K, RW, ANON);
        p = (unsigned char *)(uintptr_t)b;
        check("allocated 16KB RW VMA for same-page asm fault-absence probe", b > 0);

        InterlockedExchange(&g_g23_faults, 0);
        InterlockedExchange64(&g_g23_watch_hi, (LONG64)((uint64_t)b + 16 * K));
        InterlockedExchange64(&g_g23_watch_lo, (LONG64)(uint64_t)b);

        arg.target = (const uint64_t *)(uintptr_t)(b + 4 * K);
        arg.started = &started;
        arg.stop = &stop;
        arg.iters = 0;
        check("spawned x86-64 asm reader on same page as MADV_DONTNEED",
              afw_os_thread_start(g23_asm_worker, &arg, &tr) == 0);

        while (!a_load_i32(&started)) vma_yield();

        for (iter = 0; iter < 2000; iter++) {
            if (MADVISE(b, 16 * K, LNX_MADV_DONTNEED) != 0) {
                madv_ok = 0;
                break;
            }
        }

        a_store_i32(&stop, 1);
        check("asm reader thread joined cleanly", afw_os_thread_join(tr) == 0);
        elapsed = now_ms() - t0;

        InterlockedExchange64(&g_g23_watch_lo, 0);
        InterlockedExchange64(&g_g23_watch_hi, 0);

        printf("  [info] asm probe: %.1f ms, reader=%llu loads, VEH faults=%ld\n",
               elapsed, (unsigned long long)arg.iters,
               (long)InterlockedCompareExchange(&g_g23_faults, 0, 0));
        check("2000 MADV_DONTNEED calls with concurrent same-page asm loads had 0 faults",
              madv_ok && arg.iters > 0 && InterlockedCompareExchange(&g_g23_faults, 0, 0) == 0);
        check("post-barrier range is all zero and cleanup leaves 0 allocations",
              MADVISE(b, 16 * K, LNX_MADV_DONTNEED) == 0 &&
              all_zero(p, 16 * K) &&
              MUNMAP(b, 16 * K) == 0 &&
              afw_vma_alloc_count() == 0);
    }
#endif

    printf("\n%s\n", failed ? "VMA TESTS FAILED" : "VMA TESTS PASSED");
    return failed ? 1 : 0;
}
