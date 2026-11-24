/*
 * vma_test.c - unit tests for the VMA layer (src/vma.c), driven through the
 * syscall dispatcher, the same path Android code takes. On Windows the state
 * of every page is also checked with VirtualQuery.
 * Cases from reviewers 2 and 3 (round 7).
 */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#include <time.h>
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

int main(void) {
    int64_t b;
    unsigned char *p;
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

        /* 13c: MADV_DONTNEED decommit succeeds, recommit fails -> metadata drops P_COMMIT */
        b = MMAP(0, 8 * K, RW, ANON);
        p = (unsigned char *)(uintptr_t)b;
        memset(p, 0x99, 8 * K);
        afw_vma_test_fail_os(2);   /* 1 = os_decommit ok, 2 = os_commit fails */
        check("madvise(DONTNEED) returns ENOMEM when recommit fails",
              MADVISE(b, 8 * K, LNX_MADV_DONTNEED) == -12);
        afw_vma_test_fail_os(0);
        WIN_CHECK("dropped back to reserved after recommit failure", (uint64_t)b, "reserved");
        /* If metadata had falsely kept P_COMMIT, Windows would call VirtualProtect
         * on MEM_RESERVE here and fail; committing proves metadata is truthful. */
        check("mprotect(RW) afterwards commits cleanly with zeros",
              MPROTECT(b, 8 * K, RW) == 0 && all_zero(p, 8 * K));
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

    printf("\n%s\n", failed ? "VMA TESTS FAILED" : "VMA TESTS PASSED");
    return failed ? 1 : 0;
}
