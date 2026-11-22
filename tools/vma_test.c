/*
 * vma_test.c - unit tests for the VMA layer (src/vma.c), driven through the
 * syscall dispatcher, the same path Android code takes. On Windows the state
 * of every page is also checked with VirtualQuery.
 * Cases from reviewers 2 and 3 (round 7).
 */
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
    return "commit-other";
}
#define WIN_CHECK(what, a, want) check(what, strcmp(state(a), want) == 0)
#else
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

    printf("7. Arguments\n");
    check("unaligned address -> EINVAL", MUNMAP(4097, 4096) == -22 && MPROTECT(4097, 4096, RW) == -22);
    check("zero length mmap -> EINVAL", MMAP(0, 0, RW, ANON) == -22);
    b = MMAP(0, 100, RW, ANON);
    check("length rounded up to a page", b > 0 && (((unsigned char *)(uintptr_t)b)[4095] = 1) == 1);
    MUNMAP(b, 100);
    check("file mappings not supported yet -> ENODEV", sc(9, 0, 4096, RW, LNX_MAP_PRIVATE, 3, 0) == -19);
    check("prctl(PR_SET_VMA) accepted", sc(157, 0x53564d41, 0, 0, 0, 0, 0) == 0);

    printf("\n%s\n", failed ? "VMA TESTS FAILED" : "VMA TESTS PASSED");
    return failed ? 1 : 0;
}
