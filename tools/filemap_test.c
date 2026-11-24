/*
 * filemap_test.c - Gate G2-2 tests for read-only file-backed mmap (src/filemap.c + src/vma.c).
 *
 * Runs identically on Linux (under ASan + UBSan + pointer-compare) and Windows:
 *   1. MAP_SHARED | PROT_READ (Bionic /dev/__properties__ map_fd_ro pattern) and MAP_PRIVATE | PROT_READ
 *   2. Partial final page zero-padding past EOF up to 4KB page end
 *   3. Non-64KB-aligned 4KB offsets (delta > 0): PAGE_NOACCESS on prefix + full munmap releases view
 *   4. 0-byte file: succeeds without CreateFileMappingW failure; reads fault cleanly
 *   5. Partial munmap on VMA_FILEMAP: middle faults (PAGE_NOACCESS), sides remain readable,
 *      idempotent re-unmap, MAP_FIXED/MAP_FIXED_NOREPLACE, full unmap releases view
 *   6. Transactional rollback under AFW_TEST fault injection (Phase-1 metadata OOM & Phase-2 OS fail)
 *   7. unlink() + close(fd) while mapped (FILE_SHARE_DELETE)
 *   8. Deterministic negative error codes (PROT_EXEC -> -EACCES, PROT_WRITE -> -ENOSYS,
 *      O_WRONLY -> -EACCES, bad fd -> -EBADF, stdio/dir -> -ENODEV, bad off/len/flags -> -EINVAL,
 *      past-EOF whole pages -> -ENOSYS)
 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "../src/fd.h"
#include "../src/platform.h"
#include "../src/syscall.h"
#include "../src/vma.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#endif

#define PG 4096ULL
#define LNX_AT_FDCWD (-100)
#define LNX_AT_REMOVEDIR 0x200

#define LNX_EBADF  9
#define LNX_ENOMEM 12
#define LNX_EACCES 13
#define LNX_EEXIST 17
#define LNX_ENODEV 19
#define LNX_EINVAL 22
#define LNX_ENOSYS 38

static int g_pass, g_fail;

static void check(const char *msg, int ok) {
    printf("  [%s] %s\n", ok ? " OK " : "FAIL", msg);
    if (ok) g_pass++;
    else    g_fail++;
}

static int64_t sc(int64_t nr, int64_t a0, int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5) {
    int64_t a[6] = {a0, a1, a2, a3, a4, a5};
    return afw_syscall_dispatch(nr, a);
}

#define MMAP_F(a, l, p, f, fd, o) sc(9, (int64_t)(a), (int64_t)(l), (p), (f), (fd), (o))
#define MUNMAP(a, l)              sc(11, (int64_t)(a), (int64_t)(l), 0, 0, 0, 0)
#define MPROTECT(a, l, p)         sc(10, (int64_t)(a), (int64_t)(l), (p), 0, 0, 0)
#define MADVISE(a, l, adv)        sc(28, (int64_t)(a), (int64_t)(l), (adv), 0, 0, 0)

/* ---- Fault probing (returns 1 if faulted, 0 if access succeeded) ---- */
#if defined(_WIN32)
extern char fm_read_fault[], fm_read_recover[], fm_write_fault[], fm_write_recover[];
int fm_probe_read(const volatile unsigned char *p, unsigned char *out);
int fm_probe_write(volatile unsigned char *p, unsigned char val);

__asm__(
    ".att_syntax prefix\n"
    ".text\n"
    ".globl fm_probe_read\n"
    ".globl fm_read_fault\n"
    ".globl fm_read_recover\n"
    "fm_probe_read:\n\t"
    "fm_read_fault:\n\t"
    "movzbl (%rcx), %eax\n\t"
    "test %rdx, %rdx\n\t"
    "jz 1f\n\t"
    "movb %al, (%rdx)\n"
    "1:\n\t"
    "xor %eax, %eax\n\t"
    "ret\n"
    "fm_read_recover:\n\t"
    "mov $1, %eax\n\t"
    "ret\n"

    ".globl fm_probe_write\n"
    ".globl fm_write_fault\n"
    ".globl fm_write_recover\n"
    "fm_probe_write:\n\t"
    "fm_write_fault:\n\t"
    "movb %dl, (%rcx)\n\t"
    "xor %eax, %eax\n\t"
    "ret\n"
    "fm_write_recover:\n\t"
    "mov $1, %eax\n\t"
    "ret\n"
    ".intel_syntax noprefix\n"
);

static LONG CALLBACK fm_veh_handler(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_IN_PAGE_ERROR)
        return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ContextRecord->Rip == (DWORD64)(uintptr_t)fm_read_fault) {
        ep->ContextRecord->Rip = (DWORD64)(uintptr_t)fm_read_recover;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (ep->ContextRecord->Rip == (DWORD64)(uintptr_t)fm_write_fault) {
        ep->ContextRecord->Rip = (DWORD64)(uintptr_t)fm_write_recover;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int try_read_byte(const volatile unsigned char *p, unsigned char *out) {
    return fm_probe_read(p, out);
}

static int try_write_byte(volatile unsigned char *p, unsigned char val) {
    return fm_probe_write(p, val);
}
#else
static sigjmp_buf g_fault_jmp;
static volatile sig_atomic_t g_fault_armed;

static void fault_sig_handler(int sig) {
    (void)sig;
    if (g_fault_armed) {
        g_fault_armed = 0;
        siglongjmp(g_fault_jmp, 1);
    }
    _exit(128 + sig);
}

static int try_read_byte(const volatile unsigned char *p, unsigned char *out) {
    struct sigaction sa, old_segv, old_bus;
    int faulted = 0;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fault_sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);
    if (sigsetjmp(g_fault_jmp, 1) == 0) {
        g_fault_armed = 1;
        unsigned char v = *p;
        g_fault_armed = 0;
        if (out) *out = v;
    } else {
        faulted = 1;
    }
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    return faulted;
}

static int try_write_byte(volatile unsigned char *p, unsigned char val) {
    struct sigaction sa, old_segv, old_bus;
    int faulted = 0;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fault_sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);
    if (sigsetjmp(g_fault_jmp, 1) == 0) {
        g_fault_armed = 1;
        *p = val;
        g_fault_armed = 0;
    } else {
        faulted = 1;
    }
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    return faulted;
}
#endif

static unsigned char pattern_byte(size_t off) {
    size_t pg = off / 4096;
    return (unsigned char)(((pg * 37u) + (off & 0xffu) + 1u) & 0xffu);
}

static int create_pattern_file(const char *path, size_t len) {
    unsigned char *buf = len ? (unsigned char *)malloc(len) : NULL;
    size_t i;
    int64_t fd, wr;
    if (len && !buf) return -1;
    for (i = 0; i < len; i++) buf[i] = pattern_byte(i);
    fd = afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDWR | AFW_O_CREAT | AFW_O_TRUNC, 0644);
    if (fd < 0) { free(buf); return -1; }
    if (len) {
        wr = afw_fd_write(fd, buf, len);
        free(buf);
        if (wr != (int64_t)len) { afw_fd_close(fd); return -1; }
    }
    afw_fd_close(fd);
    return 0;
}

static int verify_pattern(const unsigned char *p, size_t file_off, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        if (p[i] != pattern_byte(file_off + i)) return 0;
    return 1;
}

static int verify_zeros(const unsigned char *p, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        if (p[i] != 0) return 0;
    return 1;
}

int main(void) {
    const char *f_data   = "out/filemap_test_data.bin";
    const char *f_empty  = "out/filemap_test_empty.bin";
    const char *f_unlink = "out/filemap_test_unlink.bin";
    const char *d_dir    = "out/filemap_test_dir";
    const size_t data_len = 131072 + 5000; /* 2 x 64KB + 1 full page + 904B partial page */
    int64_t fd, b;
    unsigned char ch = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
#if defined(_WIN32)
    {
        PVOID veh = AddVectoredExceptionHandler(1, fm_veh_handler);
        if (!veh) { printf("ERROR: AddVectoredExceptionHandler failed\n"); return 1; }
        (void)veh;
    }
#endif
    printf("=== filemap_test: Gate G2-2 read-only file-backed mmap ===\n");

    afw_fd_unlinkat(LNX_AT_FDCWD, f_data, 0);
    afw_fd_unlinkat(LNX_AT_FDCWD, f_empty, 0);
    afw_fd_unlinkat(LNX_AT_FDCWD, f_unlink, 0);
    afw_fd_unlinkat(LNX_AT_FDCWD, d_dir, LNX_AT_REMOVEDIR);

    check("setup: create 136072-byte pattern file", create_pattern_file(f_data, data_len) == 0);
    check("setup: create 0-byte empty file", create_pattern_file(f_empty, 0) == 0);
    check("setup: create 16384-byte unlink-while-mapped file", create_pattern_file(f_unlink, 16384) == 0);

    /* 1. MAP_SHARED | PROT_READ (Bionic map_fd_ro pattern) + partial final page zero tail */
    printf("1. MAP_SHARED | PROT_READ, MAP_PRIVATE | PROT_READ, partial tail, MADV_DONTNEED no-op\n");
    fd = afw_fd_openat(LNX_AT_FDCWD, f_data, AFW_O_RDONLY, 0);
    check("open pattern file O_RDONLY", fd >= 3);

    b = MMAP_F(0, data_len, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 0);
    check("MAP_SHARED | PROT_READ full file succeeds", b > 0 && ((uint64_t)b & (PG - 1)) == 0);
    if (b > 0) {
        const unsigned char *p = (const unsigned char *)(uintptr_t)b;
        check("MAP_SHARED bytes [0..136072) match file content", verify_pattern(p, 0, data_len));
        check("partial final page tail [136072..139264) reads as zeros",
              verify_zeros(p + data_len, 139264 - data_len));
        check("writing to PROT_READ filemap faults", try_write_byte((volatile unsigned char *)p, 0x99) == 1);
        check("MADV_DONTNEED on MAP_SHARED filemap returns 0 and keeps file content",
              MADVISE(b, data_len, LNX_MADV_DONTNEED) == 0 && verify_pattern(p, 0, 4096));
        check("full munmap releases view (alloc_count == 0)",
              MUNMAP(b, data_len) == 0 && afw_vma_alloc_count() == 0);
    }

    b = MMAP_F(0, 16384, LNX_PROT_READ, LNX_MAP_PRIVATE, (int)fd, 0);
    check("MAP_PRIVATE | PROT_READ succeeds and matches file",
          b > 0 && verify_pattern((const unsigned char *)(uintptr_t)b, 0, 16384));
    if (b > 0) {
        check("MADV_DONTNEED on MAP_PRIVATE filemap returns 0 and keeps file content",
              MADVISE(b, 16384, LNX_MADV_DONTNEED) == 0 &&
              verify_pattern((const unsigned char *)(uintptr_t)b, 0, 16384));
        check("munmap MAP_PRIVATE releases view",
              MUNMAP(b, 16384) == 0 && afw_vma_alloc_count() == 0);
    }

    /* PROT_NONE -> mprotect(PROT_READ) -> mprotect(PROT_NONE) */
    b = MMAP_F(0, 8192, 0, LNX_MAP_SHARED, (int)fd, 0);
    check("MAP_SHARED | PROT_NONE succeeds and initial read faults",
          b > 0 && try_read_byte((const volatile unsigned char *)(uintptr_t)b, &ch) == 1);
    if (b > 0) {
        check("mprotect(PROT_READ) makes filemap readable with exact bytes",
              MPROTECT(b, 8192, LNX_PROT_READ) == 0 &&
              verify_pattern((const unsigned char *)(uintptr_t)b, 0, 8192));
        check("mprotect(PROT_NONE) makes filemap fault again",
              MPROTECT(b, 4096, 0) == 0 &&
              try_read_byte((const volatile unsigned char *)(uintptr_t)b, &ch) == 1 &&
              verify_pattern((const unsigned char *)(uintptr_t)(b + 4096), 4096, 4096));
        check("munmap cleans up", MUNMAP(b, 8192) == 0 && afw_vma_alloc_count() == 0);
    }

    /* 2. Non-64KB-aligned 4KB offsets (delta > 0) */
    printf("2. Non-64KB-aligned 4KB offsets (delta prefix PAGE_NOACCESS + logical mapped_bytes)\n");
    b = MMAP_F(0, 3 * PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 4096);
    check("mmap at off=4096 (delta=4096) succeeds and is 4KB-aligned",
          b > 0 && ((uint64_t)b & (PG - 1)) == 0);
    if (b > 0) {
        const unsigned char *p = (const unsigned char *)(uintptr_t)b;
        check("off=4096 content matches file [4096..16384)", verify_pattern(p, 4096, 3 * PG));
        check("leading delta prefix below returned addr faults (PAGE_NOACCESS)",
              try_read_byte((const volatile unsigned char *)(uintptr_t)(b - 1), &ch) == 1 &&
              try_read_byte((const volatile unsigned char *)(uintptr_t)(b - 4096), &ch) == 1);
        check("mprotect on unmapped delta prefix fails with -ENOMEM",
              MPROTECT(b - 4096, 4096, LNX_PROT_READ) == -LNX_ENOMEM);
        check("full munmap(addr, 3*PG) releases entire view including delta (alloc_count == 0)",
              MUNMAP(b, 3 * PG) == 0 && afw_vma_alloc_count() == 0);
    }

    /* Second 64KB chunk + delta=12288 + partial tail page */
    {
        uint64_t off2 = 65536 + 12288; /* 77824 */
        size_t len2 = data_len - (size_t)off2; /* 58248 -> rounds to 61440 (15 pages) */
        size_t round2 = (len2 + PG - 1) & ~(PG - 1);
        b = MMAP_F(0, len2, LNX_PROT_READ, LNX_MAP_PRIVATE, (int)fd, (int64_t)off2);
        check("mmap at off=77824 (delta=12288) through partial EOF page succeeds", b > 0);
        if (b > 0) {
            const unsigned char *p = (const unsigned char *)(uintptr_t)b;
            check("off=77824 data bytes match file and EOF tail is zeroed",
                  verify_pattern(p, (size_t)off2, len2) &&
                  verify_zeros(p + len2, round2 - len2));
            check("delta prefix [addr-12288 .. addr) faults",
                  try_read_byte((const volatile unsigned char *)(uintptr_t)(b - 4096), &ch) == 1 &&
                  try_read_byte((const volatile unsigned char *)(uintptr_t)(b - 12288), &ch) == 1);
            check("full munmap releases view",
                  MUNMAP(b, len2) == 0 && afw_vma_alloc_count() == 0);
        }
    }

    /* 3. 0-byte file */
    printf("3. 0-byte empty file\n");
    {
        int64_t fd0 = afw_fd_openat(LNX_AT_FDCWD, f_empty, AFW_O_RDONLY, 0);
        check("open 0-byte file succeeds", fd0 >= 3);
        b = MMAP_F(0, 2 * PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd0, 0);
        check("mmap 0-byte file succeeds (no CreateFileMappingW failure)", b > 0);
        if (b > 0) {
            check("reading 0-byte file mapping faults cleanly",
                  try_read_byte((const volatile unsigned char *)(uintptr_t)b, &ch) == 1 &&
                  try_read_byte((const volatile unsigned char *)(uintptr_t)(b + PG), &ch) == 1);
            check("mprotect(PROT_READ) keeps 0-byte mapping faulting",
                  MPROTECT(b, PG, LNX_PROT_READ) == 0 &&
                  try_read_byte((const volatile unsigned char *)(uintptr_t)b, &ch) == 1);
            check("mprotect on 0-byte mapping rejects PROT_EXEC (-EACCES) and PROT_WRITE (-ENOSYS)",
                  MPROTECT(b, PG, LNX_PROT_EXEC) == -LNX_EACCES &&
                  MPROTECT(b, PG, LNX_PROT_WRITE) == -LNX_ENOSYS);
            check("madvise(MADV_DONTNEED) on 0-byte mapping returns 0",
                  MADVISE(b, 2 * PG, LNX_MADV_DONTNEED) == 0);
            check("partial munmap then final munmap releases 0-byte mapping",
                  MUNMAP(b, PG) == 0 && afw_vma_alloc_count() == 1 &&
                  MUNMAP(b + PG, PG) == 0 && afw_vma_alloc_count() == 0);
        }
        afw_fd_close(fd0);
    }

    /* 4. Partial munmap on VMA_FILEMAP (including Windows VirtualProtect(PAGE_NOACCESS) check) */
    printf("4. Partial munmap on VMA_FILEMAP (sub-range PAGE_NOACCESS, idempotence, MAP_FIXED)\n");
    b = MMAP_F(0, 4 * PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 4096);
    check("map 4 pages at off=4096", b > 0);
    if (b > 0) {
        check("partial munmap of middle 2 pages succeeds and keeps view alive",
              MUNMAP(b + PG, 2 * PG) == 0 && afw_vma_alloc_count() == 1);
        check("unmapped middle 2 pages fault (PAGE_NOACCESS)",
              try_read_byte((const volatile unsigned char *)(uintptr_t)(b + PG), &ch) == 1 &&
              try_read_byte((const volatile unsigned char *)(uintptr_t)(b + 2 * PG), &ch) == 1);
        check("remaining outer pages (0 and 3) still read exact file bytes",
              verify_pattern((const unsigned char *)(uintptr_t)b, 4096, PG) &&
              verify_pattern((const unsigned char *)(uintptr_t)(b + 3 * PG), 4096 + 3 * PG, PG));
        check("idempotent re-unmap of middle hole returns 0 without underflowing mapped_bytes",
              MUNMAP(b + PG, 2 * PG) == 0 && afw_vma_alloc_count() == 1);
        check("mprotect on partial-munmap hole fails with -ENOMEM (never revives hole)",
              MPROTECT(b + PG, PG, LNX_PROT_READ) == -LNX_ENOMEM &&
              try_read_byte((const volatile unsigned char *)(uintptr_t)(b + PG), &ch) == 1);
        check("MAP_FIXED_NOREPLACE over live page 0 -> -EEXIST",
              MMAP_F(b, PG, LNX_PROT_READ | LNX_PROT_WRITE,
                     LNX_MAP_PRIVATE | LNX_MAP_ANONYMOUS | LNX_MAP_FIXED_NOREPLACE, -1, 0) == -LNX_EEXIST);
        check("MAP_FIXED into filemap hole -> -ENOSYS (documented G2 limit)",
              MMAP_F(b + PG, PG, LNX_PROT_READ | LNX_PROT_WRITE,
                     LNX_MAP_PRIVATE | LNX_MAP_ANONYMOUS | LNX_MAP_FIXED, -1, 0) == -LNX_ENOSYS);
        check("unmap page 0 keeps page 3 live; unmap page 3 releases whole view",
              MUNMAP(b, PG) == 0 && afw_vma_alloc_count() == 1 &&
              verify_pattern((const unsigned char *)(uintptr_t)(b + 3 * PG), 4096 + 3 * PG, PG) &&
              MUNMAP(b + 3 * PG, PG) == 0 && afw_vma_alloc_count() == 0);
    }

    /* 5. Transactional fault injection (Phase-1 metadata OOM & Phase-2 OS VirtualProtect fail) */
#ifdef AFW_TEST
    printf("5. Transactional rollback on metadata OOM and OS VirtualProtect failure (AFW_TEST)\n");
    b = MMAP_F(0, 3 * PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 0);
    check("map 3 pages for fault-injection test", b > 0);
    if (b > 0) {
        uint64_t os_before = afw_vma_os_call_count();
        afw_vma_test_fail_meta(1);
        check("Phase-1 metadata OOM on partial munmap returns -ENOMEM with 0 OS calls",
              MUNMAP(b + PG, PG) == -LNX_ENOMEM && afw_vma_os_call_count() == os_before);
        afw_vma_test_fail_meta(0);
        check("after Phase-1 failure, middle page is still readable and metadata is intact",
              verify_pattern((const unsigned char *)(uintptr_t)(b + PG), PG, PG) &&
              afw_vma_extent_count() == 1);

        afw_vma_test_fail_os(1);
        check("Phase-2 OS VirtualProtect failure on partial munmap returns -ENOMEM",
              MUNMAP(b + PG, PG) == -LNX_ENOMEM);
        afw_vma_test_fail_os(0);
        check("after Phase-2 failure, middle page is still readable and extents coalesced back to 1",
              verify_pattern((const unsigned char *)(uintptr_t)(b + PG), PG, PG) &&
              afw_vma_extent_count() == 1);

        check("retry partial munmap without fault injection succeeds and middle faults",
              MUNMAP(b + PG, PG) == 0 &&
              try_read_byte((const volatile unsigned char *)(uintptr_t)(b + PG), &ch) == 1 &&
              verify_pattern((const unsigned char *)(uintptr_t)b, 0, PG) &&
              verify_pattern((const unsigned char *)(uintptr_t)(b + 2 * PG), 2 * PG, PG));
        check("cleanup fault-injection view",
              MUNMAP(b, 3 * PG) == 0 && afw_vma_alloc_count() == 0);
    }

    /* Multi-run transactional rollback (Reviewer 2): 5 pages [P0, P1(hole), P2, P3, P4],
     * fail the 2nd OS VirtualProtect call -> P0 MUST be rolled back to readable! */
    b = MMAP_F(0, 5 * PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 0);
    check("multi-run rollback: map 5 pages [P0..P4]", b > 0);
    if (b > 0) {
        check("multi-run rollback: unmap P1 to create 2 disjoint mapped runs ([P0] and [P2..P4])",
              MUNMAP(b + PG, PG) == 0 && afw_vma_extent_count() == 3 &&
              try_read_byte((const volatile unsigned char *)(uintptr_t)(b + PG), &ch) == 1);
        afw_vma_test_fail_os(2);
        check("multi-run rollback: munmap(P0..P4) with fail_os(2) returns -ENOMEM",
              MUNMAP(b, 5 * PG) == -LNX_ENOMEM);
        afw_vma_test_fail_os(0);
        check("multi-run rollback: P0 was restored and all originally mapped pages [P0, P2..P4] remain readable",
              verify_pattern((const unsigned char *)(uintptr_t)b, 0, PG) &&
              verify_pattern((const unsigned char *)(uintptr_t)(b + 2 * PG), 2 * PG, 3 * PG));
        check("multi-run rollback: P1 remains an unmapped fault hole and metadata has exact 3 extents",
              try_read_byte((const volatile unsigned char *)(uintptr_t)(b + PG), &ch) == 1 &&
              MPROTECT(b + PG, PG, LNX_PROT_READ) == -LNX_ENOMEM &&
              afw_vma_alloc_count() == 1 && afw_vma_extent_count() == 3);
#if defined(_WIN32)
        {
            MEMORY_BASIC_INFORMATION m0, m1, m2;
            int qok = VirtualQuery((void *)(uintptr_t)b, &m0, sizeof m0) &&
                      VirtualQuery((void *)(uintptr_t)(b + PG), &m1, sizeof m1) &&
                      VirtualQuery((void *)(uintptr_t)(b + 2 * PG), &m2, sizeof m2);
            check("multi-run rollback (Win32 VirtualQuery): P0=PAGE_READONLY, P1=PAGE_NOACCESS, P2=PAGE_READONLY",
                  qok && m0.Protect == PAGE_READONLY && m1.Protect == PAGE_NOACCESS && m2.Protect == PAGE_READONLY);
        }
#endif
        check("multi-run rollback: retry munmap(P0..P4) succeeds and releases view completely",
              MUNMAP(b, 5 * PG) == 0 && afw_vma_alloc_count() == 0);
    }
#endif

    /* 6. unlink() + close(fd) while mapped (FILE_SHARE_DELETE) */
    printf("6. unlink() and close(fd) while mapped (FILE_SHARE_DELETE)\n");
    {
        int64_t fdu = afw_fd_openat(LNX_AT_FDCWD, f_unlink, AFW_O_RDONLY, 0);
        afw_lnx_stat st;
        check("open unlink-test file", fdu >= 3);
        b = MMAP_F(0, 4 * PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fdu, 0);
        check("map unlink-test file", b > 0);
        if (b > 0) {
            check("close(fd) while mapped succeeds", afw_fd_close(fdu) == 0);
            check("unlink() while view is still mapped succeeds (FILE_SHARE_DELETE)",
                  afw_fd_unlinkat(LNX_AT_FDCWD, f_unlink, 0) == 0);
            check("mapped bytes remain readable after close + unlink",
                  verify_pattern((const unsigned char *)(uintptr_t)b, 0, 4 * PG));
            check("munmap releases unlinked view cleanly",
                  MUNMAP(b, 4 * PG) == 0 && afw_vma_alloc_count() == 0);
            check("file is gone after munmap (newfstatat -> -ENOENT)",
                  afw_fd_newfstatat(LNX_AT_FDCWD, f_unlink, &st, 0) == -2);
        } else if (fdu >= 3) {
            afw_fd_close(fdu);
        }
    }

    /* 7. Deterministic negative error codes (Section 5.1 & Rule 6) */
    printf("7. Deterministic negative error codes\n");
    {
        int64_t fd_wo, fd_dir;
        check("PROT_EXEC on filemap -> -EACCES (-13)",
              MMAP_F(0, PG, LNX_PROT_READ | LNX_PROT_EXEC, LNX_MAP_PRIVATE, (int)fd, 0) == -LNX_EACCES &&
              MMAP_F(0, PG, LNX_PROT_EXEC, LNX_MAP_SHARED, (int)fd, 0) == -LNX_EACCES);
        check("PROT_WRITE on filemap -> -ENOSYS (-38)",
              MMAP_F(0, PG, LNX_PROT_READ | LNX_PROT_WRITE, LNX_MAP_PRIVATE, (int)fd, 0) == -LNX_ENOSYS &&
              MMAP_F(0, PG, LNX_PROT_WRITE, LNX_MAP_SHARED, (int)fd, 0) == -LNX_ENOSYS);

        b = MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 0);
        check("mprotect upgrading filemap to PROT_EXEC -> -EACCES, PROT_WRITE -> -ENOSYS",
              b > 0 &&
              MPROTECT(b, PG, LNX_PROT_READ | LNX_PROT_EXEC) == -LNX_EACCES &&
              MPROTECT(b, PG, LNX_PROT_READ | LNX_PROT_WRITE) == -LNX_ENOSYS);
        if (b > 0) MUNMAP(b, PG);

        fd_wo = afw_fd_openat(LNX_AT_FDCWD, f_data, AFW_O_WRONLY, 0);
        check("O_WRONLY fd -> -EACCES (-13)",
              fd_wo >= 3 && MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd_wo, 0) == -LNX_EACCES);
        if (fd_wo >= 3) afw_fd_close(fd_wo);

        check("invalid/closed fd -> -EBADF (-9)",
              MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, -1, 0) == -LNX_EBADF &&
              MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_PRIVATE, 99, 0) == -LNX_EBADF);

        check("stdio fds (0/1/2) -> -ENODEV (-19)",
              MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, 0, 0) == -LNX_ENODEV &&
              MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, 1, 0) == -LNX_ENODEV);

        check("mkdir for directory mmap test", afw_os_mkdir(d_dir, 0755) == 0);
        fd_dir = afw_fd_openat(LNX_AT_FDCWD, d_dir, AFW_O_RDONLY | AFW_O_DIRECTORY, 0);
        check("directory fd -> -ENODEV (-19)",
              fd_dir >= 3 && MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd_dir, 0) == -LNX_ENODEV);
        if (fd_dir >= 3) afw_fd_close(fd_dir);
        afw_fd_unlinkat(LNX_AT_FDCWD, d_dir, LNX_AT_REMOVEDIR);

        check("bad offset/len/flags -> -EINVAL (-22)",
              MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, -4096) == -LNX_EINVAL &&
              MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 123) == -LNX_EINVAL &&
              MMAP_F(0, 0, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 0) == -LNX_EINVAL &&
              MMAP_F(0, PG, LNX_PROT_READ, 0, (int)fd, 0) == -LNX_EINVAL &&
              MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED | LNX_MAP_PRIVATE, (int)fd, 0) == -LNX_EINVAL &&
              MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, (int64_t)(INT64_MAX & ~4095LL)) == -LNX_EINVAL);

        check("MAP_FIXED / MAP_FIXED_NOREPLACE on filemap -> -ENOSYS (-38)",
              MMAP_F(0x100000, PG, LNX_PROT_READ, LNX_MAP_SHARED | LNX_MAP_FIXED, (int)fd, 0) == -LNX_ENOSYS &&
              MMAP_F(0x100000, PG, LNX_PROT_READ, LNX_MAP_PRIVATE | LNX_MAP_FIXED_NOREPLACE, (int)fd, 0) == -LNX_ENOSYS);

        check("whole pages strictly past roundup(file_size, 4096) -> -ENOSYS (-38)",
              MMAP_F(0, 139264 + PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 0) == -LNX_ENOSYS &&
              MMAP_F(0, PG, LNX_PROT_READ, LNX_MAP_SHARED, (int)fd, 139264) == -LNX_ENOSYS);
    }

    afw_fd_close(fd);
    afw_fd_unlinkat(LNX_AT_FDCWD, f_data, 0);
    afw_fd_unlinkat(LNX_AT_FDCWD, f_empty, 0);
    check("zero VMA allocations leaked", afw_vma_alloc_count() == 0);

    printf("\nfilemap_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
