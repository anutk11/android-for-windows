/*
 * g2_dontneed_bench.c - Blocking G2-3 measurement (docs/design/G2-PLAN.md Section 4.2(5)).
 *
 * Measures Working Set (RSS), Commit Charge (PrivateUsage on Windows), and
 * g_lock hold duration (wall-clock ms of afw_madvise) for MADV_DONTNEED on 1GB
 * anonymous mappings across three scenarios:
 *   A. 1GB untouched demand-zero MEM_COMMIT (Reviewer 1's RSS inflation check)
 *   B. 1GB touched MEM_COMMIT (dirty pages zeroed in place; verifies zeros)
 *   C. 1GB touched MEM_COMMIT -> mprotect(PROT_NONE) -> MADV_DONTNEED (decommit path)
 */
#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <time.h>
#endif

#include "../src/syscall.h"
#include "../src/vma.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

typedef struct {
    double ws_mb;
    double commit_mb;
    double peak_ws_mb;
} mem_snap;

static mem_snap take_mem(void) {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    mem_snap s = {0, 0, 0};
    memset(&pmc, 0, sizeof pmc);
    pmc.cb = sizeof pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof pmc)) {
        s.ws_mb      = (double)pmc.WorkingSetSize / (1024.0 * 1024.0);
        s.commit_mb  = (double)pmc.PrivateUsage / (1024.0 * 1024.0);
        s.peak_ws_mb = (double)pmc.PeakWorkingSetSize / (1024.0 * 1024.0);
    }
    return s;
}

static double now_ms(void) {
    LARGE_INTEGER f, t;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1000.0 / (double)f.QuadPart;
}
#else
typedef struct {
    double ws_mb;
    double commit_mb;
    double peak_ws_mb;
} mem_snap;

static mem_snap take_mem(void) {
    mem_snap s = {0, 0, 0};
    FILE *fp = fopen("/proc/self/status", "r");
    char line[256];
    if (!fp) return s;
    while (fgets(line, sizeof line, fp)) {
        unsigned long long kb = 0;
        if (sscanf(line, "VmRSS: %llu kB", &kb) == 1) s.ws_mb = (double)kb / 1024.0;
        else if (sscanf(line, "VmHWM: %llu kB", &kb) == 1) s.peak_ws_mb = (double)kb / 1024.0;
        else if (sscanf(line, "VmData: %llu kB", &kb) == 1) s.commit_mb = (double)kb / 1024.0;
    }
    fclose(fp);
    return s;
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}
#endif

static int64_t sc(int64_t nr, int64_t a0, int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5) {
    int64_t a[6];
    a[0] = a0; a[1] = a1; a[2] = a2; a[3] = a3; a[4] = a4; a[5] = a5;
    return afw_syscall_dispatch(nr, a);
}

#define MMAP(addr, len, prot, flags) sc(9, (int64_t)(addr), (int64_t)(len), prot, flags, -1, 0)
#define MUNMAP(addr, len)            sc(11, (int64_t)(addr), (int64_t)(len), 0, 0, 0, 0)
#define MPROTECT(addr, len, prot)    sc(10, (int64_t)(addr), (int64_t)(len), prot, 0, 0, 0)
#define MADVISE(addr, len, adv)      sc(28, (int64_t)(addr), (int64_t)(len), adv, 0, 0, 0)

#define ANON (LNX_MAP_PRIVATE | LNX_MAP_ANONYMOUS)
#define RW   (LNX_PROT_READ | LNX_PROT_WRITE)

static void print_snap(const char *label, mem_snap m) {
    printf("  %-26s WS=%7.1f MB   Commit=%7.1f MB   PeakWS=%7.1f MB\n",
           label, m.ws_mb, m.commit_mb, m.peak_ws_mb);
}

static int verify_sampled_zeros(const unsigned char *p, size_t len) {
    size_t off;
    /* Check first, last, and every 256th page (4 bytes per sampled page). */
    for (off = 0; off < len; off += 256u * 4096u) {
        if (p[off] != 0 || p[off + 4095] != 0) return 0;
    }
    if (p[len - 1] != 0) return 0;
    return 1;
}

int main(void) {
    const uint64_t ONE_GB = 1024ULL * 1024ULL * 1024ULL;
    const size_t PG = 4096;
    int64_t b;
    unsigned char *p;
    double t0, dt;
    mem_snap m0, m1, m2, m3;
    size_t off;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== G2-3 MADV_DONTNEED 1GB Working Set / Commit / g_lock Benchmark ===\n");

    /* Scenario A: 1GB untouched demand-zero MEM_COMMIT -> MADV_DONTNEED */
    printf("\n[Scenario A] 1GB untouched demand-zero RW MEM_COMMIT -> MADV_DONTNEED\n");
    m0 = take_mem();
    print_snap("before mmap(1GB)", m0);
    b = MMAP(0, ONE_GB, RW, ANON);
    if (b <= 0) { printf("FAIL: mmap(1GB) returned %lld\n", (long long)b); return 1; }
    m1 = take_mem();
    print_snap("after mmap(1GB) untouched", m1);

    t0 = now_ms();
    if (MADVISE(b, ONE_GB, LNX_MADV_DONTNEED) != 0) {
        printf("FAIL: madvise(DONTNEED) failed\n");
        MUNMAP(b, ONE_GB);
        return 1;
    }
    dt = now_ms() - t0;
    m2 = take_mem();
    print_snap("after madvise(DONTNEED)", m2);
    printf("  madvise(1GB untouched):    time=%.2f ms (g_lock hold), delta_WS=%+.1f MB, delta_Commit=%+.1f MB\n",
           dt, m2.ws_mb - m1.ws_mb, m2.commit_mb - m1.commit_mb);

    if (MUNMAP(b, ONE_GB) != 0) { printf("FAIL: munmap failed\n"); return 1; }
    m3 = take_mem();
    print_snap("after munmap(1GB)", m3);

    /* Scenario B-sparse: 1GB RW MEM_COMMIT with only 4MB (1024 pages) touched -> MADV_DONTNEED */
    printf("\n[Scenario B-sparse] 1GB RW MEM_COMMIT, 4MB touched -> MADV_DONTNEED\n");
    b = MMAP(0, ONE_GB, RW, ANON);
    if (b <= 0) { printf("FAIL: mmap(1GB) returned %lld\n", (long long)b); return 1; }
    p = (unsigned char *)(uintptr_t)b;
    for (off = 0; off < 1024u * PG; off += PG) p[off] = 0x77;
    m1 = take_mem();
    print_snap("after touching 4MB/1GB", m1);

    t0 = now_ms();
    if (MADVISE(b, ONE_GB, LNX_MADV_DONTNEED) != 0) {
        printf("FAIL: madvise(DONTNEED) failed\n");
        MUNMAP(b, ONE_GB);
        return 1;
    }
    dt = now_ms() - t0;
    m2 = take_mem();
    print_snap("after madvise(DONTNEED)", m2);
    for (off = 0; off < 1024u * PG; off += PG) {
        if (p[off] != 0) {
            printf("FAIL: sparse dirty page at off=%zu was not zeroed\n", off);
            MUNMAP(b, ONE_GB);
            return 1;
        }
    }
    printf("  madvise(1GB sparse 4MB):   time=%.2f ms (g_lock hold), delta_WS=%+.1f MB, delta_Commit=%+.1f MB, touched_zeros=OK\n",
           dt, m2.ws_mb - m1.ws_mb, m2.commit_mb - m1.commit_mb);
    if (MUNMAP(b, ONE_GB) != 0) { printf("FAIL: munmap failed\n"); return 1; }

    /* Scenario B: 1GB full touched MEM_COMMIT -> MADV_DONTNEED (tests contiguous-chunk fast-path) */
    printf("\n[Scenario B] 1GB full touched (262144 pages) RW MEM_COMMIT -> MADV_DONTNEED\n");
    m0 = take_mem();
    print_snap("before mmap(1GB)", m0);
    b = MMAP(0, ONE_GB, RW, ANON);
    if (b <= 0) { printf("FAIL: mmap(1GB) returned %lld\n", (long long)b); return 1; }
    p = (unsigned char *)(uintptr_t)b;
    for (off = 0; off < (size_t)ONE_GB; off += PG) p[off] = 0x5a;
    m1 = take_mem();
    print_snap("after touching all 262144p", m1);

    t0 = now_ms();
    if (MADVISE(b, ONE_GB, LNX_MADV_DONTNEED) != 0) {
        printf("FAIL: madvise(DONTNEED) failed\n");
        MUNMAP(b, ONE_GB);
        return 1;
    }
    dt = now_ms() - t0;
    m2 = take_mem();
    print_snap("after madvise(DONTNEED)", m2);
    if (!verify_sampled_zeros(p, (size_t)ONE_GB)) {
        printf("FAIL: sampled pages were not zeroed\n");
        MUNMAP(b, ONE_GB);
        return 1;
    }
    printf("  madvise(1GB touched):      time=%.2f ms (g_lock hold), delta_WS=%+.1f MB, delta_Commit=%+.1f MB, sampled_zeros=OK\n",
           dt, m2.ws_mb - m1.ws_mb, m2.commit_mb - m1.commit_mb);

    if (MUNMAP(b, ONE_GB) != 0) { printf("FAIL: munmap failed\n"); return 1; }
    m3 = take_mem();
    print_snap("after munmap(1GB)", m3);

    /* Scenario C: 1GB touched -> PROT_NONE -> MADV_DONTNEED (decommit + ResetWriteWatch) */
    printf("\n[Scenario C] 1GB touched -> mprotect(PROT_NONE) -> MADV_DONTNEED (os_decommit + WW reset)\n");
    b = MMAP(0, ONE_GB, RW, ANON);
    if (b <= 0) { printf("FAIL: mmap(1GB) returned %lld\n", (long long)b); return 1; }
    p = (unsigned char *)(uintptr_t)b;
    for (off = 0; off < (size_t)ONE_GB; off += PG) p[off] = 0x3c;
    if (MPROTECT(b, ONE_GB, 0) != 0) {
        printf("FAIL: mprotect(PROT_NONE) failed\n");
        MUNMAP(b, ONE_GB);
        return 1;
    }
    m1 = take_mem();
    print_snap("after touch + PROT_NONE", m1);

    t0 = now_ms();
    if (MADVISE(b, ONE_GB, LNX_MADV_DONTNEED) != 0) {
        printf("FAIL: madvise(DONTNEED) on PROT_NONE failed\n");
        MUNMAP(b, ONE_GB);
        return 1;
    }
    dt = now_ms() - t0;
    m2 = take_mem();
    print_snap("after madvise(PROT_NONE)", m2);
    printf("  madvise(1GB PROT_NONE):    time=%.2f ms (g_lock hold), delta_WS=%+.1f MB, delta_Commit=%+.1f MB\n",
           dt, m2.ws_mb - m1.ws_mb, m2.commit_mb - m1.commit_mb);

    if (MUNMAP(b, ONE_GB) != 0) { printf("FAIL: munmap failed\n"); return 1; }
    m3 = take_mem();
    print_snap("after munmap(1GB)", m3);

    /* Scenario D: 64GB PROT_NONE Scudo reservation via integrated VMA (with MEM_WRITE_WATCH on Windows) */
    printf("\n[Scenario D] 64GB PROT_NONE Scudo reservation via integrated VMA\n");
    {
        const uint64_t G64 = 64ULL * ONE_GB;
        m0 = take_mem();
        t0 = now_ms();
        b = MMAP(0, G64, 0, ANON | LNX_MAP_NORESERVE);
        dt = now_ms() - t0;
        if (b <= 0) { printf("FAIL: mmap(64GB) returned %lld\n", (long long)b); return 1; }
        m1 = take_mem();
        printf("  mmap(64GB PROT_NONE):      time=%.2f ms, delta_WS=%+.1f MB, delta_Commit=%+.1f MB\n",
               dt, m1.ws_mb - m0.ws_mb, m1.commit_mb - m0.commit_mb);
        if (MUNMAP(b, G64) != 0) { printf("FAIL: munmap(64GB) failed\n"); return 1; }
    }

    if (afw_vma_alloc_count() != 0) {
        printf("FAIL: leaked VMA allocations (%d)\n", afw_vma_alloc_count());
        return 1;
    }

#if defined(_WIN32)
    /* Scenario B-breakdown (Reviewer 2 request): measure get_ms vs memset_ms for
     * 64x16MB chunked GetWriteWatch(0) vs single 1GB GetWriteWatch(0) vs plain memset(1GB). */
    printf("\n[Scenario B-breakdown] 1GB full touched: 64x16MB vs 1x1GB GetWriteWatch(0) vs plain memset\n");
    {
        const SIZE_T NPAGES = (SIZE_T)(ONE_GB / PG);
        const SIZE_T CHUNK_BYTES = 16ULL * 1024ULL * 1024ULL;
        PVOID *addrs = (PVOID *)malloc(NPAGES * sizeof(PVOID));
        unsigned char *w1g = (unsigned char *)VirtualAlloc(NULL, (SIZE_T)ONE_GB,
                                 MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
        unsigned char *plain = (unsigned char *)VirtualAlloc(NULL, (SIZE_T)ONE_GB,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        double get_ms = 0.0, zero_ms = 0.0, t1;
        DWORD gran = 0;
        ULONG_PTR cnt;
        SIZE_T c_off;

        if (!addrs || !w1g || !plain) {
            printf("FAIL: B-breakdown allocation failed (addrs=%p w1g=%p plain=%p)\n",
                   (void *)addrs, (void *)w1g, (void *)plain);
            if (w1g) VirtualFree(w1g, 0, MEM_RELEASE);
            if (plain) VirtualFree(plain, 0, MEM_RELEASE);
            free(addrs);
            return 1;
        }

        /* Touch all 262,144 pages of both 1GB buffers */
        for (off = 0; off < (size_t)ONE_GB; off += PG) w1g[off] = 0x5a;
        for (off = 0; off < (size_t)ONE_GB; off += PG) plain[off] = 0x5a;

        /* B1: 64 x 16MB chunked GetWriteWatch(0) + contiguous memset */
        for (c_off = 0; c_off < (SIZE_T)ONE_GB; c_off += CHUNK_BYTES) {
            cnt = 4096;
            t0 = now_ms();
            if (GetWriteWatch(0, w1g + c_off, CHUNK_BYTES, addrs, &cnt, &gran) != 0 ||
                gran != PG || cnt != 4096) {
                printf("FAIL: B1 chunk GetWriteWatch failed (cnt=%llu gran=%lu)\n",
                       (unsigned long long)cnt, (unsigned long)gran);
                VirtualFree(w1g, 0, MEM_RELEASE);
                VirtualFree(plain, 0, MEM_RELEASE);
                free(addrs);
                return 1;
            }
            t1 = now_ms();
            get_ms += (t1 - t0);
            memset(w1g + c_off, 0, CHUNK_BYTES);
            zero_ms += (now_ms() - t1);
        }
        printf("  B1 (64x16MB WW):           total=%.2f ms (GetWriteWatch=%.2f ms, memset=%.2f ms)\n",
               get_ms + zero_ms, get_ms, zero_ms);

        /* Re-dirty all 262,144 pages */
        for (off = 0; off < (size_t)ONE_GB; off += PG) w1g[off] = 0x5b;

        /* B2: single 1GB GetWriteWatch(0) + single 1GB memset */
        cnt = NPAGES;
        t0 = now_ms();
        if (GetWriteWatch(0, w1g, (SIZE_T)ONE_GB, addrs, &cnt, &gran) != 0 ||
            gran != PG || cnt != NPAGES) {
            printf("FAIL: B2 single-call GetWriteWatch failed (cnt=%llu gran=%lu)\n",
                   (unsigned long long)cnt, (unsigned long)gran);
            VirtualFree(w1g, 0, MEM_RELEASE);
            VirtualFree(plain, 0, MEM_RELEASE);
            free(addrs);
            return 1;
        }
        t1 = now_ms();
        get_ms = t1 - t0;
        memset(w1g, 0, (SIZE_T)ONE_GB);
        zero_ms = now_ms() - t1;
        printf("  B2 (1x1GB single-call WW): total=%.2f ms (GetWriteWatch=%.2f ms, memset=%.2f ms)\n",
               get_ms + zero_ms, get_ms, zero_ms);

        /* B3: control — plain MEM_COMMIT (no MEM_WRITE_WATCH) memset(1GB) on same runner */
        t0 = now_ms();
        memset(plain, 0, (SIZE_T)ONE_GB);
        dt = now_ms() - t0;
        printf("  B3 (plain control, no WW): total=%.2f ms (memset only)\n", dt);

        VirtualFree(w1g, 0, MEM_RELEASE);
        VirtualFree(plain, 0, MEM_RELEASE);
        free(addrs);
    }
#endif

    printf("\nG2-3 DONTNEED BENCHMARK COMPLETED\n");
    return 0;
}
