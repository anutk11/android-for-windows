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

    /* Scenario B: 1GB touched MEM_COMMIT -> MADV_DONTNEED */
    printf("\n[Scenario B] 1GB touched (dirty) RW MEM_COMMIT -> MADV_DONTNEED\n");
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

    /* Scenario C: 1GB touched -> PROT_NONE -> MADV_DONTNEED (decommit path) */
    printf("\n[Scenario C] 1GB touched -> mprotect(PROT_NONE) -> MADV_DONTNEED (os_decommit)\n");
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

    if (afw_vma_alloc_count() != 0) {
        printf("FAIL: leaked VMA allocations (%d)\n", afw_vma_alloc_count());
        return 1;
    }

#if defined(_WIN32)
    /* ---- Isolated MEM_WRITE_WATCH experiment (Reviewer 2 request; does NOT modify vma.c) ---- */
    printf("\n=== Isolated MEM_WRITE_WATCH Probe (Windows-only, does not alter vma.c) ===\n");
    {
        const SIZE_T SIXTY_FOUR_GB = 64ULL * 1024ULL * 1024ULL * 1024ULL;
        const SIZE_T CHUNK_BYTES   = 16ULL * 1024ULL * 1024ULL; /* 4096 pages */
        PVOID *addrs = (PVOID *)malloc(4096 * sizeof(PVOID));
        if (!addrs) { printf("FAIL: OOM for addrs\n"); return 1; }

        /* WW-1: 64GB MEM_RESERVE | MEM_WRITE_WATCH (Scudo arena scale compatibility) */
        printf("\n[WW-1] 64GB VirtualAlloc(MEM_RESERVE | MEM_WRITE_WATCH, PAGE_NOACCESS)\n");
        m0 = take_mem();
        print_snap("before 64GB reserve+WW", m0);
        t0 = now_ms();
        void *r64 = VirtualAlloc(NULL, SIXTY_FOUR_GB, MEM_RESERVE | MEM_WRITE_WATCH, PAGE_NOACCESS);
        dt = now_ms() - t0;
        m1 = take_mem();
        if (!r64) {
            printf("  64GB reserve+WW FAILED: GetLastError=%lu, time=%.2f ms\n",
                   (unsigned long)GetLastError(), dt);
        } else {
            void *slice;
            ULONG_PTR cnt = 4096;
            DWORD gran = 0;
            UINT ww_rc;
            print_snap("after 64GB reserve+WW", m1);
            printf("  64GB reserve+WW SUCCEEDED: time=%.2f ms, delta_WS=%+.1f MB, delta_Commit=%+.1f MB\n",
                   dt, m1.ws_mb - m0.ws_mb, m1.commit_mb - m0.commit_mb);
            /* Commit 64KB at +32GB, write 4 pages, verify GetWriteWatch */
            slice = VirtualAlloc((unsigned char *)r64 + (32ULL << 30), 64 * 1024, MEM_COMMIT, PAGE_READWRITE);
            if (!slice) {
                printf("  64GB +32GB commit FAILED: GetLastError=%lu\n", (unsigned long)GetLastError());
            } else {
                unsigned char *sp = (unsigned char *)slice;
                sp[0] = 1; sp[4096] = 2; sp[8192] = 3; sp[12288] = 4;
                ww_rc = GetWriteWatch(0, slice, 64 * 1024, addrs, &cnt, &gran);
                printf("  +32GB 64KB slice (4 written pages): GetWriteWatch rc=%u, dirty=%llu, gran=%lu\n",
                       ww_rc, (unsigned long long)cnt, (unsigned long)gran);
                ResetWriteWatch(slice, 64 * 1024);
            }
            VirtualFree(r64, 0, MEM_RELEASE);
            m2 = take_mem();
            print_snap("after VirtualFree(64GB)", m2);
        }

        /* WW-2: Evicted / non-resident dirty pages (QueryWorkingSetEx vs GetWriteWatch) */
        printf("\n[WW-2] Evicted dirty pages: QueryWorkingSetEx(Valid) vs GetWriteWatch\n");
        {
            const SIZE_T FOUR_MB = 4ULL * 1024ULL * 1024ULL;
            unsigned char *w4 = (unsigned char *)VirtualAlloc(NULL, FOUR_MB,
                                    MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
            if (!w4) {
                printf("  WW-2 VirtualAlloc(4MB) FAILED: err=%lu\n", (unsigned long)GetLastError());
            } else {
                PSAPI_WORKING_SET_EX_INFORMATION wsi[16];
                int i, valid_cnt = 0, still_zero = 1;
                ULONG_PTR cnt = 4096;
                DWORD gran = 0;
                UINT ww_rc;

                for (i = 0; i < 16; i++) w4[(size_t)i * PG] = 0x5a;
                EmptyWorkingSet(GetCurrentProcess());
                memset(wsi, 0, sizeof wsi);
                for (i = 0; i < 16; i++) wsi[i].VirtualAddress = w4 + (size_t)i * PG;
                if (QueryWorkingSetEx(GetCurrentProcess(), wsi, sizeof wsi)) {
                    for (i = 0; i < 16; i++) if (wsi[i].VirtualAttributes.Valid) valid_cnt++;
                }
                ww_rc = GetWriteWatch(0, w4, FOUR_MB, addrs, &cnt, &gran);
                printf("  after EmptyWorkingSet on 16 dirty pages: QueryWorkingSetEx Valid=%d/16, GetWriteWatch rc=%u dirty=%llu/16\n",
                       valid_cnt, ww_rc, (unsigned long long)cnt);
                for (ULONG_PTR k = 0; k < cnt; k++) memset(addrs[k], 0, gran ? gran : PG);
                ResetWriteWatch(w4, FOUR_MB);
                cnt = 4096;
                ww_rc = GetWriteWatch(0, w4, FOUR_MB, addrs, &cnt, &gran);
                for (i = 0; i < 16; i++) if (w4[(size_t)i * PG] != 0) still_zero = 0;
                printf("  after zero + ResetWriteWatch: post_dirty=%llu, all_16_zero=%d\n",
                       (unsigned long long)cnt, still_zero);
                VirtualFree(w4, 0, MEM_RELEASE);
            }
        }

        /* WW-3: 1GB Scenarios A-WW (untouched), B-sparse-WW (4MB touched), B-WW (1GB touched), C-WW (decommit) */
        printf("\n[WW-3] 1GB MEM_WRITE_WATCH Scenarios (A untouched, B-sparse 4MB, B full 1GB, C PROT_NONE decommit)\n");
        {
            unsigned char *w1g = (unsigned char *)VirtualAlloc(NULL, (SIZE_T)ONE_GB,
                                     MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
            if (!w1g) {
                printf("  WW-3 VirtualAlloc(1GB+WW) FAILED: err=%lu\n", (unsigned long)GetLastError());
            } else {
                uint64_t total_dirty;
                SIZE_T c_off;
                DWORD gran = 0;

                /* A-WW: untouched 1GB */
                m1 = take_mem();
                print_snap("A-WW before scan (untouch)", m1);
                t0 = now_ms();
                total_dirty = 0;
                for (c_off = 0; c_off < (SIZE_T)ONE_GB; c_off += CHUNK_BYTES) {
                    ULONG_PTR cnt = 4096;
                    if (GetWriteWatch(0, w1g + c_off, CHUNK_BYTES, addrs, &cnt, &gran) == 0 && cnt > 0) {
                        for (ULONG_PTR k = 0; k < cnt; k++) memset(addrs[k], 0, gran ? gran : PG);
                        ResetWriteWatch(w1g + c_off, CHUNK_BYTES);
                        total_dirty += cnt;
                    }
                }
                dt = now_ms() - t0;
                m2 = take_mem();
                print_snap("A-WW after scan", m2);
                printf("  A-WW (1GB untouched):      time=%.2f ms, dirty=%llu, delta_WS=%+.1f MB, delta_Commit=%+.1f MB\n",
                       dt, (unsigned long long)total_dirty, m2.ws_mb - m1.ws_mb, m2.commit_mb - m1.commit_mb);

                /* B-sparse-WW: 4MB (1024 pages) touched out of 1GB */
                for (off = 0; off < 1024u * PG; off += PG) w1g[off] = 0x77;
                m1 = take_mem();
                t0 = now_ms();
                total_dirty = 0;
                for (c_off = 0; c_off < (SIZE_T)ONE_GB; c_off += CHUNK_BYTES) {
                    ULONG_PTR cnt = 4096;
                    if (GetWriteWatch(0, w1g + c_off, CHUNK_BYTES, addrs, &cnt, &gran) == 0 && cnt > 0) {
                        for (ULONG_PTR k = 0; k < cnt; k++) memset(addrs[k], 0, gran ? gran : PG);
                        ResetWriteWatch(w1g + c_off, CHUNK_BYTES);
                        total_dirty += cnt;
                    }
                }
                dt = now_ms() - t0;
                m2 = take_mem();
                printf("  B-sparse-WW (4MB/1GB):     time=%.2f ms, dirty=%llu, delta_WS=%+.1f MB, zero0=%d\n",
                       dt, (unsigned long long)total_dirty, m2.ws_mb - m1.ws_mb, w1g[0] == 0);

                /* B-WW: full 1GB touched (all 262,144 pages) */
                for (off = 0; off < (size_t)ONE_GB; off += PG) w1g[off] = 0x5a;
                m1 = take_mem();
                t0 = now_ms();
                total_dirty = 0;
                for (c_off = 0; c_off < (SIZE_T)ONE_GB; c_off += CHUNK_BYTES) {
                    ULONG_PTR cnt = 4096;
                    if (GetWriteWatch(0, w1g + c_off, CHUNK_BYTES, addrs, &cnt, &gran) == 0 && cnt > 0) {
                        for (ULONG_PTR k = 0; k < cnt; k++) memset(addrs[k], 0, gran ? gran : PG);
                        ResetWriteWatch(w1g + c_off, CHUNK_BYTES);
                        total_dirty += cnt;
                    }
                }
                dt = now_ms() - t0;
                m2 = take_mem();
                printf("  B-WW (1GB full touched):   time=%.2f ms, dirty=%llu, delta_WS=%+.1f MB, sampled_zeros=%s\n",
                       dt, (unsigned long long)total_dirty, m2.ws_mb - m1.ws_mb,
                       verify_sampled_zeros(w1g, (size_t)ONE_GB) ? "OK" : "FAIL");

                /* C-WW: VirtualProtect(PAGE_NOACCESS) + VirtualFree(MEM_DECOMMIT) on WW region */
                {
                    DWORD oldp = 0;
                    VirtualProtect(w1g, (SIZE_T)ONE_GB, PAGE_NOACCESS, &oldp);
                    m1 = take_mem();
                    t0 = now_ms();
                    BOOL ok = VirtualFree(w1g, (SIZE_T)ONE_GB, MEM_DECOMMIT);
                    dt = now_ms() - t0;
                    m2 = take_mem();
                    printf("  C-WW (1GB PROT_NONE decommit): ok=%d, time=%.2f ms, delta_WS=%+.1f MB, delta_Commit=%+.1f MB\n",
                           (int)ok, dt, m2.ws_mb - m1.ws_mb, m2.commit_mb - m1.commit_mb);
                }

                VirtualFree(w1g, 0, MEM_RELEASE);
            }
        }
        free(addrs);
    }
#endif

    printf("\nG2-3 DONTNEED BENCHMARK COMPLETED\n");
    return 0;
}
