/*
 * vma.c - see vma.h for the semantics.
 */
#include "vma.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PG 4096ull
#define GRAN (64 * 1024ull)
#define LNX_EINVAL 22
#define LNX_ENOMEM 12
#define LNX_ENODEV 19

/* per-page state */
#define P_MAPPED 0x08
#define P_COMMIT 0x10
#define P_PROT   0x07   /* Linux PROT_* bits */

typedef struct {
    uint64_t base, size;      /* the Windows reservation */
    unsigned char *page;      /* size / PG entries */
    uint64_t mapped;          /* number of mapped pages */
} winalloc;

static winalloc *g_a;
static int g_n, g_cap;

int afw_vma_alloc_count(void) { return g_n; }

static winalloc *find(uint64_t addr) {
    int i;
    for (i = 0; i < g_n; i++)
        if (addr >= g_a[i].base && addr < g_a[i].base + g_a[i].size) return &g_a[i];
    return NULL;
}

static winalloc *add(uint64_t base, uint64_t size) {
    winalloc *w;
    if (g_n == g_cap) {
        g_cap = g_cap ? g_cap * 2 : 64;
        g_a = (winalloc *)realloc(g_a, (size_t)g_cap * sizeof *g_a);
    }
    w = &g_a[g_n++];
    w->base = base; w->size = size; w->mapped = 0;
    w->page = (unsigned char *)calloc((size_t)(size / PG), 1);
    return w;
}

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static DWORD win_prot(int prot) {
    int r = prot & LNX_PROT_READ, w = prot & LNX_PROT_WRITE, x = prot & LNX_PROT_EXEC;
    if (x) return w ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    if (w) return PAGE_READWRITE;           /* write-only does not exist on Windows */
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}
static int os_reserve(uint64_t addr, uint64_t size, uint64_t *out) {
    void *p = VirtualAlloc((void *)(uintptr_t)addr, (SIZE_T)size, MEM_RESERVE, PAGE_NOACCESS);
    if (!p) return -1;
    *out = (uint64_t)(uintptr_t)p;
    return 0;
}
static void os_release(uint64_t base) { VirtualFree((void *)(uintptr_t)base, 0, MEM_RELEASE); }
static int os_commit(uint64_t a, uint64_t n, int prot) {
    return VirtualAlloc((void *)(uintptr_t)a, (SIZE_T)n, MEM_COMMIT, win_prot(prot)) ? 0 : -1;
}
static void os_decommit(uint64_t a, uint64_t n) { VirtualFree((void *)(uintptr_t)a, (SIZE_T)n, MEM_DECOMMIT); }
static int os_protect(uint64_t a, uint64_t n, int prot) {
    DWORD old;
    return VirtualProtect((void *)(uintptr_t)a, (SIZE_T)n, win_prot(prot), &old) ? 0 : -1;
}
static int os_free_range(uint64_t addr, uint64_t size) {
    MEMORY_BASIC_INFORMATION mi;
    uint64_t a = addr;
    while (a < addr + size) {
        if (!VirtualQuery((void *)(uintptr_t)a, &mi, sizeof mi) || mi.State != MEM_FREE) return 0;
        a = (uint64_t)(uintptr_t)mi.BaseAddress + mi.RegionSize;
    }
    return 1;
}
#else
/* Host build (Linux): same bookkeeping over mmap, so the logic is testable. */
#include <sys/mman.h>
static int lprot(int prot) {
    int p = 0;
    if (prot & LNX_PROT_READ) p |= PROT_READ;
    if (prot & LNX_PROT_WRITE) p |= PROT_READ | PROT_WRITE;
    if (prot & LNX_PROT_EXEC) p |= PROT_EXEC | PROT_READ;
    return p;
}
static int os_reserve(uint64_t addr, uint64_t size, uint64_t *out) {
    void *p = mmap((void *)(uintptr_t)addr, (size_t)size, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | (addr ? MAP_FIXED_NOREPLACE : 0), -1, 0);
    if (p == MAP_FAILED) return -1;
    *out = (uint64_t)(uintptr_t)p;
    return 0;
}
static void os_release(uint64_t base) { (void)base; }  /* munmap below, per allocation */
static int os_commit(uint64_t a, uint64_t n, int prot) {
    return mprotect((void *)(uintptr_t)a, (size_t)n, lprot(prot));
}
static void os_decommit(uint64_t a, uint64_t n) {
    mmap((void *)(uintptr_t)a, (size_t)n, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
}
static int os_protect(uint64_t a, uint64_t n, int prot) {
    return mprotect((void *)(uintptr_t)a, (size_t)n, lprot(prot));
}
static int os_free_range(uint64_t addr, uint64_t size) { (void)addr; (void)size; return 1; }
#endif

static void release_if_empty(winalloc *w) {
    if (w->mapped) return;
#if !defined(_WIN32)
    munmap((void *)(uintptr_t)w->base, (size_t)w->size);
#endif
    os_release(w->base);
    free(w->page);
    *w = g_a[--g_n];
}

/* Map pages [a, a+n) inside w with prot: fresh, zero-filled. */
static int map_pages(winalloc *w, uint64_t a, uint64_t n, int prot) {
    uint64_t i, first = (a - w->base) / PG, cnt = n / PG;
    for (i = 0; i < cnt; i++)
        if (w->page[first + i] & P_COMMIT) { os_decommit(a, n); break; }   /* MAP_FIXED over old pages: zero */
    if (prot != 0 && os_commit(a, n, prot) != 0) return -1;
    for (i = 0; i < cnt; i++) {
        unsigned char *s = &w->page[first + i];
        if (!(*s & P_MAPPED)) w->mapped++;
        *s = (unsigned char)(P_MAPPED | (prot & P_PROT) | (prot ? P_COMMIT : 0));
    }
    return 0;
}

int64_t afw_mmap(uint64_t addr, uint64_t len, int prot, int flags, int fd, int64_t off) {
    uint64_t n = (len + PG - 1) & ~(PG - 1), base;
    winalloc *w;
    (void)off;
    if (!len || n < len) return -LNX_EINVAL;
    if (!(flags & LNX_MAP_ANONYMOUS) || fd != -1) return -LNX_ENODEV;   /* files: not yet */
    if (flags & (LNX_MAP_FIXED | LNX_MAP_FIXED_NOREPLACE)) {
        if (addr & (PG - 1)) return -LNX_EINVAL;
        w = find(addr);
        if (w) {
            if (addr + n > w->base + w->size) {
                fprintf(stderr, "[vma] MAP_FIXED 0x%llx+0x%llx spans two Windows allocations: not supported yet\n",
                        (unsigned long long)addr, (unsigned long long)n);
                return -LNX_ENOMEM;
            }
            if (flags & LNX_MAP_FIXED_NOREPLACE) {
                uint64_t i, first = (addr - w->base) / PG;
                for (i = 0; i < n / PG; i++)
                    if (w->page[first + i] & P_MAPPED) return -17; /* EEXIST */
            }
            return map_pages(w, addr, n, prot) == 0 ? (int64_t)addr : -LNX_ENOMEM;
        }
        if ((addr & (GRAN - 1)) || !os_free_range(addr, n)) {
            fprintf(stderr, "[vma] MAP_FIXED at 0x%llx: free space that is not 64KB-aligned "
                            "cannot be reserved on Windows (documented limit)\n", (unsigned long long)addr);
            return -LNX_ENOMEM;
        }
        if (os_reserve(addr, n, &base) != 0) return -LNX_ENOMEM;
    } else {
        if (os_reserve(0, n, &base) != 0) return -LNX_ENOMEM;
    }
    w = add(base, n);
    if (map_pages(w, base, n, prot) != 0) { w->mapped = 0; release_if_empty(w); return -LNX_ENOMEM; }
    return (int64_t)base;
}

/* Apply fn to the parts of [addr, addr+n) that lie in Windows allocations. */
typedef int (*range_fn)(winalloc *w, uint64_t a, uint64_t n, int arg);

static int each(uint64_t addr, uint64_t n, range_fn fn, int arg, int need_mapped) {
    uint64_t a = addr, end = addr + n;
    while (a < end) {
        winalloc *w = find(a);
        uint64_t stop;
        if (!w) {
            if (need_mapped) return -LNX_ENOMEM;
            a += PG;
            continue;
        }
        stop = w->base + w->size < end ? w->base + w->size : end;
        if (need_mapped) {
            uint64_t p;
            for (p = a; p < stop; p += PG)
                if (!(w->page[(p - w->base) / PG] & P_MAPPED)) return -LNX_ENOMEM;
        }
        if (fn(w, a, stop - a, arg) != 0) return -LNX_ENOMEM;
        a = stop;   /* w may have been released by fn: not used again */
    }
    return 0;
}

static int do_unmap(winalloc *w, uint64_t a, uint64_t n, int arg) {
    uint64_t p;
    (void)arg;
    for (p = a; p < a + n; p += PG) {
        unsigned char *s = &w->page[(p - w->base) / PG];
        if (*s & P_COMMIT) os_decommit(p, PG);
        if (*s & P_MAPPED) w->mapped--;
        *s = 0;
    }
    release_if_empty(w);
    return 0;
}

static int do_protect(winalloc *w, uint64_t a, uint64_t n, int prot) {
    uint64_t p;
    for (p = a; p < a + n; p += PG) {
        unsigned char *s = &w->page[(p - w->base) / PG];
        if (*s & P_COMMIT) {
            if (os_protect(p, PG, prot) != 0) return -1;        /* PROT_NONE keeps contents */
        } else if (prot) {
            if (os_commit(p, PG, prot) != 0) return -1;         /* never touched: zero, now usable */
            *s |= P_COMMIT;
        }
        *s = (unsigned char)((*s & ~P_PROT) | (prot & P_PROT));
    }
    return 0;
}

static int do_dontneed(winalloc *w, uint64_t a, uint64_t n, int arg) {
    uint64_t p;
    (void)arg;
    for (p = a; p < a + n; p += PG) {
        unsigned char *s = &w->page[(p - w->base) / PG];
        if (!(*s & P_COMMIT)) continue;                          /* reserved pages stay reserved */
        os_decommit(p, PG);                                      /* contents dropped ... */
        if (os_commit(p, PG, *s & P_PROT ? *s & P_PROT : LNX_PROT_READ) != 0) return -1; /* ... zeros back */
        if (!(*s & P_PROT)) os_protect(p, PG, 0);
    }
    return 0;
}

int64_t afw_munmap(uint64_t addr, uint64_t len) {
    uint64_t n = (len + PG - 1) & ~(PG - 1);
    if ((addr & (PG - 1)) || !len) return -LNX_EINVAL;
    each(addr, n, do_unmap, 0, 0);       /* unmapping holes is not an error on Linux */
    return 0;
}

int64_t afw_mprotect(uint64_t addr, uint64_t len, int prot) {
    uint64_t n = (len + PG - 1) & ~(PG - 1);
    if (addr & (PG - 1)) return -LNX_EINVAL;
    if (!len) return 0;
    return each(addr, n, do_protect, prot, 1);
}

int64_t afw_madvise(uint64_t addr, uint64_t len, int advice) {
    uint64_t n = (len + PG - 1) & ~(PG - 1);
    if (addr & (PG - 1)) return -LNX_EINVAL;
    if (!len) return 0;
    if (advice != LNX_MADV_DONTNEED) return 0;  /* WILLNEED, FREE, HUGEPAGE...: advice only */
    return each(addr, n, do_dontneed, 0, 1);
}
