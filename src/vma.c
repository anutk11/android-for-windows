/*
 * vma.c - see vma.h for the semantics.
 *
 * Invariant (review round 8): the per-page metadata always describes what
 * Windows really has. Every OS call reports success or failure, and a page's
 * state is changed only after the call that changes it has succeeded. On a
 * failure the operation stops and returns -ENOMEM; pages already processed
 * keep their new (true) state, the rest keep their old (true) state.
 * All operations hold one lock (SRWLOCK on Windows).
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
#define LNX_EEXIST 17

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

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static SRWLOCK g_lock = SRWLOCK_INIT;
#define LOCK() AcquireSRWLockExclusive(&g_lock)
#define UNLOCK() ReleaseSRWLockExclusive(&g_lock)
#else
#include <pthread.h>
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
#define LOCK() pthread_mutex_lock(&g_lock)
#define UNLOCK() pthread_mutex_unlock(&g_lock)
#endif

int afw_vma_alloc_count(void) { return g_n; }

/* Round len up to pages; reject overflow of the length or of addr + len. */
static int range(uint64_t addr, uint64_t len, uint64_t *n) {
    if (len > UINT64_MAX - (PG - 1)) return -1;
    *n = (len + PG - 1) & ~(PG - 1);
    if (addr > UINT64_MAX - *n) return -1;
    return 0;
}

static winalloc *find(uint64_t addr) {
    int i;
    for (i = 0; i < g_n; i++)
        if (addr >= g_a[i].base && addr < g_a[i].base + g_a[i].size) return &g_a[i];
    return NULL;
}

/* All-or-nothing: the entry is published only when everything it needs exists. */
static winalloc *add(uint64_t base, uint64_t size) {
    unsigned char *pages = (unsigned char *)calloc((size_t)(size / PG), 1);
    winalloc *w;
    if (!pages) return NULL;
    if (g_n == g_cap) {
        int cap = g_cap ? g_cap * 2 : 64;
        winalloc *na = (winalloc *)realloc(g_a, (size_t)cap * sizeof *g_a);
        if (!na) { free(pages); return NULL; }
        g_a = na; g_cap = cap;
    }
    w = &g_a[g_n++];
    w->base = base; w->size = size; w->mapped = 0; w->page = pages;
    return w;
}

#if defined(_WIN32)
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
static int os_release(uint64_t base, uint64_t size) {
    (void)size;
    return VirtualFree((void *)(uintptr_t)base, 0, MEM_RELEASE) ? 0 : -1;
}
static int os_commit(uint64_t a, uint64_t n, int prot) {
    return VirtualAlloc((void *)(uintptr_t)a, (SIZE_T)n, MEM_COMMIT, win_prot(prot)) ? 0 : -1;
}
static int os_decommit(uint64_t a, uint64_t n) {
    return VirtualFree((void *)(uintptr_t)a, (SIZE_T)n, MEM_DECOMMIT) ? 0 : -1;
}
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
static int os_release(uint64_t base, uint64_t size) {
    return munmap((void *)(uintptr_t)base, (size_t)size);
}
static int os_commit(uint64_t a, uint64_t n, int prot) {
    return mprotect((void *)(uintptr_t)a, (size_t)n, lprot(prot));
}
static int os_decommit(uint64_t a, uint64_t n) {
    void *p = mmap((void *)(uintptr_t)a, (size_t)n, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? -1 : 0;
}
static int os_protect(uint64_t a, uint64_t n, int prot) {
    return mprotect((void *)(uintptr_t)a, (size_t)n, lprot(prot));
}
static int os_free_range(uint64_t addr, uint64_t size) { (void)addr; (void)size; return 1; }
#endif

/* Release a Windows allocation once nothing in it is mapped. If the OS call
 * fails, the entry stays (it still describes reserved memory). */
static void release_if_empty(winalloc *w) {
    if (w->mapped) return;
    if (os_release(w->base, w->size) != 0) {
        fprintf(stderr, "[vma] could not release 0x%llx (kept as reserved)\n", (unsigned long long)w->base);
        return;
    }
    free(w->page);
    *w = g_a[--g_n];
}

/* Map pages [a, a+n) inside w with prot, zero-filled, page by page so the
 * metadata stays true if Windows fails half way. */
static int map_pages(winalloc *w, uint64_t a, uint64_t n, int prot) {
    uint64_t p;
    for (p = a; p < a + n; p += PG) {
        unsigned char *s = &w->page[(p - w->base) / PG];
        if (*s & P_COMMIT) {                                  /* MAP_FIXED over a used page: zero it */
            if (os_decommit(p, PG) != 0) return -1;
            *s &= (unsigned char)~P_COMMIT;
        }
        if (prot) {
            if (os_commit(p, PG, prot) != 0) return -1;
            *s |= P_COMMIT;
        }
        if (!(*s & P_MAPPED)) w->mapped++;
        *s = (unsigned char)(P_MAPPED | (*s & P_COMMIT) | (prot & P_PROT));
    }
    return 0;
}

static int64_t mmap_locked(uint64_t addr, uint64_t len, int prot, int flags, int fd, int64_t off) {
    uint64_t n, base;
    winalloc *w;
    (void)off;   /* file offset: kept in the interface for file mappings (not yet) */
    if (!len || range(addr, len, &n) != 0) return -LNX_EINVAL;
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
                    if (w->page[first + i] & P_MAPPED) return -LNX_EEXIST;
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
    if (!w) { os_release(base, n); return -LNX_ENOMEM; }
    if (map_pages(w, base, n, prot) != 0) {
        /* undo: releasing the whole reservation also drops what was committed */
        if (os_release(base, n) == 0) { free(w->page); *w = g_a[--g_n]; }
        return -LNX_ENOMEM;
    }
    return (int64_t)base;
}

/* Apply fn to the parts of [addr, addr+n) that lie in Windows allocations. */
typedef int (*range_fn)(winalloc *w, uint64_t a, uint64_t n, int arg);

static int each(uint64_t addr, uint64_t n, range_fn fn, int arg, int need_mapped) {
    uint64_t a = addr, end = addr + n;   /* callers checked addr + n with range() */
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
        if (*s & P_COMMIT) {
            if (os_decommit(p, PG) != 0) return -1;           /* page keeps its true state */
            *s &= (unsigned char)~P_COMMIT;
        }
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
        int prot = *s & P_PROT;
        if (!(*s & P_COMMIT)) continue;                          /* reserved pages stay reserved */
        if (os_decommit(p, PG) != 0) return -1;                  /* contents dropped */
        *s &= (unsigned char)~P_COMMIT;
        if (prot) {                                              /* accessible: zeros back now */
            if (os_commit(p, PG, prot) != 0) return -1;
            *s |= P_COMMIT;
        }
        /* PROT_NONE: stays reserved; a later mprotect commits fresh zero pages */
    }
    return 0;
}

int64_t afw_mmap(uint64_t addr, uint64_t len, int prot, int flags, int fd, int64_t off) {
    int64_t r;
    LOCK();
    r = mmap_locked(addr, len, prot, flags, fd, off);
    UNLOCK();
    return r;
}

int64_t afw_munmap(uint64_t addr, uint64_t len) {
    uint64_t n;
    int64_t r;
    if ((addr & (PG - 1)) || !len || range(addr, len, &n) != 0) return -LNX_EINVAL;
    LOCK();
    r = each(addr, n, do_unmap, 0, 0);       /* unmapping holes is not an error on Linux */
    UNLOCK();
    return r;
}

int64_t afw_mprotect(uint64_t addr, uint64_t len, int prot) {
    uint64_t n;
    int64_t r;
    if ((addr & (PG - 1)) || range(addr, len, &n) != 0) return -LNX_EINVAL;
    if (!len) return 0;
    LOCK();
    r = each(addr, n, do_protect, prot, 1);
    UNLOCK();
    return r;
}

int64_t afw_madvise(uint64_t addr, uint64_t len, int advice) {
    uint64_t n;
    int64_t r;
    if ((addr & (PG - 1)) || range(addr, len, &n) != 0) return -LNX_EINVAL;
    if (!len) return 0;
    if (advice != LNX_MADV_DONTNEED) return 0;  /* WILLNEED, FREE, HUGEPAGE...: advice only */
    LOCK();
    r = each(addr, n, do_dontneed, 0, 1);
    UNLOCK();
    return r;
}
