/*
 * vma.c - Extent-based VMA layer (see vma.h for the semantics).
 *
 * Each Windows VirtualAlloc reservation ("winalloc") holds a sorted, disjoint
 * partition of [base, base + size) into normalized extents [start, end, state].
 * Adjacent extents with identical state are always coalesced, so a 64GB
 * PROT_NONE reservation takes one extent (~bytes of metadata) and OS calls
 * (VirtualAlloc / VirtualProtect / VirtualFree) are coalesced across runs.
 *
 * Invariant (review round 8): metadata always describes what the OS really
 * has. Capacity for splitting extents is reserved before any OS call, every
 * OS call reports success or failure, and an extent's state changes only after
 * the OS call that changes it has succeeded. On failure the operation stops
 * and returns -ENOMEM; extents already processed keep their new (true) state,
 * the rest keep their old (true) state.
 * All operations hold one lock (SRWLOCK on Windows, pthread mutex on host).
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

/* per-extent state bits */
#define P_MAPPED 0x08
#define P_COMMIT 0x10
#define P_PROT   0x07   /* Linux PROT_* bits */

typedef struct {
    uint64_t start;          /* inclusive, page-aligned */
    uint64_t end;            /* exclusive, page-aligned, start < end */
    unsigned char state;     /* P_MAPPED | P_COMMIT | P_PROT */
} vma_ext;

typedef struct {
    uint64_t base, size;     /* the Windows reservation [base, base + size) */
    uint64_t mapped_bytes;   /* sum of (end - start) over P_MAPPED extents */
    vma_ext *ext;            /* sorted partition of [base, base + size) */
    size_t next, cap;
    unsigned char owned;     /* 1 = VMA owns the OS reservation; 0 = adopted */
} winalloc;

/* Sorted by base, pairwise disjoint. */
static winalloc *g_a;
static size_t g_n, g_cap;
static uint64_t g_os_calls;
#ifdef AFW_TEST
static int g_fail_os;
#endif

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

int afw_vma_alloc_count(void) {
    int n;
    LOCK();
    n = (int)g_n;
    UNLOCK();
    return n;
}

size_t afw_vma_meta_bytes(void) {
    size_t i, total;
    LOCK();
    total = g_cap * sizeof *g_a;
    for (i = 0; i < g_n; i++)
        total += g_a[i].cap * sizeof *g_a[i].ext;
    UNLOCK();
    return total;
}

size_t afw_vma_extent_count(void) {
    size_t i, total = 0;
    LOCK();
    for (i = 0; i < g_n; i++)
        total += g_a[i].next;
    UNLOCK();
    return total;
}

uint64_t afw_vma_os_call_count(void) {
    uint64_t n;
    LOCK();
    n = g_os_calls;
    UNLOCK();
    return n;
}

#ifdef AFW_TEST
void afw_vma_test_fail_os(int nth) {
    LOCK();
    g_fail_os = nth > 0 ? nth : 0;
    UNLOCK();
}
#endif

/* Round len up to pages; reject overflow of len, size_t truncation, or addr + n. */
static int range(uint64_t addr, uint64_t len, uint64_t *n) {
    if (len > UINT64_MAX - (PG - 1)) return -1;
    *n = (len + PG - 1) & ~(PG - 1);
    if (*n > (uint64_t)SIZE_MAX) return -1;
    if (addr > UINT64_MAX - *n) return -1;
    return 0;
}

/* First allocation with base + size > addr (or g_n if none). */
static size_t lower_bound_alloc(uint64_t addr) {
    size_t lo = 0, hi = g_n;
    while (lo < hi) {
        size_t m = lo + (hi - lo) / 2;
        if (g_a[m].base + g_a[m].size <= addr) lo = m + 1;
        else hi = m;
    }
    return lo;
}

static winalloc *find(uint64_t addr) {
    size_t i = lower_bound_alloc(addr);
    if (i < g_n && addr >= g_a[i].base) return &g_a[i];
    return NULL;
}

/* Unique extent containing addr (caller guarantees w->base <= addr < w->base + w->size). */
static size_t find_ext(const winalloc *w, uint64_t addr) {
    size_t lo = 0, hi = w->next;
    while (lo < hi) {
        size_t m = lo + (hi - lo) / 2;
        if (w->ext[m].end <= addr) lo = m + 1;
        else hi = m;
    }
    return lo;
}

static int range_all_mapped(const winalloc *w, uint64_t a, uint64_t b) {
    size_t i = find_ext(w, a);
    while (i < w->next && w->ext[i].start < b) {
        if (!(w->ext[i].state & P_MAPPED)) return 0;
        i++;
    }
    return 1;
}

static int range_any_mapped(const winalloc *w, uint64_t a, uint64_t b) {
    size_t i = find_ext(w, a);
    while (i < w->next && w->ext[i].start < b) {
        if (w->ext[i].state & P_MAPPED) return 1;
        i++;
    }
    return 0;
}

static int ensure_ext_cap(winalloc *w, size_t need) {
    size_t cap;
    vma_ext *ne;
    if (need <= w->cap) return 0;
    cap = w->cap ? w->cap : 8;
    while (cap < need) {
        if (cap > SIZE_MAX / 2 / sizeof *w->ext) {
            if (need > SIZE_MAX / sizeof *w->ext) return -1;
            cap = need;
            break;
        }
        cap *= 2;
    }
    ne = (vma_ext *)realloc(w->ext, cap * sizeof *w->ext);
    if (!ne) return -1;
    w->ext = ne;
    w->cap = cap;
    return 0;
}

/*
 * Ensure [a, b) starts and ends on exact extent boundaries inside w.
 * Splitting an extent into identical-state halves never changes the logical
 * state of any page. Capacity (+2) is reserved first, so no OS call ever
 * runs if metadata allocation could fail.
 */
static int split_range(winalloc *w, uint64_t a, uint64_t b, size_t *out_first, size_t *out_end) {
    size_t i;
    if (w->next > SIZE_MAX - 2 || ensure_ext_cap(w, w->next + 2) != 0) return -1;
    i = find_ext(w, a);
    if (w->ext[i].start < a) {
        memmove(&w->ext[i + 2], &w->ext[i + 1], (w->next - (i + 1)) * sizeof *w->ext);
        w->ext[i + 1].start = a;
        w->ext[i + 1].end = w->ext[i].end;
        w->ext[i + 1].state = w->ext[i].state;
        w->ext[i].end = a;
        w->next++;
        i++;
    }
    *out_first = i;
    if (b == w->base + w->size) {
        *out_end = w->next;
        return 0;
    }
    i = find_ext(w, b);
    if (w->ext[i].start < b) {
        memmove(&w->ext[i + 2], &w->ext[i + 1], (w->next - (i + 1)) * sizeof *w->ext);
        w->ext[i + 1].start = b;
        w->ext[i + 1].end = w->ext[i].end;
        w->ext[i + 1].state = w->ext[i].state;
        w->ext[i].end = b;
        w->next++;
        i++;
    }
    *out_end = i;
    return 0;
}

/* Merge adjacent equal-state extents around [i0, i1) and optionally shrink cap. */
static void coalesce_around(winalloc *w, size_t i0, size_t i1) {
    size_t lo, hi, r, wr, tail;
    if (w->next <= 1) return;
    lo = i0 > 0 ? i0 - 1 : 0;
    hi = i1 < w->next ? i1 : w->next - 1;
    if (lo < hi) {
        wr = lo;
        for (r = lo + 1; r <= hi; r++) {
            if (w->ext[r].state == w->ext[wr].state) {
                w->ext[wr].end = w->ext[r].end;
            } else {
                wr++;
                if (wr != r) w->ext[wr] = w->ext[r];
            }
        }
        if (wr < hi) {
            tail = w->next - (hi + 1);
            if (tail) memmove(&w->ext[wr + 1], &w->ext[hi + 1], tail * sizeof *w->ext);
            w->next -= (hi - wr);
        }
    }
    if (w->cap > 64 && w->next * 4 < w->cap) {
        size_t ncap = w->cap / 2;
        vma_ext *ne = (vma_ext *)realloc(w->ext, ncap * sizeof *w->ext);
        if (ne) { w->ext = ne; w->cap = ncap; }
    }
}

/* All-or-nothing insertion into sorted g_a[]. */
static winalloc *add(uint64_t base, uint64_t size) {
    vma_ext *ext = (vma_ext *)calloc(8, sizeof *ext);
    size_t pos;
    winalloc *w;
    if (!ext) return NULL;
    if (g_n == g_cap) {
        size_t cap;
        winalloc *na;
        if (g_cap > SIZE_MAX / 2 / sizeof *g_a) { free(ext); return NULL; }
        cap = g_cap ? g_cap * 2 : 16;
        na = (winalloc *)realloc(g_a, cap * sizeof *g_a);
        if (!na) { free(ext); return NULL; }
        g_a = na; g_cap = cap;
    }
    pos = lower_bound_alloc(base);
    if (pos < g_n) memmove(&g_a[pos + 1], &g_a[pos], (g_n - pos) * sizeof *g_a);
    g_n++;
    w = &g_a[pos];
    w->base = base;
    w->size = size;
    w->mapped_bytes = 0;
    w->ext = ext;
    w->next = 1;
    w->cap = 8;
    w->owned = 1;
    w->ext[0].start = base;
    w->ext[0].end = base + size;
    w->ext[0].state = 0;
    return w;
}

static void remove_alloc(winalloc *w) {
    size_t idx = (size_t)(w - g_a);
    free(w->ext);
    if (idx + 1 < g_n) memmove(&g_a[idx], &g_a[idx + 1], (g_n - idx - 1) * sizeof *g_a);
    g_n--;
}

static int os_tick(void) {
    g_os_calls++;
#ifdef AFW_TEST
    if (g_fail_os > 0 && --g_fail_os == 0) return -1;
#endif
    return 0;
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
    void *p;
    if (os_tick() != 0) return -1;
    p = VirtualAlloc((void *)(uintptr_t)addr, (SIZE_T)size, MEM_RESERVE, PAGE_NOACCESS);
    if (!p) return -1;
    *out = (uint64_t)(uintptr_t)p;
    return 0;
}
static int os_release(uint64_t base, uint64_t size) {
    (void)size;
    if (os_tick() != 0) return -1;
    return VirtualFree((void *)(uintptr_t)base, 0, MEM_RELEASE) ? 0 : -1;
}
static int os_commit(uint64_t a, uint64_t n, int prot) {
    if (os_tick() != 0) return -1;
    return VirtualAlloc((void *)(uintptr_t)a, (SIZE_T)n, MEM_COMMIT, win_prot(prot)) ? 0 : -1;
}
static int os_decommit(uint64_t a, uint64_t n) {
    if (os_tick() != 0) return -1;
    return VirtualFree((void *)(uintptr_t)a, (SIZE_T)n, MEM_DECOMMIT) ? 0 : -1;
}
static int os_protect(uint64_t a, uint64_t n, int prot) {
    DWORD old;
    if (os_tick() != 0) return -1;
    return VirtualProtect((void *)(uintptr_t)a, (SIZE_T)n, win_prot(prot), &old) ? 0 : -1;
}
static int os_free_range(uint64_t addr, uint64_t size) {
    MEMORY_BASIC_INFORMATION mi;
    uint64_t a = addr;
    while (a < addr + size) {
        uint64_t next;
        if (!VirtualQuery((void *)(uintptr_t)a, &mi, sizeof mi) || mi.State != MEM_FREE) return 0;
        next = (uint64_t)(uintptr_t)mi.BaseAddress + mi.RegionSize;
        if (next <= a) return 0;
        a = next;
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
    void *p;
    if (os_tick() != 0) return -1;
    p = mmap((void *)(uintptr_t)addr, (size_t)size, PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | (addr ? MAP_FIXED_NOREPLACE : 0), -1, 0);
    if (p == MAP_FAILED) return -1;
    *out = (uint64_t)(uintptr_t)p;
    return 0;
}
static int os_release(uint64_t base, uint64_t size) {
    if (os_tick() != 0) return -1;
    return munmap((void *)(uintptr_t)base, (size_t)size);
}
static int os_commit(uint64_t a, uint64_t n, int prot) {
    if (os_tick() != 0) return -1;
    return mprotect((void *)(uintptr_t)a, (size_t)n, lprot(prot));
}
static int os_decommit(uint64_t a, uint64_t n) {
    void *p;
    if (os_tick() != 0) return -1;
    p = mmap((void *)(uintptr_t)a, (size_t)n, PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? -1 : 0;
}
static int os_protect(uint64_t a, uint64_t n, int prot) {
    if (os_tick() != 0) return -1;
    return mprotect((void *)(uintptr_t)a, (size_t)n, lprot(prot));
}
static int os_free_range(uint64_t addr, uint64_t size) { (void)addr; (void)size; return 1; }
#endif

/* Release a VMA-owned Windows allocation once nothing in it is mapped.
 * Adopted library regions (owned == 0) are never released here: the loader
 * owns the VirtualAlloc (and its trailing stub reserve) and frees it after
 * afw_vma_forget(). If the OS call fails, the entry stays (still reserved). */
static void release_if_empty(winalloc *w) {
    if (!w->owned || w->mapped_bytes) return;
    if (os_release(w->base, w->size) != 0) {
        fprintf(stderr, "[vma] could not release 0x%llx (kept as reserved)\n", (unsigned long long)w->base);
        return;
    }
    remove_alloc(w);
}

/*
 * Map [a, a+n) inside w with prot, zero-filled.
 * Phase 1: decommit any contiguous committed runs (zeroing MAP_FIXED targets).
 * Phase 2: if prot != 0, commit [a, a+n) in a single OS call.
 * Metadata changes only after each OS call succeeds.
 */
static int map_extents(winalloc *w, uint64_t a, uint64_t n, int prot) {
    size_t i0, i1, i, j, k;
    int rc = 0;
    prot &= P_PROT;
    if (split_range(w, a, a + n, &i0, &i1) != 0) return -1;

    /* Phase 1: decommit committed runs so MAP_FIXED over live pages reads zeros. */
    for (i = i0; i < i1;) {
        if (!(w->ext[i].state & P_COMMIT)) { i++; continue; }
        j = i + 1;
        while (j < i1 && (w->ext[j].state & P_COMMIT)) j++;
        if (os_decommit(w->ext[i].start, w->ext[j - 1].end - w->ext[i].start) != 0) {
            rc = -1;
            break;
        }
        for (k = i; k < j; k++)
            w->ext[k].state = (unsigned char)(w->ext[k].state & P_MAPPED);
        i = j;
    }

    /* Phase 2: commit whole range in one call (if accessible), then publish. */
    if (rc == 0 && prot) {
        if (os_commit(a, n, prot) != 0) rc = -1;
    }
    if (rc == 0) {
        unsigned char st = (unsigned char)(P_MAPPED | (prot ? P_COMMIT : 0) | prot);
        for (i = i0; i < i1; i++) {
            if (!(w->ext[i].state & P_MAPPED))
                w->mapped_bytes += w->ext[i].end - w->ext[i].start;
            w->ext[i].state = st;
        }
    }

    coalesce_around(w, i0, i1);
    return rc;
}

static int64_t mmap_locked(uint64_t addr, uint64_t len, int prot, int flags, int fd, int64_t off) {
    uint64_t n, base;
    int fixed = (flags & (LNX_MAP_FIXED | LNX_MAP_FIXED_NOREPLACE)) != 0;
    winalloc *w;
    (void)off;   /* file offset: kept in the interface for file mappings (not yet) */
    if (!len || range(fixed ? addr : 0, len, &n) != 0) return -LNX_EINVAL;
    if (!(flags & LNX_MAP_ANONYMOUS) || fd != -1) return -LNX_ENODEV;   /* files: not yet */
    prot &= P_PROT;
    if (fixed) {
        size_t idx;
        if (addr & (PG - 1)) return -LNX_EINVAL;
        w = find(addr);
        if (w) {
            if (addr + n > w->base + w->size) {
                fprintf(stderr, "[vma] MAP_FIXED 0x%llx+0x%llx spans two Windows allocations: not supported yet\n",
                        (unsigned long long)addr, (unsigned long long)n);
                return -LNX_ENOMEM;
            }
            if ((flags & LNX_MAP_FIXED_NOREPLACE) && range_any_mapped(w, addr, addr + n))
                return -LNX_EEXIST;
            return map_extents(w, addr, n, prot) == 0 ? (int64_t)addr : -LNX_ENOMEM;
        }
        /* Reject ranges in free space that would collide with a later allocation. */
        idx = lower_bound_alloc(addr);
        if (idx < g_n && g_a[idx].base < addr + n) {
            if ((flags & LNX_MAP_FIXED_NOREPLACE) &&
                range_any_mapped(&g_a[idx], g_a[idx].base,
                                 g_a[idx].base + g_a[idx].size < addr + n ? g_a[idx].base + g_a[idx].size : addr + n))
                return -LNX_EEXIST;
            fprintf(stderr, "[vma] MAP_FIXED 0x%llx+0x%llx overlaps an existing Windows allocation\n",
                    (unsigned long long)addr, (unsigned long long)n);
            return -LNX_ENOMEM;
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
    if (map_extents(w, base, n, prot) != 0) {
        /* undo: releasing the whole reservation also drops anything committed */
        if (os_release(base, n) == 0) remove_alloc(w);
        return -LNX_ENOMEM;
    }
    return (int64_t)base;
}

/* Apply fn to the parts of [addr, addr+n) that lie in Windows allocations. */
typedef int (*range_fn)(winalloc *w, uint64_t a, uint64_t n, int arg);

static int each(uint64_t addr, uint64_t n, range_fn fn, int arg, int need_mapped) {
    uint64_t a = addr, end = addr + n;   /* callers checked addr + n with range() */
    if (need_mapped) {
        uint64_t c = addr;
        while (c < end) {
            size_t idx = lower_bound_alloc(c);
            uint64_t stop;
            if (idx >= g_n || c < g_a[idx].base) return -LNX_ENOMEM;
            stop = g_a[idx].base + g_a[idx].size < end ? g_a[idx].base + g_a[idx].size : end;
            if (!range_all_mapped(&g_a[idx], c, stop)) return -LNX_ENOMEM;
            c = stop;
        }
    }
    while (a < end) {
        size_t idx = lower_bound_alloc(a);
        winalloc *w;
        uint64_t stop;
        if (idx >= g_n || g_a[idx].base >= end)
            return need_mapped ? -LNX_ENOMEM : 0;
        w = &g_a[idx];
        if (a < w->base) {
            if (need_mapped) return -LNX_ENOMEM;
            a = w->base;
        }
        stop = w->base + w->size < end ? w->base + w->size : end;
        if (fn(w, a, stop - a, arg) != 0) return -LNX_ENOMEM;
        a = stop;   /* w may have been released by fn: never reused */
    }
    return 0;
}

static int do_unmap(winalloc *w, uint64_t a, uint64_t n, int arg) {
    size_t i0, i1, i, j, k;
    int rc = 0;
    (void)arg;
    if (split_range(w, a, a + n, &i0, &i1) != 0) return -1;

    for (i = i0; i < i1;) {
        if (w->ext[i].state & P_COMMIT) {
            j = i + 1;
            while (j < i1 && (w->ext[j].state & P_COMMIT)) j++;
            if (os_decommit(w->ext[i].start, w->ext[j - 1].end - w->ext[i].start) != 0) {
                rc = -1;
                break;
            }
            for (k = i; k < j; k++) {
                if (w->ext[k].state & P_MAPPED)
                    w->mapped_bytes -= w->ext[k].end - w->ext[k].start;
                w->ext[k].state = 0;
            }
            i = j;
        } else {
            if (w->ext[i].state & P_MAPPED)
                w->mapped_bytes -= w->ext[i].end - w->ext[i].start;
            w->ext[i].state = 0;
            i++;
        }
    }

    coalesce_around(w, i0, i1);
    release_if_empty(w);
    return rc;
}

static int do_protect(winalloc *w, uint64_t a, uint64_t n, int prot) {
    size_t i0, i1, i, j, k;
    int rc = 0;
    prot &= P_PROT;
    if (split_range(w, a, a + n, &i0, &i1) != 0) return -1;

    for (i = i0; i < i1;) {
        if (w->ext[i].state & P_COMMIT) {
            if ((w->ext[i].state & P_PROT) == prot) { i++; continue; }
            j = i + 1;
            while (j < i1 && (w->ext[j].state & P_COMMIT) && (w->ext[j].state & P_PROT) != prot) j++;
            /* PROT_NONE keeps contents: VirtualProtect(PAGE_NOACCESS), never decommit */
            if (os_protect(w->ext[i].start, w->ext[j - 1].end - w->ext[i].start, prot) != 0) {
                rc = -1;
                break;
            }
            for (k = i; k < j; k++)
                w->ext[k].state = (unsigned char)(P_MAPPED | P_COMMIT | prot);
            i = j;
        } else if (prot) {
            j = i + 1;
            while (j < i1 && !(w->ext[j].state & P_COMMIT)) j++;
            if (os_commit(w->ext[i].start, w->ext[j - 1].end - w->ext[i].start, prot) != 0) {
                rc = -1;
                break;
            }
            for (k = i; k < j; k++)
                w->ext[k].state = (unsigned char)(P_MAPPED | P_COMMIT | prot);
            i = j;
        } else {
            w->ext[i].state = P_MAPPED;
            i++;
        }
    }

    coalesce_around(w, i0, i1);
    return rc;
}

static int do_dontneed(winalloc *w, uint64_t a, uint64_t n, int arg) {
    size_t i0, i1, i;
    int rc = 0;
    (void)arg;
    if (split_range(w, a, a + n, &i0, &i1) != 0) return -1;

    for (i = i0; i < i1; i++) {
        uint64_t len = w->ext[i].end - w->ext[i].start;
        int prot = w->ext[i].state & P_PROT;
        if (!(w->ext[i].state & P_COMMIT)) continue;      /* reserved stays reserved */
        if (os_decommit(w->ext[i].start, len) != 0) {     /* drop contents */
            rc = -1;
            break;
        }
        w->ext[i].state = P_MAPPED;                       /* now truthfully reserved */
        if (prot) {                                       /* accessible: zeros back now */
            if (os_commit(w->ext[i].start, len, prot) != 0) {
                rc = -1;
                break;
            }
            w->ext[i].state = (unsigned char)(P_MAPPED | P_COMMIT | prot);
        }
        /* PROT_NONE: stays reserved; a later mprotect commits fresh zero pages */
    }

    coalesce_around(w, i0, i1);
    return rc;
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

int afw_vma_adopt(uint64_t base, uint64_t size, const unsigned char *page_prot) {
    size_t npages, nruns, cap, p, r, idx;
    vma_ext *ext;
    winalloc *w;

    if (!base || (base & (PG - 1)) || !size || (size & (PG - 1)) || !page_prot ||
        size > (uint64_t)SIZE_MAX || base > UINT64_MAX - size)
        return -LNX_EINVAL;

    npages = (size_t)(size / PG);
    nruns = 1;
    for (p = 1; p < npages; p++)
        if ((page_prot[p] & P_PROT) != (page_prot[p - 1] & P_PROT)) nruns++;

    cap = nruns < 8 ? 8 : nruns;
    if (cap > SIZE_MAX / sizeof *ext) return -LNX_ENOMEM;
    ext = (vma_ext *)malloc(cap * sizeof *ext);
    if (!ext) return -LNX_ENOMEM;

    for (p = 0, r = 0; p < npages; r++) {
        unsigned char prot = (unsigned char)(page_prot[p] & P_PROT);
        size_t q = p + 1;
        while (q < npages && (page_prot[q] & P_PROT) == prot) q++;
        ext[r].start = base + (uint64_t)p * PG;
        ext[r].end = base + (uint64_t)q * PG;
        ext[r].state = (unsigned char)(P_MAPPED | P_COMMIT | prot);
        p = q;
    }

    LOCK();
    idx = lower_bound_alloc(base);
    if (idx < g_n && g_a[idx].base == base && g_a[idx].size == size) {
        size_t i;
        if (g_a[idx].owned) { UNLOCK(); free(ext); return -LNX_EEXIST; }
        /* Re-adopt contract (reviewer 2, PR #14): allowed only while the whole
         * range is still mapped and committed (before munmap / decommit). */
        if (g_a[idx].mapped_bytes != size) { UNLOCK(); free(ext); return -LNX_EINVAL; }
        for (i = 0; i < g_a[idx].next; i++) {
            if ((g_a[idx].ext[i].state & (P_MAPPED | P_COMMIT)) != (P_MAPPED | P_COMMIT)) {
                UNLOCK(); free(ext); return -LNX_EINVAL;
            }
        }
        /* Replace extents atomically (e.g. after RELRO). */
        free(g_a[idx].ext);
        g_a[idx].ext = ext;
        g_a[idx].next = nruns;
        g_a[idx].cap = cap;
        g_a[idx].mapped_bytes = size;
        UNLOCK();
        return 0;
    }
    if (idx < g_n && g_a[idx].base < base + size) {
        UNLOCK();
        free(ext);
        return -LNX_EEXIST;
    }
    if (g_n == g_cap) {
        size_t ncap;
        winalloc *na;
        if (g_cap > SIZE_MAX / 2 / sizeof *g_a) { UNLOCK(); free(ext); return -LNX_ENOMEM; }
        ncap = g_cap ? g_cap * 2 : 16;
        na = (winalloc *)realloc(g_a, ncap * sizeof *g_a);
        if (!na) { UNLOCK(); free(ext); return -LNX_ENOMEM; }
        g_a = na; g_cap = ncap;
    }
    if (idx < g_n) memmove(&g_a[idx + 1], &g_a[idx], (g_n - idx) * sizeof *g_a);
    g_n++;
    w = &g_a[idx];
    w->base = base;
    w->size = size;
    w->mapped_bytes = size;
    w->ext = ext;
    w->next = nruns;
    w->cap = cap;
    w->owned = 0;
    UNLOCK();
    return 0;
}

int afw_vma_forget(uint64_t base) {
    winalloc *w;
    if (!base) return 0;
    LOCK();
    w = find(base);
    if (!w) { UNLOCK(); return 0; }
    if (w->base != base || w->owned) { UNLOCK(); return -LNX_EINVAL; }
    remove_alloc(w);
    UNLOCK();
    return 0;
}
