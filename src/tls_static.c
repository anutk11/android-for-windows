/* tls_static.c - see tls_static.h */
#include "tls_static.h"
#include "tls_patch.h"
#include "bionic_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

static afw_tls_layout g_layout;
static afw_bionic_static_tls g_bionic_stl;
static const void *g_image[AFW_TLS_MAX_MODULES];
static afw_tls_segment g_seg[AFW_TLS_MAX_MODULES];
static int g_finished;

/* ---- G2-5b: Dynamic PT_TLS modules (dlopen after startup) + per-thread DTV ---- */
typedef struct {
    const void     *raw_image; /* mapped .tdata before finalize (Phase A) */
    unsigned char  *image;     /* owned heap copy of relocated .tdata (Phase B) */
    size_t          filesz;
    size_t          memsz;
    size_t          align;
    int32_t         ready;     /* seq_cst published once image is copied & immutable */
} afw_dyn_tls_mod;

typedef struct {
    void *slots[AFW_TLS_MAX_DYN];
} afw_dtv;

static afw_dyn_tls_mod g_dyn_mods[AFW_TLS_MAX_DYN];
static int g_ndyn;
static _Thread_local afw_dtv *t_dtv;

static void dtv_release_cb(void *p) {
    afw_dtv *d = (afw_dtv *)p;
    int i;
    if (!d) return;
    if (t_dtv == d) t_dtv = NULL;
    for (i = 0; i < AFW_TLS_MAX_DYN; i++) {
        if (d->slots[i]) {
            afw_os_aligned_free(d->slots[i]);
            d->slots[i] = NULL;
        }
    }
    free(d);
}

void afw_tls_dtv_free_current(void) {
    afw_dtv *d = t_dtv;
    if (!d) return;
    /* Release only after the OS FLS/key slot is cleared; on failure keep t_dtv
     * and the OS registration intact so the thread-exit callback cleans it up
     * once without a double-free or UAF. */
    if (afw_os_dtv_fls_set(NULL, NULL) != 0) return;
    t_dtv = NULL;
    dtv_release_cb(d);
}

int afw_tls_is_static_module(int mod) {
    return mod >= 1 && mod <= g_layout.nmod;
}

int afw_tls_is_dynamic_module(int mod) {
    return mod >= AFW_TLS_DYN_BASE && mod < AFW_TLS_DYN_BASE + g_ndyn;
}

static int register_dynamic(const void *image, const afw_tls_segment *seg, const char *name) {
    uint64_t align;
    int idx;
    if (!seg) return 0;
    if (g_ndyn >= AFW_TLS_MAX_DYN) {
        fprintf(stderr, "error: %s: too many dynamic TLS modules (limit %d)\n", name, AFW_TLS_MAX_DYN);
        return 0;
    }
    align = seg->p_align ? seg->p_align : 1u;
    if ((align & (align - 1u)) != 0 || align > AFW_TLS_MAX_ALIGN) {
        fprintf(stderr, "error: %s: invalid dynamic TLS alignment %llu\n",
                name, (unsigned long long)seg->p_align);
        return 0;
    }
    if (seg->p_filesz > seg->p_memsz) {
        fprintf(stderr, "error: %s: dynamic TLS file size above memory size\n", name);
        return 0;
    }
    if (seg->p_memsz > (64ULL * 1024ULL * 1024ULL)) {
        fprintf(stderr, "error: %s: dynamic TLS size %llu exceeds 64MB limit\n",
                name, (unsigned long long)seg->p_memsz);
        return 0;
    }
    idx = g_ndyn++;
    g_dyn_mods[idx].raw_image = image;
    g_dyn_mods[idx].image     = NULL;
    g_dyn_mods[idx].filesz    = (size_t)seg->p_filesz;
    g_dyn_mods[idx].memsz     = (size_t)seg->p_memsz;
    g_dyn_mods[idx].align     = (size_t)align;
    afw_os_atomic_store_i32(&g_dyn_mods[idx].ready, 0);
    return AFW_TLS_DYN_BASE + idx;
}

int afw_tls_dynamic_finalize(int mod) {
    int idx;
    afw_dyn_tls_mod *m;
    unsigned char *copy = NULL;
    if (mod < AFW_TLS_DYN_BASE || mod >= AFW_TLS_DYN_BASE + g_ndyn) return -1;
    idx = mod - AFW_TLS_DYN_BASE;
    m = &g_dyn_mods[idx];
    if (afw_os_atomic_load_i32(&m->ready) != 0) return 0;
    if (m->filesz > 0) {
        if (!m->raw_image) return -1;
        copy = (unsigned char *)malloc(m->filesz);
        if (!copy) {
            fprintf(stderr, "error: out of memory copying dynamic TLS .tdata image\n");
            return -1;
        }
        memcpy(copy, m->raw_image, m->filesz);
    }
    m->image = copy;
    m->raw_image = NULL;
    afw_os_atomic_store_i32(&m->ready, 1);
    return 0;
}

int afw_tls_dynamic_is_finalized(int mod) {
    int idx;
    if (mod < AFW_TLS_DYN_BASE || mod >= AFW_TLS_DYN_BASE + AFW_TLS_MAX_DYN) return 0;
    idx = mod - AFW_TLS_DYN_BASE;
    return afw_os_atomic_load_i32(&g_dyn_mods[idx].ready) != 0;
}

int afw_tls_static_register(const void *image, const afw_tls_segment *seg, const char *name) {
    int m;
    if (g_finished)
        return register_dynamic(image, seg, name);
    m = afw_tls_layout_add(&g_layout, seg);
    if (m < 0) {
        static const char *why[] = {"", "too many TLS modules", "TLS alignment is not a power of two",
                                    "TLS alignment above 64KB", "TLS file size above memory size",
                                    "TLS size overflow"};
        fprintf(stderr, "error: %s: %s\n", name, why[-m < 6 ? -m : 0]);
        return 0;
    }
    g_image[m] = image;
    g_seg[m] = *seg;
    return m + 1;
}

int afw_tls_static_unregister(int mod) {
    if (mod >= AFW_TLS_DYN_BASE) {
        int idx = mod - AFW_TLS_DYN_BASE;
        if (idx < 0 || idx != g_ndyn - 1) return -1;
        if (afw_os_atomic_load_i32(&g_dyn_mods[idx].ready) != 0) return -1;
        g_dyn_mods[idx].raw_image = NULL;
        g_dyn_mods[idx].image     = NULL;
        g_dyn_mods[idx].filesz    = 0;
        g_dyn_mods[idx].memsz     = 0;
        g_dyn_mods[idx].align     = 0;
        afw_os_atomic_store_i32(&g_dyn_mods[idx].ready, 0);
        g_ndyn--;
        return 0;
    }
    if (g_finished || mod < 1 || mod != g_layout.nmod) return -1;
    g_layout.nmod--;
    g_layout.off[mod - 1] = 0;
    g_image[mod - 1] = NULL;
    memset(&g_seg[mod - 1], 0, sizeof g_seg[mod - 1]);
    /* max_align may stay larger than needed: only wastes a little padding */
    return 0;
}

uint64_t afw_tls_static_off(int mod) {
    return (mod >= 1 && mod <= g_layout.nmod) ? g_layout.off[mod - 1] : 0;
}

int afw_tls_static_get_bionic_layout(afw_bionic_static_tls *out) {
    if (!g_finished || !out) return -1;
    *out = g_bionic_stl;
    return 0;
}

uint64_t afw_tls_static_tp_off(void) {
    return g_finished ? g_layout.tp_off : 0;
}

void afw_tls_static_init_external(uintptr_t *tp) {
    unsigned char *tp_bytes = (unsigned char *)tp;
    int m;
    if (!g_finished || !tp_bytes) return;
    for (m = 0; m < g_layout.nmod; m++) {
        unsigned char *dst = tp_bytes - g_layout.off[m];
        uint64_t fsz = g_seg[m].p_filesz;
        uint64_t msz = g_seg[m].p_memsz;
        if (fsz > msz) fsz = msz;
        if (fsz && g_image[m])
            memcpy(dst, g_image[m], (size_t)fsz);
        if (msz > fsz)
            memset(dst + fsz, 0, (size_t)(msz - fsz));
    }
}

uintptr_t *afw_tls_static_alloc(void **out, unsigned char **area) {
    unsigned char *block, *tp;
    size_t total;
    int m;
    *out = NULL; *area = NULL;
    if (!g_finished && afw_tls_layout_finish(&g_layout) != 0) return NULL;
    /* the bionic thread area (pthread_internal_t, bionic_tls) shares the
     * allocation: it is released with the block, by the same FLS/key callback */
    if (g_layout.alloc_size > SIZE_MAX - AFW_THREAD_AREA_SIZE) return NULL;
    total = (size_t)g_layout.alloc_size + AFW_THREAD_AREA_SIZE;
#if defined(_WIN32)
    block = (unsigned char *)VirtualAlloc(NULL, (SIZE_T)total, MEM_RESERVE | MEM_COMMIT,
                                          PAGE_READWRITE);   /* 64KB aligned, zeroed */
#else
    {
        void *p = NULL;
        if (posix_memalign(&p, AFW_TLS_MAX_ALIGN, total) != 0) p = NULL;
        if (p) memset(p, 0, total);
        block = (unsigned char *)p;
    }
#endif
    if (!block) return NULL;
    *out = block;
    *area = block + g_layout.alloc_size;       /* alloc_size is page-aligned */
    tp = block + g_layout.tp_off;
    for (m = 0; m < g_layout.nmod; m++)   /* .tdata copied, .tbss already zero */
        if (g_seg[m].p_filesz) memcpy(tp - g_layout.off[m], g_image[m], (size_t)g_seg[m].p_filesz);
    return (uintptr_t *)tp;
}

void afw_tls_static_free(void *block) {
    if (!block) return;
#if defined(_WIN32)
    VirtualFree(block, 0, MEM_RELEASE);
#else
    free(block);
#endif
}

int afw_tls_static_finish(void) {
    int m;
    afw_bionic_static_tls stl;
    const void *orig[AFW_TLS_MAX_MODULES] = {0};
    void *copy[AFW_TLS_MAX_MODULES] = {0};
    if (g_finished) return 0;
    if (afw_tls_layout_finish(&g_layout) != 0 ||
        afw_tls_layout_to_bionic(&g_layout, &stl) != 0) {
        fprintf(stderr, "error: static TLS layout overflow\n");
        return -1;
    }
    /* Own copies of the (relocated) .tdata images from now on: a library
     * whose load fails later may release its mapping, and threads created
     * later must not read from it (reviewer 4, PR #9). */
    /* All copies first, then swap; if thread_rebuild fails, roll back cleanly
     * and keep g_finished = 0 so failed loads can unregister and retry works. */
    for (m = 0; m < g_layout.nmod; m++) {
        orig[m] = g_image[m];
        if (!g_seg[m].p_filesz) continue;
        copy[m] = malloc((size_t)g_seg[m].p_filesz);
        if (!copy[m]) {
            while (m-- > 0) free(copy[m]);
            fprintf(stderr, "error: out of memory copying TLS images\n");
            return -1;
        }
        memcpy(copy[m], g_image[m], (size_t)g_seg[m].p_filesz);
    }
    for (m = 0; m < g_layout.nmod; m++) g_image[m] = copy[m];
    if (afw_tls_thread_rebuild() != 0) {
        for (m = 0; m < g_layout.nmod; m++) { g_image[m] = orig[m]; free(copy[m]); }
        return -1;
    }
    g_bionic_stl = stl;
    afw_shared_globals_set_static_tls(&g_bionic_stl);
    g_finished = 1;
    return 0;
}

int afw_tls_static_is_finished(void) { return g_finished; }
int afw_tls_static_count(void) { return g_layout.nmod; }

uint64_t afw_tls_static_memsz(int mod) {
    if (mod >= 1 && mod <= g_layout.nmod) return g_seg[mod - 1].p_memsz;
    if (mod >= AFW_TLS_DYN_BASE && mod < AFW_TLS_DYN_BASE + AFW_TLS_MAX_DYN) {
        int idx = mod - AFW_TLS_DYN_BASE;
        return afw_os_atomic_load_i32(&g_dyn_mods[idx].ready) ? (uint64_t)g_dyn_mods[idx].memsz : 0;
    }
    return 0;
}

void *afw_tls_static_resolve(uint64_t module, uint64_t offset) {
    uintptr_t *tp = afw_tls_block();
    if (!tp || module < 1 || module > (uint64_t)g_layout.nmod) return NULL;
    /* inside the module's block: offset < p_memsz (reviewer 2, PR #6 A2);
     * off >= p_memsz always holds (tls_layout.c), so this never wraps */
    if (offset >= g_seg[module - 1].p_memsz) return NULL;
    return (unsigned char *)tp - g_layout.off[module - 1] + offset;
}

static void *tls_dynamic_resolve(uint64_t module, uint64_t offset, int do_alloc) {
    uint64_t idx64;
    const afw_dyn_tls_mod *m;
    void *blk;
    if (module < (uint64_t)AFW_TLS_DYN_BASE) return NULL;
    idx64 = module - (uint64_t)AFW_TLS_DYN_BASE;
    if (idx64 >= (uint64_t)AFW_TLS_MAX_DYN) return NULL;
    m = &g_dyn_mods[idx64];
    /* Acquire load of ready synchronizes-with release store in afw_tls_dynamic_finalize(). */
    if (afw_os_atomic_load_i32(&m->ready) == 0) return NULL;
    if (offset >= (uint64_t)m->memsz) return NULL;
    if (!t_dtv) {
        afw_dtv *d;
        if (!do_alloc) return NULL;
        d = (afw_dtv *)calloc(1, sizeof *d);
        if (!d) return NULL;
        if (afw_os_dtv_fls_set(dtv_release_cb, d) != 0) {
            free(d);
            return NULL;
        }
        t_dtv = d;
    }
    blk = t_dtv->slots[idx64];
    if (!blk) {
        if (!do_alloc) return NULL;
        blk = afw_os_aligned_alloc_zero(m->align, m->memsz);
        if (!blk) return NULL;
        if (m->filesz > 0 && m->image)
            memcpy(blk, m->image, m->filesz);
        t_dtv->slots[idx64] = blk;
    }
    return (unsigned char *)blk + offset;
}

void *afw_tls_resolve_existing(uint64_t module) {
    if (module >= 1 && module <= (uint64_t)g_layout.nmod)
        return afw_tls_static_resolve(module, 0);
    return tls_dynamic_resolve(module, 0, 0);
}

SYSV void *afw_tls_get_addr(const afw_tls_index *ti) {
    void *p = NULL;
    if (ti) {
        if (ti->module >= 1 && ti->module <= (uint64_t)g_layout.nmod)
            p = afw_tls_static_resolve(ti->module, ti->offset);
        else
            p = tls_dynamic_resolve(ti->module, ti->offset, 1);
    }
    if (!p) {
        fprintf(stderr, "fatal: __tls_get_addr(module %llu, offset 0x%llx): outside every TLS block "
                        "(%d static, %d dynamic modules)\n", ti ? (unsigned long long)ti->module : 0ULL,
                ti ? (unsigned long long)ti->offset : 0ULL, g_layout.nmod, g_ndyn);
        abort();
    }
    return p;
}
