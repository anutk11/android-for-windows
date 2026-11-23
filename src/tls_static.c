/* tls_static.c - see tls_static.h */
#include "tls_static.h"
#include "tls_patch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

static afw_tls_layout g_layout;
static const void *g_image[AFW_TLS_MAX_MODULES];
static afw_tls_segment g_seg[AFW_TLS_MAX_MODULES];
static int g_finished;

int afw_tls_static_register(const void *image, const afw_tls_segment *seg, const char *name) {
    int m;
    if (g_finished) {
        fprintf(stderr, "error: %s has thread-local storage but was loaded after startup; "
                        "dynamic TLS is not supported yet (G2)\n", name);
        return 0;
    }
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
    const void *orig[AFW_TLS_MAX_MODULES] = {0};
    void *copy[AFW_TLS_MAX_MODULES] = {0};
    if (g_finished) return 0;
    if (afw_tls_layout_finish(&g_layout) != 0) {
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
    g_finished = 1;
    return 0;
}

int afw_tls_static_is_finished(void) { return g_finished; }
int afw_tls_static_count(void) { return g_layout.nmod; }

uint64_t afw_tls_static_memsz(int mod) {
    return (mod >= 1 && mod <= g_layout.nmod) ? g_seg[mod - 1].p_memsz : 0;
}

void *afw_tls_static_resolve(uint64_t module, uint64_t offset) {
    uintptr_t *tp = afw_tls_block();
    if (!tp || module < 1 || module > (uint64_t)g_layout.nmod) return NULL;
    /* inside the module's block: offset < p_memsz (reviewer 2, PR #6 A2);
     * off >= p_memsz always holds (tls_layout.c), so this never wraps */
    if (offset >= g_seg[module - 1].p_memsz) return NULL;
    return (unsigned char *)tp - g_layout.off[module - 1] + offset;
}

SYSV void *afw_tls_get_addr(const afw_tls_index *ti) {
    void *p = ti ? afw_tls_static_resolve(ti->module, ti->offset) : NULL;
    if (!p) {
        fprintf(stderr, "fatal: __tls_get_addr(module %llu, offset 0x%llx): outside every TLS block "
                        "(%d modules)\n", ti ? (unsigned long long)ti->module : 0ULL,
                ti ? (unsigned long long)ti->offset : 0ULL, g_layout.nmod);
        abort();
    }
    return p;
}
