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

uint64_t afw_tls_static_off(int mod) {
    return (mod >= 1 && mod <= g_layout.nmod) ? g_layout.off[mod - 1] : 0;
}

uintptr_t *afw_tls_static_alloc(void **out) {
    unsigned char *block, *tp;
    *out = NULL;
    int m;
    if (!g_finished && afw_tls_layout_finish(&g_layout) != 0) return NULL;
#if defined(_WIN32)
    block = (unsigned char *)VirtualAlloc(NULL, (SIZE_T)g_layout.alloc_size, MEM_RESERVE | MEM_COMMIT,
                                          PAGE_READWRITE);   /* 64KB aligned, zeroed */
#else
    {
        void *p = NULL;
        if (posix_memalign(&p, AFW_TLS_MAX_ALIGN, (size_t)g_layout.alloc_size) != 0) p = NULL;
        if (p) memset(p, 0, (size_t)g_layout.alloc_size);
        block = (unsigned char *)p;
    }
#endif
    if (!block) return NULL;
    *out = block;
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
    if (g_finished) return 0;
    if (afw_tls_layout_finish(&g_layout) != 0) {
        fprintf(stderr, "error: static TLS layout overflow\n");
        return -1;
    }
    g_finished = 1;
    return afw_tls_thread_rebuild();
}

SYSV void *afw_tls_get_addr(const afw_tls_index *ti) {
    uintptr_t *tp = afw_tls_block();
    if (!ti || ti->module < 1 || ti->module > (uint64_t)g_layout.nmod || !tp) {
        fprintf(stderr, "fatal: __tls_get_addr with module %llu (loaded: %d)\n",
                ti ? (unsigned long long)ti->module : 0ULL, g_layout.nmod);
        abort();
    }
    return (unsigned char *)tp - g_layout.off[ti->module - 1] + ti->offset;
}
