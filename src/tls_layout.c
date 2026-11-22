/* tls_layout.c - see tls_layout.h. Formulas from reviewer 3 (issue #4). */
#include "tls_layout.h"

#include <string.h>

static int round_up(uint64_t v, uint64_t a, uint64_t *out) {   /* a: power of two */
    if (v > UINT64_MAX - (a - 1)) return -1;
    *out = (v + a - 1) & ~(a - 1);
    return 0;
}

int afw_tls_layout_add(afw_tls_layout *l, const afw_tls_segment *seg) {
    uint64_t a = seg->p_align ? seg->p_align : 1, r, prev, need, off;
    if (l->nmod >= AFW_TLS_MAX_MODULES) return -1;
    if (a & (a - 1)) return -2;
    if (a > AFW_TLS_MAX_ALIGN) return -3;
    if (seg->p_filesz > seg->p_memsz) return -4;
    r = seg->p_vaddr & (a - 1);
    prev = l->nmod ? l->off[l->nmod - 1] : 0;
    /* off = roundup(prev + memsz + r, a) - r */
    if (seg->p_memsz > UINT64_MAX - prev || prev + seg->p_memsz > UINT64_MAX - r) return -5;
    need = prev + seg->p_memsz + r;
    if (round_up(need, a, &off)) return -5;
    off -= r;
    l->off[l->nmod] = off;
    if (a > l->max_align) l->max_align = a;
    return l->nmod++;
}

int afw_tls_layout_finish(afw_tls_layout *l) {
    uint64_t top = l->nmod ? l->off[l->nmod - 1] : 0, tp, sz;
    if (l->max_align < 16) l->max_align = 16;
    if (round_up(top, l->max_align, &tp)) return -5;
    if (tp > UINT64_MAX - AFW_TLS_SLOTS_BYTES) return -5;
    if (round_up(tp + AFW_TLS_SLOTS_BYTES, 4096, &sz)) return -5;
    l->tp_off = tp;
    l->alloc_size = sz;
    return 0;
}
