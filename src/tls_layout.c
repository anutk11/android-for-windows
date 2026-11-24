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
    if (a > l->mod_align) l->mod_align = a;
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

int afw_tls_layout_to_bionic(const afw_tls_layout *l, afw_bionic_static_tls *out) {
    uint64_t tcb_end, bionic_tls_off, size, align;
    if (!l || !out) return -5;
    if (l->max_align < 16 || (l->max_align & (l->max_align - 1)) != 0 ||
        l->max_align > AFW_BIONIC_STATIC_TLS_MAX_ALIGN)
        return -5;
    if (l->mod_align != 0 &&
        ((l->mod_align & (l->mod_align - 1)) != 0 ||
         l->mod_align > AFW_BIONIC_STATIC_TLS_MAX_ALIGN ||
         l->mod_align > l->max_align))
        return -5;
    if (l->tp_off % l->max_align != 0) return -5;
    if (l->nmod > 0 && l->off[l->nmod - 1] > l->tp_off) return -5;
    if (l->tp_off > UINT64_MAX - AFW_BIONIC_TCB_SIZE) return -5;
    tcb_end = l->tp_off + AFW_BIONIC_TCB_SIZE;
    if (round_up(tcb_end, AFW_BIONIC_TLS_ALIGN, &bionic_tls_off)) return -5;
    if (bionic_tls_off > UINT64_MAX - AFW_BIONIC_TLS_SIZE) return -5;
    align = l->mod_align < AFW_BIONIC_TLS_ALIGN ? AFW_BIONIC_TLS_ALIGN : l->mod_align;
    if (round_up(bionic_tls_off + AFW_BIONIC_TLS_SIZE, align, &size)) return -5;
    out->size = size;
    out->align = align;
    out->overflowed = 0;
    out->offset_thread_pointer = l->tp_off;
    out->offset_bionic_tls = bionic_tls_off;
    return 0;
}
