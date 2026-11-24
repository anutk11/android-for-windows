/*
 * tls_layout.h - Static TLS layout, x86_64 Variant II (docs/design/G1-TLS.md, section 2).
 *
 *   low                                                   high
 *   [ module N ] ... [ module 1 ] [ bionic slots, 128 bytes ]
 *                                 ^ tp
 * Module m lives at tp - off[m]. Pure arithmetic: no OS calls, unit-tested
 * on the host (tools/tls_layout_test.c).
 */
#ifndef AFW_TLS_LAYOUT_H
#define AFW_TLS_LAYOUT_H

#include <stddef.h>
#include <stdint.h>

#define AFW_TLS_MAX_MODULES 32
#define AFW_TLS_SLOTS_BYTES 128           /* 16 bionic slots */
#define AFW_TLS_MAX_ALIGN   (64 * 1024)   /* VirtualAlloc granularity */

typedef struct {
    uint64_t p_vaddr, p_align, p_memsz, p_filesz;
} afw_tls_segment;

typedef struct {
    int nmod;
    uint64_t off[AFW_TLS_MAX_MODULES];    /* module m (0-based) at tp - off[m] */
    uint64_t max_align;                    /* >= 16 */
    uint64_t tp_off;                       /* tp = block + tp_off */
    uint64_t alloc_size;                   /* bytes per thread, page multiple */
} afw_tls_layout;

/* Append one PT_TLS module. Returns its 0-based index, or a negative error:
 * -1 too many modules, -2 p_align not a power of two, -3 p_align above
 * 64KB, -4 p_filesz > p_memsz, -5 size overflow. On error the layout is
 * unchanged. */
int afw_tls_layout_add(afw_tls_layout *l, const afw_tls_segment *seg);

/* Recompute tp_off and alloc_size after the last add. Returns 0, or -5 on
 * overflow. */
int afw_tls_layout_finish(afw_tls_layout *l);

/*
 * Bionic StaticTlsLayout (5 x uint64_t at libc_shared_globals + 0x450,
 * Android 14 libc.so Build ID fa337969c798946280caa45e2d71a2e7):
 *
 *   low                                                                 high
 *   [ module N ] ... [ module 1 ] [ bionic_tcb (128B) ] [pad] [ bionic_tls ]
 *                                 ^ tp (= offset_bionic_tcb_ = offset_thread_pointer_)
 *                                                             ^ offset_bionic_tls_
 *   |<------------------------------- size_ ------------------------------->|
 *
 * Module m lives at tp - l->off[m] inside [0, offset_thread_pointer_),
 * matching R_X86_64_TPOFF64 relocations computed by G1-TLS.
 */
#define AFW_BIONIC_TLS_SIZE  (64u * 1024u)  /* generous upper bound; oracle-checked in bionic-probe */
#define AFW_BIONIC_TLS_ALIGN 64u            /* cache-line alignment (power of two) */

typedef struct {
    uint64_t size;
    uint64_t align;
    uint64_t offset_bionic_tcb;
    uint64_t offset_thread_pointer;
    uint64_t offset_bionic_tls;
} afw_bionic_static_tls;

/* Derive Bionic's StaticTlsLayout from a finished afw_tls_layout.
 * Returns 0 on success, or -5 on invalid layout / overflow. */
int afw_tls_layout_to_bionic(const afw_tls_layout *l, afw_bionic_static_tls *out);

#endif
