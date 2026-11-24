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
 * Bionic StaticTlsLayout (40 bytes at libc_shared_globals + 0x450,
 * Android 14 Build ID fa337969c798946280caa45e2d71a2e7 — verified directly
 * against linker64 + libc.so disassembly in bionic-probe):
 *   +0x00 (0x450): size_                    (page-aligned & align_-aligned total size)
 *   +0x08 (0x458): align_                   (power of two, >= max_align)
 *   +0x10 (0x460): overflowed_              (bool + 7B pad; MUST be 0)
 *   +0x18 (0x468): offset_bionic_tcb_ / TP  (x86_64 Variant II: == tp_off)
 *   +0x20 (0x470): offset_bionic_tls_       (>= tp_off + 0x50 [sizeof(bionic_tcb)])
 *
 *   low                                                                 high
 *   [ module N ] ... [ module 1 ] [ bionic_tcb (128B) ] [pad] [ bionic_tls (0x2fa8) ]
 *                                 ^ tp (= offset_thread_pointer)
 *                                                             ^ offset_bionic_tls
 *   |<------------------------------------ size ------------------------------------>|
 *
 * Module m lives at tp - l->off[m] inside [0, offset_thread_pointer),
 * matching R_X86_64_TPOFF64 relocations computed by G1-TLS.
 */
#define AFW_BIONIC_TCB_SIZE  0x50u          /* measured: linker64 0x145ffe (addq $0x50) */
#define AFW_BIONIC_TLS_SIZE  0x2fa8u        /* measured: linker64 0x146087 (addq $0x2fa8) */
#define AFW_BIONIC_TLS_ALIGN 64u            /* >= alignof(bionic_tls)=8 (linker64 0x146077) */

typedef struct {
    uint64_t size;
    uint64_t align;
    uint64_t overflowed;                    /* bool overflowed_ + 7B zero padding: always 0 */
    uint64_t offset_thread_pointer;         /* +0x18: offset_bionic_tcb_ / offset_thread_pointer_ */
    uint64_t offset_bionic_tls;             /* +0x20: offset_bionic_tls_ */
} afw_bionic_static_tls;

/* Derive Bionic's StaticTlsLayout from a finished afw_tls_layout.
 * Returns 0 on success, or -5 on invalid layout / overflow. */
int afw_tls_layout_to_bionic(const afw_tls_layout *l, afw_bionic_static_tls *out);

#endif
