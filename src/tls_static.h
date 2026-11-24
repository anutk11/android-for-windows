/*
 * tls_static.h - ELF static TLS for the libraries loaded at startup
 * (docs/design/G1-TLS.md). One layout for the whole process, fixed before
 * any library code runs; every thread gets its own copy of every module's
 * TLS block, below tp.
 */
#ifndef AFW_TLS_STATIC_H
#define AFW_TLS_STATIC_H

#include <stddef.h>
#include <stdint.h>
#include "platform.h"
#include "tls_layout.h"

/* Register a PT_TLS segment whose initial image (.tdata) is at `image`.
 * Returns the 1-based module id, or 0 on error (message printed): layout
 * already fixed, bad alignment, too many modules. */
int afw_tls_static_register(const void *image, const afw_tls_segment *seg, const char *name);

/* Undo the last registration (a library that failed to load). Returns 0,
 * or -1 if mod is not the last module or the layout is already fixed. */
int afw_tls_static_unregister(int mod);

/* Fix the layout. After this, register() refuses (dynamic TLS is G2).
 * Rebuilds the calling thread's block. Idempotent. Returns 0 or -1. */
int afw_tls_static_finish(void);
int afw_tls_static_is_finished(void);
int afw_tls_static_count(void);

/* Offset of module `mod` (1-based) below tp, or 0 if unknown. */
uint64_t afw_tls_static_off(int mod);

/* Copy the finalized Bionic StaticTlsLayout (valid after afw_tls_static_finish).
 * Returns 0 on success, -1 if not yet finalized. */
int afw_tls_static_get_bionic_layout(afw_bionic_static_tls *out);

/* Thread pointer offset below static TLS base (0 if not finished). */
uint64_t afw_tls_static_tp_off(void);

/* Initialize static ELF TLS .tdata images (p_filesz > 0) below an externally
 * allocated thread pointer `tp` (e.g. Bionic pthread_create newtls). */
void afw_tls_static_init_external(uintptr_t *tp);

/* Allocate and initialise one thread's block. Returns tp (the bionic slot
 * array), or NULL; *block gets the allocation, which is what
 * afw_tls_static_free() takes (tp's offset in it depends on the layout at
 * the time of allocation, so tp alone is not enough). */
uintptr_t *afw_tls_static_alloc(void **block, unsigned char **area);

/* Per-thread bionic state that bionic reaches through the thread pointer
 * (docs/design/G1-LIBC-INIT.md), zeroed, in the same allocation as the TLS
 * block (*area above, page-aligned):
 *   [0, 64KB)     pthread_internal_t  (tp[1]; tid at +0x10, errno at +0x300 measured)
 *   [64KB, 128KB) bionic_tls          (tp[9])
 * Both sizes are generous upper bounds until the real sizes are measured. */
#define AFW_THREAD_AREA_SIZE   (128u * 1024u)
#define AFW_PTHREAD_INTERNAL_OFF 0u
#define AFW_BIONIC_TLS_OFF     (64u * 1024u)
#define AFW_PTI_TID            0x10   /* int: gettid() reads it (measured) */
void afw_tls_static_free(void *block);

/* Address of byte `offset` of module `module` (1-based) for the calling
 * thread, or NULL if the module does not exist or offset >= its p_memsz. */
void *afw_tls_static_resolve(uint64_t module, uint64_t offset);
uint64_t afw_tls_static_memsz(int mod);   /* p_memsz of module mod, 0 if unknown */

/* What general-dynamic code calls (resolved for every library in G1, ahead
 * of libc's own export: TEMPORARY until bionic's DTV is built in G2). */
typedef struct { uint64_t module, offset; } afw_tls_index;
SYSV void *afw_tls_get_addr(const afw_tls_index *ti);

#endif
