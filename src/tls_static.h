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

#define AFW_TLS_DYN_BASE (AFW_TLS_MAX_MODULES + 1)
#define AFW_TLS_MAX_DYN  64

/* Register a PT_TLS segment whose initial image (.tdata) is at `image`.
 * Before afw_tls_static_finish(): registers a static TLS module (1..64).
 * After  afw_tls_static_finish(): registers a dynamic TLS module (65..128)
 * served lazily from the per-thread DTV in afw_tls_get_addr().
 * Returns the 1-based module id, or 0 on error. */
int afw_tls_static_register(const void *image, const afw_tls_segment *seg, const char *name);

/* Undo the last registration (a library that failed to load before finalize). */
int afw_tls_static_unregister(int mod);

int afw_tls_is_static_module(int mod);
int afw_tls_is_dynamic_module(int mod);

/* Finalize a dynamically registered PT_TLS module after relocations (copies
 * relocated .tdata image to owned heap memory and publishes ready = 1). */
int afw_tls_dynamic_finalize(int mod);
int afw_tls_dynamic_is_finalized(int mod);

/* Release all lazily allocated dynamic DTV blocks for the calling thread
 * (called after Bionic's __cxa_thread_finalize and before clear_child_tid wake). */
void afw_tls_dtv_free_current(void);

/* Fix the static layout (startup modules). After this, new PT_TLS modules
 * use the dynamic DTV. Rebuilds the calling thread's block. Idempotent. */
int afw_tls_static_finish(void);
int afw_tls_static_is_finished(void);
int afw_tls_static_count(void);

/* Offset of static module `mod` (1-based) below tp, or 0 if unknown/dynamic. */
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

/* Address of byte `offset` of static module `module` (1-based) for the calling
 * thread, or NULL if the module does not exist or offset >= its p_memsz. */
void *afw_tls_static_resolve(uint64_t module, uint64_t offset);
/* Non-allocating TLS block lookup for dl_iterate_phdr() dlpi_tls_data:
 * returns static block or already-allocated dynamic DTV block, else NULL. */
void *afw_tls_resolve_existing(uint64_t module);
uint64_t afw_tls_static_memsz(int mod);   /* p_memsz of module mod (static or dynamic), 0 if unknown */

/* General-dynamic TLS resolver: handles both startup static TLS modules and
 * dynamically dlopen'd PT_TLS modules via the internal per-thread DTV. */
typedef struct { uint64_t module, offset; } afw_tls_index;
SYSV void *afw_tls_get_addr(const afw_tls_index *ti);

#endif
