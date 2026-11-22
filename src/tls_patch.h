/*
 * tls_patch.h - Make Linux/bionic "fs:" thread-local accesses work on Windows.
 *
 * Android code reads per-thread data with "fs:[offset]" (e.g. the stack
 * guard at fs:[0x28]). Windows x64 gives programs no usable fs segment, so
 * those instructions fault. We catch the fault and rewrite the instruction
 * once, in place, to "gs:[TEB TlsSlot]" - same length, native speed after.
 * See tools/fs_probe.c for the experiment that proved this.
 */
#ifndef AFW_TLS_PATCH_H
#define AFW_TLS_PATCH_H

#include <stdint.h>

/* bionic x86_64 TLS slots (fs:[8*slot]) */
#define BIONIC_TLS_SLOTS 16
#define TLS_SLOT_SELF 0
#define TLS_SLOT_THREAD_ID 1
#define TLS_SLOT_STACK_GUARD 5

/* Install the fault handler and set up the calling thread. */
int afw_tls_init(void);

/* Set up a new thread's bionic TLS block. Call at the start of every thread
 * that will run Android code. Returns 0, or -1 if the block could not be
 * allocated: the thread must then not run Android code. */
int afw_tls_thread_init(void);

/* Replace the calling thread's block with one built from the final static
 * TLS layout (bionic slots carried over). Returns 0 or -1. */
int afw_tls_thread_rebuild(void);

/* Test hooks: the next publish fails at step n (0..15: after n TLS slots
 * were set, 16: at the FLS step; -1 off); what slot i holds for the CPU. */
void afw_tls_test_fail_publish(int step);
uintptr_t afw_tls_published_slot(int i);

/* Windows TEB offset (gs:) that holds bionic slot `slot`, or -1 when there
 * is none (non-Windows, or slot out of range). Used by load-time patching. */
int afw_tls_teb_offset(int slot);

/* Number of instructions rewritten so far. */
long afw_tls_patch_count(void);

/* Current thread's bionic TLS slots (what fs:0 points to on Android). */
uintptr_t *afw_tls_block(void);

#endif
