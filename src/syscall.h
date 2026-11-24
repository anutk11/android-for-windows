/*
 * syscall.h - Linux syscall emulation: the entry that patched `syscall`
 * sites call, and the dispatcher that turns Linux calls into host calls.
 */
#ifndef AFW_SYSCALL_H
#define AFW_SYSCALL_H

#include <stdint.h>

/*
 * Assembly entry, reached from a per-number stub:  mov eax, NR ; jmp entry
 *
 * ASSUMPTION (documented on purpose): the patched site was
 * "mov eax, NR; syscall" and is now "call stub; nop; nop". The `call` writes
 * the return address at [rsp-8] of the caller, and this entry pushes more
 * below that. That is only safe because the caller keeps nothing in the
 * System V red zone (the 128 bytes below rsp). The patcher checks every
 * enclosing function for [rsp-N] accesses and refuses to patch otherwise.
 *
 * Contract, same as the real instruction: arguments in rdi, rsi, rdx, r10,
 * r8, r9; result (or -errno) in rax; rcx and r11 clobbered; everything else,
 * including all xmm registers, preserved.
 */
void afw_syscall_entry(void);

/* The dispatcher, called by the entry with the native C convention. */
int64_t afw_syscall_dispatch(int64_t nr, int64_t *args);

/* Per-number call counts, for the runtime report. */
#define AFW_MAX_SYSCALL 512
extern long afw_syscall_counts[AFW_MAX_SYSCALL];
void afw_syscall_report(void);

/* The last syscall made through the entry: number, arguments, and the
 * return address into the Android code that made it (diagnosis). */
extern volatile int64_t afw_last_syscall_nr;
extern volatile int64_t afw_last_syscall_args[6];
extern volatile uint64_t afw_last_syscall_ret;
int64_t afw_syscall_from_entry(int64_t nr, int64_t *args);

/* Opt-in G2-1 measurement logging (--probe-syscalls); 0 by default. */
extern int afw_syscall_probe_log;
void afw_syscall_probe_summary(void);

#endif
