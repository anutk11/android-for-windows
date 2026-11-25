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

/* Frame built by afw_syscall_entry at rbp - 88 (offsets verified by _Static_assert). */
typedef struct {
    uint64_t rbx;        /* +0   (rbp - 88) */
    uint64_t r12;        /* +8   (rbp - 80) */
    uint64_t r13;        /* +16  (rbp - 72) */
    uint64_t r14;        /* +24  (rbp - 64) */
    uint64_t r15;        /* +32  (rbp - 56) */
    int64_t  args[6];    /* +40  (rbp - 48): rdi, rsi, rdx, r10, r8, r9 */
    uint64_t caller_rbp; /* +88  (rbp + 0)  */
    uint64_t rflags;     /* +96  (rbp + 8)  */
    uint64_t rip;        /* +104 (rbp + 16) stub return address */
} afw_syscall_frame;

/* The last syscall made through the entry: number, arguments, and the
 * return address into the Android code that made it (diagnosis). */
extern volatile int64_t afw_last_syscall_nr;
extern volatile int64_t afw_last_syscall_args[6];
extern volatile uint64_t afw_last_syscall_ret;
int64_t afw_syscall_from_entry(int64_t nr, afw_syscall_frame *frame);

/* Per-thread Linux signal mask (for SYS_rt_sigprocmask and clone inheritance). */
uint64_t afw_syscall_get_sigmask(void);
void     afw_syscall_set_sigmask(uint64_t mask);

/* Opt-in G2-1 measurement logging (--probe-syscalls); 0 by default. */
extern int afw_syscall_probe_log;
void afw_syscall_probe_summary(void);

/* Register ART %gs base setter/getter for SYS_arch_prctl (ARCH_SET_GS / ARCH_GET_GS). */
void afw_syscall_set_gs_ops(void (*set_gs)(uintptr_t), uintptr_t (*get_gs)(void));
void afw_syscall_set_abort_cb(void (*on_abort)(uintptr_t sp));
void afw_syscall_set_net_cb(int (*net_cb)(int64_t nr, const int64_t *args, int64_t *ret_out));

#endif
