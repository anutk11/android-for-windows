/*
 * thread.h - G2-4b SYS_clone(56), SYS_set_tid_address(218), and safe
 * Bionic-stack thread teardown (SYS_exit(60) + _exit_with_stack_teardown).
 *
 * Pure C11: all Win32 calls and assembly trampolines live in src/platform.c
 * (Rule 8). All VMA queries go through src/vma.c under g_lock.
 */
#ifndef AFW_THREAD_H
#define AFW_THREAD_H

#include <stddef.h>
#include <stdint.h>

/* Measured Linux x86_64 clone(2) flags (Android 14 Bionic pthread_create
 * passes 0x3d0f00 = VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|PARENT_SETTID|
 * CHILD_CLEARTID, CI 138282614245). */
#define LNX_CLONE_VM             0x00000100ULL
#define LNX_CLONE_FS             0x00000200ULL
#define LNX_CLONE_FILES          0x00000400ULL
#define LNX_CLONE_SIGHAND        0x00000800ULL
#define LNX_CLONE_THREAD         0x00010000ULL
#define LNX_CLONE_SYSVSEM        0x00040000ULL
#define LNX_CLONE_SETTLS         0x00080000ULL
#define LNX_CLONE_PARENT_SETTID  0x00100000ULL
#define LNX_CLONE_CHILD_CLEARTID 0x00200000ULL
#define LNX_CLONE_CHILD_SETTID   0x01000000ULL

/* Parent register state captured in afw_syscall_entry for SYS_clone(56). */
typedef struct {
    uint64_t rip;    /* stub_ret (return address inside __bionic_clone) */
    uint64_t rbp;
    uint64_t rflags;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
} afw_clone_regs;

/* Register TLS callbacks from tls_patch.c/tls_static.c so standalone VMA/FD
 * test binaries linking syscall.c + thread.c do not need to link bionic_shim.c. */
typedef void     (*afw_tls_init_static_fn)(uintptr_t *tp);
typedef int      (*afw_tls_attach_ext_fn)(uintptr_t *tp);
typedef void     (*afw_tls_detach_ext_fn)(void);
typedef uint64_t (*afw_tls_tp_off_fn)(void);
void afw_thread_set_tls_ops(afw_tls_init_static_fn init_static,
                            afw_tls_attach_ext_fn attach_ext,
                            afw_tls_detach_ext_fn detach_ext,
                            afw_tls_tp_off_fn tp_off);

/* SYS_clone(56) and SYS_set_tid_address(218) implementations. */
int64_t afw_sys_clone(uint64_t flags, uint64_t child_stack,
                      uint64_t ptid, uint64_t ctid, uint64_t newtls,
                      const afw_clone_regs *regs);
int64_t afw_sys_set_tid_address(uint64_t tidptr);

/* If the calling cloned thread is currently running on [addr, addr + len)
 * (detached _exit_with_stack_teardown), defer the munmap until SYS_exit(60)
 * switches back to host_rsp and return 1 (*rc_out receives 0 or -errno).
 * Otherwise return 0 so normal afw_munmap runs immediately. */
int afw_thread_try_defer_self_unmap(uint64_t addr, uint64_t len,
                                    uintptr_t cur_sp, int64_t *rc_out);

/* Returns 1 if the current thread is a cloned thread on a Bionic stack. */
int afw_thread_is_cloned(void);

/* Exit a cloned thread cleanly: switch to host_rsp + restore NT_TIB ->
 * execute deferred stack munmap -> atomic clear_child_tid + WakeByAddressAll
 * -> ExitThread (never returns). */
void afw_thread_exit(int exit_code);

#endif
