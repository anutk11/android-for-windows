/*
 * thread.c - G2-4b SYS_clone(56), SYS_set_tid_address(218), and safe
 * Bionic-stack exit teardown (docs/design/G2-PLAN.md Section 3).
 *
 * Pure C11: all Win32 calls and assembly trampolines live in src/platform.c
 * (Rule 8).
 */
#include "thread.h"
#include "platform.h"
#include "syscall.h"
#include "tls_layout.h"
#include "vma.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define LNX_EAGAIN 11
#define LNX_ENOMEM 12
#define LNX_EFAULT 14
#define LNX_EINVAL 22
#define LNX_ENOSYS 38

#define AFW_CLONE_REQUIRED (LNX_CLONE_VM | LNX_CLONE_FS | LNX_CLONE_FILES | \
                            LNX_CLONE_SIGHAND | LNX_CLONE_THREAD)
#define AFW_CLONE_ALLOWED  (AFW_CLONE_REQUIRED | LNX_CLONE_SYSVSEM | \
                            LNX_CLONE_SETTLS | LNX_CLONE_PARENT_SETTID | \
                            LNX_CLONE_CHILD_CLEARTID | LNX_CLONE_CHILD_SETTID)

typedef struct {
    afw_os_clone_trampoline tramp;
    uint64_t  flags;
    uint64_t  ptid;
    uint64_t  ctid;
    uint64_t  newtls;
    uint64_t  init_sigmask;
    int32_t   tid;
    int       on_bionic_stack;
    uint64_t  pending_unmap_addr;
    uint64_t  pending_unmap_len;
    uintptr_t clear_child_tid_addr; /* atomic via afw_os_atomic_*_uptr */
    int32_t   clear_tid_done;       /* atomic via afw_os_atomic_xchg_i32 */
} afw_thread_ctx;

typedef struct {
    afw_thread_ctx *ctx;
    afw_os_event    ready_ev;
    int32_t         tid;
    int             start_err;
    int             ctx_owned_by_fls;
} clone_handshake;

static _Thread_local afw_thread_ctx *t_ctx;

static afw_tls_init_static_fn g_tls_init_static;
static afw_tls_attach_ext_fn  g_tls_attach_ext;
static afw_tls_tp_off_fn      g_tls_tp_off;

void afw_thread_set_tls_ops(afw_tls_init_static_fn init_static,
                            afw_tls_attach_ext_fn attach_ext,
                            afw_tls_tp_off_fn tp_off) {
    g_tls_init_static = init_static;
    g_tls_attach_ext = attach_ext;
    g_tls_tp_off = tp_off;
}

/* One-shot atomic clear_child_tid + futex wake (G2-PLAN.md Section 3.4b).
 * On abnormal exit (in_fls != 0, inside LdrShutdownThread), checks VMA
 * writability before writing so already-unmapped memory cannot fault. */
static void thread_clear_tid_once(afw_thread_ctx *ctx, int in_fls) {
    uintptr_t addr;
    if (!ctx) return;
    if (afw_os_atomic_xchg_i32(&ctx->clear_tid_done, 1) != 0) return;
    addr = afw_os_atomic_xchg_uptr(&ctx->clear_child_tid_addr, 0);
    if (!addr) return;
    if (in_fls && !afw_vma_is_writable((uint64_t)addr, 4)) return;
    /* seq_cst zero write strictly happens-before WakeByAddressAll. */
    afw_os_atomic_store_i32((void *)addr, 0);
    afw_os_wake_address_all((void *)addr);
}

/* Dedicated thread-ctx FLS release callback (runs on Windows host stack
 * during ExitThread/LdrShutdownThread). Never frees Bionic's newtls. */
static void ctx_fls_release(void *p) {
    afw_thread_ctx *ctx = (afw_thread_ctx *)p;
    if (!ctx) return;
    thread_clear_tid_once(ctx, 1);
    t_ctx = NULL;
    free(ctx);
}

/* Step 2-4 of SYS_exit(60) after afw_os_clone_exit_on_host has switched
 * RSP back to host_rsp and restored original NT_TIB / DeallocationStack. */
static void finish_exit_on_host(void *p, int exit_code) {
    afw_thread_ctx *ctx = (afw_thread_ctx *)p;
    ctx->on_bionic_stack = 0;
    if (ctx->pending_unmap_len != 0) {
        uint64_t a = ctx->pending_unmap_addr;
        uint64_t n = ctx->pending_unmap_len;
        ctx->pending_unmap_addr = 0;
        ctx->pending_unmap_len = 0;
        (void)afw_munmap(a, n);
    }
    /* Only now — after all Bionic memory touches are done — clear tid and wake
     * pthread_join so the joining thread may safely munmap stack + newtls. */
    thread_clear_tid_once(ctx, 0);
    afw_os_exit_thread(exit_code);
}

/* Child OS thread entry point (runs initially on Windows host stack). */
static void clone_child_start(void *arg) {
    clone_handshake *hs = (clone_handshake *)arg;
    afw_thread_ctx *ctx = hs->ctx;
    uint32_t raw_tid = afw_os_current_tid();

    if (raw_tid == 0 || raw_tid > (uint32_t)INT32_MAX) {
        hs->start_err = -LNX_EAGAIN;
        hs->ctx_owned_by_fls = 0;
        afw_os_event_signal(hs->ready_ev);
        return;
    }

    if (afw_os_thread_ctx_fls_set(ctx_fls_release, ctx) != 0) {
        hs->start_err = -LNX_ENOMEM;
        hs->ctx_owned_by_fls = 0;
        afw_os_event_signal(hs->ready_ev);
        return;
    }
    hs->ctx_owned_by_fls = 1;
    t_ctx = ctx;

    if (ctx->flags & LNX_CLONE_SETTLS) {
        uintptr_t *tp = (uintptr_t *)(uintptr_t)ctx->newtls;
        /* Copy non-zero .tdata images of startup static TLS modules below tp
         * (Reviewer 3 anchor #1: Bionic tls_modules is empty so __init_static_tls
         * does not copy loader-managed static TLS modules). */
        g_tls_init_static(tp);
        if (g_tls_attach_ext(tp) != 0) {
            hs->start_err = -LNX_ENOMEM;
            afw_os_event_signal(hs->ready_ev);
            return;
        }
    }

    /* Inherit parent's per-thread signal mask (Reviewer 1 note). */
    afw_syscall_set_sigmask(ctx->init_sigmask);

    ctx->tid = (int32_t)raw_tid;
    if ((ctx->flags & LNX_CLONE_PARENT_SETTID) && ctx->ptid)
        afw_os_atomic_store_i32((void *)(uintptr_t)ctx->ptid, ctx->tid);
    if ((ctx->flags & LNX_CLONE_CHILD_SETTID) && ctx->ctid)
        afw_os_atomic_store_i32((void *)(uintptr_t)ctx->ctid, ctx->tid);
    if ((ctx->flags & LNX_CLONE_CHILD_CLEARTID) && ctx->ctid)
        afw_os_atomic_store_uptr(&ctx->clear_child_tid_addr, (uintptr_t)ctx->ctid);

    ctx->on_bionic_stack = 1;
    hs->tid = ctx->tid;
    hs->start_err = 0;
    /* Wake parent; hs lives on parent's stack and MUST NOT be touched after this. */
    afw_os_event_signal(hs->ready_ev);

    afw_os_clone_enter_bionic(&ctx->tramp);
}

int64_t afw_sys_clone(uint64_t flags, uint64_t child_stack,
                      uint64_t ptid, uint64_t ctid, uint64_t newtls,
                      const afw_clone_regs *regs) {
    uint64_t stack_base = 0, stack_limit = 0, dealloc_stack = 0;
    afw_thread_ctx *ctx;
    clone_handshake hs;
    int rc;

    if (!regs || !regs->rip) return -LNX_ENOSYS;
    /* Thread clones must have exit signal 0 and all required thread-sharing flags. */
    if ((flags & 0xffULL) != 0) return -LNX_ENOSYS;
    if ((flags & AFW_CLONE_REQUIRED) != AFW_CLONE_REQUIRED) return -LNX_ENOSYS;
    if ((flags & ~AFW_CLONE_ALLOWED) != 0) return -LNX_ENOSYS;

    if (child_stack == 0 || (child_stack & 15ULL) != 0) return -LNX_EINVAL;
    if (afw_vma_stack_bounds(child_stack, &stack_base, &stack_limit, &dealloc_stack) != 0)
        return -LNX_EINVAL;

    if (flags & LNX_CLONE_PARENT_SETTID) {
        if (ptid == 0) return -LNX_EFAULT;
        if ((ptid & 3ULL) != 0) return -LNX_EINVAL;
        if (!afw_vma_is_writable(ptid, 4)) return -LNX_EFAULT;
    }
    if (flags & (LNX_CLONE_CHILD_CLEARTID | LNX_CLONE_CHILD_SETTID)) {
        if (ctid != 0 && (ctid & 3ULL) != 0) return -LNX_EINVAL;
        if (ctid != 0 && !afw_vma_is_writable(ctid, 4)) return -LNX_EFAULT;
    }
    if (flags & LNX_CLONE_SETTLS) {
        uint64_t tp_off;
        if (newtls == 0 || (newtls & 7ULL) != 0) return -LNX_EINVAL;
        if (!g_tls_init_static || !g_tls_attach_ext || !g_tls_tp_off) return -LNX_ENOSYS;
        tp_off = g_tls_tp_off();
        if (newtls < tp_off || newtls > UINT64_MAX - AFW_BIONIC_TCB_SIZE)
            return -LNX_EFAULT;
        if (!afw_vma_is_writable(newtls - tp_off, tp_off + AFW_BIONIC_TCB_SIZE))
            return -LNX_EFAULT;
    }

    if (!afw_os_clone_supported()) return -LNX_ENOSYS;

    ctx = (afw_thread_ctx *)calloc(1, sizeof *ctx);
    if (!ctx) return -LNX_ENOMEM;

    ctx->tramp.bionic_stack_base    = stack_base;
    ctx->tramp.bionic_stack_limit   = stack_limit;
    ctx->tramp.bionic_dealloc_stack = dealloc_stack;
    ctx->tramp.child_rsp            = child_stack;
    ctx->tramp.child_rip            = regs->rip;
    ctx->tramp.rbx                  = regs->rbx;
    ctx->tramp.rbp                  = regs->rbp;
    ctx->tramp.r12                  = regs->r12;
    ctx->tramp.r13                  = regs->r13;
    ctx->tramp.r14                  = regs->r14;
    ctx->tramp.r15                  = regs->r15;
    ctx->flags                      = flags;
    ctx->ptid                       = ptid;
    ctx->ctid                       = ctid;
    ctx->newtls                     = newtls;
    ctx->init_sigmask               = afw_syscall_get_sigmask();

    memset(&hs, 0, sizeof hs);
    hs.ctx = ctx;
    rc = afw_os_event_init(&hs.ready_ev);
    if (rc != 0) {
        free(ctx);
        return -LNX_ENOMEM;
    }

    rc = afw_os_thread_spawn_detached(clone_child_start, &hs);
    if (rc != 0) {
        afw_os_event_destroy(hs.ready_ev);
        free(ctx);
        return -LNX_EAGAIN;
    }

    afw_os_event_wait(hs.ready_ev);
    afw_os_event_destroy(hs.ready_ev);
    if (hs.start_err != 0) {
        if (!hs.ctx_owned_by_fls) free(ctx);
        return hs.start_err;
    }
    return (int64_t)hs.tid;
}

int64_t afw_sys_set_tid_address(uint64_t tidptr) {
    uint32_t tid = afw_os_current_tid();
    if (t_ctx) {
        if (tidptr != 0 && (tidptr & 3ULL) != 0)
            afw_os_atomic_store_uptr(&t_ctx->clear_child_tid_addr, 0);
        else
            afw_os_atomic_store_uptr(&t_ctx->clear_child_tid_addr, (uintptr_t)tidptr);
    }
    return (int64_t)tid;
}

int afw_thread_try_defer_self_unmap(uint64_t addr, uint64_t len,
                                    uintptr_t cur_sp, int64_t *rc_out) {
    uint64_t rlen;
    if (!t_ctx || !t_ctx->on_bionic_stack) return 0;
    if (len == 0 || (addr & 4095ULL) != 0 || len > UINT64_MAX - 4095ULL) return 0;
    rlen = (len + 4095ULL) & ~4095ULL;
    if (addr > UINT64_MAX - rlen) return 0;
    if ((uint64_t)cur_sp < addr || (uint64_t)cur_sp >= addr + rlen) return 0;
    if (t_ctx->pending_unmap_len != 0) {
        *rc_out = -LNX_EINVAL;
        return 1;
    }
    t_ctx->pending_unmap_addr = addr;
    t_ctx->pending_unmap_len = rlen;
    *rc_out = 0;
    return 1;
}

int afw_thread_is_cloned(void) {
    return t_ctx != NULL && t_ctx->on_bionic_stack;
}

void afw_thread_exit(int exit_code) {
    afw_thread_ctx *ctx = t_ctx;
    if (!ctx || !ctx->on_bionic_stack) {
        afw_os_exit_thread(exit_code);
        return;
    }
    afw_os_clone_exit_on_host(&ctx->tramp, ctx, exit_code, finish_exit_on_host);
}
