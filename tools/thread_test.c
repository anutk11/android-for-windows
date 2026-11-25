/*
 * thread_test.c - Host unit tests for G2-4b VMA stack/writability queries,
 * SYS_clone(56) flag/alignment/VMA validation, SYS_rt_sigprocmask(14),
 * SYS_set_tid_address(218), and SYS_futex(FUTEX_WAIT|CLOCK_REALTIME).
 *
 * Runs under Linux ASan+UBSan+pointer-compare AND Windows CI.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../src/vma.h"
#include "../src/syscall.h"
#include "../src/thread.h"
#include "../src/platform.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define LNX_EFAULT 14
#define LNX_EINVAL 22
#define LNX_ENOSYS 38

static int g_pass, g_fail;
#define CHECK(c, ...) do { \
    if (c) { g_pass++; } \
    else { g_fail++; printf("[FAIL] %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

static void dummy_init_static(uintptr_t *tp) { (void)tp; }
static int  dummy_attach_ext(uintptr_t *tp)  { (void)tp; return 0; }
static void dummy_detach_ext(void)           {}
static uint64_t dummy_tp_off(void)           { return 16; }

int main(void) {
    int64_t r;
    uint64_t map_addr, stack_top, sb = 0, sl = 0, ds = 0;
    afw_clone_regs fake_regs;
    const uint64_t bionic_flags = LNX_CLONE_VM | LNX_CLONE_FS | LNX_CLONE_FILES |
                                  LNX_CLONE_SIGHAND | LNX_CLONE_THREAD | LNX_CLONE_SYSVSEM |
                                  LNX_CLONE_SETTLS | LNX_CLONE_PARENT_SETTID | LNX_CLONE_CHILD_CLEARTID;

    memset(&fake_regs, 0, sizeof fake_regs);
    fake_regs.rip = 0x12345678ULL;

    /* 1. Build a simulated Bionic thread mapping:
     *    [0x0000, 0x1000) PROT_NONE bottom guard
     *    [0x1000, 0x9000) PROT_READ|PROT_WRITE stack + TLS (32KB)
     *    [0x9000, 0xa000) PROT_NONE top guard */
    r = afw_mmap(0, 10 * 4096, 0, LNX_MAP_PRIVATE | LNX_MAP_ANONYMOUS, -1, 0);
    CHECK(r > 0, "mmap simulated thread mapping failed: %lld", (long long)r);
    map_addr = (uint64_t)r;
    CHECK(afw_mprotect(map_addr + 4096, 8 * 4096, LNX_PROT_READ | LNX_PROT_WRITE) == 0,
          "mprotect RW region");
    stack_top = map_addr + 7 * 4096; /* 16-byte aligned inside RW region */

    /* 2. afw_vma_stack_bounds positive + negative tests */
    CHECK(afw_vma_stack_bounds(stack_top, &sb, &sl, &ds) == 0, "stack_bounds valid sp");
    CHECK(sl == map_addr + 4096, "stack_limit=0x%llx want 0x%llx", (unsigned long long)sl, (unsigned long long)(map_addr + 4096));
    CHECK(sb == map_addr + 9 * 4096, "stack_base=0x%llx want 0x%llx", (unsigned long long)sb, (unsigned long long)(map_addr + 9 * 4096));
    CHECK(ds == map_addr, "dealloc_stack=0x%llx want 0x%llx", (unsigned long long)ds, (unsigned long long)map_addr);

    /* Exact upper boundary of RW extent: top = map_addr + 9 * 4096 (Reviewer 2) */
    CHECK(afw_vma_stack_bounds(map_addr + 9 * 4096, &sb, &sl, &ds) == -1, "sp == top must fail");
    CHECK(afw_vma_stack_bounds(map_addr + 9 * 4096 - 8, &sb, &sl, &ds) == -1, "sp == top - 8 must fail");
    sb = sl = ds = 0;
    CHECK(afw_vma_stack_bounds(map_addr + 9 * 4096 - 16, &sb, &sl, &ds) == 0, "sp == top - 16 (aligned) must succeed");
    CHECK(sl == map_addr + 4096 && sb == map_addr + 9 * 4096 && ds == map_addr, "sp == top - 16 bounds exact");

    CHECK(afw_vma_stack_bounds(map_addr + 4096, &sb, &sl, &ds) == -1, "sp at bottom guard edge must fail");
    CHECK(afw_vma_stack_bounds(map_addr + 4096 + 2048, &sb, &sl, &ds) == -1, "sp with <4KB headroom must fail");
    CHECK(afw_vma_stack_bounds(map_addr + 9 * 4096 + 16, &sb, &sl, &ds) == -1, "sp in top guard must fail");
    CHECK(afw_vma_stack_bounds(0x10000, &sb, &sl, &ds) == -1, "sp in unmapped space must fail");

    /* 3. afw_vma_is_writable tests */
    CHECK(afw_vma_is_writable(map_addr + 4096, 8 * 4096) == 1, "RW region writable");
    CHECK(afw_vma_is_writable(map_addr, 4096) == 0, "bottom guard NOT writable");
    CHECK(afw_vma_is_writable(map_addr + 9 * 4096, 4096) == 0, "top guard NOT writable");
    CHECK(afw_vma_is_writable(map_addr + 4096 - 4, 8) == 0, "crossing bottom guard NOT writable");
    CHECK(afw_vma_is_writable(map_addr + 9 * 4096 - 4, 8) == 0, "crossing top guard NOT writable");
    CHECK(afw_vma_is_writable(map_addr + 4096, 0) == 0, "zero len NOT writable");
    CHECK(afw_vma_is_writable(UINT64_MAX - 2, 16) == 0, "overflow len NOT writable");

    /* Read-only page inside mapping */
    {
        int64_t ro = afw_mmap(0, 4096, LNX_PROT_READ, LNX_MAP_PRIVATE | LNX_MAP_ANONYMOUS, -1, 0);
        CHECK(ro > 0, "mmap RO page");
        CHECK(afw_vma_is_writable((uint64_t)ro, 4) == 0, "RO page NOT writable");
        CHECK(afw_vma_stack_bounds((uint64_t)ro + 4096, &sb, &sl, &ds) == -1, "RO page not valid stack");
        CHECK(afw_munmap((uint64_t)ro, 4096) == 0, "munmap RO page");
    }

    /* 4. SYS_clone negative validation tests */
    afw_thread_set_tls_ops(dummy_init_static, dummy_attach_ext, dummy_detach_ext, dummy_tp_off);
    CHECK(afw_sys_clone(bionic_flags, stack_top, stack_top, stack_top, stack_top + 64, NULL) == -LNX_ENOSYS,
          "NULL regs -> -ENOSYS");
    /* fork-like flags (missing CLONE_VM | CLONE_THREAD) -> -ENOSYS */
    CHECK(afw_sys_clone(0, stack_top, 0, 0, 0, &fake_regs) == -LNX_ENOSYS, "fork(0) -> -ENOSYS");
    CHECK(afw_sys_clone(bionic_flags | 17 /* SIGCHLD */, stack_top, stack_top, stack_top, stack_top + 64, &fake_regs) == -LNX_ENOSYS,
          "non-zero exit signal -> -ENOSYS");
    CHECK(afw_sys_clone(bionic_flags | 0x00020000ULL /* CLONE_NEWNS */, stack_top, stack_top, stack_top, stack_top + 64, &fake_regs) == -LNX_ENOSYS,
          "unknown/disallowed flag -> -ENOSYS");
    /* Bad child_stack */
    CHECK(afw_sys_clone(bionic_flags, 0, stack_top, stack_top, stack_top + 64, &fake_regs) == -LNX_EINVAL,
          "NULL child_stack -> -EINVAL");
    CHECK(afw_sys_clone(bionic_flags, stack_top + 8, stack_top, stack_top, stack_top + 64, &fake_regs) == -LNX_EINVAL,
          "misaligned child_stack -> -EINVAL");
    CHECK(afw_sys_clone(bionic_flags, map_addr + 16, stack_top, stack_top, stack_top + 64, &fake_regs) == -LNX_EINVAL,
          "guard-page child_stack -> -EINVAL");
    CHECK(afw_sys_clone(bionic_flags, map_addr + 9 * 4096, stack_top, stack_top, stack_top + 64, &fake_regs) == -LNX_EINVAL,
          "child_stack == top (at top guard edge) -> -EINVAL");
    /* Bad ptid / ctid */
    CHECK(afw_sys_clone(bionic_flags, stack_top, 0, stack_top, stack_top + 64, &fake_regs) == -LNX_EFAULT,
          "NULL ptid with PARENT_SETTID -> -EFAULT");
    CHECK(afw_sys_clone(bionic_flags, stack_top, stack_top + 2, stack_top, stack_top + 64, &fake_regs) == -LNX_EINVAL,
          "misaligned ptid -> -EINVAL");
    CHECK(afw_sys_clone(bionic_flags, stack_top, map_addr, stack_top, stack_top + 64, &fake_regs) == -LNX_EFAULT,
          "guard-page ptid -> -EFAULT");
    CHECK(afw_sys_clone(bionic_flags | LNX_CLONE_CHILD_SETTID, stack_top, stack_top, 0, stack_top + 64, &fake_regs) == -LNX_EFAULT,
          "NULL ctid with CHILD_SETTID -> -EFAULT");
    CHECK(afw_sys_clone(bionic_flags, stack_top, stack_top, stack_top + 2, stack_top + 64, &fake_regs) == -LNX_EINVAL,
          "misaligned ctid -> -EINVAL");
    CHECK(afw_sys_clone(bionic_flags, stack_top, stack_top, map_addr, stack_top + 64, &fake_regs) == -LNX_EFAULT,
          "guard-page ctid -> -EFAULT");
    /* Bad newtls */
    CHECK(afw_sys_clone(bionic_flags, stack_top, stack_top, stack_top, 0, &fake_regs) == -LNX_EINVAL,
          "NULL newtls -> -EINVAL");
    CHECK(afw_sys_clone(bionic_flags, stack_top, stack_top, stack_top, stack_top + 4, &fake_regs) == -LNX_EINVAL,
          "misaligned newtls -> -EINVAL");
    CHECK(afw_sys_clone(bionic_flags, stack_top, stack_top, stack_top, map_addr + 4096, &fake_regs) == -LNX_EFAULT,
          "newtls - tp_off crossing into bottom guard -> -EFAULT");
    CHECK(afw_sys_clone(bionic_flags, stack_top, stack_top, stack_top, map_addr + 9 * 4096 - 16, &fake_regs) == -LNX_EFAULT,
          "newtls + TCB(0x50) crossing into top guard -> -EFAULT");

    /* 5. SYS_rt_sigprocmask(14) tests */
    {
        uint64_t set = 0, old = 0xdeadbeefULL;
        int64_t a[6] = {0};
        /* Invalid sigsetsize -> -EINVAL, old unchanged */
        a[0] = 2; a[1] = (int64_t)(uintptr_t)&set; a[2] = (int64_t)(uintptr_t)&old; a[3] = 4;
        CHECK(afw_syscall_dispatch(14, a) == -LNX_EINVAL && old == 0xdeadbeefULL, "sigprocmask bad size");
        /* Invalid how -> -EINVAL, old unchanged */
        a[0] = 99; a[3] = 8;
        CHECK(afw_syscall_dispatch(14, a) == -LNX_EINVAL && old == 0xdeadbeefULL, "sigprocmask bad how");
        /* SIG_SETMASK with SIGUSR1(10) + SIGKILL(9) + SIGSTOP(19) -> SIGKILL/SIGSTOP stripped */
        set = (1ULL << 9) | (1ULL << 8) | (1ULL << 18);
        a[0] = 2; a[1] = (int64_t)(uintptr_t)&set; a[2] = (int64_t)(uintptr_t)&old; a[3] = 8;
        CHECK(afw_syscall_dispatch(14, a) == 0 && old == 0, "sigprocmask setmask");
        CHECK(afw_syscall_get_sigmask() == (1ULL << 9), "SIGKILL/SIGSTOP must be masked out");
        /* Aliasing set == oldset */
        set = (1ULL << 11); /* SIGUSR2(12) */
        a[0] = 0; a[1] = (int64_t)(uintptr_t)&set; a[2] = (int64_t)(uintptr_t)&set; a[3] = 8;
        CHECK(afw_syscall_dispatch(14, a) == 0 && set == (1ULL << 9), "sigprocmask aliasing set==oldset");
        CHECK(afw_syscall_get_sigmask() == ((1ULL << 9) | (1ULL << 11)), "SIG_BLOCK combined");
        /* SIG_UNBLOCK */
        set = (1ULL << 9);
        a[0] = 1; a[1] = (int64_t)(uintptr_t)&set; a[2] = (int64_t)(uintptr_t)&old; a[3] = 8;
        CHECK(afw_syscall_dispatch(14, a) == 0 && old == ((1ULL << 9) | (1ULL << 11)), "SIG_UNBLOCK old");
        CHECK(afw_syscall_get_sigmask() == (1ULL << 11), "SIG_UNBLOCK result");
        /* Reset to 0 */
        set = 0; a[0] = 2; a[2] = 0;
        CHECK(afw_syscall_dispatch(14, a) == 0 && afw_syscall_get_sigmask() == 0, "sigprocmask reset");
    }

    /* 6. SYS_futex(FUTEX_WAIT | FUTEX_CLOCK_REALTIME) -> -ENOSYS (G2-PLAN 3.5) */
    {
        int32_t word = 7;
        int64_t a[6] = { (int64_t)(uintptr_t)&word, 0 /* FUTEX_WAIT */ | 256 /* FUTEX_CLOCK_REALTIME */, 7, 0, 0, 0 };
        CHECK(afw_syscall_dispatch(202, a) == -LNX_ENOSYS, "FUTEX_WAIT|CLOCK_REALTIME -> -ENOSYS");
    }

    /* 7. SYS_set_tid_address(218) returns positive tid */
    {
        int32_t tid_word = 0;
        int64_t a[6] = { (int64_t)(uintptr_t)&tid_word, 0, 0, 0, 0, 0 };
        int64_t tid = afw_syscall_dispatch(218, a);
        CHECK(tid > 0 && tid == (int64_t)afw_os_current_tid(), "set_tid_address returned %lld", (long long)tid);
    }

    /* 8. G3 ART syscalls: uname, prctl, prlimit64, sysinfo, statfs, sigaction, sigaltstack, FUTEX_CMP_REQUEUE, sigtimedwait+tgkill */
    {
        char uts[390];
        char comm[16];
        uint64_t rl[2] = {0, 0};
        unsigned char si[112], sf[120], sa[32], old_sa[32], ss[24], old_ss[24];
        int32_t futex_w = 42, futex_w2 = 0;
        uint64_t mask = (1ULL << 9); /* SIGUSR1 = 10 */
        unsigned char siginfo[128];
        int64_t a[6] = {0};

        memset(uts, 0, sizeof uts);
        a[0] = (int64_t)(uintptr_t)uts;
        CHECK(afw_syscall_dispatch(63, a) == 0 && strcmp(uts, "Linux") == 0 &&
              strcmp(uts + 260, "x86_64") == 0, "uname returns Linux x86_64");

        a[0] = 15; a[1] = (int64_t)(uintptr_t)"g3-worker";
        CHECK(afw_syscall_dispatch(157, a) == 0, "prctl(PR_SET_NAME) succeeds");
        memset(comm, 0, sizeof comm);
        a[0] = 16; a[1] = (int64_t)(uintptr_t)comm;
        CHECK(afw_syscall_dispatch(157, a) == 0 && strcmp(comm, "g3-worker") == 0,
              "prctl(PR_GET_NAME) round-trips");

        memset(a, 0, sizeof a);
        a[1] = 3; /* RLIMIT_STACK */ a[3] = (int64_t)(uintptr_t)rl;
        CHECK(afw_syscall_dispatch(302, a) == 0 && rl[0] == 8ULL * 1024ULL * 1024ULL,
              "prlimit64(RLIMIT_STACK) returns 8MB");

        memset(si, 0, sizeof si);
        a[0] = (int64_t)(uintptr_t)si;
        CHECK(afw_syscall_dispatch(99, a) == 0, "sysinfo(99) succeeds");

        memset(sf, 0, sizeof sf);
        a[0] = (int64_t)(uintptr_t)"/"; a[1] = (int64_t)(uintptr_t)sf;
        CHECK(afw_syscall_dispatch(137, a) == 0, "statfs(137) succeeds");

        memset(sa, 0, sizeof sa); memset(old_sa, 0, sizeof old_sa);
        sa[0] = 0x55;
        a[0] = 10; a[1] = (int64_t)(uintptr_t)sa; a[2] = (int64_t)(uintptr_t)old_sa; a[3] = 8;
        CHECK(afw_syscall_dispatch(13, a) == 0, "rt_sigaction(SIGUSR1) sets handler");
        a[1] = 0; a[2] = (int64_t)(uintptr_t)old_sa;
        CHECK(afw_syscall_dispatch(13, a) == 0 && old_sa[0] == 0x55, "rt_sigaction returns stored handler");

        memset(ss, 0, sizeof ss); memset(old_ss, 0, sizeof old_ss);
        {
            uint64_t spv = 0x12340000ULL, szv = 16384ULL;
            memcpy(ss, &spv, 8); memcpy(ss + 16, &szv, 8);
        }
        a[0] = (int64_t)(uintptr_t)ss; a[1] = (int64_t)(uintptr_t)old_ss;
        CHECK(afw_syscall_dispatch(131, a) == 0, "sigaltstack set succeeds");
        a[0] = 0; a[1] = (int64_t)(uintptr_t)old_ss;
        CHECK(afw_syscall_dispatch(131, a) == 0 && memcmp(old_ss, ss, 8) == 0, "sigaltstack query round-trips");

        /* FUTEX_CMP_REQUEUE (4 | PRIVATE): mismatch -> -EAGAIN, match -> >= 0 */
        a[0] = (int64_t)(uintptr_t)&futex_w; a[1] = 4 | 128; a[2] = 1; a[3] = 1;
        a[4] = (int64_t)(uintptr_t)&futex_w2; a[5] = 99;
        CHECK(afw_syscall_dispatch(202, a) == -11 /* -EAGAIN */, "FUTEX_CMP_REQUEUE mismatch -> -EAGAIN");
        a[5] = 42;
        CHECK(afw_syscall_dispatch(202, a) >= 0, "FUTEX_CMP_REQUEUE match succeeds");

        /* tgkill(SIGUSR1) + rt_sigtimedwait(SIGUSR1) round-trip */
        a[0] = 0; a[1] = (int64_t)afw_os_current_tid(); a[2] = 10;
        CHECK(afw_syscall_dispatch(234, a) == 0, "tgkill(SIGUSR1) queues signal");
        memset(siginfo, 0, sizeof siginfo);
        a[0] = (int64_t)(uintptr_t)&mask; a[1] = (int64_t)(uintptr_t)siginfo; a[2] = 0; a[3] = 8;
        CHECK(afw_syscall_dispatch(128, a) == 10 && *(int32_t *)siginfo == 10,
              "rt_sigtimedwait consumes queued SIGUSR1");
    }

    CHECK(afw_munmap(map_addr, 10 * 4096) == 0, "cleanup thread mapping");
    CHECK(afw_vma_alloc_count() == 0, "zero VMA leaks (got %d)", afw_vma_alloc_count());

    printf("thread_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail != 0;
}
