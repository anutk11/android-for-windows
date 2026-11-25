/*
 * syscall.c - Entry trampoline and first Linux syscalls.
 *
 * Unimplemented calls return -ENOSYS and are counted, so a run tells us
 * exactly which syscalls a program really needs.
 */
#include "syscall.h"
#include "fd.h"
#include "platform.h"
#include "thread.h"
#include "vma.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#endif

#define LNX_ENOENT 2
#define LNX_ESRCH 3
#define LNX_EBADF 9
#define LNX_EAGAIN 11
#define LNX_EFAULT 14
#define LNX_EINVAL 22
#define LNX_ERANGE 34
#define LNX_ENOSYS 38
#define LNX_ETIMEDOUT 110

#if defined(_WIN32)
#pragma comment(lib, "synchronization.lib")   /* WaitOnAddress / WakeByAddress* */
#endif

long afw_syscall_counts[AFW_MAX_SYSCALL];
static long g_unimplemented[AFW_MAX_SYSCALL];

_Static_assert(offsetof(afw_syscall_frame, rbx)        == 0,   "frame.rbx");
_Static_assert(offsetof(afw_syscall_frame, r12)        == 8,   "frame.r12");
_Static_assert(offsetof(afw_syscall_frame, r13)        == 16,  "frame.r13");
_Static_assert(offsetof(afw_syscall_frame, r14)        == 24,  "frame.r14");
_Static_assert(offsetof(afw_syscall_frame, r15)        == 32,  "frame.r15");
_Static_assert(offsetof(afw_syscall_frame, args)       == 40,  "frame.args");
_Static_assert(offsetof(afw_syscall_frame, caller_rbp) == 88,  "frame.caller_rbp");
_Static_assert(offsetof(afw_syscall_frame, rflags)     == 96,  "frame.rflags");
_Static_assert(offsetof(afw_syscall_frame, rip)        == 104, "frame.rip");

/*
 * Stack frame built by the entry (offsets from rbp):
 *   rbp+16   return address into the patched wrapper (frame.rip)
 *   rbp+8    the caller's RFLAGS (restored on return, like sysret)
 *   rbp+0    the caller's RBP (frame.caller_rbp)
 *   rbp-48   args[6] = rdi, rsi, rdx, r10, r8, r9
 *   rbp-88   callee-saved = rbx, r12, r13, r14, r15 (for SYS_clone)
 *   rbp-344  xmm0..xmm15 (16 x 16 bytes)
 * then rsp is aligned to 16 and 32 bytes of shadow space are reserved
 * (required by the Windows ABI, harmless elsewhere).
 */
/* Only the low 32 bits of rax are the syscall number: Linux treats it as an
 * int since 5.13 ("x86/entry: Use int everywhere for system call numbers"),
 * so 0x100000001 is write(), as here (checked for reviewer 4, #8). */
#if defined(_WIN32)
#  define DISPATCH_ARGS "mov %eax, %ecx\n\t lea -88(%rbp), %rdx\n\t"
#else
#  define DISPATCH_ARGS "mov %eax, %edi\n\t lea -88(%rbp), %rsi\n\t"
#endif

__attribute__((naked)) void afw_syscall_entry(void) {
    __asm__ volatile(
        "pushfq\n\t"                 /* Linux returns from syscall with the caller's RFLAGS (reviewer 4) */
        "push %rbp\n\t"
        "mov %rsp, %rbp\n\t"
        "sub $352, %rsp\n\t"
        "mov %rdi, -48(%rbp)\n\t"
        "mov %rsi, -40(%rbp)\n\t"
        "mov %rdx, -32(%rbp)\n\t"
        "mov %r10, -24(%rbp)\n\t"
        "mov %r8,  -16(%rbp)\n\t"
        "mov %r9,   -8(%rbp)\n\t"
        "mov %rbx, -88(%rbp)\n\t"
        "mov %r12, -80(%rbp)\n\t"
        "mov %r13, -72(%rbp)\n\t"
        "mov %r14, -64(%rbp)\n\t"
        "mov %r15, -56(%rbp)\n\t"
        "movdqu %xmm0,  -344(%rbp)\n\t"
        "movdqu %xmm1,  -328(%rbp)\n\t"
        "movdqu %xmm2,  -312(%rbp)\n\t"
        "movdqu %xmm3,  -296(%rbp)\n\t"
        "movdqu %xmm4,  -280(%rbp)\n\t"
        "movdqu %xmm5,  -264(%rbp)\n\t"
        "movdqu %xmm6,  -248(%rbp)\n\t"
        "movdqu %xmm7,  -232(%rbp)\n\t"
        "movdqu %xmm8,  -216(%rbp)\n\t"
        "movdqu %xmm9,  -200(%rbp)\n\t"
        "movdqu %xmm10, -184(%rbp)\n\t"
        "movdqu %xmm11, -168(%rbp)\n\t"
        "movdqu %xmm12, -152(%rbp)\n\t"
        "movdqu %xmm13, -136(%rbp)\n\t"
        "movdqu %xmm14, -120(%rbp)\n\t"
        "movdqu %xmm15, -104(%rbp)\n\t"
        "and $-16, %rsp\n\t"
        "sub $32, %rsp\n\t"
        DISPATCH_ARGS
        "call afw_syscall_from_entry\n\t"
        "movdqu -344(%rbp), %xmm0\n\t"
        "movdqu -328(%rbp), %xmm1\n\t"
        "movdqu -312(%rbp), %xmm2\n\t"
        "movdqu -296(%rbp), %xmm3\n\t"
        "movdqu -280(%rbp), %xmm4\n\t"
        "movdqu -264(%rbp), %xmm5\n\t"
        "movdqu -248(%rbp), %xmm6\n\t"
        "movdqu -232(%rbp), %xmm7\n\t"
        "movdqu -216(%rbp), %xmm8\n\t"
        "movdqu -200(%rbp), %xmm9\n\t"
        "movdqu -184(%rbp), %xmm10\n\t"
        "movdqu -168(%rbp), %xmm11\n\t"
        "movdqu -152(%rbp), %xmm12\n\t"
        "movdqu -136(%rbp), %xmm13\n\t"
        "movdqu -120(%rbp), %xmm14\n\t"
        "movdqu -104(%rbp), %xmm15\n\t"
        "mov -48(%rbp), %rdi\n\t"
        "mov -40(%rbp), %rsi\n\t"
        "mov -32(%rbp), %rdx\n\t"
        "mov -24(%rbp), %r10\n\t"
        "mov -16(%rbp), %r8\n\t"
        "mov  -8(%rbp), %r9\n\t"
        "mov %rbp, %rsp\n\t"
        "pop %rbp\n\t"
        "popfq\n\t"
        "ret\n\t");
}

/* ---- individual syscalls (file I/O is in fd.c) ---- */

static int64_t sys_gettid(void) {   /* the same id the thread area holds (tls_patch.c) */
#if defined(_WIN32)
    return (int64_t)GetCurrentThreadId();
#else
    return (int64_t)syscall(SYS_gettid);
#endif
}

/* ---- time --------------------------------------------------------------- */
struct lnx_timespec { int64_t tv_sec, tv_nsec; };
#define LNX_CLOCK_REALTIME 0
#define LNX_CLOCK_MONOTONIC 1
#define LNX_CLOCK_PROCESS_CPUTIME_ID 2
#define LNX_CLOCK_THREAD_CPUTIME_ID 3
#define LNX_CLOCK_MONOTONIC_RAW 4
#define LNX_CLOCK_REALTIME_COARSE 5
#define LNX_CLOCK_MONOTONIC_COARSE 6
#define LNX_CLOCK_BOOTTIME 7

/* Nanoseconds on one clock; -1 for a clock we do not have. */
static int64_t clock_ns(int64_t clk) {
#if defined(_WIN32)
    switch (clk) {
    case LNX_CLOCK_REALTIME: case LNX_CLOCK_REALTIME_COARSE: {
        FILETIME ft;   /* 100ns since 1601 */
        uint64_t t;
        GetSystemTimePreciseAsFileTime(&ft);
        t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        return (int64_t)(t - 116444736000000000ULL) * 100;
    }
    case LNX_CLOCK_MONOTONIC: case LNX_CLOCK_MONOTONIC_RAW:
    case LNX_CLOCK_MONOTONIC_COARSE: case LNX_CLOCK_BOOTTIME: {
        static LARGE_INTEGER f;
        LARGE_INTEGER c;
        if (!f.QuadPart) QueryPerformanceFrequency(&f);
        QueryPerformanceCounter(&c);
        return (int64_t)(c.QuadPart / f.QuadPart) * 1000000000LL +
               (int64_t)(c.QuadPart % f.QuadPart) * 1000000000LL / f.QuadPart;
    }
    case LNX_CLOCK_PROCESS_CPUTIME_ID: case LNX_CLOCK_THREAD_CPUTIME_ID: {
        FILETIME c, e, k, u;
        BOOL ok = clk == LNX_CLOCK_PROCESS_CPUTIME_ID ? GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)
                                                      : GetThreadTimes(GetCurrentThread(), &c, &e, &k, &u);
        if (!ok) return -1;
        return (int64_t)((((uint64_t)k.dwHighDateTime << 32) | k.dwLowDateTime) +
                         (((uint64_t)u.dwHighDateTime << 32) | u.dwLowDateTime)) * 100;
    }
    default: return -1;
    }
#else
    struct timespec ts;
    if (clock_gettime((clockid_t)clk, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
#endif
}

static int64_t sys_clock_gettime(int64_t clk, struct lnx_timespec *tp) {
    int64_t ns = clock_ns(clk);
    if (ns < 0) return -LNX_EINVAL;
    if (!tp) return -LNX_EFAULT;
    tp->tv_sec = ns / 1000000000LL;
    tp->tv_nsec = ns % 1000000000LL;
    return 0;
}

/* ---- futex (one process: WaitOnAddress / WakeByAddress*) ---------------- */
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_BITSET_MATCH_ANY 0xffffffffu

#if defined(_WIN32)
/* The deadline in ns on clock clk: a relative timeout becomes absolute on
 * MONOTONIC now. 0 = none (wait forever); -1 = a malformed timespec. */
static int64_t deadline_ns(const struct lnx_timespec *t, int absolute, int64_t *clk) {
    int64_t ns;
    if (!t) return 0;
    if (t->tv_sec < 0 || t->tv_nsec < 0 || t->tv_nsec >= 1000000000LL) return -1;
    if (t->tv_sec > (INT64_MAX / 2) / 1000000000LL) return 0;          /* centuries: forever */
    ns = t->tv_sec * 1000000000LL + t->tv_nsec;
    if (!absolute) { *clk = LNX_CLOCK_MONOTONIC; ns += clock_ns(LNX_CLOCK_MONOTONIC); }
    return ns > 0 ? ns : 1;
}
#endif

static int64_t sys_futex(int64_t uaddr, int64_t op_full, int64_t val, int64_t ts, int64_t uaddr2, int64_t val3) {
    int op = (int)(op_full & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME));
    volatile int32_t *p = (volatile int32_t *)(uintptr_t)uaddr;
    (void)uaddr2;
    if (!p || (uaddr & 3)) return -LNX_EINVAL;
    if ((op == FUTEX_WAIT_BITSET || op == FUTEX_WAKE_BITSET) && (uint32_t)val3 != FUTEX_BITSET_MATCH_ANY) {
        if ((uint32_t)val3 == 0) return -LNX_EINVAL;
        return -LNX_ENOSYS;      /* partial bitsets: not used by bionic; refused loudly */
    }
    /* Match Linux kernel: FUTEX_CLOCK_REALTIME is allowed on FUTEX_WAIT_BITSET,
     * never on plain FUTEX_WAIT (G2-PLAN.md Section 3.5). */
    if (op == FUTEX_WAIT && (op_full & FUTEX_CLOCK_REALTIME)) return -LNX_ENOSYS;
#if defined(_WIN32)
    if (op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET) {
        int32_t expect = (int32_t)val;
        int64_t clk = (op_full & FUTEX_CLOCK_REALTIME) ? LNX_CLOCK_REALTIME : LNX_CLOCK_MONOTONIC;
        int64_t dl = deadline_ns((const struct lnx_timespec *)(uintptr_t)ts, op == FUTEX_WAIT_BITSET, &clk);
        if (dl < 0) return -LNX_EINVAL;
        if (*p != expect) return -LNX_EAGAIN;           /* the value already changed */
        for (;;) {
            DWORD ms = INFINITE;
            if (dl) {
                int64_t left = dl - clock_ns(clk);
                if (left <= 0) return -LNX_ETIMEDOUT;
                left = (left + 999999) / 1000000;       /* round up */
                ms = left >= (int64_t)INFINITE ? INFINITE - 1 : (DWORD)left;
            }
            if (WaitOnAddress((volatile VOID *)p, &expect, sizeof expect, ms)) return 0;
            /* a return of 0 may be spurious: futex callers re-check, as on Linux */
            if (GetLastError() != ERROR_TIMEOUT) return -LNX_EINVAL;
            /* Windows timers may fire up to a tick early: never report a
             * timeout before the deadline (measured: a test failed on CI) */
        }
    }
    if (op == FUTEX_WAKE || op == FUTEX_WAKE_BITSET) {
        /* WakeByAddress* does not say how many woke; bionic ignores the count.
         * Report 0, never more than were asked. */
        if (val <= 0) return 0;
        if (val == 1) WakeByAddressSingle((PVOID)p);
        else WakeByAddressAll((PVOID)p);
        return 0;
    }
    return -LNX_ENOSYS;
#else
    if (op != FUTEX_WAIT && op != FUTEX_WAKE && op != FUTEX_WAIT_BITSET && op != FUTEX_WAKE_BITSET)
        return -LNX_ENOSYS;
    {   /* host build: the real futex, same semantics */
        long r = syscall(SYS_futex, p, (int)op_full, (int)val, (void *)(uintptr_t)ts, (void *)(uintptr_t)uaddr2, (int)val3);
        return r < 0 ? -(int64_t)errno : r;
    }
#endif
}

static int64_t sys_getrandom(void *buf, uint64_t len, int64_t flags) {
    (void)flags;   /* GRND_NONBLOCK / GRND_RANDOM: the OS generator never blocks */
    if (!buf) return -LNX_EFAULT;
    if (len > 33554431) len = 33554431;      /* Linux caps one call at 32MB-1 */
    return afw_random_bytes(buf, (size_t)len) == 0 ? (int64_t)len : -LNX_EAGAIN;
}

static int64_t sys_getpid(void) {
#if defined(_WIN32)
    return (int64_t)GetCurrentProcessId();
#else
    return (int64_t)getpid();
#endif
}

/* Per-thread signal mask bookkeeping for SYS_rt_sigprocmask(14).
 * Bionic's __init_static_tls and pthread_create block/restore signals via
 * rt_sigprocmask(SIG_SETMASK, ..., sigsetsize=8) around thread setup. */
static _Thread_local uint64_t t_sigmask;

uint64_t afw_syscall_get_sigmask(void) { return t_sigmask; }
void afw_syscall_set_sigmask(uint64_t mask) {
    const uint64_t unmaskable = (1ULL << (9 - 1)) | (1ULL << (19 - 1));
    t_sigmask = mask & ~unmaskable;
}

static int64_t sys_rt_sigprocmask(int how, const void *set, void *oldset, uint64_t sigsetsize) {
    uint64_t prev = t_sigmask;
    if (sigsetsize != 8) return -LNX_EINVAL;
    if (set) {
        uint64_t mask = 0;
        const uint64_t unmaskable = (1ULL << (9 - 1)) | (1ULL << (19 - 1)); /* SIGKILL, SIGSTOP */
        memcpy(&mask, set, 8);
        mask &= ~unmaskable;
        switch (how) {
        case 0: /* SIG_BLOCK */   t_sigmask |= mask; break;
        case 1: /* SIG_UNBLOCK */ t_sigmask &= ~mask; break;
        case 2: /* SIG_SETMASK */ t_sigmask = mask; break;
        default: return -LNX_EINVAL;
        }
    }
    if (oldset) memcpy(oldset, &prev, 8);
    return 0;
}

/* ---- signals: rt_sigaction(13) & sigaltstack(131) ----------------------- */
struct lnx_kernel_sigaction {
    uint64_t sa_handler;
    uint64_t sa_flags;
    uint64_t sa_restorer;
    uint64_t sa_mask;
};
_Static_assert(sizeof(struct lnx_kernel_sigaction) == 32, "kernel_sigaction must be 32 bytes");

struct lnx_stack_t {
    uint64_t ss_sp;
    int32_t  ss_flags;
    int32_t  __pad;
    uint64_t ss_size;
};
_Static_assert(sizeof(struct lnx_stack_t) == 24, "stack_t must be 24 bytes");

static struct lnx_kernel_sigaction g_sigactions[65];
static int32_t g_sigaction_spin;
static _Thread_local struct lnx_stack_t t_altstack = { 0, 2 /* SS_DISABLE */, 0, 0 };
static _Thread_local char t_thread_comm[16] = "android-app";

static void sigaction_lock(void) {
    while (afw_os_atomic_cmpxchg_i32(&g_sigaction_spin, 0, 1) != 0) {}
}
static void sigaction_unlock(void) {
    afw_os_atomic_store_i32(&g_sigaction_spin, 0);
}

static int64_t sys_rt_sigaction(int64_t signum, const void *act, void *oldact, uint64_t sigsetsize) {
    if (sigsetsize != 8 || signum < 1 || signum > 64) return -LNX_EINVAL;
    if (act && (signum == 9 || signum == 19)) return -LNX_EINVAL;
    sigaction_lock();
    if (oldact) memcpy(oldact, &g_sigactions[signum], sizeof g_sigactions[signum]);
    if (act)    memcpy(&g_sigactions[signum], act, sizeof g_sigactions[signum]);
    sigaction_unlock();
    return 0;
}

static int64_t sys_sigaltstack(const void *ss, void *old_ss) {
    if (old_ss) memcpy(old_ss, &t_altstack, sizeof t_altstack);
    if (ss) {
        struct lnx_stack_t ns;
        memcpy(&ns, ss, sizeof ns);
        if (ns.ss_flags & 2 /* SS_DISABLE */) {
            t_altstack.ss_sp = 0;
            t_altstack.ss_flags = 2;
            t_altstack.ss_size = 0;
        } else {
            if (ns.ss_size < 2048) return -12; /* ENOMEM */
            t_altstack.ss_sp = ns.ss_sp;
            t_altstack.ss_flags = ns.ss_flags & ~1;
            t_altstack.ss_size = ns.ss_size;
        }
    }
    return 0;
}

/* ---- uname(63) ---------------------------------------------------------- */
struct lnx_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};
_Static_assert(sizeof(struct lnx_utsname) == 390, "struct new_utsname must be 390 bytes");

static int64_t sys_uname(void *buf) {
    struct lnx_utsname u;
    if (!buf) return -LNX_EFAULT;
    memset(&u, 0, sizeof u);
    strcpy(u.sysname,    "Linux");
    strcpy(u.nodename,   "android-win");
    strcpy(u.release,    "6.1.0-android14-afw");
    strcpy(u.version,    "#1 SMP PREEMPT");
    strcpy(u.machine,    "x86_64");
    strcpy(u.domainname, "(none)");
    memcpy(buf, &u, sizeof u);
    return 0;
}

/* ---- prctl(157) --------------------------------------------------------- */
static int64_t sys_prctl(int64_t opt, int64_t a2, int64_t a3, int64_t a4, int64_t a5) {
    (void)a3; (void)a4; (void)a5;
    switch (opt) {
    case 0x53564d41: /* PR_SET_VMA */
        return 0;
    case 15: /* PR_SET_NAME */ {
        const char *name = (const char *)(uintptr_t)a2;
        if (!name) return -LNX_EFAULT;
        strncpy(t_thread_comm, name, sizeof(t_thread_comm) - 1);
        t_thread_comm[sizeof(t_thread_comm) - 1] = '\0';
        return 0;
    }
    case 16: /* PR_GET_NAME */ {
        char *out = (char *)(uintptr_t)a2;
        if (!out) return -LNX_EFAULT;
        memcpy(out, t_thread_comm, sizeof t_thread_comm);
        return 0;
    }
    case 3:  /* PR_GET_DUMPABLE */ return 1;
    case 4:  /* PR_SET_DUMPABLE */ return 0;
    case 38: /* PR_SET_NO_NEW_PRIVS */ return 0;
    case 39: /* PR_GET_NO_NEW_PRIVS */ return 0;
    case 56: /* PR_GET_TAGGED_ADDR_CTRL */ return 0;
    default:
        return -LNX_EINVAL;
    }
}

/* ---- rlimit(97/160/302) ------------------------------------------------- */
struct lnx_rlimit64 {
    uint64_t rlim_cur;
    uint64_t rlim_max;
};

static int64_t sys_prlimit64(int64_t pid, int64_t res, const void *new_lim, void *old_lim) {
    (void)new_lim;
    if (pid != 0 && pid != sys_getpid()) return -LNX_ESRCH;
    if (res < 0 || res >= 16) return -LNX_EINVAL;
    if (old_lim) {
        struct lnx_rlimit64 rl;
        switch (res) {
        case 3: /* RLIMIT_STACK */
            rl.rlim_cur = 8ULL * 1024ULL * 1024ULL;
            rl.rlim_max = ~0ULL;
            break;
        case 4: /* RLIMIT_CORE */
            rl.rlim_cur = 0;
            rl.rlim_max = 0;
            break;
        case 7: /* RLIMIT_NOFILE */
            rl.rlim_cur = AFW_MAX_FDS;
            rl.rlim_max = 4096;
            break;
        default:
            rl.rlim_cur = ~0ULL;
            rl.rlim_max = ~0ULL;
            break;
        }
        memcpy(old_lim, &rl, sizeof rl);
    }
    return 0;
}

/* ---- sched & cpu: sched_getaffinity(204), sched_yield(24), getcpu(309) -- */
static int64_t sys_sched_getaffinity(int64_t pid, uint64_t cpusetsize, void *mask) {
    uint64_t bits = 0;
    unsigned ncpu = 1;
    (void)pid;
    if (!mask) return -LNX_EFAULT;
    if (cpusetsize < 8) return -LNX_EINVAL;
#if defined(_WIN32)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        if (si.dwNumberOfProcessors > 0) ncpu = (unsigned)si.dwNumberOfProcessors;
    }
#else
    {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        if (n > 0) ncpu = (unsigned)n;
    }
#endif
    if (ncpu > 64) ncpu = 64;
    bits = (ncpu == 64) ? ~0ULL : ((1ULL << ncpu) - 1ULL);
    memset(mask, 0, cpusetsize > 128 ? 128 : (size_t)cpusetsize);
    memcpy(mask, &bits, sizeof bits);
    return 8;
}

static int64_t sys_sched_yield(void) {
#if defined(_WIN32)
    SwitchToThread();
#else
    sched_yield();
#endif
    return 0;
}

static int64_t sys_getcpu(uint32_t *cpu, uint32_t *node) {
    if (cpu)  *cpu  = 0;
    if (node) *node = 0;
    return 0;
}

/* ---- getcwd(79) & readlinkat(89/267) ------------------------------------ */
static int64_t sys_getcwd(char *buf, uint64_t size) {
    char tmp[4096];
    size_t len;
    if (!buf) return -LNX_EFAULT;
    if (size == 0) return -LNX_EINVAL;
#if defined(_WIN32)
    {
        DWORD n = GetCurrentDirectoryA((DWORD)sizeof(tmp), tmp);
        DWORD i;
        if (n == 0 || n >= sizeof(tmp)) return -LNX_ERANGE;
        for (i = 0; i < n; i++) if (tmp[i] == '\\') tmp[i] = '/';
        len = (size_t)n;
    }
#else
    if (!getcwd(tmp, sizeof tmp)) return -(int64_t)errno;
    len = strlen(tmp);
#endif
    if (len + 1 > size) return -LNX_ERANGE;
    memcpy(buf, tmp, len + 1);
    return (int64_t)(len + 1);
}

static int64_t sys_readlinkat(int64_t dirfd, const char *path, char *buf, int64_t bufsiz) {
    (void)dirfd;
    if (!path || !buf) return -LNX_EFAULT;
    if (bufsiz <= 0) return -LNX_EINVAL;
    if (strcmp(path, "/proc/self/exe") == 0) {
        char tmp[4096];
        size_t len, n;
#if defined(_WIN32)
        DWORD r = GetModuleFileNameA(NULL, tmp, (DWORD)sizeof(tmp));
        DWORD i;
        if (r == 0 || r >= sizeof(tmp)) return -LNX_EINVAL;
        for (i = 0; i < r; i++) if (tmp[i] == '\\') tmp[i] = '/';
        len = (size_t)r;
#else
        ssize_t r = readlink("/proc/self/exe", tmp, sizeof(tmp));
        if (r < 0) return -(int64_t)errno;
        len = (size_t)r;
#endif
        n = len < (size_t)bufsiz ? len : (size_t)bufsiz;
        memcpy(buf, tmp, n);
        return (int64_t)n;
    }
#if !defined(_WIN32)
    {
        ssize_t r = readlink(path, buf, (size_t)bufsiz);
        return r < 0 ? -(int64_t)errno : (int64_t)r;
    }
#else
    return -LNX_EINVAL;
#endif
}

/* ---- time extras: clock_getres(229), nanosleep(35/230), gettimeofday(96) */
static int64_t sys_clock_getres(int64_t clk, struct lnx_timespec *tp) {
    if (clk < 0 || clk > 7) return -LNX_EINVAL;
    if (tp) {
        tp->tv_sec = 0;
        tp->tv_nsec = 1;
    }
    return 0;
}

static int64_t sys_clock_nanosleep(int64_t clk, int64_t flags, const struct lnx_timespec *req,
                                   struct lnx_timespec *rem) {
    int64_t wait_ns;
    (void)rem;
    if (!req) return -LNX_EFAULT;
    if (req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec >= 1000000000LL) return -LNX_EINVAL;
    if (clk < 0 || clk > 7) return -LNX_EINVAL;
    wait_ns = req->tv_sec * 1000000000LL + req->tv_nsec;
    if (flags & 1 /* TIMER_ABSTIME */) {
        int64_t now = clock_ns(clk);
        if (now < 0) return -LNX_EINVAL;
        wait_ns = wait_ns > now ? (wait_ns - now) : 0;
    }
    if (wait_ns > 0) {
#if defined(_WIN32)
        int64_t ms = (wait_ns + 999999LL) / 1000000LL;
        Sleep(ms > 0x7fffffffLL ? 0x7fffffffu : (DWORD)ms);
#else
        struct timespec ts;
        ts.tv_sec = (time_t)(wait_ns / 1000000000LL);
        ts.tv_nsec = (long)(wait_ns % 1000000000LL);
        nanosleep(&ts, NULL);
#endif
    }
    return 0;
}

static int64_t sys_gettimeofday(int64_t *tv, void *tz) {
    int64_t ns = clock_ns(LNX_CLOCK_REALTIME);
    if (ns < 0) return -LNX_EINVAL;
    if (tv) {
        tv[0] = ns / 1000000000LL;
        tv[1] = (ns % 1000000000LL) / 1000LL;
    }
    if (tz) memset(tz, 0, 8);
    return 0;
}

static int32_t g_umask = 0022;

static int64_t dispatch_ex(int64_t nr, int64_t *a, const afw_clone_regs *regs, uintptr_t cur_sp);

/* The last syscall the process made (diagnosis: the watchdog). Only set when
 * called through afw_syscall_entry, never from tests calling dispatch. */
volatile int64_t afw_last_syscall_nr = -1;
volatile int64_t afw_last_syscall_args[6];
volatile uint64_t afw_last_syscall_ret;

int64_t afw_syscall_from_entry(int64_t nr, afw_syscall_frame *f) {
    int i;
    afw_clone_regs regs;
    afw_last_syscall_nr = nr;
    for (i = 0; i < 6; i++) afw_last_syscall_args[i] = f->args[i];
    afw_last_syscall_ret = f->rip;
    if (nr == 56) {
        regs.rip    = f->rip;
        regs.rbp    = f->caller_rbp;
        regs.rflags = f->rflags;
        regs.rbx    = f->rbx;
        regs.r12    = f->r12;
        regs.r13    = f->r13;
        regs.r14    = f->r14;
        regs.r15    = f->r15;
        return dispatch_ex(nr, f->args, &regs, (uintptr_t)f);
    }
    return dispatch_ex(nr, f->args, NULL, (uintptr_t)f);
}

/* Opt-in G2-1 measurement logging (--probe-syscalls); off by default.
 * Purely observational: never changes syscall behavior or return values. */
int afw_syscall_probe_log = 0;

static long g_probe_clone_calls;
static long g_probe_futex_total;
static long g_probe_futex_ops[16];
static long g_probe_futex_other;
static long g_probe_futex_requeue;
static long g_probe_futex_partial_bitset;
static long g_probe_futex_logged;
static long g_probe_misc_logged;
static int g_probe_summary_printed;

static const char *probe_futex_op_name(int op) {
    static const char *const names[13] = {
        "WAIT", "WAKE", "FD", "REQUEUE", "CMP_REQUEUE", "WAKE_OP",
        "LOCK_PI", "UNLOCK_PI", "TRYLOCK_PI", "WAIT_BITSET", "WAKE_BITSET",
        "WAIT_REQUEUE_PI", "CMP_REQUEUE_PI"
    };
    return (op >= 0 && op < 13) ? names[op] : "OTHER";
}

static void probe_log_clone(const int64_t *a) {
    static const struct { uint64_t bit; const char *name; } flag_bits[] = {
        { 0x00000100ULL, "CLONE_VM" },
        { 0x00000200ULL, "CLONE_FS" },
        { 0x00000400ULL, "CLONE_FILES" },
        { 0x00000800ULL, "CLONE_SIGHAND" },
        { 0x00002000ULL, "CLONE_PTRACE" },
        { 0x00004000ULL, "CLONE_VFORK" },
        { 0x00008000ULL, "CLONE_PARENT" },
        { 0x00010000ULL, "CLONE_THREAD" },
        { 0x00020000ULL, "CLONE_NEWNS" },
        { 0x00040000ULL, "CLONE_SYSVSEM" },
        { 0x00080000ULL, "CLONE_SETTLS" },
        { 0x00100000ULL, "CLONE_PARENT_SETTID" },
        { 0x00200000ULL, "CLONE_CHILD_CLEARTID" },
        { 0x00400000ULL, "CLONE_DETACHED" },
        { 0x00800000ULL, "CLONE_UNTRACED" },
        { 0x01000000ULL, "CLONE_CHILD_SETTID" },
    };
    uint64_t flags = (uint64_t)a[0];
    uint64_t sig = flags & 0xffULL;
    uint64_t high = flags & ~0xffULL;
    uint64_t known = 0;
    uint64_t child_stack = (uint64_t)a[1];
    uint64_t ptid = (uint64_t)a[2];
    uint64_t ctid = (uint64_t)a[3];
    uint64_t newtls = (uint64_t)a[4];
    size_t i;

    g_probe_clone_calls++;
    printf("[probe] clone #%ld: flags=0x%llx (sig=%llu", g_probe_clone_calls,
           (unsigned long long)flags, (unsigned long long)sig);
    for (i = 0; i < sizeof flag_bits / sizeof flag_bits[0]; i++) {
        if (high & flag_bits[i].bit) {
            printf("|%s", flag_bits[i].name);
            known |= flag_bits[i].bit;
        }
    }
    if (high & ~known)
        printf("|UNKNOWN=0x%llx", (unsigned long long)(high & ~known));
    printf(")\n");
    printf("[probe]   child_stack=0x%llx (mod16=%llu) ptid=0x%llx ctid=0x%llx newtls=0x%llx stub_ret=0x%llx\n",
           (unsigned long long)child_stack, (unsigned long long)(child_stack & 15ULL),
           (unsigned long long)ptid, (unsigned long long)ctid,
           (unsigned long long)newtls, (unsigned long long)afw_last_syscall_ret);
    if (child_stack && (child_stack & 7ULL) == 0) {
        const uint64_t *sp = (const uint64_t *)(uintptr_t)child_stack;
        size_t max_q = (4096ULL - (child_stack & 4095ULL)) / 8ULL;
        if (max_q > 8) max_q = 8;
        printf("[probe]   child_stack[0..%zu]:", max_q ? max_q - 1 : 0);
        for (i = 0; i < max_q; i++)
            printf(" [%zu]=0x%llx", i, (unsigned long long)sp[i]);
        printf("\n");
    }
    if (newtls && (newtls & 7ULL) == 0) {
        const uint64_t *tls = (const uint64_t *)(uintptr_t)newtls;
        size_t max_q = (4096ULL - (newtls & 4095ULL)) / 8ULL;
        if (max_q > 10) max_q = 10; /* sizeof(bionic_tcb) == 0x50 (10 slots: 0x00..0x48) */
        printf("[probe]   newtls slots[0..%zu]:\n", max_q ? max_q - 1 : 0);
        for (i = 0; i < max_q; i++)
            printf("[probe]     fs:[0x%02zx] = 0x%016llx\n", i * 8, (unsigned long long)tls[i]);
    }
    fflush(stdout);
}

static void probe_log_futex(const int64_t *a) {
    int64_t op_full = a[1];
    int op = (int)(op_full & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME));
    int is_priv = (op_full & FUTEX_PRIVATE_FLAG) != 0;
    int is_rt = (op_full & FUTEX_CLOCK_REALTIME) != 0;
    uint32_t val3 = (uint32_t)a[5];

    g_probe_futex_total++;
    if (op >= 0 && op < 16) g_probe_futex_ops[op]++;
    else g_probe_futex_other++;
    if (op == 3 || op == 4 || op == 11 || op == 12) g_probe_futex_requeue++;
    if ((op == FUTEX_WAIT_BITSET || op == FUTEX_WAKE_BITSET) && val3 != FUTEX_BITSET_MATCH_ANY)
        g_probe_futex_partial_bitset++;

    if (g_probe_futex_logged < 64) {
        g_probe_futex_logged++;
        printf("[probe] futex #%ld: op=%s(%d)%s%s uaddr=0x%llx val=0x%llx ts=0x%llx uaddr2=0x%llx val3=0x%x\n",
               g_probe_futex_total, probe_futex_op_name(op), op,
               is_priv ? "|PRIVATE" : "", is_rt ? "|CLOCK_REALTIME" : "",
               (unsigned long long)a[0], (unsigned long long)a[2],
               (unsigned long long)a[3], (unsigned long long)a[4], val3);
        if ((op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET) && a[3] != 0) {
            const struct lnx_timespec *tp = (const struct lnx_timespec *)(uintptr_t)a[3];
            printf("[probe]   timeout={tv_sec=%lld, tv_nsec=%lld}\n",
                   (long long)tp->tv_sec, (long long)tp->tv_nsec);
        }
        fflush(stdout);
    }
}

static void probe_log_syscall(int64_t nr, const int64_t *a) {
    if (nr == 56) { probe_log_clone(a); return; }
    if (nr == 202) { probe_log_futex(a); return; }
    if (g_probe_misc_logged >= 80) return;
    switch (nr) {
    case 9:
        g_probe_misc_logged++;
        printf("[probe] mmap(addr=0x%llx, len=0x%llx, prot=0x%llx, flags=0x%llx, fd=%lld, off=0x%llx)\n",
               (unsigned long long)a[0], (unsigned long long)a[1], (unsigned long long)a[2],
               (unsigned long long)a[3], (long long)a[4], (unsigned long long)a[5]);
        break;
    case 10:
        g_probe_misc_logged++;
        printf("[probe] mprotect(addr=0x%llx, len=0x%llx, prot=0x%llx)\n",
               (unsigned long long)a[0], (unsigned long long)a[1], (unsigned long long)a[2]);
        break;
    case 11:
        g_probe_misc_logged++;
        printf("[probe] munmap(addr=0x%llx, len=0x%llx)\n",
               (unsigned long long)a[0], (unsigned long long)a[1]);
        break;
    case 28:
        g_probe_misc_logged++;
        printf("[probe] madvise(addr=0x%llx, len=0x%llx, advice=%lld)\n",
               (unsigned long long)a[0], (unsigned long long)a[1], (long long)a[2]);
        break;
    case 14: case 97: case 131: case 157: case 204: case 218: case 273: case 302:
        g_probe_misc_logged++;
        printf("[probe] sys#%lld(a0=0x%llx, a1=0x%llx, a2=0x%llx, a3=0x%llx)\n",
               (long long)nr, (unsigned long long)a[0], (unsigned long long)a[1],
               (unsigned long long)a[2], (unsigned long long)a[3]);
        break;
    default:
        break;
    }
}

void afw_syscall_probe_summary(void) {
    int op;
    if (!afw_syscall_probe_log || g_probe_summary_printed) return;
    g_probe_summary_printed = 1;
    printf("\n=== G2-1 Syscall Probe Summary ===\n");
    printf("clone(56) calls observed: %ld (all returned -ENOSYS; measurement-only)\n", g_probe_clone_calls);
    printf("futex(202) calls observed: %ld\n", g_probe_futex_total);
    for (op = 0; op < 13; op++) {
        if (g_probe_futex_ops[op])
            printf("  FUTEX_%-15s: %ld\n", probe_futex_op_name(op), g_probe_futex_ops[op]);
    }
    if (g_probe_futex_other) printf("  FUTEX_OTHER          : %ld\n", g_probe_futex_other);
    printf("FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: %s (%ld)\n",
           g_probe_futex_requeue ? "SEEN" : "NOT SEEN", g_probe_futex_requeue);
    printf("FUTEX partial bitset (val3 != 0xffffffff): %s (%ld)\n",
           g_probe_futex_partial_bitset ? "SEEN" : "NOT SEEN", g_probe_futex_partial_bitset);
    afw_syscall_report();
    fflush(stdout);
}

static long atomic_inc_long(long *p) {
#if defined(_WIN32)
    return (long)InterlockedIncrement((volatile LONG *)p) - 1;
#else
    return __atomic_fetch_add(p, 1, __ATOMIC_RELAXED);
#endif
}

static void (*g_set_gs_cb)(uintptr_t);
static uintptr_t (*g_get_gs_cb)(void);
static _Thread_local uintptr_t t_fallback_gs;

void afw_syscall_set_gs_ops(void (*set_gs)(uintptr_t), uintptr_t (*get_gs)(void)) {
    g_set_gs_cb = set_gs;
    g_get_gs_cb = get_gs;
}

static void sys_set_art_gs(uintptr_t addr) {
    if (g_set_gs_cb) g_set_gs_cb(addr);
    else t_fallback_gs = addr;
}

static uintptr_t sys_get_art_gs(void) {
    return g_get_gs_cb ? g_get_gs_cb() : t_fallback_gs;
}

static int64_t dispatch_ex(int64_t nr, int64_t *a, const afw_clone_regs *regs, uintptr_t cur_sp) {
    if (nr >= 0 && nr < AFW_MAX_SYSCALL) (void)atomic_inc_long(&afw_syscall_counts[nr]);
    if (afw_syscall_probe_log) probe_log_syscall(nr, a);
    switch (nr) {
    case 0:   return afw_fd_read(a[0], (void *)(uintptr_t)a[1], (uint64_t)a[2]);
    case 1:   return afw_fd_write(a[0], (const void *)(uintptr_t)a[1], (uint64_t)a[2]);
    case 2:   return afw_fd_openat(-100, (const char *)(uintptr_t)a[0], a[1], (uint64_t)a[2]);
    case 3:   return afw_fd_close(a[0]);
    case 4:   return afw_fd_newfstatat(-100, (const char *)(uintptr_t)a[0], (void *)(uintptr_t)a[1], 0);
    case 5:   return afw_fd_fstat(a[0], (void *)(uintptr_t)a[1]);
    case 6:   return afw_fd_newfstatat(-100, (const char *)(uintptr_t)a[0], (void *)(uintptr_t)a[1], 0x100);
    case 8:   return afw_fd_lseek(a[0], a[1], a[2]);
    case 13:  return sys_rt_sigaction(a[0], (const void *)(uintptr_t)a[1],
                                      (void *)(uintptr_t)a[2], (uint64_t)a[3]);
    case 17:  return afw_fd_pread(a[0], (void *)(uintptr_t)a[1], (uint64_t)a[2], a[3]);
    case 18:  return afw_fd_pwrite(a[0], (const void *)(uintptr_t)a[1], (uint64_t)a[2], a[3]);
    case 19:  return afw_fd_readv(a[0], (const uint64_t *)(uintptr_t)a[1], a[2]);
    case 20:  return afw_fd_writev(a[0], (const uint64_t *)(uintptr_t)a[1], a[2]);
    case 21:  return afw_fd_faccessat(-100, (const char *)(uintptr_t)a[0], a[1], 0);
    case 24:  return sys_sched_yield();
    case 35:  return sys_clock_nanosleep(LNX_CLOCK_MONOTONIC, 0,
                                         (const struct lnx_timespec *)(uintptr_t)a[0],
                                         (struct lnx_timespec *)(uintptr_t)a[1]);
    case 39:  return sys_getpid();
    case 56:  return afw_sys_clone((uint64_t)a[0], (uint64_t)a[1], (uint64_t)a[2],
                                   (uint64_t)a[3], (uint64_t)a[4], regs);
    case 63:  return sys_uname((void *)(uintptr_t)a[0]);
    case 72:  return afw_fd_fcntl(a[0], a[1], a[2]);
    case 79:  return sys_getcwd((char *)(uintptr_t)a[0], (uint64_t)a[1]);
    case 87:  return afw_fd_unlinkat(-100, (const char *)(uintptr_t)a[0], 0);
    case 89:  return sys_readlinkat(-100, (const char *)(uintptr_t)a[0],
                                    (char *)(uintptr_t)a[1], a[2]);
    case 95:  return (int64_t)afw_os_atomic_xchg_i32(&g_umask, (int32_t)(a[0] & 0777));
    case 96:  return sys_gettimeofday((int64_t *)(uintptr_t)a[0], (void *)(uintptr_t)a[1]);
    case 97:  return sys_prlimit64(0, a[0], NULL, (void *)(uintptr_t)a[1]);
    case 110: return 1;            /* getppid */
    case 111: return sys_getpid(); /* getpgrp */
    case 121: return sys_getpid(); /* getpgid */
    case 124: return sys_getpid(); /* getsid */
    case 131: return sys_sigaltstack((const void *)(uintptr_t)a[0], (void *)(uintptr_t)a[1]);
    case 140: return 20;           /* getpriority (Linux returns 20 - nice; default nice=0 -> 20) */
    case 141: return 0;            /* setpriority */
    case 160: return sys_prlimit64(0, a[0], (const void *)(uintptr_t)a[1], NULL);
    case 202: return sys_futex(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 204: return sys_sched_getaffinity(a[0], (uint64_t)a[1], (void *)(uintptr_t)a[2]);
    case 218: return afw_sys_set_tid_address((uint64_t)a[0]);
    case 228: return sys_clock_gettime(a[0], (struct lnx_timespec *)(uintptr_t)a[1]);
    case 229: return sys_clock_getres(a[0], (struct lnx_timespec *)(uintptr_t)a[1]);
    case 230: return sys_clock_nanosleep(a[0], a[1],
                                         (const struct lnx_timespec *)(uintptr_t)a[2],
                                         (struct lnx_timespec *)(uintptr_t)a[3]);
    case 234: /* tgkill */
    case 297: /* rt_tgsigqueueinfo */
        fprintf(stderr, "[syscall] signal nr=%lld tgid=%lld tid=%lld sig=%lld\n",
                (long long)nr, (long long)a[0], (long long)a[1], (long long)a[2]);
        fflush(stderr);
        if (nr >= 0 && nr < AFW_MAX_SYSCALL) (void)atomic_inc_long(&g_unimplemented[nr]);
        return -LNX_ENOSYS;
    case 257: return afw_fd_openat(a[0], (const char *)(uintptr_t)a[1], a[2], (uint64_t)a[3]);
    case 262: return afw_fd_newfstatat(a[0], (const char *)(uintptr_t)a[1], (void *)(uintptr_t)a[2], a[3]);
    case 263: return afw_fd_unlinkat(a[0], (const char *)(uintptr_t)a[1], a[2]);
    case 267: return sys_readlinkat(a[0], (const char *)(uintptr_t)a[1],
                                    (char *)(uintptr_t)a[2], a[3]);
    case 269: return afw_fd_faccessat(a[0], (const char *)(uintptr_t)a[1], a[2], 0);
    case 302: return sys_prlimit64(a[0], a[1], (const void *)(uintptr_t)a[2],
                                   (void *)(uintptr_t)a[3]);
    case 309: return sys_getcpu((uint32_t *)(uintptr_t)a[0], (uint32_t *)(uintptr_t)a[1]);
    case 318: return sys_getrandom((void *)(uintptr_t)a[0], (uint64_t)a[1], a[2]);
    case 439: return afw_fd_faccessat(a[0], (const char *)(uintptr_t)a[1], a[2], a[3]);
    /* one app user, as AT_UID/AT_GID say (bionic_shim.c): uid 10000 */
    case 102: case 104: case 107: case 108: return 10000;   /* getuid getgid geteuid getegid */
    case 186: return sys_gettid();
    case 9:   return afw_mmap((uint64_t)a[0], (uint64_t)a[1], (int)a[2], (int)a[3], (int)a[4], a[5]);
    case 10:  return afw_mprotect((uint64_t)a[0], (uint64_t)a[1], (int)a[2]);
    case 11: {
        int64_t rc = 0;
        if (afw_thread_try_defer_self_unmap((uint64_t)a[0], (uint64_t)a[1], cur_sp, &rc))
            return rc;
        return afw_munmap((uint64_t)a[0], (uint64_t)a[1]);
    }
    case 14:  return sys_rt_sigprocmask((int)a[0], (const void *)(uintptr_t)a[1],
                                        (void *)(uintptr_t)a[2], (uint64_t)a[3]);
    case 28:  return afw_madvise((uint64_t)a[0], (uint64_t)a[1], (int)a[2]);
    case 12:  return -12;  /* brk: no heap break; bionic and Scudo use mmap */
    case 157: return sys_prctl(a[0], a[1], a[2], a[3], a[4]);
    case 158: /* arch_prctl(code, addr) */
        if (a[0] == 0x1001) { /* ARCH_SET_GS */
            sys_set_art_gs((uintptr_t)a[1]);
            return 0;
        }
        if (a[0] == 0x1004) { /* ARCH_GET_GS */
            uintptr_t *out = (uintptr_t *)(uintptr_t)a[1];
            if (!out) return -14; /* EFAULT */
            *out = sys_get_art_gs();
            return 0;
        }
        return -22;
    case 60:  /* exit: ends only the calling thread */
        if (afw_thread_is_cloned())
            afw_thread_exit((int)a[0]);
        afw_syscall_probe_summary();
        fflush(stdout);
#if defined(_WIN32)
        ExitThread((DWORD)a[0]);
#else
        _exit((int)a[0]);   /* host test builds have no emulated threads yet */
#endif
    case 231: /* exit_group: ends the whole process */
        afw_syscall_probe_summary();
        fflush(stdout);
#if defined(_WIN32)
        ExitProcess((UINT)a[0]);
#else
        exit((int)a[0]);
#endif
    default:
        if (nr >= 0 && nr < AFW_MAX_SYSCALL && atomic_inc_long(&g_unimplemented[nr]) == 0)
            fprintf(stderr, "[syscall] %lld not implemented, returning -ENOSYS\n", (long long)nr);
        return -LNX_ENOSYS;
    }
}

int64_t afw_syscall_dispatch(int64_t nr, int64_t *a) {
    return dispatch_ex(nr, a, NULL, (uintptr_t)&nr);
}

void afw_syscall_report(void) {
    int i, any = 0;
    for (i = 0; i < AFW_MAX_SYSCALL; i++) {
        if (!afw_syscall_counts[i]) continue;
        if (!any) printf("Linux syscalls made:\n");
        any = 1;
        printf("  %3d x%-6ld%s\n", i, afw_syscall_counts[i], g_unimplemented[i] ? "  (ENOSYS)" : "");
    }
    if (!any) printf("Linux syscalls made: none\n");
}
