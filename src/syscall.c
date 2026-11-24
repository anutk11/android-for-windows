/*
 * syscall.c - Entry trampoline and first Linux syscalls.
 *
 * Unimplemented calls return -ENOSYS and are counted, so a run tells us
 * exactly which syscalls a program really needs.
 */
#include "syscall.h"
#include "fd.h"
#include "platform.h"
#include "vma.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#endif

#define LNX_ENOSYS 38
#define LNX_EBADF 9
#define LNX_EAGAIN 11
#define LNX_EINVAL 22
#define LNX_EFAULT 14
#define LNX_ETIMEDOUT 110

#if defined(_WIN32)
#pragma comment(lib, "synchronization.lib")   /* WaitOnAddress / WakeByAddress* */
#endif

long afw_syscall_counts[AFW_MAX_SYSCALL];
static long g_unimplemented[AFW_MAX_SYSCALL];

/*
 * Stack frame built by the entry (offsets from rbp):
 *   rbp+16   return address into the patched wrapper
 *   rbp+8    the caller's RFLAGS (restored on return, like sysret)
 *   rbp-48   args[6] = rdi, rsi, rdx, r10, r8, r9
 *   rbp-304  xmm0..xmm15 (16 x 16 bytes)
 * then rsp is aligned to 16 and 32 bytes of shadow space are reserved
 * (required by the Windows ABI, harmless elsewhere).
 */
/* Only the low 32 bits of rax are the syscall number: Linux treats it as an
 * int since 5.13 ("x86/entry: Use int everywhere for system call numbers"),
 * so 0x100000001 is write(), as here (checked for reviewer 4, #8). */
#if defined(_WIN32)
#  define DISPATCH_ARGS "mov %eax, %ecx\n\t lea -48(%rbp), %rdx\n\t"
#else
#  define DISPATCH_ARGS "mov %eax, %edi\n\t lea -48(%rbp), %rsi\n\t"
#endif

__attribute__((naked)) void afw_syscall_entry(void) {
    __asm__ volatile(
        "pushfq\n\t"                 /* Linux returns from syscall with the caller's RFLAGS (reviewer 4) */
        "push %rbp\n\t"
        "mov %rsp, %rbp\n\t"
        "sub $304, %rsp\n\t"
        "mov %rdi, -48(%rbp)\n\t"
        "mov %rsi, -40(%rbp)\n\t"
        "mov %rdx, -32(%rbp)\n\t"
        "mov %r10, -24(%rbp)\n\t"
        "mov %r8,  -16(%rbp)\n\t"
        "mov %r9,   -8(%rbp)\n\t"
        "movdqu %xmm0,  -304(%rbp)\n\t"
        "movdqu %xmm1,  -288(%rbp)\n\t"
        "movdqu %xmm2,  -272(%rbp)\n\t"
        "movdqu %xmm3,  -256(%rbp)\n\t"
        "movdqu %xmm4,  -240(%rbp)\n\t"
        "movdqu %xmm5,  -224(%rbp)\n\t"
        "movdqu %xmm6,  -208(%rbp)\n\t"
        "movdqu %xmm7,  -192(%rbp)\n\t"
        "movdqu %xmm8,  -176(%rbp)\n\t"
        "movdqu %xmm9,  -160(%rbp)\n\t"
        "movdqu %xmm10, -144(%rbp)\n\t"
        "movdqu %xmm11, -128(%rbp)\n\t"
        "movdqu %xmm12, -112(%rbp)\n\t"
        "movdqu %xmm13,  -96(%rbp)\n\t"
        "movdqu %xmm14,  -80(%rbp)\n\t"
        "movdqu %xmm15,  -64(%rbp)\n\t"
        "and $-16, %rsp\n\t"
        "sub $32, %rsp\n\t"
        DISPATCH_ARGS
        "call afw_syscall_from_entry\n\t"
        "movdqu -304(%rbp), %xmm0\n\t"
        "movdqu -288(%rbp), %xmm1\n\t"
        "movdqu -272(%rbp), %xmm2\n\t"
        "movdqu -256(%rbp), %xmm3\n\t"
        "movdqu -240(%rbp), %xmm4\n\t"
        "movdqu -224(%rbp), %xmm5\n\t"
        "movdqu -208(%rbp), %xmm6\n\t"
        "movdqu -192(%rbp), %xmm7\n\t"
        "movdqu -176(%rbp), %xmm8\n\t"
        "movdqu -160(%rbp), %xmm9\n\t"
        "movdqu -144(%rbp), %xmm10\n\t"
        "movdqu -128(%rbp), %xmm11\n\t"
        "movdqu -112(%rbp), %xmm12\n\t"
        "movdqu  -96(%rbp), %xmm13\n\t"
        "movdqu  -80(%rbp), %xmm14\n\t"
        "movdqu  -64(%rbp), %xmm15\n\t"
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

static int64_t sys_rt_sigprocmask(int64_t how, const void *set, void *oldset, uint64_t sigsetsize) {
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

/* The last syscall the process made (diagnosis: the watchdog). The
 * entry frame holds the return address into the patched wrapper at
 * rbp+16, 64 bytes above args (rbp-48). Only set when called through the
 * entry (afw_syscall_entry_frame), never from tests calling dispatch. */
volatile int64_t afw_last_syscall_nr = -1;
volatile int64_t afw_last_syscall_args[6];
volatile uint64_t afw_last_syscall_ret;

int64_t afw_syscall_from_entry(int64_t nr, int64_t *a) {
    int i;
    afw_last_syscall_nr = nr;
    for (i = 0; i < 6; i++) afw_last_syscall_args[i] = a[i];
    afw_last_syscall_ret = ((uint64_t *)a)[8];
    return afw_syscall_dispatch(nr, a);
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
        if (max_q > 11) max_q = 11;
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

int64_t afw_syscall_dispatch(int64_t nr, int64_t *a) {
    if (nr >= 0 && nr < AFW_MAX_SYSCALL) afw_syscall_counts[nr]++;
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
    case 19:  return afw_fd_readv(a[0], (const uint64_t *)(uintptr_t)a[1], a[2]);
    case 20:  return afw_fd_writev(a[0], (const uint64_t *)(uintptr_t)a[1], a[2]);
    case 39:  return sys_getpid();
    case 72:  return afw_fd_fcntl(a[0], a[1], a[2]);
    case 87:  return afw_fd_unlinkat(-100, (const char *)(uintptr_t)a[0], 0);
    case 202: return sys_futex(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 228: return sys_clock_gettime(a[0], (struct lnx_timespec *)(uintptr_t)a[1]);
    case 257: return afw_fd_openat(a[0], (const char *)(uintptr_t)a[1], a[2], (uint64_t)a[3]);
    case 262: return afw_fd_newfstatat(a[0], (const char *)(uintptr_t)a[1], (void *)(uintptr_t)a[2], a[3]);
    case 263: return afw_fd_unlinkat(a[0], (const char *)(uintptr_t)a[1], a[2]);
    case 318: return sys_getrandom((void *)(uintptr_t)a[0], (uint64_t)a[1], a[2]);
    /* one app user, as AT_UID/AT_GID say (bionic_shim.c): uid 10000 */
    case 102: case 104: case 107: case 108: return 10000;   /* getuid getgid geteuid getegid */
    case 186: return sys_gettid();
    case 9:   return afw_mmap((uint64_t)a[0], (uint64_t)a[1], (int)a[2], (int)a[3], (int)a[4], a[5]);
    case 10:  return afw_mprotect((uint64_t)a[0], (uint64_t)a[1], (int)a[2]);
    case 11:  return afw_munmap((uint64_t)a[0], (uint64_t)a[1]);
    case 14:  return sys_rt_sigprocmask(a[0], (const void *)(uintptr_t)a[1],
                                        (void *)(uintptr_t)a[2], (uint64_t)a[3]);
    case 28:  return afw_madvise((uint64_t)a[0], (uint64_t)a[1], (int)a[2]);
    case 12:  return -12;  /* brk: no heap break; bionic and Scudo use mmap */
    case 157: /* prctl */
        if (a[0] == 0x53564d41) return 0;  /* PR_SET_VMA (naming an area): accepted */
        return -22;
    case 60:  /* exit: ends only the calling thread */
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
        if (nr >= 0 && nr < AFW_MAX_SYSCALL && g_unimplemented[nr]++ == 0)
            fprintf(stderr, "[syscall] %lld not implemented, returning -ENOSYS\n", (long long)nr);
        return -LNX_ENOSYS;
    }
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
