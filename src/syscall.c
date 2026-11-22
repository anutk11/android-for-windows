/*
 * syscall.c - Entry trampoline and first Linux syscalls.
 *
 * Unimplemented calls return -ENOSYS and are counted, so a run tells us
 * exactly which syscalls a program really needs.
 */
#include "syscall.h"
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

/* ---- individual syscalls ---- */

static int64_t sys_write(int64_t fd, const void *buf, uint64_t len) {
#if defined(_WIN32)
    DWORD done = 0;
    HANDLE h;
    if (fd == 1) h = GetStdHandle(STD_OUTPUT_HANDLE);
    else if (fd == 2) h = GetStdHandle(STD_ERROR_HANDLE);
    else return -LNX_EBADF;
    if (!WriteFile(h, buf, (DWORD)len, &done, NULL)) return -LNX_EBADF;
    return (int64_t)done;
#else
    ssize_t r;
    if (fd != 1 && fd != 2) return -LNX_EBADF;
    r = write((int)fd, buf, (size_t)len);
    return r < 0 ? -LNX_EBADF : r;
#endif
}

/* writev: each iovec in order through write(); stops at the first short or
 * failed write, like Linux returns the bytes written so far. */
static int64_t sys_writev(int64_t fd, const uint64_t *iov, int64_t cnt) {
    int64_t total = 0, i;
    if (cnt < 0 || cnt > 1024) return -22;          /* EINVAL beyond IOV_MAX */
    for (i = 0; i < cnt; i++) {
        uint64_t len = iov[2 * i + 1];
        int64_t r;
        if (!len) continue;
        r = sys_write(fd, (const void *)(uintptr_t)iov[2 * i], len);
        if (r < 0) return total ? total : r;
        total += r;
        if ((uint64_t)r < len) break;
    }
    return total;
}

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

/* Milliseconds to wait, rounded UP (never return before the deadline), or
 * INFINITE; -1 for a malformed timespec. */
#if defined(_WIN32)
static int64_t wait_ms(const struct lnx_timespec *t, int absolute, int64_t clk) {
    int64_t ns;
    if (!t) return INFINITE;
    if (t->tv_sec < 0 || t->tv_nsec < 0 || t->tv_nsec >= 1000000000LL) return -1;
    if (t->tv_sec > (INT64_MAX - 999999999LL) / 1000000000LL) return INFINITE;
    ns = t->tv_sec * 1000000000LL + t->tv_nsec;
    if (absolute) { int64_t now = clock_ns(clk); ns = ns > now ? ns - now : 0; }
    ns = (ns + 999999) / 1000000;
    return ns >= (int64_t)INFINITE ? (int64_t)INFINITE - 1 : ns;
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
        int64_t ms = wait_ms((const struct lnx_timespec *)(uintptr_t)ts, op == FUTEX_WAIT_BITSET,
                             (op_full & FUTEX_CLOCK_REALTIME) ? LNX_CLOCK_REALTIME : LNX_CLOCK_MONOTONIC);
        if (ms < 0) return -LNX_EINVAL;
        if (*p != expect) return -LNX_EAGAIN;           /* the value already changed */
        if (WaitOnAddress((volatile VOID *)p, &expect, sizeof expect, (DWORD)ms)) return 0;
        return GetLastError() == ERROR_TIMEOUT ? -LNX_ETIMEDOUT : -LNX_EINVAL;
        /* a return of 0 may be spurious: futex callers re-check, as on Linux */
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

int64_t afw_syscall_dispatch(int64_t nr, int64_t *a) {
    if (nr >= 0 && nr < AFW_MAX_SYSCALL) afw_syscall_counts[nr]++;
    switch (nr) {
    case 1:   return sys_write(a[0], (const void *)(uintptr_t)a[1], (uint64_t)a[2]);
    case 39:  return sys_getpid();
    case 20:  return sys_writev(a[0], (const uint64_t *)(uintptr_t)a[1], a[2]);
    case 202: return sys_futex(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 228: return sys_clock_gettime(a[0], (struct lnx_timespec *)(uintptr_t)a[1]);
    case 318: return sys_getrandom((void *)(uintptr_t)a[0], (uint64_t)a[1], a[2]);
    /* one app user, as AT_UID/AT_GID say (bionic_shim.c): uid 10000 */
    case 102: case 104: case 107: case 108: return 10000;   /* getuid getgid geteuid getegid */
    case 186: return sys_gettid();
    case 9:   return afw_mmap((uint64_t)a[0], (uint64_t)a[1], (int)a[2], (int)a[3], (int)a[4], a[5]);
    case 10:  return afw_mprotect((uint64_t)a[0], (uint64_t)a[1], (int)a[2]);
    case 11:  return afw_munmap((uint64_t)a[0], (uint64_t)a[1]);
    case 28:  return afw_madvise((uint64_t)a[0], (uint64_t)a[1], (int)a[2]);
    case 12:  return -12;  /* brk: no heap break; bionic and Scudo use mmap */
    case 157: /* prctl */
        if (a[0] == 0x53564d41) return 0;  /* PR_SET_VMA (naming an area): accepted */
        return -22;
    case 60:  /* exit: ends only the calling thread */
        fflush(stdout);
#if defined(_WIN32)
        ExitThread((DWORD)a[0]);
#else
        _exit((int)a[0]);   /* host test builds have no emulated threads yet */
#endif
    case 231: /* exit_group: ends the whole process */
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
