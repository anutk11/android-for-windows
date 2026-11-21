/*
 * syscall.c - Entry trampoline and first Linux syscalls.
 *
 * Unimplemented calls return -ENOSYS and are counted, so a run tells us
 * exactly which syscalls a program really needs.
 */
#include "syscall.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

#define LNX_ENOSYS 38
#define LNX_EBADF 9

long afw_syscall_counts[AFW_MAX_SYSCALL];
static long g_unimplemented[AFW_MAX_SYSCALL];

/*
 * Stack frame built by the entry (offsets from rbp):
 *   rbp+8    return address into the patched wrapper
 *   rbp-48   args[6] = rdi, rsi, rdx, r10, r8, r9
 *   rbp-304  xmm0..xmm15 (16 x 16 bytes)
 * then rsp is aligned to 16 and 32 bytes of shadow space are reserved
 * (required by the Windows ABI, harmless elsewhere).
 */
#if defined(_WIN32)
#  define DISPATCH_ARGS "mov %eax, %ecx\n\t lea -48(%rbp), %rdx\n\t"
#else
#  define DISPATCH_ARGS "mov %eax, %edi\n\t lea -48(%rbp), %rsi\n\t"
#endif

__attribute__((naked)) void afw_syscall_entry(void) {
    __asm__ volatile(
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
        "call afw_syscall_dispatch\n\t"
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

static int64_t sys_getpid(void) {
#if defined(_WIN32)
    return (int64_t)GetCurrentProcessId();
#else
    return (int64_t)getpid();
#endif
}

int64_t afw_syscall_dispatch(int64_t nr, int64_t *a) {
    if (nr >= 0 && nr < AFW_MAX_SYSCALL) afw_syscall_counts[nr]++;
    switch (nr) {
    case 1:   return sys_write(a[0], (const void *)(uintptr_t)a[1], (uint64_t)a[2]);
    case 39:  return sys_getpid();
    case 60:  /* exit */
    case 231: /* exit_group */
        fflush(stdout);
        exit((int)a[0]);
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
