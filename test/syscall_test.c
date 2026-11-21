/*
 * syscall_test.c - Raw Linux syscalls, written exactly the way bionic's
 * generated wrappers are ("mov eax, NR; syscall"). On Windows these only
 * work if the loader rewrote them at load time.
 */
#include <stddef.h>

long afw_sys_getpid(void) {
    long r;
    __asm__ volatile("mov $39, %%eax\n\tsyscall" : "=a"(r) : : "rcx", "r11", "memory");
    return r;
}

long afw_sys_write(int fd, const void *buf, size_t len) {
    long r;
    __asm__ volatile("mov $1, %%eax\n\tsyscall"
                     : "=a"(r) : "D"((long)fd), "S"(buf), "d"(len) : "rcx", "r11", "memory");
    return r;
}

/* A syscall the emulator does not implement: must come back as -ENOSYS (-38). */
long afw_sys_unknown(void) {
    long r;
    __asm__ volatile("mov $169, %%eax\n\tsyscall" : "=a"(r) : : "rcx", "r11", "memory"); /* reboot */
    return r;
}

/* xmm registers must survive a syscall, as on Linux. */
double afw_sys_keeps_xmm(double x) {
    double y;
    __asm__ volatile("movsd %1, %%xmm7\n\t"
                     "mov $39, %%eax\n\tsyscall\n\t"
                     "movsd %%xmm7, %0"
                     : "=x"(y) : "x"(x) : "rax", "rcx", "r11", "xmm7", "memory");
    return y;
}

/*
 * UNSAFE on purpose: a branch lands on the syscall itself, in the middle of
 * the 7-byte site. The loader must refuse to patch it (and say so loudly).
 * Never called from the tests.
 */
long afw_sys_branch_into_site(int skip_mov) {
    long r;
    __asm__ volatile("test %k1, %k1\n\t"
                     "mov $39, %%eax\n\t"
                     "jnz 1f\n\t"
                     "mov $39, %%eax\n"
                     "1:\tsyscall"
                     : "=a"(r) : "r"(skip_mov) : "rcx", "r11", "memory");
    return r;
}
