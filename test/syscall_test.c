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

/*
 * Form B sites (no adjacent "mov eax, imm32"):
 * 1) bionic's generic syscall(): the number arrives in rdi at run time.
 *    Same instruction sequence as bionic/libc/arch-x86_64/bionic/syscall.S
 *    (without its errno handling, which is not what is being tested).
 */
__attribute__((naked)) long afw_generic_syscall(long nr, long a, long b, long c, long d, long e) {
    __asm__ volatile(
        "mov %rdi, %rax\n\t"
        "mov %rsi, %rdi\n\t"
        "mov %rdx, %rsi\n\t"
        "mov %rcx, %rdx\n\t"
        "mov %r8, %r10\n\t"
        "mov %r9, %r8\n\t"
        "mov 8(%rsp), %r9\n\t"
        "syscall\n\t"
        "ret");
}

/* 2) __restore_rt style: "mov rax, imm32" (7 bytes, sign-extended) */
long afw_sys_getpid_rax(void) {
    long r;
    __asm__ volatile("mov $39, %%rax\n\tsyscall" : "=a"(r) : : "rcx", "r11", "memory");
    return r;
}

/*
 * NEGATIVE test (reviewer 2): inside this function's .eh_frame range are
 * bytes that look exactly like "mov eax, 39; syscall" and an fs:[0x28] load,
 * but a jmp skips them: they are never executed. The loader must leave them
 * byte for byte unchanged.
 */
__attribute__((naked)) long afw_fake_site(void) {
    __asm__ volatile(
        "jmp 1f\n\t"
        ".globl afw_fake_site_bytes\n"
        "afw_fake_site_bytes:\n\t"
        ".byte 0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05\n\t"                   /* mov eax,39; syscall */
        ".byte 0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00\n"          /* mov rax, fs:[0x28] */
        "1:\tmov $7, %eax\n\t"
        "ret");
}

/*
 * A syscall reached ONLY through a switch jump table (clang emits
 * "lea; movsxd; add; jmp reg"). Control-flow analysis must resolve the table
 * and patch it; otherwise this raw syscall would stay and run on Windows.
 */
long afw_switch_syscall(int k) {
    long r;
    switch (k) {
    case 0: __asm__ volatile("nop" ::: "memory"); return 10;
    case 1: __asm__ volatile("nop; nop" ::: "memory"); return 11;
    case 2: __asm__ volatile("nop; nop; nop" ::: "memory"); return 12;
    case 3: __asm__ volatile("pause" ::: "memory"); return 13;
    case 4: __asm__ volatile("mov $39, %%eax\n\tsyscall" : "=a"(r) : : "rcx", "r11", "memory"); return r;
    case 5: __asm__ volatile("lfence" ::: "memory"); return 15;
    case 6: __asm__ volatile("sfence" ::: "memory"); return 16;
    case 7: __asm__ volatile("mfence" ::: "memory"); return 17;
    default: return -1;
    }
}
