/*
 * redzone_test.c - NEGATIVE test: every syscall here except afw_rz_safe sits
 * in a function that keeps data below rsp (the System V red zone). Patching
 * them would let the stub's `call` overwrite that data, so the loader must
 * REFUSE all three. Only afw_rz_safe may be patched and called.
 */
__attribute__((naked)) long afw_rz_direct(long x) {
    __asm__ volatile(
        "mov %rdi, -8(%rsp)\n\t"       /* keep x in the red zone */
        "mov $39, %eax\n\t"
        "syscall\n\t"
        "mov -8(%rsp), %rax\n\t"       /* expect x back */
        "ret");
}

/* The red zone use is in an earlier block, before an unconditional jump:
 * a block-local check would start after the jmp and miss it. */
__attribute__((naked)) long afw_rz_earlier_block(long x) {
    __asm__ volatile(
        "mov %rdi, -16(%rsp)\n\t"
        "jmp 1f\n\t"
        "ud2\n"
        "1:\tmov $39, %eax\n\t"
        "syscall\n\t"
        "mov -16(%rsp), %rax\n\t"
        "ret");
}

/* Through a copy of rsp: [rdx - 8] is below rsp too. */
__attribute__((naked)) long afw_rz_via_copy(long x) {
    __asm__ volatile(
        "mov %rsp, %rdx\n\t"
        "mov %rdi, -8(%rdx)\n\t"
        "mov $39, %eax\n\t"
        "syscall\n\t"
        "mov -8(%rsp), %rax\n\t"
        "ret");
}

/* Control: no red zone, must be patched and must work. */
__attribute__((naked)) long afw_rz_safe(void) {
    __asm__ volatile(
        "mov $39, %eax\n\t"
        "syscall\n\t"
        "ret");
}
