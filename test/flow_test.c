/*
 * flow_test.c - switch tables whose bound check does NOT bound the 64-bit
 * index register (reviewer 4, #8). The analysis must not accept them: each
 * has a syscall reachable only through the table, which must stay UNPROVEN
 * and make the gate refuse the library.
 *   afw_flow_cmp32: cmp $1, %edi (32 bits), then index %rdi (64 bits, upper half unknown)
 *   afw_flow_mov8:  bound on %rbx, then mov %bl, %al: %rax's upper bits are not from %rbx
 */
__attribute__((naked)) long afw_flow_cmp32(long i) {
    __asm__("cmp $1, %edi\n\t"
            "ja 9f\n\t"
            "lea 8f(%rip), %rcx\n\t"
            "movslq (%rcx,%rdi,4), %rax\n\t"
            "add %rcx, %rax\n\t"
            "jmp *%rax\n"
            "1:\n\t"
            "mov $39, %eax\n\t"
            "syscall\n\t"
            "ret\n"
            "2:\n\t"
            "xor %eax, %eax\n\t"
            "ret\n"
            "9:\n\t"
            "mov $-1, %rax\n\t"
            "ret\n\t"
            ".section .rodata\n\t"
            ".p2align 2\n"
            "8:\n\t"
            ".long 1b - 8b\n\t"
            ".long 2b - 8b\n\t"
            ".text\n");
}

__attribute__((naked)) long afw_flow_mov8(long i) {
    __asm__("mov %rdi, %rbx\n\t"
            "cmp $1, %rbx\n\t"
            "ja 9f\n\t"
            "mov %bl, %al\n\t"
            "lea 8f(%rip), %rcx\n\t"
            "movslq (%rcx,%rax,4), %rax\n\t"
            "add %rcx, %rax\n\t"
            "jmp *%rax\n"
            "1:\n\t"
            "mov $39, %eax\n\t"
            "syscall\n\t"
            "ret\n"
            "2:\n\t"
            "xor %eax, %eax\n\t"
            "ret\n"
            "9:\n\t"
            "mov $-1, %rax\n\t"
            "ret\n\t"
            ".section .rodata\n\t"
            ".p2align 2\n"
            "8:\n\t"
            ".long 1b - 8b\n\t"
            ".long 2b - 8b\n\t"
            ".text\n");
}

/* 8-bit AND does NOT zero-extend bits 8..63: rdi remains unbounded -> MUST stay UNPROVEN. */
__attribute__((naked)) long afw_flow_and8(long i) {
    __asm__("and $1, %dil\n\t"
            "lea 8f(%rip), %rcx\n\t"
            "movslq (%rcx,%rdi,4), %rax\n\t"
            "add %rcx, %rax\n\t"
            "jmp *%rax\n"
            "1:\n\t"
            "mov $39, %eax\n\t"
            "syscall\n\t"
            "ret\n"
            "2:\n\t"
            "xor %eax, %eax\n\t"
            "ret\n"
            ".section .rodata\n\t"
            ".p2align 2\n"
            "8:\n\t"
            ".long 1b - 8b\n\t"
            ".long 2b - 8b\n\t"
            ".text\n");
}

/* 64-bit AND with negative sign-extended imm8 (-1 = 0xFFFFFFFFFFFFFFFF): unbounded -> MUST stay UNPROVEN. */
__attribute__((naked)) long afw_flow_and64_neg(long i) {
    __asm__("and $-1, %rdi\n\t"
            "lea 8f(%rip), %rcx\n\t"
            "movslq (%rcx,%rdi,4), %rax\n\t"
            "add %rcx, %rax\n\t"
            "jmp *%rax\n"
            "1:\n\t"
            "mov $39, %eax\n\t"
            "syscall\n\t"
            "ret\n"
            "2:\n\t"
            "xor %eax, %eax\n\t"
            "ret\n"
            ".section .rodata\n\t"
            ".p2align 2\n"
            "8:\n\t"
            ".long 1b - 8b\n\t"
            ".long 2b - 8b\n\t"
            ".text\n");
}
