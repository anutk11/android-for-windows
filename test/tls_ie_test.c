/*
 * tls_ie_test.c - fs:[reg] ELF TLS accesses (initial-exec), the form bionic's
 * gwp_asan uses: tp-relative through a register holding the TPOFF value.
 * Windows rewrites each one through a jmp trampoline (G1-TLS design, sec. 6).
 */
struct locals { int a, b; };
__thread struct locals afw_ie __attribute__((tls_model("initial-exec"))) = {11, 22};

/* compiler-generated forms: mov reg,[GOT]; op fs:[reg+disp] */
int afw_ie_read_b(void) { return afw_ie.b; }
void afw_ie_write_a(int v) { afw_ie.a = v; }
int afw_ie_and_b(int m) { return m & afw_ie.b; }
int *afw_ie_addr(void) { return &afw_ie.a; }            /* tp + TPOFF, the other form */

/* hand-written shapes from libc.so (measured in libc-tls-scan.txt):
 * a 3-byte store right before ret (needs the preceding mov to be moved,
 * rip-relative), and a read whose flags are consumed after the stub */
__attribute__((naked)) void afw_ie_store_ret(int v) {
    __asm__("mov afw_ie@gottpoff(%rip), %rcx\n\t"
            "mov %edi, %eax\n\t"
            "mov %eax, %fs:(%rcx)\n\t"
            "ret");
}
__attribute__((naked)) int afw_ie_test_flags(void) {      /* 1 if afw_ie.b has bit 0 clear */
    __asm__("mov afw_ie@gottpoff(%rip), %rax\n\t"
            "mov %fs:4(%rax), %eax\n\t"
            "test $1, %eax\n\t"
            "sete %al\n\t"
            "movzx %al, %eax\n\t"
            "ret");
}

/* a branch lands right after the access: the successor cannot be moved, so
 * the trampoline must take the preceding instruction instead.
 * x == 0: afw_ie.b + 1; otherwise 1 */
__attribute__((naked)) int afw_ie_branch_after(int x) {
    __asm__("mov afw_ie@gottpoff(%rip), %rcx\n\t"
            "xor %eax, %eax\n\t"
            "test %edi, %edi\n\t"
            "jnz 2f\n\t"
            "lea 1(%rdi), %edx\n\t"
            "mov %fs:4(%rcx), %eax\n"
            "2:\n\t"
            "add $1, %eax\n\t"
            "ret");
}

/* two fs:[reg] sites sharing the instruction between them (reviewer 3):
 * the first must take its predecessor so the second can take the middle.
 * afw_ie.a += 1 */
__attribute__((naked)) void afw_ie_incr_a(void) {
    __asm__("mov afw_ie@gottpoff(%rip), %rax\n\t"
            "mov %fs:(%rax), %ecx\n\t"
            "add $1, %ecx\n\t"
            "mov %ecx, %fs:(%rax)\n\t"
            "ret");
}
