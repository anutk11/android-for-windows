/*
 * attest_test.c - jump tables the analysis cannot bound, for the
 * attestation tests (PR #7). Each variant has one dispatch with NO bound
 * check and one fs: look-alike reachable only through the table.
 * Exported labels: afw_at_jmp (the jmp), afw_at_tbl (the attested table).
 *   VARIANT 1 good       lea T -> movsxd [T+i*4] -> add -> jmp: must be APPLIED
 *   VARIANT 2 unrelated  a lea of T exists, but the jump uses another table: REJECTED
 *   VARIANT 3 writable   the table is in .data: REJECTED (not read-only)
 *   VARIANT 4 padding    an entry lands on int3 padding: REJECTED
 *   VARIANT 5 bypass     a second path jumps straight to the jmp, around the chain: REJECTED
 *   VARIANT 6 second     another unresolved jmp reg in the same function could land in the chain: REJECTED
 *   VARIANT 7 behind     an unresolved jmp reg reachable only through the attested entries: REJECTED
 *   VARIANT 8 again      a second dispatch through the SAME table behind the entries
 *                        (clang duplicates switch dispatches, measured in libc++): APPLIED
 *   VARIANT 9 xblock_ok  second dispatch reuses callee-saved r15 = T across a call
 *                        (models libc++ 0xd54f2 / 0xd5554): APPLIED
 *   VARIANT 10 xblock_clobber one path into the second dispatch clobbers r15: REJECTED
 *   VARIANT 11 xblock_caller  second dispatch reuses caller-saved rcx = T across a call: REJECTED
 *   VARIANT 12 xblock_switch  another bounded switch in the same function clobbers r15: REJECTED (fail-closed)
 *   VARIANT 13 xblock_subreg  32-bit sub-register write (xor r15d, r15d) clobbers r15: REJECTED
 *   VARIANT 14 xblock_ext_pre another function jumps just before cross-block movsxd: REJECTED (must_hold_table seeding)
 *   VARIANT 15 xblock_ext_at  another function jumps directly onto cross-block movsxd: REJECTED
 */
#ifndef VARIANT
#define VARIANT 1
#endif

#if VARIANT == 3
#define TSEC ".data"
#else
#define TSEC ".rodata"
#endif

#if VARIANT >= 9
__attribute__((noinline, used, visibility("hidden"))) void afw_at_helper(void) { __asm__ volatile(""); }
#endif

#if VARIANT == 14 || VARIANT == 15
__attribute__((naked, used)) void afw_at_ext_caller(void) {
    __asm__("jmp afw_at_ext_tgt\n");
}
#endif

__attribute__((naked)) int afw_at_dispatch(int i) {
    __asm__(
#if VARIANT == 6
        "cmp $100, %edi\n\t"                     /* i == 100: jump through rsi (unknown target) */
        "jne 2f\n\t"
        "jmp *%rsi\n"
        "2:\n\t"
        "lea afw_at_tbl(%rip), %rcx\n\t"
        "movslq (%rcx,%rdi,4), %rax\n\t"
        "add %rcx, %rax\n\t"
#elif VARIANT == 5
        "cmp $100, %edi\n\t"                     /* i == 100: rax = c1, straight to the jmp */
        "jne 2f\n\t"
        "lea c1(%rip), %rax\n\t"
        "jmp afw_at_jmp\n"
        "2:\n\t"
        "lea afw_at_tbl(%rip), %rcx\n\t"
        "movslq (%rcx,%rdi,4), %rax\n\t"
        "add %rcx, %rax\n\t"
#elif VARIANT == 2
        "lea afw_at_tbl(%rip), %rcx\n\t"          /* lea of the attested table: not used by the jump */
        "lea other_tbl(%rip), %rdx\n\t"
        "movslq (%rdx,%rdi,4), %rax\n\t"
        "add %rdx, %rax\n\t"
#elif VARIANT == 9 || VARIANT == 10 || VARIANT == 12 || VARIANT == 13 || VARIANT == 14 || VARIANT == 15
        "lea afw_at_tbl(%rip), %r15\n\t"          /* callee-saved table base, like libc++ 0xd54e1 */
        "movslq (%r15,%rdi,4), %rax\n\t"
        "add %r15, %rax\n\t"
#else
        "lea afw_at_tbl(%rip), %rcx\n\t"
        "movslq (%rcx,%rdi,4), %rax\n\t"
        "add %rcx, %rax\n\t"
#endif
        ".globl afw_at_jmp\n"
        ".hidden afw_at_jmp\n"
        "afw_at_jmp:\n\t"
        "jmp *%rax\n"
        "c0:\n\t"
        "mov %fs:0x28, %rax\n\t"                   /* look-alike reachable only through the table */
        "mov $7, %eax\n\t"
        "ret\n"
        "c1:\n\t"
#if VARIANT == 7
        "jmp *%rsi\n\t"                          /* unresolved, behind the attested entries */
#elif VARIANT == 8
        "test %esi, %esi\n\t"                    /* second dispatch through the same table */
        "jz 3f\n\t"
        "mov %esi, %edx\n\t"
        "lea afw_at_tbl(%rip), %rcx\n\t"
        "movslq (%rcx,%rdx,4), %rax\n\t"
        "add %rcx, %rax\n\t"
        "jmp *%rax\n"
        "3:\n\t"
#elif VARIANT == 9
        "test %esi, %esi\n\t"                    /* callee-saved r15 preserved across call */
        "jz 3f\n\t"
        "call afw_at_helper\n\t"
        "mov %esi, %edx\n\t"
        "movslq (%r15,%rdx,4), %rax\n\t"
        "add %r15, %rax\n\t"
        "jmp *%rax\n"
        "3:\n\t"
#elif VARIANT == 10
        "test %esi, %esi\n\t"                    /* one path clobbers r15 before join -> MUST reject */
        "jz 3f\n\t"
        "cmp $1, %esi\n\t"
        "je 4f\n\t"
        "mov %rsi, %r15\n"
        "4:\n\t"
        "mov %esi, %edx\n\t"
        "movslq (%r15,%rdx,4), %rax\n\t"
        "add %r15, %rax\n\t"
        "jmp *%rax\n"
        "3:\n\t"
#elif VARIANT == 11
        "test %esi, %esi\n\t"                    /* caller-saved rcx clobbered by call -> MUST reject */
        "jz 3f\n\t"
        "call afw_at_helper\n\t"
        "mov %esi, %edx\n\t"
        "movslq (%rcx,%rdx,4), %rax\n\t"
        "add %rcx, %rax\n\t"
        "jmp *%rax\n"
        "3:\n\t"
#elif VARIANT == 12
        "cmp $1, %rsi\n\t"                       /* another bounded switch whose arm clobbers r15 -> fail-closed REJECT */
        "ja 3f\n\t"
        "lea sub_tbl(%rip), %rcx\n\t"
        "movslq (%rcx,%rsi,4), %rax\n\t"
        "add %rcx, %rax\n\t"
        "jmp *%rax\n"
        "sub0:\n\t"
        "jmp 4f\n"
        "sub1:\n\t"
        "mov %rsi, %r15\n"
        "4:\n\t"
        "mov %esi, %edx\n\t"
        "movslq (%r15,%rdx,4), %rax\n\t"
        "add %r15, %rax\n\t"
        "jmp *%rax\n"
        "3:\n\t"
#elif VARIANT == 13
        "test %esi, %esi\n\t"                    /* 32-bit sub-register write zeroes all 64 bits of r15 -> MUST reject */
        "jz 3f\n\t"
        "cmp $1, %esi\n\t"
        "je 4f\n\t"
        "xor %r15d, %r15d\n"
        "4:\n\t"
        "mov %esi, %edx\n\t"
        "movslq (%r15,%rdx,4), %rax\n\t"
        "add %r15, %rax\n\t"
        "jmp *%rax\n"
        "3:\n\t"
#elif VARIANT == 14
        "test %esi, %esi\n\t"                    /* external function jumps just before movsxd -> MUST reject via must_hold_table seeding */
        "jz 3f\n\t"
        "call afw_at_helper\n\t"
        ".globl afw_at_ext_tgt\n"
        ".hidden afw_at_ext_tgt\n"
        "afw_at_ext_tgt:\n\t"
        "mov %esi, %edx\n\t"
        "movslq (%r15,%rdx,4), %rax\n\t"
        "add %r15, %rax\n\t"
        "jmp *%rax\n"
        "3:\n\t"
#elif VARIANT == 15
        "test %esi, %esi\n\t"                    /* external function jumps directly onto movsxd -> MUST reject */
        "jz 3f\n\t"
        "call afw_at_helper\n\t"
        "mov %esi, %edx\n\t"
        ".globl afw_at_ext_tgt\n"
        ".hidden afw_at_ext_tgt\n"
        "afw_at_ext_tgt:\n\t"
        "movslq (%r15,%rdx,4), %rax\n\t"
        "add %r15, %rax\n\t"
        "jmp *%rax\n"
        "3:\n\t"
#endif
        "mov $1, %eax\n\t"
        "ret\n"
        "pad:\n\t"
        "int3\n\t"
        "int3\n\t"
        ".section " TSEC "\n\t"
        ".p2align 2\n"
        ".globl afw_at_tbl\n"
        ".hidden afw_at_tbl\n"
        "afw_at_tbl:\n\t"
#if VARIANT == 4
        ".long pad - afw_at_tbl\n\t"
#else
        ".long c0 - afw_at_tbl\n\t"
#endif
        ".long c1 - afw_at_tbl\n"
        "other_tbl:\n\t"
        ".long c0 - other_tbl\n\t"
        ".long c1 - other_tbl\n"
#if VARIANT == 12
        "sub_tbl:\n\t"
        ".long sub0 - sub_tbl\n\t"
        ".long sub1 - sub_tbl\n"
#endif
        ".text\n");
}
