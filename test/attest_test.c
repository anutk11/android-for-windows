/*
 * attest_test.c - jump tables the analysis cannot bound, for the
 * attestation tests (PR #7). Each variant has one dispatch with NO bound
 * check and one fs: look-alike reachable only through the table.
 * Exported labels: afw_at_jmp (the jmp), afw_at_tbl (the attested table).
 *   VARIANT 1 good       lea T -> movsxd [T+i*4] -> add -> jmp: must be APPLIED
 *   VARIANT 2 unrelated  a lea of T exists, but the jump uses another table: REJECTED
 *   VARIANT 3 writable   the table is in .data: REJECTED (not read-only)
 *   VARIANT 4 padding    an entry lands on int3 padding: REJECTED
 */
#ifndef VARIANT
#define VARIANT 1
#endif

#if VARIANT == 3
#define TSEC ".data"
#else
#define TSEC ".rodata"
#endif

__attribute__((naked)) int afw_at_dispatch(int i) {
    __asm__(
#if VARIANT == 2
        "lea afw_at_tbl(%rip), %rcx\n\t"          /* lea of the attested table: not used by the jump */
        "lea other_tbl(%rip), %rdx\n\t"
        "movslq (%rdx,%rdi,4), %rax\n\t"
        "add %rdx, %rax\n\t"
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
        ".long c1 - other_tbl\n\t"
        ".text\n");
}
