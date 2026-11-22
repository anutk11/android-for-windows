/* fs_gate_test.c - must be REFUSED by the load gate (G1-TLS test 7):
 * one read of a bionic slot other than tp / stack guard, one write. */
long afw_fs_other_slot(void) { long v; __asm__ volatile("mov %%fs:0x10, %0" : "=r"(v)); return v; }
void afw_fs_write(long v) { __asm__ volatile("mov %0, %%fs:0x28" : : "r"(v)); }

/* reviewer 3 (issue #4): forms a trampoline must refuse */
void afw_fs_rsp_store(void) { __asm__ volatile("xor %%ecx, %%ecx\n\tmov %%rsp, %%fs:(%%rcx)" ::: "rcx"); }
void afw_fs_push(void) { __asm__ volatile("xor %%ecx, %%ecx\n\tpushq %%fs:(%%rcx)\n\tadd $8, %%rsp" ::: "rcx"); }
/* lea with an fs: prefix: the CPU ignores the segment, so it computes rcx on
 * Linux and on Windows alike. It is NOT an access and must be left alone
 * (the gate counts 5 above, not 6), never rewritten to [r11 + rcx]. */
void afw_fs_lea(void) { __asm__ volatile("xor %%ecx, %%ecx\n\t.byte 0x64\n\tlea (%%rcx), %%rax" ::: "rcx", "rax"); }
void afw_fs_cmpxchg(void) { __asm__ volatile("xor %%eax, %%eax\n\tlock cmpxchg %%rdx, %%fs:0x28" ::: "rax"); }

/* reviewer 4 (PR #9): mov rax, fs:[0] as moffs64 (64 48 a1 + imm64) has no
 * 32-bit displacement to rewrite: refused */
void afw_fs_moffs(void) { __asm__ volatile(".byte 0x64, 0x48, 0xa1\n\t.quad 0" ::: "rax"); }
