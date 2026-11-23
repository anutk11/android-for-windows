/*
 * exec.c - start an Android executable: the kernel's part of execve.
 *
 * An Android executable is a PIE whose _start (crtbegin) does
 *     xor %ebp,%ebp; mov %rsp,%rdi; and $-16,%rsp; call _start_main
 * and _start_main calls libc's __libc_init(raw_args, NULL, &main, &structors).
 * raw_args is what the Linux kernel leaves at the initial rsp:
 *     argc | argv[0..argc-1] | NULL | envp[..] | NULL | auxv pairs | AT_NULL
 * (KernelArgumentBlock). __libc_init runs main and ends in exit(), which is
 * exit_group: the process ends there and afw_exec never returns.
 *
 * The block is built ON THIS THREAD'S STACK with alloca (which probes the
 * pages downward, the way Windows grows a stack through its guard page);
 * the executable then runs on the rest of the same stack, so Windows'
 * stack limits in the TEB stay true for its exception dispatch.
 */
#include "exec.h"
#include "bionic_shim.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <malloc.h>
#define afw_alloca _alloca
#else
#include <alloca.h>
#define afw_alloca alloca
#endif

#define AT_NULL_ 0
#define AT_PHDR_ 3
#define AT_PHENT_ 4
#define AT_PHNUM_ 5
#define AT_PAGESZ_ 6
#define AT_BASE_ 7
#define AT_ENTRY_ 9
#define AT_UID_ 11
#define AT_EUID_ 12
#define AT_GID_ 13
#define AT_EGID_ 14
#define AT_HWCAP_ 16
#define AT_SECURE_ 23
#define AT_RANDOM_ 25
#define AT_HWCAP2_ 26
#define AT_EXECFN_ 31

/* Jump to `entry` with rsp = sp, rbp = 0, rdx = 0 (no rtld fini). Never returns. */
#if defined(_WIN32)
/* clang-cl reads top-level asm as Intel syntax: say AT&T here, then restore */
__asm__(".att_syntax prefix\n.text\n.globl afw_enter\nafw_enter:\n\t"   /* Windows x64: rcx = entry, rdx = sp */
        "mov %rdx, %rsp\n\txor %ebp, %ebp\n\txor %edx, %edx\n\tjmp *%rcx\n.intel_syntax noprefix\n");
#else
__asm__(".text\n.globl afw_enter\n.type afw_enter,@function\nafw_enter:\n\t"   /* SysV: rdi, rsi */
        "mov %rsi, %rsp\n\txor %ebp, %ebp\n\tmov %rdi, %rax\n\txor %edx, %edx\n\tjmp *%rax\n");
#endif
void afw_enter(uint64_t entry, void *sp);

/* The program headers in the executable's memory (AT_PHDR): PT_PHDR says
 * where, else the first PT_LOAD that covers e_phoff in the file. */
static uint64_t phdr_in_memory(const afw_lib *exe) {
    int k;
    if (!exe->phdr) return 0;
    for (k = 0; k < exe->phnum; k++)
        if (exe->phdr[k].p_type == PT_PHDR) return (uint64_t)exe->bias + exe->phdr[k].p_vaddr;
    for (k = 0; k < exe->phnum; k++) {
        const Elf64_Phdr *p = &exe->phdr[k];
        if (p->p_type == PT_LOAD && exe->phoff >= p->p_offset &&
            p->p_filesz <= UINT64_MAX - p->p_offset &&
            exe->phoff < p->p_offset + p->p_filesz)
            return (uint64_t)exe->bias + p->p_vaddr + (exe->phoff - p->p_offset);
    }
    return 0;
}

#define AFW_EXEC_MAX_ARGS 4096
#define AFW_EXEC_MAX_ENV  4096

static uint64_t g_exec_auxv[2 * 20];
static size_t g_exec_auxv_len;

void afw_exec_prepare_auxv(const afw_lib *exe, const char *execfn) {
    const unsigned char *at_random;
    size_t k = 0;
    if (!exe || !exe->entry) return;
    if (!execfn) execfn = exe->path;

    /* Reuse the single AT_RANDOM seed initialized in libc_shared_globals so
     * libc.so constructors, executable constructors, and KernelArgumentBlock
     * see the exact same 16 random bytes (stack guard / setjmp cookie). */
    at_random = afw_shared_globals_random();

    /* Fixed/default auxv fields (documented in docs/design/G1-LIBC-INIT.md):
     *   AT_BASE  = 0: afw-loader replaces PT_INTERP (/system/bin/linker64)
     *                 rather than mapping a separate interpreter binary.
     *   AT_*UID/GID = 10000: first Android app uid/gid (matches syscall.c).
     *   AT_HWCAP/2  = 0: conservative baseline x86_64 until CPUID mapping. */
#define PUT(t, v) (g_exec_auxv[k++] = (uint64_t)(t), g_exec_auxv[k++] = (uint64_t)(v))
    PUT(AT_PHDR_, phdr_in_memory(exe));
    PUT(AT_PHENT_, sizeof(Elf64_Phdr));
    PUT(AT_PHNUM_, exe->phnum);
    PUT(AT_PAGESZ_, 4096);
    PUT(AT_BASE_, 0);
    PUT(AT_ENTRY_, exe->entry);
    PUT(AT_UID_, 10000); PUT(AT_EUID_, 10000); PUT(AT_GID_, 10000); PUT(AT_EGID_, 10000);
    PUT(AT_HWCAP_, 0); PUT(AT_HWCAP2_, 0);
    PUT(AT_SECURE_, 0);
    PUT(AT_RANDOM_, (uintptr_t)at_random);
    PUT(AT_EXECFN_, (uintptr_t)execfn);
    PUT(AT_NULL_, 0);
#undef PUT
    g_exec_auxv_len = k;
    afw_shared_globals_set_process(g_exec_auxv, NULL, execfn);
}

/* Not instrumented by ASan: the program's own stack grows down from the
 * block, through what ASan would have made an alloca red zone (measured:
 * a false "dynamic-stack-buffer-overflow" in the syscall entry). */
#if defined(__clang__) || defined(__GNUC__)
__attribute__((no_sanitize("address")))
#endif
int afw_exec(const afw_lib *exe, int argc, char **argv, char **envp) {
    static char *empty_env[1] = {NULL};
    char **envp_use = envp ? envp : empty_env;
    uint64_t *blk;
    size_t nenv = 0, nwords, bytes, i;
    int a;
    unsigned char *mem;

    if (!exe || !exe->entry) { fprintf(stderr, "error: %s has no entry point\n", exe ? exe->path : "(null)"); return -1; }
    if (argc < 1 || argc > AFW_EXEC_MAX_ARGS || !argv || !argv[0]) {
        fprintf(stderr, "error: bad argument count %d\n", argc);
        return -1;
    }
    while (envp_use[nenv]) {
        if (++nenv > AFW_EXEC_MAX_ENV) {
            fprintf(stderr, "error: too many environment entries (>%d)\n", AFW_EXEC_MAX_ENV);
            return -1;
        }
    }

    afw_exec_prepare_auxv(exe, argv[0]);
    afw_shared_globals_set_process(g_exec_auxv, envp_use, argv[0]);

    /* Layout: argc | argv[0..argc-1] | NULL | envp[0..nenv-1] | NULL | auxv[0..len-1] */
    nwords = 1 + (size_t)argc + 1 + nenv + 1 + g_exec_auxv_len;
    if (nwords > (SIZE_MAX - 64) / 8) { fprintf(stderr, "error: initial stack size overflow\n"); return -1; }
    bytes = nwords * 8 + 64;
    mem = (unsigned char *)afw_alloca(bytes);
    blk = (uint64_t *)(((uintptr_t)mem + 15) & ~(uintptr_t)15);   /* rsp at argc: 16-aligned */
    i = 0;
    blk[i++] = (uint64_t)argc;
    for (a = 0; a < argc; a++) blk[i++] = (uint64_t)(uintptr_t)argv[a];
    blk[i++] = 0;
    for (a = 0; (size_t)a < nenv; a++) blk[i++] = (uint64_t)(uintptr_t)envp_use[a];
    blk[i++] = 0;
    memcpy(&blk[i], g_exec_auxv, g_exec_auxv_len * 8);

    fflush(stdout); fflush(stderr);
    afw_enter(exe->entry, blk);
    return -1;                                /* not reached */
}
