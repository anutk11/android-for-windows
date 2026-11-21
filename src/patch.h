/*
 * patch.h - Load-time code patching (gate G1).
 *
 * Before an Android library's code becomes executable, every instruction that
 * cannot work on Windows is rewritten once, in place.
 *
 * syscall sites, two forms:
 *   A) "mov eax, NR; syscall" (7 bytes) -> "call stub_NR; nop2"
 *      stub_NR: mov eax, NR; jmp afw_syscall_entry
 *   B) anything else (generic syscall(), __restore_rt): the instructions just
 *      before the syscall (>= 3 bytes, same basic block, position-independent,
 *      not using r11) move into a stub, and the site becomes "call stub; nops".
 *      stub: pop r11; <moved instructions>; push r11; jmp afw_syscall_entry
 *      rax holds the number at run time and reaches the dispatcher as is.
 *      r11 is free to use: the real syscall instruction clobbers it too.
 * Stubs live in a reserve right after the library (one allocation), so every
 * call rel32 reaches; running out of room or range is a load error.
 *
 * A site is REFUSED (left untouched, reported loudly) unless it is provably
 * safe:
 *   - no branch may land inside the bytes being replaced;
 *   - its function must be known (from .eh_frame, else sized symbols);
 *   - nothing in the whole function may touch memory below rsp: no [rsp-N],
 *     and no [reg-N] through a register that was given a copy of rsp. The
 *     stub's call writes at [rsp-8], i.e. into the System V red zone.
 *
 * fs: accesses: "fs:[disp32]" bionic TLS slots -> "gs:[TEB TlsSlot]"
 * (Windows only). "fs:[reg]" forms (ELF TLS) are reported with their bytes,
 * decoding and whether they lie inside a known function.
 */
#ifndef AFW_PATCH_H
#define AFW_PATCH_H

#include <stddef.h>
#include <stdint.h>

#define AFW_STUB_RESERVE (64 * 1024)

typedef struct {
    int fs_patched;            /* fs:[disp32] rewritten to gs: */
    int fs_reg_in_func;        /* fs:[reg] inside a known function: real code */
    int fs_reg_outside;        /* fs:[reg] outside any function: decoded data */
    int sys_patched;           /* form A */
    int sys_patched_moved;     /* form B */
    int sys_refused_branch;
    int sys_refused_redzone;
    int sys_refused_unknown;   /* function bounds unknown, or nothing movable */
    int stubs;
} afw_patch_report;

typedef struct { unsigned char *addr; size_t size; } afw_code_range;

typedef int (*afw_bounds_fn)(const void *ctx, uint64_t addr, uint64_t *start, uint64_t *end);

typedef struct {
    afw_bounds_fn bounds;   /* function boundaries */
    const void *ctx;
    intptr_t bias;          /* to print library-relative offsets */
    const char *name;       /* library name for messages */
} afw_patch_ctx;

/* Returns 0 on success, 1 if some sites were refused, -1 on a fatal error
 * (stub area full or out of range): the library must not be run. */
int afw_patch_code(const afw_code_range *ranges, int nranges,
                   unsigned char *stub_area, size_t stub_size,
                   const afw_patch_ctx *ctx, afw_patch_report *rep, int verbose);

#endif
