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
 * Only instructions that control flow can reach from a function's entry are
 * considered (direct branches and clang switch tables followed; a function
 * with an indirect jump that cannot be resolved is UNDECIDED and its
 * unreached bytes stay untouched and are reported). Bytes that merely look like a
 * syscall or an fs: access but are never executed are left untouched.
 *
 * A site is REFUSED unless it is provably safe. A refused site keeps every
 * byte except its 2-byte `syscall`, which becomes `ud2` (0F 0B): same length,
 * nothing moves, no stack is touched - if it ever runs, the program stops with
 * a clear report instead of entering the Windows kernel with a Linux number.
 * Conditions:
 *   - no branch may land inside the bytes being replaced;
 *   - its function must be known (from .eh_frame, else sized symbols);
 *   - nothing in the whole function may touch memory below rsp: no [rsp-N],
 *     and no [reg-N] through a register holding a copy of rsp (frame
 *     pointer) unless N is within what "sub rsp, K" allocated (N <= K).
 *     The stub's call writes at [rsp-8], i.e. into the System V red zone.
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
    int fs_skipped_outside;    /* fs:[disp32] outside any function: not touched */
    int sys_patched;           /* form A */
    int sys_patched_moved;     /* form B */
    int sys_refused_branch;
    int sys_refused_redzone;
    int sys_refused_unknown;   /* function bounds unknown, or nothing movable */
    int stubs;
    /* audit: candidate bytes found by a plain linear sweep of the segments */
    int unreachable_ignored;   /* inside a function, but no path reaches them */
    int unproven;              /* unreached, in a function with an unresolved indirect jump */
    int funcs_undecided;       /* functions with an unresolved indirect jump */
    int fs_disp_seen;          /* reachable fs:[disp32] accesses (any platform) */
    int landing_pads;          /* C++ landing pads used as entry points */
    int lsda_failures;         /* exception tables we could not fully decode */
    int sys_trapped;           /* refused sites whose syscall became ud2 (loud trap) */
    int sys_untouched;         /* syscall bytes neither patched nor trapped: blocks loading */
    int sys_outside_functions; /* syscall in executable bytes with no .eh_frame entry */
    int fs_outside_functions;
    int fs_reg_trampolined;    /* fs:[reg] rewritten through a jmp trampoline (Windows) */
    int fs_reg_feasible;       /* fs:[reg] a trampoline can handle (counted on every platform) */
    int fs_unsupported;        /* reachable fs: access other than a read of fs:[0] / fs:[0x28]: blocks loading */
    int gs_unsupported;        /* reachable gs: access (ART's Thread*; on Windows gs is the TEB): blocks loading */
    int gs_outside_functions;  /* gs: look-alikes outside .eh_frame: blocks loading, like fs: */
    int redzone_direct;        /* refusals by reason: [rsp-N] */
    int redzone_via_copy;      /* [reg-N] beyond what sub rsp allocated */
    /* every reachable fs:[disp32] access by (offset, instruction, read/write) */
    struct { int64_t disp; int mnemonic; int write; int count; } fs_kind[48];
    int nfs_kind;
} afw_patch_report;

/* If pc is inside an fs:[reg] trampoline, the original instruction it
 * replaces (for crash reports); otherwise NULL. */
const void *afw_stub_origin(const void *pc);

/* Name of a Zydis mnemonic id (for the fs: histogram). */
const char *afw_mnemonic_name(int mnemonic);

typedef struct { unsigned char *addr; size_t size; } afw_code_range;

typedef int (*afw_bounds_fn)(const void *ctx, uint64_t addr, uint64_t *start, uint64_t *end);

typedef struct {
    afw_bounds_fn bounds;   /* function boundaries */
    const void *ctx;
    intptr_t bias;          /* to print library-relative offsets */
    const char *name;       /* library name for messages */
    int ranges_are_functions; /* ranges come from .eh_frame: follow control flow */
    /* memory the analysis may read (switch tables) */
    int (*readable)(const void *ctx, uint64_t addr, uint64_t len);
    /* extra entry points of a function (C++ landing pads) */
    int (*entries)(const void *ctx, uint64_t func, uint64_t *out, int max);
    const afw_code_range *segs; int nsegs; /* executable segments, for the audit */
} afw_patch_ctx;

/* Returns 0 on success, 1 if some sites were refused, -1 on a fatal error
 * (stub area full or out of range): the library must not be run. */
int afw_patch_code(const afw_code_range *ranges, int nranges,
                   unsigned char *stub_area, size_t stub_size,
                   const afw_patch_ctx *ctx, afw_patch_report *rep, int verbose);

#endif
