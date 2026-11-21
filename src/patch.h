/*
 * patch.h - Load-time code patching (gate G1).
 *
 * Before an Android library's code becomes executable, every instruction that
 * cannot work on Windows is rewritten once, in place:
 *   - "mov eax, NR; syscall" (7 bytes) -> "call stub_NR; nop; nop" (5 + 2),
 *     where stub_NR lives right after the library, so rel32 always reaches;
 *   - "fs:[disp32]" bionic TLS accesses -> "gs:[TEB TlsSlot]" (Windows only).
 * A site is refused (and reported loudly) when it is unsafe to rewrite:
 *   - a branch lands inside the 7 bytes (it would jump into the new call);
 *   - its straight-line code touches [rsp-N] (the System V red zone, which
 *     the stub's call would overwrite).
 */
#ifndef AFW_PATCH_H
#define AFW_PATCH_H

#include <stddef.h>
#include <stdint.h>

#define AFW_STUB_RESERVE (64 * 1024)

typedef struct {
    int fs_patched;          /* fs:[disp32] rewritten to gs: */
    int fs_register_form;    /* fs:[reg] - needs ELF TLS (gate G2) */
    int sys_patched;
    int sys_refused_branch;  /* a branch targets the middle of the site */
    int sys_refused_redzone;
    int sys_unhandled;       /* no adjacent mov eax, imm32 */
    int stubs;
} afw_patch_report;

typedef struct { unsigned char *addr; size_t size; } afw_code_range;

/* Patch all code ranges of one library. stub_area must lie within +-2GB. */
int afw_patch_code(const afw_code_range *ranges, int nranges,
                   unsigned char *stub_area, size_t stub_size,
                   afw_patch_report *rep, int verbose);

#endif
