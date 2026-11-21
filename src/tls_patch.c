/*
 * tls_patch.c - fs: -> gs: instruction rewriting (Windows only).
 *
 * Every bionic slot offset fs:[8*i] (i < 16) gets its own Windows TEB
 * TlsSlot, reserved up front so every thread has it. Each thread fills its
 * TEB slots from its own bionic TLS block in afw_tls_thread_init().
 *
 * Known limits (documented in README):
 *   - only "fs:[disp32]" absolute operands are rewritten; register-based
 *     forms such as fs:[rax] are reported, not handled yet;
 *   - a write through fs:[x] updates the TEB slot, not the block itself.
 */
#include "tls_patch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Thread_local uintptr_t *t_block;
static uintptr_t g_guard = 0x5afe5afe5afe5afeULL;

uintptr_t *afw_tls_block(void) { return t_block; }

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define TEB_TLS_SLOTS 0x1480

static DWORD g_slot[BIONIC_TLS_SLOTS];
static volatile LONG g_patches;
static int g_ready;

long afw_tls_patch_count(void) { return g_patches; }

/* Find the fs: prefix and disp32 of an "fs:[disp32]" instruction. */
static unsigned char *find_fs_disp(unsigned char *ip, unsigned char **disp, int *reg_form) {
    unsigned char *p = ip, *fs = NULL;
    *reg_form = 0;
    for (;;) {
        if (*p == 0x64) fs = p;
        else if (*p != 0x66 && *p != 0xF2 && *p != 0xF3) break;
        p++;
    }
    if (!fs) return NULL;
    if ((*p & 0xF0) == 0x40) p++;                         /* REX */
    if (*p == 0x0F) { p++; if (*p == 0x38 || *p == 0x3A) p++; }
    p++;                                                  /* opcode */
    if ((p[0] & 0xC7) != 0x04 || p[1] != 0x25) { *reg_form = 1; return fs; }
    *disp = p + 2;
    return fs;
}

static LONG CALLBACK fs_handler(EXCEPTION_POINTERS *ep) {
    unsigned char *ip, *fs, *disp = NULL;
    int32_t off, nd;
    int reg_form;
    DWORD old;

    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    ip = (unsigned char *)ep->ContextRecord->Rip;
    fs = find_fs_disp(ip, &disp, &reg_form);
    if (!fs) return EXCEPTION_CONTINUE_SEARCH;

    if (reg_form) {
        fprintf(stderr, "[tls] unsupported register-based fs: access at %p\n", (void *)ip);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    memcpy(&off, disp, 4);
    if (off < 0 || off >= 8 * BIONIC_TLS_SLOTS || (off & 7)) {
        fprintf(stderr, "[tls] unsupported fs:[0x%x] access at %p\n", off, (void *)ip);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    nd = TEB_TLS_SLOTS + 8 * (int32_t)g_slot[off / 8];

    VirtualProtect(fs, 16, PAGE_EXECUTE_READWRITE, &old);
    *fs = 0x65;                      /* fs: -> gs: */
    memcpy(disp, &nd, 4);
    VirtualProtect(fs, 16, old, &old);
    FlushInstructionCache(GetCurrentProcess(), fs, 16);
    InterlockedIncrement(&g_patches);
    return EXCEPTION_CONTINUE_EXECUTION;
}

int afw_tls_init(void) {
    int i;
    if (g_ready) return 0;
    for (i = 0; i < BIONIC_TLS_SLOTS; i++) {
        g_slot[i] = TlsAlloc();
        if (g_slot[i] == TLS_OUT_OF_INDEXES || g_slot[i] >= 64) {
            fprintf(stderr, "[tls] not enough Windows TLS slots\n");
            return -1;
        }
    }
    AddVectoredExceptionHandler(1, fs_handler);
    g_ready = 1;
    afw_tls_thread_init();
    return 0;
}

void afw_tls_thread_init(void) {
    int i;
    if (!t_block) t_block = (uintptr_t *)calloc(BIONIC_TLS_SLOTS, sizeof(uintptr_t));
    t_block[TLS_SLOT_SELF] = (uintptr_t)t_block;
    t_block[TLS_SLOT_THREAD_ID] = (uintptr_t)GetCurrentThreadId();
    t_block[TLS_SLOT_STACK_GUARD] = g_guard;
    for (i = 0; i < BIONIC_TLS_SLOTS; i++) TlsSetValue(g_slot[i], (void *)t_block[i]);
}

#else
/* Linux: fs: already works natively; nothing to patch. */
long afw_tls_patch_count(void) { return 0; }
int afw_tls_init(void) { afw_tls_thread_init(); return 0; }
void afw_tls_thread_init(void) {
    if (!t_block) t_block = (uintptr_t *)calloc(BIONIC_TLS_SLOTS, sizeof(uintptr_t));
    t_block[TLS_SLOT_SELF] = (uintptr_t)t_block;
    t_block[TLS_SLOT_STACK_GUARD] = g_guard;
}
#endif
