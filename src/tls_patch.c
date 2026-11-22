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
#include "tls_static.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Thread_local uintptr_t *t_block;   /* tp: bionic slots, module TLS below it */
static _Thread_local void *t_alloc;       /* the allocation that holds t_block */
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

int afw_tls_teb_offset(int slot) {
    if (!g_ready || slot < 0 || slot >= BIONIC_TLS_SLOTS) return -1;
    return TEB_TLS_SLOTS + 8 * (int)g_slot[slot];
}

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

static SRWLOCK g_patch_lock = SRWLOCK_INIT;

/* Rewrites one faulting fs:[disp32] read, in place, to gs:[TEB slot].
 * Order (reviewer 1, issue #2): the new disp32 first, then the prefix.
 * Every in-between state (old prefix fs:, any mix of old and new disp
 * bytes, all below 64KB) still faults, so another thread can never run
 * a half-written instruction: it faults, waits for the lock, sees gs:
 * and simply runs the finished instruction again. */
static LONG CALLBACK fs_handler(EXCEPTION_POINTERS *ep) {
    unsigned char *ip, *fs, *disp = NULL, *q;
    int32_t off, nd;
    int reg_form;
    DWORD old, tmp;
    LONG rc = EXCEPTION_CONTINUE_SEARCH;

    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    ip = (unsigned char *)ep->ContextRecord->Rip;
    AcquireSRWLockExclusive(&g_patch_lock);
    /* already rewritten by another thread while we waited: just run it again */
    for (q = ip; q < ip + 4 && (*q == 0x65 || *q == 0x66 || *q == 0xF2 || *q == 0xF3); q++)
        if (*q == 0x65) { rc = EXCEPTION_CONTINUE_EXECUTION; goto out; }
    fs = find_fs_disp(ip, &disp, &reg_form);
    if (!fs) goto out;
    if (reg_form) {
        fprintf(stderr, "[tls] unsupported register-based fs: access at %p\n", (void *)ip);
        goto out;
    }
    memcpy(&off, disp, 4);
    if (off != 0 && off != 0x28) {   /* same rule as the load gate: tp and stack guard only */
        fprintf(stderr, "[tls] unsupported fs:[0x%x] access at %p\n", off, (void *)ip);
        goto out;
    }
    nd = TEB_TLS_SLOTS + 8 * (int32_t)g_slot[off / 8];
    if (!VirtualProtect(fs, 16, PAGE_EXECUTE_READWRITE, &old)) {
        fprintf(stderr, "[tls] cannot make code writable at %p (error %lu; ACG?): the fs: access stays "
                        "unpatched and this is a crash, not a skip\n", (void *)ip, GetLastError());
        goto out;
    }
    memcpy(disp, &nd, 4);            /* 1. displacement (still fs:, still faults) */
    MemoryBarrier();
    *fs = 0x65;                      /* 2. prefix fs: -> gs: (one byte, atomic) */
    VirtualProtect(fs, 16, old, &tmp);
    FlushInstructionCache(GetCurrentProcess(), fs, 16);
    InterlockedIncrement(&g_patches);
    rc = EXCEPTION_CONTINUE_EXECUTION;
out:
    ReleaseSRWLockExclusive(&g_patch_lock);
    return rc;
}

/* Frees a thread's block when the thread exits. Never FlsFree: that would
 * run this for every live thread (reviewer 3, issue #4). Not called on
 * TerminateThread: one block leaks, accepted. */
static DWORD g_fls = FLS_OUT_OF_INDEXES;
static VOID WINAPI fls_release(PVOID p) { afw_tls_static_free(p); }

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
    g_fls = FlsAlloc(fls_release);
    if (g_fls == FLS_OUT_OF_INDEXES) { fprintf(stderr, "[tls] no FLS index\n"); return -1; }
    AddVectoredExceptionHandler(1, fs_handler);
    g_ready = 1;
    return afw_tls_thread_init();
}

static void publish(void) {
    int i;
    for (i = 0; i < BIONIC_TLS_SLOTS; i++) TlsSetValue(g_slot[i], (void *)t_block[i]);
    FlsSetValue(g_fls, t_alloc);
}

int afw_tls_thread_init(void) {
    if (!t_block) t_block = afw_tls_static_alloc(&t_alloc);
    if (!t_block) { fprintf(stderr, "[tls] cannot allocate the thread's TLS block\n"); return -1; }
    t_block[TLS_SLOT_SELF] = (uintptr_t)t_block;
    t_block[TLS_SLOT_THREAD_ID] = (uintptr_t)GetCurrentThreadId();
    t_block[TLS_SLOT_STACK_GUARD] = g_guard;
    publish();
    return 0;
}

int afw_tls_thread_rebuild(void) {
    void *old_alloc = t_alloc, *new_alloc;
    uintptr_t *old = t_block, *nb = afw_tls_static_alloc(&new_alloc);
    if (!nb) return -1;
    if (old) memcpy(nb, old, BIONIC_TLS_SLOTS * sizeof *nb);
    nb[TLS_SLOT_SELF] = (uintptr_t)nb;
    t_block = nb; t_alloc = new_alloc;
    publish();                       /* the FLS value now names the new block */
    afw_tls_static_free(old_alloc);
    return 0;
}

#else
/* Linux: fs: already works natively; nothing to patch. */
long afw_tls_patch_count(void) { return 0; }
int afw_tls_teb_offset(int slot) { (void)slot; return -1; }
#include <pthread.h>
/* Same rule as FLS on Windows: the key frees a thread's block at exit. */
static pthread_key_t g_key;
static void key_release(void *p) { afw_tls_static_free(p); }
int afw_tls_init(void) {
    if (pthread_key_create(&g_key, key_release) != 0) return -1;
    return afw_tls_thread_init();
}
int afw_tls_thread_init(void) {
    if (!t_block) t_block = afw_tls_static_alloc(&t_alloc);
    if (!t_block) return -1;
    t_block[TLS_SLOT_SELF] = (uintptr_t)t_block;
    t_block[TLS_SLOT_STACK_GUARD] = g_guard;
    pthread_setspecific(g_key, t_alloc);
    return 0;
}
int afw_tls_thread_rebuild(void) {
    void *old_alloc = t_alloc, *new_alloc;
    uintptr_t *old = t_block, *nb = afw_tls_static_alloc(&new_alloc);
    if (!nb) return -1;
    if (old) memcpy(nb, old, BIONIC_TLS_SLOTS * sizeof *nb);
    nb[TLS_SLOT_SELF] = (uintptr_t)nb;
    t_block = nb; t_alloc = new_alloc;
    pthread_setspecific(g_key, t_alloc);
    afw_tls_static_free(old_alloc);
    return 0;
}
#endif
