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
static _Thread_local unsigned char *t_area; /* bionic thread area, inside t_alloc */
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
static PVOID g_veh;
static VOID WINAPI fls_release(PVOID p) { afw_tls_static_free(p); }

/* Process-wide setup happens once; the calling thread's block is set up on
 * every call until it succeeds, so a failed first call can be retried
 * (reviewer 2, PR #6). */
int afw_tls_init(void) {
    int i;
    if (!g_ready) {
        static int nslots;                       /* slots kept from an earlier, failed call */
        for (i = nslots; i < BIONIC_TLS_SLOTS; i++) {
            DWORD idx = TlsAlloc();
            if (idx == TLS_OUT_OF_INDEXES || idx >= 64) {
                if (idx != TLS_OUT_OF_INDEXES) TlsFree(idx);
                fprintf(stderr, "[tls] not enough Windows TLS slots\n");
                return -1;
            }
            g_slot[i] = idx; nslots = i + 1;
        }
        if (g_fls == FLS_OUT_OF_INDEXES) g_fls = FlsAlloc(fls_release);
        if (g_fls == FLS_OUT_OF_INDEXES) { fprintf(stderr, "[tls] no FLS index\n"); return -1; }
        if (!g_veh) g_veh = AddVectoredExceptionHandler(1, fs_handler);
        if (!g_veh) { fprintf(stderr, "[tls] cannot install the fs: handler\n"); return -1; }
        g_ready = 1;
    }
    return afw_tls_thread_init();
}

static int g_fail_publish = -1;   /* test hook: fail at step n (0..15 a TLS slot, 16 FLS) */
void afw_tls_test_fail_publish(int step) { g_fail_publish = step; }

/* Make blk this thread's block for the CPU (TEB TlsSlots) and for the
 * release at thread exit (FLS). A transaction (reviewer 2, PR #6 A1): the
 * previous values are saved first, and if any step fails every step that
 * already happened is undone, so nothing is left naming blk. 0 or -1. */
static int publish(uintptr_t *blk, void *alloc) {
    void *prev[BIONIC_TLS_SLOTS], *prev_fls;
    int i, done = 0, fail = g_fail_publish;
    g_fail_publish = -1;
    for (i = 0; i < BIONIC_TLS_SLOTS; i++) prev[i] = TlsGetValue(g_slot[i]);
    prev_fls = FlsGetValue(g_fls);
    for (; done < BIONIC_TLS_SLOTS; done++)
        if (done == fail || !TlsSetValue(g_slot[done], (void *)blk[done])) goto undo;
    if (fail == BIONIC_TLS_SLOTS || !FlsSetValue(g_fls, alloc)) goto undo;
    return 0;
undo:
    for (i = 0; i < done; i++) TlsSetValue(g_slot[i], prev[i]);   /* setting a valid index cannot fail */
    FlsSetValue(g_fls, prev_fls);
    return -1;
}

/* What the CPU-visible copy of slot i holds right now (tests). */
uintptr_t afw_tls_published_slot(int i) { return (uintptr_t)TlsGetValue(g_slot[i]); }
static uintptr_t thread_id(void) { return (uintptr_t)GetCurrentThreadId(); }

#else
/* Linux: fs: already works natively; nothing to patch. */
long afw_tls_patch_count(void) { return 0; }
int afw_tls_teb_offset(int slot) { (void)slot; return -1; }
#include <pthread.h>
/* Same rule as FLS on Windows: the key frees a thread's block at exit. */
static pthread_key_t g_key;
static void key_release(void *p) { afw_tls_static_free(p); }
static int g_fail_publish = -1;
void afw_tls_test_fail_publish(int step) { g_fail_publish = step; }
static int publish(uintptr_t *blk, void *alloc) {   /* one step only: nothing to undo on failure */
    int fail = g_fail_publish;
    (void)blk;
    g_fail_publish = -1;
    if (fail >= 0) return -1;
    return pthread_setspecific(g_key, alloc) == 0 ? 0 : -1;
}
uintptr_t afw_tls_published_slot(int i) { return t_block ? t_block[i] : 0; }   /* fs: is native here */
#include <sys/syscall.h>
#include <unistd.h>
static uintptr_t thread_id(void) { return (uintptr_t)syscall(SYS_gettid); }
static int g_key_ready;
int afw_tls_init(void) {   /* the key once; the thread's block until it succeeds */
    if (!g_key_ready) {
        if (pthread_key_create(&g_key, key_release) != 0) return -1;
        g_key_ready = 1;
    }
    return afw_tls_thread_init();
}
#endif

/* The thread's state changes only after publishing succeeded (reviewer 2,
 * PR #6 A1): on failure the new block is freed and nothing else moves. */
/* Slots that point into the thread area: bionic dereferences them in memory
 * (__errno: [[tp] + 8] + 0x300, measured), so they hold pointers, never ids. */
static void point_into_area(uintptr_t *blk, unsigned char *area) {
    blk[TLS_SLOT_THREAD_ID] = (uintptr_t)(area + AFW_PTHREAD_INTERNAL_OFF);
    blk[TLS_SLOT_BIONIC_TLS] = (uintptr_t)(area + AFW_BIONIC_TLS_OFF);
}

int afw_tls_thread_init(void) {
    void *alloc;
    unsigned char *area;
    uintptr_t *blk;
    int32_t tid;
    if (t_block) return 0;
    blk = afw_tls_static_alloc(&alloc, &area);
    if (!blk) { fprintf(stderr, "[tls] cannot allocate the thread's TLS block\n"); return -1; }
    blk[TLS_SLOT_SELF] = (uintptr_t)blk;
    point_into_area(blk, area);
    tid = (int32_t)thread_id();
    memcpy(area + AFW_PTHREAD_INTERNAL_OFF + AFW_PTI_TID, &tid, 4);
    blk[TLS_SLOT_STACK_GUARD] = g_guard;
    if (publish(blk, alloc) != 0) {
        fprintf(stderr, "[tls] cannot publish the thread's TLS block\n");
        afw_tls_static_free(alloc);
        return -1;
    }
    t_block = blk; t_alloc = alloc; t_area = area;
    return 0;
}

/* Used once, when the layout becomes final (before any library code runs):
 * module data is taken fresh from the .tdata images, only the slots carry over. */
int afw_tls_thread_rebuild(void) {
    void *new_alloc;
    unsigned char *new_area;
    uintptr_t *nb = afw_tls_static_alloc(&new_alloc, &new_area);
    if (!nb) return -1;
    if (t_block) {
        memcpy(nb, t_block, BIONIC_TLS_SLOTS * sizeof *nb);
        memcpy(new_area, t_area, AFW_THREAD_AREA_SIZE);     /* errno, tid... carry over */
    } else {
        int32_t tid = (int32_t)thread_id();
        memcpy(new_area + AFW_PTHREAD_INTERNAL_OFF + AFW_PTI_TID, &tid, 4);
        nb[TLS_SLOT_STACK_GUARD] = g_guard;
    }
    nb[TLS_SLOT_SELF] = (uintptr_t)nb;
    point_into_area(nb, new_area);    /* never into the old allocation, which is freed below */
    if (publish(nb, new_alloc) != 0) {   /* undone completely: the old block is still the published one */
        afw_tls_static_free(new_alloc);
        fprintf(stderr, "[tls] cannot publish the rebuilt TLS block; the old one stays\n");
        return -1;
    }
    afw_tls_static_free(t_alloc);    /* only now: nothing names the old block any more */
    t_block = nb; t_alloc = new_alloc; t_area = new_area;
    return 0;
}
