/*
 * g2_stack_probe.c - Gate G2 Stage-0 (G2-1) standalone Windows x64 probe.
 *
 * Measurement-only experiment (no production SYS_clone implementation).
 * Tests Items 2, 3, 4a, 4b, 4c, and 5 from docs/design/G2-PLAN.md Section 3.1
 * on a real Windows x64 runner and prints an explicit PASS / FAIL / NOT TESTED
 * verdict for every item:
 *
 *   Item 2:  Assembly trampoline stack switch to VirtualAlloc "Bionic stack" +
 *            non-ret jmp resume (rax=0, rsp=child_stack, callee-saved preserved).
 *   Item 3:  PAGE_NOACCESS guard page at bottom of Bionic stack traps cleanly in VEH.
 *   Item 4a: VEH fs:[0] fault recovery + live fs:->gs: rewrite on Bionic stack
 *            (plus empirical measurement of KiUserExceptionDispatcher Red Zone clobber).
 *   Item 4b: Deep Win32 calls (VirtualQuery, CreateFileW/WriteFile/ReadFile/DeleteFileW,
 *            WaitOnAddress) + 16KB local frame (__chkstk) on Bionic stack under NT_TIB.
 *   Item 4c: Windows stack walk (RtlCaptureStackBackTrace) on Bionic stack;
 *            DWARF libunwind in libc++_shared.so explicitly marked NOT TESTED.
 *   Item 5:  Switch back to host_rsp + restore NT_TIB + VirtualFree(Bionic stack) +
 *            ExitThread(0x42) while a live Windows FLS callback runs on host stack.
 *
 * Build: clang-cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /Fe:out\g2_stack_probe.exe tools\g2_stack_probe.c /link synchronization.lib
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "synchronization.lib")

#define BIONIC_STACK_SIZE (1024 * 1024)
#define PAGE_SIZE_BYTES   4096
#define TEB_TLS_SLOTS     0x1480

typedef struct {
    uint64_t host_rsp;        /* 0x00 */
    uint64_t host_rbp;        /* 0x08 */
    uint64_t host_rbx;        /* 0x10 */
    uint64_t host_rsi;        /* 0x18 */
    uint64_t host_rdi;        /* 0x20 */
    uint64_t host_r12;        /* 0x28 */
    uint64_t host_r13;        /* 0x30 */
    uint64_t host_r14;        /* 0x38 */
    uint64_t host_r15;        /* 0x40 */
    uint64_t child_rsp;       /* 0x48 */
    uint64_t child_rip;       /* 0x50 */
    uint64_t want_rbx;        /* 0x58 */
    uint64_t want_rbp;        /* 0x60 */
    uint64_t want_r12;        /* 0x68 */
    uint64_t want_r13;        /* 0x70 */
    uint64_t want_r14;        /* 0x78 */
    uint64_t want_r15;        /* 0x80 */
    uint64_t got_rax;         /* 0x88 */
    uint64_t got_rsp;         /* 0x90 */
    uint64_t got_rbx;         /* 0x98 */
    uint64_t got_rbp;         /* 0xa0 */
    uint64_t got_r12;         /* 0xa8 */
    uint64_t got_r13;         /* 0xb0 */
    uint64_t got_r14;         /* 0xb8 */
    uint64_t got_r15;         /* 0xc0 */
    uint64_t got_slot0;       /* 0xc8 */
    uint64_t got_slot1;       /* 0xd0 */
    uint64_t on_bionic_fn;    /* 0xd8 */
    uint64_t exit_mode;       /* 0xe0: 0 = return to caller, 1 = teardown+ExitThread */
    uint64_t orig_tib_base;    /* 0xe8 */
    uint64_t orig_tib_limit;   /* 0xf0 */
    uint64_t orig_teb_dealloc; /* 0xf8 */
    uint64_t bionic_alloc;     /* 0x100 */
    uint64_t bionic_limit;     /* 0x108 */
    uint64_t bionic_top;       /* 0x110 */
    uint64_t test_ok;          /* 0x118 */
} trampoline_ctx;

_Static_assert(offsetof(trampoline_ctx, host_rsp)         == 0x00, "host_rsp");
_Static_assert(offsetof(trampoline_ctx, host_r15)         == 0x40, "host_r15");
_Static_assert(offsetof(trampoline_ctx, child_rsp)        == 0x48, "child_rsp");
_Static_assert(offsetof(trampoline_ctx, child_rip)        == 0x50, "child_rip");
_Static_assert(offsetof(trampoline_ctx, want_rbx)         == 0x58, "want_rbx");
_Static_assert(offsetof(trampoline_ctx, got_rax)          == 0x88, "got_rax");
_Static_assert(offsetof(trampoline_ctx, got_slot0)        == 0xc8, "got_slot0");
_Static_assert(offsetof(trampoline_ctx, on_bionic_fn)     == 0xd8, "on_bionic_fn");
_Static_assert(offsetof(trampoline_ctx, exit_mode)        == 0xe0, "exit_mode");
_Static_assert(offsetof(trampoline_ctx, orig_tib_base)    == 0xe8, "orig_tib_base");
_Static_assert(offsetof(trampoline_ctx, orig_tib_limit)   == 0xf0, "orig_tib_limit");
_Static_assert(offsetof(trampoline_ctx, orig_teb_dealloc) == 0xf8, "orig_teb_dealloc");

void probe_enter_bionic(trampoline_ctx *ctx);
void probe_child_stub(void);
void probe_host_teardown(trampoline_ctx *ctx);
uint64_t probe_guard_read(const volatile uint64_t *addr);
extern char probe_guard_recover[];
uint64_t probe_fs_and_redzone(void *fs_code, uint32_t *rz_bytes_out, uint32_t *max_depth_out);

/* Top-level AT&T asm (clang-cl defaults to Intel syntax; restore afterwards). */
__asm__(
    ".att_syntax prefix\n"
    ".text\n"

    /* void probe_enter_bionic(trampoline_ctx *ctx)  [rcx = ctx] */
    ".globl probe_enter_bionic\n"
    "probe_enter_bionic:\n\t"
    "mov %rsp, 0x00(%rcx)\n\t"
    "mov %rbp, 0x08(%rcx)\n\t"
    "mov %rbx, 0x10(%rcx)\n\t"
    "mov %rsi, 0x18(%rcx)\n\t"
    "mov %rdi, 0x20(%rcx)\n\t"
    "mov %r12, 0x28(%rcx)\n\t"
    "mov %r13, 0x30(%rcx)\n\t"
    "mov %r14, 0x38(%rcx)\n\t"
    "mov %r15, 0x40(%rcx)\n\t"
    /* Keep ctx in r10, target rip in r11; load simulated parent callee-saved regs */
    "mov %rcx, %r10\n\t"
    "mov 0x50(%r10), %r11\n\t"
    "mov 0x58(%r10), %rbx\n\t"
    "mov 0x60(%r10), %rbp\n\t"
    "mov 0x68(%r10), %r12\n\t"
    "mov 0x70(%r10), %r13\n\t"
    "mov 0x78(%r10), %r14\n\t"
    "mov 0x80(%r10), %r15\n\t"
    /* Switch to Bionic child_stack, set rax=0, and jmp (never ret!) */
    "mov 0x48(%r10), %rsp\n\t"
    "xor %eax, %eax\n\t"
    "jmp *%r11\n"

    /* Simulated __bionic_clone post-syscall child entry (reached via jmp) */
    ".globl probe_child_stub\n"
    "probe_child_stub:\n\t"
    "mov %rax, 0x88(%r10)\n\t"
    "mov %rsp, 0x90(%r10)\n\t"
    "mov %rbx, 0x98(%r10)\n\t"
    "mov %rbp, 0xa0(%r10)\n\t"
    "mov %r12, 0xa8(%r10)\n\t"
    "mov %r13, 0xb0(%r10)\n\t"
    "mov %r14, 0xb8(%r10)\n\t"
    "mov %r15, 0xc0(%r10)\n\t"
    "mov 0x00(%rsp), %rax\n\t"
    "mov %rax, 0xc8(%r10)\n\t"
    "mov 0x08(%rsp), %rax\n\t"
    "mov %rax, 0xd0(%r10)\n\t"
    /* Save ctx in rbx (callee-saved), call ctx->on_bionic_fn(ctx) on Bionic stack */
    "mov %r10, %rbx\n\t"
    "mov 0xd8(%rbx), %rax\n\t"
    "test %rax, %rax\n\t"
    "jz 1f\n\t"
    "sub $32, %rsp\n\t"          /* child_rsp is 16-byte aligned; call pushes 8 -> %16==8 */
    "mov %rbx, %rcx\n\t"
    "call *%rax\n\t"
    "add $32, %rsp\n"
    "1:\n\t"
    /* Switch back to host_rsp and restore original NT_TIB + DeallocationStack BEFORE freeing/exiting */
    "mov 0x00(%rbx), %rsp\n\t"
    "mov 0xe8(%rbx), %rax\n\t"
    "mov %rax, %gs:0x08\n\t"
    "mov 0xf0(%rbx), %rax\n\t"
    "mov %rax, %gs:0x10\n\t"
    "mov 0xf8(%rbx), %rax\n\t"
    "mov %rax, %gs:0x1478\n\t"
    /* Check exit_mode: 0 = return cleanly, 1 = VirtualFree + ExitThread on host stack */
    "cmpq $0, 0xe0(%rbx)\n\t"
    "jne 2f\n\t"
    "mov 0x08(%rbx), %rbp\n\t"
    "mov 0x18(%rbx), %rsi\n\t"
    "mov 0x20(%rbx), %rdi\n\t"
    "mov 0x28(%rbx), %r12\n\t"
    "mov 0x30(%rbx), %r13\n\t"
    "mov 0x38(%rbx), %r14\n\t"
    "mov 0x40(%rbx), %r15\n\t"
    "mov 0x10(%rbx), %rbx\n\t"
    "ret\n"
    "2:\n\t"
    /* host_rsp has %16 == 8 (entry to probe_enter_bionic). sub $40 -> %16 == 0 + 32B shadow */
    "sub $40, %rsp\n\t"
    "mov %rbx, %rcx\n\t"
    "call probe_host_teardown\n\t"
    "ud2\n"

    /* uint64_t probe_guard_read(const volatile uint64_t *addr) [rcx = addr] */
    ".globl probe_guard_read\n"
    ".globl probe_guard_recover\n"
    "probe_guard_read:\n\t"
    "mov (%rcx), %rax\n\t"       /* expected to fault with AV on PAGE_NOACCESS */
    "ret\n"
    "probe_guard_recover:\n\t"
    "mov $0x5AFE0001, %eax\n\t"
    "ret\n"

    /* uint64_t probe_fs_and_redzone(void *fs_code, uint32_t *rz_bytes_out, uint32_t *max_depth_out)
     * rcx = fs_code, rdx = rz_bytes_out, r8 = max_depth_out.
     * Fills [rsp-2048 .. rsp-16] with 0xAA, calls fs_code (which faults on fs:[0],
     * triggers KiUserExceptionDispatcher -> VEH -> EXCEPTION_CONTINUE_EXECUTION),
     * then scans [rsp-2048 .. rsp-9] to measure exact Red Zone + below-RSP clobber. */
    ".globl probe_fs_and_redzone\n"
    "probe_fs_and_redzone:\n\t"
    "push %rbx\n\t"
    "push %rsi\n\t"
    "push %rdi\n\t"
    "mov %rdx, %rsi\n\t"         /* rsi = rz_bytes_out */
    "mov %r8, %rdi\n\t"          /* rdi = max_depth_out */
    /* Fill [rsp - 2048 .. rsp - 16] with 0xAA (staying clear of [rsp-8] for call ret addr) */
    "lea -2048(%rsp), %r9\n\t"
    "lea -16(%rsp), %r10\n"
    "3:\n\t"
    "movb $0xAA, (%r9)\n\t"
    "inc %r9\n\t"
    "cmp %r10, %r9\n\t"
    "jb 3b\n\t"
    /* Call fs_code: callee sees rsp_callee = rsp - 8; Red Zone is [rsp-136 .. rsp-9] */
    "call *%rcx\n\t"
    "mov %rax, %rbx\n\t"         /* save TLS value returned by fs_code */
    /* Count overwritten bytes in [rsp-136 .. rsp-16] (120 bytes of the 128-byte Red Zone) */
    "xor %r11d, %r11d\n\t"       /* rz clobber count */
    "lea -136(%rsp), %r9\n\t"
    "lea -16(%rsp), %r10\n"
    "4:\n\t"
    "cmpb $0xAA, (%r9)\n\t"
    "je 5f\n\t"
    "inc %r11d\n"
    "5:\n\t"
    "inc %r9\n\t"
    "cmp %r10, %r9\n\t"
    "jb 4b\n\t"
    "mov %r11d, (%rsi)\n\t"
    /* Find deepest offset below rsp_callee (up to 2040 bytes) that was overwritten */
    "xor %r11d, %r11d\n\t"       /* max depth */
    "lea -2048(%rsp), %r9\n\t"
    "lea -16(%rsp), %r10\n"
    "6:\n\t"
    "cmpb $0xAA, (%r9)\n\t"
    "je 7f\n\t"
    "mov %rsp, %rax\n\t"
    "sub $8, %rax\n\t"           /* rax = rsp_callee */
    "sub %r9, %rax\n\t"          /* depth = rsp_callee - ptr */
    "mov %eax, %r11d\n\t"
    "jmp 8f\n"
    "7:\n\t"
    "inc %r9\n\t"
    "cmp %r10, %r9\n\t"
    "jb 6b\n"
    "8:\n\t"
    "mov %r11d, (%rdi)\n\t"
    "mov %rbx, %rax\n\t"
    "pop %rdi\n\t"
    "pop %rsi\n\t"
    "pop %rbx\n\t"
    "ret\n"

    ".intel_syntax noprefix\n"
);

static uint64_t get_tib_base(void) {
    uint64_t v;
    __asm__ volatile("movq %%gs:0x08, %0" : "=r"(v));
    return v;
}
static uint64_t get_tib_limit(void) {
    uint64_t v;
    __asm__ volatile("movq %%gs:0x10, %0" : "=r"(v));
    return v;
}
static uint64_t get_teb_dealloc(void) {
    uint64_t v;
    __asm__ volatile("movq %%gs:0x1478, %0" : "=r"(v));
    return v;
}
static void set_tib_bounds(uint64_t base, uint64_t limit, uint64_t dealloc) {
    __asm__ volatile("movq %0, %%gs:0x08" : : "r"(base) : "memory");
    __asm__ volatile("movq %0, %%gs:0x10" : : "r"(limit) : "memory");
    __asm__ volatile("movq %0, %%gs:0x1478" : : "r"(dealloc) : "memory");
}

static uint8_t *alloc_bionic_stack(uint64_t *limit_out, uint64_t *top_out) {
    DWORD old = 0;
    uint8_t *mem = (uint8_t *)VirtualAlloc(NULL, BIONIC_STACK_SIZE,
                                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mem) return NULL;
    if (!VirtualProtect(mem, PAGE_SIZE_BYTES, PAGE_NOACCESS, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return NULL;
    }
    *limit_out = (uint64_t)(uintptr_t)(mem + PAGE_SIZE_BYTES);
    *top_out   = (uint64_t)(uintptr_t)(mem + BIONIC_STACK_SIZE);
    return mem;
}

/* ---- Global VEH state for Item 3 (guard page) and Item 4a (fs:[0]) ---- */
static volatile uint64_t g_guard_base;
static volatile LONG     g_guard_caught;
static volatile uint64_t g_guard_fault_addr;
static volatile uint64_t g_guard_rsp;

static unsigned char    *g_fs_code;
static DWORD             g_fs_tls_slot = TLS_OUT_OF_INDEXES;
static volatile LONG     g_fs_caught;
static volatile uint64_t g_fs_fault_rsp;

static LONG CALLBACK g2_veh_handler(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    /* Item 3: deliberate probe into PAGE_NOACCESS guard page */
    if (g_guard_base && ep->ExceptionRecord->NumberParameters >= 2) {
        uint64_t faddr = (uint64_t)ep->ExceptionRecord->ExceptionInformation[1];
        if (faddr >= g_guard_base && faddr < g_guard_base + PAGE_SIZE_BYTES) {
            g_guard_fault_addr = faddr;
            g_guard_rsp = (uint64_t)ep->ContextRecord->Rsp;
            InterlockedIncrement(&g_guard_caught);
            ep->ContextRecord->Rip = (DWORD64)(uintptr_t)probe_guard_recover;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    /* Item 4a: mov rax, fs:[0] at g_fs_code -> live patch to gs:[0x1480 + 8*slot] */
    if (g_fs_code && ep->ContextRecord->Rip == (DWORD64)(uintptr_t)g_fs_code &&
        g_fs_tls_slot != TLS_OUT_OF_INDEXES && g_fs_tls_slot < 64) {
        int32_t new_disp = TEB_TLS_SLOTS + 8 * (int32_t)g_fs_tls_slot;
        DWORD old = 0;
        g_fs_fault_rsp = (uint64_t)ep->ContextRecord->Rsp;
        VirtualProtect(g_fs_code, 16, PAGE_EXECUTE_READWRITE, &old);
        g_fs_code[0] = 0x65; /* fs: -> gs: */
        memcpy(g_fs_code + 5, &new_disp, 4);
        VirtualProtect(g_fs_code, 16, old, &old);
        FlushInstructionCache(GetCurrentProcess(), g_fs_code, 16);
        InterlockedIncrement(&g_fs_caught);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- Item 2: Trampoline + non-ret jmp child resume ---- */
static void item2_on_bionic(trampoline_ctx *ctx) {
    volatile uint64_t local_var = 0;
    uint64_t sp = (uint64_t)(uintptr_t)&local_var;
    int on_bionic = (sp >= ctx->bionic_limit && sp < ctx->bionic_top);
    int tib_set = (get_tib_base() == ctx->bionic_top &&
                   get_tib_limit() == ctx->bionic_limit &&
                   get_teb_dealloc() == ctx->bionic_alloc);
    int regs_ok =
        ctx->got_rax == 0 &&
        ctx->got_rsp == ctx->child_rsp &&
        ctx->got_rbx == ctx->want_rbx &&
        ctx->got_rbp == ctx->want_rbp &&
        ctx->got_r12 == ctx->want_r12 &&
        ctx->got_r13 == ctx->want_r13 &&
        ctx->got_r14 == ctx->want_r14 &&
        ctx->got_r15 == ctx->want_r15 &&
        ctx->got_slot0 == 0x1111222233334444ULL &&
        ctx->got_slot1 == 0x5555666677778888ULL;
    ctx->test_ok = (on_bionic && tib_set && regs_ok) ? 1 : 0;
}

static DWORD WINAPI item2_thread(LPVOID param) {
    int *res = (int *)param;
    uint64_t lim = 0, top = 0;
    uint8_t *mem = alloc_bionic_stack(&lim, &top);
    trampoline_ctx ctx;
    uint64_t *csp;
    if (!mem) { *res = 0; return 1; }

    memset(&ctx, 0, sizeof ctx);
    ctx.orig_tib_base    = get_tib_base();
    ctx.orig_tib_limit   = get_tib_limit();
    ctx.orig_teb_dealloc = get_teb_dealloc();
    ctx.bionic_alloc     = (uint64_t)(uintptr_t)mem;
    ctx.bionic_limit     = lim;
    ctx.bionic_top       = top;
    ctx.child_rsp        = (top - 64) & ~15ULL;
    ctx.child_rip        = (uint64_t)(uintptr_t)probe_child_stub;
    ctx.want_rbx         = 0xAA01AA01AA01AA01ULL;
    ctx.want_rbp         = 0xBB02BB02BB02BB02ULL;
    ctx.want_r12         = 0xCC03CC03CC03CC03ULL;
    ctx.want_r13         = 0xDD04DD04DD04DD04ULL;
    ctx.want_r14         = 0xEE05EE05EE05EE05ULL;
    ctx.want_r15         = 0xFF06FF06FF06FF06ULL;
    ctx.on_bionic_fn     = (uint64_t)(uintptr_t)item2_on_bionic;
    ctx.exit_mode        = 0;

    csp = (uint64_t *)(uintptr_t)ctx.child_rsp;
    csp[0] = 0x1111222233334444ULL; /* simulated bionic fn */
    csp[1] = 0x5555666677778888ULL; /* simulated bionic arg */

    printf("[Item 2] orig NT_TIB: base=0x%llx limit=0x%llx dealloc=0x%llx; bionic=[0x%llx..0x%llx)\n",
           (unsigned long long)ctx.orig_tib_base, (unsigned long long)ctx.orig_tib_limit,
           (unsigned long long)ctx.orig_teb_dealloc,
           (unsigned long long)lim, (unsigned long long)top);

    set_tib_bounds(top, lim, ctx.bionic_alloc);
    probe_enter_bionic(&ctx);

    {
        int tib_restored = (get_tib_base() == ctx.orig_tib_base &&
                            get_tib_limit() == ctx.orig_tib_limit &&
                            get_teb_dealloc() == ctx.orig_teb_dealloc);
        printf("[Item 2] got_rax=0x%llx got_rsp=0x%llx (want=0x%llx) slot0=0x%llx slot1=0x%llx tib_and_dealloc_restored=%d\n",
               (unsigned long long)ctx.got_rax, (unsigned long long)ctx.got_rsp,
               (unsigned long long)ctx.child_rsp, (unsigned long long)ctx.got_slot0,
               (unsigned long long)ctx.got_slot1, tib_restored);
        *res = (ctx.test_ok && tib_restored) ? 1 : 0;
    }
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

/* ---- Item 3: PAGE_NOACCESS guard page trap via VEH ---- */
static void item3_on_bionic(trampoline_ctx *ctx) {
    const volatile uint64_t *guard_ptr = (const volatile uint64_t *)(uintptr_t)(ctx->bionic_alloc + 0x800);
    uint64_t r;
    g_guard_caught = 0;
    g_guard_fault_addr = 0;
    g_guard_rsp = 0;
    g_guard_base = ctx->bionic_alloc;
    r = probe_guard_read(guard_ptr);
    g_guard_base = 0;
    ctx->test_ok = (r == 0x5AFE0001ULL && g_guard_caught == 1 &&
                    g_guard_fault_addr == ctx->bionic_alloc + 0x800 &&
                    g_guard_rsp >= ctx->bionic_limit && g_guard_rsp < ctx->bionic_top) ? 1 : 0;
}

static DWORD WINAPI item3_thread(LPVOID param) {
    int *res = (int *)param;
    uint64_t lim = 0, top = 0;
    uint8_t *mem = alloc_bionic_stack(&lim, &top);
    trampoline_ctx ctx;
    if (!mem) { *res = 0; return 1; }

    memset(&ctx, 0, sizeof ctx);
    ctx.orig_tib_base    = get_tib_base();
    ctx.orig_tib_limit   = get_tib_limit();
    ctx.orig_teb_dealloc = get_teb_dealloc();
    ctx.bionic_alloc     = (uint64_t)(uintptr_t)mem;
    ctx.bionic_limit     = lim;
    ctx.bionic_top       = top;
    ctx.child_rsp        = (top - 64) & ~15ULL;
    ctx.child_rip        = (uint64_t)(uintptr_t)probe_child_stub;
    ctx.on_bionic_fn     = (uint64_t)(uintptr_t)item3_on_bionic;

    set_tib_bounds(top, lim, ctx.bionic_alloc);
    probe_enter_bionic(&ctx);

    printf("[Item 3a] guard_caught=%ld fault_addr=0x%llx (guard_base=0x%llx) fault_rsp=0x%llx\n",
           (long)g_guard_caught, (unsigned long long)g_guard_fault_addr,
           (unsigned long long)ctx.bionic_alloc, (unsigned long long)g_guard_rsp);
    *res = (int)ctx.test_ok;
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

/* ---- Item 4a: VEH fs:[0] fault recovery + Red Zone clobber measurement ---- */
static uint32_t g_rz_clobbered;
static uint32_t g_rz_max_depth;
static uint64_t g_fs_val_read;

static void item4a_on_bionic(trampoline_ctx *ctx) {
    uint64_t want = 0xDEADBEEFCAFE1234ULL;
    TlsSetValue(g_fs_tls_slot, (LPVOID)(uintptr_t)want);
    g_fs_caught = 0;
    g_fs_fault_rsp = 0;
    g_rz_clobbered = 0;
    g_rz_max_depth = 0;
    g_fs_val_read = probe_fs_and_redzone(g_fs_code, &g_rz_clobbered, &g_rz_max_depth);
    ctx->test_ok = (g_fs_caught == 1 && g_fs_val_read == want &&
                    g_fs_code[0] == 0x65 &&
                    g_fs_fault_rsp >= ctx->bionic_limit &&
                    g_fs_fault_rsp < ctx->bionic_top) ? 1 : 0;
}

static DWORD WINAPI item4a_thread(LPVOID param) {
    static const unsigned char code_fs0[] = {
        0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, /* mov rax, fs:[0] */
        0xC3                                                  /* ret */
    };
    int *res = (int *)param;
    uint64_t lim = 0, top = 0;
    uint8_t *mem = alloc_bionic_stack(&lim, &top);
    trampoline_ctx ctx;
    if (!mem) { *res = 0; return 1; }

    g_fs_tls_slot = TlsAlloc();
    g_fs_code = (unsigned char *)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (g_fs_tls_slot == TLS_OUT_OF_INDEXES || g_fs_tls_slot >= 64 || !g_fs_code) {
        if (g_fs_code) VirtualFree(g_fs_code, 0, MEM_RELEASE);
        if (g_fs_tls_slot != TLS_OUT_OF_INDEXES) TlsFree(g_fs_tls_slot);
        VirtualFree(mem, 0, MEM_RELEASE);
        *res = 0;
        return 1;
    }
    memcpy(g_fs_code, code_fs0, sizeof code_fs0);

    memset(&ctx, 0, sizeof ctx);
    ctx.orig_tib_base    = get_tib_base();
    ctx.orig_tib_limit   = get_tib_limit();
    ctx.orig_teb_dealloc = get_teb_dealloc();
    ctx.bionic_alloc     = (uint64_t)(uintptr_t)mem;
    ctx.bionic_limit     = lim;
    ctx.bionic_top       = top;
    ctx.child_rsp        = (top - 4096) & ~15ULL; /* plenty of room below rsp for Red Zone measurement */
    ctx.child_rip        = (uint64_t)(uintptr_t)probe_child_stub;
    ctx.on_bionic_fn     = (uint64_t)(uintptr_t)item4a_on_bionic;

    set_tib_bounds(top, lim, ctx.bionic_alloc);
    probe_enter_bionic(&ctx);

    printf("[Item 4a] fs_caught=%ld patched_prefix=0x%02x val=0x%llx fault_rsp=0x%llx\n",
           (long)g_fs_caught, g_fs_code[0], (unsigned long long)g_fs_val_read,
           (unsigned long long)g_fs_fault_rsp);
    printf("[Item 4a] KiUserExceptionDispatcher below-RSP measurement: %u/120 bytes in [rsp-136..rsp-16] clobbered, deepest clobber=%u bytes below RSP\n",
           g_rz_clobbered, g_rz_max_depth);

    *res = (int)ctx.test_ok;
    VirtualFree(g_fs_code, 0, MEM_RELEASE);
    g_fs_code = NULL;
    TlsFree(g_fs_tls_slot);
    g_fs_tls_slot = TLS_OUT_OF_INDEXES;
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

/* ---- Item 4b: Deep Win32 API calls + 16KB __chkstk frame on Bionic stack ---- */
__declspec(noinline) static int item4b_big_frame_and_win32(uint64_t bionic_limit, uint64_t bionic_top) {
    volatile unsigned char big_buf[16384];
    MEMORY_BASIC_INFORMATION mbi;
    WCHAR tmp_dir[MAX_PATH], tmp_file[MAX_PATH];
    HANDLE hf;
    const char payload[] = "G2-1 Win32 file I/O from VirtualAlloc Bionic stack";
    char rbuf[128];
    DWORD nw = 0, nr = 0;
    LARGE_INTEGER zero = {0};
    volatile LONG futex_word = 7;
    LONG expect = 7;
    size_t i;
    int sum_ok = 1;

    /* Touch every page of the 16KB stack frame (forces __chkstk) */
    for (i = 0; i < sizeof big_buf; i += 256) big_buf[i] = (unsigned char)(i >> 8);
    for (i = 0; i < sizeof big_buf; i += 256)
        if (big_buf[i] != (unsigned char)(i >> 8)) sum_ok = 0;

    if ((uint64_t)(uintptr_t)&big_buf[0] < bionic_limit ||
        (uint64_t)(uintptr_t)&big_buf[sizeof big_buf - 1] >= bionic_top)
        return 0;

    /* 1. VirtualQuery on the Bionic stack */
    memset(&mbi, 0, sizeof mbi);
    if (VirtualQuery((LPCVOID)&big_buf[0], &mbi, sizeof mbi) == 0 || mbi.State != MEM_COMMIT)
        return 0;

    /* 2. Full CreateFileW / WriteFile / ReadFile / CloseHandle / DeleteFileW round-trip */
    if (!GetTempPathW(MAX_PATH, tmp_dir)) return 0;
    if (!GetTempFileNameW(tmp_dir, L"afw", 0, tmp_file)) return 0;
    hf = CreateFileW(tmp_file, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hf == INVALID_HANDLE_VALUE) { DeleteFileW(tmp_file); return 0; }
    if (!WriteFile(hf, payload, (DWORD)(sizeof payload - 1), &nw, NULL) || nw != sizeof payload - 1) {
        CloseHandle(hf); DeleteFileW(tmp_file); return 0;
    }
    FlushFileBuffers(hf);
    SetFilePointerEx(hf, zero, NULL, FILE_BEGIN);
    memset(rbuf, 0, sizeof rbuf);
    if (!ReadFile(hf, rbuf, sizeof rbuf - 1, &nr, NULL) || nr != sizeof payload - 1 ||
        memcmp(rbuf, payload, sizeof payload - 1) != 0) {
        CloseHandle(hf); DeleteFileW(tmp_file); return 0;
    }
    CloseHandle(hf);
    DeleteFileW(tmp_file);

    /* 3. WaitOnAddress (1ms timeout -> ERROR_TIMEOUT) from Bionic stack */
    if (WaitOnAddress(&futex_word, &expect, sizeof expect, 1) || GetLastError() != ERROR_TIMEOUT)
        return 0;

    return sum_ok;
}

static void item4b_on_bionic(trampoline_ctx *ctx) {
    ctx->test_ok = item4b_big_frame_and_win32(ctx->bionic_limit, ctx->bionic_top) ? 1 : 0;
}

static DWORD WINAPI item4b_thread(LPVOID param) {
    int *res = (int *)param;
    uint64_t lim = 0, top = 0;
    uint8_t *mem = alloc_bionic_stack(&lim, &top);
    trampoline_ctx ctx;
    if (!mem) { *res = 0; return 1; }

    memset(&ctx, 0, sizeof ctx);
    ctx.orig_tib_base    = get_tib_base();
    ctx.orig_tib_limit   = get_tib_limit();
    ctx.orig_teb_dealloc = get_teb_dealloc();
    ctx.bionic_alloc     = (uint64_t)(uintptr_t)mem;
    ctx.bionic_limit     = lim;
    ctx.bionic_top       = top;
    ctx.child_rsp        = (top - 64) & ~15ULL;
    ctx.child_rip        = (uint64_t)(uintptr_t)probe_child_stub;
    ctx.on_bionic_fn     = (uint64_t)(uintptr_t)item4b_on_bionic;

    set_tib_bounds(top, lim, ctx.bionic_alloc);
    probe_enter_bionic(&ctx);
    *res = (int)ctx.test_ok;
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

/* ---- Item 4c: Windows stack walk (RtlCaptureStackBackTrace) on Bionic stack ---- */
static USHORT g_bt_frames;
__declspec(noinline) static int item4c_lvl3(void) {
    void *frames[16];
    g_bt_frames = RtlCaptureStackBackTrace(0, 16, frames, NULL);
    printf("[Item 4c-win] RtlCaptureStackBackTrace captured %u frames (frame[0]=%p frame[1]=%p frame[2]=%p)\n",
           (unsigned)g_bt_frames,
           g_bt_frames > 0 ? frames[0] : NULL,
           g_bt_frames > 1 ? frames[1] : NULL,
           g_bt_frames > 2 ? frames[2] : NULL);
    return g_bt_frames >= 3;
}
__declspec(noinline) static int item4c_lvl2(volatile int x) { return item4c_lvl3() + (x & 0); }
__declspec(noinline) static int item4c_lvl1(volatile int x) { return item4c_lvl2(x + 1); }

static void item4c_on_bionic(trampoline_ctx *ctx) {
    ctx->test_ok = item4c_lvl1(1) ? 1 : 0;
}

static DWORD WINAPI item4c_thread(LPVOID param) {
    int *res = (int *)param;
    uint64_t lim = 0, top = 0;
    uint8_t *mem = alloc_bionic_stack(&lim, &top);
    trampoline_ctx ctx;
    if (!mem) { *res = 0; return 1; }

    memset(&ctx, 0, sizeof ctx);
    ctx.orig_tib_base    = get_tib_base();
    ctx.orig_tib_limit   = get_tib_limit();
    ctx.orig_teb_dealloc = get_teb_dealloc();
    ctx.bionic_alloc     = (uint64_t)(uintptr_t)mem;
    ctx.bionic_limit     = lim;
    ctx.bionic_top       = top;
    ctx.child_rsp        = (top - 64) & ~15ULL;
    ctx.child_rip        = (uint64_t)(uintptr_t)probe_child_stub;
    ctx.on_bionic_fn     = (uint64_t)(uintptr_t)item4c_on_bionic;

    set_tib_bounds(top, lim, ctx.bionic_alloc);
    probe_enter_bionic(&ctx);
    *res = (int)ctx.test_ok;
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

/* ---- Item 5: Restore host_rsp + NT_TIB + DeallocationStack + VirtualFree + ExitThread (FLS + DLL_THREAD_DETACH) ---- */
typedef void (*detach_arm_fn)(DWORD);
typedef LONG (*detach_res_fn)(uint64_t *);
static detach_arm_fn     g_detach_arm;
static detach_res_fn     g_detach_result;

static DWORD             g_fls_idx = FLS_OUT_OF_INDEXES;
static volatile LONG     g_fls_called;
static volatile uint64_t g_fls_val_seen;
static volatile uint64_t g_fls_rsp_seen;
static volatile uint64_t g_item5_orig_limit;
static volatile uint64_t g_item5_orig_base;
static volatile LONG     g_item5_vfree_ok;
static volatile LONG     g_item5_tib_restored;

static VOID WINAPI item5_fls_callback(PVOID val) {
    volatile uint64_t local_var = 0;
    g_fls_val_seen = (uint64_t)(uintptr_t)val;
    g_fls_rsp_seen = (uint64_t)(uintptr_t)&local_var;
    InterlockedIncrement(&g_fls_called);
}

void probe_host_teardown(trampoline_ctx *ctx) {
    /* Running on restored host_rsp with restored original NT_TIB + DeallocationStack! */
    int restored = (get_tib_base() == ctx->orig_tib_base &&
                    get_tib_limit() == ctx->orig_tib_limit &&
                    get_teb_dealloc() == ctx->orig_teb_dealloc);
    BOOL freed = VirtualFree((void *)(uintptr_t)ctx->bionic_alloc, 0, MEM_RELEASE);
    InterlockedExchange(&g_item5_tib_restored, restored ? 1 : 0);
    InterlockedExchange(&g_item5_vfree_ok, freed ? 1 : 0);
    ExitThread(0x42);
}

static void item5_on_bionic(trampoline_ctx *ctx) {
    volatile uint64_t local_var = 0;
    uint64_t sp = (uint64_t)(uintptr_t)&local_var;
    int tib_set = (get_tib_base() == ctx->bionic_top &&
                   get_tib_limit() == ctx->bionic_limit &&
                   get_teb_dealloc() == ctx->bionic_alloc);
    ctx->test_ok = (sp >= ctx->bionic_limit && sp < ctx->bionic_top && tib_set) ? 1 : 0;
}

static DWORD WINAPI item5_thread(LPVOID param) {
    trampoline_ctx *ctx = (trampoline_ctx *)param;
    uint64_t lim = 0, top = 0;
    uint8_t *mem = alloc_bionic_stack(&lim, &top);
    if (!mem) return 1;

    memset(ctx, 0, sizeof *ctx);
    ctx->orig_tib_base    = get_tib_base();
    ctx->orig_tib_limit   = get_tib_limit();
    ctx->orig_teb_dealloc = get_teb_dealloc();
    g_item5_orig_base     = ctx->orig_tib_base;
    g_item5_orig_limit    = ctx->orig_tib_limit;
    ctx->bionic_alloc     = (uint64_t)(uintptr_t)mem;
    ctx->bionic_limit     = lim;
    ctx->bionic_top       = top;
    ctx->child_rsp        = (top - 64) & ~15ULL;
    ctx->child_rip        = (uint64_t)(uintptr_t)probe_child_stub;
    ctx->on_bionic_fn     = (uint64_t)(uintptr_t)item5_on_bionic;
    ctx->exit_mode        = 1;

    if (g_detach_arm) g_detach_arm(GetCurrentThreadId());
    FlsSetValue(g_fls_idx, (PVOID)(uintptr_t)0xF15C0DEULL);
    set_tib_bounds(top, lim, ctx->bionic_alloc);
    probe_enter_bionic(ctx);
    return 99; /* unreachable */
}

static int run_thread_test(LPTHREAD_START_ROUTINE fn, void *arg, DWORD *exit_code_out) {
    HANDLE h = CreateThread(NULL, 0, fn, arg, 0, NULL);
    DWORD wr, ec = 0;
    if (!h) return 0;
    wr = WaitForSingleObject(h, 10000);
    GetExitCodeThread(h, &ec);
    CloseHandle(h);
    if (exit_code_out) *exit_code_out = ec;
    return wr == WAIT_OBJECT_0;
}

int main(void) {
    PVOID veh;
    HMODULE hdll;
    int r2 = 0, r3 = 0, r4a = 0, r4b = 0, r4c = 0, r5 = 0;
    int fails = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== Gate G2 Stage-0 (G2-1) Windows Stack / NT_TIB / VEH / ExitThread Probe ===\n");
    veh = AddVectoredExceptionHandler(1, g2_veh_handler);
    if (!veh) {
        printf("ERROR: AddVectoredExceptionHandler failed\n");
        return 1;
    }

    hdll = LoadLibraryA("out\\g2_detach_probe.dll");
    if (!hdll) hdll = LoadLibraryA("g2_detach_probe.dll");
    if (hdll) {
        g_detach_arm    = (detach_arm_fn)GetProcAddress(hdll, "g2_detach_arm");
        g_detach_result = (detach_res_fn)GetProcAddress(hdll, "g2_detach_result");
    }

    /* Item 2 */
    if (!run_thread_test(item2_thread, &r2, NULL)) r2 = 0;
    printf("VERDICT Item 2 (Trampoline stack switch + non-ret jmp resume + NT_TIB/DeallocationStack restore): %s\n",
           r2 ? "PASS" : "FAIL");
    fails += !r2;

    /* Item 3 */
    if (!run_thread_test(item3_thread, &r3, NULL)) r3 = 0;
    printf("VERDICT Item 3a (Explicit data read into PAGE_NOACCESS guard page with ~1MB RSP headroom): %s\n",
           r3 ? "PASS" : "FAIL");
    printf("VERDICT Item 3b (True RSP stack-overflow into PAGE_NOACCESS with <2KB headroom): NOT TESTED (KiUserExceptionDispatcher writes ~2KB below RSP)\n");
    fails += !r3;

    /* Item 4a */
    if (!run_thread_test(item4a_thread, &r4a, NULL)) r4a = 0;
    printf("VERDICT Item 4a (VEH fs:[0] fault recovery on Bionic stack): %s\n", r4a ? "PASS" : "FAIL");
    fails += !r4a;

    /* Item 4b */
    if (!run_thread_test(item4b_thread, &r4b, NULL)) r4b = 0;
    printf("VERDICT Item 4b (Deep Win32 + 16KB __chkstk frame on Bionic stack): %s\n", r4b ? "PASS" : "FAIL");
    fails += !r4b;

    /* Item 4c */
    if (!run_thread_test(item4c_thread, &r4c, NULL)) r4c = 0;
    printf("VERDICT Item 4c-win (RtlCaptureStackBackTrace on Bionic stack): %s\n", r4c ? "PASS" : "FAIL");
    printf("VERDICT Item 4c-dwarf (DWARF libunwind / C++ throw on Bionic stack): NOT TESTED (gated on PR #7 / G2-5a)\n");
    fails += !r4c;

    /* Item 5 */
    g_fls_idx = FlsAlloc(item5_fls_callback);
    if (g_fls_idx != FLS_OUT_OF_INDEXES) {
        static trampoline_ctx ctx5;
        DWORD ec = 0;
        int joined;
        LONG detach_cnt = 0;
        uint64_t detach_rsp = 0;
        g_fls_called = 0;
        g_fls_val_seen = 0;
        g_fls_rsp_seen = 0;
        g_item5_vfree_ok = 0;
        g_item5_tib_restored = 0;
        joined = run_thread_test(item5_thread, &ctx5, &ec);
        if (g_detach_result) detach_cnt = g_detach_result(&detach_rsp);
        {
            int fls_on_host_stack = (g_fls_rsp_seen >= g_item5_orig_limit &&
                                     g_fls_rsp_seen < g_item5_orig_base);
            int detach_on_host_stack = (detach_rsp >= g_item5_orig_limit &&
                                        detach_rsp < g_item5_orig_base);
            int dll_ok = (g_detach_arm && g_detach_result && detach_cnt == 1 && detach_on_host_stack);
            printf("[Item 5] joined=%d exit_code=0x%lx tib_dealloc_restored=%ld vfree_ok=%ld "
                   "fls_called=%ld fls_val=0x%llx fls_rsp=0x%llx (on_host=%d) "
                   "dll_detach_cnt=%ld dll_detach_rsp=0x%llx (on_host=%d) host=[0x%llx..0x%llx)\n",
                   joined, (unsigned long)ec, (long)g_item5_tib_restored, (long)g_item5_vfree_ok,
                   (long)g_fls_called, (unsigned long long)g_fls_val_seen,
                   (unsigned long long)g_fls_rsp_seen, fls_on_host_stack,
                   (long)detach_cnt, (unsigned long long)detach_rsp, detach_on_host_stack,
                   (unsigned long long)g_item5_orig_limit, (unsigned long long)g_item5_orig_base);
            r5 = (joined && ec == 0x42 && ctx5.test_ok && g_item5_tib_restored == 1 &&
                  g_item5_vfree_ok == 1 && g_fls_called == 1 && g_fls_val_seen == 0xF15C0DEULL &&
                  fls_on_host_stack && dll_ok);
        }
        FlsFree(g_fls_idx);
    }
    printf("VERDICT Item 5 (Restore host_rsp + NT_TIB/DeallocationStack + VirtualFree + ExitThread with FLS + DLL_THREAD_DETACH): %s\n",
           r5 ? "PASS" : "FAIL");
    fails += !r5;

    if (hdll) FreeLibrary(hdll);
    RemoveVectoredExceptionHandler(veh);
    printf("\nG2-1 Windows probe summary: %s (failures=%d; Items 3b and 4c-dwarf explicitly NOT TESTED)\n",
           fails ? "FAIL" : "ALL EXECUTED WINDOWS ITEMS PASSED", fails);
    return fails ? 1 : 0;
}
