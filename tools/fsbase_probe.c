/*
 * fsbase_probe.c - Experiment (G1, suggested by reviewer 2): can a Windows
 * program set its own fs base with WRFSBASE, per thread, and keep it?
 *
 * If yes, bionic's "fs:" TLS would work natively, with no patching at all.
 * Steps:
 *   1. CPUID: does the CPU have FSGSBASE?
 *   2. Does the OS allow WRFSBASE in user mode (or is it #UD)?
 *   3. Two threads, each with its own fake bionic TLS block as fs base;
 *      each changes slot 7 (fs:[0x38], ART's thread self) at run time.
 *   4. Many context switches, sleeps and Windows API calls in between:
 *      does each thread still see its own block?
 *
 * Build: clang-cl /O2 tools\fsbase_probe.c
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void wrfsbase(uint64_t v) {
    /* wrfsbase rax = F3 48 0F AE D0 */
    __asm__ volatile(".byte 0xf3, 0x48, 0x0f, 0xae, 0xd0" : : "a"(v) : "memory");
}
static uint64_t rdfsbase(void) {
    uint64_t v;
    /* rdfsbase rax = F3 48 0F AE C0 */
    __asm__ volatile(".byte 0xf3, 0x48, 0x0f, 0xae, 0xc0" : "=a"(v));
    return v;
}
static uint64_t read_fs_slot7(void) {
    uint64_t v;
    __asm__ volatile("movq %%fs:0x38, %0" : "=r"(v));
    return v;
}
static uint64_t read_fs_self(void) {
    uint64_t v;
    __asm__ volatile("movq %%fs:0x0, %0" : "=r"(v));
    return v;
}

typedef struct {
    uint64_t slots[16];      /* fake bionic TLS block */
    int id;
    long checks, bad, faults;
    uint64_t base_seen_after;
} thread_state;

static DWORD WINAPI worker(void *arg) {
    thread_state *t = (thread_state *)arg;
    int i;
    t->slots[0] = (uint64_t)(uintptr_t)t->slots;      /* TLS_SLOT_SELF */
    __try {
        wrfsbase((uint64_t)(uintptr_t)t->slots);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        t->faults = -1;
        return 0;
    }
    for (i = 0; i < 200000; i++) {
        uint64_t want = ((uint64_t)t->id << 32) | (uint64_t)i;
        t->slots[7] = want;                            /* changed through memory, like ART */
        if ((i & 1023) == 0) { Sleep(0); SwitchToThread(); GetTickCount64(); }
        if ((i & 16383) == 0) { char buf[64]; GetEnvironmentVariableA("PATH", buf, sizeof buf); Sleep(1); }
        __try {
            uint64_t got = read_fs_slot7();
            uint64_t self = read_fs_self();
            t->checks++;
            if (got != want || self != (uint64_t)(uintptr_t)t->slots) t->bad++;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            t->faults++;
        }
    }
    t->base_seen_after = rdfsbase();
    return 0;
}

typedef LONG (WINAPI *RtlGetVersion_fn)(OSVERSIONINFOW *);

/* Step-by-step: WHEN is the fs base lost? (reviewer 1) */
static void when_is_it_lost(void) {
    static uint64_t block[16];
    uint64_t r;
    block[0] = (uint64_t)(uintptr_t)block;
    printf("4. When is the fs base lost? (main thread)\n");
    __try { wrfsbase((uint64_t)(uintptr_t)block); } __except (EXCEPTION_EXECUTE_HANDLER) { printf("   WRFSBASE faulted\n"); return; }
    r = rdfsbase();
    printf("   a) right after WRFSBASE, no system call:   %s\n", r == (uint64_t)(uintptr_t)block ? "kept" : "LOST");
    wrfsbase((uint64_t)(uintptr_t)block);
    GetFileAttributesA("C:\\");        /* one system call (NtQueryAttributesFile), no wait */
    r = rdfsbase();
    printf("   b) after one system call:                 %s\n", r == (uint64_t)(uintptr_t)block ? "kept" : "LOST");
    wrfsbase((uint64_t)(uintptr_t)block);
    Sleep(20);                           /* the thread is switched out and back */
    r = rdfsbase();
    printf("   c) after a sleep (context switch):         %s\n", r == (uint64_t)(uintptr_t)block ? "kept" : "LOST");
    wrfsbase(0);
}

int main(void) {
    int regs[4];
    thread_state a = {{0}}, b = {{0}};
    HANDLE ha, hb;
    int ok = 1;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== WRFSBASE experiment ===\n");
    {
        int b[12];
        char brand[49] = {0};
        OSVERSIONINFOW v = {sizeof v};
        RtlGetVersion_fn rgv = (RtlGetVersion_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
        __cpuid(b, 0x80000002); __cpuid(b + 4, 0x80000003); __cpuid(b + 8, 0x80000004);
        memcpy(brand, b, 48);
        if (rgv) rgv(&v);
        printf("CPU: %s\nWindows: %lu.%lu build %lu\n", brand, v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
    }
    __cpuidex(regs, 7, 0);
    printf("1. CPU has FSGSBASE (CPUID.7.EBX[0]): %s\n", (regs[1] & 1) ? "yes" : "no");
    if (!(regs[1] & 1)) { printf("RESULT: not available on this CPU\n"); return 0; }

    __try {
        uint64_t before = rdfsbase();
        printf("2. RDFSBASE in user mode works; current fs base = 0x%llx\n", (unsigned long long)before);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("2. RDFSBASE faults (0x%08lx): Windows does not enable FSGSBASE for user mode\n",
               GetExceptionCode());
        printf("RESULT: WRFSBASE is not usable -> keep patching fs: accesses\n");
        return 0;
    }

    when_is_it_lost();

    a.id = 1; b.id = 2;
    ha = CreateThread(NULL, 0, worker, &a, 0, NULL);
    hb = CreateThread(NULL, 0, worker, &b, 0, NULL);
    WaitForSingleObject(ha, INFINITE);
    WaitForSingleObject(hb, INFINITE);

    if (a.faults < 0 || b.faults < 0) {
        printf("3. WRFSBASE faults in user mode\nRESULT: not usable -> keep patching fs: accesses\n");
        return 0;
    }
    printf("3. thread 1: %ld checks, %ld wrong, %ld faults, fs base at end %s\n", a.checks, a.bad, a.faults,
           a.base_seen_after == (uint64_t)(uintptr_t)a.slots ? "kept" : "LOST");
    printf("   thread 2: %ld checks, %ld wrong, %ld faults, fs base at end %s\n", b.checks, b.bad, b.faults,
           b.base_seen_after == (uint64_t)(uintptr_t)b.slots ? "kept" : "LOST");
    ok = a.bad == 0 && b.bad == 0 && a.faults == 0 && b.faults == 0 &&
         a.base_seen_after == (uint64_t)(uintptr_t)a.slots && b.base_seen_after == (uint64_t)(uintptr_t)b.slots;
    printf("RESULT: %s\n", ok ? "WRFSBASE works and survives context switches and API calls"
                              : "WRFSBASE is NOT reliable on Windows -> keep patching fs: accesses");
    return 0;
}
