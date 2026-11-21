/*
 * fs_probe.c - Experiment for M1: can we make Linux "fs:" TLS accesses work
 * on Windows x64?
 *
 * Android code reads thread-local data with instructions like
 *     mov rax, qword ptr fs:[0x28]        ; 64 48 8B 04 25 28 00 00 00
 * On Windows x64 the fs segment is not usable by programs.
 *
 * Idea: when such an instruction faults, rewrite it in place to
 *     mov rax, qword ptr gs:[0x1480 + 8*slot]
 * gs points to the Windows TEB, and TEB+0x1480 holds the 64 TlsSlots that
 * TlsAlloc() hands out. Same instruction length, so nothing else moves, and
 * the instruction never faults again (zero overhead after the first time).
 *
 * Build: clang-cl /O2 tools\fs_probe.c
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEB_TLS_SLOTS 0x1480
#define MAX_FS_OFFSETS 32

static struct { int32_t fs_off; DWORD slot; } g_map[MAX_FS_OFFSETS];
static int g_nmap;
static volatile LONG g_patches;

static DWORD slot_for_offset(int32_t off) {
    int i;
    for (i = 0; i < g_nmap; i++)
        if (g_map[i].fs_off == off) return g_map[i].slot;
    return TLS_OUT_OF_INDEXES;
}

/* Decode "fs: [disp32]" memory operand. Returns pointer to the 0x64 prefix
 * and sets *disp to the location of the 32-bit displacement. */
static unsigned char *find_fs_disp(unsigned char *ip, unsigned char **disp) {
    unsigned char *p = ip, *fs = NULL;
    /* legacy prefixes, in any order */
    for (;;) {
        if (*p == 0x64) fs = p;
        else if (*p != 0x66 && *p != 0xF2 && *p != 0xF3) break;
        p++;
    }
    if (!fs) return NULL;
    if ((*p & 0xF0) == 0x40) p++;           /* REX */
    if (*p == 0x0F) { p++; if (*p == 0x38 || *p == 0x3A) p++; }
    p++;                                     /* opcode */
    /* ModRM: mod=00, rm=100 (SIB follows); SIB=0x25 (no base, no index) */
    if ((p[0] & 0xC7) != 0x04 || p[1] != 0x25) return NULL;
    *disp = p + 2;
    return fs;
}

static LONG CALLBACK fs_handler(EXCEPTION_POINTERS *ep) {
    unsigned char *ip, *fs, *disp;
    int32_t off;
    DWORD slot, old;
    int32_t new_disp;

    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    ip = (unsigned char *)ep->ContextRecord->Rip;
    fs = find_fs_disp(ip, &disp);
    if (!fs) return EXCEPTION_CONTINUE_SEARCH;

    memcpy(&off, disp, 4);
    slot = slot_for_offset(off);
    if (slot == TLS_OUT_OF_INDEXES || slot >= 64) return EXCEPTION_CONTINUE_SEARCH;
    new_disp = TEB_TLS_SLOTS + 8 * (int32_t)slot;

    VirtualProtect(fs, 16, PAGE_EXECUTE_READWRITE, &old);
    *fs = 0x65;                        /* fs: -> gs: */
    memcpy(disp, &new_disp, 4);
    VirtualProtect(fs, 16, old, &old);
    FlushInstructionCache(GetCurrentProcess(), fs, 16);
    InterlockedIncrement(&g_patches);
    return EXCEPTION_CONTINUE_EXECUTION; /* re-run the patched instruction */
}

static int map_offset(int32_t off, void *value) {
    DWORD s = TlsAlloc();
    if (s == TLS_OUT_OF_INDEXES || s >= 64) return -1;
    g_map[g_nmap].fs_off = off;
    g_map[g_nmap].slot = s;
    g_nmap++;
    TlsSetValue(s, value);
    return (int)s;
}

typedef uint64_t (*read_fn)(void);
typedef void (*write_fn)(uint64_t);

static DWORD WINAPI thread_main(void *arg) {
    read_fn rd = (read_fn)arg;
    TlsSetValue(g_map[0].slot, (void *)(uintptr_t)0x2222222222222222ULL);
    return (DWORD)(rd() == 0x2222222222222222ULL);
}

int main(void) {
    /* Real machine code, exactly as the Android NDK emits it */
    static const unsigned char code_read[] = {
        0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, /* mov rax, fs:[0x28] */
        0xC3                                                  /* ret */
    };
    static const unsigned char code_write[] = {
        0x64, 0x48, 0x89, 0x0C, 0x25, 0x00, 0x00, 0x00, 0x00, /* mov fs:[0], rcx */
        0xC3
    };
    static const unsigned char code_read0[] = {
        0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, /* mov rax, fs:[0] */
        0xC3
    };
    unsigned char *mem;
    read_fn rd, rd0;
    write_fn wr;
    uint64_t v;
    int fails = 0;
    HANDLE th;
    DWORD th_ok = 0;

    printf("=== fs: TLS experiment ===\n");

    mem = (unsigned char *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, code_read, sizeof code_read);
    memcpy(mem + 64, code_write, sizeof code_write);
    memcpy(mem + 128, code_read0, sizeof code_read0);
    rd = (read_fn)mem;
    wr = (write_fn)(mem + 64);
    rd0 = (read_fn)(mem + 128);

    /* Step 1: what happens without our trick? */
    __try {
        v = rd();
        printf("1. raw fs:[0x28] did NOT fault, read 0x%llx -> fault-based patching won't work\n",
               (unsigned long long)v);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("1. raw fs:[0x28] faults (code 0x%08lx) - good, we can catch it\n",
               GetExceptionCode());
    }

    /* Step 2: install the handler and map two fs offsets to TEB slots */
    AddVectoredExceptionHandler(1, fs_handler);
    printf("2. fs:[0x28] -> TEB slot %d, fs:[0] -> TEB slot %d\n",
           map_offset(0x28, (void *)(uintptr_t)0x1111111111111111ULL),
           map_offset(0x00, NULL));

    v = rd();
    printf("3. read  fs:[0x28] = 0x%llx  %s\n", (unsigned long long)v,
           v == 0x1111111111111111ULL ? "OK" : "FAIL");
    fails += v != 0x1111111111111111ULL;

    printf("   instruction is now: %02x %02x %02x %02x %02x %02x %02x %02x %02x  (%s)\n",
           mem[0], mem[1], mem[2], mem[3], mem[4], mem[5], mem[6], mem[7], mem[8],
           mem[0] == 0x65 ? "gs:, patched" : "not patched");

    wr(0xABCDEF);
    v = rd0();
    printf("4. write fs:[0] then read back = 0x%llx  %s\n", (unsigned long long)v,
           v == 0xABCDEF ? "OK" : "FAIL");
    fails += v != 0xABCDEF;

    /* Step 5: is it really per-thread? */
    th = CreateThread(NULL, 0, thread_main, (void *)rd, 0, NULL);
    WaitForSingleObject(th, INFINITE);
    GetExitCodeThread(th, &th_ok);
    v = rd();
    printf("5. other thread sees its own value: %s, this thread still 0x%llx  %s\n",
           th_ok ? "OK" : "FAIL", (unsigned long long)v,
           (th_ok && v == 0x1111111111111111ULL) ? "OK" : "FAIL");
    fails += !(th_ok && v == 0x1111111111111111ULL);

    /* Step 6: speed after patching */
    {
        LARGE_INTEGER f, a, b;
        int i;
        volatile uint64_t sink = 0;
        QueryPerformanceFrequency(&f);
        QueryPerformanceCounter(&a);
        for (i = 0; i < 10000000; i++) sink += rd();
        QueryPerformanceCounter(&b);
        printf("6. 10,000,000 patched reads: %.1f ms (patches applied: %ld)\n",
               (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)f.QuadPart, g_patches);
    }

    printf("\n%s\n", fails ? "EXPERIMENT FAILED" : "EXPERIMENT PASSED - fs: TLS can work on Windows!");
    return fails ? 1 : 0;
}
