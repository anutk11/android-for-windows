/*
 * crash.c - Turns "exit code -1073741819" into something we can act on.
 */
#include "patch.h"
#include "crash.h"
#include "elf_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "syscall.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static LONG WINAPI on_crash(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    CONTEXT *c = ep->ContextRecord;
    char where[512];
    unsigned char *ip = (unsigned char *)c->Rip;
    uint64_t *sp = (uint64_t *)c->Rsp;
    int i;

    fflush(stdout);
    afw_describe_address((uintptr_t)c->Rip, where, sizeof where);
    fprintf(stderr, "\n=== CRASH ===\n");
    fprintf(stderr, "exception 0x%08lx at %s\n", er->ExceptionCode, where);
    {
        const void *orig = afw_stub_origin(ip);
        if (orig) {
            char w2[512];
            afw_describe_address((uintptr_t)orig, w2, sizeof w2);
            fprintf(stderr, "  inside the fs:[reg] trampoline that replaces the instruction at %s\n", w2);
        }
    }
    if (er->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION && ip[0] == 0x0F && ip[1] == 0x0B)
        fprintf(stderr, "  this is a syscall site the loader REFUSED to patch (it was turned into ud2);\n"
                        "  see the [patch] REFUSED lines printed when the library was loaded\n");
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
        fprintf(stderr, "  %s address 0x%llx\n",
                er->ExceptionInformation[0] == 0 ? "reading" :
                er->ExceptionInformation[0] == 1 ? "writing" : "executing",
                (unsigned long long)er->ExceptionInformation[1]);
    fprintf(stderr, "  code: ");
    for (i = 0; i < 12; i++) fprintf(stderr, "%02x ", ip[i]);
    fprintf(stderr, "\n  rax=%llx rbx=%llx rcx=%llx rdx=%llx\n  rsi=%llx rdi=%llx rbp=%llx rsp=%llx\n",
            c->Rax, c->Rbx, c->Rcx, c->Rdx, c->Rsi, c->Rdi, c->Rbp, c->Rsp);
    fprintf(stderr, "  possible callers (from stack):\n");
    for (i = 0; i < 64; i++) {
        if (afw_describe_address((uintptr_t)sp[i], where, sizeof where))
            fprintf(stderr, "    %s\n", where);
    }
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}

void afw_crash_init(void) {
    SetUnhandledExceptionFilter(on_crash);
}

/* ---- watchdog: where is a run that makes no progress? -----------------
 * After `seconds`, the main thread is suspended and sampled 3 times, 200ms
 * apart: the same RIP each time with the syscall counts unchanged means it
 * is blocked; changing RIPs mean it spins. Then the process ends (124). */
static HANDLE g_wd_main;
static DWORD g_wd_seconds;

static void wd_sample(int n) {
    CONTEXT c;
    char where[512];
    int i;
    uint64_t sp[48];
    SIZE_T got = 0;
    memset(&c, 0, sizeof c);
    c.ContextFlags = CONTEXT_FULL;
    if (SuspendThread(g_wd_main) == (DWORD)-1) { fprintf(stderr, "  (cannot suspend the main thread)\n"); return; }
    if (!GetThreadContext(g_wd_main, &c)) { ResumeThread(g_wd_main); fprintf(stderr, "  (no context)\n"); return; }
    fprintf(stderr, "sample %d: rip=%llx ", n, (unsigned long long)c.Rip);
    if (afw_describe_address((uintptr_t)c.Rip, where, sizeof where)) fprintf(stderr, "(%s)\n", where);
    else fprintf(stderr, "(outside the Android libraries: the loader or Windows)\n");
    fprintf(stderr, "  rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx rsp=%llx\n",
            c.Rax, c.Rbx, c.Rcx, c.Rdx, c.Rsi, c.Rdi, c.Rsp);
    if (ReadProcessMemory(GetCurrentProcess(), (void *)(uintptr_t)c.Rsp, sp, sizeof sp, &got)) {
        fprintf(stderr, "  Android frames on the stack:\n");
        for (i = 0; i < (int)(got / 8); i++)
            if (afw_describe_address((uintptr_t)sp[i], where, sizeof where))
                fprintf(stderr, "    %s\n", where);
    }
    ResumeThread(g_wd_main);
}

static DWORD WINAPI wd_thread(LPVOID unused) {
    int k;
    (void)unused;
    Sleep(g_wd_seconds * 1000);
    fflush(stdout);
    fprintf(stderr, "\n=== WATCHDOG: no end after %lu s ===\n", (unsigned long)g_wd_seconds);
    for (k = 1; k <= 3; k++) { wd_sample(k); if (k < 3) Sleep(200); }
    fprintf(stderr, "syscalls so far:\n");
    afw_syscall_report();
    fflush(stderr); fflush(stdout);
    ExitProcess(124);
    return 0;
}

int afw_watchdog_start(unsigned seconds) {
    HANDLE t;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &g_wd_main,
                         THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, 0))
        return -1;
    g_wd_seconds = seconds;
    t = CreateThread(NULL, 0, wd_thread, NULL, 0, NULL);
    if (!t) return -1;
    CloseHandle(t);
    return 0;
}
#else
void afw_crash_init(void) {}
int afw_watchdog_start(unsigned seconds) { (void)seconds; return 0; }   /* Windows only */
#endif
