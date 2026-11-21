/*
 * crash.c - Turns "exit code -1073741819" into something we can act on.
 */
#include "crash.h"
#include "elf_loader.h"

#include <stdio.h>
#include <stdlib.h>

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
#else
void afw_crash_init(void) {}
#endif
