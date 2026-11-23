/*
 * platform.c - Memory management for Windows (VirtualAlloc) and Linux (mmap).
 */
#include "platform.h"

#if defined(_WIN32)
#define _CRT_RAND_S        /* rand_s: the OS's cryptographic generator */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int afw_check_security(void) {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn = {0};
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = {0};
    int ok = 1;
    if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &dyn, sizeof dyn) &&
        dyn.ProhibitDynamicCode) {
        fprintf(stderr,
                "error: Arbitrary Code Guard (ACG) is enabled for this program.\n"
                "       Android code must be loaded into memory and patched, which ACG forbids.\n"
                "       Check Windows Security > App & browser control > Exploit protection,\n"
                "       or your organization's policy for afw-loader.exe.\n");
        ok = 0;
    }
    if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &cfg, sizeof cfg) &&
        cfg.EnableControlFlowGuard)
        fprintf(stderr, "warning: Control Flow Guard is on; calls into Android code may be blocked\n");
    return ok ? 0 : -1;
}

void *afw_mem_alloc(size_t size) {
    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

void afw_mem_free(void *addr, size_t size) {
    (void)size;
    if (addr) VirtualFree(addr, 0, MEM_RELEASE);
}

int afw_mem_protect(void *addr, size_t size, int prot) {
    DWORD p, old;
    int x = prot & AFW_PROT_X, w = prot & AFW_PROT_W, r = prot & AFW_PROT_R;
    if (x && w)      p = PAGE_EXECUTE_READWRITE;
    else if (x)      p = PAGE_EXECUTE_READ;
    else if (w)      p = PAGE_READWRITE;
    else if (r)      p = PAGE_READONLY;
    else             p = PAGE_NOACCESS;
    return VirtualProtect(addr, size, p, &old) ? 0 : -1;
}

void afw_flush_icache(void *addr, size_t size) {
    FlushInstructionCache(GetCurrentProcess(), addr, size);
}

int afw_random_bytes(void *buf, size_t n) {
    unsigned char *b = (unsigned char *)buf;
    while (n) {
        unsigned int v;
        size_t k = n < sizeof v ? n : sizeof v;
        if (rand_s(&v) != 0) return -1;
        memcpy(b, &v, k); b += k; n -= k;
    }
    return 0;
}

#else
#include <sys/mman.h>

int afw_check_security(void) { return 0; }

int afw_random_bytes(void *buf, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = f ? fread(buf, 1, n, f) : 0;
    if (f) fclose(f);
    return got == n ? 0 : -1;
}

void *afw_mem_alloc(size_t size) {
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

void afw_mem_free(void *addr, size_t size) {
    if (addr) munmap(addr, size);
}

int afw_mem_protect(void *addr, size_t size, int prot) {
    int p = 0;
    if (prot & AFW_PROT_R) p |= PROT_READ;
    if (prot & AFW_PROT_W) p |= PROT_WRITE;
    if (prot & AFW_PROT_X) p |= PROT_EXEC;
    return mprotect(addr, size, p);
}

void afw_flush_icache(void *addr, size_t size) {
    __builtin___clear_cache((char *)addr, (char *)addr + size);
}
#endif
