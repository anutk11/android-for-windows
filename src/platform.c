/*
 * platform.c - Memory management for Windows (VirtualAlloc) and Linux (mmap).
 */
#include "platform.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void *afw_mem_alloc(size_t size) {
    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
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

#else
#include <sys/mman.h>

void *afw_mem_alloc(size_t size) {
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
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
