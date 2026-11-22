/*
 * platform.h - The thin layer between the loader and the host OS.
 *
 * The real target is Windows. The same code also builds on Linux so the
 * loader logic can be tested anywhere.
 */
#ifndef AFW_PLATFORM_H
#define AFW_PLATFORM_H

#include <stddef.h>

/*
 * Calling convention bridge.
 *
 * Android x86_64 code uses the System V ABI (arguments in rdi, rsi, rdx...).
 * Windows code uses the Microsoft x64 ABI (arguments in rcx, rdx, r8...).
 * Every function that Android code calls, and every Android function we call,
 * must be marked SYSV so the compiler generates the right glue.
 * This needs clang / clang-cl (MSVC's cl.exe does not support it).
 */
#if defined(_WIN32)
#  if !defined(__clang__)
#    error "Build with clang-cl: MSVC cl.exe cannot call System V ABI code."
#  endif
#  define SYSV __attribute__((sysv_abi))
#else
#  define SYSV
/* Check Windows exploit-protection policies that would block the engine
 * (ACG forbids creating or patching executable memory). Can be forced on a
 * program from outside, by an administrator. Returns 0 if we can run. */
int afw_check_security(void);

#endif

/* Memory protection flags (same bits as ELF PF_*) */
#define AFW_PROT_X 1
#define AFW_PROT_W 2
#define AFW_PROT_R 4

#define AFW_PAGE_SIZE 4096

/* Reserve+commit zeroed read/write memory. Returns NULL on failure. */
void *afw_mem_alloc(size_t size);
/* Release memory from afw_mem_alloc. */
void afw_mem_free(void *addr, size_t size);
/* Change protection of a page-aligned range. Returns 0 on success. */
int afw_mem_protect(void *addr, size_t size, int prot);
/* Make sure the CPU sees freshly written code. */
void afw_flush_icache(void *addr, size_t size);

/* n bytes from the OS's cryptographic random generator; 0 on success */
int afw_random_bytes(void *buf, size_t n);

/* Check Windows exploit-protection policies that would block the engine
 * (ACG forbids creating or patching executable memory). Can be forced on a
 * program from outside, by an administrator. Returns 0 if we can run. */
int afw_check_security(void);

#endif
