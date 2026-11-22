/*
 * vma.h - Linux memory mappings (mmap/munmap/mprotect/madvise) on Windows.
 *
 * Two notions, kept apart (reviewer 3):
 *   - a Windows allocation ("WinAlloc"): one VirtualAlloc reservation; it can
 *     only be released whole, from its base;
 *   - Linux pages inside it: each 4KB page is unmapped or mapped, has Linux
 *     protections, and is committed or only reserved on the Windows side.
 *
 * Semantics (the part that matters for bionic/Scudo):
 *   mmap anonymous   reserve; pages with prot != PROT_NONE are committed
 *                    (zeroed by Windows); PROT_NONE pages stay reserved:
 *                    no commit charge
 *   mmap MAP_FIXED   inside an existing allocation: the pages are
 *                    decommitted (zeroed) and remapped; in free space only at
 *                    a 64KB-aligned address (Windows reservation granularity),
 *                    otherwise -ENOMEM with a log line (documented limit)
 *   munmap partial   MEM_DECOMMIT of those pages; the allocation is released
 *                    when no page of it is mapped any more
 *   mprotect         committed pages: VirtualProtect (PROT_NONE keeps the
 *                    contents, as on Linux - NOT a decommit); reserved pages
 *                    made accessible are committed then
 *   madvise          MADV_DONTNEED: mapped committed pages read back as zeros
 *                    (decommit + recommit); other advice is accepted as a no-op
 * File-backed mappings are not supported yet (-ENODEV).
 * Not thread-safe yet: G1 runs a single thread (one lock comes with G2).
 */
#ifndef AFW_VMA_H
#define AFW_VMA_H

#include <stdint.h>

#define LNX_PROT_READ 1
#define LNX_PROT_WRITE 2
#define LNX_PROT_EXEC 4
#define LNX_MAP_SHARED 0x01
#define LNX_MAP_PRIVATE 0x02
#define LNX_MAP_FIXED 0x10
#define LNX_MAP_ANONYMOUS 0x20
#define LNX_MAP_NORESERVE 0x4000
#define LNX_MAP_FIXED_NOREPLACE 0x100000
#define LNX_MADV_DONTNEED 4

/* Each returns the Linux result: an address / 0, or -errno. */
int64_t afw_mmap(uint64_t addr, uint64_t len, int prot, int flags, int fd, int64_t off);
int64_t afw_munmap(uint64_t addr, uint64_t len);
int64_t afw_mprotect(uint64_t addr, uint64_t len, int prot);
int64_t afw_madvise(uint64_t addr, uint64_t len, int advice);

/* For tests: number of live Windows allocations. */
int afw_vma_alloc_count(void);

#endif
