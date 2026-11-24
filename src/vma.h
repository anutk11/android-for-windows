/*
 * vma.h - Linux memory mappings (mmap/munmap/mprotect/madvise) on Windows.
 *
 * Two notions, kept apart (reviewer 3):
 *   - a Windows allocation ("WinAlloc"): one VirtualAlloc reservation; it can
 *     only be released whole, from its base;
 *   - sorted, non-overlapping extents inside it: each extent [start, end) is
 *     unmapped or mapped, has Linux protections, and is committed or only
 *     reserved on the Windows side. Adjacent extents with equal state merge.
 *
 * Semantics (the part that matters for bionic/Scudo):
 *   mmap anonymous   reserve; ranges with prot != PROT_NONE are committed
 *                    (zeroed by Windows); PROT_NONE ranges stay reserved:
 *                    no commit charge
 *   mmap MAP_FIXED   inside an existing allocation: the range is decommitted
 *                    (zeroed) and remapped; in free space only at a 64KB-
 *                    aligned address (Windows reservation granularity),
 *                    otherwise -ENOMEM with a log line (documented limit)
 *   munmap partial   MEM_DECOMMIT of committed extents in that range; the
 *                    allocation is released when nothing in it is mapped
 *   mprotect         committed extents: VirtualProtect (PROT_NONE keeps the
 *                    contents, as on Linux - NOT a decommit); reserved
 *                    extents made accessible are committed then
 *   madvise          MADV_DONTNEED: on VMA_ANON committed accessible pages,
 *                    zeroes in place via memset(0) under g_lock (temporary
 *                    RW->RO around anonymous PROT_READ); PROT_NONE committed
 *                    pages decommit back to reserved; reserved pages and
 *                    VMA_FILEMAP/MAP_SHARED are safe no-ops; other advice is
 *                    a no-op
 * File-backed read-only mappings are handled by src/filemap.c (VMA_FILEMAP).
 * Synchronized with a single lock (SRWLOCK on Windows, pthread mutex on host).
 */
#ifndef AFW_VMA_H
#define AFW_VMA_H

#include <stddef.h>
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

/*
 * Register an externally mapped region (e.g. an ELF library image allocated
 * with afw_mem_alloc) so Linux mprotect/madvise/munmap/MAP_FIXED work on
 * [base, base + size). Any stub reserve after base + size stays outside VMA.
 *
 * Ownership stays with the caller: VMA never calls VirtualFree(MEM_RELEASE)
 * or full-region munmap on an adopted entry; call afw_vma_forget(base) before
 * afw_mem_free().
 *
 * page_prot holds (size / 4096) entries using LNX_PROT_* flags (NOT ELF PF_*
 * flags: LNX_PROT_READ=1, LNX_PROT_WRITE=2, LNX_PROT_EXEC=4). All pages are
 * recorded as mapped and committed.
 *
 * Re-adopt contract (calling afw_vma_adopt() again on the exact same adopted
 * [base, base + size)):
 *   - allowed ONLY while the entire range is still mapped and committed;
 *   - intended solely to update protections (e.g. after RELRO) BEFORE any
 *     Linux code has touched the region;
 *   - MUST NOT be used to bring back a region after munmap or decommit, or
 *     after any Linux-side VMA change (returns -EINVAL if any Linux-side
 *     VMA operation has touched the region, or if any tracked page is
 *     unmapped or decommitted).
 * Returns 0 or -errno (-EINVAL, -ENOMEM, -EEXIST).
 */
int afw_vma_adopt(uint64_t base, uint64_t size, const unsigned char *page_prot);

/*
 * Drop an adopted region from VMA tracking without making OS calls (call
 * before afw_mem_free). Idempotent if base is not registered (returns 0).
 * Returns -EINVAL if base is an interior address or a VMA-owned mmap.
 */
int afw_vma_forget(uint64_t base);

/*
 * Register an already-mapped read-only OS file view [view_base, view_base + view_span)
 * in the VMA table. Any leading 64KB-alignment prefix [view_base, view_base + delta)
 * is recorded as unmapped (not counted in mapped_bytes) and [view_base + delta,
 * view_base + delta + logical_len) is recorded as mapped+committed with prot.
 * Returns (int64_t)(view_base + delta) on success, or -errno on failure.
 */
int64_t afw_vma_register_filemap(uint64_t view_base, uint64_t view_span,
                                 uint64_t delta, uint64_t logical_len, int prot);

/*
 * Allocate a PROT_NONE empty-filemap reservation of logical_len bytes (for
 * 0-byte files where Windows CreateFileMappingW fails with ERROR_FILE_INVALID).
 * Reads fault cleanly like Linux SIGBUS; madvise(DONTNEED) is a no-op; munmap
 * releases the reservation. Returns address or -errno.
 */
int64_t afw_vma_alloc_empty_filemap(uint64_t logical_len, int prot);

/*
 * Query the contiguous mapped+committed RW VMA stack extent containing sp - 1
 * (for SYS_clone NT_TIB StackBase / StackLimit / DeallocationStack setup).
 * Returns 0 on success (requiring at least 4KB of committed RW stack below sp),
 * or -1 if sp is not inside a valid anonymous RW VMA extent.
 */
int afw_vma_stack_bounds(uint64_t sp, uint64_t *stack_base_out,
                         uint64_t *stack_limit_out, uint64_t *dealloc_stack_out);

/* Returns 1 if the entire [addr, addr + len) range is covered by mapped,
 * committed, writable VMA extents (g_lock-protected); 0 otherwise. */
int afw_vma_is_writable(uint64_t addr, uint64_t len);

/* For tests: live Windows allocations, total metadata bytes, total extents,
 * and total OS memory calls made so far. */
int afw_vma_alloc_count(void);
size_t afw_vma_meta_bytes(void);
size_t afw_vma_extent_count(void);
uint64_t afw_vma_os_call_count(void);

#ifdef AFW_TEST
/* Test hook: fail the nth next OS memory call (1 = very next, 0 = off). */
void afw_vma_test_fail_os(int nth);
/* Test hook: fail the nth next extent metadata growth (1 = very next, 0 = off). */
void afw_vma_test_fail_meta(int nth);
/* Test hook: fail the nth next write-watch API call (1 = very next, 0 = off). */
void afw_vma_test_fail_ww(int nth);
/* Test hook: returns 1 if the allocation containing addr has write_watch active, else 0. */
int afw_vma_test_ww_active(uint64_t addr);
#endif

#endif
