/*
 * filemap.c - Read-only file-backed Linux mmap() implementation (Gate G2-2).
 *
 * Pure C11: all OS calls go through platform.h (Rule 8).
 *
 * Supported ABI (docs/design/G2-PLAN.md Section 5):
 *   - MAP_SHARED | PROT_READ (required for Bionic /dev/__properties__ map_fd_ro)
 *   - MAP_PRIVATE | PROT_READ (and PROT_NONE with either MAP_SHARED/MAP_PRIVATE).
 *     Note (G2 known limit): on Windows, both use FILE_MAP_READ, which reflects
 *     external writes to the underlying file (sufficient for /dev/__properties__
 *     and immutable assets in G2).
 *   - 4KB-aligned offsets that are not 64KB-aligned on Windows: maps from
 *     aligned_off = off & ~0xFFFF, sets PAGE_NOACCESS on the leading delta bytes,
 *     returns view_base + delta, and counts only logical [addr, addr + len) in
 *     VMA mapped_bytes so full munmap releases the entire view.
 *   - 0-byte files: allocates a PROT_NONE empty-filemap VMA (reads fault like
 *     Linux SIGBUS) without failing in Windows CreateFileMappingW.
 *   - Partial final page: maps min(delta + logical_len, file_size - aligned_off);
 *     bytes past EOF to page end read as zero. Whole pages strictly past
 *     roundup(file_size, 4096) return -ENOSYS (documented G2 limit).
 *
 * Rejected deterministically:
 *   - PROT_EXEC   -> -EACCES (never bypasses load-time code patching, Rule 6)
 *   - PROT_WRITE  -> -ENOSYS (outside G2 read-only scope)
 *   - MAP_FIXED*  -> -ENOSYS
 *   - invalid fd  -> -EBADF; O_WRONLY -> -EACCES; stdio/dir/non-regular -> -ENODEV
 *   - off < 0, off % 4096 != 0, len == 0, overflow, bad flags -> -EINVAL
 */
#include "filemap.h"
#include "fd.h"
#include "platform.h"
#include "vma.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define PG   4096ULL
#define GRAN 65536ULL

#define LNX_EBADF  9
#define LNX_ENOMEM 12
#define LNX_EACCES 13
#define LNX_ENODEV 19
#define LNX_EINVAL 22
#define LNX_ENOSYS 38

#define LNX_MAP_POPULATE 0x8000
#define LNX_FILEMAP_ALLOWED_FLAGS \
    (LNX_MAP_SHARED | LNX_MAP_PRIVATE | LNX_MAP_NORESERVE | LNX_MAP_POPULATE)

int64_t afw_filemap_mmap(uint64_t addr, uint64_t len, int prot, int flags,
                         int fd, int64_t off) {
    int share_type;
    uint64_t logical_len, uoff, file_size_u, file_pages_end;
    uint64_t aligned_off, delta, view_span, avail, view_map_bytes;
    afw_os_file os_f = AFW_OS_FILE_INVALID;
    int64_t file_size = 0;
    void *view_base = NULL;
    int rc;

    (void)addr; /* non-fixed hint ignored */

    /* 1. Validate length, offset, flags, and protection bits before taking locks. */
    if (!len || len > UINT64_MAX - (PG - 1)) return -LNX_EINVAL;
    logical_len = (len + PG - 1) & ~(PG - 1);
    if (logical_len > (uint64_t)SIZE_MAX) return -LNX_EINVAL;

    if (off < 0) return -LNX_EINVAL;
    uoff = (uint64_t)off;
    if (uoff & (PG - 1)) return -LNX_EINVAL;
    if (logical_len > (uint64_t)INT64_MAX || uoff > (uint64_t)INT64_MAX - logical_len)
        return -LNX_EINVAL;

    share_type = flags & (LNX_MAP_SHARED | LNX_MAP_PRIVATE);
    if (share_type != LNX_MAP_SHARED && share_type != LNX_MAP_PRIVATE)
        return -LNX_EINVAL;

    if (flags & (LNX_MAP_FIXED | LNX_MAP_FIXED_NOREPLACE))
        return -LNX_ENOSYS;
    if (flags & ~LNX_FILEMAP_ALLOWED_FLAGS)
        return -LNX_EINVAL;

    if (prot & ~(LNX_PROT_READ | LNX_PROT_WRITE | LNX_PROT_EXEC))
        return -LNX_EINVAL;
    if (prot & LNX_PROT_EXEC)
        return -LNX_EACCES;   /* single deterministic error (Rule 6) */
    if (prot & LNX_PROT_WRITE)
        return -LNX_ENOSYS;   /* read-only scope for G2 */

    /* 2. Validate fd, inspect file size, and create OS view under afw_fd_lock()
     *    so concurrent close(fd) cannot race with CreateFileMappingW / mmap.
     *    Lock ordering: afw_fd_lock() is NEVER nested with VMA g_lock. */
    afw_fd_lock();
    rc = afw_fd_inspect_for_mmap_locked(fd, (intptr_t *)&os_f, &file_size);
    if (rc != 0) {
        afw_fd_unlock();
        return rc;
    }

    if (file_size == 0) {
        afw_fd_unlock();
        return afw_vma_alloc_empty_filemap(logical_len, prot);
    }

    file_size_u = (uint64_t)file_size;
    if (file_size_u > UINT64_MAX - (PG - 1)) {
        afw_fd_unlock();
        return -LNX_EINVAL;
    }
    file_pages_end = (file_size_u + PG - 1) & ~(PG - 1);

    /* Whole pages strictly past roundup(file_size, 4096) are rejected cleanly. */
    if (uoff >= file_size_u || uoff + logical_len > file_pages_end) {
        afw_fd_unlock();
        return -LNX_ENOSYS;
    }

    aligned_off = uoff & ~(GRAN - 1);
    delta = uoff - aligned_off;
    if (delta > UINT64_MAX - logical_len) {
        afw_fd_unlock();
        return -LNX_EINVAL;
    }
    view_span = delta + logical_len;
    if (view_span > (uint64_t)SIZE_MAX) {
        afw_fd_unlock();
        return -LNX_ENOMEM;
    }
    avail = file_size_u - aligned_off;
    view_map_bytes = view_span < avail ? view_span : avail;

    rc = afw_os_filemap_ro(os_f, aligned_off, (size_t)view_map_bytes,
                           share_type == LNX_MAP_SHARED, &view_base);
    afw_fd_unlock();
    if (rc != 0)
        return rc;

    /* 3. Lock down any leading 64KB-alignment delta prefix to PAGE_NOACCESS / PROT_NONE
     *    so memory below the returned address is never accessible. */
    if (delta > 0) {
        if (afw_os_filemap_protect(view_base, (size_t)delta, 0) != 0) {
            afw_os_filemap_unmap(view_base, (size_t)view_span);
            return -LNX_ENOMEM;
        }
    }

    /* If caller asked for PROT_NONE, lock down the logical mapped range too. */
    if (prot == 0) {
        if (afw_os_filemap_protect((unsigned char *)view_base + delta,
                                   (size_t)logical_len, 0) != 0) {
            afw_os_filemap_unmap(view_base, (size_t)view_span);
            return -LNX_ENOMEM;
        }
    }

    /* 4. Register in VMA table (acquires VMA g_lock). Unmap view if OOM. */
    {
        int64_t res = afw_vma_register_filemap((uint64_t)(uintptr_t)view_base,
                                               view_span, delta, logical_len, prot);
        if (res < 0) {
            afw_os_filemap_unmap(view_base, (size_t)view_span);
            return res;
        }
        return res;
    }
}
