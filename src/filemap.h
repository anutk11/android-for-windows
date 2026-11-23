/*
 * filemap.h - Read-only file-backed Linux mmap() (MAP_SHARED and MAP_PRIVATE).
 *
 * Pure C11: all OS-specific calls go through platform.h (Rule 8).
 * Tracks mapped views inside src/vma.c so munmap, mprotect, and madvise share
 * one unified extent table and lock.
 */
#ifndef AFW_FILEMAP_H
#define AFW_FILEMAP_H

#include <stdint.h>

/* Handle a file-backed Linux mmap() call (!(flags & LNX_MAP_ANONYMOUS)).
 * Supports MAP_SHARED and MAP_PRIVATE with PROT_READ or PROT_NONE.
 * Rejects PROT_EXEC (-EACCES), PROT_WRITE (-ENOSYS), MAP_FIXED (-ENOSYS),
 * bad/non-regular/write-only fds (-EBADF / -ENODEV / -EACCES), and invalid
 * length/offset (-EINVAL).
 * Returns the mapped address (>= 0) or negative Linux errno. */
int64_t afw_filemap_mmap(uint64_t addr, uint64_t len, int prot, int flags,
                         int fd, int64_t off);

#endif
