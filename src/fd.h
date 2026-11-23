/*
 * fd.h - Linux file descriptor table and file I/O syscalls (openat, read,
 * write, readv, writev, close, lseek, fstat, newfstatat, unlinkat, fcntl).
 *
 * Pure C11: all OS-specific calls go through platform.h (Rule 8).
 */
#ifndef AFW_FD_H
#define AFW_FD_H

#include <stddef.h>
#include <stdint.h>

#define AFW_MAX_FDS 256

/* Linux x86_64 UAPI struct stat (144 bytes). */
typedef struct {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t __pad0;
    uint64_t st_rdev;
    int64_t  st_size;
    int64_t  st_blksize;
    int64_t  st_blocks;
    int64_t  st_atime_s;
    int64_t  st_atime_ns;
    int64_t  st_mtime_s;
    int64_t  st_mtime_ns;
    int64_t  st_ctime_s;
    int64_t  st_ctime_ns;
    int64_t  __unused[3];
} afw_lnx_stat;

/* Each returns the Linux syscall result (>= 0 on success, -errno on error). */
int64_t afw_fd_openat(int64_t dirfd, const char *path, int64_t flags, uint64_t mode);
int64_t afw_fd_close(int64_t fd);
int64_t afw_fd_read(int64_t fd, void *buf, uint64_t len);
int64_t afw_fd_write(int64_t fd, const void *buf, uint64_t len);
int64_t afw_fd_readv(int64_t fd, const uint64_t *iov, int64_t cnt);
int64_t afw_fd_writev(int64_t fd, const uint64_t *iov, int64_t cnt);
int64_t afw_fd_lseek(int64_t fd, int64_t off, int64_t whence);
int64_t afw_fd_fstat(int64_t fd, void *statbuf);
int64_t afw_fd_newfstatat(int64_t dirfd, const char *path, void *statbuf, int64_t flags);
int64_t afw_fd_unlinkat(int64_t dirfd, const char *path, int64_t flags);
int64_t afw_fd_fcntl(int64_t fd, int64_t cmd, int64_t arg);

#endif
