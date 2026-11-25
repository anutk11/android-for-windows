/*
 * fd.c - Linux file descriptor table and file I/O syscalls.
 *
 * Pure C11: every OS call goes through platform.h (Rule 8).
 */
#include "fd.h"
#include "platform.h"

#include <stddef.h>
#include <string.h>

_Static_assert(sizeof(afw_lnx_stat) == 144, "Linux x86_64 struct stat must be 144 bytes");
_Static_assert(offsetof(afw_lnx_stat, st_mode) == 24, "st_mode offset");
_Static_assert(offsetof(afw_lnx_stat, st_size) == 48, "st_size offset");
_Static_assert(offsetof(afw_lnx_stat, st_atime_s) == 72, "st_atim offset");
_Static_assert(offsetof(afw_lnx_stat, st_mtime_s) == 88, "st_mtim offset");
_Static_assert(offsetof(afw_lnx_stat, st_ctime_s) == 104, "st_ctim offset");

#define LNX_ENOENT   2
#define LNX_EBADF    9
#define LNX_EFAULT   14
#define LNX_EINVAL   22
#define LNX_EMFILE   24
#define LNX_ESPIPE   29
#define LNX_ENOSYS   38

#define LNX_AT_FDCWD            (-100)
#define LNX_AT_SYMLINK_NOFOLLOW 0x100
#define LNX_AT_REMOVEDIR        0x200
#define LNX_AT_EMPTY_PATH       0x1000

#define LNX_O_NOCTTY    0x100
#define LNX_O_LARGEFILE 0x8000
#define LNX_O_CLOEXEC   0x80000

#define LNX_SUPPORTED_OPEN_FLAGS \
    (AFW_O_ACCMODE | AFW_O_CREAT | AFW_O_EXCL | LNX_O_NOCTTY | \
     AFW_O_TRUNC | AFW_O_APPEND | AFW_O_DIRECTORY | AFW_O_NOFOLLOW | \
     LNX_O_LARGEFILE | LNX_O_CLOEXEC)

/* Flags Linux x86_64 preserves in file->f_flags and reports from F_GETFL. */
#define LNX_F_STATUS_STORED_MASK \
    (AFW_O_ACCMODE | AFW_O_APPEND | LNX_O_LARGEFILE | AFW_O_DIRECTORY | AFW_O_NOFOLLOW)

#define LNX_F_GETFD 1
#define LNX_F_SETFD 2
#define LNX_F_GETFL 3
#define LNX_F_SETFL 4

#define LNX_MAX_RW_COUNT 0x7ffff000u

#include <stdlib.h>

enum { FD_NONE = 0, FD_STDIO = 1, FD_FILE = 2, FD_DEVNULL = 3, FD_MEMBUF = 4 };

typedef struct {
    int         kind;
    int         std_fd;     /* 0/1/2 for FD_STDIO */
    afw_os_file os;         /* OS handle for FD_FILE */
    int         flags;      /* LNX_F_STATUS_STORED_MASK (with LNX_O_LARGEFILE forced) */
    int         cloexec;
    const char *mem_buf;    /* backing buffer for FD_MEMBUF */
    size_t      mem_len;
    size_t      mem_pos;
    int         mem_owned;
} fd_entry;

static fd_entry g_fds[AFW_MAX_FDS];
static int g_fds_init;

static const char g_proc_cmdline[] = "g3_art_gate_exe\0";
static const char g_proc_maps[] = "";
static const char g_proc_cpuinfo[] =
    "processor\t: 0\n"
    "vendor_id\t: GenuineIntel\n"
    "cpu family\t: 6\n"
    "model name\t: Android-for-Windows x86_64\n"
    "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx lm constant_tsc ssse3 sse4_1 sse4_2 popcnt aes avx\n\n";
static const char g_proc_meminfo[] =
    "MemTotal:        8388608 kB\n"
    "MemFree:         4194304 kB\n"
    "MemAvailable:    4194304 kB\n";
static const char g_sys_cpu_online[] = "0-3\n";

/* Match synthetic virtual files needed by Android runtime on Windows.
 * Returns FD_DEVNULL, FD_MEMBUF (setting *buf_out and *len_out), or 0 for real OS path. */
static int match_virtual_path(const char *path, const char **buf_out, size_t *len_out) {
    if (strcmp(path, "/dev/null") == 0) return FD_DEVNULL;
    if (strcmp(path, "/proc/self/cmdline") == 0) {
        if (buf_out) *buf_out = g_proc_cmdline;
        if (len_out) *len_out = sizeof(g_proc_cmdline) - 1;
        return FD_MEMBUF;
    }
    if (strcmp(path, "/proc/self/maps") == 0) {
        if (buf_out) *buf_out = g_proc_maps;
        if (len_out) *len_out = 0;
        return FD_MEMBUF;
    }
    if (strcmp(path, "/proc/cpuinfo") == 0) {
        if (buf_out) *buf_out = g_proc_cpuinfo;
        if (len_out) *len_out = sizeof(g_proc_cpuinfo) - 1;
        return FD_MEMBUF;
    }
    if (strcmp(path, "/proc/meminfo") == 0) {
        if (buf_out) *buf_out = g_proc_meminfo;
        if (len_out) *len_out = sizeof(g_proc_meminfo) - 1;
        return FD_MEMBUF;
    }
    if (strcmp(path, "/sys/devices/system/cpu/online") == 0 ||
        strcmp(path, "/sys/devices/system/cpu/possible") == 0 ||
        strcmp(path, "/sys/devices/system/cpu/present") == 0) {
        if (buf_out) *buf_out = g_sys_cpu_online;
        if (len_out) *len_out = sizeof(g_sys_cpu_online) - 1;
        return FD_MEMBUF;
    }
    return 0;
}

/* Must be called with afw_fd_lock() held. */
static void fds_ensure_init(void) {
    if (g_fds_init) return;
    memset(g_fds, 0, sizeof g_fds);
    g_fds[0].kind = FD_STDIO; g_fds[0].std_fd = 0; g_fds[0].os = AFW_OS_FILE_INVALID; g_fds[0].flags = AFW_O_RDONLY | LNX_O_LARGEFILE;
    g_fds[1].kind = FD_STDIO; g_fds[1].std_fd = 1; g_fds[1].os = AFW_OS_FILE_INVALID; g_fds[1].flags = AFW_O_WRONLY | LNX_O_LARGEFILE;
    g_fds[2].kind = FD_STDIO; g_fds[2].std_fd = 2; g_fds[2].os = AFW_OS_FILE_INVALID; g_fds[2].flags = AFW_O_WRONLY | LNX_O_LARGEFILE;
    g_fds_init = 1;
}

static int valid_fd_locked(int64_t fd) {
    return fd >= 0 && fd < AFW_MAX_FDS && g_fds[fd].kind != FD_NONE;
}

static int is_abs_path(const char *p) {
    if (!p || !p[0]) return 0;
    if (p[0] == '/' || p[0] == '\\') return 1;
    if (((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) &&
        p[1] == ':' && (p[2] == '/' || p[2] == '\\'))
        return 1;
    return 0;
}

/* Validate dirfd for *at() syscalls when path is relative. Returns 0 or -errno. */
static int check_dirfd(int64_t dirfd, const char *path) {
    if (is_abs_path(path) || (int)dirfd == LNX_AT_FDCWD) return 0;
    afw_fd_lock();
    fds_ensure_init();
    if (!valid_fd_locked(dirfd)) {
        afw_fd_unlock();
        return -LNX_EBADF;
    }
    afw_fd_unlock();
    return -LNX_ENOSYS;   /* relative paths against non-AT_FDCWD directory fds: not yet */
}

static void fill_lnx_stat(const afw_os_stat_info *src, afw_lnx_stat *dst) {
    memset(dst, 0, sizeof *dst);
    dst->st_dev      = src->dev;
    dst->st_ino      = src->ino;
    dst->st_nlink    = src->nlink ? src->nlink : 1;
    dst->st_mode     = src->mode;
    dst->st_uid      = 10000;
    dst->st_gid      = 10000;
    dst->st_size     = src->size;
    dst->st_blksize  = 4096;
    dst->st_blocks   = (src->size > 0 && src->size <= INT64_MAX - 511) ? (src->size + 511) / 512 : 0;
    dst->st_atime_s  = src->atime_s; dst->st_atime_ns = src->atime_ns;
    dst->st_mtime_s  = src->mtime_s; dst->st_mtime_ns = src->mtime_ns;
    dst->st_ctime_s  = src->ctime_s; dst->st_ctime_ns = src->ctime_ns;
}

int64_t afw_fd_openat(int64_t dirfd, const char *path, int64_t flags, uint64_t mode) {
    int acc = (int)(flags & AFW_O_ACCMODE);
    int os_flags, rc, slot = -1, i, vkind;
    const char *vbuf = NULL;
    size_t vlen = 0;
    afw_os_file f = AFW_OS_FILE_INVALID;

    if (!path) return -LNX_EFAULT;
    if (path[0] == '\0') return -LNX_ENOENT;
    if (acc == 3 || (flags & ~(int64_t)LNX_SUPPORTED_OPEN_FLAGS) != 0)
        return -LNX_EINVAL;
    rc = check_dirfd(dirfd, path);
    if (rc != 0) return rc;

    vkind = match_virtual_path(path, &vbuf, &vlen);
    if (vkind != 0) {
        if (flags & AFW_O_DIRECTORY) return -20; /* ENOTDIR */
        if (vkind == FD_MEMBUF && acc != AFW_O_RDONLY) return -13; /* EACCES */
        afw_fd_lock();
        fds_ensure_init();
        for (i = 0; i < AFW_MAX_FDS; i++) {
            if (g_fds[i].kind == FD_NONE) { slot = i; break; }
        }
        if (slot < 0) {
            afw_fd_unlock();
            return -LNX_EMFILE;
        }
        memset(&g_fds[slot], 0, sizeof g_fds[slot]);
        g_fds[slot].kind    = vkind;
        g_fds[slot].std_fd  = -1;
        g_fds[slot].os      = AFW_OS_FILE_INVALID;
        g_fds[slot].flags   = (int)(flags & LNX_F_STATUS_STORED_MASK) | LNX_O_LARGEFILE;
        g_fds[slot].cloexec = (flags & LNX_O_CLOEXEC) ? 1 : 0;
        g_fds[slot].mem_buf = vbuf;
        g_fds[slot].mem_len = vlen;
        g_fds[slot].mem_pos = 0;
        g_fds[slot].mem_owned = 0;
        afw_fd_unlock();
        return slot;
    }

    os_flags = (int)(flags & (AFW_O_ACCMODE | AFW_O_CREAT | AFW_O_EXCL |
                              AFW_O_TRUNC | AFW_O_APPEND | AFW_O_DIRECTORY |
                              AFW_O_NOFOLLOW));
    rc = afw_os_open(path, os_flags, (uint32_t)mode, &f);
    if (rc != 0) return rc;

    afw_fd_lock();
    fds_ensure_init();
    for (i = 0; i < AFW_MAX_FDS; i++) {
        if (g_fds[i].kind == FD_NONE) { slot = i; break; }
    }
    if (slot < 0) {
        afw_fd_unlock();
        (void)afw_os_close(f);
        return -LNX_EMFILE;
    }
    memset(&g_fds[slot], 0, sizeof g_fds[slot]);
    g_fds[slot].kind    = FD_FILE;
    g_fds[slot].std_fd  = -1;
    g_fds[slot].os      = f;
    g_fds[slot].flags   = (int)(flags & LNX_F_STATUS_STORED_MASK) | LNX_O_LARGEFILE;
    g_fds[slot].cloexec = (flags & LNX_O_CLOEXEC) ? 1 : 0;
    afw_fd_unlock();
    return slot;
}

int64_t afw_fd_close(int64_t fd) {
    int rc = 0;
    afw_fd_lock();
    fds_ensure_init();
    if (!valid_fd_locked(fd)) {
        afw_fd_unlock();
        return -LNX_EBADF;
    }
    if (g_fds[fd].kind == FD_FILE) {
        afw_os_file f = g_fds[fd].os;
        rc = afw_os_close(f);
    } else if (g_fds[fd].kind == FD_MEMBUF && g_fds[fd].mem_owned) {
        free((void *)g_fds[fd].mem_buf);
    }
    /* Clear descriptor slot (for FD_STDIO we leave host handles intact for the loader). */
    memset(&g_fds[fd], 0, sizeof g_fds[fd]);
    g_fds[fd].kind = FD_NONE;
    g_fds[fd].std_fd = -1;
    g_fds[fd].os = AFW_OS_FILE_INVALID;
    afw_fd_unlock();
    return rc;
}

int64_t afw_fd_read(int64_t fd, void *buf, uint64_t len) {
    int kind, std_fd, acc;
    int64_t r;
    size_t chunk;

    if (len > 0 && !buf) return -LNX_EFAULT;
    chunk = len > LNX_MAX_RW_COUNT ? LNX_MAX_RW_COUNT : (size_t)len;

    afw_fd_lock();
    fds_ensure_init();
    if (!valid_fd_locked(fd)) { afw_fd_unlock(); return -LNX_EBADF; }
    acc = g_fds[fd].flags & AFW_O_ACCMODE;
    if (acc == AFW_O_WRONLY) { afw_fd_unlock(); return -LNX_EBADF; }
    kind = g_fds[fd].kind;
    std_fd = g_fds[fd].std_fd;
    if (kind == FD_FILE) {
        r = chunk ? afw_os_read(g_fds[fd].os, buf, chunk) : 0;
        afw_fd_unlock();
        return r;
    }
    if (kind == FD_DEVNULL) {
        afw_fd_unlock();
        return 0;
    }
    if (kind == FD_MEMBUF) {
        size_t avail = g_fds[fd].mem_pos < g_fds[fd].mem_len
                       ? g_fds[fd].mem_len - g_fds[fd].mem_pos : 0;
        size_t n = chunk < avail ? chunk : avail;
        if (n > 0) {
            memcpy(buf, g_fds[fd].mem_buf + g_fds[fd].mem_pos, n);
            g_fds[fd].mem_pos += n;
        }
        afw_fd_unlock();
        return (int64_t)n;
    }
    afw_fd_unlock();
    if (std_fd != 0) return -LNX_EBADF;
    return chunk ? afw_os_stdio_read(buf, chunk) : 0;
}

int64_t afw_fd_write(int64_t fd, const void *buf, uint64_t len) {
    int kind, std_fd, acc, append;
    int64_t r;
    size_t chunk;

    if (len > 0 && !buf) return -LNX_EFAULT;
    chunk = len > LNX_MAX_RW_COUNT ? LNX_MAX_RW_COUNT : (size_t)len;

    afw_fd_lock();
    fds_ensure_init();
    if (!valid_fd_locked(fd)) { afw_fd_unlock(); return -LNX_EBADF; }
    acc = g_fds[fd].flags & AFW_O_ACCMODE;
    if (acc == AFW_O_RDONLY) { afw_fd_unlock(); return -LNX_EBADF; }
    kind = g_fds[fd].kind;
    std_fd = g_fds[fd].std_fd;
    append = (g_fds[fd].flags & AFW_O_APPEND) != 0;
    if (kind == FD_FILE) {
        r = chunk ? afw_os_write(g_fds[fd].os, buf, chunk, append) : 0;
        afw_fd_unlock();
        return r;
    }
    if (kind == FD_DEVNULL) {
        afw_fd_unlock();
        return (int64_t)chunk;
    }
    if (kind == FD_MEMBUF) {
        afw_fd_unlock();
        return -LNX_EBADF;
    }
    if (std_fd != 1 && std_fd != 2) { afw_fd_unlock(); return -LNX_EBADF; }
    r = chunk ? afw_os_stdio_write(std_fd, buf, chunk, append) : 0;
    afw_fd_unlock();
    return r;
}

int64_t afw_fd_readv(int64_t fd, const uint64_t *iov, int64_t cnt) {
    int64_t total = 0, i;
    if (cnt < 0 || cnt > 1024) return -LNX_EINVAL;
    if (cnt > 0 && !iov) return -LNX_EFAULT;
    for (i = 0; i < cnt; i++) {
        uint64_t len = iov[2 * i + 1];
        uint64_t rem = (uint64_t)LNX_MAX_RW_COUNT - (uint64_t)total;
        int64_t r;
        if (!len) continue;
        if (rem == 0) break;
        if (len > rem) len = rem;
        r = afw_fd_read(fd, (void *)(uintptr_t)iov[2 * i], len);
        if (r < 0) return total ? total : r;
        total += r;
        if ((uint64_t)r < len) break;
    }
    return total;
}

int64_t afw_fd_writev(int64_t fd, const uint64_t *iov, int64_t cnt) {
    int64_t total = 0, i;
    if (cnt < 0 || cnt > 1024) return -LNX_EINVAL;
    if (cnt > 0 && !iov) return -LNX_EFAULT;
    for (i = 0; i < cnt; i++) {
        uint64_t len = iov[2 * i + 1];
        uint64_t rem = (uint64_t)LNX_MAX_RW_COUNT - (uint64_t)total;
        int64_t r;
        if (!len) continue;
        if (rem == 0) break;
        if (len > rem) len = rem;
        r = afw_fd_write(fd, (const void *)(uintptr_t)iov[2 * i], len);
        if (r < 0) return total ? total : r;
        total += r;
        if ((uint64_t)r < len) break;
    }
    return total;
}

int64_t afw_fd_lseek(int64_t fd, int64_t off, int64_t whence) {
    int64_t r;
    if (whence != AFW_SEEK_SET && whence != AFW_SEEK_CUR && whence != AFW_SEEK_END)
        return -LNX_EINVAL;
    afw_fd_lock();
    fds_ensure_init();
    if (!valid_fd_locked(fd)) { afw_fd_unlock(); return -LNX_EBADF; }
    if (g_fds[fd].kind == FD_STDIO) { afw_fd_unlock(); return -LNX_ESPIPE; }
    if (g_fds[fd].kind == FD_DEVNULL) { afw_fd_unlock(); return 0; }
    if (g_fds[fd].kind == FD_MEMBUF) {
        int64_t base = (whence == AFW_SEEK_SET) ? 0
                     : (whence == AFW_SEEK_CUR) ? (int64_t)g_fds[fd].mem_pos
                                                : (int64_t)g_fds[fd].mem_len;
        int64_t np = base + off;
        if (np < 0) { afw_fd_unlock(); return -LNX_EINVAL; }
        g_fds[fd].mem_pos = (size_t)np;
        afw_fd_unlock();
        return np;
    }
    r = afw_os_lseek(g_fds[fd].os, off, (int)whence);
    afw_fd_unlock();
    return r;
}

int64_t afw_fd_fstat(int64_t fd, void *statbuf) {
    afw_os_stat_info info;
    afw_lnx_stat st;
    int rc;
    if (!statbuf) return -LNX_EFAULT;
    afw_fd_lock();
    fds_ensure_init();
    if (!valid_fd_locked(fd)) { afw_fd_unlock(); return -LNX_EBADF; }
    if (g_fds[fd].kind == FD_STDIO) {
        rc = afw_os_stdio_stat(g_fds[fd].std_fd, &info);
    } else if (g_fds[fd].kind == FD_DEVNULL) {
        memset(&info, 0, sizeof info);
        info.mode = 0020666u; /* S_IFCHR | 0666 */
        info.nlink = 1;
        rc = 0;
    } else if (g_fds[fd].kind == FD_MEMBUF) {
        memset(&info, 0, sizeof info);
        info.mode = 0100444u; /* S_IFREG | 0444 */
        info.nlink = 1;
        info.size = (int64_t)g_fds[fd].mem_len;
        rc = 0;
    } else {
        rc = afw_os_fstat(g_fds[fd].os, &info);
    }
    afw_fd_unlock();
    if (rc != 0) return rc;
    fill_lnx_stat(&info, &st);
    memcpy(statbuf, &st, sizeof st);
    return 0;
}

int64_t afw_fd_newfstatat(int64_t dirfd, const char *path, void *statbuf, int64_t flags) {
    afw_os_stat_info info;
    afw_lnx_stat st;
    int rc, vkind;
    const char *vbuf = NULL;
    size_t vlen = 0;
    if (!path || !statbuf) return -LNX_EFAULT;
    if (flags & ~(int64_t)(LNX_AT_SYMLINK_NOFOLLOW | LNX_AT_EMPTY_PATH))
        return -LNX_EINVAL;
    if ((flags & LNX_AT_EMPTY_PATH) && path[0] == '\0')
        return afw_fd_fstat(dirfd, statbuf);
    if (path[0] == '\0') return -LNX_ENOENT;
    rc = check_dirfd(dirfd, path);
    if (rc != 0) return rc;
    vkind = match_virtual_path(path, &vbuf, &vlen);
    if (vkind != 0) {
        memset(&info, 0, sizeof info);
        info.mode = (vkind == FD_DEVNULL) ? 0020666u : 0100444u;
        info.nlink = 1;
        info.size = (vkind == FD_MEMBUF) ? (int64_t)vlen : 0;
        fill_lnx_stat(&info, &st);
        memcpy(statbuf, &st, sizeof st);
        return 0;
    }
    rc = afw_os_stat(path, (flags & LNX_AT_SYMLINK_NOFOLLOW) != 0, &info);
    if (rc != 0) return rc;
    fill_lnx_stat(&info, &st);
    memcpy(statbuf, &st, sizeof st);
    return 0;
}

int64_t afw_fd_unlinkat(int64_t dirfd, const char *path, int64_t flags) {
    int rc;
    if (!path) return -LNX_EFAULT;
    if (path[0] == '\0') return -LNX_ENOENT;
    if (flags & ~(int64_t)LNX_AT_REMOVEDIR) return -LNX_EINVAL;
    rc = check_dirfd(dirfd, path);
    if (rc != 0) return rc;
    return afw_os_unlink(path, (flags & LNX_AT_REMOVEDIR) != 0);
}

int64_t afw_fd_fcntl(int64_t fd, int64_t cmd, int64_t arg) {
    int64_t r;
    afw_fd_lock();
    fds_ensure_init();
    if (!valid_fd_locked(fd)) { afw_fd_unlock(); return -LNX_EBADF; }
    switch (cmd) {
    case LNX_F_GETFD:
        r = g_fds[fd].cloexec ? 1 : 0;
        break;
    case LNX_F_SETFD:
        g_fds[fd].cloexec = (arg & 1) ? 1 : 0;
        r = 0;
        break;
    case LNX_F_GETFL:
        r = g_fds[fd].flags;
        break;
    case LNX_F_SETFL: {
        int want_append, rc;
        if (arg & ~(int64_t)LNX_SUPPORTED_OPEN_FLAGS) {
            r = -LNX_EINVAL;
            break;
        }
        want_append = (arg & AFW_O_APPEND) != 0;
        if (g_fds[fd].kind == FD_FILE)
            rc = afw_os_set_append(g_fds[fd].os, want_append);
        else if (g_fds[fd].kind == FD_STDIO)
            rc = afw_os_stdio_set_append(g_fds[fd].std_fd, want_append);
        else
            rc = 0;
        if (rc != 0) {
            r = rc;
            break;
        }
        g_fds[fd].flags = (g_fds[fd].flags & ~AFW_O_APPEND) | (int)(arg & AFW_O_APPEND);
        r = 0;
        break;
    }
    default:
        r = -LNX_ENOSYS;
        break;
    }
    afw_fd_unlock();
    return r;
}

int64_t afw_fd_pread(int64_t fd, void *buf, uint64_t len, int64_t off) {
    int acc, kind;
    int64_t saved, r;
    size_t chunk;

    if (off < 0) return -LNX_EINVAL;
    if (len > 0 && !buf) return -LNX_EFAULT;
    chunk = len > LNX_MAX_RW_COUNT ? LNX_MAX_RW_COUNT : (size_t)len;

    afw_fd_lock();
    fds_ensure_init();
    if (!valid_fd_locked(fd)) { afw_fd_unlock(); return -LNX_EBADF; }
    acc = g_fds[fd].flags & AFW_O_ACCMODE;
    if (acc == AFW_O_WRONLY) { afw_fd_unlock(); return -LNX_EBADF; }
    kind = g_fds[fd].kind;
    if (kind == FD_STDIO) { afw_fd_unlock(); return -LNX_ESPIPE; }
    if (kind == FD_DEVNULL) { afw_fd_unlock(); return 0; }
    if (kind == FD_MEMBUF) {
        size_t pos = (uint64_t)off < g_fds[fd].mem_len ? (size_t)off : g_fds[fd].mem_len;
        size_t avail = g_fds[fd].mem_len - pos;
        size_t n = chunk < avail ? chunk : avail;
        if (n > 0) memcpy(buf, g_fds[fd].mem_buf + pos, n);
        afw_fd_unlock();
        return (int64_t)n;
    }
    saved = afw_os_lseek(g_fds[fd].os, 0, AFW_SEEK_CUR);
    if (saved < 0) { afw_fd_unlock(); return saved; }
    r = afw_os_lseek(g_fds[fd].os, off, AFW_SEEK_SET);
    if (r < 0) { afw_fd_unlock(); return r; }
    r = chunk ? afw_os_read(g_fds[fd].os, buf, chunk) : 0;
    (void)afw_os_lseek(g_fds[fd].os, saved, AFW_SEEK_SET);
    afw_fd_unlock();
    return r;
}

int64_t afw_fd_pwrite(int64_t fd, const void *buf, uint64_t len, int64_t off) {
    int acc, kind;
    int64_t saved, r;
    size_t chunk;

    if (off < 0) return -LNX_EINVAL;
    if (len > 0 && !buf) return -LNX_EFAULT;
    chunk = len > LNX_MAX_RW_COUNT ? LNX_MAX_RW_COUNT : (size_t)len;

    afw_fd_lock();
    fds_ensure_init();
    if (!valid_fd_locked(fd)) { afw_fd_unlock(); return -LNX_EBADF; }
    acc = g_fds[fd].flags & AFW_O_ACCMODE;
    if (acc == AFW_O_RDONLY) { afw_fd_unlock(); return -LNX_EBADF; }
    kind = g_fds[fd].kind;
    if (kind == FD_STDIO) { afw_fd_unlock(); return -LNX_ESPIPE; }
    if (kind == FD_DEVNULL) { afw_fd_unlock(); return (int64_t)chunk; }
    if (kind == FD_MEMBUF) { afw_fd_unlock(); return -LNX_EBADF; }
    saved = afw_os_lseek(g_fds[fd].os, 0, AFW_SEEK_CUR);
    if (saved < 0) { afw_fd_unlock(); return saved; }
    r = afw_os_lseek(g_fds[fd].os, off, AFW_SEEK_SET);
    if (r < 0) { afw_fd_unlock(); return r; }
    r = chunk ? afw_os_write(g_fds[fd].os, buf, chunk, 0) : 0;
    (void)afw_os_lseek(g_fds[fd].os, saved, AFW_SEEK_SET);
    afw_fd_unlock();
    return r;
}

int64_t afw_fd_faccessat(int64_t dirfd, const char *path, int64_t mode, int64_t flags) {
    afw_os_stat_info info;
    int rc;
    if (!path) return -LNX_EFAULT;
    if (path[0] == '\0') return -LNX_ENOENT;
    if (mode & ~(int64_t)7) return -LNX_EINVAL;
    if (flags & ~(int64_t)(LNX_AT_SYMLINK_NOFOLLOW | 0x200)) return -LNX_EINVAL;
    rc = check_dirfd(dirfd, path);
    if (rc != 0) return rc;
    if (match_virtual_path(path, NULL, NULL) != 0) return 0;
    rc = afw_os_stat(path, (flags & LNX_AT_SYMLINK_NOFOLLOW) != 0, &info);
    return rc == 0 ? 0 : rc;
}

int afw_fd_inspect_for_mmap_locked(int fd, intptr_t *os_out, int64_t *size_out) {
    afw_os_stat_info st;
    int rc;
    fds_ensure_init();
    if (!valid_fd_locked(fd)) return -LNX_EBADF;
    if (g_fds[fd].kind != FD_FILE) return -19; /* ENODEV: stdio is not mappable */
    if (g_fds[fd].flags & AFW_O_DIRECTORY) return -19; /* ENODEV: directory */
    if ((g_fds[fd].flags & AFW_O_ACCMODE) == AFW_O_WRONLY) return -13; /* EACCES: write-only */
    rc = afw_os_fstat(g_fds[fd].os, &st);
    if (rc != 0) return rc;
    if ((st.mode & 0170000u) != 0100000u) return -19; /* ENODEV: not S_IFREG */
    if (st.size < 0) return -LNX_EINVAL;
    if (os_out) *os_out = (intptr_t)g_fds[fd].os;
    if (size_out) *size_out = st.size;
    return 0;
}
