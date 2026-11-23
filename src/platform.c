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

/* ---- Windows OS file primitives & FD lock (Rule 8: Win32 stays here) ---- */
static SRWLOCK g_fd_srw = SRWLOCK_INIT;
void afw_fd_lock(void)   { AcquireSRWLockExclusive(&g_fd_srw); }
void afw_fd_unlock(void) { ReleaseSRWLockExclusive(&g_fd_srw); }

static int win_err_to_lnx(DWORD e) {
    switch (e) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:      return -2;   /* ENOENT */
    case ERROR_TOO_MANY_OPEN_FILES:return -24;  /* EMFILE */
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
    case ERROR_WRITE_PROTECT:      return -13;  /* EACCES */
    case ERROR_INVALID_HANDLE:     return -9;   /* EBADF */
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:        return -12;  /* ENOMEM */
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:     return -17;  /* EEXIST */
    case ERROR_DIRECTORY:          return -20;  /* ENOTDIR */
    case ERROR_DIR_NOT_EMPTY:      return -39;  /* ENOTEMPTY */
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:   return -28;  /* ENOSPC */
    case ERROR_FILENAME_EXCED_RANGE:return -36; /* ENAMETOOLONG */
    case ERROR_NEGATIVE_SEEK:
    case ERROR_INVALID_PARAMETER:
    case ERROR_INVALID_NAME:       return -22;  /* EINVAL */
    case ERROR_BROKEN_PIPE:        return -32;  /* EPIPE */
    default:                       return -5;   /* EIO */
    }
}

static const wchar_t *utf8_to_wide(const char *path, wchar_t *sbuf, size_t scap, wchar_t **heap) {
    int need;
    wchar_t *w, *p;
    *heap = NULL;
    if (!path) return NULL;
    if (strcmp(path, "/dev/null") == 0) return L"NUL";
    need = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (need <= 0) return NULL;
    if ((size_t)need <= scap) {
        w = sbuf;
    } else {
        w = (wchar_t *)malloc((size_t)need * sizeof(wchar_t));
        if (!w) return NULL;
        *heap = w;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, w, need) <= 0) {
        free(*heap); *heap = NULL; return NULL;
    }
    for (p = w; *p; p++) if (*p == L'/') *p = L'\\';
    return w;
}

static void filetime_to_unix(FILETIME ft, int64_t *sec, int64_t *nsec) {
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    if (t < 116444736000000000ULL) { *sec = 0; *nsec = 0; return; }
    t -= 116444736000000000ULL;
    *sec = (int64_t)(t / 10000000ULL);
    *nsec = (int64_t)((t % 10000000ULL) * 100ULL);
}

static void fill_stat_from_bhfi(const BY_HANDLE_FILE_INFORMATION *bi, afw_os_stat_info *out) {
    memset(out, 0, sizeof *out);
    out->dev = bi->dwVolumeSerialNumber;
    out->ino = ((uint64_t)bi->nFileIndexHigh << 32) | bi->nFileIndexLow;
    out->nlink = bi->nNumberOfLinks ? bi->nNumberOfLinks : 1;
    if (bi->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        out->mode = 0040755u;
    else
        out->mode = (bi->dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 0100444u : 0100644u;
    out->size = (int64_t)(((uint64_t)bi->nFileSizeHigh << 32) | bi->nFileSizeLow);
    filetime_to_unix(bi->ftLastAccessTime, &out->atime_s, &out->atime_ns);
    filetime_to_unix(bi->ftLastWriteTime,  &out->mtime_s, &out->mtime_ns);
    filetime_to_unix(bi->ftCreationTime,   &out->ctime_s, &out->ctime_ns);
}

static int win_is_symlink_handle(HANDLE h) {
    FILE_ATTRIBUTE_TAG_INFO tag;
    if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof tag))
        return 0;
    if (!(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return 0;
    return tag.ReparseTag == IO_REPARSE_TAG_SYMLINK ||
           tag.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT;
}

int afw_os_open(const char *path, int flags, uint32_t mode, afw_os_file *out) {
    wchar_t wbuf[512], *wheap = NULL;
    const wchar_t *w;
    DWORD access, disp, share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD create_flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS;
    int acc = flags & AFW_O_ACCMODE;
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION bi;
    (void)mode;
    if (!path || !out) return -14;
    if (acc == AFW_O_RDONLY) access = GENERIC_READ;
    else if (acc == AFW_O_WRONLY) access = GENERIC_WRITE;
    else if (acc == AFW_O_RDWR) access = GENERIC_READ | GENERIC_WRITE;
    else return -22;

    if ((flags & AFW_O_CREAT) && (flags & AFW_O_EXCL)) disp = CREATE_NEW;
    else if ((flags & AFW_O_CREAT) && (flags & AFW_O_TRUNC)) disp = CREATE_ALWAYS;
    else if (flags & AFW_O_CREAT) disp = OPEN_ALWAYS;
    else if (flags & AFW_O_TRUNC) disp = TRUNCATE_EXISTING;
    else disp = OPEN_EXISTING;

    w = utf8_to_wide(path, wbuf, sizeof wbuf / sizeof wbuf[0], &wheap);
    if (!w) return -22;

    if (flags & AFW_O_NOFOLLOW) {
        /* Guard O_TRUNC | O_NOFOLLOW before CreateFileW can truncate a symlink. */
        if (flags & AFW_O_TRUNC) {
            HANDLE probe = CreateFileW(w, FILE_READ_ATTRIBUTES, share, NULL, OPEN_EXISTING,
                                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            if (probe != INVALID_HANDLE_VALUE) {
                int is_lnk = win_is_symlink_handle(probe);
                CloseHandle(probe);
                if (is_lnk) { free(wheap); return -40; /* ELOOP */ }
            }
        }
        create_flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }

    h = CreateFileW(w, access, share, NULL, disp, create_flags, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED && (acc != AFW_O_RDONLY || (flags & (AFW_O_TRUNC | AFW_O_CREAT)))) {
            DWORD a = GetFileAttributesW(w);
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
                free(wheap); return -21; /* EISDIR */
            }
        }
        free(wheap);
        return win_err_to_lnx(err);
    }
    free(wheap);
    if ((flags & AFW_O_NOFOLLOW) && win_is_symlink_handle(h)) {
        CloseHandle(h);
        return -40; /* ELOOP */
    }
    if (GetFileInformationByHandle(h, &bi)) {
        int is_dir = (bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if ((flags & AFW_O_DIRECTORY) && !is_dir) { CloseHandle(h); return -20; /* ENOTDIR */ }
        if (is_dir && (acc != AFW_O_RDONLY || (flags & (AFW_O_TRUNC | AFW_O_CREAT)))) {
            CloseHandle(h); return -21; /* EISDIR */
        }
    }
    *out = (afw_os_file)h;
    return 0;
}

int afw_os_close(afw_os_file f) {
    if (f == AFW_OS_FILE_INVALID) return -9;
    return CloseHandle((HANDLE)f) ? 0 : win_err_to_lnx(GetLastError());
}

int64_t afw_os_read(afw_os_file f, void *buf, size_t len) {
    DWORD chunk, got = 0;
    if (f == AFW_OS_FILE_INVALID) return -9;
    if (len == 0) return 0;
    if (!buf) return -14;
    chunk = len > 0x7ffff000u ? 0x7ffff000u : (DWORD)len;
    if (!ReadFile((HANDLE)f, buf, chunk, &got, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE) return 0;
        return win_err_to_lnx(err);
    }
    return (int64_t)got;
}

int64_t afw_os_write(afw_os_file f, const void *buf, size_t len, int append) {
    DWORD chunk, done = 0;
    if (f == AFW_OS_FILE_INVALID) return -9;
    if (len == 0) return 0;
    if (!buf) return -14;
    if (append) {
        LARGE_INTEGER z;
        z.QuadPart = 0;
        if (!SetFilePointerEx((HANDLE)f, z, NULL, FILE_END))
            return win_err_to_lnx(GetLastError());
    }
    chunk = len > 0x7ffff000u ? 0x7ffff000u : (DWORD)len;
    if (!WriteFile((HANDLE)f, buf, chunk, &done, NULL))
        return win_err_to_lnx(GetLastError());
    return (int64_t)done;
}

int64_t afw_os_lseek(afw_os_file f, int64_t off, int whence) {
    DWORD method, ftype;
    LARGE_INTEGER dist, pos;
    if (f == AFW_OS_FILE_INVALID) return -9;
    if (whence == AFW_SEEK_SET) { if (off < 0) return -22; method = FILE_BEGIN; }
    else if (whence == AFW_SEEK_CUR) method = FILE_CURRENT;
    else if (whence == AFW_SEEK_END) method = FILE_END;
    else return -22;
    ftype = GetFileType((HANDLE)f);
    if (ftype == FILE_TYPE_CHAR || ftype == FILE_TYPE_PIPE) return -29; /* ESPIPE */
    dist.QuadPart = off;
    if (!SetFilePointerEx((HANDLE)f, dist, &pos, method))
        return win_err_to_lnx(GetLastError());
    return (int64_t)pos.QuadPart;
}

int afw_os_fstat(afw_os_file f, afw_os_stat_info *out) {
    BY_HANDLE_FILE_INFORMATION bi;
    DWORD ftype;
    if (f == AFW_OS_FILE_INVALID) return -9;
    if (!out) return -14;
    ftype = GetFileType((HANDLE)f);
    if (ftype == FILE_TYPE_CHAR || ftype == FILE_TYPE_PIPE) {
        memset(out, 0, sizeof *out);
        out->nlink = 1;
        out->mode = (ftype == FILE_TYPE_CHAR) ? 0020666u : 0010600u;
        return 0;
    }
    if (!GetFileInformationByHandle((HANDLE)f, &bi))
        return win_err_to_lnx(GetLastError());
    fill_stat_from_bhfi(&bi, out);
    return 0;
}

int afw_os_stat(const char *path, int nofollow, afw_os_stat_info *out) {
    wchar_t wbuf[512], *wheap = NULL;
    const wchar_t *w;
    DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD attr_flags = FILE_FLAG_BACKUP_SEMANTICS | (nofollow ? FILE_FLAG_OPEN_REPARSE_POINT : 0);
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION bi;
    if (!path || !out) return -14;
    w = utf8_to_wide(path, wbuf, sizeof wbuf / sizeof wbuf[0], &wheap);
    if (!w) return -22;
    h = CreateFileW(w, FILE_READ_ATTRIBUTES, share, NULL, OPEN_EXISTING, attr_flags, NULL);
    free(wheap);
    if (h == INVALID_HANDLE_VALUE)
        return win_err_to_lnx(GetLastError());
    if (!GetFileInformationByHandle(h, &bi)) {
        DWORD err = GetLastError();
        CloseHandle(h);
        return win_err_to_lnx(err);
    }
    fill_stat_from_bhfi(&bi, out);
    if (nofollow && win_is_symlink_handle(h))
        out->mode = 0120777u; /* S_IFLNK | 0777 */
    CloseHandle(h);
    return 0;
}

int afw_os_unlink(const char *path, int rmdir_flag) {
    wchar_t wbuf[512], *wheap = NULL;
    const wchar_t *w;
    BOOL ok;
    if (!path) return -14;
    w = utf8_to_wide(path, wbuf, sizeof wbuf / sizeof wbuf[0], &wheap);
    if (!w) return -22;
    ok = rmdir_flag ? RemoveDirectoryW(w) : DeleteFileW(w);
    if (!ok) {
        DWORD err = GetLastError();
        if (!rmdir_flag && err == ERROR_ACCESS_DENIED) {
            DWORD a = GetFileAttributesW(w);
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
                free(wheap); return -21; /* EISDIR */
            }
        }
        free(wheap);
        return win_err_to_lnx(err);
    }
    free(wheap);
    return 0;
}

#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif

int afw_os_symlink(const char *target, const char *linkpath) {
    wchar_t tbuf[512], lbuf[512], *theap = NULL, *lheap = NULL;
    const wchar_t *wt, *wl;
    DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    BOOL ok;
    if (!target || !linkpath) return -14;
    wt = utf8_to_wide(target, tbuf, sizeof tbuf / sizeof tbuf[0], &theap);
    wl = utf8_to_wide(linkpath, lbuf, sizeof lbuf / sizeof lbuf[0], &lheap);
    if (!wt || !wl) { free(theap); free(lheap); return -22; }
    ok = CreateSymbolicLinkW(wl, wt, flags);
    if (!ok && GetLastError() == ERROR_INVALID_PARAMETER)
        ok = CreateSymbolicLinkW(wl, wt, 0);
    if (!ok) {
        DWORD err = GetLastError();
        free(theap); free(lheap);
        return win_err_to_lnx(err);
    }
    free(theap); free(lheap);
    return 0;
}

static HANDLE std_handle(int std_fd) {
    if (std_fd == 0) return GetStdHandle(STD_INPUT_HANDLE);
    if (std_fd == 1) return GetStdHandle(STD_OUTPUT_HANDLE);
    if (std_fd == 2) return GetStdHandle(STD_ERROR_HANDLE);
    return INVALID_HANDLE_VALUE;
}

int64_t afw_os_stdio_read(void *buf, size_t len) {
    HANDLE h = std_handle(0);
    if (!h || h == INVALID_HANDLE_VALUE) return -9;
    return afw_os_read((afw_os_file)h, buf, len);
}

int64_t afw_os_stdio_write(int std_fd, const void *buf, size_t len) {
    HANDLE h = std_handle(std_fd);
    if (std_fd != 1 && std_fd != 2) return -9;
    if (!h || h == INVALID_HANDLE_VALUE) return -9;
    return afw_os_write((afw_os_file)h, buf, len, 0);
}

int afw_os_stdio_stat(int std_fd, afw_os_stat_info *out) {
    HANDLE h = std_handle(std_fd);
    if (!h || h == INVALID_HANDLE_VALUE) return -9;
    return afw_os_fstat((afw_os_file)h, out);
}

#else
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* ---- Linux host OS file primitives & FD lock ---- */
static pthread_mutex_t g_fd_mu = PTHREAD_MUTEX_INITIALIZER;
void afw_fd_lock(void)   { pthread_mutex_lock(&g_fd_mu); }
void afw_fd_unlock(void) { pthread_mutex_unlock(&g_fd_mu); }

static void fill_stat_from_posix(const struct stat *st, afw_os_stat_info *out) {
    memset(out, 0, sizeof *out);
    out->dev = (uint64_t)st->st_dev;
    out->ino = (uint64_t)st->st_ino;
    out->nlink = (uint64_t)st->st_nlink;
    out->mode = (uint32_t)st->st_mode;
    out->size = (int64_t)st->st_size;
    out->atime_s = (int64_t)st->st_atim.tv_sec;  out->atime_ns = (int64_t)st->st_atim.tv_nsec;
    out->mtime_s = (int64_t)st->st_mtim.tv_sec;  out->mtime_ns = (int64_t)st->st_mtim.tv_nsec;
    out->ctime_s = (int64_t)st->st_ctim.tv_sec;  out->ctime_ns = (int64_t)st->st_ctim.tv_nsec;
}

int afw_os_open(const char *path, int flags, uint32_t mode, afw_os_file *out) {
    int of = 0, acc = flags & AFW_O_ACCMODE, fd;
    if (!path || !out) return -EFAULT;
    if (acc == AFW_O_RDONLY) of = O_RDONLY;
    else if (acc == AFW_O_WRONLY) of = O_WRONLY;
    else if (acc == AFW_O_RDWR) of = O_RDWR;
    else return -EINVAL;
    if (flags & AFW_O_CREAT) of |= O_CREAT;
    if (flags & AFW_O_EXCL) of |= O_EXCL;
    if (flags & AFW_O_TRUNC) of |= O_TRUNC;
    /* Do not set host O_APPEND: afw_os_write handles append under afw_fd_lock()
     * so F_SETFL toggling O_APPEND on/off behaves identically on Linux and Windows. */
    if (flags & AFW_O_DIRECTORY) of |= O_DIRECTORY;
    if (flags & AFW_O_NOFOLLOW) of |= O_NOFOLLOW;
    of |= O_CLOEXEC;
    fd = open(path, of, (mode_t)(mode & 0777u));
    if (fd < 0) return -errno;
    *out = (afw_os_file)fd;
    return 0;
}

int afw_os_close(afw_os_file f) {
    if (f == AFW_OS_FILE_INVALID) return -EBADF;
    return close((int)f) == 0 ? 0 : -errno;
}

int64_t afw_os_read(afw_os_file f, void *buf, size_t len) {
    ssize_t r;
    if (f == AFW_OS_FILE_INVALID) return -EBADF;
    if (len == 0) return 0;
    if (!buf) return -EFAULT;
    if (len > 0x7ffff000u) len = 0x7ffff000u;
    r = read((int)f, buf, len);
    return r < 0 ? -(int64_t)errno : (int64_t)r;
}

int64_t afw_os_write(afw_os_file f, const void *buf, size_t len, int append) {
    ssize_t r;
    if (f == AFW_OS_FILE_INVALID) return -EBADF;
    if (len == 0) return 0;
    if (!buf) return -EFAULT;
    if (len > 0x7ffff000u) len = 0x7ffff000u;
    if (append && lseek((int)f, 0, SEEK_END) < 0 && errno != ESPIPE) return -(int64_t)errno;
    r = write((int)f, buf, len);
    return r < 0 ? -(int64_t)errno : (int64_t)r;
}

int64_t afw_os_lseek(afw_os_file f, int64_t off, int whence) {
    int w;
    off_t r;
    if (f == AFW_OS_FILE_INVALID) return -EBADF;
    if (whence == AFW_SEEK_SET) { if (off < 0) return -EINVAL; w = SEEK_SET; }
    else if (whence == AFW_SEEK_CUR) w = SEEK_CUR;
    else if (whence == AFW_SEEK_END) w = SEEK_END;
    else return -EINVAL;
    r = lseek((int)f, (off_t)off, w);
    return r < 0 ? -(int64_t)errno : (int64_t)r;
}

int afw_os_fstat(afw_os_file f, afw_os_stat_info *out) {
    struct stat st;
    if (f == AFW_OS_FILE_INVALID) return -EBADF;
    if (!out) return -EFAULT;
    if (fstat((int)f, &st) != 0) return -errno;
    fill_stat_from_posix(&st, out);
    return 0;
}

int afw_os_stat(const char *path, int nofollow, afw_os_stat_info *out) {
    struct stat st;
    if (!path || !out) return -EFAULT;
    if ((nofollow ? lstat(path, &st) : stat(path, &st)) != 0) return -errno;
    fill_stat_from_posix(&st, out);
    return 0;
}

int afw_os_unlink(const char *path, int rmdir_flag) {
    if (!path) return -EFAULT;
    if (rmdir_flag) return rmdir(path) == 0 ? 0 : -errno;
    return unlink(path) == 0 ? 0 : -errno;
}

int afw_os_symlink(const char *target, const char *linkpath) {
    if (!target || !linkpath) return -EFAULT;
    return symlink(target, linkpath) == 0 ? 0 : -errno;
}

int64_t afw_os_stdio_read(void *buf, size_t len) {
    return afw_os_read((afw_os_file)0, buf, len);
}

int64_t afw_os_stdio_write(int std_fd, const void *buf, size_t len) {
    if (std_fd != 1 && std_fd != 2) return -EBADF;
    return afw_os_write((afw_os_file)std_fd, buf, len, 0);
}

int afw_os_stdio_stat(int std_fd, afw_os_stat_info *out) {
    if (std_fd < 0 || std_fd > 2) return -EBADF;
    return afw_os_fstat((afw_os_file)std_fd, out);
}
#endif
