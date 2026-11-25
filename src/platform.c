/*
 * platform.c - Memory management for Windows (VirtualAlloc) and Linux (mmap).
 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
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
#include <winioctl.h>
#include <malloc.h>
#include <wchar.h>
#pragma comment(lib, "synchronization.lib")

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

/* ---- Windows OS file primitives & locks (Rule 8: Win32 stays here) ---- */
static SRWLOCK g_fd_srw = SRWLOCK_INIT;
void afw_fd_lock(void)   { AcquireSRWLockExclusive(&g_fd_srw); }
void afw_fd_unlock(void) { ReleaseSRWLockExclusive(&g_fd_srw); }

static SRWLOCK g_libs_srw = SRWLOCK_INIT;
void afw_libs_rdlock(void)   { AcquireSRWLockShared(&g_libs_srw); }
void afw_libs_rdunlock(void) { ReleaseSRWLockShared(&g_libs_srw); }
void afw_libs_wrlock(void)   { AcquireSRWLockExclusive(&g_libs_srw); }
void afw_libs_wrunlock(void) { ReleaseSRWLockExclusive(&g_libs_srw); }

static INIT_ONCE g_dlopen_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_dlopen_cs;
static BOOL CALLBACK win_dlopen_cs_init(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once; (void)param; (void)ctx;
    InitializeCriticalSection(&g_dlopen_cs);
    return TRUE;
}
void afw_dlopen_lock(void) {
    InitOnceExecuteOnce(&g_dlopen_once, win_dlopen_cs_init, NULL, NULL);
    EnterCriticalSection(&g_dlopen_cs);
}
void afw_dlopen_unlock(void) {
    LeaveCriticalSection(&g_dlopen_cs);
}

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

static DWORD win_reparse_tag(HANDLE h) {
    FILE_ATTRIBUTE_TAG_INFO tag;
    if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof tag))
        return 0;
    if (!(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return 0;
    return tag.ReparseTag;
}

static int win_is_symlink_handle(HANDLE h) {
    return win_reparse_tag(h) == IO_REPARSE_TAG_SYMLINK;
}

static int win_is_mount_point_handle(HANDLE h) {
    return win_reparse_tag(h) == IO_REPARSE_TAG_MOUNT_POINT;
}

static int win_probe_is_symlink(const wchar_t *w) {
    HANDLE probe = CreateFileW(w, FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    int is_lnk;
    if (probe == INVALID_HANDLE_VALUE) return 0;
    is_lnk = win_is_symlink_handle(probe);
    CloseHandle(probe);
    return is_lnk;
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
        if ((flags & AFW_O_TRUNC) && win_probe_is_symlink(w)) {
            free(wheap);
            return (flags & AFW_O_DIRECTORY) ? -20 : -40; /* ENOTDIR / ELOOP */
        }
        create_flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }

    h = CreateFileW(w, access, share, NULL, disp, create_flags, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            if ((flags & AFW_O_NOFOLLOW) && win_probe_is_symlink(w)) {
                free(wheap);
                return (flags & AFW_O_DIRECTORY) ? -20 : -40; /* ENOTDIR / ELOOP */
            }
            if (acc != AFW_O_RDONLY || (flags & (AFW_O_TRUNC | AFW_O_CREAT))) {
                DWORD a = GetFileAttributesW(w);
                if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
                    free(wheap); return -21; /* EISDIR */
                }
            }
        }
        free(wheap);
        return win_err_to_lnx(err);
    }
    if (flags & AFW_O_NOFOLLOW) {
        if (win_is_symlink_handle(h)) {
            CloseHandle(h);
            free(wheap);
            return (flags & AFW_O_DIRECTORY) ? -20 : -40; /* ENOTDIR / ELOOP */
        }
        /* Directory junctions / mount points are not symlinks: follow to the
         * mounted directory, matching Linux O_NOFOLLOW on a mount point. */
        if (win_is_mount_point_handle(h)) {
            HANDLE target = CreateFileW(w, access, share, NULL, disp,
                                        create_flags & ~(DWORD)FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            CloseHandle(h);
            if (target == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                free(wheap);
                return win_err_to_lnx(err);
            }
            h = target;
        }
    }
    free(wheap);
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
    OVERLAPPED ov;
    LPOVERLAPPED pov = NULL;
    if (f == AFW_OS_FILE_INVALID) return -9;
    if (len == 0) return 0;
    if (!buf) return -14;
    if (append && GetFileType((HANDLE)f) == FILE_TYPE_DISK) {
        /* Single-syscall kernel-atomic EOF append (NT FILE_WRITE_TO_END_OF_FILE):
         * Microsoft WriteFile spec guarantees atomic seek-to-EOF + write when
         * Offset == OffsetHigh == 0xFFFFFFFF on a synchronous disk handle. */
        memset(&ov, 0, sizeof ov);
        ov.Offset = 0xFFFFFFFFu;
        ov.OffsetHigh = 0xFFFFFFFFu;
        pov = &ov;
    }
    chunk = len > 0x7ffff000u ? 0x7ffff000u : (DWORD)len;
    if (!WriteFile((HANDLE)f, buf, chunk, &done, pov))
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
    int is_lnk = 0;
    if (!path || !out) return -14;
    w = utf8_to_wide(path, wbuf, sizeof wbuf / sizeof wbuf[0], &wheap);
    if (!w) return -22;
    h = CreateFileW(w, FILE_READ_ATTRIBUTES, share, NULL, OPEN_EXISTING, attr_flags, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        free(wheap);
        return win_err_to_lnx(err);
    }
    if (nofollow) {
        is_lnk = win_is_symlink_handle(h);
        if (!is_lnk && win_is_mount_point_handle(h)) {
            /* Mount point / junction: report mounted directory metadata, not S_IFLNK. */
            HANDLE target = CreateFileW(w, FILE_READ_ATTRIBUTES, share, NULL, OPEN_EXISTING,
                                        FILE_FLAG_BACKUP_SEMANTICS, NULL);
            if (target != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
                h = target;
            }
        }
    }
    free(wheap);
    if (!GetFileInformationByHandle(h, &bi)) {
        DWORD err = GetLastError();
        CloseHandle(h);
        return win_err_to_lnx(err);
    }
    fill_stat_from_bhfi(&bi, out);
    if (nofollow && is_lnk)
        out->mode = 0120777u; /* S_IFLNK | 0777 */
    CloseHandle(h);
    return 0;
}

int afw_os_unlink(const char *path, int rmdir_flag) {
    wchar_t wbuf[512], *wheap = NULL;
    const wchar_t *w;
    BOOL ok;
    DWORD err = 0;
    if (!path) return -14;
    w = utf8_to_wide(path, wbuf, sizeof wbuf / sizeof wbuf[0], &wheap);
    if (!w) return -22;
    if (rmdir_flag) {
        if (win_probe_is_symlink(w)) {
            free(wheap);
            return -20; /* ENOTDIR: rmdir on symlink */
        }
        ok = RemoveDirectoryW(w);
        if (!ok) err = GetLastError();
    } else {
        ok = DeleteFileW(w);
        if (!ok) {
            err = GetLastError();
            if (err == ERROR_ACCESS_DENIED && win_probe_is_symlink(w)) {
                ok = RemoveDirectoryW(w); /* directory symlink: unlink removes link */
                if (!ok) err = GetLastError();
            }
        }
    }
    if (!ok) {
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

int afw_os_mkdir(const char *path, uint32_t mode) {
    wchar_t wbuf[512], *wheap = NULL;
    const wchar_t *w;
    BOOL ok;
    DWORD err;
    (void)mode;
    if (!path) return -14;
    w = utf8_to_wide(path, wbuf, sizeof wbuf / sizeof wbuf[0], &wheap);
    if (!w) return -22;
    ok = CreateDirectoryW(w, NULL);
    err = ok ? 0 : GetLastError();
    free(wheap);
    return ok ? 0 : win_err_to_lnx(err);
}

#ifndef SYMBOLIC_LINK_FLAG_DIRECTORY
#define SYMBOLIC_LINK_FLAG_DIRECTORY 0x1
#endif
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif

static int win_target_is_dir(const char *target, const char *linkpath) {
    wchar_t wbuf[512], *wheap = NULL;
    const wchar_t *w;
    DWORD attr;
    int is_rel = target[0] != '/' && target[0] != '\\' && !(target[0] && target[1] == ':');
    if (is_rel) {
        /* Windows resolves relative symlink targets relative to linkpath's parent directory. */
        const char *slash = strrchr(linkpath, '/');
        const char *bslash = strrchr(linkpath, '\\');
        const char *sep = (!slash || (bslash && bslash > slash)) ? bslash : slash;
        if (sep) {
            size_t dir_len = (size_t)(sep - linkpath) + 1;
            size_t tgt_len = strlen(target);
            char *joined = (tgt_len <= SIZE_MAX - dir_len - 1) ? (char *)malloc(dir_len + tgt_len + 1) : NULL;
            if (!joined) return 0;
            memcpy(joined, linkpath, dir_len);
            memcpy(joined + dir_len, target, tgt_len + 1);
            w = utf8_to_wide(joined, wbuf, sizeof wbuf / sizeof wbuf[0], &wheap);
            free(joined);
            if (!w) return 0;
            attr = GetFileAttributesW(w);
            free(wheap);
            return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
        }
    }
    w = utf8_to_wide(target, wbuf, sizeof wbuf / sizeof wbuf[0], &wheap);
    if (!w) return 0;
    attr = GetFileAttributesW(w);
    free(wheap);
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

int afw_os_symlink(const char *target, const char *linkpath) {
    wchar_t tbuf[512], lbuf[512], *theap = NULL, *lheap = NULL;
    const wchar_t *wt, *wl;
    DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    BOOL ok;
    if (!target || !linkpath) return -14;
    if (win_target_is_dir(target, linkpath))
        flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;
    wt = utf8_to_wide(target, tbuf, sizeof tbuf / sizeof tbuf[0], &theap);
    wl = utf8_to_wide(linkpath, lbuf, sizeof lbuf / sizeof lbuf[0], &lheap);
    if (!wt || !wl) { free(theap); free(lheap); return -22; }
    ok = CreateSymbolicLinkW(wl, wt, flags);
    if (!ok && GetLastError() == ERROR_INVALID_PARAMETER)
        ok = CreateSymbolicLinkW(wl, wt, flags & ~(DWORD)SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
    if (!ok) {
        DWORD err = GetLastError();
        free(theap); free(lheap);
        return win_err_to_lnx(err);
    }
    free(theap); free(lheap);
    return 0;
}

typedef struct {
    uint32_t tag;
    uint16_t data_len;
    uint16_t reserved;
    uint16_t subst_off;
    uint16_t subst_len;
    uint16_t print_off;
    uint16_t print_len;
    wchar_t  path_buf[];
} afw_mp_reparse;

_Static_assert(offsetof(afw_mp_reparse, path_buf) == 16, "MountPointReparseBuffer header must be 16 bytes");

int afw_os_junction(const char *target, const char *linkpath) {
    wchar_t tbuf[512], lbuf[512], full[512], *theap = NULL, *lheap = NULL;
    const wchar_t *wt, *wl, *print_p;
    DWORD flen, attr, out_bytes = 0;
    size_t print_len, subst_len, subst_bytes, print_bytes, data_len, total_len;
    afw_mp_reparse *rb = NULL;
    HANDLE h;
    if (!target || !linkpath) return -14;
    wt = utf8_to_wide(target, tbuf, sizeof tbuf / sizeof tbuf[0], &theap);
    wl = utf8_to_wide(linkpath, lbuf, sizeof lbuf / sizeof lbuf[0], &lheap);
    if (!wt || !wl) { free(theap); free(lheap); return -22; }

    flen = GetFullPathNameW(wt, (DWORD)(sizeof full / sizeof full[0]), full, NULL);
    free(theap);
    if (flen == 0 || flen >= (sizeof full / sizeof full[0])) {
        free(lheap);
        return -22;
    }
    attr = GetFileAttributesW(full);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        free(lheap);
        return win_err_to_lnx(err);
    }
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        free(lheap);
        return -20; /* ENOTDIR */
    }
    while (flen > 3 && (full[flen - 1] == L'\\' || full[flen - 1] == L'/'))
        full[--flen] = L'\0';

    print_p = (flen >= 4 && full[0] == L'\\' && full[1] == L'\\' &&
               full[2] == L'?' && full[3] == L'\\') ? (full + 4) : full;
    print_len = wcslen(print_p);
    subst_len = 4 + print_len; /* \??\ + print_p */
    subst_bytes = subst_len * sizeof(wchar_t);
    print_bytes = print_len * sizeof(wchar_t);
    data_len = 8 + subst_bytes + sizeof(wchar_t) + print_bytes + sizeof(wchar_t);
    total_len = 8 + data_len;
    if (data_len > 0xffffu || total_len > MAXIMUM_REPARSE_DATA_BUFFER_SIZE) {
        free(lheap);
        return -36; /* ENAMETOOLONG */
    }
    rb = (afw_mp_reparse *)calloc(1, total_len);
    if (!rb) { free(lheap); return -12; }
    rb->tag       = IO_REPARSE_TAG_MOUNT_POINT;
    rb->data_len  = (uint16_t)data_len;
    rb->reserved  = 0;
    rb->subst_off = 0;
    rb->subst_len = (uint16_t)subst_bytes;
    rb->print_off = (uint16_t)(subst_bytes + sizeof(wchar_t));
    rb->print_len = (uint16_t)print_bytes;
    memcpy(rb->path_buf, L"\\??\\", 4 * sizeof(wchar_t));
    memcpy(rb->path_buf + 4, print_p, print_bytes);
    rb->path_buf[subst_len] = L'\0';
    memcpy(rb->path_buf + subst_len + 1, print_p, print_bytes);
    rb->path_buf[subst_len + 1 + print_len] = L'\0';

    if (!CreateDirectoryW(wl, NULL)) {
        DWORD err = GetLastError();
        free(rb); free(lheap);
        return win_err_to_lnx(err);
    }
    h = CreateFileW(wl, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        RemoveDirectoryW(wl);
        free(rb); free(lheap);
        return win_err_to_lnx(err);
    }
    if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, rb, (DWORD)total_len, NULL, 0, &out_bytes, NULL)) {
        DWORD err = GetLastError();
        CloseHandle(h);
        RemoveDirectoryW(wl);
        free(rb); free(lheap);
        return win_err_to_lnx(err);
    }
    CloseHandle(h);
    free(rb);
    free(lheap);
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

int64_t afw_os_stdio_write(int std_fd, const void *buf, size_t len, int append) {
    HANDLE h = std_handle(std_fd);
    if (std_fd != 1 && std_fd != 2) return -9;
    if (!h || h == INVALID_HANDLE_VALUE) return -9;
    return afw_os_write((afw_os_file)h, buf, len, append);
}

int afw_os_stdio_stat(int std_fd, afw_os_stat_info *out) {
    HANDLE h = std_handle(std_fd);
    if (!h || h == INVALID_HANDLE_VALUE) return -9;
    return afw_os_fstat((afw_os_file)h, out);
}

int afw_os_set_append(afw_os_file f, int append) {
    (void)append;
    return f == AFW_OS_FILE_INVALID ? -9 : 0;
}

int afw_os_stdio_set_append(int std_fd, int append) {
    HANDLE h;
    (void)append;
    if (std_fd < 0 || std_fd > 2) return -9;
    h = std_handle(std_fd);
    return (!h || h == INVALID_HANDLE_VALUE) ? -9 : 0;
}

int afw_os_stdio_swap(int std_fd, afw_os_file new_f, afw_os_file *saved) {
    DWORD id = (std_fd == 1) ? STD_OUTPUT_HANDLE : (std_fd == 2) ? STD_ERROR_HANDLE : 0;
    HANDLE cur;
    if (!id || new_f == AFW_OS_FILE_INVALID || !saved) return -22;
    cur = GetStdHandle(id);
    if (!SetStdHandle(id, (HANDLE)new_f)) return win_err_to_lnx(GetLastError());
    *saved = (afw_os_file)cur;
    return 0;
}

int afw_os_stdio_restore(int std_fd, afw_os_file saved) {
    DWORD id = (std_fd == 1) ? STD_OUTPUT_HANDLE : (std_fd == 2) ? STD_ERROR_HANDLE : 0;
    if (!id) return -22;
    return SetStdHandle(id, (HANDLE)saved) ? 0 : win_err_to_lnx(GetLastError());
}

typedef struct { void (*fn)(void *); void *arg; } afw_win_thr;
static DWORD WINAPI afw_win_thr_entry(LPVOID p) {
    afw_win_thr t = *(afw_win_thr *)p;
    free(p);
    t.fn(t.arg);
    return 0;
}

int afw_os_thread_start(void (*fn)(void *), void *arg, afw_os_thread *out) {
    afw_win_thr *p;
    HANDLE h;
    if (!fn || !out) return -22;
    p = (afw_win_thr *)malloc(sizeof *p);
    if (!p) return -12;
    p->fn = fn; p->arg = arg;
    h = CreateThread(NULL, 0, afw_win_thr_entry, p, 0, NULL);
    if (!h) { DWORD e = GetLastError(); free(p); return win_err_to_lnx(e); }
    *out = (afw_os_thread)h;
    return 0;
}

int afw_os_thread_join(afw_os_thread t) {
    HANDLE h = (HANDLE)t;
    DWORD w = WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    return w == WAIT_OBJECT_0 ? 0 : -5;
}

int afw_os_filemap_ro(afw_os_file f, uint64_t aligned_off, size_t view_len,
                      int shared, void **view_base_out) {
    HANDLE hm;
    void *view;
    (void)shared; /* read-only view: MAP_SHARED and MAP_PRIVATE both use FILE_MAP_READ */
    if (f == AFW_OS_FILE_INVALID || !view_len || !view_base_out) return -22;
    hm = CreateFileMappingW((HANDLE)f, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hm) return win_err_to_lnx(GetLastError());
    view = MapViewOfFile(hm, FILE_MAP_READ,
                         (DWORD)(aligned_off >> 32),
                         (DWORD)(aligned_off & 0xffffffffu),
                         (SIZE_T)view_len);
    if (!view) {
        DWORD err = GetLastError();
        CloseHandle(hm);
        return win_err_to_lnx(err);
    }
    CloseHandle(hm);
    *view_base_out = view;
    return 0;
}

int afw_os_filemap_unmap(void *view_base, size_t view_len) {
    (void)view_len;
    if (!view_base) return -22;
    return UnmapViewOfFile(view_base) ? 0 : win_err_to_lnx(GetLastError());
}

int afw_os_filemap_protect(void *addr, size_t len, int prot) {
    DWORD wp, old = 0;
    if (!addr || !len) return -22;
    if (prot & (AFW_PROT_W | AFW_PROT_X)) return -13; /* EACCES: read-only filemap */
    wp = (prot & AFW_PROT_R) ? PAGE_READONLY : PAGE_NOACCESS;
    return VirtualProtect(addr, (SIZE_T)len, wp, &old) ? 0 : win_err_to_lnx(GetLastError());
}

int afw_os_ww_reserve(uint64_t addr, uint64_t size, uint64_t *out, int *ww_out) {
    void *p;
    if (!size || !out || !ww_out) return -1;
    p = VirtualAlloc((void *)(uintptr_t)addr, (SIZE_T)size,
                     MEM_RESERVE | MEM_WRITE_WATCH, PAGE_NOACCESS);
    if (p) {
        *out = (uint64_t)(uintptr_t)p;
        *ww_out = 1;
        return 0;
    }
    /* Fallback to plain MEM_RESERVE if MEM_WRITE_WATCH is unavailable. */
    p = VirtualAlloc((void *)(uintptr_t)addr, (SIZE_T)size, MEM_RESERVE, PAGE_NOACCESS);
    if (!p) return -1;
    *out = (uint64_t)(uintptr_t)p;
    *ww_out = 0;
    return 0;
}

int afw_os_ww_get(uint64_t addr, uint64_t len, int reset,
                  void **addrs, size_t *count_io, uint32_t *gran_out) {
    ULONG_PTR cnt;
    DWORD gran = 0;
    DWORD flags = reset ? WRITE_WATCH_FLAG_RESET : 0;
    if (!addr || !len || !addrs || !count_io || !*count_io || !gran_out) return -1;
    cnt = (ULONG_PTR)*count_io;
    if (GetWriteWatch(flags, (void *)(uintptr_t)addr, (SIZE_T)len,
                      addrs, &cnt, &gran) != 0)
        return -1;
    *count_io = (size_t)cnt;
    *gran_out = (uint32_t)gran;
    return 0;
}

int afw_os_ww_reset(uint64_t addr, uint64_t len) {
    if (!addr || !len) return -1;
    return ResetWriteWatch((void *)(uintptr_t)addr, (SIZE_T)len) == 0 ? 0 : -1;
}

/* ---- G2-4b Windows thread-clone, FLS, event, atomic & NT_TIB trampoline ---- */
_Static_assert(offsetof(afw_os_clone_trampoline, host_rsp)             == 0x00, "host_rsp");
_Static_assert(offsetof(afw_os_clone_trampoline, orig_tib_base)        == 0x08, "orig_tib_base");
_Static_assert(offsetof(afw_os_clone_trampoline, orig_tib_limit)       == 0x10, "orig_tib_limit");
_Static_assert(offsetof(afw_os_clone_trampoline, orig_teb_dealloc)     == 0x18, "orig_teb_dealloc");
_Static_assert(offsetof(afw_os_clone_trampoline, bionic_stack_base)    == 0x20, "bionic_stack_base");
_Static_assert(offsetof(afw_os_clone_trampoline, bionic_stack_limit)   == 0x28, "bionic_stack_limit");
_Static_assert(offsetof(afw_os_clone_trampoline, bionic_dealloc_stack) == 0x30, "bionic_dealloc_stack");
_Static_assert(offsetof(afw_os_clone_trampoline, child_rsp)            == 0x38, "child_rsp");
_Static_assert(offsetof(afw_os_clone_trampoline, child_rip)            == 0x40, "child_rip");
_Static_assert(offsetof(afw_os_clone_trampoline, rbx)                  == 0x48, "rbx");
_Static_assert(offsetof(afw_os_clone_trampoline, rbp)                  == 0x50, "rbp");
_Static_assert(offsetof(afw_os_clone_trampoline, r12)                  == 0x58, "r12");
_Static_assert(offsetof(afw_os_clone_trampoline, r13)                  == 0x60, "r13");
_Static_assert(offsetof(afw_os_clone_trampoline, r14)                  == 0x68, "r14");
_Static_assert(offsetof(afw_os_clone_trampoline, r15)                  == 0x70, "r15");

uint32_t afw_os_current_tid(void) {
    return (uint32_t)GetCurrentThreadId();
}

int afw_os_thread_spawn_detached(void (*fn)(void *), void *arg) {
    afw_win_thr *p;
    HANDLE h;
    if (!fn) return -22;
    p = (afw_win_thr *)malloc(sizeof *p);
    if (!p) return -12;
    p->fn = fn; p->arg = arg;
    h = CreateThread(NULL, 0, afw_win_thr_entry, p, 0, NULL);
    if (!h) {
        DWORD e = GetLastError();
        free(p);
        return win_err_to_lnx(e);
    }
    CloseHandle(h);
    return 0;
}

int afw_os_event_init(afw_os_event *ev) {
    HANDLE h;
    if (!ev) return -22;
    h = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!h) return win_err_to_lnx(GetLastError());
    *ev = (afw_os_event)h;
    return 0;
}

void afw_os_event_signal(afw_os_event ev) {
    if (ev) SetEvent((HANDLE)ev);
}

void afw_os_event_wait(afw_os_event ev) {
    if (ev) WaitForSingleObject((HANDLE)ev, INFINITE);
}

void afw_os_event_destroy(afw_os_event ev) {
    if (ev) CloseHandle((HANDLE)ev);
}

static INIT_ONCE g_ctx_fls_once = INIT_ONCE_STATIC_INIT;
static DWORD g_ctx_fls = FLS_OUT_OF_INDEXES;
static void (*g_ctx_fls_cb)(void *);

static VOID WINAPI win_ctx_fls_thunk(PVOID p) {
    if (p && g_ctx_fls_cb) g_ctx_fls_cb(p);
}

static BOOL CALLBACK win_ctx_fls_init_cb(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once; (void)ctx;
    g_ctx_fls_cb = (void (*)(void *))param;
    g_ctx_fls = FlsAlloc(win_ctx_fls_thunk);
    return g_ctx_fls != FLS_OUT_OF_INDEXES;
}

int afw_os_thread_ctx_fls_set(void (*release_cb)(void *), void *ctx) {
    if (!InitOnceExecuteOnce(&g_ctx_fls_once, win_ctx_fls_init_cb, (PVOID)release_cb, NULL))
        return -1;
    if (g_ctx_fls == FLS_OUT_OF_INDEXES) return -1;
    return FlsSetValue(g_ctx_fls, ctx) ? 0 : -1;
}

void afw_os_atomic_store_i32(void *addr, int32_t val) {
    InterlockedExchange((volatile LONG *)addr, (LONG)val);
}

int32_t afw_os_atomic_xchg_i32(int32_t *addr, int32_t val) {
    return (int32_t)InterlockedExchange((volatile LONG *)addr, (LONG)val);
}

int32_t afw_os_atomic_add_i32(int32_t *addr, int32_t delta) {
    return (int32_t)InterlockedExchangeAdd((volatile LONG *)addr, (LONG)delta) + delta;
}

int32_t afw_os_atomic_cmpxchg_i32(int32_t *addr, int32_t expected, int32_t desired) {
    return (int32_t)InterlockedCompareExchange((volatile LONG *)addr, (LONG)desired, (LONG)expected);
}

int32_t afw_os_atomic_load_i32(const int32_t *addr) {
    return __atomic_load_n(addr, __ATOMIC_SEQ_CST);
}

uintptr_t afw_os_atomic_xchg_uptr(uintptr_t *addr, uintptr_t val) {
    return (uintptr_t)InterlockedExchangePointer((PVOID volatile *)addr, (PVOID)val);
}

void afw_os_atomic_store_uptr(uintptr_t *addr, uintptr_t val) {
    (void)InterlockedExchangePointer((PVOID volatile *)addr, (PVOID)val);
}

uintptr_t afw_os_atomic_load_uptr(const uintptr_t *addr) {
    return __atomic_load_n(addr, __ATOMIC_SEQ_CST);
}

void *afw_os_aligned_alloc_zero(size_t align, size_t size) {
    void *p;
    if (size == 0 || align == 0 || (align & (align - 1)) != 0) return NULL;
    if (align < sizeof(void *)) align = sizeof(void *);
    p = _aligned_malloc(size, align);
    if (p) memset(p, 0, size);
    return p;
}

void afw_os_aligned_free(void *p) {
    if (p) _aligned_free(p);
}

static INIT_ONCE g_dtv_fls_once = INIT_ONCE_STATIC_INIT;
static DWORD g_dtv_fls = FLS_OUT_OF_INDEXES;
static int32_t g_dtv_fls_ready = 0;
static void (*g_dtv_fls_cb)(void *);

static VOID WINAPI win_dtv_fls_thunk(PVOID p) {
    if (p && g_dtv_fls_cb) g_dtv_fls_cb(p);
}

static BOOL CALLBACK win_dtv_fls_init_cb(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    DWORD idx;
    (void)once; (void)ctx;
    g_dtv_fls_cb = (void (*)(void *))param;
    idx = FlsAlloc(win_dtv_fls_thunk);
    if (idx == FLS_OUT_OF_INDEXES) return FALSE;
    g_dtv_fls = idx;
    afw_os_atomic_store_i32(&g_dtv_fls_ready, 1);
    return TRUE;
}

int afw_os_dtv_fls_set(void (*release_cb)(void *), void *dtv) {
    if (!release_cb && !dtv) {
        if (afw_os_atomic_load_i32(&g_dtv_fls_ready)) (void)FlsSetValue(g_dtv_fls, NULL);
        return 0;
    }
    if (!InitOnceExecuteOnce(&g_dtv_fls_once, win_dtv_fls_init_cb, (PVOID)release_cb, NULL))
        return -1;
    if (!afw_os_atomic_load_i32(&g_dtv_fls_ready)) return -1;
    return FlsSetValue(g_dtv_fls, dtv) ? 0 : -1;
}

void afw_os_wake_address_all(void *addr) {
    WakeByAddressAll(addr);
}

void afw_os_exit_thread(int code) {
    ExitThread((DWORD)code);
}

int afw_os_clone_supported(void) {
    return 1;
}

/* Windows x64 assembly trampolines for entering Bionic's child_stack on clone(56)
 * and returning to the original Windows host_rsp + NT_TIB on SYS_exit(60).
 * Validated in Stage-0 (tools/g2_stack_probe.c, Items 2a, 4a, 4b, 4c-win, 5). */
__asm__(
    ".att_syntax prefix\n"
    ".text\n"

    /* void afw_os_clone_enter_bionic(afw_os_clone_trampoline *t) [rcx = t] */
    ".globl afw_os_clone_enter_bionic\n"
    "afw_os_clone_enter_bionic:\n\t"
    "mov %rsp, %rax\n\t"
    "sub $64, %rax\n\t"
    "and $-16, %rax\n\t"
    "mov %rax, 0x00(%rcx)\n\t"         /* host_rsp (16-byte aligned, 64B headroom) */
    "mov %gs:0x08, %rax\n\t"
    "mov %rax, 0x08(%rcx)\n\t"         /* orig_tib_base */
    "mov %gs:0x10, %rax\n\t"
    "mov %rax, 0x10(%rcx)\n\t"         /* orig_tib_limit */
    "mov %gs:0x1478, %rax\n\t"
    "mov %rax, 0x18(%rcx)\n\t"         /* orig_teb_dealloc */
    "mov 0x20(%rcx), %rax\n\t"
    "mov %rax, %gs:0x08\n\t"           /* bionic_stack_base */
    "mov 0x28(%rcx), %rax\n\t"
    "mov %rax, %gs:0x10\n\t"           /* bionic_stack_limit */
    "mov 0x30(%rcx), %rax\n\t"
    "mov %rax, %gs:0x1478\n\t"         /* bionic_dealloc_stack */
    /* Note: volatile registers (rdi/rsi/rdx/r8/r9/r10) are not restored in the
     * child — matches Android 14 __bionic_clone, which tests rax == 0 and
     * immediately pops fn/arg into rdi/rsi from child_stack. */
    "cld\n\t"
    "mov 0x40(%rcx), %r11\n\t"         /* child_rip (stub_ret) */
    "mov 0x48(%rcx), %rbx\n\t"
    "mov 0x50(%rcx), %rbp\n\t"
    "mov 0x58(%rcx), %r12\n\t"
    "mov 0x60(%rcx), %r13\n\t"
    "mov 0x68(%rcx), %r14\n\t"
    "mov 0x70(%rcx), %r15\n\t"
    "mov 0x38(%rcx), %rsp\n\t"         /* child_rsp */
    "xor %eax, %eax\n\t"               /* rax = 0 (child return value of clone) */
    "jmp *%r11\n"

    /* void afw_os_clone_exit_on_host(afw_os_clone_trampoline *t, void *ctx,
     *                                int exit_code, void (*fn)(void *, int))
     * rcx = t, rdx = ctx, r8d = exit_code, r9 = fn */
    ".globl afw_os_clone_exit_on_host\n"
    "afw_os_clone_exit_on_host:\n\t"
    "mov 0x00(%rcx), %rsp\n\t"         /* switch to Windows host_rsp FIRST */
    "mov 0x08(%rcx), %rax\n\t"
    "mov %rax, %gs:0x08\n\t"           /* restore orig_tib_base */
    "mov 0x10(%rcx), %rax\n\t"
    "mov %rax, %gs:0x10\n\t"           /* restore orig_tib_limit */
    "mov 0x18(%rcx), %rax\n\t"
    "mov %rax, %gs:0x1478\n\t"         /* restore orig_teb_dealloc */
    "cld\n\t"
    "mov %rdx, %rcx\n\t"               /* arg1 = ctx */
    "mov %r8d, %edx\n\t"               /* arg2 = exit_code */
    "sub $32, %rsp\n\t"                /* host_rsp % 16 == 0; 32B Win64 shadow space */
    "call *%r9\n\t"
    "ud2\n"

    ".intel_syntax noprefix\n"
);

#else
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

/* ---- Linux host OS file primitives & locks ---- */
static pthread_mutex_t g_fd_mu = PTHREAD_MUTEX_INITIALIZER;
void afw_fd_lock(void)   { pthread_mutex_lock(&g_fd_mu); }
void afw_fd_unlock(void) { pthread_mutex_unlock(&g_fd_mu); }

static pthread_rwlock_t g_libs_rw = PTHREAD_RWLOCK_INITIALIZER;
void afw_libs_rdlock(void)   { pthread_rwlock_rdlock(&g_libs_rw); }
void afw_libs_rdunlock(void) { pthread_rwlock_unlock(&g_libs_rw); }
void afw_libs_wrlock(void)   { pthread_rwlock_wrlock(&g_libs_rw); }
void afw_libs_wrunlock(void) { pthread_rwlock_unlock(&g_libs_rw); }

static pthread_once_t g_dlopen_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_dlopen_mu;
static void posix_dlopen_mu_init(void) {
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_dlopen_mu, &a);
    pthread_mutexattr_destroy(&a);
}
void afw_dlopen_lock(void) {
    pthread_once(&g_dlopen_once, posix_dlopen_mu_init);
    pthread_mutex_lock(&g_dlopen_mu);
}
void afw_dlopen_unlock(void) {
    pthread_mutex_unlock(&g_dlopen_mu);
}

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
    if (flags & AFW_O_APPEND) of |= O_APPEND;
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
    (void)append; /* Kernel O_APPEND is synced via open() and afw_os_set_append(). */
    if (f == AFW_OS_FILE_INVALID) return -EBADF;
    if (len == 0) return 0;
    if (!buf) return -EFAULT;
    if (len > 0x7ffff000u) len = 0x7ffff000u;
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

int afw_os_mkdir(const char *path, uint32_t mode) {
    if (!path) return -EFAULT;
    return mkdir(path, (mode_t)(mode & 0777u)) == 0 ? 0 : -errno;
}

int afw_os_symlink(const char *target, const char *linkpath) {
    if (!target || !linkpath) return -EFAULT;
    return symlink(target, linkpath) == 0 ? 0 : -errno;
}

int afw_os_junction(const char *target, const char *linkpath) {
    (void)target; (void)linkpath;
    return -ENOSYS;
}

int64_t afw_os_stdio_read(void *buf, size_t len) {
    return afw_os_read((afw_os_file)0, buf, len);
}

int64_t afw_os_stdio_write(int std_fd, const void *buf, size_t len, int append) {
    if (std_fd != 1 && std_fd != 2) return -EBADF;
    return afw_os_write((afw_os_file)std_fd, buf, len, append);
}

int afw_os_stdio_stat(int std_fd, afw_os_stat_info *out) {
    if (std_fd < 0 || std_fd > 2) return -EBADF;
    return afw_os_fstat((afw_os_file)std_fd, out);
}

int afw_os_set_append(afw_os_file f, int append) {
    int fl;
    if (f == AFW_OS_FILE_INVALID) return -EBADF;
    fl = fcntl((int)f, F_GETFL);
    if (fl < 0) return -errno;
    if (append) fl |= O_APPEND;
    else        fl &= ~O_APPEND;
    return fcntl((int)f, F_SETFL, fl) == 0 ? 0 : -errno;
}

int afw_os_stdio_set_append(int std_fd, int append) {
    if (std_fd < 0 || std_fd > 2) return -EBADF;
    return afw_os_set_append((afw_os_file)std_fd, append);
}

int afw_os_stdio_swap(int std_fd, afw_os_file new_f, afw_os_file *saved) {
    int dup_old;
    if ((std_fd != 1 && std_fd != 2) || new_f == AFW_OS_FILE_INVALID || !saved) return -EINVAL;
    dup_old = dup(std_fd);
    if (dup_old < 0) return -errno;
    if (dup2((int)new_f, std_fd) < 0) {
        int e = errno;
        close(dup_old);
        return -e;
    }
    *saved = (afw_os_file)dup_old;
    return 0;
}

int afw_os_stdio_restore(int std_fd, afw_os_file saved) {
    int rc;
    if ((std_fd != 1 && std_fd != 2) || saved == AFW_OS_FILE_INVALID) return -EINVAL;
    rc = dup2((int)saved, std_fd) < 0 ? -errno : 0;
    close((int)saved);
    return rc;
}

typedef struct { void (*fn)(void *); void *arg; } afw_posix_thr;
static void *afw_posix_thr_entry(void *p) {
    afw_posix_thr t = *(afw_posix_thr *)p;
    free(p);
    t.fn(t.arg);
    return NULL;
}

int afw_os_thread_start(void (*fn)(void *), void *arg, afw_os_thread *out) {
    afw_posix_thr *p;
    pthread_t *pt;
    int rc;
    if (!fn || !out) return -EINVAL;
    p = (afw_posix_thr *)malloc(sizeof *p);
    pt = (pthread_t *)malloc(sizeof *pt);
    if (!p || !pt) { free(p); free(pt); return -ENOMEM; }
    p->fn = fn; p->arg = arg;
    rc = pthread_create(pt, NULL, afw_posix_thr_entry, p);
    if (rc != 0) { free(p); free(pt); return -rc; }
    *out = (afw_os_thread)(uintptr_t)pt;
    return 0;
}

int afw_os_thread_join(afw_os_thread t) {
    pthread_t *pt = (pthread_t *)(uintptr_t)t;
    int rc = pthread_join(*pt, NULL);
    free(pt);
    return rc == 0 ? 0 : -rc;
}

int afw_os_filemap_ro(afw_os_file f, uint64_t aligned_off, size_t view_len,
                      int shared, void **view_base_out) {
    void *p;
    int flags;
    if (f == AFW_OS_FILE_INVALID || !view_len || !view_base_out) return -EINVAL;
    flags = shared ? MAP_SHARED : MAP_PRIVATE;
    p = mmap(NULL, view_len, PROT_READ, flags, (int)f, (off_t)aligned_off);
    if (p == MAP_FAILED) return -errno;
    *view_base_out = p;
    return 0;
}

int afw_os_filemap_unmap(void *view_base, size_t view_len) {
    if (!view_base || !view_len) return -EINVAL;
    return munmap(view_base, view_len) == 0 ? 0 : -errno;
}

int afw_os_filemap_protect(void *addr, size_t len, int prot) {
    int lp;
    if (!addr || !len) return -EINVAL;
    if (prot & (AFW_PROT_W | AFW_PROT_X)) return -EACCES;
    lp = (prot & AFW_PROT_R) ? PROT_READ : PROT_NONE;
    return mprotect(addr, len, lp) == 0 ? 0 : -errno;
}

int afw_os_ww_reserve(uint64_t addr, uint64_t size, uint64_t *out, int *ww_out) {
    void *p;
    if (!size || !out || !ww_out) return -1;
    p = mmap((void *)(uintptr_t)addr, (size_t)size, PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | (addr ? MAP_FIXED_NOREPLACE : 0), -1, 0);
    if (p == MAP_FAILED) return -1;
    *out = (uint64_t)(uintptr_t)p;
    *ww_out = 0;
    return 0;
}

int afw_os_ww_get(uint64_t addr, uint64_t len, int reset,
                  void **addrs, size_t *count_io, uint32_t *gran_out) {
    (void)addr; (void)len; (void)reset; (void)addrs; (void)count_io; (void)gran_out;
    return -1;
}

int afw_os_ww_reset(uint64_t addr, uint64_t len) {
    (void)addr; (void)len;
    return -1;
}

uint32_t afw_os_current_tid(void) {
    return (uint32_t)syscall(SYS_gettid);
}

int afw_os_thread_spawn_detached(void (*fn)(void *), void *arg) {
    afw_posix_thr *p;
    pthread_t pt;
    int rc;
    if (!fn) return -EINVAL;
    p = (afw_posix_thr *)malloc(sizeof *p);
    if (!p) return -ENOMEM;
    p->fn = fn; p->arg = arg;
    rc = pthread_create(&pt, NULL, afw_posix_thr_entry, p);
    if (rc != 0) { free(p); return -rc; }
    pthread_detach(pt);
    return 0;
}

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int signaled;
} afw_posix_event;

int afw_os_event_init(afw_os_event *ev) {
    afw_posix_event *e;
    if (!ev) return -EINVAL;
    e = (afw_posix_event *)calloc(1, sizeof *e);
    if (!e) return -ENOMEM;
    if (pthread_mutex_init(&e->mu, NULL) != 0) { free(e); return -ENOMEM; }
    if (pthread_cond_init(&e->cv, NULL) != 0) {
        pthread_mutex_destroy(&e->mu); free(e); return -ENOMEM;
    }
    *ev = (afw_os_event)(uintptr_t)e;
    return 0;
}

void afw_os_event_signal(afw_os_event ev) {
    afw_posix_event *e = (afw_posix_event *)(uintptr_t)ev;
    if (!e) return;
    pthread_mutex_lock(&e->mu);
    e->signaled = 1;
    pthread_cond_broadcast(&e->cv);
    pthread_mutex_unlock(&e->mu);
}

void afw_os_event_wait(afw_os_event ev) {
    afw_posix_event *e = (afw_posix_event *)(uintptr_t)ev;
    if (!e) return;
    pthread_mutex_lock(&e->mu);
    while (!e->signaled) pthread_cond_wait(&e->cv, &e->mu);
    pthread_mutex_unlock(&e->mu);
}

void afw_os_event_destroy(afw_os_event ev) {
    afw_posix_event *e = (afw_posix_event *)(uintptr_t)ev;
    if (!e) return;
    pthread_cond_destroy(&e->cv);
    pthread_mutex_destroy(&e->mu);
    free(e);
}

static pthread_once_t g_ctx_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t g_ctx_key;
static int g_ctx_key_ok;
static void (*g_ctx_key_cb)(void *);

static void posix_ctx_key_dtor(void *p) {
    if (p && g_ctx_key_cb) g_ctx_key_cb(p);
}

static void posix_ctx_key_init(void) {
    if (pthread_key_create(&g_ctx_key, posix_ctx_key_dtor) == 0)
        g_ctx_key_ok = 1;
}

int afw_os_thread_ctx_fls_set(void (*release_cb)(void *), void *ctx) {
    if (!g_ctx_key_cb) g_ctx_key_cb = release_cb;
    pthread_once(&g_ctx_key_once, posix_ctx_key_init);
    if (!g_ctx_key_ok) return -1;
    return pthread_setspecific(g_ctx_key, ctx) == 0 ? 0 : -1;
}

void afw_os_atomic_store_i32(void *addr, int32_t val) {
    __atomic_store_n((int32_t *)addr, val, __ATOMIC_SEQ_CST);
}

int32_t afw_os_atomic_xchg_i32(int32_t *addr, int32_t val) {
    return __atomic_exchange_n(addr, val, __ATOMIC_ACQ_REL);
}

int32_t afw_os_atomic_add_i32(int32_t *addr, int32_t delta) {
    return __atomic_add_fetch(addr, delta, __ATOMIC_SEQ_CST);
}

int32_t afw_os_atomic_cmpxchg_i32(int32_t *addr, int32_t expected, int32_t desired) {
    int32_t cur = expected;
    (void)__atomic_compare_exchange_n(addr, &cur, desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return cur;
}

int32_t afw_os_atomic_load_i32(const int32_t *addr) {
    return __atomic_load_n(addr, __ATOMIC_SEQ_CST);
}

uintptr_t afw_os_atomic_xchg_uptr(uintptr_t *addr, uintptr_t val) {
    return __atomic_exchange_n(addr, val, __ATOMIC_ACQ_REL);
}

void afw_os_atomic_store_uptr(uintptr_t *addr, uintptr_t val) {
    __atomic_store_n(addr, val, __ATOMIC_SEQ_CST);
}

uintptr_t afw_os_atomic_load_uptr(const uintptr_t *addr) {
    return __atomic_load_n(addr, __ATOMIC_SEQ_CST);
}

void *afw_os_aligned_alloc_zero(size_t align, size_t size) {
    void *p = NULL;
    if (size == 0 || align == 0 || (align & (align - 1)) != 0) return NULL;
    if (align < sizeof(void *)) align = sizeof(void *);
    if (posix_memalign(&p, align, size) != 0) return NULL;
    memset(p, 0, size);
    return p;
}

void afw_os_aligned_free(void *p) {
    free(p);
}

static pthread_once_t g_dtv_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t g_dtv_key;
static int32_t g_dtv_key_ok = 0;
static uintptr_t g_dtv_key_cb = 0;

static void posix_dtv_key_dtor(void *p) {
    void (*cb)(void *) = (void (*)(void *))afw_os_atomic_load_uptr(&g_dtv_key_cb);
    if (p && cb) cb(p);
}

static void posix_dtv_key_init(void) {
    if (pthread_key_create(&g_dtv_key, posix_dtv_key_dtor) == 0)
        afw_os_atomic_store_i32(&g_dtv_key_ok, 1);
}

int afw_os_dtv_fls_set(void (*release_cb)(void *), void *dtv) {
    if (!release_cb && !dtv) {
        if (afw_os_atomic_load_i32(&g_dtv_key_ok)) (void)pthread_setspecific(g_dtv_key, NULL);
        return 0;
    }
    if (release_cb)
        afw_os_atomic_store_uptr(&g_dtv_key_cb, (uintptr_t)release_cb);
    pthread_once(&g_dtv_key_once, posix_dtv_key_init);
    if (!afw_os_atomic_load_i32(&g_dtv_key_ok)) return -1;
    return pthread_setspecific(g_dtv_key, dtv) == 0 ? 0 : -1;
}

void afw_os_wake_address_all(void *addr) {
    (void)syscall(SYS_futex, addr, 1 /* FUTEX_WAKE */, INT_MAX, NULL, NULL, 0);
}

void afw_os_exit_thread(int code) {
    (void)code;
    pthread_exit(NULL);
}

int afw_os_clone_supported(void) {
    return 0;
}

void afw_os_clone_enter_bionic(afw_os_clone_trampoline *t) {
    (void)t;
    abort();
}

void afw_os_clone_exit_on_host(afw_os_clone_trampoline *t, void *ctx,
                               int exit_code, void (*fn)(void *, int)) {
    (void)t; (void)ctx; (void)exit_code; (void)fn;
    abort();
}
#endif
