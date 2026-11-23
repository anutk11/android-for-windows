/*
 * fd_test.c - Unit tests for src/fd.c + src/platform.c file I/O syscalls.
 * Runs under Linux ASan+UBSan and on Windows.
 */
#include "../src/fd.h"
#include "../src/platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LNX_ENOENT   2
#define LNX_EBADF    9
#define LNX_EFAULT   14
#define LNX_EEXIST   17
#define LNX_EINVAL   22
#define LNX_EMFILE   24
#define LNX_ESPIPE   29
#define LNX_ENOSYS   38
#define LNX_ELOOP    40
#define LNX_AT_FDCWD            (-100)
#define LNX_AT_SYMLINK_NOFOLLOW 0x100
#define LNX_AT_EMPTY_PATH       0x1000
#define LNX_O_CLOEXEC 0x80000
#define LNX_O_NONBLOCK 0x800
#define LNX_O_DIRECT   0x4000
#define LNX_O_PATH     0x200000
#define LNX_F_GETFD 1
#define LNX_F_SETFD 2
#define LNX_F_GETFL 3
#define LNX_F_SETFL 4
#define S_IFMT_  0170000u
#define S_IFREG_ 0100000u
#define S_IFLNK_ 0120000u

static int g_pass, g_fail;
static void chk(const char *name, int cond) {
    if (cond) { g_pass++; printf("  [ OK ] %s\n", name); }
    else      { g_fail++; printf("  [FAIL] %s\n", name); }
}

int main(void) {
    const char *path = "out/fd_test_tmp.dat";
    int64_t fd, fd2, r;
    afw_lnx_stat st;
    char buf[128];

    printf("=== fd_test: Linux file I/O syscall layer ===\n");
    (void)afw_fd_unlinkat(LNX_AT_FDCWD, path, 0);

    /* 1. Error handling on invalid inputs */
    chk("openat(NULL) -> -EFAULT", afw_fd_openat(LNX_AT_FDCWD, NULL, AFW_O_RDONLY, 0) == -LNX_EFAULT);
    chk("openat(\"\") -> -ENOENT", afw_fd_openat(LNX_AT_FDCWD, "", AFW_O_RDONLY, 0) == -LNX_ENOENT);
    chk("openat(missing) -> -ENOENT", afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDONLY, 0) == -LNX_ENOENT);
    chk("openat(bad accmode 3) -> -EINVAL", afw_fd_openat(LNX_AT_FDCWD, path, 3, 0) == -LNX_EINVAL);
    chk("openat(bad dirfd) -> -EBADF", afw_fd_openat(99, "rel.txt", AFW_O_RDONLY, 0) == -LNX_EBADF);
    chk("fstat(bad fd) -> -EBADF", afw_fd_fstat(99, &st) == -LNX_EBADF);
    chk("fstat(NULL) -> -EFAULT", afw_fd_fstat(1, NULL) == -LNX_EFAULT);
    chk("fstat(stdout) succeeds", afw_fd_fstat(1, &st) == 0);
    chk("lseek(stdout) -> -ESPIPE", afw_fd_lseek(1, 0, AFW_SEEK_CUR) == -LNX_ESPIPE);

    /* 2. Create with O_CREAT|O_EXCL, second attempt fails with -EEXIST */
    fd = afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDWR | AFW_O_CREAT | AFW_O_EXCL | LNX_O_CLOEXEC, 0644);
    chk("openat(O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC) succeeds (fd >= 3)", fd >= 3);
    chk("second openat(O_CREAT|O_EXCL) -> -EEXIST",
        afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDWR | AFW_O_CREAT | AFW_O_EXCL, 0644) == -LNX_EEXIST);

    /* 3. fcntl F_GETFD / F_SETFD / F_GETFL / F_SETFL / unknown */
    chk("fcntl(F_GETFD) reflects O_CLOEXEC", afw_fd_fcntl(fd, LNX_F_GETFD, 0) == 1);
    chk("fcntl(F_SETFD, 0) clears cloexec", afw_fd_fcntl(fd, LNX_F_SETFD, 0) == 0 && afw_fd_fcntl(fd, LNX_F_GETFD, 0) == 0);
    chk("fcntl(F_GETFL) returns O_RDWR", (afw_fd_fcntl(fd, LNX_F_GETFL, 0) & AFW_O_ACCMODE) == AFW_O_RDWR);
    chk("fcntl(unknown) -> -ENOSYS", afw_fd_fcntl(fd, 999, 0) == -LNX_ENOSYS);

    /* 4. write, lseek, read, fstat, newfstatat */
    r = afw_fd_write(fd, "hello-afw-", 10);
    chk("write(10 bytes) returns 10", r == 10);
    r = afw_fd_write(fd, "fileio", 6);
    chk("write(6 bytes) returns 6", r == 6);
    chk("lseek(SEEK_CUR, 0) == 16", afw_fd_lseek(fd, 0, AFW_SEEK_CUR) == 16);
    chk("lseek(SEEK_SET, -1) -> -EINVAL", afw_fd_lseek(fd, -1, AFW_SEEK_SET) == -LNX_EINVAL);
    chk("lseek(bad whence) -> -EINVAL", afw_fd_lseek(fd, 0, 9) == -LNX_EINVAL);
    chk("lseek(SEEK_SET, 0) == 0", afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0);
    memset(buf, 0, sizeof buf);
    r = afw_fd_read(fd, buf, sizeof buf);
    chk("read returns 16 bytes matching written content", r == 16 && memcmp(buf, "hello-afw-fileio", 16) == 0);
    chk("read at EOF returns 0", afw_fd_read(fd, buf, sizeof buf) == 0);
    chk("lseek(SEEK_END, -6) == 10", afw_fd_lseek(fd, -6, AFW_SEEK_END) == 10);
    memset(buf, 0, sizeof buf);
    chk("read tail returns \"fileio\"", afw_fd_read(fd, buf, 6) == 6 && memcmp(buf, "fileio", 6) == 0);

    memset(&st, 0, sizeof st);
    chk("fstat reports regular file size 16, blksize 4096, uid 10000",
        afw_fd_fstat(fd, &st) == 0 && st.st_size == 16 &&
        (st.st_mode & S_IFMT_) == S_IFREG_ && st.st_blksize == 4096 && st.st_uid == 10000);
    memset(&st, 0, sizeof st);
    chk("newfstatat(path) reports size 16",
        afw_fd_newfstatat(LNX_AT_FDCWD, path, &st, 0) == 0 && st.st_size == 16 &&
        (st.st_mode & S_IFMT_) == S_IFREG_);
    memset(&st, 0, sizeof st);
    chk("newfstatat(fd, \"\", AT_EMPTY_PATH) reports size 16",
        afw_fd_newfstatat(fd, "", &st, LNX_AT_EMPTY_PATH) == 0 && st.st_size == 16);

    /* 5. writev / readv scatter-gather + invalid args */
    {
        const char *p1 = "ABC", *p2 = "DEFG";
        uint64_t wiov[4] = { (uint64_t)(uintptr_t)p1, 3, (uint64_t)(uintptr_t)p2, 4 };
        char r1[4] = {0}, r2[8] = {0};
        uint64_t riov[4] = { (uint64_t)(uintptr_t)r1, 3, (uint64_t)(uintptr_t)r2, 4 };
        chk("writev invalid cnt -> -EINVAL", afw_fd_writev(fd, wiov, -1) == -LNX_EINVAL && afw_fd_writev(fd, wiov, 1025) == -LNX_EINVAL);
        chk("readv NULL iov -> -EFAULT", afw_fd_readv(fd, NULL, 1) == -LNX_EFAULT);
        chk("lseek to 0 + writev(7 bytes)", afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_writev(fd, wiov, 2) == 7);
        chk("lseek to 0 + readv(7 bytes) matches ABCDEFG",
            afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_readv(fd, riov, 2) == 7 &&
            memcmp(r1, "ABC", 3) == 0 && memcmp(r2, "DEFG", 4) == 0);
    }

    chk("close(fd) succeeds", afw_fd_close(fd) == 0);
    chk("operations on closed fd -> -EBADF",
        afw_fd_read(fd, buf, 4) == -LNX_EBADF && afw_fd_write(fd, "x", 1) == -LNX_EBADF &&
        afw_fd_fstat(fd, &st) == -LNX_EBADF && afw_fd_lseek(fd, 0, AFW_SEEK_SET) == -LNX_EBADF &&
        afw_fd_fcntl(fd, LNX_F_GETFD, 0) == -LNX_EBADF && afw_fd_close(fd) == -LNX_EBADF);

    /* 6. O_TRUNC + O_APPEND + access mode enforcement (O_RDONLY/O_WRONLY) */
    fd = afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDWR | AFW_O_TRUNC, 0);
    chk("O_TRUNC truncates file to 0 bytes",
        fd >= 3 && afw_fd_fstat(fd, &st) == 0 && st.st_size == 0);
    chk("write + close after O_TRUNC", afw_fd_write(fd, "base", 4) == 4 && afw_fd_close(fd) == 0);

    fd = afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDWR | AFW_O_APPEND, 0);
    chk("O_APPEND writes at EOF even after lseek(0)",
        fd >= 3 && afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_write(fd, "+tail", 5) == 5 &&
        afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_read(fd, buf, 16) == 9 &&
        memcmp(buf, "base+tail", 9) == 0 && afw_fd_close(fd) == 0);

    fd = afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDONLY, 0);
    chk("O_RDONLY rejects write with -EBADF", fd >= 3 && afw_fd_write(fd, "x", 1) == -LNX_EBADF && afw_fd_close(fd) == 0);
    fd = afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_WRONLY, 0);
    chk("O_WRONLY rejects read with -EBADF", fd >= 3 && afw_fd_read(fd, buf, 1) == -LNX_EBADF && afw_fd_close(fd) == 0);

    /* 6b. Unsupported openat flags must be rejected with -EINVAL (never silently ignored) */
    chk("openat(O_DIRECT) -> -EINVAL", afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDONLY | LNX_O_DIRECT, 0) == -LNX_EINVAL);
    chk("openat(O_PATH) -> -EINVAL", afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDONLY | LNX_O_PATH, 0) == -LNX_EINVAL);
    chk("openat(O_NONBLOCK) -> -EINVAL", afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDONLY | LNX_O_NONBLOCK, 0) == -LNX_EINVAL);
    chk("openat(unknown bit 0x40000000) -> -EINVAL", afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDONLY | 0x40000000, 0) == -LNX_EINVAL);

    /* 6c. F_SETFL toggling O_APPEND on/off consistently on both Linux and Windows */
    fd = afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDWR | AFW_O_TRUNC | AFW_O_APPEND, 0);
    chk("F_SETFL: open O_APPEND and write 4 bytes", fd >= 3 && afw_fd_write(fd, "1111", 4) == 4);
    chk("F_SETFL: unsupported flag -> -EINVAL", afw_fd_fcntl(fd, LNX_F_SETFL, LNX_O_DIRECT) == -LNX_EINVAL);
    chk("F_SETFL: clearing O_APPEND allows overwrite at offset 0",
        afw_fd_fcntl(fd, LNX_F_SETFL, 0) == 0 &&
        (afw_fd_fcntl(fd, LNX_F_GETFL, 0) & AFW_O_APPEND) == 0 &&
        afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_write(fd, "22", 2) == 2 &&
        afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_read(fd, buf, 16) == 4 &&
        memcmp(buf, "2211", 4) == 0);
    chk("F_SETFL: re-enabling O_APPEND writes at EOF after lseek(0)",
        afw_fd_fcntl(fd, LNX_F_SETFL, AFW_O_APPEND) == 0 &&
        (afw_fd_fcntl(fd, LNX_F_GETFL, 0) & AFW_O_APPEND) == AFW_O_APPEND &&
        afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_write(fd, "33", 2) == 2 &&
        afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_read(fd, buf, 16) == 6 &&
        memcmp(buf, "221133", 6) == 0 && afw_fd_close(fd) == 0);

    /* 6d. Symlinks: lstat (AT_SYMLINK_NOFOLLOW) vs stat, and openat(O_NOFOLLOW) -> -ELOOP */
    {
        const char *linkpath = "out/fd_test_link.dat";
        int64_t lfd;
        (void)afw_fd_unlinkat(LNX_AT_FDCWD, linkpath, 0);
        chk("create symlink out/fd_test_link.dat -> fd_test_tmp.dat",
            afw_os_symlink("fd_test_tmp.dat", linkpath) == 0);
        memset(&st, 0, sizeof st);
        chk("lstat (AT_SYMLINK_NOFOLLOW) reports S_IFLNK on symlink",
            afw_fd_newfstatat(LNX_AT_FDCWD, linkpath, &st, LNX_AT_SYMLINK_NOFOLLOW) == 0 &&
            (st.st_mode & S_IFMT_) == S_IFLNK_);
        memset(&st, 0, sizeof st);
        chk("stat (follow) reports S_IFREG and target size 6 on symlink",
            afw_fd_newfstatat(LNX_AT_FDCWD, linkpath, &st, 0) == 0 &&
            (st.st_mode & S_IFMT_) == S_IFREG_ && st.st_size == 6);
        chk("openat(O_RDONLY|O_NOFOLLOW) on symlink -> -ELOOP",
            afw_fd_openat(LNX_AT_FDCWD, linkpath, AFW_O_RDONLY | AFW_O_NOFOLLOW, 0) == -LNX_ELOOP);
        chk("openat(O_RDWR|O_TRUNC|O_NOFOLLOW) on symlink -> -ELOOP without truncating target",
            afw_fd_openat(LNX_AT_FDCWD, linkpath, AFW_O_RDWR | AFW_O_TRUNC | AFW_O_NOFOLLOW, 0) == -LNX_ELOOP &&
            afw_fd_newfstatat(LNX_AT_FDCWD, path, &st, 0) == 0 && st.st_size == 6);
        lfd = afw_fd_openat(LNX_AT_FDCWD, linkpath, AFW_O_RDONLY, 0);
        memset(buf, 0, sizeof buf);
        chk("openat(O_RDONLY) without O_NOFOLLOW follows symlink and reads target",
            lfd >= 3 && afw_fd_read(lfd, buf, 16) == 6 && memcmp(buf, "221133", 6) == 0 &&
            afw_fd_close(lfd) == 0);
        chk("unlinkat removes symlink while keeping target file intact",
            afw_fd_unlinkat(LNX_AT_FDCWD, linkpath, 0) == 0 &&
            afw_fd_newfstatat(LNX_AT_FDCWD, linkpath, &st, LNX_AT_SYMLINK_NOFOLLOW) == -LNX_ENOENT &&
            afw_fd_newfstatat(LNX_AT_FDCWD, path, &st, 0) == 0 && st.st_size == 6);
    }

    /* 7. EMFILE: exhaust all AFW_MAX_FDS - 3 slots cleanly, then close and reopen */
    {
        int64_t opened[AFW_MAX_FDS];
        int n = 0, i, ok = 1;
        while (n < AFW_MAX_FDS) {
            fd2 = afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDONLY, 0);
            if (fd2 < 0) break;
            opened[n++] = fd2;
        }
        if (n != AFW_MAX_FDS - 3 || fd2 != -LNX_EMFILE) ok = 0;
        for (i = 0; i < n; i++) if (afw_fd_close(opened[i]) != 0) ok = 0;
        fd2 = afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDONLY, 0);
        if (fd2 < 3 || afw_fd_close(fd2) != 0) ok = 0;
        chk("EMFILE at AFW_MAX_FDS (253 open files) + clean recovery after close", ok);
    }

    /* 8. unlinkat deletes the file */
    chk("unlinkat invalid flags -> -EINVAL", afw_fd_unlinkat(LNX_AT_FDCWD, path, 1) == -LNX_EINVAL);
    chk("unlinkat removes file", afw_fd_unlinkat(LNX_AT_FDCWD, path, 0) == 0);
    chk("openat after unlinkat -> -ENOENT", afw_fd_openat(LNX_AT_FDCWD, path, AFW_O_RDONLY, 0) == -LNX_ENOENT);
    chk("newfstatat after unlinkat -> -ENOENT", afw_fd_newfstatat(LNX_AT_FDCWD, path, &st, 0) == -LNX_ENOENT);

    printf("\nfd_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
