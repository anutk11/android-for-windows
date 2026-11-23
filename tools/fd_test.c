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
#define LNX_ENOTDIR  20
#define LNX_EISDIR   21
#define LNX_EINVAL   22
#define LNX_EMFILE   24
#define LNX_ESPIPE   29
#define LNX_ENOSYS   38
#define LNX_ELOOP    40
#define LNX_AT_FDCWD            (-100)
#define LNX_AT_SYMLINK_NOFOLLOW 0x100
#define LNX_AT_REMOVEDIR        0x200
#define LNX_AT_EMPTY_PATH       0x1000
#define LNX_O_LARGEFILE 0x8000
#define LNX_O_CLOEXEC   0x80000
#define LNX_O_NONBLOCK  0x800
#define LNX_O_DIRECT    0x4000
#define LNX_O_PATH      0x200000
#define LNX_F_GETFD 1
#define LNX_F_SETFD 2
#define LNX_F_GETFL 3
#define LNX_F_SETFL 4
#define S_IFMT_  0170000u
#define S_IFDIR_ 0040000u
#define S_IFREG_ 0100000u
#define S_IFLNK_ 0120000u

static int g_pass, g_fail;
static void chk(const char *name, int cond) {
    if (cond) { g_pass++; printf("  [ OK ] %s\n", name); }
    else      { g_fail++; printf("  [FAIL] %s\n", name); }
}

typedef struct {
    afw_os_file osf;
    int         iters;
    int         ok;
} atomic_append_arg;

static void atomic_append_worker(void *p) {
    atomic_append_arg *a = (atomic_append_arg *)p;
    char rec[64];
    int i;
    memset(rec, 'B', sizeof rec);
    a->ok = 1;
    for (i = 0; i < a->iters; i++) {
        if (afw_os_write(a->osf, rec, sizeof rec, 1) != (int64_t)sizeof rec) {
            a->ok = 0;
            return;
        }
    }
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
    chk("fcntl(F_GETFL) returns exact O_RDWR|O_LARGEFILE (0x8002)",
        afw_fd_fcntl(fd, LNX_F_GETFL, 0) == (AFW_O_RDWR | LNX_O_LARGEFILE));
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

    /* 6c. F_GETFL / F_SETFL exact Linux x86_64 flags and O_APPEND toggle */
    fd = afw_fd_openat(LNX_AT_FDCWD, path,
                       AFW_O_RDWR | AFW_O_TRUNC | AFW_O_APPEND | AFW_O_NOFOLLOW, 0);
    chk("F_SETFL: open O_RDWR|O_TRUNC|O_APPEND|O_NOFOLLOW -> exact F_GETFL 0x28402",
        fd >= 3 &&
        afw_fd_fcntl(fd, LNX_F_GETFL, 0) == (AFW_O_RDWR | AFW_O_APPEND | LNX_O_LARGEFILE | AFW_O_NOFOLLOW) &&
        afw_fd_write(fd, "1111", 4) == 4);
    chk("F_SETFL: unsupported flag -> -EINVAL without mutating F_GETFL",
        afw_fd_fcntl(fd, LNX_F_SETFL, LNX_O_DIRECT) == -LNX_EINVAL &&
        afw_fd_fcntl(fd, LNX_F_GETFL, 0) == (AFW_O_RDWR | AFW_O_APPEND | LNX_O_LARGEFILE | AFW_O_NOFOLLOW));
    chk("F_SETFL: clearing O_APPEND preserves O_RDWR|O_LARGEFILE|O_NOFOLLOW (0x28002) and overwrites at 0",
        afw_fd_fcntl(fd, LNX_F_SETFL, 0) == 0 &&
        afw_fd_fcntl(fd, LNX_F_GETFL, 0) == (AFW_O_RDWR | LNX_O_LARGEFILE | AFW_O_NOFOLLOW) &&
        afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_write(fd, "22", 2) == 2 &&
        afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_read(fd, buf, 16) == 4 &&
        memcmp(buf, "2211", 4) == 0);
    {
        int64_t cur_fl = afw_fd_fcntl(fd, LNX_F_GETFL, 0);
        chk("F_SETFL(F_GETFL | O_APPEND): re-enables O_APPEND (0x28402) and writes at EOF",
            afw_fd_fcntl(fd, LNX_F_SETFL, cur_fl | AFW_O_APPEND) == 0 &&
            afw_fd_fcntl(fd, LNX_F_GETFL, 0) == (AFW_O_RDWR | AFW_O_APPEND | LNX_O_LARGEFILE | AFW_O_NOFOLLOW) &&
            afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_write(fd, "33", 2) == 2 &&
            afw_fd_lseek(fd, 0, AFW_SEEK_SET) == 0 && afw_fd_read(fd, buf, 16) == 6 &&
            memcmp(buf, "221133", 6) == 0 && afw_fd_close(fd) == 0);
    }

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

    /* 6e. Directory F_GETFL (0x38000), directory symlink, and Windows junction separation */
    {
        const char *dirp = "out/fd_test_dir";
        const char *dlink = "out/fd_test_dirlink";
        int64_t dfd;
        (void)afw_fd_unlinkat(LNX_AT_FDCWD, dlink, 0);
        (void)afw_fd_unlinkat(LNX_AT_FDCWD, dirp, LNX_AT_REMOVEDIR);
        chk("mkdir out/fd_test_dir succeeds", afw_os_mkdir(dirp, 0755) == 0);
        dfd = afw_fd_openat(LNX_AT_FDCWD, dirp, AFW_O_RDONLY | AFW_O_DIRECTORY | AFW_O_NOFOLLOW, 0);
        chk("dir open(O_DIRECTORY|O_NOFOLLOW) -> exact F_GETFL 0x38000",
            dfd >= 3 &&
            afw_fd_fcntl(dfd, LNX_F_GETFL, 0) == (AFW_O_RDONLY | LNX_O_LARGEFILE | AFW_O_DIRECTORY | AFW_O_NOFOLLOW));
        chk("dir F_SETFL(0x38000|O_APPEND) -> 0x38400, then F_SETFL(0) -> 0x38000",
            afw_fd_fcntl(dfd, LNX_F_SETFL, 0x38000 | AFW_O_APPEND) == 0 &&
            afw_fd_fcntl(dfd, LNX_F_GETFL, 0) == 0x38400 &&
            afw_fd_fcntl(dfd, LNX_F_SETFL, 0) == 0 &&
            afw_fd_fcntl(dfd, LNX_F_GETFL, 0) == 0x38000 &&
            afw_fd_close(dfd) == 0);

        chk("create directory symlink out/fd_test_dirlink -> fd_test_dir",
            afw_os_symlink("fd_test_dir", dlink) == 0);
        memset(&st, 0, sizeof st);
        chk("lstat on directory symlink reports S_IFLNK",
            afw_fd_newfstatat(LNX_AT_FDCWD, dlink, &st, LNX_AT_SYMLINK_NOFOLLOW) == 0 &&
            (st.st_mode & S_IFMT_) == S_IFLNK_);
        memset(&st, 0, sizeof st);
        chk("stat on directory symlink follows to S_IFDIR",
            afw_fd_newfstatat(LNX_AT_FDCWD, dlink, &st, 0) == 0 &&
            (st.st_mode & S_IFMT_) == S_IFDIR_);
        chk("openat(O_RDONLY|O_NOFOLLOW) on directory symlink -> -ELOOP",
            afw_fd_openat(LNX_AT_FDCWD, dlink, AFW_O_RDONLY | AFW_O_NOFOLLOW, 0) == -LNX_ELOOP);
        chk("openat(O_DIRECTORY|O_NOFOLLOW) on directory symlink -> -ENOTDIR",
            afw_fd_openat(LNX_AT_FDCWD, dlink, AFW_O_RDONLY | AFW_O_DIRECTORY | AFW_O_NOFOLLOW, 0) == -LNX_ENOTDIR);
        chk("unlinkat(AT_REMOVEDIR) on directory symlink -> -ENOTDIR",
            afw_fd_unlinkat(LNX_AT_FDCWD, dlink, LNX_AT_REMOVEDIR) == -LNX_ENOTDIR);
        chk("unlinkat(0) removes directory symlink while keeping target dir",
            afw_fd_unlinkat(LNX_AT_FDCWD, dlink, 0) == 0 &&
            afw_fd_newfstatat(LNX_AT_FDCWD, dirp, &st, 0) == 0 && (st.st_mode & S_IFMT_) == S_IFDIR_);

#ifdef _WIN32
        {
            const char *junc = "out/fd_test_junc";
            int64_t jfd;
            (void)afw_fd_unlinkat(LNX_AT_FDCWD, junc, LNX_AT_REMOVEDIR);
            chk("Windows junction: create out/fd_test_junc -> out/fd_test_dir",
                afw_os_junction(dirp, junc) == 0);
            memset(&st, 0, sizeof st);
            chk("Windows junction: lstat (AT_SYMLINK_NOFOLLOW) reports S_IFDIR, not S_IFLNK",
                afw_fd_newfstatat(LNX_AT_FDCWD, junc, &st, LNX_AT_SYMLINK_NOFOLLOW) == 0 &&
                (st.st_mode & S_IFMT_) == S_IFDIR_);
            memset(&st, 0, sizeof st);
            chk("Windows junction: stat (follow) reports S_IFDIR",
                afw_fd_newfstatat(LNX_AT_FDCWD, junc, &st, 0) == 0 &&
                (st.st_mode & S_IFMT_) == S_IFDIR_);
            jfd = afw_fd_openat(LNX_AT_FDCWD, junc, AFW_O_RDONLY | AFW_O_NOFOLLOW, 0);
            chk("Windows junction: openat(O_RDONLY|O_NOFOLLOW) succeeds (not -ELOOP), F_GETFL 0x28000",
                jfd >= 3 && afw_fd_fcntl(jfd, LNX_F_GETFL, 0) == 0x28000 && afw_fd_close(jfd) == 0);
            jfd = afw_fd_openat(LNX_AT_FDCWD, junc, AFW_O_RDONLY | AFW_O_DIRECTORY | AFW_O_NOFOLLOW, 0);
            memset(&st, 0, sizeof st);
            chk("Windows junction: openat(O_DIRECTORY|O_NOFOLLOW) succeeds (not -ENOTDIR), fstat S_IFDIR, F_GETFL 0x38000",
                jfd >= 3 &&
                afw_fd_fstat(jfd, &st) == 0 && (st.st_mode & S_IFMT_) == S_IFDIR_ &&
                afw_fd_fcntl(jfd, LNX_F_GETFL, 0) == 0x38000 &&
                afw_fd_close(jfd) == 0);
            chk("Windows junction: unlinkat(0) -> -EISDIR, unlinkat(AT_REMOVEDIR) removes junction keeping target dir",
                afw_fd_unlinkat(LNX_AT_FDCWD, junc, 0) == -LNX_EISDIR &&
                afw_fd_unlinkat(LNX_AT_FDCWD, junc, LNX_AT_REMOVEDIR) == 0 &&
                afw_fd_newfstatat(LNX_AT_FDCWD, dirp, &st, 0) == 0 && (st.st_mode & S_IFMT_) == S_IFDIR_);
        }
#endif
        chk("unlinkat(AT_REMOVEDIR) removes out/fd_test_dir",
            afw_fd_unlinkat(LNX_AT_FDCWD, dirp, LNX_AT_REMOVEDIR) == 0);
    }

    /* 6f. Relative symlink resolves against linkpath's parent dir, not CWD (even when shadowed) */
    {
        const char *cwd_file = "fd_test_shadow";
        const char *out_dir  = "out/fd_test_shadow";
        const char *slink    = "out/fd_test_shadow_link";
        int64_t ffd, dfd;
        (void)afw_fd_unlinkat(LNX_AT_FDCWD, slink, 0);
        (void)afw_fd_unlinkat(LNX_AT_FDCWD, out_dir, LNX_AT_REMOVEDIR);
        (void)afw_fd_unlinkat(LNX_AT_FDCWD, cwd_file, 0);
        ffd = afw_fd_openat(LNX_AT_FDCWD, cwd_file, AFW_O_RDWR | AFW_O_CREAT | AFW_O_TRUNC, 0644);
        chk("shadow symlink setup: create CWD file + out/ directory with same name",
            ffd >= 3 && afw_fd_write(ffd, "file", 4) == 4 && afw_fd_close(ffd) == 0 &&
            afw_os_mkdir(out_dir, 0755) == 0);
        chk("shadow symlink: afw_os_symlink(\"fd_test_shadow\", \"out/fd_test_shadow_link\") succeeds",
            afw_os_symlink("fd_test_shadow", slink) == 0);
        memset(&st, 0, sizeof st);
        chk("shadow symlink: lstat -> S_IFLNK and stat (follow) -> S_IFDIR (not CWD file)",
            afw_fd_newfstatat(LNX_AT_FDCWD, slink, &st, LNX_AT_SYMLINK_NOFOLLOW) == 0 &&
            (st.st_mode & S_IFMT_) == S_IFLNK_ &&
            afw_fd_newfstatat(LNX_AT_FDCWD, slink, &st, 0) == 0 &&
            (st.st_mode & S_IFMT_) == S_IFDIR_);
        dfd = afw_fd_openat(LNX_AT_FDCWD, slink, AFW_O_RDONLY | AFW_O_DIRECTORY, 0);
        memset(&st, 0, sizeof st);
        chk("shadow symlink: openat(O_RDONLY|O_DIRECTORY) follows dir symlink cleanly",
            dfd >= 3 && afw_fd_fstat(dfd, &st) == 0 && (st.st_mode & S_IFMT_) == S_IFDIR_ &&
            afw_fd_close(dfd) == 0);
        chk("shadow symlink cleanup",
            afw_fd_unlinkat(LNX_AT_FDCWD, slink, 0) == 0 &&
            afw_fd_unlinkat(LNX_AT_FDCWD, out_dir, LNX_AT_REMOVEDIR) == 0 &&
            afw_fd_unlinkat(LNX_AT_FDCWD, cwd_file, 0) == 0);
    }

    /* 6g. F_SETFL(O_APPEND) applies to redirected stdout (1) and stderr (2) */
    {
        const char *spath = "out/fd_test_stdio.dat";
        afw_os_file osf = AFW_OS_FILE_INVALID, saved = AFW_OS_FILE_INVALID;
        int64_t fl1 = -1, fl2 = -1, w1 = -1, w2 = -1, w3 = -1, n1 = -1, n2 = -1, n3 = -1;
        char b1[32] = {0}, b2[32] = {0}, b3[32] = {0};
        int sw_ok = 0, rs_ok = 0;

        (void)afw_fd_unlinkat(LNX_AT_FDCWD, spath, 0);
        fd2 = afw_fd_openat(LNX_AT_FDCWD, spath, AFW_O_RDWR | AFW_O_CREAT | AFW_O_TRUNC, 0644);
        chk("stdio append setup: seed out/fd_test_stdio.dat with \"BASE\"",
            fd2 >= 3 && afw_fd_write(fd2, "BASE", 4) == 4 && afw_fd_close(fd2) == 0);

        if (afw_os_open(spath, AFW_O_RDWR, 0, &osf) == 0) {
            fflush(stdout);
            fflush(stderr);
            /* Step 1: stdout redirected at offset 0 with F_SETFL(O_APPEND) must append at EOF */
            if (afw_os_stdio_swap(1, osf, &saved) == 0) {
                sw_ok = 1;
                (void)afw_fd_fcntl(1, LNX_F_SETFL, AFW_O_APPEND);
                fl1 = afw_fd_fcntl(1, LNX_F_GETFL, 0);
                w1 = afw_fd_write(1, "+APP", 4);
                rs_ok = (afw_os_stdio_restore(1, saved) == 0);
            }
            if (afw_os_lseek(osf, 0, AFW_SEEK_SET) == 0)
                n1 = afw_os_read(osf, b1, sizeof b1 - 1);

            /* Step 2: clearing O_APPEND on stdout writes at offset 0 (overwrites "BASE") */
            if (afw_os_lseek(osf, 0, AFW_SEEK_SET) == 0 && afw_os_stdio_swap(1, osf, &saved) == 0) {
                (void)afw_fd_fcntl(1, LNX_F_SETFL, 0);
                fl2 = afw_fd_fcntl(1, LNX_F_GETFL, 0);
                w2 = afw_fd_write(1, "OVER", 4);
                (void)afw_os_stdio_restore(1, saved);
            }
            if (afw_os_lseek(osf, 0, AFW_SEEK_SET) == 0)
                n2 = afw_os_read(osf, b2, sizeof b2 - 1);

            /* Step 3: stderr redirected at offset 0 with F_SETFL(O_APPEND) appends at EOF */
            if (afw_os_lseek(osf, 0, AFW_SEEK_SET) == 0 && afw_os_stdio_swap(2, osf, &saved) == 0) {
                (void)afw_fd_fcntl(2, LNX_F_SETFL, AFW_O_APPEND);
                w3 = afw_fd_write(2, "+ERR", 4);
                (void)afw_fd_fcntl(2, LNX_F_SETFL, 0);
                (void)afw_os_stdio_restore(2, saved);
            }
            if (afw_os_lseek(osf, 0, AFW_SEEK_SET) == 0)
                n3 = afw_os_read(osf, b3, sizeof b3 - 1);

            (void)afw_os_close(osf);
        }
        chk("stdout F_SETFL(O_APPEND) writes at EOF of redirected file (\"BASE+APP\")",
            sw_ok && rs_ok && fl1 == (AFW_O_WRONLY | AFW_O_APPEND | LNX_O_LARGEFILE) &&
            w1 == 4 && n1 == 8 && memcmp(b1, "BASE+APP", 8) == 0);
        chk("stdout F_SETFL(0) clears O_APPEND and overwrites at offset 0 (\"OVER+APP\")",
            fl2 == (AFW_O_WRONLY | LNX_O_LARGEFILE) &&
            w2 == 4 && n2 == 8 && memcmp(b2, "OVER+APP", 8) == 0);
        chk("stderr F_SETFL(O_APPEND) appends at EOF of redirected file (\"OVER+APP+ERR\")",
            w3 == 4 && n3 == 12 && memcmp(b3, "OVER+APP+ERR", 12) == 0);
        chk("stdio append cleanup", afw_fd_unlinkat(LNX_AT_FDCWD, spath, 0) == 0);
    }

    /* 6h. Kernel-atomic O_APPEND across independent OS handles (bypasses afw_fd_lock) */
    {
        const char *apath = "out/fd_test_atomic_append.dat";
        const int iters = 300;
        const size_t rsz = 64;
        const size_t expect_bytes = (size_t)(iters * 2) * rsz;
        int64_t fda;
        afw_os_file osb = AFW_OS_FILE_INVALID;
        afw_os_thread thr = 0;
        atomic_append_arg arg;
        char rec_a[64];
        int i, main_ok = 1, started = 0, joined = 0, intact = 1, cnt_a = 0, cnt_b = 0;
        int64_t pos_after = -1;

        (void)afw_fd_unlinkat(LNX_AT_FDCWD, apath, 0);
        fda = afw_fd_openat(LNX_AT_FDCWD, apath, AFW_O_RDWR | AFW_O_CREAT | AFW_O_TRUNC | AFW_O_APPEND, 0644);
        memset(rec_a, 'A', sizeof rec_a);
        if (fda >= 3 && afw_os_open(apath, AFW_O_WRONLY | AFW_O_APPEND, 0, &osb) == 0) {
            arg.osf = osb;
            arg.iters = iters;
            arg.ok = 0;
            started = (afw_os_thread_start(atomic_append_worker, &arg, &thr) == 0);
            if (started) {
                for (i = 0; i < iters; i++) {
                    if (afw_fd_lseek(fda, 0, AFW_SEEK_SET) != 0 ||
                        afw_fd_write(fda, rec_a, rsz) != (int64_t)rsz) {
                        main_ok = 0;
                        break;
                    }
                }
                joined = (afw_os_thread_join(thr) == 0);
            }
            (void)afw_os_close(osb);
        } else {
            main_ok = 0;
        }
        memset(&st, 0, sizeof st);
        chk("atomic O_APPEND: 2 independent handles x 300 x 64B -> exact 38400 bytes, zero lost writes",
            fda >= 3 && started && joined && main_ok && arg.ok &&
            afw_fd_fstat(fda, &st) == 0 && (size_t)st.st_size == expect_bytes);
        if (fda >= 3) {
            char *all = (char *)malloc(expect_bytes);
            size_t got = 0;
            if (all && afw_fd_lseek(fda, 0, AFW_SEEK_SET) == 0) {
                while (got < expect_bytes) {
                    int64_t n = afw_fd_read(fda, all + got, expect_bytes - got);
                    if (n <= 0) break;
                    got += (size_t)n;
                }
                if (got != expect_bytes) intact = 0;
                for (i = 0; intact && i < iters * 2; i++) {
                    char ch = all[(size_t)i * rsz];
                    size_t j;
                    if (ch != 'A' && ch != 'B') { intact = 0; break; }
                    for (j = 1; j < rsz; j++) {
                        if (all[(size_t)i * rsz + j] != ch) { intact = 0; break; }
                    }
                    if (ch == 'A') cnt_a++; else cnt_b++;
                }
            } else {
                intact = 0;
            }
            free(all);
            /* Also verify O_APPEND updates file offset to new EOF after lseek(0)+write. */
            if (afw_fd_lseek(fda, 0, AFW_SEEK_SET) == 0 && afw_fd_write(fda, "Z", 1) == 1)
                pos_after = afw_fd_lseek(fda, 0, AFW_SEEK_CUR);
            (void)afw_fd_close(fda);
        }
        chk("atomic O_APPEND: all 600 records intact (300 A + 300 B, zero torn/overwritten blocks)",
            intact && cnt_a == iters && cnt_b == iters);
        chk("atomic O_APPEND: SEEK_CUR advances to new EOF after lseek(0)+write",
            pos_after == (int64_t)(expect_bytes + 1));
        chk("atomic O_APPEND cleanup", afw_fd_unlinkat(LNX_AT_FDCWD, apath, 0) == 0);
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
