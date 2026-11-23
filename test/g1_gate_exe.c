/*
 * g1_gate_exe.c - Full Gate G1 end-to-end Android executable (NDK, real bionic libc.so):
 * prints to stdout, allocates memory, creates/writes/stats/seeks/reads/appends/unlinks
 * a real file through both bionic stdio (fopen/fwrite/fread) and POSIX (open/read/write/
 * lseek/fstat/stat/fcntl/unlink), and exits with code 0.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(int code, const char *msg) {
    fprintf(stderr, "[g1_gate_exe] FAIL (%d): %s (errno=%d: %s)\n", code, msg, errno, strerror(errno));
    fflush(stderr);
    return code;
}

int main(int argc, char **argv) {
    const char *path;
    const char *line1 = "Android-for-Windows G1 Gate: ";
    const char *line2 = "real bionic libc.so file I/O on Windows!\n";
    char expected[128], buf[256];
    size_t elen, nread, i;
    unsigned char *big;
    FILE *fp;
    struct stat st;
    int fd;

    if (argc < 2) return fail(1, "missing temp file path argument");
    path = argv[1];
    (void)unlink(path);

    printf("[g1_gate_exe] starting full G1 gate test (pid=%d, file=%s)\n", (int)getpid(), path);
    fflush(stdout);

    /* 1. Heap allocation (scudo) */
    big = (unsigned char *)calloc(256, 1024);
    if (!big) return fail(2, "calloc 256KB failed");
    for (i = 0; i < 256 * 1024; i += 4096) big[i] = (unsigned char)(i >> 12);
    for (i = 0; i < 256 * 1024; i += 4096)
        if (big[i] != (unsigned char)(i >> 12)) return fail(3, "heap verification mismatch");
    free(big);

    /* 2. Bionic stdio write: fopen / fprintf / fwrite / fclose */
    snprintf(expected, sizeof expected, "%s%s", line1, line2);
    elen = strlen(expected);
    fp = fopen(path, "wb");
    if (!fp) return fail(4, "fopen(wb) failed");
    if (fprintf(fp, "%s", line1) != (int)strlen(line1)) return fail(5, "fprintf failed");
    if (fwrite(line2, 1, strlen(line2), fp) != strlen(line2)) return fail(6, "fwrite failed");
    if (fclose(fp) != 0) return fail(7, "fclose(wb) failed");

    /* 3. stat() check */
    memset(&st, 0, sizeof st);
    if (stat(path, &st) != 0) return fail(8, "stat() failed");
    if (!S_ISREG(st.st_mode) || (size_t)st.st_size != elen) return fail(9, "stat() mode/size mismatch");

    /* 4. Bionic stdio read + fseek: fopen / fseek / fread / fclose */
    fp = fopen(path, "rb");
    if (!fp) return fail(10, "fopen(rb) failed");
    memset(buf, 0, sizeof buf);
    nread = fread(buf, 1, sizeof buf - 1, fp);
    if (nread != elen || memcmp(buf, expected, elen) != 0) return fail(11, "fread content mismatch");
    if (fseek(fp, (long)strlen(line1), SEEK_SET) != 0) return fail(12, "fseek failed");
    memset(buf, 0, sizeof buf);
    nread = fread(buf, 1, strlen(line2), fp);
    if (nread != strlen(line2) || memcmp(buf, line2, strlen(line2)) != 0) return fail(13, "fseek+fread mismatch");
    if (fclose(fp) != 0) return fail(14, "fclose(rb) failed");

    /* 5. POSIX open/O_EXCL, O_APPEND, fstat, fcntl, O_RDONLY write refusal */
    errno = 0;
    if (open(path, O_RDWR | O_CREAT | O_EXCL, 0644) >= 0 || errno != EEXIST)
        return fail(15, "open(O_CREAT|O_EXCL) did not fail with EEXIST");

    fd = open(path, O_RDWR | O_APPEND | O_CLOEXEC);
    if (fd < 0) return fail(16, "open(O_RDWR|O_APPEND|O_CLOEXEC) failed");
    if (fcntl(fd, F_GETFD) != FD_CLOEXEC) return fail(17, "fcntl(F_GETFD) != FD_CLOEXEC");
    if (lseek(fd, 0, SEEK_SET) != 0) return fail(18, "lseek(0) failed");
    if (write(fd, "APPENDED", 8) != 8) return fail(19, "O_APPEND write failed");
    memset(&st, 0, sizeof st);
    if (fstat(fd, &st) != 0 || (size_t)st.st_size != elen + 8) return fail(20, "fstat after append mismatch");
    if (lseek(fd, (off_t)elen, SEEK_SET) != (off_t)elen) return fail(21, "lseek(elen) failed");
    memset(buf, 0, sizeof buf);
    if (read(fd, buf, 8) != 8 || memcmp(buf, "APPENDED", 8) != 0) return fail(22, "read appended bytes mismatch");
    if (close(fd) != 0) return fail(23, "close(fd) failed");

    fd = open(path, O_RDONLY);
    if (fd < 0) return fail(24, "open(O_RDONLY) failed");
    errno = 0;
    if (write(fd, "x", 1) >= 0 || errno != EBADF) return fail(25, "write on O_RDONLY did not fail with EBADF");
    if (close(fd) != 0) return fail(26, "close(rdonly) failed");

    /* 6. unlink() + ENOENT verification */
    if (unlink(path) != 0) return fail(27, "unlink() failed");
    errno = 0;
    if (stat(path, &st) == 0 || errno != ENOENT) return fail(28, "stat after unlink did not fail with ENOENT");

    printf("[g1_gate_exe] G1 GATE PASSED (stdout + malloc + stdio + POSIX file I/O + unlink + exit 0)\n");
    fflush(stdout);
    return 0;
}
