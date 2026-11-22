/*
 * real_libc_test.c - Android code that uses the REAL bionic libc.so (G1).
 * Built with the NDK against libc.so; loaded with --with-deps and
 * AFW_LIB_PATH pointing at the extracted bionic, its imports resolve to the
 * real libc, not to bionic-win. Each check sets one bit; all = 0x7ff.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

int afw_real_libc_check(void) {
    int bits = 0, i;
    char buf[128];
    int v[5] = {5, 3, 9, 1, 7};
    struct timespec ts;
    void *blocks[64];
    long l;

    snprintf(buf, sizeof buf, "%d|%s|%.3f|%#x", 42, "bionic", 3.14159, 255);
    if (strcmp(buf, "42|bionic|3.142|0xff") == 0) bits |= 1 << 0;             /* stdio formatting */

    for (i = 0; i < 64; i++) blocks[i] = malloc((size_t)(16 << (i % 12)));    /* scudo, up to 32KB */
    for (i = 0; i < 64; i++) if (blocks[i]) memset(blocks[i], i, 16);
    for (i = 0; i < 64 && blocks[i] && ((unsigned char *)blocks[i])[15] == (unsigned char)i; i++) {}
    if (i == 64) bits |= 1 << 1;
    for (i = 0; i < 64; i++) free(blocks[i]);

    qsort(v, 5, sizeof v[0], cmp);
    if (v[0] == 1 && v[4] == 9) bits |= 1 << 2;

    errno = 0;
    l = strtol("99999999999999999999999", NULL, 10);
    if (errno == ERANGE && l > 0) bits |= 1 << 3;                             /* errno through the TCB */

    if (pthread_self() != 0) bits |= 1 << 4;                                  /* tp[1] */
    if (getpid() > 0) bits |= 1 << 5;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0 && (ts.tv_sec > 0 || ts.tv_nsec > 0)) bits |= 1 << 6;

    {
        char *p = strdup("android-for-windows");
        if (p && strlen(p) == 19) bits |= 1 << 7;
        free(p);
    }
    {
        void *big = malloc(8 << 20);                                         /* 8MB: a secondary (mmap) */
        if (big) { memset(big, 1, 8 << 20); bits |= 1 << 8; }
        free(big);
    }
    if (printf("  [real libc] printf works: %s %d\n", "yes", 7) > 0) bits |= 1 << 9;
    fflush(stdout);
    {
        char *e = strerror(ENOENT);
        if (e && strstr(e, "No such file")) bits |= 1 << 10;                  /* bionic_tls buffers */
    }
    return bits;
}
