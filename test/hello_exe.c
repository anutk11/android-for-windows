/* hello_exe.c - an ordinary Android executable (NDK, real bionic libc.so):
 * main(argc, argv) through crtbegin's _start and libc's __libc_init; a
 * constructor before main; atexit after it; the exit code from main. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int ctor_ran;
__attribute__((constructor)) static void before_main(void) { ctor_ran = 1; }
static void after_main(void) { printf("[android exe] atexit handler ran\n"); fflush(stdout); }

int main(int argc, char **argv) {
    char *heap = malloc(64);
    printf("[android exe] hello from main: argc=%d argv[0]=%s argv[1]=%s constructor=%d pid=%d\n",
           argc, argv[0], argc > 1 ? argv[1] : "(none)", ctor_ran, (int)getpid());
    if (argc != 2 || strcmp(argv[1], "world") != 0) return 1;
    if (!ctor_ran) return 2;
    if (!heap) return 3;
    snprintf(heap, 64, "%s-%d", "malloc", 64);
    if (strcmp(heap, "malloc-64") != 0) return 4;
    free(heap);
    if (atexit(after_main) != 0) return 5;
    return 42;
}
