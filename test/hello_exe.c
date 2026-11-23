/* hello_exe.c - an ordinary Android executable (NDK, real bionic libc.so):
 * main(argc, argv) through crtbegin's _start and libc's __libc_init; a
 * constructor before main; envp forwarding + getauxval + getprogname
 * consistency across constructors and main; atexit after it; exit code 42. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

static int ctor_ran;
static unsigned long ctor_random;
static int ctor_env_ok;
__attribute__((constructor)) static void before_main(void) {
    const char *h = getenv("AFW_HOST_VAR");
    const char *f = getenv("AFW_FLAG_VAR");
    ctor_ran = 1;
    ctor_random = getauxval(AT_RANDOM);
    ctor_env_ok = (h && strcmp(h, "from_windows") == 0 && f && strcmp(f, "from_flag") == 0);
}
static void after_main(void) { printf("[android exe] atexit handler ran\n"); fflush(stdout); }

int main(int argc, char **argv) {
    char *heap = malloc(64);
    const char *host_v = getenv("AFW_HOST_VAR");
    const char *flag_v = getenv("AFW_FLAG_VAR");
    const char *prog = getprogname();
    unsigned long main_random = getauxval(AT_RANDOM);
    printf("[android exe] hello from main: argc=%d argv[0]=%s argv[1]=%s constructor=%d pid=%d prog=%s host_env=%s flag_env=%s\n",
           argc, argv[0], argc > 1 ? argv[1] : "(none)", ctor_ran, (int)getpid(),
           prog ? prog : "(null)", host_v ? host_v : "(null)", flag_v ? flag_v : "(null)");
    if (argc != 2 || strcmp(argv[1], "world") != 0) return 1;
    if (!ctor_ran) return 2;
    if (!heap) return 3;
    snprintf(heap, 64, "%s-%d", "malloc", 64);
    if (strcmp(heap, "malloc-64") != 0) return 4;
    free(heap);
    if (atexit(after_main) != 0) return 5;
    if (!ctor_env_ok || !host_v || strcmp(host_v, "from_windows") != 0 ||
        !flag_v || strcmp(flag_v, "from_flag") != 0) return 6;
    if (!prog || !strstr(prog, "hello_exe")) return 7;
    if (!ctor_random || main_random != ctor_random) return 8;
    if (getauxval(AT_PAGESZ) != 4096 || getauxval(AT_UID) != 10000 ||
        !getauxval(AT_PHDR) || !getauxval(AT_ENTRY)) return 9;
    return 42;
}
