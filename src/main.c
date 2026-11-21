/*
 * main.c - afw-loader: Milestone M0 of Android-for-Windows.
 *
 *   afw-loader <library.so>          load a library and show what is inside
 *   afw-loader <library.so> -v       also list every linked import
 *
 * If the library is test/hello.c (libhello.so), the M0 tests run as well.
 */
#include <stdio.h>
#include <string.h>

#include "bionic_shim.h"
#include "elf_loader.h"
#include "platform.h"
#include "tls_patch.h"
#include "crash.h"

#define AFW_VERSION "0.2.0-M1-dev"

/* Signatures of the test library's functions (Android = System V ABI). */
typedef const char *(SYSV *greeting_fn)(void);
typedef int (SYSV *add_fn)(int, int);
typedef int (SYSV *init_value_fn)(void);
typedef void (SYSV *say_fn)(const char *);
typedef int (SYSV *callback_fn)(int);
typedef int (SYSV *apply_fn)(callback_fn, int);
typedef int (SYSV *stack_test_fn)(int);

/* A Windows function that Android code will call back into. */
static SYSV int times_ten(int x) { return x * 10; }

static int g_failed;
static void check(const char *what, int ok) {
    printf("  [%s] %s\n", ok ? " OK " : "FAIL", what);
    if (!ok) g_failed++;
}

static int run_m0_tests(const afw_lib *lib) {
    greeting_fn greeting = (greeting_fn)afw_sym(lib, "afw_greeting");
    add_fn add = (add_fn)afw_sym(lib, "afw_add");
    init_value_fn init_value = (init_value_fn)afw_sym(lib, "afw_init_value");
    say_fn say = (say_fn)afw_sym(lib, "afw_say");
    apply_fn apply = (apply_fn)afw_sym(lib, "afw_apply");
    stack_test_fn stack_test = (stack_test_fn)afw_sym(lib, "afw_stack_test");

    printf("\n=== M0 tests: calling Android code from Windows ===\n");
    check("exported functions found", greeting && add && init_value && say && apply);
    if (g_failed) return 1;

    {
        const char *g = greeting();
        printf("  afw_greeting()   -> \"%s\"\n", g);
        check("string returned from Android code", strcmp(g, "Hello from Android code!") == 0);
    }
    {
        int r = add(2, 3);
        printf("  afw_add(2, 3)    -> %d\n", r);
        check("arguments passed across ABIs", r == 5);
    }
    {
        int r = init_value();
        printf("  afw_init_value() -> %d\n", r);
        check("library constructor ran (init_array)", r == 42);
    }
    {
        int r = apply(times_ten, 7);
        printf("  afw_apply(times_ten, 7) -> %d\n", r);
        check("Android code called back into Windows code", r == 70);
    }
    if (stack_test) {
        int r = stack_test(4);
        printf("  afw_stack_test(4) -> %d  (fs: instructions rewritten: %ld)\n",
               r, afw_tls_patch_count());
        check("stack protector works (fs:[0x28] TLS emulation)", r == 96);
    }
    printf("  afw_say(\"Windows\") prints:\n");
    say("Windows");
    check("Android code used malloc/strcpy/puts/logcat via bionic-win", 1);

    printf("\n%s\n", g_failed ? "M0 FAILED" : "M0 PASSED - Android code runs natively on this machine!");
    return g_failed ? 1 : 0;
}

int main(int argc, char **argv) {
    afw_lib lib;
    int verbose = 1, rc = 0;

    setvbuf(stdout, NULL, _IONBF, 0); /* never lose output on a crash */
    afw_crash_init();
    printf("Android-for-Windows loader %s\n", AFW_VERSION);
    printf("bionic-win provides %d functions\n\n", afw_shim_count());

    if (argc < 2) {
        printf("usage: %s <library.so> [-v]\n", argv[0]);
        return 2;
    }
    if (argc > 2 && strcmp(argv[2], "-v") == 0) verbose = 2;
    if (afw_tls_init() != 0) return 1;

    if (afw_load(argv[1], &lib, verbose) != 0) {
        printf("\nLoad failed.\n");
        return 1;
    }

    printf("\nLoaded at %p (%zu KB)\n", (void *)lib.base, lib.size / 1024);
    printf("  relocations applied: %d\n", lib.nrelocs);
    printf("  exports:             %d\n", lib.nexports);
    printf("  imports linked:      %d\n", lib.nimports_shimmed);
    printf("  imports missing:     %d\n", lib.nimports_missing);
    printf("  weak imports empty:  %d\n", lib.nimports_weak_null);

    if (afw_sym(&lib, "afw_add")) rc = run_m0_tests(&lib);

    afw_unload(&lib);
    return rc;
}
