/* deps_base.c - a dependency for the --with-deps test (libdeps_base.so).
 * No TLS, like libdl: loaded first, it must not close the static TLS layout
 * before libdeps_user.so (which has TLS) is mapped. Exports an IFUNC, like
 * libc's memcpy: an importer may run its resolver only after this library
 * is finished. */
int afw_base_value(void) { return 30; }

static volatile int base_ready;   /* volatile: else the compiler folds the constructor away */
__attribute__((constructor)) static void base_init(void) { base_ready = base_ready + 1; }

static int pick_impl(void) { return 5; }
static void *resolve_pick(void) { return (void *)pick_impl; }
int afw_base_pick(void) __attribute__((ifunc("resolve_pick")));

int afw_base_ready(void) { return base_ready == 1; }
