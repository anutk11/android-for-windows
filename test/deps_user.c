/* deps_user.c - needs libdeps_base.so: its imports must resolve to the loaded
 * dependency, not to a bionic-win stub; it has TLS although the dependency
 * loaded before it has none; it imports an IFUNC. 30 + 5 + 7 = 42. */
int afw_base_value(void);
int afw_base_pick(void);
int afw_base_ready(void);

static __thread volatile int t = 7;   /* volatile: else folded to 7 and no PT_TLS is emitted */
int afw_deps_check(void) {
    if (!afw_base_ready()) return -1;   /* the dependency's constructor ran first */
    return afw_base_value() + afw_base_pick() + t;
}
