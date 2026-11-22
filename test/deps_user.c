/* deps_user.c - needs libdeps_base.so: its import must resolve to the loaded
 * dependency, not to a bionic-win stub. */
int afw_base_value(void);
int afw_deps_check(void) { return afw_base_value() + 1; }
