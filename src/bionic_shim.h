/*
 * bionic_shim.h - "bionic-win": Android's C library, implemented on top of
 * the host OS. Android code thinks it is calling libc.so / liblog.so, but
 * it is really calling these functions.
 */
#ifndef AFW_BIONIC_SHIM_H
#define AFW_BIONIC_SHIM_H

/* Find a replacement for an Android library symbol. NULL if we have none. */
void *afw_shim_lookup(const char *name);

/*
 * Create a tiny stub for a symbol we do not implement yet. If Android code
 * ever calls it, we print the symbol's name and stop, instead of crashing
 * mysteriously. This tells us exactly what to implement next.
 */
void *afw_shim_missing_stub(const char *name);

/* Run functions registered by the library with __cxa_atexit. */
void afw_shim_run_atexit(void);

/* Statistics for the report. */
int afw_shim_count(void);

#endif
