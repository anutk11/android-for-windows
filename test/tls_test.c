/*
 * tls_test.c - G1-TLS test library (docs/design/G1-TLS.md, section 5).
 * Built with the NDK; the loader calls these functions, on two threads.
 */
#include <stdint.h>

__thread int afw_tdata = 0x5eed1234;               /* .tdata, non-zero initial value */
__thread int afw_tbss;                              /* .tbss, starts at zero */
__thread char afw_aligned[64] __attribute__((aligned(64))) = {7};
static __thread long s_local = 77;                  /* static: relocations with symbol 0 */

/* general-dynamic: the compiler calls __tls_get_addr */
int *afw_tls_addr_gd(void) { return &afw_tdata; }

/* initial-exec, written by hand so it does not depend on compiler choices:
 * tp from fs:[0], plus the TPOFF64 value the loader stored in the GOT */
int *afw_tls_addr_ie(void) {
    int *p;
    __asm__("mov %%fs:0, %0\n\tadd afw_tdata@gottpoff(%%rip), %0" : "=r"(p));
    return p;
}

int afw_tls_tdata(void) { return afw_tdata; }
int afw_tls_tbss(void) { return afw_tbss; }
long afw_tls_local(void) { return s_local; }
uintptr_t afw_tls_aligned_addr(void) { return (uintptr_t)afw_aligned; }
int afw_tls_aligned_first(void) { return afw_aligned[0]; }

/* Two threads: each writes its own values, waits for the other, then checks
 * that nobody else's write reached it. Returns 0 or the number of the
 * failed check. `wait` is a barrier provided by the loader. */
int afw_tls_worker(int id, void (*wait)(void), int use_ie) {
    int *p = use_ie ? afw_tls_addr_ie() : afw_tls_addr_gd();
    if (afw_tdata != 0x5eed1234) return 1;          /* fresh copy of .tdata */
    if (afw_tbss != 0) return 2;                    /* fresh .tbss */
    if (s_local != 77) return 3;
    if (((uintptr_t)afw_aligned & 63) != 0) return 4;
    if (afw_aligned[0] != 7) return 5;
    if (p != &afw_tdata) return 6;                  /* both access models agree */
    *p = id * 1000;
    afw_tbss = id;
    s_local = id + 100;
    wait();
    if (afw_tdata != id * 1000) return 7;
    if (afw_tbss != id) return 8;
    if (s_local != id + 100) return 9;
    return 0;
}
