/*
 * ifunc_test.c - an IFUNC whose resolver reads the stack guard (fs:[0x28],
 * built with -fstack-protector-all). The loader may run the resolver only
 * after the code is patched and executable (reviewer 4, #8): before that,
 * on Windows the call faults on a non-executable page, or reads fs:[0x28]
 * unpatched.
 */
static int impl42(void) { return 42; }

static void *resolve_answer(void) {
    volatile char buf[32];                 /* forces a stack-guard check */
    buf[0] = 1;
    return buf[0] ? (void *)impl42 : 0;
}

int afw_ifunc_answer(void) __attribute__((ifunc("resolve_answer")));

int afw_ifunc_call(void) { return afw_ifunc_answer(); }

/* the same through IRELATIVE (a hidden IFUNC: no symbol, just a resolver address) */
__attribute__((visibility("hidden"))) int afw_ifunc_hidden(void) __attribute__((ifunc("resolve_answer")));
int afw_ifunc_call_hidden(void) { return afw_ifunc_hidden(); }
