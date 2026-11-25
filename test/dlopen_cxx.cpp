/*
 * dlopen_cxx.cpp - Runtime-dlopen'd C++ DSO for G2a T6 (concurrent dlopen vs
 * live cross-DSO C++ exceptions + deterministic constructor/dlsym barrier).
 * Has NO PT_TLS (dlopen + PT_TLS is G2-5b PR #27).
 */
#include <cstring>
#include <dlfcn.h>
#include <stdexcept>

static int g_ctor_state = 0;

__attribute__((constructor))
static void dlopen_cxx_init(void) {
    /* Recursive dlsym() from inside a constructor on the loading thread must
     * succeed without deadlocking against afw_dlopen_lock. */
    using barrier_fn = void (*)(void);
    barrier_fn barrier = reinterpret_cast<barrier_fn>(dlsym(RTLD_DEFAULT, "g2a_ctor_barrier"));
    if (barrier) barrier();
    g_ctor_state = 0x1337CAFE;
}

extern "C" int dlopen_cxx_ctor_ready(void) {
    return g_ctor_state;
}

extern "C" int dlopen_cxx_throw_and_catch(const char *msg) {
    try {
        throw std::runtime_error(msg ? msg : "");
    } catch (const std::runtime_error &e) {
        return (msg && e.what() && std::strcmp(e.what(), msg) == 0) ? 1 : -1;
    } catch (...) {
        return -2;
    }
}
