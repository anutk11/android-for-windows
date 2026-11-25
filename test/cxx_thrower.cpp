/*
 * cxx_thrower.cpp - DSO A for the G2a C++ cross-DSO exception + thread_local gate.
 * Compiled into a separate shared library (libcxx_thrower.so) loaded via
 * afw_load_with_deps alongside libcxx_catcher.so and real libc++_shared.so.
 */
#include <cstdint>
#include <stdexcept>

namespace {
struct LocalRaiiGuard {
    int *cleaned;
    explicit LocalRaiiGuard(int *p) : cleaned(p) {}
    ~LocalRaiiGuard() {
        if (cleaned) (*cleaned)++;
    }
};

struct ThrowerTlsGuard {
    uint32_t canary = 0;
    int worker_id = -1;
    void (*log_fn)(int worker_id, int tag, int seen_id) = nullptr;

    ThrowerTlsGuard() : canary(0x5448524Fu) {}

    ~ThrowerTlsGuard() {
        int reported = (canary == 0x5448524Fu) ? worker_id : -999;
        canary = 0xDEADBEEFu;
        if (log_fn) log_fn(worker_id, 1 /* TAG_THROWER */, reported);
    }
};

thread_local ThrowerTlsGuard g_thrower_tls;
} // namespace

extern "C" void cxx_throw_runtime_error(const char *msg, int *raii_cleaned) {
    LocalRaiiGuard guard(raii_cleaned);
    throw std::runtime_error(msg ? msg : "");
}

extern "C" void cxx_thrower_touch_tls(int worker_id, void (*log_fn)(int, int, int)) {
    g_thrower_tls.worker_id = worker_id;
    g_thrower_tls.log_fn = log_fn;
}

extern "C" int cxx_thrower_get_tls_id(void) {
    return (g_thrower_tls.canary == 0x5448524Fu) ? g_thrower_tls.worker_id : -999;
}
