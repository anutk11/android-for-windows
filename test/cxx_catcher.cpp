/*
 * cxx_catcher.cpp - DSO B for the G2a C++ cross-DSO exception + thread_local gate.
 * Compiled into a separate shared library (libcxx_catcher.so) loaded via
 * afw_load_with_deps; catches typed std::runtime_error thrown by libcxx_thrower.so.
 */
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>

extern "C" void cxx_throw_runtime_error(const char *msg, int *raii_cleaned);

namespace {
struct CatcherTlsGuard {
    uint32_t canary = 0;
    int worker_id = -1;
    void (*log_fn)(int worker_id, int tag, int seen_id) = nullptr;

    CatcherTlsGuard() : canary(0x43415443u) {}

    ~CatcherTlsGuard() {
        int reported = (canary == 0x43415443u) ? worker_id : -999;
        canary = 0xDEADBEEFu;
        if (log_fn) log_fn(worker_id, 2 /* TAG_CATCHER */, reported);
    }
};

thread_local CatcherTlsGuard g_catcher_tls;
} // namespace

/* Returns:
 *   1  if caught as typed `const std::runtime_error &e` with exact payload match
 *  -1  if caught as typed `const std::runtime_error &e` with mismatched payload
 *  -2  if caught only by catch(...)
 *   0  if no exception was thrown */
extern "C" int cxx_catch_cross_dso(const char *payload, char *got_buf, size_t got_sz, int *raii_cleaned) {
    try {
        cxx_throw_runtime_error(payload, raii_cleaned);
        return 0;
    } catch (const std::runtime_error &e) {
        const char *w = e.what();
        if (got_buf && got_sz) {
            std::snprintf(got_buf, got_sz, "%s", w ? w : "");
        }
        return (w && payload && std::strcmp(w, payload) == 0) ? 1 : -1;
    } catch (...) {
        return -2;
    }
}

extern "C" void cxx_catcher_touch_tls(int worker_id, void (*log_fn)(int, int, int)) {
    g_catcher_tls.worker_id = worker_id;
    g_catcher_tls.log_fn = log_fn;
}

extern "C" int cxx_catcher_get_tls_id(void) {
    return (g_catcher_tls.canary == 0x43415443u) ? g_catcher_tls.worker_id : -999;
}

/* G2b: loader-provided DWARF-unwound callback bridge trampoline (resolved by
 * src/bionic_shim.c directly to the 4KB RX trampoline page). */
extern "C" __attribute__((weak))
int __loader_afw_callback_bridge(int (*cb)(void *), void *arg);

struct BridgeThrowArg {
    const char *msg;
    int *raii_cleaned;
    int value;
};

extern "C" int cxx_bridge_no_throw_cb(void *arg);
extern "C" int cxx_bridge_throw_cb(void *arg);

extern "C" int cxx_call_via_loader_bridge_no_throw(int value, int *calls_out) {
    if (!__loader_afw_callback_bridge) return -3;
    BridgeThrowArg arg{nullptr, calls_out, value};
    return __loader_afw_callback_bridge(cxx_bridge_no_throw_cb, &arg);
}

/* Unwinds std::runtime_error thrown in libcxx_thrower.so through the loader's
 * [afw-callback-bridge] DWARF frame back into libcxx_catcher.so. */
extern "C" int cxx_catch_via_loader_bridge(const char *payload, char *got_buf,
                                           size_t got_sz, int *raii_cleaned) {
    if (!__loader_afw_callback_bridge) return -3;
    BridgeThrowArg arg{payload, raii_cleaned, 0};
    try {
        (void)__loader_afw_callback_bridge(cxx_bridge_throw_cb, &arg);
        return 0;
    } catch (const std::runtime_error &e) {
        const char *w = e.what();
        if (got_buf && got_sz) {
            std::snprintf(got_buf, got_sz, "%s", w ? w : "");
        }
        return (w && payload && std::strcmp(w, payload) == 0) ? 1 : -1;
    } catch (...) {
        return -2;
    }
}

