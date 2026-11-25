/*
 * g2b_dlopen_tls.cpp - Dynamically dlopen'd C++ DSO with PT_TLS for Gate G2b.
 *
 * Exercises:
 *   - non-zero initialized .tdata with 64-byte alignment (alignas(64))
 *   - zero-initialized .tbss
 *   - non-trivial C++ thread_local destructor (DynTlsGuard) whose ~DynTlsGuard()
 *     verifies the dynamic DTV block is still alive, aligned, and uncorrupted
 *     when Bionic's __cxa_thread_finalize() runs (before DTV teardown).
 */
#include <cstdint>

namespace {
struct alignas(64) DynTlsBlock {
    uint64_t magic1;
    uint64_t magic2;
    uint32_t pad[12];
};

static constexpr uint64_t kMagic1 = 0x1122334455667788ULL;
static constexpr uint64_t kMagic2 = 0xCAFEBABE01020304ULL;
static constexpr uint64_t kCanary = 0x44594E544C534744ULL;

static thread_local DynTlsBlock g_dyn_tdata = { kMagic1, kMagic2, {0} };
static thread_local uint64_t g_dyn_tbss[8];

struct DynTlsGuard {
    uint64_t canary = 0;
    int worker_id = -1;
    void (*log_fn)(int worker_id, int intact) = nullptr;

    DynTlsGuard() : canary(kCanary) {}

    ~DynTlsGuard() {
        int intact = (canary == kCanary &&
                      ((uintptr_t)&g_dyn_tdata % 64u) == 0 &&
                      g_dyn_tdata.magic1 == (kMagic1 ^ (uint64_t)worker_id) &&
                      g_dyn_tdata.magic2 == kMagic2 &&
                      g_dyn_tbss[3] == (0xBEEF0000ULL + (uint64_t)worker_id)) ? 1 : 0;
        canary = 0xDEADBEEFDEADBEEFULL;
        if (log_fn) log_fn(worker_id, intact);
    }
};

static thread_local DynTlsGuard g_dyn_guard;
} // namespace

extern "C" int g2b_tls_touch_and_check(int worker_id, void (*dtor_cb)(int, int), uintptr_t *addr_out) {
    if (((uintptr_t)&g_dyn_tdata % 64u) != 0) return -1;
    if (g_dyn_tdata.magic1 != kMagic1 || g_dyn_tdata.magic2 != kMagic2) return -2;
    for (int i = 0; i < 8; i++) {
        if (g_dyn_tbss[i] != 0) return -3;
    }
    g_dyn_tdata.magic1 ^= (uint64_t)worker_id;
    g_dyn_tbss[3] = 0xBEEF0000ULL + (uint64_t)worker_id;
    g_dyn_guard.worker_id = worker_id;
    g_dyn_guard.log_fn = dtor_cb;
    if (addr_out) *addr_out = (uintptr_t)&g_dyn_tdata;
    return 1;
}

extern "C" int g2b_tls_recheck(int worker_id) {
    if (((uintptr_t)&g_dyn_tdata % 64u) != 0) return -1;
    if (g_dyn_tdata.magic1 != (kMagic1 ^ (uint64_t)worker_id)) return -2;
    if (g_dyn_tdata.magic2 != kMagic2) return -3;
    if (g_dyn_tbss[3] != (0xBEEF0000ULL + (uint64_t)worker_id)) return -4;
    if (g_dyn_guard.canary != kCanary || g_dyn_guard.worker_id != worker_id) return -5;
    return 1;
}
