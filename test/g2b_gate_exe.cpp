/*
 * g2b_gate_exe.cpp - Blocking Windows Gate G2b executable (closes full Gate G2):
 *
 *   B1: dlopen("libg2b_dlopen_tls.so", RTLD_NOW | RTLD_GLOBAL) after startup ->
 *       dl_iterate_phdr reports dlpi_tls_modid >= 65 and dlpi_tls_data == NULL
 *       BEFORE first TLS access; [afw-callback-bridge] is present with RX PT_LOAD
 *       and PT_GNU_EH_FRAME; touching TLS verifies .tdata, .tbss, 64B alignment,
 *       and dlpi_tls_data != NULL AFTER first access.
 *   B2: 2 waves x 4 pthread_create workers accessing dynamic PT_TLS concurrently
 *       (held live simultaneously at a wave barrier) -> fresh .tdata/.tbss, 64B
 *       alignment, pairwise distinct DTV blocks, and ~DynTlsGuard() running
 *       exact-once with intact dynamic TLS BEFORE pthread_join returns.
 *   B3: Main-thread non-throwing AND throwing C++ exception across
 *       libcxx_catcher.so -> [afw-callback-bridge] -> libcxx_thrower.so ->
 *       caught as typed `const std::runtime_error &e` with RAII cleanup == 1.
 *   B4: 4 concurrent pthread_create workers x 50 throws = 200 concurrent
 *       cross-callback-bridge C++ exceptions caught cleanly.
 *   B5: Main-thread dynamic dlopen thread_local destructor runs cleanly on
 *       return 0 -> exit(0) with intact dynamic TLS (verified in std::atexit).
 */
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <unistd.h>

extern "C" {
int cxx_call_via_loader_bridge_no_throw(int value, int *calls_out);
int cxx_catch_via_loader_bridge(const char *payload, char *got_buf,
                                size_t got_sz, int *raii_cleaned);
}

using TouchFn   = int (*)(int worker_id, void (*dtor_cb)(int, int), uintptr_t *addr_out);
using RecheckFn = int (*)(int worker_id);

static TouchFn   g_touch_fn   = nullptr;
static RecheckFn g_recheck_fn = nullptr;

static constexpr int kWaves          = 2;
static constexpr int kWaveWorkers    = 4;
static constexpr int kTotalWorkers   = kWaves * kWaveWorkers;
static constexpr int kBridgeWorkers  = 4;
static constexpr int kThrowsPerThrd  = 50;

static std::atomic<int> g_worker_dtor_calls[kTotalWorkers + 1];
static std::atomic<int> g_worker_dtor_intact[kTotalWorkers + 1];

static void record_dyn_dtor(int worker_id, int intact) {
    if (worker_id >= 0 && worker_id <= kTotalWorkers) {
        g_worker_dtor_calls[worker_id].fetch_add(1, std::memory_order_acq_rel);
        g_worker_dtor_intact[worker_id].fetch_add(intact ? 1 : 0, std::memory_order_acq_rel);
    }
}

static void verify_main_dyn_tls_dtor(void) {
    int calls  = g_worker_dtor_calls[0].load(std::memory_order_acquire);
    int intact = g_worker_dtor_intact[0].load(std::memory_order_acquire);
    if (calls != 1 || intact != 1) {
        std::fprintf(stderr, "FAIL B5: main dynamic thread_local dtor calls=%d intact=%d (expected 1, 1)\n",
                     calls, intact);
        std::fflush(stderr);
        _exit(97);
    }
    std::printf("G2B MAIN DYN TLS DTOR OK\n");
    std::fflush(stdout);
}

struct PhdrProbe {
    int found_dyn;
    size_t dyn_modid;
    void *dyn_tls_data;
    int found_bridge;
    int bridge_has_rx_load;
    int bridge_has_eh_frame;
};

static int phdr_probe_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    PhdrProbe *p = static_cast<PhdrProbe *>(data);
    if (info->dlpi_name && std::strstr(info->dlpi_name, "libg2b_dlopen_tls.so") != nullptr) {
        p->found_dyn = 1;
        p->dyn_modid = info->dlpi_tls_modid;
        p->dyn_tls_data = info->dlpi_tls_data;
    }
    if (info->dlpi_name && std::strcmp(info->dlpi_name, "[afw-callback-bridge]") == 0) {
        p->found_bridge = 1;
        for (Elf64_Half i = 0; i < info->dlpi_phnum; i++) {
            const Elf64_Phdr &ph = info->dlpi_phdr[i];
            if (ph.p_type == PT_LOAD && (ph.p_flags & (PF_R | PF_X)) == (PF_R | PF_X) &&
                !(ph.p_flags & PF_W)) {
                p->bridge_has_rx_load = 1;
            }
            if (ph.p_type == PT_GNU_EH_FRAME && ph.p_memsz >= 20) {
                p->bridge_has_eh_frame = 1;
            }
        }
    }
    return 0;
}

struct WaveBarrier {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int arrived;
    int target;
};

static void barrier_init(WaveBarrier *b, int target) {
    pthread_mutex_init(&b->mu, nullptr);
    pthread_cond_init(&b->cv, nullptr);
    b->arrived = 0;
    b->target = target;
}

static void barrier_wait(WaveBarrier *b) {
    pthread_mutex_lock(&b->mu);
    b->arrived++;
    if (b->arrived >= b->target) {
        pthread_cond_broadcast(&b->cv);
    } else {
        while (b->arrived < b->target) {
            pthread_cond_wait(&b->cv, &b->mu);
        }
    }
    pthread_mutex_unlock(&b->mu);
}

static void barrier_destroy(WaveBarrier *b) {
    pthread_cond_destroy(&b->cv);
    pthread_mutex_destroy(&b->mu);
}

struct TlsWorkerArg {
    int id;
    WaveBarrier *barrier;
    uintptr_t tls_addr;
    int ok;
    int err;
};

static void *tls_worker_fn(void *vp) {
    TlsWorkerArg *w = static_cast<TlsWorkerArg *>(vp);
    PhdrProbe before{}, after{};

    dl_iterate_phdr(phdr_probe_cb, &before);
    if (!before.found_dyn || before.dyn_modid < 65 || before.dyn_tls_data != nullptr) {
        w->err = -10;
        w->ok = 0;
        barrier_wait(w->barrier);
        return nullptr;
    }

    int rc = g_touch_fn(w->id, record_dyn_dtor, &w->tls_addr);
    if (rc != 1 || (w->tls_addr % 64u) != 0) {
        w->err = rc;
        w->ok = 0;
        barrier_wait(w->barrier);
        return nullptr;
    }

    dl_iterate_phdr(phdr_probe_cb, &after);
    if (!after.found_dyn || after.dyn_tls_data == nullptr) {
        w->err = -11;
        w->ok = 0;
        barrier_wait(w->barrier);
        return nullptr;
    }

    /* Hold all 4 wave workers' dynamic DTV blocks live simultaneously */
    barrier_wait(w->barrier);

    int rc2 = g_recheck_fn(w->id);
    if (rc2 != 1) {
        w->err = -20 + rc2;
        w->ok = 0;
        return nullptr;
    }

    w->ok = 1;
    w->err = 0;
    return nullptr;
}

struct BridgeWorkerArg {
    int id;
    int caught;
    int ok;
};

static void *bridge_worker_fn(void *vp) {
    BridgeWorkerArg *w = static_cast<BridgeWorkerArg *>(vp);
    int good = 1;
    w->caught = 0;

    for (int i = 0; i < kThrowsPerThrd; i++) {
        char payload[64];
        char got[64];
        int raii = 0;
        std::snprintf(payload, sizeof payload, "afw-g2b-bridge-w%d-i%d", w->id, i);
        got[0] = '\0';
        int rc = cxx_catch_via_loader_bridge(payload, got, sizeof got, &raii);
        if (rc != 1 || raii != 1 || std::strcmp(got, payload) != 0) {
            std::fprintf(stderr, "FAIL B4 worker %d iter %d: rc=%d raii=%d got='%s' want='%s'\n",
                         w->id, i, rc, raii, got, payload);
            good = 0;
            break;
        }
        w->caught++;
    }
    w->ok = good;
    return nullptr;
}

int main(void) {
    std::printf("=== G2b Gate: dlopen+PT_TLS DTV + cross-callback-bridge C++ exception ===\n");
    std::fflush(stdout);

    if (std::atexit(verify_main_dyn_tls_dtor) != 0) {
        std::fprintf(stderr, "FAIL: std::atexit registration failed\n");
        return 1;
    }

    /* B1: Dynamic dlopen of DSO with PT_TLS (.tdata + .tbss + alignas(64)) */
    void *h = dlopen("libg2b_dlopen_tls.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        std::fprintf(stderr, "FAIL B1: dlopen(libg2b_dlopen_tls.so) failed: %s\n",
                     dlerror() ? dlerror() : "(null)");
        return 1;
    }
    g_touch_fn   = reinterpret_cast<TouchFn>(dlsym(h, "g2b_tls_touch_and_check"));
    g_recheck_fn = reinterpret_cast<RecheckFn>(dlsym(h, "g2b_tls_recheck"));
    if (!g_touch_fn || !g_recheck_fn) {
        std::fprintf(stderr, "FAIL B1: dlsym failed: %s\n", dlerror() ? dlerror() : "(null)");
        return 1;
    }

    PhdrProbe p_before{}, p_after{};
    dl_iterate_phdr(phdr_probe_cb, &p_before);
    if (!p_before.found_dyn || p_before.dyn_modid < 65 || p_before.dyn_tls_data != nullptr) {
        std::fprintf(stderr, "FAIL B1 before touch: found=%d modid=%zu tls_data=%p\n",
                     p_before.found_dyn, p_before.dyn_modid, p_before.dyn_tls_data);
        return 1;
    }
    if (!p_before.found_bridge || !p_before.bridge_has_rx_load || !p_before.bridge_has_eh_frame) {
        std::fprintf(stderr, "FAIL B1 bridge phdr: found=%d rx=%d eh=%d\n",
                     p_before.found_bridge, p_before.bridge_has_rx_load, p_before.bridge_has_eh_frame);
        return 1;
    }

    uintptr_t main_tls_addr = 0;
    int rc = g_touch_fn(0, record_dyn_dtor, &main_tls_addr);
    if (rc != 1 || (main_tls_addr % 64u) != 0) {
        std::fprintf(stderr, "FAIL B1 main touch: rc=%d addr=0x%llx\n",
                     rc, (unsigned long long)main_tls_addr);
        return 1;
    }
    dl_iterate_phdr(phdr_probe_cb, &p_after);
    if (!p_after.found_dyn || p_after.dyn_tls_data == nullptr) {
        std::fprintf(stderr, "FAIL B1 after touch: found=%d tls_data=%p\n",
                     p_after.found_dyn, p_after.dyn_tls_data);
        return 1;
    }
    if (g_recheck_fn(0) != 1) {
        std::fprintf(stderr, "FAIL B1 main recheck failed\n");
        return 1;
    }
    std::printf("  [ OK ] B1 dlopen+PT_TLS main thread: modid=%zu, dlpi_tls_data NULL->%p, 64B aligned, [afw-callback-bridge] phdr OK\n",
                p_before.dyn_modid, p_after.dyn_tls_data);

    /* B2: 2 waves x 4 concurrent pthread_create workers accessing dynamic PT_TLS */
    for (int wave = 0; wave < kWaves; wave++) {
        WaveBarrier barrier;
        barrier_init(&barrier, kWaveWorkers);
        pthread_t th[kWaveWorkers];
        TlsWorkerArg w[kWaveWorkers];

        for (int i = 0; i < kWaveWorkers; i++) {
            w[i].id = wave * kWaveWorkers + i + 1;
            w[i].barrier = &barrier;
            w[i].tls_addr = 0;
            w[i].ok = 0;
            w[i].err = 0;
            if (pthread_create(&th[i], nullptr, tls_worker_fn, &w[i]) != 0) {
                std::fprintf(stderr, "FAIL B2: pthread_create wave %d worker %d\n", wave, i);
                return 1;
            }
        }
        for (int i = 0; i < kWaveWorkers; i++) {
            if (pthread_join(th[i], nullptr) != 0 || !w[i].ok) {
                std::fprintf(stderr, "FAIL B2 wave %d worker %d: ok=%d err=%d\n",
                             wave, w[i].id, w[i].ok, w[i].err);
                return 1;
            }
            if (w[i].tls_addr == main_tls_addr) {
                std::fprintf(stderr, "FAIL B2 wave %d worker %d aliased main TLS\n", wave, w[i].id);
                return 1;
            }
            int dcalls  = g_worker_dtor_calls[w[i].id].load(std::memory_order_acquire);
            int dintact = g_worker_dtor_intact[w[i].id].load(std::memory_order_acquire);
            if (dcalls != 1 || dintact != 1) {
                std::fprintf(stderr, "FAIL B2 wave %d worker %d dtor: calls=%d intact=%d\n",
                             wave, w[i].id, dcalls, dintact);
                return 1;
            }
        }
        for (int i = 0; i < kWaveWorkers; i++) {
            for (int j = i + 1; j < kWaveWorkers; j++) {
                if (w[i].tls_addr == w[j].tls_addr) {
                    std::fprintf(stderr, "FAIL B2 wave %d workers %d & %d shared DTV block\n",
                                 wave, w[i].id, w[j].id);
                    return 1;
                }
            }
        }
        barrier_destroy(&barrier);
    }
    if (g_recheck_fn(0) != 1 || g_worker_dtor_calls[0].load(std::memory_order_acquire) != 0) {
        std::fprintf(stderr, "FAIL B2: main dynamic TLS corrupted after worker waves\n");
        return 1;
    }
    std::printf("  [ OK ] B2 dlopen+PT_TLS workers: %d waves x %d threads = %d isolated DTV blocks + %d intact dtors before join\n",
                kWaves, kWaveWorkers, kTotalWorkers, kTotalWorkers);

    /* B3: Main-thread non-throwing and throwing C++ exception across loader callback bridge */
    {
        int calls = 0;
        int nrc = cxx_call_via_loader_bridge_no_throw(11, &calls);
        if (nrc != 40 || calls != 1) {
            std::fprintf(stderr, "FAIL B3 no-throw bridge: rc=%d calls=%d (expected 40, 1)\n", nrc, calls);
            return 1;
        }
        char got[64] = {0};
        int raii = 0;
        int trc = cxx_catch_via_loader_bridge("afw-g2b-bridge-main", got, sizeof got, &raii);
        if (trc != 1 || raii != 1 || std::strcmp(got, "afw-g2b-bridge-main") != 0) {
            std::fprintf(stderr, "FAIL B3 throw bridge: rc=%d raii=%d got='%s'\n", trc, raii, got);
            return 1;
        }
        std::printf("  [ OK ] B3 main-thread cross-bridge call (40) & typed std::runtime_error unwind (raii=%d)\n",
                    raii);
    }

    /* B4: 4 concurrent pthread_create workers x 50 throws across loader callback bridge */
    {
        pthread_t th[kBridgeWorkers];
        BridgeWorkerArg w[kBridgeWorkers];
        int total = 0;
        for (int i = 0; i < kBridgeWorkers; i++) {
            w[i].id = i;
            w[i].caught = 0;
            w[i].ok = 0;
            if (pthread_create(&th[i], nullptr, bridge_worker_fn, &w[i]) != 0) {
                std::fprintf(stderr, "FAIL B4: pthread_create(%d)\n", i);
                return 1;
            }
        }
        for (int i = 0; i < kBridgeWorkers; i++) {
            if (pthread_join(th[i], nullptr) != 0 || !w[i].ok || w[i].caught != kThrowsPerThrd) {
                std::fprintf(stderr, "FAIL B4 worker %d: ok=%d caught=%d\n", i, w[i].ok, w[i].caught);
                return 1;
            }
            total += w[i].caught;
        }
        std::printf("  [ OK ] B4 multi-threaded cross-bridge exceptions: %d/%d caught across %d threads\n",
                    total, kBridgeWorkers * kThrowsPerThrd, kBridgeWorkers);
    }

    std::printf("G2B GATE PASSED\n");
    std::fflush(stdout);
    return 0;
}
