/*
 * cxx_gate_exe.cpp - Blocking G2a Gate executable (Android NDK C++ PIE).
 *
 * Loaded via `afw-loader.exe out\cxx_gate_exe --with-deps --watchdog=60 --exec`
 * against real Android 14 libc.so, libm.so, libdl.so, real NDK libc++_shared.so,
 * and TWO separately compiled C++ DSOs (libcxx_thrower.so, libcxx_catcher.so).
 *
 * Verifies all G2-PLAN.md Section 6(4) G2a criteria:
 *   T1: dl_iterate_phdr reports libcxx_thrower.so, libcxx_catcher.so, and
 *       libc++_shared.so as distinct DSOs, each with PT_GNU_EH_FRAME.
 *   T2: Main-thread cross-DSO `throw std::runtime_error("payload")` in DSO A
 *       caught by typed `catch (const std::runtime_error &e)` in DSO B with
 *       exact message match and local RAII unwinding.
 *   T3: 4 concurrent pthread_create workers x 50 cross-DSO throw/catch cycles
 *       (200 concurrent cross-DSO C++ exceptions hammering dl_iterate_phdr + libunwind).
 *   T4: Cross-DSO thread_local destructors in BOTH DSO A and DSO B run exact
 *       once per worker thread, in strict LIFO order, with intact per-thread
 *       TLS state, BEFORE pthread_join() returns.
 *   T5: Main-thread thread_local destructors (DSO B -> DSO A -> exe) run in
 *       strict LIFO order upon return from main() -> exit(0) -> __cxa_thread_finalize().
 */
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <unistd.h>

extern "C" {
int  cxx_catch_cross_dso(const char *payload, char *got_buf, size_t got_sz, int *raii_cleaned);
void cxx_thrower_touch_tls(int worker_id, void (*log_fn)(int, int, int));
int  cxx_thrower_get_tls_id(void);
void cxx_catcher_touch_tls(int worker_id, void (*log_fn)(int, int, int));
int  cxx_catcher_get_tls_id(void);
}

static constexpr int kWorkers = 4;
static constexpr int kThrowsPerWorker = 50;
static constexpr int kMainSlot = kWorkers;

struct DtorLog {
    std::atomic<int> count{0};
    int tags[4] = {0, 0, 0, 0};
    int seen[4] = {-1, -1, -1, -1};
};

static DtorLog g_dtor_logs[kWorkers + 1];
static int g_main_tls_armed = 0;

static void record_dtor(int slot, int tag, int seen_id) {
    if (slot < 0 || slot > kMainSlot) return;
    int idx = g_dtor_logs[slot].count.fetch_add(1, std::memory_order_acq_rel);
    if (idx >= 0 && idx < 4) {
        g_dtor_logs[slot].tags[idx] = tag;
        g_dtor_logs[slot].seen[idx] = seen_id;
    }
}

/* Runs during exit(0) after Bionic's __cxa_thread_finalize() has destroyed
 * main thread's cross-DSO thread_local objects in LIFO order [2, 1]. */
static void verify_main_tls_dtors(void) {
    if (!g_main_tls_armed) return;
    const DtorLog &log = g_dtor_logs[kMainSlot];
    int c = log.count.load(std::memory_order_acquire);
    if (c == 2 && log.tags[0] == 2 && log.tags[1] == 1 &&
        log.seen[0] == kMainSlot && log.seen[1] == kMainSlot) {
        static const char ok[] = "G2A MAIN THREAD_LOCAL DTOR OK\n";
        ssize_t wr = write(1, ok, sizeof(ok) - 1);
        (void)wr;
    } else {
        char buf[128];
        int n = std::snprintf(buf, sizeof buf,
                              "FAIL main thread_local dtor: count=%d tags=[%d,%d] seen=[%d,%d]\n",
                              c, log.tags[0], log.tags[1], log.seen[0], log.seen[1]);
        if (n > 0) {
            ssize_t wr = write(2, buf, (size_t)n);
            (void)wr;
        }
        _exit(2);
    }
}

struct PhdrCheck {
    uintptr_t thrower_addr = 0;
    uintptr_t catcher_addr = 0;
    uintptr_t libcxx_addr = 0;
    int thrower_eh = 0;
    int catcher_eh = 0;
    int libcxx_eh = 0;
};

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    auto *pc = static_cast<PhdrCheck *>(data);
    if (!info || !info->dlpi_name) return 0;
    int has_eh = 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_GNU_EH_FRAME && info->dlpi_phdr[i].p_memsz > 0) {
            has_eh = 1;
            break;
        }
    }
    if (std::strstr(info->dlpi_name, "libcxx_thrower.so")) {
        pc->thrower_addr = (uintptr_t)info->dlpi_addr;
        pc->thrower_eh = has_eh;
    } else if (std::strstr(info->dlpi_name, "libcxx_catcher.so")) {
        pc->catcher_addr = (uintptr_t)info->dlpi_addr;
        pc->catcher_eh = has_eh;
    } else if (std::strstr(info->dlpi_name, "libc++_shared.so")
#ifndef __ANDROID__
               || std::strstr(info->dlpi_name, "libstdc++.so")
#endif
    ) {
        pc->libcxx_addr = (uintptr_t)info->dlpi_addr;
        pc->libcxx_eh = has_eh;
    }
    return 0;
}

struct WorkerArg {
    int id;
    int ok;
    int caught;
};

static void *worker_fn(void *p) {
    auto *wa = static_cast<WorkerArg *>(p);
    int id = wa->id;
    wa->ok = 1;
    wa->caught = 0;

    /* Construct thread_local in DSO A first, then DSO B second -> LIFO dtor order must be [2, 1]. */
    cxx_thrower_touch_tls(id, record_dtor);
    cxx_catcher_touch_tls(id, record_dtor);

    if (cxx_thrower_get_tls_id() != id || cxx_catcher_get_tls_id() != id) {
        std::fprintf(stderr, "FAIL T4 worker %d: initial TLS isolation mismatch (%d, %d)\n",
                     id, cxx_thrower_get_tls_id(), cxx_catcher_get_tls_id());
        wa->ok = 0;
        return nullptr;
    }

    for (int i = 0; i < kThrowsPerWorker; i++) {
        char payload[64], got[64];
        int raii = 0;
        std::snprintf(payload, sizeof payload, "afw-g2a-worker-%d-iter-%d", id, i);
        got[0] = '\0';
        int rc = cxx_catch_cross_dso(payload, got, sizeof got, &raii);
        if (rc != 1 || raii != 1 || std::strcmp(got, payload) != 0) {
            std::fprintf(stderr, "FAIL T3 worker %d iter %d: rc=%d raii=%d got='%s' want='%s'\n",
                         id, i, rc, raii, got, payload);
            wa->ok = 0;
            return nullptr;
        }
        wa->caught++;
    }

    /* Re-verify per-thread TLS isolation after 50 exceptions across concurrent threads. */
    if (cxx_thrower_get_tls_id() != id || cxx_catcher_get_tls_id() != id) {
        std::fprintf(stderr, "FAIL T4 worker %d: post-throw TLS isolation mismatch (%d, %d)\n",
                     id, cxx_thrower_get_tls_id(), cxx_catcher_get_tls_id());
        wa->ok = 0;
        return nullptr;
    }

    return nullptr;
}

int main() {
    std::printf("=== G2a Gate: cross-DSO C++ exceptions + thread_local dtors ===\n");
    std::fflush(stdout);

    /* T1: Verify separate DSOs and PT_GNU_EH_FRAME via dl_iterate_phdr */
    PhdrCheck pc;
    dl_iterate_phdr(phdr_cb, &pc);
    if (!pc.thrower_addr || !pc.catcher_addr || !pc.libcxx_addr ||
        pc.thrower_addr == pc.catcher_addr || pc.thrower_addr == pc.libcxx_addr ||
        pc.catcher_addr == pc.libcxx_addr ||
        !pc.thrower_eh || !pc.catcher_eh || !pc.libcxx_eh) {
        std::fprintf(stderr,
                     "FAIL T1 dl_iterate_phdr: thrower=%p(eh=%d) catcher=%p(eh=%d) libcxx=%p(eh=%d)\n",
                     (void *)pc.thrower_addr, pc.thrower_eh,
                     (void *)pc.catcher_addr, pc.catcher_eh,
                     (void *)pc.libcxx_addr, pc.libcxx_eh);
        return 1;
    }
    std::printf("  [ OK ] T1 dl_iterate_phdr: 3 distinct DSOs with PT_GNU_EH_FRAME\n");
    std::fflush(stdout);

    /* T2: Main-thread cross-DSO throw -> typed catch */
    {
        char got[64] = {};
        int raii = 0;
        const char *want = "afw-g2a-main-payload";
        int rc = cxx_catch_cross_dso(want, got, sizeof got, &raii);
        if (rc != 1 || raii != 1 || std::strcmp(got, want) != 0) {
            std::fprintf(stderr, "FAIL T2 main cross-DSO catch: rc=%d raii=%d got='%s'\n", rc, raii, got);
            return 1;
        }
        std::printf("  [ OK ] T2 main-thread cross-DSO std::runtime_error caught (%s, raii=%d)\n", got, raii);
        std::fflush(stdout);
    }

    /* T5 setup: construct main-thread cross-DSO thread_local objects in order:
     * Thrower(1) -> Catcher(2). On exit(0), Bionic runs __cxa_thread_finalize()
     * in LIFO order [2, 1] before verify_main_tls_dtors() (atexit). */
    std::atexit(verify_main_tls_dtors);
    g_main_tls_armed = 1;
    cxx_thrower_touch_tls(kMainSlot, record_dtor);
    cxx_catcher_touch_tls(kMainSlot, record_dtor);

    /* T3 + T4: Concurrent pthread_create workers doing cross-DSO throws + thread_local dtors */
    pthread_t th[kWorkers];
    WorkerArg args[kWorkers];
    for (int w = 0; w < kWorkers; w++) {
        args[w].id = w;
        args[w].ok = 0;
        args[w].caught = 0;
        if (pthread_create(&th[w], nullptr, worker_fn, &args[w]) != 0) {
            std::fprintf(stderr, "FAIL T3/T4: pthread_create(%d) failed\n", w);
            return 1;
        }
    }
    int total_caught = 0;
    for (int w = 0; w < kWorkers; w++) {
        if (pthread_join(th[w], nullptr) != 0) {
            std::fprintf(stderr, "FAIL T3/T4: pthread_join(%d) failed\n", w);
            return 1;
        }
        if (!args[w].ok || args[w].caught != kThrowsPerWorker) {
            std::fprintf(stderr, "FAIL T3 worker %d: ok=%d caught=%d\n", w, args[w].ok, args[w].caught);
            return 1;
        }
        total_caught += args[w].caught;
    }
    std::printf("  [ OK ] T3 multi-threaded cross-DSO exceptions: %d/%d caught across %d threads\n",
                total_caught, kWorkers * kThrowsPerWorker, kWorkers);

    /* Verify every worker's thread_local dtors already ran exact once in LIFO order [2, 1] */
    for (int w = 0; w < kWorkers; w++) {
        int c = g_dtor_logs[w].count.load(std::memory_order_acquire);
        if (c != 2 || g_dtor_logs[w].tags[0] != 2 || g_dtor_logs[w].tags[1] != 1 ||
            g_dtor_logs[w].seen[0] != w || g_dtor_logs[w].seen[1] != w) {
            std::fprintf(stderr, "FAIL T4 worker %d thread_local dtor: count=%d tags=[%d,%d] seen=[%d,%d]\n",
                         w, c, g_dtor_logs[w].tags[0], g_dtor_logs[w].tags[1],
                         g_dtor_logs[w].seen[0], g_dtor_logs[w].seen[1]);
            return 1;
        }
    }
    /* Verify main thread's own thread_local state was untouched by workers */
    if (cxx_thrower_get_tls_id() != kMainSlot || cxx_catcher_get_tls_id() != kMainSlot ||
        g_dtor_logs[kMainSlot].count.load(std::memory_order_acquire) != 0) {
        std::fprintf(stderr, "FAIL T4/T5 main thread TLS corrupted by workers\n");
        return 1;
    }
    std::printf("  [ OK ] T4 cross-DSO thread_local dtors: exact-once LIFO [2,1] on all %d workers before join\n",
                kWorkers);
    std::printf("G2A CXX GATE PASSED\n");
    std::fflush(stdout);
    return 0;
}
