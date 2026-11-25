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
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <time.h>
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

void (*g_t6_barrier_hook)(void) = nullptr;
extern "C" __attribute__((visibility("default"))) void g2a_ctor_barrier(void) {
    if (g_t6_barrier_hook) g_t6_barrier_hook();
}

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

    /* T6: Concurrent dlopen("libdlopen_cxx.so") vs live C++ exceptions (dl_iterate_phdr)
     * + deterministic constructor/dlsym barrier (Reviewer 2 Blocker 2 + Rule 4). */
    {
        static std::atomic<int> s_ctor_entered{0};
        static std::atomic<int> s_dlsym_attempting{0};
        static std::atomic<int> s_dlsym_early{0};
        static std::atomic<int> s_t6_stop{0};
        static std::atomic<int> s_t6_throws{0};
        static std::atomic<int> s_t6_during_ctor{0};
        static std::atomic<int> s_t6_err{0};

        struct T6Hooks {
            static void sleep_ms(int ms) {
                pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
                pthread_condattr_t attr;
                pthread_cond_t cv;
                struct timespec ts;
                pthread_condattr_init(&attr);
                pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
                pthread_cond_init(&cv, &attr);
                pthread_condattr_destroy(&attr);
                clock_gettime(CLOCK_MONOTONIC, &ts);
                ts.tv_nsec += (long)ms * 1000000L;
                while (ts.tv_nsec >= 1000000000L) {
                    ts.tv_sec++;
                    ts.tv_nsec -= 1000000000L;
                }
                pthread_mutex_lock(&mu);
                (void)pthread_cond_timedwait(&cv, &mu, &ts);
                pthread_mutex_unlock(&mu);
                pthread_cond_destroy(&cv);
                pthread_mutex_destroy(&mu);
            }

            static void barrier_impl() {
                s_ctor_entered.store(1, std::memory_order_release);
                while (!s_dlsym_attempting.load(std::memory_order_acquire))
                    sleep_ms(1);
                int before = s_t6_throws.load(std::memory_order_acquire);
                /* Hold constructor open while external dlsym() is blocked on afw_dlopen_lock
                 * AND concurrent unwinder threads perform >= 40 live cross-DSO throws. */
                while (s_t6_throws.load(std::memory_order_acquire) - before < 40)
                    sleep_ms(2);
                sleep_ms(50);
                s_t6_during_ctor.store(s_t6_throws.load(std::memory_order_acquire) - before,
                                       std::memory_order_release);
            }

            static void *unwind_worker(void *arg) {
                int id = *static_cast<int *>(arg);
                int iter = 0;
                while (!s_t6_stop.load(std::memory_order_acquire)) {
                    char payload[64], got[64];
                    int raii = 0;
                    std::snprintf(payload, sizeof payload, "afw-g2a-t6-%d-%d", id, iter++);
                    got[0] = '\0';
                    int rc = cxx_catch_cross_dso(payload, got, sizeof got, &raii);
                    if (rc != 1 || raii != 1 || std::strcmp(got, payload) != 0) {
                        s_t6_err.fetch_add(1, std::memory_order_acq_rel);
                        return nullptr;
                    }
                    s_t6_throws.fetch_add(1, std::memory_order_acq_rel);
                }
                return nullptr;
            }

            static void *dlsym_waiter(void *arg) {
                int *out_state = static_cast<int *>(arg);
                while (!s_ctor_entered.load(std::memory_order_acquire))
                    sleep_ms(1);
                s_dlsym_attempting.store(1, std::memory_order_release);
                using ready_fn = int (*)(void);
                ready_fn fn = reinterpret_cast<ready_fn>(dlsym(RTLD_DEFAULT, "dlopen_cxx_ctor_ready"));
                int st = fn ? fn() : -1;
                if (st != 0x1337CAFE) s_dlsym_early.store(1, std::memory_order_release);
                *out_state = st;
                return nullptr;
            }
        };

        /* Bind exported C barrier symbol to T6Hooks::barrier_impl */
        extern void (*g_t6_barrier_hook)(void);
        g_t6_barrier_hook = T6Hooks::barrier_impl;

        pthread_t uth[kWorkers], dth;
        int uids[kWorkers];
        int dlsym_state = 0;
        for (int w = 0; w < kWorkers; w++) {
            uids[w] = w;
            if (pthread_create(&uth[w], nullptr, T6Hooks::unwind_worker, &uids[w]) != 0) {
                std::fprintf(stderr, "FAIL T6: pthread_create(unwind %d) failed\n", w);
                return 1;
            }
        }
        if (pthread_create(&dth, nullptr, T6Hooks::dlsym_waiter, &dlsym_state) != 0) {
            std::fprintf(stderr, "FAIL T6: pthread_create(dlsym_waiter) failed\n");
            return 1;
        }
        /* Wait until concurrent unwinders are actively hammering dl_iterate_phdr */
        while (s_t6_throws.load(std::memory_order_acquire) < 8)
            T6Hooks::sleep_ms(1);

        /* Concurrent failed dlopen must return NULL cleanly while unwinders run */
        if (dlopen("libnonexistent_g2a.so", RTLD_NOW) != nullptr) {
            std::fprintf(stderr, "FAIL T6: nonexistent dlopen unexpectedly succeeded\n");
            return 1;
        }

        /* Concurrent real dlopen of libdlopen_cxx.so (pauses in g2a_ctor_barrier) */
        void *dh = dlopen("libdlopen_cxx.so", RTLD_NOW | RTLD_GLOBAL);
        if (!dh) {
            std::fprintf(stderr, "FAIL T6: dlopen(libdlopen_cxx.so) failed: %s\n", dlerror());
            return 1;
        }
        using tc_fn = int (*)(const char *);
        tc_fn dlopen_tc = reinterpret_cast<tc_fn>(dlsym(dh, "dlopen_cxx_throw_and_catch"));
        if (!dlopen_tc || dlopen_tc("afw-g2a-dlopen-payload") != 1) {
            std::fprintf(stderr, "FAIL T6: newly dlopen'd DSO throw/catch failed\n");
            return 1;
        }

        s_t6_stop.store(1, std::memory_order_release);
        (void)pthread_join(dth, nullptr);
        for (int w = 0; w < kWorkers; w++) (void)pthread_join(uth[w], nullptr);

        int during = s_t6_during_ctor.load(std::memory_order_acquire);
        int total_t6 = s_t6_throws.load(std::memory_order_acquire);
        if (s_t6_err.load(std::memory_order_acquire) != 0 ||
            s_dlsym_early.load(std::memory_order_acquire) != 0 ||
            dlsym_state != 0x1337CAFE || during < 40) {
            std::fprintf(stderr,
                         "FAIL T6: err=%d early=%d dlsym_state=0x%x during_ctor=%d total=%d\n",
                         s_t6_err.load(), s_dlsym_early.load(), dlsym_state, during, total_t6);
            return 1;
        }
        std::printf("  [ OK ] T6 concurrent dlopen vs unwind: %d throws during ctor (%d total), "
                    "external dlsym saw post-ctor 0x%x, dlopen'd DSO unwind OK\n",
                    during, total_t6, dlsym_state);
    }

    std::printf("G2A CXX GATE PASSED\n");
    std::fflush(stdout);
    return 0;
}
