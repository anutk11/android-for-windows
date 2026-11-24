/*
 * pthread_mt_test.c - Gate G2-4b multi-threaded Bionic pthreads test PIE.
 *
 * Built with Android NDK against real Android 14 bionic libc.so +
 * libpthread_tdata.so. Exercises real SYS_clone(56) over Windows CreateThread:
 *   1. Joinable pthread_create / pthread_join (8 threads, distinct tid/self, rv)
 *   2. Per-thread errno isolation under concurrent stress
 *   3. Non-zero .tdata (p_filesz > 0) + .tbss isolation in child threads
 *   4. pthread_mutex contention (8 threads x 20,000 increments)
 *   5. pthread_cond_wait / broadcast / signal / timedwait (MONO & REALTIME)
 *   6. pthread_rwlock + pthread_once (8 racing threads) + pthread_key_t dtors
 *   7. PTHREAD_CREATE_DETACHED storm (32 threads, _exit_with_stack_teardown)
 *   8. pthread_sigmask inheritance across pthread_create
 *   9. Deep stack (16KB frame) + concurrent Scudo malloc/free + snprintf
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern uint64_t afw_tdata_get_magic(void);
extern void     afw_tdata_set_magic(uint64_t v);
extern uint64_t afw_tdata_get_tag(void);
extern void     afw_tdata_set_tag(uint64_t v);
extern uint64_t afw_tbss_get(void);
extern void     afw_tbss_set(uint64_t v);

#define TDATA_MAGIC 0x1122334455667788ULL
#define TDATA_TAG   0xCAFEBABE12345678ULL

static int g_fails;
#define CHECK(c, ...) do { \
    if (!(c)) { \
        g_fails++; \
        printf("[FAIL] " __VA_ARGS__); \
        printf("\n"); \
        fflush(stdout); \
    } \
} while (0)

/* ---- Test 1 + 2 + 3: joinable, tid/self, errno, .tdata/.tbss ---- */
typedef struct {
    int id;
    int tid;
    pthread_t self;
    int err_ok;
    int tls_ok;
} basic_arg;

static void *basic_worker(void *p) {
    basic_arg *a = (basic_arg *)p;
    int i;
    uint64_t m0 = afw_tdata_get_magic();
    uint64_t t0 = afw_tdata_get_tag();
    uint64_t z0 = afw_tbss_get();
    uint64_t my_magic, my_tag, my_tbss;

    a->tid = (int)gettid();
    a->self = pthread_self();

    /* Verify initial .tdata (non-zero!) and .tbss (zero) before mutating */
    a->tls_ok = (m0 == TDATA_MAGIC && t0 == TDATA_TAG && z0 == 0);
    my_magic = TDATA_MAGIC ^ ((uint64_t)(a->id + 1) * 0x0101010101010101ULL);
    my_tag   = TDATA_TAG + (uint64_t)a->tid;
    my_tbss  = 0xAA000000ULL + (uint64_t)a->id;
    afw_tdata_set_magic(my_magic);
    afw_tdata_set_tag(my_tag);
    afw_tbss_set(my_tbss);

    a->err_ok = 1;
    for (i = 0; i < 4000; i++) {
        int want = 10 + a->id;
        errno = want;
        if (i % 250 == 0) {
            /* Trigger real bionic errno write via strtol ERANGE */
            char *end = NULL;
            (void)strtol("99999999999999999999999999999", &end, 10);
            if (errno != ERANGE) a->err_ok = 0;
            errno = want;
        }
        if (errno != want) a->err_ok = 0;
        if (afw_tdata_get_magic() != my_magic ||
            afw_tdata_get_tag() != my_tag ||
            afw_tbss_get() != my_tbss)
            a->tls_ok = 0;
    }

    return (void *)(uintptr_t)(0x4200ULL + (uint64_t)a->id);
}

/* ---- Test 4: pthread_mutex contention ---- */
static pthread_mutex_t g_cnt_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_cnt_val;

static void *mutex_worker(void *p) {
    int n = (int)(intptr_t)p;
    int i;
    for (i = 0; i < n; i++) {
        pthread_mutex_lock(&g_cnt_mu);
        g_cnt_val++;
        pthread_mutex_unlock(&g_cnt_mu);
    }
    return NULL;
}

/* ---- Test 5: pthread_cond broadcast + signal ---- */
static pthread_mutex_t g_bcast_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_bcast_ready_cv = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  g_bcast_go_cv = PTHREAD_COND_INITIALIZER;
static int g_bcast_ready;
static int g_bcast_go;
static _Atomic int g_bcast_woke;

static void *bcast_worker(void *p) {
    (void)p;
    pthread_mutex_lock(&g_bcast_mu);
    g_bcast_ready++;
    pthread_cond_signal(&g_bcast_ready_cv);
    while (!g_bcast_go)
        pthread_cond_wait(&g_bcast_go_cv, &g_bcast_mu);
    pthread_mutex_unlock(&g_bcast_mu);
    atomic_fetch_add(&g_bcast_woke, 1);
    return NULL;
}

/* Producer/consumer ring with pthread_cond_signal */
static pthread_mutex_t g_pc_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_pc_cv = PTHREAD_COND_INITIALIZER;
static int g_pc_has_item;
static int g_pc_item;
static int g_pc_sum;

static void *pc_consumer(void *p) {
    int count = (int)(intptr_t)p;
    int i, sum = 0;
    for (i = 0; i < count; i++) {
        pthread_mutex_lock(&g_pc_mu);
        while (!g_pc_has_item)
            pthread_cond_wait(&g_pc_cv, &g_pc_mu);
        sum += g_pc_item;
        g_pc_has_item = 0;
        pthread_cond_signal(&g_pc_cv);
        pthread_mutex_unlock(&g_pc_mu);
    }
    g_pc_sum = sum;
    return NULL;
}

/* Helper for T5 pthread_cond_timedwait (signaled wakeup before deadline) */
typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int ready;
    int go;
} timedwait_ctx;

static void *timedwait_signaler(void *p) {
    timedwait_ctx *tc = (timedwait_ctx *)p;
    pthread_mutex_lock(&tc->mu);
    tc->go = 1;
    pthread_cond_signal(&tc->cv);
    pthread_mutex_unlock(&tc->mu);
    return NULL;
}

static void add_ms(struct timespec *ts, long ms) {
    ts->tv_nsec += ms * 1000000L;
    while (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec += 1;
        ts->tv_nsec -= 1000000000L;
    }
}

/* ---- Test 6: pthread_rwlock + pthread_once + pthread_key_t ---- */
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static _Atomic int g_once_runs;
static void once_fn(void) { atomic_fetch_add(&g_once_runs, 1); }

static pthread_rwlock_t g_rw = PTHREAD_RWLOCK_INITIALIZER;
static int g_rw_shared;
static pthread_key_t g_key;
static _Atomic int g_key_dtor_calls;
static _Atomic uintptr_t g_key_dtor_sum;

static void key_dtor(void *val) {
    atomic_fetch_add(&g_key_dtor_calls, 1);
    atomic_fetch_add(&g_key_dtor_sum, (uintptr_t)val);
}

static void *rw_once_key_worker(void *p) {
    int id = (int)(intptr_t)p;
    int i, ok = 1;
    uintptr_t tag = (uintptr_t)(0x100 + id);
    pthread_once(&g_once, once_fn);
    if (pthread_setspecific(g_key, (void *)tag) != 0) ok = 0;
    for (i = 0; i < 500; i++) {
        if ((i & 7) == 0) {
            pthread_rwlock_wrlock(&g_rw);
            g_rw_shared++;
            pthread_rwlock_unlock(&g_rw);
        } else {
            int v;
            pthread_rwlock_rdlock(&g_rw);
            v = g_rw_shared;
            pthread_rwlock_unlock(&g_rw);
            if (v < 0) ok = 0;
        }
    }
    if ((uintptr_t)pthread_getspecific(g_key) != tag) ok = 0;
    return (void *)(intptr_t)ok;
}

/* ---- Test 7: PTHREAD_CREATE_DETACHED storm ---- */
static pthread_mutex_t g_det_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_det_cv = PTHREAD_COND_INITIALIZER;
static int g_det_done;
static _Atomic int g_det_ok;

static void *detached_worker(void *p) {
    int id = (int)(intptr_t)p;
    int ok = 1;
    char *buf;
    if (afw_tdata_get_magic() != TDATA_MAGIC || afw_tbss_get() != 0) ok = 0;
    afw_tdata_set_magic(TDATA_MAGIC + (uint64_t)id);
    errno = 50 + id;
    buf = (char *)malloc(4096);
    if (!buf) {
        ok = 0;
    } else {
        memset(buf, (int)(id & 0xff), 4096);
        if ((unsigned char)buf[4095] != (unsigned char)(id & 0xff)) ok = 0;
        free(buf);
    }
    if (errno != 50 + id) ok = 0;
    if (ok) atomic_fetch_add(&g_det_ok, 1);

    pthread_mutex_lock(&g_det_mu);
    g_det_done++;
    pthread_cond_signal(&g_det_cv);
    pthread_mutex_unlock(&g_det_mu);
    return NULL; /* returns -> pthread_exit -> _exit_with_stack_teardown */
}

/* ---- Test 8: pthread_sigmask inheritance ---- */
static void *sigmask_worker(void *p) {
    sigset_t cur;
    int *out = (int *)p;
    sigemptyset(&cur);
    if (pthread_sigmask(SIG_SETMASK, NULL, &cur) == 0 && sigismember(&cur, SIGUSR1) == 1)
        *out = 1;
    else
        *out = 0;
    return NULL;
}

/* ---- Test 9: Deep stack (16KB frame -> __chkstk) + Scudo + snprintf ---- */
static void *deep_stack_worker(void *p) {
    int id = (int)(intptr_t)p;
    volatile unsigned char big[16384];
    char line[128];
    int i, ok = 1;
    for (i = 0; i < (int)sizeof big; i += 257)
        big[i] = (unsigned char)((id + i) & 0xff);
    snprintf(line, sizeof line, "worker-%d-tid-%d", id, (int)gettid());
    if (strncmp(line, "worker-", 7) != 0) ok = 0;
    for (i = 0; i < 64; i++) {
        void *q = malloc(1024 + (size_t)(i * 64));
        if (!q) { ok = 0; break; }
        memset(q, id, 1024);
        free(q);
    }
    for (i = 0; i < (int)sizeof big; i += 257)
        if (big[i] != (unsigned char)((id + i) & 0xff)) ok = 0;
    return (void *)(intptr_t)ok;
}

int main(void) {
    int main_tid = (int)gettid();
    printf("[pthread_mt] start: pid=%d main_tid=%d main_tdata=0x%llx\n",
           (int)getpid(), main_tid, (unsigned long long)afw_tdata_get_magic());
    fflush(stdout);

    CHECK(afw_tdata_get_magic() == TDATA_MAGIC && afw_tdata_get_tag() == TDATA_TAG && afw_tbss_get() == 0,
          "main thread initial .tdata/.tbss wrong");
    /* Mutate main thread's .tdata BEFORE spawning children to prove children copy
     * from the pristine .tdata image, NOT from the main thread's mutated copy! */
    afw_tdata_set_magic(0xDEADBEEF00000001ULL);
    afw_tbss_set(0x9999ULL);

    /* Test 1 + 2 + 3: 8 joinable threads */
    {
        pthread_t th[8];
        basic_arg args[8];
        int i, j;
        memset(args, 0, sizeof args);
        for (i = 0; i < 8; i++) {
            args[i].id = i;
            CHECK(pthread_create(&th[i], NULL, basic_worker, &args[i]) == 0,
                  "T1 pthread_create %d failed", i);
        }
        for (i = 0; i < 8; i++) {
            void *rv = NULL;
            CHECK(pthread_join(th[i], &rv) == 0, "T1 pthread_join %d failed", i);
            CHECK(rv == (void *)(uintptr_t)(0x4200ULL + (uint64_t)i), "T1 rv %d mismatch", i);
            CHECK(args[i].tid > 0 && args[i].tid != main_tid, "T1 bad tid %d", args[i].tid);
            CHECK(args[i].self == th[i], "T1 self != pthread_t for %d", i);
            CHECK(args[i].err_ok, "T2 errno isolation failed on thread %d", i);
            CHECK(args[i].tls_ok, "T3 .tdata/.tbss init or isolation failed on thread %d", i);
            for (j = 0; j < i; j++)
                CHECK(args[i].tid != args[j].tid, "T1 duplicate tid %d", args[i].tid);
        }
        CHECK(afw_tdata_get_magic() == 0xDEADBEEF00000001ULL && afw_tbss_get() == 0x9999ULL,
              "T3 main thread TLS corrupted by children");
        printf("[pthread_mt] T1-T3 (joinable, tid/self, errno, .tdata/.tbss): ok\n");
        fflush(stdout);
    }

    /* Test 4: pthread_mutex contention */
    {
        pthread_t th[8];
        int i;
        g_cnt_val = 0;
        for (i = 0; i < 8; i++)
            CHECK(pthread_create(&th[i], NULL, mutex_worker, (void *)(intptr_t)20000) == 0,
                  "T4 pthread_create %d failed", i);
        for (i = 0; i < 8; i++)
            CHECK(pthread_join(th[i], NULL) == 0, "T4 pthread_join %d failed", i);
        CHECK(g_cnt_val == 160000, "T4 mutex counter=%d want 160000", g_cnt_val);
        printf("[pthread_mt] T4 (mutex contention 8x20000=%d): ok\n", g_cnt_val);
        fflush(stdout);
    }

    /* Test 5: pthread_cond broadcast + producer/consumer signal */
    {
        pthread_t th[4], cth;
        int i, want_sum = 0;
        for (i = 0; i < 4; i++)
            CHECK(pthread_create(&th[i], NULL, bcast_worker, NULL) == 0, "T5 bcast create %d", i);
        pthread_mutex_lock(&g_bcast_mu);
        while (g_bcast_ready < 4)
            pthread_cond_wait(&g_bcast_ready_cv, &g_bcast_mu);
        g_bcast_go = 1;
        pthread_cond_broadcast(&g_bcast_go_cv);
        pthread_mutex_unlock(&g_bcast_mu);
        for (i = 0; i < 4; i++)
            CHECK(pthread_join(th[i], NULL) == 0, "T5 bcast join %d", i);
        CHECK(atomic_load(&g_bcast_woke) == 4, "T5 bcast woke=%d want 4", atomic_load(&g_bcast_woke));

        CHECK(pthread_create(&cth, NULL, pc_consumer, (void *)(intptr_t)200) == 0, "T5 pc create");
        for (i = 1; i <= 200; i++) {
            pthread_mutex_lock(&g_pc_mu);
            while (g_pc_has_item)
                pthread_cond_wait(&g_pc_cv, &g_pc_mu);
            g_pc_item = i;
            g_pc_has_item = 1;
            pthread_cond_signal(&g_pc_cv);
            pthread_mutex_unlock(&g_pc_mu);
            want_sum += i;
        }
        CHECK(pthread_join(cth, NULL) == 0, "T5 pc join");
        CHECK(g_pc_sum == want_sum, "T5 pc sum=%d want %d", g_pc_sum, want_sum);

        /* T5c: pthread_cond_timedwait on CLOCK_REALTIME (timeout + signaled wakeup) */
        {
            timedwait_ctx tc;
            pthread_t sth;
            struct timespec dl;
            int r_to, r_sig = 0;

            memset(&tc, 0, sizeof tc);
            CHECK(pthread_mutex_init(&tc.mu, NULL) == 0, "T5 rt mu init");
            CHECK(pthread_cond_init(&tc.cv, NULL) == 0, "T5 rt cv init");

            pthread_mutex_lock(&tc.mu);
            CHECK(clock_gettime(CLOCK_REALTIME, &dl) == 0, "T5 rt clock_gettime");
            add_ms(&dl, 10);
            r_to = pthread_cond_timedwait(&tc.cv, &tc.mu, &dl);
            CHECK(r_to == ETIMEDOUT, "T5 rt timedwait timeout rc=%d want %d", r_to, ETIMEDOUT);

            /* Hold tc.mu while spawning signaler so signaler cannot run before timedwait sleeps */
            CHECK(clock_gettime(CLOCK_REALTIME, &dl) == 0, "T5 rt clock_gettime 2");
            add_ms(&dl, 5000);
            CHECK(pthread_create(&sth, NULL, timedwait_signaler, &tc) == 0, "T5 rt signaler create");
            while (!tc.go && r_sig == 0)
                r_sig = pthread_cond_timedwait(&tc.cv, &tc.mu, &dl);
            pthread_mutex_unlock(&tc.mu);
            CHECK(pthread_join(sth, NULL) == 0, "T5 rt signaler join");
            CHECK(r_sig == 0 && tc.go == 1, "T5 rt timedwait signaled rc=%d go=%d", r_sig, tc.go);

            pthread_cond_destroy(&tc.cv);
            pthread_mutex_destroy(&tc.mu);
        }

        /* T5d: pthread_cond_timedwait on CLOCK_MONOTONIC (timeout + signaled wakeup) */
        {
            timedwait_ctx tc;
            pthread_condattr_t ca;
            pthread_t sth;
            struct timespec dl;
            int r_to, r_sig = 0;

            memset(&tc, 0, sizeof tc);
            CHECK(pthread_mutex_init(&tc.mu, NULL) == 0, "T5 mono mu init");
            CHECK(pthread_condattr_init(&ca) == 0, "T5 mono condattr init");
            CHECK(pthread_condattr_setclock(&ca, CLOCK_MONOTONIC) == 0, "T5 mono setclock");
            CHECK(pthread_cond_init(&tc.cv, &ca) == 0, "T5 mono cv init");
            pthread_condattr_destroy(&ca);

            pthread_mutex_lock(&tc.mu);
            CHECK(clock_gettime(CLOCK_MONOTONIC, &dl) == 0, "T5 mono clock_gettime");
            add_ms(&dl, 10);
            r_to = pthread_cond_timedwait(&tc.cv, &tc.mu, &dl);
            CHECK(r_to == ETIMEDOUT, "T5 mono timedwait timeout rc=%d want %d", r_to, ETIMEDOUT);

            CHECK(clock_gettime(CLOCK_MONOTONIC, &dl) == 0, "T5 mono clock_gettime 2");
            add_ms(&dl, 5000);
            CHECK(pthread_create(&sth, NULL, timedwait_signaler, &tc) == 0, "T5 mono signaler create");
            while (!tc.go && r_sig == 0)
                r_sig = pthread_cond_timedwait(&tc.cv, &tc.mu, &dl);
            pthread_mutex_unlock(&tc.mu);
            CHECK(pthread_join(sth, NULL) == 0, "T5 mono signaler join");
            CHECK(r_sig == 0 && tc.go == 1, "T5 mono timedwait signaled rc=%d go=%d", r_sig, tc.go);

            pthread_cond_destroy(&tc.cv);
            pthread_mutex_destroy(&tc.mu);
        }

        printf("[pthread_mt] T5 (cond broadcast=4, prod/cons sum=%d, timedwait RT+MONO): ok\n", g_pc_sum);
        fflush(stdout);
    }

    /* Test 6: pthread_rwlock + pthread_once + pthread_key_t dtors */
    {
        pthread_t th[8];
        int i;
        uintptr_t want_dtor_sum = 0;
        CHECK(pthread_key_create(&g_key, key_dtor) == 0, "T6 key_create");
        for (i = 0; i < 8; i++) {
            want_dtor_sum += (uintptr_t)(0x100 + i);
            CHECK(pthread_create(&th[i], NULL, rw_once_key_worker, (void *)(intptr_t)i) == 0,
                  "T6 create %d", i);
        }
        for (i = 0; i < 8; i++) {
            void *rv = NULL;
            CHECK(pthread_join(th[i], &rv) == 0 && rv == (void *)(intptr_t)1, "T6 join %d", i);
        }
        pthread_key_delete(g_key);
        CHECK(atomic_load(&g_once_runs) == 1, "T6 pthread_once runs=%d want 1", atomic_load(&g_once_runs));
        CHECK(g_rw_shared == 8 * 63, "T6 rw_shared=%d want %d", g_rw_shared, 8 * 63);
        CHECK(atomic_load(&g_key_dtor_calls) == 8, "T6 key_dtor calls=%d want 8", atomic_load(&g_key_dtor_calls));
        CHECK(atomic_load(&g_key_dtor_sum) == want_dtor_sum, "T6 key_dtor sum mismatch");
        printf("[pthread_mt] T6 (rwlock=%d, once=%d, key_dtors=%d): ok\n",
               g_rw_shared, atomic_load(&g_once_runs), atomic_load(&g_key_dtor_calls));
        fflush(stdout);
    }

    /* Test 7: 32 PTHREAD_CREATE_DETACHED threads (_exit_with_stack_teardown) */
    {
        pthread_attr_t attr;
        int i;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        for (i = 0; i < 32; i++) {
            pthread_t th;
            CHECK(pthread_create(&th, &attr, detached_worker, (void *)(intptr_t)i) == 0,
                  "T7 detached create %d", i);
        }
        pthread_attr_destroy(&attr);
        pthread_mutex_lock(&g_det_mu);
        while (g_det_done < 32)
            pthread_cond_wait(&g_det_cv, &g_det_mu);
        pthread_mutex_unlock(&g_det_mu);
        CHECK(atomic_load(&g_det_ok) == 32, "T7 detached ok=%d want 32", atomic_load(&g_det_ok));
        /* Follow-up joinable thread to prove VMA & thread creation stay healthy after teardown storm */
        {
            pthread_t th;
            basic_arg a;
            void *rv = NULL;
            memset(&a, 0, sizeof a);
            a.id = 99;
            CHECK(pthread_create(&th, NULL, basic_worker, &a) == 0 &&
                  pthread_join(th, &rv) == 0 && a.tls_ok && a.err_ok,
                  "T7 post-detached follow-up thread failed");
        }
        printf("[pthread_mt] T7 (32 detached threads + follow-up joinable): ok\n");
        fflush(stdout);
    }

    /* Test 8: pthread_sigmask inheritance */
    {
        sigset_t set, old;
        pthread_t th;
        int inherited = -1;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        CHECK(pthread_sigmask(SIG_BLOCK, &set, &old) == 0, "T8 sigmask block");
        CHECK(pthread_create(&th, NULL, sigmask_worker, &inherited) == 0, "T8 create");
        CHECK(pthread_join(th, NULL) == 0, "T8 join");
        CHECK(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0, "T8 sigmask restore");
        CHECK(inherited == 1, "T8 child did not inherit SIGUSR1 mask (got %d)", inherited);
        printf("[pthread_mt] T8 (pthread_sigmask inheritance): ok\n");
        fflush(stdout);
    }

    /* Test 9: Deep stack (16KB) + concurrent Scudo + snprintf */
    {
        pthread_t th[4];
        int i;
        for (i = 0; i < 4; i++)
            CHECK(pthread_create(&th[i], NULL, deep_stack_worker, (void *)(intptr_t)i) == 0,
                  "T9 create %d", i);
        for (i = 0; i < 4; i++) {
            void *rv = NULL;
            CHECK(pthread_join(th[i], &rv) == 0 && rv == (void *)(intptr_t)1, "T9 join %d", i);
        }
        printf("[pthread_mt] T9 (deep 16KB stack + Scudo + snprintf): ok\n");
        fflush(stdout);
    }

    if (g_fails == 0) {
        printf("PTHREAD MT TEST PASSED\n");
        fflush(stdout);
        return 0;
    }
    printf("PTHREAD MT TEST FAILED (%d failures)\n", g_fails);
    fflush(stdout);
    return 1;
}
