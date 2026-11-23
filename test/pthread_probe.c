/*
 * pthread_probe.c - Gate G2 Stage-0 (G2-1) measurement-only Android PIE.
 *
 * Runs against the real Android 14 bionic libc.so under afw-loader with
 * --probe-syscalls to measure (without implementing SYS_clone):
 *   1. Exact futex opcodes/flags used by pthread_mutex, pthread_once,
 *      pthread_rwlock, pthread_cond (signal, broadcast, timedwait on both
 *      CLOCK_REALTIME and CLOCK_MONOTONIC).
 *   2. Exact clone(56) flags, child_stack layout, ptid/ctid, newtls slots,
 *      and stub return address emitted by bionic pthread_create() for both
 *      joinable and detached threads (expecting -ENOSYS from the loader).
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int g_once_count;
static pthread_once_t g_once_ctrl = PTHREAD_ONCE_INIT;

static void once_init(void) {
    g_once_count++;
}

static void *dummy_worker(void *arg) {
    return arg;
}

static void add_ms(struct timespec *ts, long ms) {
    ts->tv_nsec += ms * 1000000L;
    while (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec += 1;
        ts->tv_nsec -= 1000000000L;
    }
}

int main(void) {
    int ok = 1;
    int rc;

    printf("[pthread_probe] start: pid=%d tid=%d self=%p dummy_worker=%p\n",
           (int)getpid(), (int)gettid(), (void *)pthread_self(), (void *)(uintptr_t)dummy_worker);
    fflush(stdout);

    /* 1. pthread_once */
    rc = pthread_once(&g_once_ctrl, once_init);
    rc |= pthread_once(&g_once_ctrl, once_init);
    printf("[pthread_probe] pthread_once: rc=%d count=%d\n", rc, g_once_count);
    if (rc != 0 || g_once_count != 1) ok = 0;

    /* 2. pthread_mutex (normal + recursive) */
    {
        pthread_mutex_t m;
        pthread_mutexattr_t ma;
        int r1, r2, r3;
        r1 = pthread_mutex_init(&m, NULL);
        r2 = pthread_mutex_lock(&m);
        r3 = pthread_mutex_unlock(&m);
        pthread_mutex_destroy(&m);
        printf("[pthread_probe] mutex(normal): init=%d lock=%d unlock=%d\n", r1, r2, r3);
        if (r1 || r2 || r3) ok = 0;

        pthread_mutexattr_init(&ma);
        pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
        r1 = pthread_mutex_init(&m, &ma);
        r2 = pthread_mutex_lock(&m) | pthread_mutex_lock(&m);
        r3 = pthread_mutex_unlock(&m) | pthread_mutex_unlock(&m);
        pthread_mutex_destroy(&m);
        pthread_mutexattr_destroy(&ma);
        printf("[pthread_probe] mutex(recursive): init=%d lock=%d unlock=%d\n", r1, r2, r3);
        if (r1 || r2 || r3) ok = 0;
    }

    /* 3. pthread_rwlock */
    {
        pthread_rwlock_t rw;
        int r1 = pthread_rwlock_init(&rw, NULL);
        int r2 = pthread_rwlock_rdlock(&rw);
        int r3 = pthread_rwlock_unlock(&rw);
        int r4 = pthread_rwlock_wrlock(&rw);
        int r5 = pthread_rwlock_unlock(&rw);
        pthread_rwlock_destroy(&rw);
        printf("[pthread_probe] rwlock: init=%d rd=%d u1=%d wr=%d u2=%d\n", r1, r2, r3, r4, r5);
        if (r1 || r2 || r3 || r4 || r5) ok = 0;
    }

    /* 4. pthread_key_t */
    {
        pthread_key_t k;
        void *got = NULL;
        int r1 = pthread_key_create(&k, NULL);
        int r2 = pthread_setspecific(k, (void *)(uintptr_t)0xCAFEBABEULL);
        got = pthread_getspecific(k);
        pthread_key_delete(k);
        printf("[pthread_probe] pthread_key: create=%d set=%d got=%p\n", r1, r2, got);
        if (r1 || r2 || got != (void *)(uintptr_t)0xCAFEBABEULL) ok = 0;
    }

    /* 5. pthread_cond: signal, broadcast, timedwait (CLOCK_REALTIME & CLOCK_MONOTONIC) */
    {
        pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
        pthread_cond_t c_rt = PTHREAD_COND_INITIALIZER;
        pthread_cond_t c_mono;
        pthread_condattr_t ca;
        struct timespec dl;
        int r_sig, r_bcast, r_tw_rt, r_tw_mono;

        r_sig = pthread_cond_signal(&c_rt);
        r_bcast = pthread_cond_broadcast(&c_rt);

        pthread_mutex_lock(&m);
        clock_gettime(CLOCK_REALTIME, &dl);
        add_ms(&dl, 2);
        r_tw_rt = pthread_cond_timedwait(&c_rt, &m, &dl);
        pthread_mutex_unlock(&m);

        pthread_condattr_init(&ca);
        pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
        pthread_cond_init(&c_mono, &ca);
        pthread_condattr_destroy(&ca);

        pthread_mutex_lock(&m);
        clock_gettime(CLOCK_MONOTONIC, &dl);
        add_ms(&dl, 2);
        r_tw_mono = pthread_cond_timedwait(&c_mono, &m, &dl);
        pthread_mutex_unlock(&m);

        r_bcast |= pthread_cond_broadcast(&c_mono);
        pthread_cond_destroy(&c_mono);
        pthread_cond_destroy(&c_rt);
        pthread_mutex_destroy(&m);

        printf("[pthread_probe] cond: signal=%d broadcast=%d timedwait(RT)=%d(ETIMEDOUT=%d) timedwait(MONO)=%d\n",
               r_sig, r_bcast, r_tw_rt, ETIMEDOUT, r_tw_mono);
        if (r_sig != 0 || r_bcast != 0 || r_tw_rt != ETIMEDOUT || r_tw_mono != ETIMEDOUT) ok = 0;
    }

    /* 6. pthread_create (joinable): expected to hit clone(56) -> ENOSYS */
    {
        pthread_t th;
        void *marker = (void *)(uintptr_t)0x123456789ABCDEF0ULL;
        printf("[pthread_probe] calling pthread_create(joinable, fn=%p, arg=%p)...\n",
               (void *)(uintptr_t)dummy_worker, marker);
        fflush(stdout);
        rc = pthread_create(&th, NULL, dummy_worker, marker);
        printf("[pthread_probe] pthread_create(joinable) returned rc=%d (%s)\n", rc, strerror(rc));
        fflush(stdout);
        if (rc != ENOSYS) ok = 0;
    }

    /* 7. pthread_create (detached): compare clone flags & newtls */
    {
        pthread_t th;
        pthread_attr_t attr;
        void *marker = (void *)(uintptr_t)0x0FEDCBA987654321ULL;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        printf("[pthread_probe] calling pthread_create(detached, fn=%p, arg=%p)...\n",
               (void *)(uintptr_t)dummy_worker, marker);
        fflush(stdout);
        rc = pthread_create(&th, &attr, dummy_worker, marker);
        pthread_attr_destroy(&attr);
        printf("[pthread_probe] pthread_create(detached) returned rc=%d (%s)\n", rc, strerror(rc));
        fflush(stdout);
        if (rc != ENOSYS) ok = 0;
    }

    printf("VERDICT Item 1 (Bionic pthread/clone/futex syscall profile): %s\n", ok ? "PASS" : "FAIL");
    fflush(stdout);
    return ok ? 0 : 1;
}
