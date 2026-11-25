/*
 * loader_lock_test.c - Host unit tests for G2-5a loader locking & atomic
 * refcount primitives (afw_libs_rdlock/wrlock, recursive afw_dlopen_lock,
 * afw_os_atomic_add_i32/cmpxchg_i32/load_i32).
 *
 * Built and run on both Linux (ASan+UBSan+pointer-compare) and Windows.
 */
#include "../src/platform.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int g_pass;
static int g_fail;

static void check(const char *name, int cond) {
    if (cond) {
        g_pass++;
    } else {
        fprintf(stderr, "FAIL: %s\n", name);
        g_fail++;
    }
}

/* ---- Test 1: afw_libs_rdlock / afw_libs_wrlock invariant under contention ---- */
static uint64_t g_shared_a;
static uint64_t g_shared_b;
static int32_t g_rw_errors;
static int32_t g_rw_stop;

static void rw_writer(void *arg) {
    int id = *(int *)arg;
    int i;
    for (i = 0; i < 4000; i++) {
        afw_libs_wrlock();
        g_shared_a++;
        /* Tiny busy-step to widen any broken lock window */
        if ((i & 63) == 0) g_shared_b = g_shared_a - 1 + (uint64_t)(id - id);
        g_shared_b = g_shared_a;
        afw_libs_wrunlock();
    }
}

static void rw_reader(void *arg) {
    (void)arg;
    int iters = 0;
    while (!afw_os_atomic_load_i32(&g_rw_stop) || iters < 2000) {
        uint64_t a, b;
        afw_libs_rdlock();
        a = g_shared_a;
        b = g_shared_b;
        afw_libs_rdunlock();
        if (a != b) afw_os_atomic_add_i32(&g_rw_errors, 1);
        iters++;
        if (iters > 200000) break;
    }
}

/* ---- Test 2: afw_dlopen_lock recursive re-entry & mutual exclusion ---- */
static uint64_t g_dlopen_counter;

static void dlopen_worker(void *arg) {
    (void)arg;
    int i;
    for (i = 0; i < 5000; i++) {
        afw_dlopen_lock();
        /* Re-enter recursively on the same thread (simulates constructor calling dlopen) */
        afw_dlopen_lock();
        g_dlopen_counter++;
        afw_dlopen_unlock();
        afw_dlopen_unlock();
    }
}

/* ---- Test 3: atomic i32 add + underflow-guarded CAS decrement ---- */
static int32_t g_refcount;
static int32_t g_atomic_errors;

static void atomic_ref_dec_clamped(int32_t *p) {
    for (;;) {
        int32_t cur = afw_os_atomic_load_i32(p);
        if (cur <= 0) return;
        if (afw_os_atomic_cmpxchg_i32(p, cur, cur - 1) == cur) return;
    }
}

static void atomic_worker(void *arg) {
    (void)arg;
    int i;
    for (i = 0; i < 10000; i++) {
        int32_t v = afw_os_atomic_add_i32(&g_refcount, 1);
        if (v <= 0) afw_os_atomic_add_i32(&g_atomic_errors, 1);
        atomic_ref_dec_clamped(&g_refcount);
    }
}

int main(void) {
    /* 1. RW lock stress */
    {
        afw_os_thread writers[2], readers[6];
        int wids[2] = { 1, 2 };
        int i, ok = 1;
        g_shared_a = 0; g_shared_b = 0;
        afw_os_atomic_store_i32(&g_rw_errors, 0);
        afw_os_atomic_store_i32(&g_rw_stop, 0);
        for (i = 0; i < 6; i++)
            if (afw_os_thread_start(rw_reader, NULL, &readers[i]) != 0) ok = 0;
        for (i = 0; i < 2; i++)
            if (afw_os_thread_start(rw_writer, &wids[i], &writers[i]) != 0) ok = 0;
        for (i = 0; i < 2; i++) afw_os_thread_join(writers[i]);
        afw_os_atomic_store_i32(&g_rw_stop, 1);
        for (i = 0; i < 6; i++) afw_os_thread_join(readers[i]);
        check("rwlock threads started", ok);
        check("rwlock writer mutual exclusion (8000 writes)", g_shared_a == 8000 && g_shared_b == 8000);
        check("rwlock readers saw zero torn state", afw_os_atomic_load_i32(&g_rw_errors) == 0);
    }

    /* 2. Recursive dlopen lock stress */
    {
        afw_os_thread th[4];
        int i, ok = 1;
        g_dlopen_counter = 0;
        /* Direct 4-level recursion on main thread */
        afw_dlopen_lock();
        afw_dlopen_lock();
        afw_dlopen_lock();
        afw_dlopen_lock();
        g_dlopen_counter++;
        afw_dlopen_unlock();
        afw_dlopen_unlock();
        afw_dlopen_unlock();
        afw_dlopen_unlock();
        check("dlopen_lock 4-level same-thread recursion", g_dlopen_counter == 1);

        g_dlopen_counter = 0;
        for (i = 0; i < 4; i++)
            if (afw_os_thread_start(dlopen_worker, NULL, &th[i]) != 0) ok = 0;
        for (i = 0; i < 4; i++) afw_os_thread_join(th[i]);
        check("dlopen_lock threads started", ok);
        check("dlopen_lock mutual exclusion + recursion (20000 increments)", g_dlopen_counter == 20000);
    }

    /* 3. Atomic refcount add / CAS clamped decrement */
    {
        afw_os_thread th[8];
        int i, ok = 1;
        afw_os_atomic_store_i32(&g_refcount, 0);
        afw_os_atomic_store_i32(&g_atomic_errors, 0);
        for (i = 0; i < 8; i++)
            if (afw_os_thread_start(atomic_worker, NULL, &th[i]) != 0) ok = 0;
        for (i = 0; i < 8; i++) afw_os_thread_join(th[i]);
        check("atomic refcount threads started", ok);
        check("atomic refcount balanced to exact 0", afw_os_atomic_load_i32(&g_refcount) == 0);
        check("atomic add never saw <= 0", afw_os_atomic_load_i32(&g_atomic_errors) == 0);

        /* Underflow clamping */
        atomic_ref_dec_clamped(&g_refcount);
        atomic_ref_dec_clamped(&g_refcount);
        check("clamped decrement stays at 0", afw_os_atomic_load_i32(&g_refcount) == 0);
        check("cmpxchg fails when expected mismatches",
              afw_os_atomic_cmpxchg_i32(&g_refcount, 7, 9) == 0 && afw_os_atomic_load_i32(&g_refcount) == 0);
        check("cmpxchg succeeds when expected matches",
              afw_os_atomic_cmpxchg_i32(&g_refcount, 0, 5) == 0 && afw_os_atomic_load_i32(&g_refcount) == 5);
    }

    printf("loader_lock_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail != 0;
}
