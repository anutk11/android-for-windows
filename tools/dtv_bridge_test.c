/*
 * dtv_bridge_test.c - Host unit tests for G2-5b:
 *   1. Dynamic PT_TLS registration, Phase A unregister rollback, Phase B
 *      finalization (owned .tdata copy), non-allocating afw_tls_resolve_existing,
 *      lazy per-thread DTV allocation (64B alignment, .tdata copy, .tbss zeroing),
 *      multi-thread isolation, and automatic FLS / explicit detach cleanup.
 *   2. Loader callback bridge trampoline (lazy W^X RX init, SysV argument/return
 *      forwarding, synthetic PT_LOAD + PT_GNU_EH_FRAME metadata, and DWARF
 *      .eh_frame_hdr / FDE bounds verified via afw_func_bounds & afw_func_list).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/platform.h"
#include "../src/tls_layout.h"
#include "../src/tls_patch.h"
#include "../src/tls_static.h"
#include "../src/callback_bridge.h"
#include "../src/elf_loader.h"
#include "../src/funcs.h"
#include "../src/thread.h"

/* Minimal stubs for bionic_shim.c / thread.c symbols referenced by tls_static.c
 * and tls_patch.c so this unit test links cleanly without pulling in the full loader. */
void afw_shared_globals_set_static_tls(const afw_bionic_static_tls *stl) { (void)stl; }
void afw_thread_set_tls_ops(afw_tls_init_static_fn init_static,
                            afw_tls_attach_ext_fn attach_ext,
                            afw_tls_detach_ext_fn detach_ext,
                            afw_tls_tp_off_fn tp_off) {
    (void)init_static; (void)attach_ext; (void)detach_ext; (void)tp_off;
}
const unsigned char *afw_shared_globals_random(void) {
    static const unsigned char seed[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01
    };
    return seed;
}

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL (%s:%d): %s\n", __FILE__, __LINE__, msg); } \
} while (0)

static int g_dyn_mod = 0;
static const uint64_t g_expected_tdata[3] = {
    0x1122334455667788ULL,
    0xCAFEBABE01020304ULL,
    0xA5A5A5A55A5A5A5AULL
};

typedef struct {
    int id;
    int explicit_free;
    int ok;
    uintptr_t tls_ptr;
} worker_arg;

static int32_t g_barrier_arrived = 0;
static int32_t g_barrier_checked = 0;

static void dtv_worker(void *p) {
    worker_arg *w = (worker_arg *)p;
    afw_tls_index ti;
    unsigned char *blk;
    uint64_t vals[3];
    size_t i;
    int good = 1;

    /* Before first access: non-allocating lookup MUST return NULL */
    if (afw_tls_resolve_existing((uint64_t)g_dyn_mod) != NULL) good = 0;

    ti.module = (uint64_t)g_dyn_mod;
    ti.offset = 0;
    blk = (unsigned char *)afw_tls_get_addr(&ti);
    if (!blk) { w->ok = 0; return; }
    w->tls_ptr = (uintptr_t)blk;

    /* Verify 64-byte alignment */
    if (((uintptr_t)blk % 64u) != 0) good = 0;

    /* Verify .tdata initialized cleanly */
    memcpy(vals, blk, sizeof vals);
    for (i = 0; i < 3; i++) {
        if (vals[i] != g_expected_tdata[i]) good = 0;
    }

    /* Verify .tbss [24..128) is all zeros */
    for (i = 24; i < 128; i++) {
        if (blk[i] != 0) { good = 0; break; }
    }

    /* Mutate per-thread TLS and verify non-allocating lookup returns same block */
    {
        uint64_t tag = 0xDE000000ULL + (uint64_t)w->id;
        memcpy(blk + 32, &tag, 8);
        if (afw_tls_resolve_existing((uint64_t)g_dyn_mod) != blk) good = 0;

        /* For the 4 FLS-auto-freed workers, hold all 4 blocks live simultaneously
         * to prove distinct allocations and zero cross-thread clobbering. */
        if (!w->explicit_free) {
            (void)afw_os_atomic_add_i32(&g_barrier_arrived, 1);
            while (afw_os_atomic_load_i32(&g_barrier_arrived) < 4) {}
        }

        /* Offset lookup inside the same dynamic module */
        ti.offset = 32;
        if (afw_tls_get_addr(&ti) != blk + 32) good = 0;
        {
            uint64_t readback = 0;
            memcpy(&readback, afw_tls_get_addr(&ti), 8);
            if (readback != tag) good = 0;
        }

        if (!w->explicit_free) {
            (void)afw_os_atomic_add_i32(&g_barrier_checked, 1);
            while (afw_os_atomic_load_i32(&g_barrier_checked) < 4) {}
        }
    }

    if (w->explicit_free) {
        /* Simulate Bionic afw_tls_thread_detach_external() + idempotent second call */
        afw_tls_dtv_free_current();
        if (afw_tls_resolve_existing((uint64_t)g_dyn_mod) != NULL) good = 0;
        afw_tls_dtv_free_current();
    }

    w->ok = good;
}

typedef struct {
    int a;
    int b;
    int calls;
} bridge_cb_ctx;

static SYSV int sample_bridge_cb(void *arg) {
    bridge_cb_ctx *c = (bridge_cb_ctx *)arg;
    c->calls++;
    return c->a * 10 + c->b;
}

static void test_dynamic_tls(void) {
    unsigned char static_img[16] = { 0x42, 0x43, 0x44, 0x45 };
    unsigned char dyn_img[24];
    afw_tls_segment sseg, dseg;
    int m_static, m_tmp, m_dyn;
    afw_tls_index ti;
    unsigned char *main_blk;
    worker_arg w[6];
    afw_os_thread th[6];
    int i, j;

    CHECK(afw_tls_init() == 0, "afw_tls_init succeeds");
    memset(&sseg, 0, sizeof sseg);
    sseg.p_filesz = 16; sseg.p_memsz = 32; sseg.p_align = 16;
    m_static = afw_tls_static_register(static_img, &sseg, "test_static.so");
    CHECK(m_static == 1, "static TLS module gets id 1");
    CHECK(afw_tls_is_static_module(m_static) == 1, "m_static is static");
    CHECK(afw_tls_static_finish() == 0, "afw_tls_static_finish succeeds");
    CHECK(afw_tls_resolve_existing((uint64_t)m_static) != NULL, "static module resolves on main thread");

    /* Register + unregister rollback before finalize */
    memcpy(dyn_img, g_expected_tdata, sizeof dyn_img);
    memset(&dseg, 0, sizeof dseg);
    dseg.p_filesz = 24; dseg.p_memsz = 128; dseg.p_align = 64;

    m_tmp = afw_tls_static_register(dyn_img, &dseg, "test_rollback.so");
    CHECK(m_tmp == AFW_TLS_DYN_BASE, "first dynamic module gets AFW_TLS_DYN_BASE");
    CHECK(afw_tls_is_dynamic_module(m_tmp) == 1, "m_tmp is dynamic");
    CHECK(afw_tls_is_static_module(m_tmp) == 0, "m_tmp is not static");
    CHECK(afw_tls_dynamic_is_finalized(m_tmp) == 0, "m_tmp not finalized yet");
    CHECK(afw_tls_resolve_existing((uint64_t)m_tmp) == NULL, "unfinalized dynamic resolves to NULL");
    CHECK(afw_tls_static_unregister(m_tmp) == 0, "unfinalized dynamic unregister succeeds");

    /* Re-register reuses the rolled-back slot */
    m_dyn = afw_tls_static_register(dyn_img, &dseg, "test_dyn.so");
    CHECK(m_dyn == AFW_TLS_DYN_BASE, "re-registered dynamic module reuses slot");
    CHECK(afw_tls_dynamic_finalize(m_dyn) == 0, "afw_tls_dynamic_finalize succeeds");
    CHECK(afw_tls_dynamic_is_finalized(m_dyn) == 1, "dynamic module reports finalized");
    CHECK(afw_tls_static_unregister(m_dyn) == -1, "finalized dynamic module cannot be unregistered");
    CHECK(afw_tls_static_memsz(m_dyn) == 128, "afw_tls_static_memsz reports dynamic memsz");

    /* Overwrite source .tdata buffer to prove finalize made an owned copy */
    memset(dyn_img, 0xCC, sizeof dyn_img);

    /* Non-allocating lookup BEFORE first access on main thread */
    CHECK(afw_tls_resolve_existing((uint64_t)m_dyn) == NULL, "dlpi_tls_data is NULL before lazy touch");

    /* Lazy allocation on main thread */
    ti.module = (uint64_t)m_dyn;
    ti.offset = 0;
    main_blk = (unsigned char *)afw_tls_get_addr(&ti);
    CHECK(main_blk != NULL, "main thread dynamic TLS allocated");
    CHECK(((uintptr_t)main_blk % 64u) == 0, "main thread dynamic TLS 64B aligned");
    CHECK(memcmp(main_blk, g_expected_tdata, sizeof g_expected_tdata) == 0,
          "main thread dynamic TLS copied owned .tdata");
    {
        int tbss_zero = 1;
        for (i = 24; i < 128; i++) if (main_blk[i] != 0) tbss_zero = 0;
        CHECK(tbss_zero, "main thread dynamic TLS .tbss is zero");
    }
    CHECK(afw_tls_resolve_existing((uint64_t)m_dyn) == main_blk,
          "dlpi_tls_data returns allocated block after touch");

    /* Multi-thread isolation + FLS auto-free (workers 0..3) + explicit detach (workers 4..5) */
    g_dyn_mod = m_dyn;
    afw_os_atomic_store_i32(&g_barrier_arrived, 0);
    afw_os_atomic_store_i32(&g_barrier_checked, 0);
    for (i = 0; i < 6; i++) {
        w[i].id = i + 1;
        w[i].explicit_free = (i >= 4);
        w[i].ok = 0;
        w[i].tls_ptr = 0;
        CHECK(afw_os_thread_start(dtv_worker, &w[i], &th[i]) == 0, "spawn DTV worker");
    }
    for (i = 0; i < 6; i++) {
        CHECK(afw_os_thread_join(th[i]) == 0, "join DTV worker");
        CHECK(w[i].ok == 1, "DTV worker verified alignment, .tdata, .tbss, isolation");
        CHECK(w[i].tls_ptr != (uintptr_t)main_blk, "worker DTV distinct from main thread");
    }
    for (i = 0; i < 4; i++) {
        for (j = i + 1; j < 4; j++) {
            CHECK(w[i].tls_ptr != w[j].tls_ptr, "simultaneous worker DTV pointers are pairwise distinct");
        }
    }

    /* Clean up main thread DTV so LSan sees zero leaks */
    afw_tls_dtv_free_current();
    CHECK(afw_tls_resolve_existing((uint64_t)m_dyn) == NULL, "main thread DTV cleared after free");
}

static void test_callback_bridge(void) {
    uint64_t addr = 0;
    const char *name = NULL;
    const Elf64_Phdr *phdr = NULL;
    uint16_t phnum = 0;
    void *entry, *entry2;
    typedef SYSV int (*bridge_fn)(SYSV int (*cb)(void *), void *arg);
    bridge_cb_ctx ctx = { 4, 2, 0 };
    int rc;
    afw_lib syn;
    unsigned off;
    unsigned char **starts = NULL;
    size_t *sizes = NULL;
    int nfuncs;

    /* Lazy: before first lookup, bridge is not reported in dl_iterate_phdr */
    CHECK(afw_callback_bridge_phdr(&addr, &name, &phdr, &phnum) == 0,
          "callback bridge stays inactive before first entry lookup");

    entry = afw_callback_bridge_entry();
    entry2 = afw_callback_bridge_entry();
    CHECK(entry != NULL, "afw_callback_bridge_entry allocates RX trampoline");
    CHECK(entry == entry2, "afw_callback_bridge_entry is idempotent");

    CHECK(afw_callback_bridge_phdr(&addr, &name, &phdr, &phnum) == 1,
          "afw_callback_bridge_phdr active after init");
    CHECK(addr == (uint64_t)(uintptr_t)entry, "bridge dlpi_addr matches entry");
    CHECK(name && strcmp(name, "[afw-callback-bridge]") == 0, "bridge dlpi_name matches");
    CHECK(phnum == 2 && phdr != NULL, "bridge exposes 2 phdrs");
    CHECK(phdr[0].p_type == PT_LOAD && (phdr[0].p_flags & (PF_R | PF_X)) == (PF_R | PF_X) &&
          !(phdr[0].p_flags & PF_W), "phdr[0] is W^X RX PT_LOAD");
    CHECK(phdr[1].p_type == PT_GNU_EH_FRAME && phdr[1].p_vaddr == AFW_CALLBACK_BRIDGE_EH_HDR_OFF,
          "phdr[1] is PT_GNU_EH_FRAME at +0x200");

    /* Invoke trampoline via SysV ABI */
    rc = ((bridge_fn)entry)(sample_bridge_cb, &ctx);
    CHECK(rc == 42 && ctx.calls == 1, "trampoline forwards SysV callback and return value");

    /* Verify DWARF .eh_frame_hdr + CIE + FDE with our own bounds-checked parser (funcs.c) */
    memset(&syn, 0, sizeof syn);
    syn.base = (unsigned char *)entry;
    syn.size = AFW_PAGE_SIZE;
    syn.eh_frame_hdr = (const unsigned char *)entry + phdr[1].p_vaddr;

    for (off = 0; off < AFW_CALLBACK_BRIDGE_CODE_SIZE; off++) {
        uint64_t s = 0, e = 0;
        int found = afw_func_bounds(&syn, (uint64_t)(uintptr_t)entry + off, &s, &e);
        if (!found || s != (uint64_t)(uintptr_t)entry ||
            e != (uint64_t)(uintptr_t)entry + AFW_CALLBACK_BRIDGE_CODE_SIZE) {
            CHECK(0, "afw_func_bounds failed on bridge instruction offset");
            break;
        }
    }
    if (off == AFW_CALLBACK_BRIDGE_CODE_SIZE) {
        CHECK(1, "afw_func_bounds covers all 14 bytes of callback bridge exactly");
    }
    {
        uint64_t s = 0, e = 0;
        CHECK(afw_func_bounds(&syn, (uint64_t)(uintptr_t)entry + AFW_CALLBACK_BRIDGE_CODE_SIZE, &s, &e) == 0,
              "afw_func_bounds rejects address immediately past bridge end");
    }

    nfuncs = afw_func_list(&syn, &starts, &sizes);
    CHECK(nfuncs == 1 && starts && sizes &&
          starts[0] == (unsigned char *)entry &&
          sizes[0] == AFW_CALLBACK_BRIDGE_CODE_SIZE,
          "afw_func_list decodes exact 1 FDE [entry, entry+14)");
    free(starts);
    free(sizes);
}

int main(void) {
    test_dynamic_tls();
    test_callback_bridge();
    printf("dtv_bridge_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
