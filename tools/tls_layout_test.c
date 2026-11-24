/* Host unit test of the static TLS layout (reviewer 3's synthetic cases). */
#include "../src/tls_layout.h"

#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* Every invariant, for every block base that is page aligned. */
static void verify(const char *name, const afw_tls_layout *l, const afw_tls_segment *s, int n) {
    int m;
    uint64_t base = 0x10000;                     /* any 64KB-aligned base */
    uint64_t tp = base + l->tp_off;
    CHECK(tp % l->max_align == 0, "%s: tp not aligned to %llu", name, (unsigned long long)l->max_align);
    CHECK(l->tp_off + AFW_TLS_SLOTS_BYTES <= l->alloc_size, "%s: no 128 bytes after tp", name);
    CHECK(l->alloc_size % 4096 == 0, "%s: size not page multiple", name);
    for (m = 0; m < n; m++) {
        uint64_t a = s[m].p_align ? s[m].p_align : 1;
        uint64_t start = tp - l->off[m];
        CHECK(l->off[m] <= l->tp_off, "%s: module %d below the block", name, m);
        CHECK(start % a == s[m].p_vaddr % a, "%s: module %d start %% align = %llu, want %llu", name, m,
              (unsigned long long)(start % a), (unsigned long long)(s[m].p_vaddr % a));
        if (m) CHECK(l->off[m] >= l->off[m - 1] + s[m].p_memsz, "%s: module %d overlaps module %d", name, m, m - 1);
        else CHECK(l->off[0] >= s[0].p_memsz, "%s: module 0 overlaps the slots", name);
    }
    printf("ok   %-34s tp_off=%llu size=%llu", name, (unsigned long long)l->tp_off, (unsigned long long)l->alloc_size);
    for (m = 0; m < n; m++) printf(" off[%d]=%llu", m, (unsigned long long)l->off[m]);
    printf("\n");

    {
        afw_bionic_static_tls stl;
        uint64_t want_align = l->max_align < AFW_BIONIC_TLS_ALIGN ? AFW_BIONIC_TLS_ALIGN : l->max_align;
        uint64_t want_bionic_tls = (l->tp_off + AFW_BIONIC_TCB_SIZE + AFW_BIONIC_TLS_ALIGN - 1) &
                                   ~(uint64_t)(AFW_BIONIC_TLS_ALIGN - 1);
        uint64_t want_size = (want_bionic_tls + AFW_BIONIC_TLS_SIZE + want_align - 1) &
                             ~(want_align - 1);
        /* Simulate libc __allocate_thread_mapping (0xcc96c..0xcc974):
         * static_tls_base = (mapping_end - 0x1000) - size_ where mapping_end is 4KB-aligned. */
        uint64_t sim_mapping_end = 0x100000ULL + 0x1000ULL; /* intentionally non-64KB page boundary */
        uint64_t sim_stl_base = (sim_mapping_end - 0x1000ULL) - want_size;
        uint64_t sim_tp = sim_stl_base + l->tp_off;

        CHECK(afw_tls_layout_to_bionic(l, &stl) == 0, "%s: layout_to_bionic failed", name);
        CHECK(stl.overflowed == 0, "%s: overflowed must be 0", name);
        CHECK(stl.align == want_align, "%s: align=%llu want %llu", name,
              (unsigned long long)stl.align, (unsigned long long)want_align);
        CHECK(stl.offset_thread_pointer == l->tp_off, "%s: tp_off=%llu want %llu", name,
              (unsigned long long)stl.offset_thread_pointer, (unsigned long long)l->tp_off);
        CHECK(stl.offset_bionic_tls == want_bionic_tls, "%s: bionic_tls_off=0x%llx want 0x%llx", name,
              (unsigned long long)stl.offset_bionic_tls, (unsigned long long)want_bionic_tls);
        CHECK(stl.size == want_size, "%s: size=0x%llx want 0x%llx", name,
              (unsigned long long)stl.size, (unsigned long long)want_size);
        CHECK(sim_stl_base % stl.align == 0, "%s: simulated static_tls_base not aligned to %llu", name,
              (unsigned long long)stl.align);
        CHECK(sim_tp % stl.align == 0, "%s: simulated tp not aligned to %llu", name,
              (unsigned long long)stl.align);
        /* Main-thread compatibility: [0, stl.size) fits inside afw_tls_static_alloc's
         * alloc_size + 128KB (AFW_THREAD_AREA_SIZE) buffer so __libc_get_static_tls_bounds stays in-bounds. */
        CHECK(stl.size <= l->alloc_size + (128u * 1024u), "%s: stl.size exceeds main-thread allocation", name);
        for (m = 0; m < n; m++) {
            uint64_t a = s[m].p_align ? s[m].p_align : 1;
            uint64_t start = stl.offset_thread_pointer - l->off[m];
            uint64_t sim_mod = sim_tp - l->off[m];
            CHECK(l->off[m] <= stl.offset_thread_pointer, "%s: mod %d underflows bionic static_tls", name, m);
            CHECK(start + s[m].p_memsz <= stl.offset_thread_pointer, "%s: mod %d overlaps bionic_tcb", name, m);
            CHECK(sim_mod % a == s[m].p_vaddr % a, "%s: simulated child mod %d alignment broken", name, m);
        }
    }
}

static void run(const char *name, const afw_tls_segment *s, int n) {
    afw_tls_layout l;
    int m;
    memset(&l, 0, sizeof l);
    for (m = 0; m < n; m++) CHECK(afw_tls_layout_add(&l, &s[m]) == m, "%s: add %d", name, m);
    CHECK(afw_tls_layout_finish(&l) == 0, "%s: finish", name);
    verify(name, &l, s, n);
}

int main(void) {
    static const afw_tls_segment libc[] = {{0, 8, 8, 0}};                  /* measured: libc PT_TLS */
    static const afw_tls_segment vaddr[] = {{0x10, 64, 24, 8}};            /* p_vaddr % p_align != 0 */
    static const afw_tls_segment zero[] = {{3, 0, 5, 5}};                  /* p_align 0 means 1 */
    static const afw_tls_segment mixed[] = {{0, 64, 64, 0}, {0, 8, 8, 8}}; /* reviewer 3 bug case */
    static const afw_tls_segment many[] = {{0, 16, 100, 4}, {0x28, 64, 3, 3}, {0, 4096, 1, 0}, {7, 8, 9, 9}};
    static const afw_tls_segment over4k[] = {{0, 8192, 16, 8}};            /* > 4096: exceeds __allocate_thread_mapping */
    static const afw_tls_segment maxa[] = {{0, 65536, 16, 8}};             /* 64KB max G1-TLS alignment */
    afw_tls_layout l;
    afw_tls_segment bad;
    afw_bionic_static_tls stl;

    run("libc only (measured)", libc, 1);
    run("p_vaddr=0x10 p_align=64", vaddr, 1);
    run("p_align=0", zero, 1);
    run("64-aligned then 8/8", mixed, 2);
    run("four modules, mixed alignment", many, 4);
    run("no modules", NULL, 0);

    /* Concrete oracle cross-check for pinned Android 14 libc.so (p_align=8, p_memsz=8):
     * tp_off=0x10, align=0x10, overflowed=0, offset_bionic_tls=0x60, size=roundup(0x60+0x2fa8, 16)=0x3010 */
    memset(&l, 0, sizeof l);
    CHECK(afw_tls_layout_add(&l, &libc[0]) == 0 && afw_tls_layout_finish(&l) == 0, "libc concrete layout");
    CHECK(afw_tls_layout_to_bionic(&l, &stl) == 0, "libc concrete bionic layout");
    CHECK(stl.size == 0x3010 && stl.align == 0x10 && stl.overflowed == 0 &&
          stl.offset_thread_pointer == 0x10 && stl.offset_bionic_tls == 0x60,
          "libc oracle mismatch: size=0x%llx align=0x%llx ov=%llu tp=0x%llx btls=0x%llx",
          (unsigned long long)stl.size, (unsigned long long)stl.align, (unsigned long long)stl.overflowed,
          (unsigned long long)stl.offset_thread_pointer, (unsigned long long)stl.offset_bionic_tls);

    /* Layouts with max_align > 4096 are valid for G1-TLS (<= 64KB), but refused by
     * afw_tls_layout_to_bionic because __allocate_thread_mapping only guarantees 4KB alignment. */
    memset(&l, 0, sizeof l);
    CHECK(afw_tls_layout_add(&l, &over4k[0]) == 0 && afw_tls_layout_finish(&l) == 0, "8KB G1-TLS layout");
    CHECK(afw_tls_layout_to_bionic(&l, &stl) == -5, "max_align=8192 must be refused by layout_to_bionic");
    memset(&l, 0, sizeof l);
    CHECK(afw_tls_layout_add(&l, &maxa[0]) == 0 && afw_tls_layout_finish(&l) == 0, "64KB G1-TLS layout");
    CHECK(afw_tls_layout_to_bionic(&l, &stl) == -5, "max_align=65536 must be refused by layout_to_bionic");

    memset(&l, 0, sizeof l);
    bad = (afw_tls_segment){0, 24, 8, 8};
    CHECK(afw_tls_layout_add(&l, &bad) == -2 && l.nmod == 0, "align 24 must be refused, layout unchanged");
    bad = (afw_tls_segment){0, 128 * 1024, 8, 8};
    CHECK(afw_tls_layout_add(&l, &bad) == -3, "align 128KB must be refused");
    bad = (afw_tls_segment){0, 8, 8, 9};
    CHECK(afw_tls_layout_add(&l, &bad) == -4, "filesz > memsz must be refused");
    bad = (afw_tls_segment){0, 8, UINT64_MAX - 2, 0};
    CHECK(afw_tls_layout_add(&l, &bad) == -5 && l.nmod == 0, "memsz overflow must be refused");

    /* Invalid / unfinished layouts rejected by afw_tls_layout_to_bionic */
    memset(&l, 0, sizeof l);
    CHECK(afw_tls_layout_to_bionic(&l, &stl) == -5, "unfinished layout (max_align=0) must be refused");
    l.max_align = 24;
    CHECK(afw_tls_layout_to_bionic(&l, &stl) == -5, "non-power-of-two max_align must be refused");
    l.max_align = 16; l.tp_off = 8;
    CHECK(afw_tls_layout_to_bionic(&l, &stl) == -5, "unaligned tp_off must be refused");
    l.max_align = 16; l.tp_off = UINT64_MAX - 15;
    CHECK(afw_tls_layout_to_bionic(&l, &stl) == -5, "tp_off overflow must be refused");

    printf("%s (%d failures)\n", fails ? "TLS LAYOUT TEST FAILED" : "TLS LAYOUT TEST PASSED", fails);
    return fails != 0;
}
