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
    afw_tls_layout l;
    afw_tls_segment bad;

    run("libc only (measured)", libc, 1);
    run("p_vaddr=0x10 p_align=64", vaddr, 1);
    run("p_align=0", zero, 1);
    run("64-aligned then 8/8", mixed, 2);
    run("four modules, mixed alignment", many, 4);
    run("no modules", NULL, 0);

    memset(&l, 0, sizeof l);
    bad = (afw_tls_segment){0, 24, 8, 8};
    CHECK(afw_tls_layout_add(&l, &bad) == -2 && l.nmod == 0, "align 24 must be refused, layout unchanged");
    bad = (afw_tls_segment){0, 128 * 1024, 8, 8};
    CHECK(afw_tls_layout_add(&l, &bad) == -3, "align 128KB must be refused");
    bad = (afw_tls_segment){0, 8, 8, 9};
    CHECK(afw_tls_layout_add(&l, &bad) == -4, "filesz > memsz must be refused");
    bad = (afw_tls_segment){0, 8, UINT64_MAX - 2, 0};
    CHECK(afw_tls_layout_add(&l, &bad) == -5 && l.nmod == 0, "memsz overflow must be refused");
    printf("%s (%d failures)\n", fails ? "TLS LAYOUT TEST FAILED" : "TLS LAYOUT TEST PASSED", fails);
    return fails != 0;
}
