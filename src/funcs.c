/*
 * funcs.c - Function boundaries from .eh_frame_hdr / .eh_frame (DWARF CFI).
 */
#include "funcs.h"
#include "elf_loader.h"

#include <stdlib.h>
#include <string.h>

/* DWARF pointer encodings */
#define PE_OMIT 0xff
#define PE_ULEB128 0x01
#define PE_UDATA2 0x02
#define PE_UDATA4 0x03
#define PE_UDATA8 0x04
#define PE_SLEB128 0x09
#define PE_SDATA2 0x0a
#define PE_SDATA4 0x0b
#define PE_SDATA8 0x0c
#define PE_PCREL 0x10
#define PE_DATAREL 0x30

static uint64_t uleb(const unsigned char **pp) {
    uint64_t v = 0; int sh = 0; unsigned char b;
    do { b = *(*pp)++; v |= (uint64_t)(b & 0x7f) << sh; sh += 7; } while (b & 0x80);
    return v;
}
static int64_t sleb(const unsigned char **pp) {
    int64_t v = 0; int sh = 0; unsigned char b;
    do { b = *(*pp)++; v |= (int64_t)(b & 0x7f) << sh; sh += 7; } while (b & 0x80);
    if (sh < 64 && (b & 0x40)) v |= -((int64_t)1 << sh);
    return v;
}

/* Read one encoded pointer. Returns 0 on an encoding we do not handle. */
static int read_enc(const unsigned char **pp, unsigned char enc, uint64_t datarel, uint64_t *out) {
    const unsigned char *p = *pp;
    uint64_t base = 0, v;
    if (enc == PE_OMIT) return 0;
    switch (enc & 0x70) {
    case 0: break;
    case PE_PCREL: base = (uint64_t)(uintptr_t)p; break;
    case PE_DATAREL: base = datarel; break;
    default: return 0;
    }
    switch (enc & 0x0f) {
    case 0x00: case PE_UDATA8: case PE_SDATA8: { uint64_t x; memcpy(&x, p, 8); v = x; p += 8; break; }
    case PE_UDATA4: { uint32_t x; memcpy(&x, p, 4); v = x; p += 4; break; }
    case PE_SDATA4: { int32_t x; memcpy(&x, p, 4); v = (uint64_t)(int64_t)x; p += 4; break; }
    case PE_UDATA2: { uint16_t x; memcpy(&x, p, 2); v = x; p += 2; break; }
    case PE_SDATA2: { int16_t x; memcpy(&x, p, 2); v = (uint64_t)(int64_t)x; p += 2; break; }
    case PE_ULEB128: v = uleb(&p); break;
    case PE_SLEB128: v = (uint64_t)sleb(&p); break;
    default: return 0;
    }
    if (enc & 0x80) return 0; /* indirect: not used for pc_begin in practice */
    *out = base + v;
    *pp = p;
    return 1;
}

/* FDE -> [start, end), and its LSDA (C++ exception table) if any */
static int fde_parse(const unsigned char *fde, uint64_t *start, uint64_t *end, uint64_t *lsda) {
    const unsigned char *p = fde, *cie, *q;
    uint32_t len, cie_off;
    unsigned char fde_enc = 0; /* absptr */
    unsigned char lsda_enc = PE_OMIT;
    int has_z = 0;
    uint64_t range;
    if (lsda) *lsda = 0;
    memcpy(&len, p, 4); p += 4;
    if (len == 0 || len == 0xffffffffu) return 0;
    memcpy(&cie_off, p, 4);
    cie = p - cie_off;
    p += 4;
    /* parse the CIE for the 'R' (FDE pointer encoding) augmentation */
    q = cie + 8;                                  /* length, CIE id */
    {
        unsigned char version = *q++;
        const char *aug = (const char *)q;
        q += strlen(aug) + 1;
        if (aug[0] == 'e' && aug[1] == 'h') { q += 8; aug += 2; }
        uleb(&q); sleb(&q);                       /* code / data alignment */
        if (version == 1) q++; else uleb(&q);     /* return address register */
        if (aug[0] == 'z') {
            const char *a;
            has_z = 1;
            uleb(&q);                             /* augmentation length */
            for (a = aug + 1; *a; a++) {
                if (*a == 'R') fde_enc = *q++;
                else if (*a == 'L') lsda_enc = *q++;
                else if (*a == 'P') { unsigned char e = *q++; uint64_t dummy; if (!read_enc(&q, e & 0x7f, 0, &dummy)) return 0; }
                else if (*a == 'S' || *a == 'B') continue;
                else break;
            }
        }
    }
    if (!read_enc(&p, fde_enc, 0, start)) return 0;
    if (!read_enc(&p, fde_enc & 0x0f, 0, &range)) return 0;
    *end = *start + range;
    if (has_z && lsda && lsda_enc != PE_OMIT) {
        uint64_t v;
        uleb(&p);                                 /* FDE augmentation length */
        if (read_enc(&p, lsda_enc, 0, &v)) *lsda = v;
    }
    return 1;
}

static int fde_range(const unsigned char *fde, uint64_t *start, uint64_t *end) {
    return fde_parse(fde, start, end, NULL);
}

/* Find the FDE for a function start through .eh_frame_hdr. */
static const unsigned char *find_fde(const afw_lib *lib, uint64_t addr) {
    const unsigned char *h = lib->eh_frame_hdr, *p;
    uint64_t eh_frame, count, hdr;
    const int32_t *tab;
    size_t lo, hi;
    if (!h) return NULL;
    p = h + 4; hdr = (uint64_t)(uintptr_t)h;
    if (h[0] != 1 || !read_enc(&p, h[1], hdr, &eh_frame) || !read_enc(&p, h[2], hdr, &count) ||
        h[3] != (PE_DATAREL | PE_SDATA4) || !count)
        return NULL;
    tab = (const int32_t *)p; lo = 0; hi = (size_t)count;
    while (hi - lo > 1) {
        size_t mid = (lo + hi) / 2;
        if (hdr + (int64_t)tab[2 * mid] <= addr) lo = mid; else hi = mid;
    }
    return (const unsigned char *)(uintptr_t)(hdr + (int64_t)tab[2 * lo + 1]);
}

/* Inside the loaded image? Used to reject corrupt exception tables. */
static int in_image(const afw_lib *lib, const unsigned char *p, size_t n) {
    return p >= lib->base && p + n <= lib->base + lib->size;
}

/*
 * Returns: >= 0 number of landing pads (0 = function has no LSDA or no pads)
 *          -1 the table uses a format we do not decode, or is corrupt
 *          -2 more landing pads than `max`
 * Callers must treat < 0 as "entry points unknown" (UNDECIDED).
 */
int afw_func_landing_pads(const afw_lib *lib, uint64_t func, uint64_t *out, int max) {
    const unsigned char *fde = find_fde(lib, func), *p, *cs_end;
    uint64_t s0, e0, lsda, lpstart, cs_len;
    unsigned char lp_enc, tt_enc, cs_enc;
    int n = 0;
    if (!fde || !fde_parse(fde, &s0, &e0, &lsda) || s0 != func) return 0;
    if (!lsda) return 0;                                   /* no exception table */
    p = (const unsigned char *)(uintptr_t)lsda;
    if (!in_image(lib, p, 4)) return -1;
    lp_enc = *p++;
    lpstart = func;
    if (lp_enc != PE_OMIT && !read_enc(&p, lp_enc, 0, &lpstart)) return -1;
    tt_enc = *p++;
    if (tt_enc != PE_OMIT) uleb(&p);
    cs_enc = *p++;
    if ((cs_enc & 0x70) != 0 || cs_enc == PE_OMIT) return -1;  /* call-site values are plain offsets */
    cs_len = uleb(&p);
    cs_end = p + cs_len;
    if (cs_len > (1u << 20) || !in_image(lib, p, (size_t)cs_len)) return -1;
    while (p < cs_end) {
        uint64_t start, len, lp;
        if (!read_enc(&p, cs_enc, 0, &start) || !read_enc(&p, cs_enc, 0, &len) ||
            !read_enc(&p, cs_enc, 0, &lp)) return -1;
        uleb(&p);                                          /* action */
        if (p > cs_end) return -1;                         /* entry runs past the table */
        if (!lp) continue;                                 /* call site without landing pad */
        if (lpstart + lp < s0 || lpstart + lp >= e0) return -1;  /* pad outside the function */
        if (n == max) return -2;
        out[n++] = lpstart + lp;
    }
    return n;
}

int afw_func_bounds(const afw_lib *lib, uint64_t addr, uint64_t *start, uint64_t *end) {
    /* 1) .eh_frame_hdr binary search table */
    if (lib->eh_frame_hdr) {
        const unsigned char *h = lib->eh_frame_hdr, *p = h + 4;
        unsigned char ptr_enc = h[1], cnt_enc = h[2], tab_enc = h[3];
        uint64_t eh_frame, count, hdr = (uint64_t)(uintptr_t)h;
        if (h[0] == 1 && read_enc(&p, ptr_enc, hdr, &eh_frame) && read_enc(&p, cnt_enc, hdr, &count) &&
            tab_enc == (PE_DATAREL | PE_SDATA4)) {
            const int32_t *tab = (const int32_t *)p;   /* pairs: initial_loc, fde */
            size_t lo = 0, hi = (size_t)count;
            while (hi - lo > 1) {
                size_t mid = (lo + hi) / 2;
                if (hdr + (int64_t)tab[2 * mid] <= addr) lo = mid; else hi = mid;
            }
            if (count && hdr + (int64_t)tab[2 * lo] <= addr) {
                const unsigned char *fde = (const unsigned char *)(uintptr_t)(hdr + (int64_t)tab[2 * lo + 1]);
                if (fde_range(fde, start, end) && addr >= *start && addr < *end) return 1;
            }
        }
    }
    /* 2) exported function symbols with a size */
    {
        size_t i;
        for (i = 1; i < lib->nsyms; i++) {
            const Elf64_Sym *s = &lib->symtab[i];
            uint64_t a = (uint64_t)lib->bias + s->st_value;
            if (s->st_shndx == SHN_UNDEF || ELF64_ST_TYPE(s->st_info) != STT_FUNC || !s->st_size) continue;
            if (addr >= a && addr < a + s->st_size) { *start = a; *end = a + s->st_size; return 1; }
        }
    }
    return 0;
}

int afw_func_list(const afw_lib *lib, unsigned char ***starts, size_t **sizes) {
    const unsigned char *h = lib->eh_frame_hdr, *p;
    uint64_t eh_frame, count, hdr, i;
    int n = 0;
    *starts = NULL; *sizes = NULL;
    if (!h) return 0;
    p = h + 4; hdr = (uint64_t)(uintptr_t)h;
    if (h[0] != 1 || !read_enc(&p, h[1], hdr, &eh_frame) || !read_enc(&p, h[2], hdr, &count) ||
        h[3] != (PE_DATAREL | PE_SDATA4))
        return 0;
    *starts = (unsigned char **)malloc((size_t)count * sizeof **starts);
    *sizes = (size_t *)malloc((size_t)count * sizeof **sizes);
    for (i = 0; i < count; i++) {
        const int32_t *tab = (const int32_t *)p;
        uint64_t s0, e0;
        const unsigned char *fde = (const unsigned char *)(uintptr_t)(hdr + (int64_t)tab[2 * i + 1]);
        if (!fde_range(fde, &s0, &e0) || e0 <= s0) continue;
        if (s0 < (uint64_t)(uintptr_t)lib->base || e0 > (uint64_t)(uintptr_t)lib->base + lib->size) continue;
        (*starts)[n] = (unsigned char *)(uintptr_t)s0;
        (*sizes)[n] = (size_t)(e0 - s0);
        n++;
    }
    return n;
}
