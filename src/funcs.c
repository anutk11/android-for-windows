/*
 * funcs.c - Function boundaries and C++ landing pads from .eh_frame_hdr,
 * .eh_frame (DWARF CFI) and the LSDA (.gcc_except_table).
 *
 * Every read is bounded: a cursor carries the end of the structure it reads
 * (a CIE/FDE record, an LSDA, the loaded image), and any read that would go
 * past it fails. A failure is always reported as a failure - never as "no
 * landing pads" or "no exception table".
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
#define PE_INDIRECT 0x80

typedef struct { const unsigned char *p, *end; int bad; } cur;

static size_t cur_rem(const cur *c) {
    uintptr_t p = (uintptr_t)c->p, e = (uintptr_t)c->end;
    return (c->bad || p >= e) ? 0 : (size_t)(e - p);
}

static unsigned char rd_u8(cur *c) {
    if (c->bad || (uintptr_t)c->p >= (uintptr_t)c->end) { c->bad = 1; return 0; }
    return *c->p++;
}
static uint64_t rd_uleb(cur *c) {
    uint64_t v = 0; int sh = 0; unsigned char b;
    do {
        b = rd_u8(c);
        if (sh < 64) v |= (uint64_t)(b & 0x7f) << sh;
        sh += 7;
    } while ((b & 0x80) && !c->bad && sh < 70);
    if (b & 0x80) c->bad = 1;
    return v;
}
static int64_t rd_sleb(cur *c) {
    int64_t v = 0; int sh = 0; unsigned char b;
    do {
        b = rd_u8(c);
        if (sh < 64) v |= (int64_t)(b & 0x7f) << sh;
        sh += 7;
    } while ((b & 0x80) && !c->bad && sh < 70);
    if (b & 0x80) c->bad = 1;
    if (sh < 64 && (b & 0x40)) v |= -((int64_t)1 << sh);
    return v;
}
static void rd_bytes(cur *c, void *out, size_t n) {
    if (c->bad || cur_rem(c) < n) { c->bad = 1; memset(out, 0, n); return; }
    memcpy(out, c->p, n);
    c->p += n;
}

/* Read one encoded pointer. Sets c->bad on an encoding we do not handle
 * (including indirect pointers) or on running past the end. */
static uint64_t rd_enc(cur *c, unsigned char enc, uint64_t datarel) {
    uint64_t base = 0, v = 0;
    const unsigned char *at = c->p;
    if (enc == PE_OMIT || (enc & PE_INDIRECT)) { c->bad = 1; return 0; }
    switch (enc & 0x70) {
    case 0: break;
    case PE_PCREL: base = (uint64_t)(uintptr_t)at; break;
    case PE_DATAREL: base = datarel; break;
    default: c->bad = 1; return 0;
    }
    switch (enc & 0x0f) {
    case 0x00: case PE_UDATA8: case PE_SDATA8: { uint64_t x; rd_bytes(c, &x, 8); v = x; break; }
    case PE_UDATA4: { uint32_t x; rd_bytes(c, &x, 4); v = x; break; }
    case PE_SDATA4: { int32_t x; rd_bytes(c, &x, 4); v = (uint64_t)(int64_t)x; break; }
    case PE_UDATA2: { uint16_t x; rd_bytes(c, &x, 2); v = x; break; }
    case PE_SDATA2: { int16_t x; rd_bytes(c, &x, 2); v = (uint64_t)(int64_t)x; break; }
    case PE_ULEB128: v = rd_uleb(c); break;
    case PE_SLEB128: v = (uint64_t)rd_sleb(c); break;
    default: c->bad = 1; return 0;
    }
    return base + v;
}

static cur image_cur(const afw_lib *lib, const unsigned char *p) {
    cur c;
    uintptr_t pa = (uintptr_t)p, lo = (uintptr_t)lib->base, hi = lo + lib->size;
    c.p = p;
    c.end = lib->base ? lib->base + lib->size : NULL;
    c.bad = !(lib->base && hi >= lo && pa >= lo && pa < hi);
    return c;
}

/* One CFI record (CIE or FDE): [start, start+4+len), within the image. */
static int record(const afw_lib *lib, const unsigned char *at, cur *body) {
    cur c = image_cur(lib, at);
    uint32_t len;
    rd_bytes(&c, &len, 4);
    if (c.bad || len == 0 || len == 0xffffffffu || cur_rem(&c) < len) return 0;
    body->p = c.p; body->end = c.p + len; body->bad = 0;
    return 1;
}

enum { FDE_BAD = -1, FDE_OK = 0, FDE_OK_LSDA = 1 };

/* FDE -> [start, end) and, if present, its LSDA address. */
static int fde_parse(const afw_lib *lib, const unsigned char *fde, uint64_t *start, uint64_t *end,
                     uint64_t *lsda) {
    cur f, ci;
    uint32_t cie_off;
    const unsigned char *cie_at;
    unsigned char fde_enc = 0, lsda_enc = PE_OMIT;
    int has_z = 0;
    uint64_t range;
    *lsda = 0;
    if (!record(lib, fde, &f)) return FDE_BAD;
    rd_bytes(&f, &cie_off, 4);
    if (f.bad || cie_off == 0) return FDE_BAD;             /* 0 would be a CIE, not an FDE */
    cie_at = (const unsigned char *)((uintptr_t)fde + 4u - (uintptr_t)cie_off);
    if (!record(lib, cie_at, &ci)) return FDE_BAD;
    {
        uint32_t id;
        unsigned char version;
        char aug[16];
        int i = 0;
        rd_bytes(&ci, &id, 4);
        version = rd_u8(&ci);
        if (ci.bad || id != 0 || (version != 1 && version != 3)) return FDE_BAD;
        do { aug[i] = (char)rd_u8(&ci); } while (aug[i] && ++i < 15 && !ci.bad);
        if (ci.bad || aug[i]) return FDE_BAD;
        if (aug[0] == 'e' && aug[1] == 'h') return FDE_BAD;  /* ancient GCC format: not supported */
        rd_uleb(&ci); rd_sleb(&ci);                          /* code / data alignment */
        if (version == 1) rd_u8(&ci); else rd_uleb(&ci);     /* return address register */
        if (aug[0] == 'z') {
            const char *a;
            uint64_t alen;
            uintptr_t aend;
            has_z = 1;
            alen = rd_uleb(&ci);
            if (ci.bad || (uint64_t)cur_rem(&ci) < alen) return FDE_BAD;
            aend = (uintptr_t)ci.p + (uintptr_t)alen;
            for (a = aug + 1; *a; a++) {
                if (*a == 'R') fde_enc = rd_u8(&ci);
                else if (*a == 'L') lsda_enc = rd_u8(&ci);
                else if (*a == 'P') { unsigned char e = rd_u8(&ci); rd_enc(&ci, (unsigned char)(e & 0x7f), 0); }
                else if (*a == 'S' || *a == 'B') continue;
                else return FDE_BAD;                         /* unknown augmentation: do not guess */
            }
            if (ci.bad || (uintptr_t)ci.p > aend) return FDE_BAD;
        } else if (aug[0]) {
            return FDE_BAD;
        }
    }
    *start = rd_enc(&f, fde_enc, 0);
    range = rd_enc(&f, (unsigned char)(fde_enc & 0x0f), 0);
    if (f.bad) return FDE_BAD;
    *end = *start + range;
    if (has_z) {
        uint64_t alen = rd_uleb(&f);
        uintptr_t aend;
        if (f.bad || (uint64_t)cur_rem(&f) < alen) return FDE_BAD;
        aend = (uintptr_t)f.p + (uintptr_t)alen;
        if (lsda_enc != PE_OMIT) {
            uint64_t v = rd_enc(&f, lsda_enc, 0);
            if (f.bad || (uintptr_t)f.p > aend) return FDE_BAD; /* present but undecodable */
            *lsda = v;
            return v ? FDE_OK_LSDA : FDE_OK;
        }
    }
    return FDE_OK;
}

/* .eh_frame_hdr: version, encodings and the sorted (initial_loc, fde) table */
static int hdr_table(const afw_lib *lib, const int32_t **tab, uint64_t *count) {
    const unsigned char *h = lib->eh_frame_hdr;
    cur c;
    uint64_t hdr;
    unsigned char ver, ptr_enc, cnt_enc, tab_enc;
    if (!h) return 0;
    c = image_cur(lib, h);
    hdr = (uint64_t)(uintptr_t)h;
    ver = rd_u8(&c); ptr_enc = rd_u8(&c); cnt_enc = rd_u8(&c); tab_enc = rd_u8(&c);
    if (c.bad || ver != 1 || tab_enc != (PE_DATAREL | PE_SDATA4)) return 0;
    rd_enc(&c, ptr_enc, hdr);
    *count = rd_enc(&c, cnt_enc, hdr);
    if (c.bad || (uint64_t)cur_rem(&c) / 8 < *count) return 0;
    *tab = (const int32_t *)c.p;
    return 1;
}

/* FDE whose table entry is the last one starting at or before addr. */
static const unsigned char *find_fde(const afw_lib *lib, uint64_t addr) {
    const int32_t *tab;
    uint64_t count, hdr = (uint64_t)(uintptr_t)lib->eh_frame_hdr;
    size_t lo = 0, hi;
    if (!hdr_table(lib, &tab, &count) || !count) return NULL;
    hi = (size_t)count;
    while (hi - lo > 1) {
        size_t mid = (lo + hi) / 2;
        if (hdr + (int64_t)tab[2 * mid] <= addr) lo = mid; else hi = mid;
    }
    if (hdr + (int64_t)tab[2 * lo] > addr) return NULL;
    return (const unsigned char *)(uintptr_t)(hdr + (int64_t)tab[2 * lo + 1]);
}

static uint64_t sym_inferred_size(const afw_lib *lib, const Elf64_Sym *s) {
    const char *nm;
    char end_nm[160];
    size_t i, nlen;
    unsigned stt = ELF64_ST_TYPE(s->st_info);
    if (stt == STT_FUNC && s->st_size) return s->st_size;
    if (stt != STT_FUNC && stt != 0 /* STT_NOTYPE */) return 0;
    if (s->st_size || !lib->strtab || !s->st_name) return 0;
    nm = lib->strtab + s->st_name;
    if (strncmp(nm, "ExecuteNterp", 12) != 0) return 0;
    nlen = strlen(nm);
    if (nlen + 4 > sizeof end_nm) return 0;
    memcpy(end_nm, "End", 3);
    memcpy(end_nm + 3, nm, nlen + 1);
    for (i = 1; i < lib->nsyms; i++) {
        const Elf64_Sym *e = &lib->symtab[i];
        if (e->st_shndx != SHN_UNDEF && e->st_name &&
            strcmp(lib->strtab + e->st_name, end_nm) == 0 && e->st_value > s->st_value)
            return e->st_value - s->st_value;
    }
    return 0;
}

int afw_func_bounds(const afw_lib *lib, uint64_t addr, uint64_t *start, uint64_t *end) {
    const unsigned char *fde = find_fde(lib, addr);
    uint64_t lsda;
    size_t i;
    if (fde && fde_parse(lib, fde, start, end, &lsda) != FDE_BAD && addr >= *start && addr < *end)
        return 1;
    /* fallback: exported function symbols with a size (or End<name> pair) */
    for (i = 1; i < lib->nsyms; i++) {
        const Elf64_Sym *s = &lib->symtab[i];
        uint64_t a = (uint64_t)lib->bias + s->st_value, sz;
        if (s->st_shndx == SHN_UNDEF) continue;
        sz = sym_inferred_size(lib, s);
        if (!sz) continue;
        if (addr >= a && addr < a + sz) { *start = a; *end = a + sz; return 1; }
    }
    for (i = 0; i < (size_t)lib->nextra_fn; i++) {
        uint64_t a = (uint64_t)lib->bias + lib->extra_fn_vaddr[i];
        uint64_t sz = lib->extra_fn_size[i];
        if (sz && addr >= a && addr < a + sz) { *start = a; *end = a + sz; return 1; }
    }
    return 0;
}

typedef struct { unsigned char *start; size_t size; } func_range_tmp;
static int cmp_func_range(const void *a, const void *b) {
    const func_range_tmp *x = (const func_range_tmp *)a, *y = (const func_range_tmp *)b;
    if (x->start < y->start) return -1;
    if (x->start > y->start) return 1;
    return (x->size > y->size) - (x->size < y->size);
}

int afw_func_list(const afw_lib *lib, unsigned char ***starts, size_t **sizes) {
    const int32_t *tab;
    uint64_t count, i, hdr = (uint64_t)(uintptr_t)lib->eh_frame_hdr;
    func_range_tmp *tmp;
    size_t cap, n = 0, k;
    *starts = NULL; *sizes = NULL;
    if (!hdr_table(lib, &tab, &count) || !count) return 0;
    cap = (size_t)count + (lib->symtab ? lib->nsyms : 0) + (size_t)lib->nextra_fn;
    tmp = (func_range_tmp *)malloc(cap * sizeof *tmp);
    if (!tmp) return 0;
    for (i = 0; i < count; i++) {
        uint64_t s0, e0, lsda;
        const unsigned char *fde = (const unsigned char *)(uintptr_t)(hdr + (int64_t)tab[2 * i + 1]);
        if (fde_parse(lib, fde, &s0, &e0, &lsda) == FDE_BAD || e0 <= s0) continue;
        if (s0 < (uint64_t)(uintptr_t)lib->base || e0 > (uint64_t)(uintptr_t)lib->base + lib->size) continue;
        tmp[n].start = (unsigned char *)(uintptr_t)s0;
        tmp[n].size  = (size_t)(e0 - s0);
        n++;
    }
    /* Also include exported STT_FUNC symbols and SHT_SYMTAB ExecuteNterp*
     * entrypoints without .eh_frame FDEs, skipping any overlapping an FDE. */
    if (n > 0 && ((lib->symtab && lib->nsyms > 1) || lib->nextra_fn > 0)) {
        size_t nfde = n;
        qsort(tmp, nfde, sizeof *tmp, cmp_func_range);
        if (lib->symtab && lib->nsyms > 1) {
            for (i = 1; i < lib->nsyms; i++) {
                const Elf64_Sym *s = &lib->symtab[i];
                uint64_t s0, e0, sz;
                size_t lo = 0, hi = nfde;
                int overlap = 0;
                if (s->st_shndx == SHN_UNDEF) continue;
                sz = sym_inferred_size(lib, s);
                if (!sz) continue;
                s0 = (uint64_t)lib->bias + s->st_value;
                e0 = s0 + sz;
                if (e0 <= s0 || s0 < (uint64_t)(uintptr_t)lib->base || e0 > (uint64_t)(uintptr_t)lib->base + lib->size)
                    continue;
                while (lo < hi) {
                    size_t mid = lo + (hi - lo) / 2;
                    if ((uint64_t)(uintptr_t)tmp[mid].start <= s0) lo = mid + 1; else hi = mid;
                }
                if (lo > 0 && (uint64_t)(uintptr_t)tmp[lo - 1].start + tmp[lo - 1].size > s0) overlap = 1;
                if (lo < nfde && (uint64_t)(uintptr_t)tmp[lo].start < e0) overlap = 1;
                if (!overlap && n < cap) {
                    tmp[n].start = (unsigned char *)(uintptr_t)s0;
                    tmp[n].size  = (size_t)(e0 - s0);
                    n++;
                }
            }
        }
        for (i = 0; i < (uint64_t)lib->nextra_fn; i++) {
            uint64_t s0 = (uint64_t)lib->bias + lib->extra_fn_vaddr[i];
            uint64_t sz = lib->extra_fn_size[i];
            uint64_t e0 = s0 + sz;
            size_t lo = 0, hi = nfde;
            int overlap = 0;
            if (!sz || e0 <= s0 || s0 < (uint64_t)(uintptr_t)lib->base || e0 > (uint64_t)(uintptr_t)lib->base + lib->size)
                continue;
            while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2;
                if ((uint64_t)(uintptr_t)tmp[mid].start <= s0) lo = mid + 1; else hi = mid;
            }
            if (lo > 0 && (uint64_t)(uintptr_t)tmp[lo - 1].start + tmp[lo - 1].size > s0) overlap = 1;
            if (lo < nfde && (uint64_t)(uintptr_t)tmp[lo].start < e0) overlap = 1;
            if (!overlap && n < cap) {
                tmp[n].start = (unsigned char *)(uintptr_t)s0;
                tmp[n].size  = (size_t)(e0 - s0);
                n++;
            }
        }
        if (n > nfde) {
            /* Sort and deduplicate any overlapping aliases */
            size_t w = 0;
            qsort(tmp, n, sizeof *tmp, cmp_func_range);
            for (k = 0; k < n; k++) {
                if (w > 0 && tmp[k].start < tmp[w - 1].start + tmp[w - 1].size) continue;
                tmp[w++] = tmp[k];
            }
            n = w;
        }
    }
    *starts = (unsigned char **)malloc((n ? n : 1) * sizeof **starts);
    *sizes = (size_t *)malloc((n ? n : 1) * sizeof **sizes);
    if (!*starts || !*sizes) { free(*starts); free(*sizes); *starts = NULL; *sizes = NULL; free(tmp); return 0; }
    for (k = 0; k < n; k++) {
        (*starts)[k] = tmp[k].start;
        (*sizes)[k]  = tmp[k].size;
    }
    free(tmp);
    return (int)n;
}

/*
 * Returns: >= 0 number of landing pads (0 only when the FDE was decoded and
 *               has no LSDA, or the LSDA has no landing pads)
 *          -1 the FDE or LSDA could not be decoded (missing FDE, wrong
 *             function, unknown augmentation, indirect or unsupported
 *             encoding, corrupt or truncated table)
 *          -2 more landing pads than `max`
 * Callers must treat < 0 as "entry points unknown" (UNDECIDED).
 */
int afw_func_landing_pads(const afw_lib *lib, uint64_t func, uint64_t *out, int max) {
    const unsigned char *fde = find_fde(lib, func);
    uint64_t s0, e0, lsda, lpstart, cs_len;
    unsigned char lp_enc, tt_enc, cs_enc;
    cur c;
    const unsigned char *cs_end;
    int n = 0, st;
    if (!fde) return 0;                                    /* .dynsym function without an FDE: no LSDA */
    st = fde_parse(lib, fde, &s0, &e0, &lsda);
    if (st == FDE_BAD) return -1;
    if (func < s0 || func >= e0) return 0;                 /* nearest FDE does not cover func: no LSDA */
    if (s0 != func) return -1;
    if (st == FDE_OK) return 0;                            /* decoded: no exception table */
    c = image_cur(lib, (const unsigned char *)(uintptr_t)lsda);
    lp_enc = rd_u8(&c);
    lpstart = func;
    if (lp_enc != PE_OMIT) lpstart = rd_enc(&c, lp_enc, 0);
    tt_enc = rd_u8(&c);
    if (tt_enc != PE_OMIT) rd_uleb(&c);
    cs_enc = rd_u8(&c);
    if (c.bad || cs_enc == PE_OMIT || (cs_enc & 0x70) != 0) return -1;  /* call sites: plain offsets */
    cs_len = rd_uleb(&c);
    if (c.bad || (uint64_t)cur_rem(&c) < cs_len) return -1;
    cs_end = c.p + cs_len;
    c.end = cs_end;                                        /* entries must stay inside the table */
    while ((uintptr_t)c.p < (uintptr_t)cs_end) {
        uint64_t lp;
        rd_enc(&c, cs_enc, 0);                             /* start */
        rd_enc(&c, cs_enc, 0);                             /* length */
        lp = rd_enc(&c, cs_enc, 0);                        /* landing pad */
        rd_uleb(&c);                                       /* action */
        if (c.bad) return -1;
        if (!lp) continue;                                 /* call site without landing pad */
        if (lpstart + lp < s0 || lpstart + lp >= e0) return -1;
        if (n == max) return -2;
        out[n++] = lpstart + lp;
    }
    return n;
}

int afw_lib_readable(const afw_lib *lib, uint64_t addr, uint64_t len) {
    uint64_t b = (uint64_t)(uintptr_t)lib->base;
    return addr >= b && len <= lib->size && addr - b <= lib->size - len;
}
