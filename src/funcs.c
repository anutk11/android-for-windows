/*
 * funcs.c - Function boundaries from .eh_frame_hdr / .eh_frame (DWARF CFI).
 */
#include "funcs.h"
#include "elf_loader.h"

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

/* FDE -> [start, end) */
static int fde_range(const unsigned char *fde, uint64_t *start, uint64_t *end) {
    const unsigned char *p = fde, *cie, *q;
    uint32_t len, cie_off;
    unsigned char fde_enc = 0; /* absptr */
    uint64_t range;
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
            uleb(&q);                             /* augmentation length */
            for (a = aug + 1; *a; a++) {
                if (*a == 'R') fde_enc = *q++;
                else if (*a == 'L') q++;
                else if (*a == 'P') { unsigned char e = *q++; uint64_t dummy; if (!read_enc(&q, e & 0x7f, 0, &dummy)) return 0; }
                else if (*a == 'S' || *a == 'B') continue;
                else break;
            }
        }
    }
    if (!read_enc(&p, fde_enc, 0, start)) return 0;
    if (!read_enc(&p, fde_enc & 0x0f, 0, &range)) return 0;
    *end = *start + range;
    return 1;
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
