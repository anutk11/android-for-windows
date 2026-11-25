/*
 * apk.c - Self-contained ZIP reader + RFC 1951 Inflate + CRC-32 for APKs.
 */
#include "apk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t rd16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---- IEEE 802.3 CRC-32 ------------------------------------------------ */
uint32_t afw_crc32(const unsigned char *buf, size_t len) {
    static uint32_t tab[256];
    static int ready;
    uint32_t crc = 0xffffffffu;
    size_t i;
    if (!ready) {
        uint32_t n, k;
        for (n = 0; n < 256u; n++) {
            uint32_t c = n;
            for (k = 0; k < 8u; k++)
                c = (c & 1u) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
            tab[n] = c;
        }
        ready = 1;
    }
    for (i = 0; i < len; i++)
        crc = tab[(crc ^ buf[i]) & 0xffu] ^ (crc >> 8);
    return crc ^ 0xffffffffu;
}

/* ---- RFC 1951 Raw Inflate (stored, fixed Huffman, dynamic Huffman) ---- */
typedef struct {
    const unsigned char *in;
    size_t   in_len;
    size_t   in_pos;
    uint64_t bitbuf;
    int      bitcnt;
} bit_reader;

static int br_fill(bit_reader *br, int need) {
    while (br->bitcnt < need) {
        if (br->in_pos >= br->in_len) return -1;
        br->bitbuf |= ((uint64_t)br->in[br->in_pos++]) << br->bitcnt;
        br->bitcnt += 8;
    }
    return 0;
}

static int br_bits(bit_reader *br, int n, uint32_t *out) {
    if (n == 0) { *out = 0; return 0; }
    if (br_fill(br, n) != 0) return -1;
    *out = (uint32_t)(br->bitbuf & ((1ULL << n) - 1ULL));
    br->bitbuf >>= n;
    br->bitcnt -= n;
    return 0;
}

static void br_align_byte(bit_reader *br) {
    int drop = br->bitcnt & 7;
    br->bitbuf >>= drop;
    br->bitcnt -= drop;
}

typedef struct {
    uint16_t count[16];
    uint16_t symbol[288];
    int      max_sym;
} huff_tab;

static int huff_build(huff_tab *ht, const uint8_t *lengths, int nsym) {
    uint16_t offs[16];
    int i, left;
    memset(ht, 0, sizeof *ht);
    ht->max_sym = nsym;
    for (i = 0; i < nsym; i++) {
        if (lengths[i] > 15) return -1;
        ht->count[lengths[i]]++;
    }
    if (ht->count[0] == nsym) return 0; /* empty tree allowed for unused distance table */
    left = 1;
    for (i = 1; i <= 15; i++) {
        left <<= 1;
        left -= ht->count[i];
        if (left < 0) return -1; /* oversubscribed */
    }
    offs[1] = 0;
    for (i = 1; i < 15; i++)
        offs[i + 1] = (uint16_t)(offs[i] + ht->count[i]);
    for (i = 0; i < nsym; i++) {
        if (lengths[i] != 0)
            ht->symbol[offs[lengths[i]]++] = (uint16_t)i;
    }
    return 0;
}

static int huff_decode(bit_reader *br, const huff_tab *ht, int *sym_out) {
    int code = 0, first = 0, index = 0, len;
    for (len = 1; len <= 15; len++) {
        uint32_t bit = 0;
        int cnt = ht->count[len];
        if (br_bits(br, 1, &bit) != 0) return -1;
        code |= (int)bit;
        if (code - cnt < first) {
            *sym_out = ht->symbol[index + (code - first)];
            return 0;
        }
        index += cnt;
        first = (first + cnt) << 1;
        code <<= 1;
    }
    return -1;
}

static int inflate_codes(bit_reader *br, const huff_tab *litlen, const huff_tab *dist,
                         unsigned char *out, size_t out_len, size_t *out_pos) {
    static const uint16_t len_base[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
    };
    static const uint8_t len_extra[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
    };
    static const uint16_t dist_base[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12289, 16385, 24577
    };
    static const uint8_t dist_extra[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    };
    for (;;) {
        int sym = 0;
        if (huff_decode(br, litlen, &sym) != 0) return -1;
        if (sym < 256) {
            if (*out_pos >= out_len) return -1;
            out[(*out_pos)++] = (unsigned char)sym;
        } else if (sym == 256) {
            return 0;
        } else {
            int lidx = sym - 257, dsym = 0;
            uint32_t ex = 0, mlen, mdist, k;
            if (lidx < 0 || lidx >= 29) return -1;
            if (br_bits(br, len_extra[lidx], &ex) != 0) return -1;
            mlen = (uint32_t)len_base[lidx] + ex;
            if (huff_decode(br, dist, &dsym) != 0 || dsym < 0 || dsym >= 30) return -1;
            if (br_bits(br, dist_extra[dsym], &ex) != 0) return -1;
            mdist = (uint32_t)dist_base[dsym] + ex;
            if (mdist == 0 || mdist > *out_pos || mlen > out_len - *out_pos) return -1;
            for (k = 0; k < mlen; k++) {
                out[*out_pos] = out[*out_pos - mdist];
                (*out_pos)++;
            }
        }
    }
}

int afw_inflate_raw(const unsigned char *in, size_t in_len,
                    unsigned char *out, size_t out_len) {
    bit_reader br;
    size_t out_pos = 0;
    uint32_t bfinal = 0;

    if ((!in && in_len > 0) || (!out && out_len > 0)) return -1;
    memset(&br, 0, sizeof br);
    br.in = in;
    br.in_len = in_len;

    do {
        uint32_t btype = 0;
        if (br_bits(&br, 1, &bfinal) != 0) return -1;
        if (br_bits(&br, 2, &btype) != 0) return -1;

        if (btype == 0) {
            /* Stored (uncompressed) block */
            uint32_t len = 0, nlen = 0, i;
            br_align_byte(&br);
            if (br_bits(&br, 16, &len) != 0 || br_bits(&br, 16, &nlen) != 0) return -1;
            if ((len & 0xffffu) != ((~nlen) & 0xffffu)) return -1;
            if (len > out_len - out_pos) return -1;
            for (i = 0; i < len; i++) {
                uint32_t b = 0;
                if (br_bits(&br, 8, &b) != 0) return -1;
                out[out_pos++] = (unsigned char)b;
            }
        } else if (btype == 1) {
            /* Fixed Huffman block */
            uint8_t ll[288], dl[32];
            huff_tab ht_ll, ht_dl;
            int i;
            for (i = 0; i <= 143; i++) ll[i] = 8;
            for (i = 144; i <= 255; i++) ll[i] = 9;
            for (i = 256; i <= 279; i++) ll[i] = 7;
            for (i = 280; i <= 287; i++) ll[i] = 8;
            for (i = 0; i < 32; i++) dl[i] = 5;
            if (huff_build(&ht_ll, ll, 288) != 0 || huff_build(&ht_dl, dl, 32) != 0) return -1;
            if (inflate_codes(&br, &ht_ll, &ht_dl, out, out_len, &out_pos) != 0) return -1;
        } else if (btype == 2) {
            /* Dynamic Huffman block */
            static const uint8_t order[19] = {
                16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
            };
            uint32_t hlit = 0, hdist = 0, hclen = 0, i;
            uint8_t cl[19], lengths[288 + 32];
            huff_tab ht_cl, ht_ll, ht_dl;
            int idx = 0, total;

            if (br_bits(&br, 5, &hlit) != 0 || br_bits(&br, 5, &hdist) != 0 ||
                br_bits(&br, 4, &hclen) != 0) return -1;
            hlit += 257; hdist += 1; hclen += 4;
            if (hlit > 286 || hdist > 30) return -1;

            memset(cl, 0, sizeof cl);
            for (i = 0; i < hclen; i++) {
                uint32_t v = 0;
                if (br_bits(&br, 3, &v) != 0) return -1;
                cl[order[i]] = (uint8_t)v;
            }
            if (huff_build(&ht_cl, cl, 19) != 0) return -1;

            total = (int)(hlit + hdist);
            while (idx < total) {
                int sym = 0;
                uint32_t rep = 0, ex = 0;
                uint8_t val = 0;
                if (huff_decode(&br, &ht_cl, &sym) != 0) return -1;
                if (sym < 16) {
                    lengths[idx++] = (uint8_t)sym;
                } else {
                    if (sym == 16) {
                        if (idx == 0 || br_bits(&br, 2, &ex) != 0) return -1;
                        val = lengths[idx - 1];
                        rep = 3 + ex;
                    } else if (sym == 17) {
                        if (br_bits(&br, 3, &ex) != 0) return -1;
                        val = 0;
                        rep = 3 + ex;
                    } else if (sym == 18) {
                        if (br_bits(&br, 7, &ex) != 0) return -1;
                        val = 0;
                        rep = 11 + ex;
                    } else {
                        return -1;
                    }
                    if (idx + (int)rep > total) return -1;
                    while (rep--) lengths[idx++] = val;
                }
            }
            if (lengths[256] == 0) return -1; /* end-of-block symbol must exist */
            if (huff_build(&ht_ll, lengths, (int)hlit) != 0 ||
                huff_build(&ht_dl, lengths + hlit, (int)hdist) != 0)
                return -1;
            if (inflate_codes(&br, &ht_ll, &ht_dl, out, out_len, &out_pos) != 0) return -1;
        } else {
            return -1;
        }
    } while (!bfinal);

    return (out_pos == out_len) ? 0 : -1;
}

/* ---- ZIP / APK Container Parser --------------------------------------- */
static int parse_apk_buffer(afw_apk *apk) {
    size_t max_back, back, eocd = 0;
    int found_eocd = 0;
    uint16_t nent;
    uint32_t cd_size, cd_off;
    size_t pos, i;

    if (apk->size < 22) return -1;
    max_back = apk->size - 22;
    if (max_back > 65535) max_back = 65535;
    for (back = 0; back <= max_back; back++) {
        size_t off = apk->size - 22 - back;
        if (rd32(apk->data + off) == 0x06054b50u) {
            uint16_t clen = rd16(apk->data + off + 20);
            if (off + 22 + clen == apk->size) {
                eocd = off;
                found_eocd = 1;
                break;
            }
        }
    }
    if (!found_eocd) return -1;

    nent    = rd16(apk->data + eocd + 10);
    cd_size = rd32(apk->data + eocd + 12);
    cd_off  = rd32(apk->data + eocd + 16);
    if ((size_t)cd_off > apk->size || (size_t)cd_size > apk->size - (size_t)cd_off) return -1;

    apk->entries = nent ? (afw_apk_entry *)calloc(nent, sizeof(afw_apk_entry)) : NULL;
    if (nent && !apk->entries) return -1;

    pos = cd_off;
    for (i = 0; i < nent; i++) {
        uint16_t method, nlen, elen, clen;
        uint32_t crc, csz, usz, lhoff;
        char *name;
        if (pos + 46 > (size_t)cd_off + (size_t)cd_size) return -1;
        if (rd32(apk->data + pos) != 0x02014b50u) return -1;
        method = rd16(apk->data + pos + 10);
        crc    = rd32(apk->data + pos + 16);
        csz    = rd32(apk->data + pos + 20);
        usz    = rd32(apk->data + pos + 24);
        nlen   = rd16(apk->data + pos + 28);
        elen   = rd16(apk->data + pos + 30);
        clen   = rd16(apk->data + pos + 32);
        lhoff  = rd32(apk->data + pos + 42);
        if ((size_t)nlen + elen + clen > ((size_t)cd_off + (size_t)cd_size) - (pos + 46))
            return -1;
        name = (char *)malloc((size_t)nlen + 1);
        if (!name) return -1;
        memcpy(name, apk->data + pos + 46, nlen);
        name[nlen] = '\0';

        apk->entries[apk->nentries].name          = name;
        apk->entries[apk->nentries].method        = method;
        apk->entries[apk->nentries].crc32         = crc;
        apk->entries[apk->nentries].comp_size     = csz;
        apk->entries[apk->nentries].uncomp_size   = usz;
        apk->entries[apk->nentries].local_hdr_off = lhoff;
        apk->nentries++;

        if (strcmp(name, "classes.dex") == 0) apk->has_dex = 1;
        if (strncmp(name, "lib/x86_64/", 11) == 0 && nlen > 14 &&
            strcmp(name + nlen - 3, ".so") == 0)
            apk->nx86_64_libs++;

        pos += 46 + (size_t)nlen + (size_t)elen + (size_t)clen;
    }

    /* Parse AndroidManifest.xml if present */
    {
        unsigned char *mbuf = NULL;
        size_t msz = 0;
        if (afw_apk_read_file(apk, "AndroidManifest.xml", &mbuf, &msz) == 0) {
            if (afw_axml_parse(mbuf, msz, &apk->manifest) == 0)
                apk->has_manifest = 1;
            free(mbuf);
        }
    }
    return 0;
}

int afw_apk_open_mem(const unsigned char *buf, size_t size, afw_apk *out) {
    if (!buf || !size || !out) return -1;
    memset(out, 0, sizeof *out);
    out->data = (unsigned char *)malloc(size);
    if (!out->data) return -1;
    memcpy(out->data, buf, size);
    out->size = size;
    if (parse_apk_buffer(out) != 0) {
        afw_apk_close(out);
        return -1;
    }
    return 0;
}

int afw_apk_open(const char *path, afw_apk *out) {
    FILE *f;
    long sz;
    if (!path || !out) return -1;
    memset(out, 0, sizeof *out);
    f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    out->data = (unsigned char *)malloc((size_t)sz);
    if (!out->data) { fclose(f); return -1; }
    if (fread(out->data, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        afw_apk_close(out);
        return -1;
    }
    fclose(f);
    out->size = (size_t)sz;
    if (parse_apk_buffer(out) != 0) {
        afw_apk_close(out);
        return -1;
    }
    return 0;
}

void afw_apk_close(afw_apk *apk) {
    size_t i;
    if (!apk) return;
    if (apk->entries) {
        for (i = 0; i < apk->nentries; i++) free(apk->entries[i].name);
        free(apk->entries);
    }
    free(apk->data);
    memset(apk, 0, sizeof *apk);
}

const afw_apk_entry *afw_apk_find(const afw_apk *apk, const char *name) {
    size_t i;
    if (!apk || !name) return NULL;
    for (i = 0; i < apk->nentries; i++) {
        if (strcmp(apk->entries[i].name, name) == 0)
            return &apk->entries[i];
    }
    return NULL;
}

int afw_apk_read_entry(const afw_apk *apk, const afw_apk_entry *e,
                       unsigned char **out_buf, size_t *out_size) {
    size_t lh, data_off;
    uint16_t nlen, elen;
    unsigned char *buf;

    if (!apk || !e || !out_buf || !out_size) return -1;
    *out_buf = NULL;
    *out_size = 0;
    lh = e->local_hdr_off;
    if (lh > apk->size || apk->size - lh < 30) return -1;
    if (rd32(apk->data + lh) != 0x04034b50u) return -1;
    nlen = rd16(apk->data + lh + 26);
    elen = rd16(apk->data + lh + 28);
    if ((size_t)nlen + elen > apk->size - lh - 30) return -1;
    data_off = lh + 30 + (size_t)nlen + (size_t)elen;
    if (e->comp_size > apk->size - data_off) return -1;
    if (e->uncomp_size > 256u * 1024u * 1024u) return -1; /* 256MB cap */

    buf = (unsigned char *)malloc((size_t)e->uncomp_size + 1);
    if (!buf) return -1;

    if (e->method == 0) {
        if (e->comp_size != e->uncomp_size) { free(buf); return -1; }
        if (e->uncomp_size) memcpy(buf, apk->data + data_off, e->uncomp_size);
    } else if (e->method == 8) {
        if (afw_inflate_raw(apk->data + data_off, e->comp_size, buf, e->uncomp_size) != 0) {
            free(buf);
            return -1;
        }
    } else {
        free(buf);
        return -1;
    }

    if (afw_crc32(buf, e->uncomp_size) != e->crc32) {
        free(buf);
        return -1;
    }
    buf[e->uncomp_size] = '\0';
    *out_buf = buf;
    *out_size = e->uncomp_size;
    return 0;
}

int afw_apk_read_file(const afw_apk *apk, const char *name,
                      unsigned char **out_buf, size_t *out_size) {
    const afw_apk_entry *e = afw_apk_find(apk, name);
    if (!e) return -1;
    return afw_apk_read_entry(apk, e, out_buf, out_size);
}

int afw_apk_extract_x86_64_libs(const afw_apk *apk, const char *out_dir) {
    size_t i;
    int extracted = 0;
    if (!apk || !out_dir) return -1;
    for (i = 0; i < apk->nentries; i++) {
        const afw_apk_entry *e = &apk->entries[i];
        const char *base;
        char path[1024];
        unsigned char *buf = NULL;
        size_t sz = 0;
        FILE *f;
        if (strncmp(e->name, "lib/x86_64/", 11) != 0) continue;
        base = e->name + 11;
        /* Prevent path traversal inside lib/x86_64/ */
        if (!base[0] || strchr(base, '/') || strchr(base, '\\') || strstr(base, ".."))
            continue;
        if (afw_apk_read_entry(apk, e, &buf, &sz) != 0) return -1;
        if ((size_t)snprintf(path, sizeof path, "%s/%s", out_dir, base) >= sizeof path) {
            free(buf);
            return -1;
        }
        f = fopen(path, "wb");
        if (!f) { free(buf); return -1; }
        if (sz > 0 && fwrite(buf, 1, sz, f) != sz) {
            fclose(f); free(buf); return -1;
        }
        fclose(f);
        free(buf);
        extracted++;
    }
    return extracted;
}
