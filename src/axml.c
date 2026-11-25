/*
 * axml.c - Android Binary XML (AXML) manifest parser (pure C11, bounds-checked).
 */
#include "axml.h"

#include <stdlib.h>
#include <string.h>

#define RES_STRING_POOL_TYPE       0x0001u
#define RES_XML_TYPE               0x0003u
#define RES_XML_START_ELEMENT_TYPE 0x0102u
#define RES_XML_END_ELEMENT_TYPE   0x0103u
#define RES_XML_RESOURCE_MAP_TYPE  0x0180u

#define AXML_UTF8_FLAG             0x00000100u
#define AXML_TYPE_STRING           0x03u
#define AXML_TYPE_INT_DEC          0x10u
#define AXML_TYPE_INT_HEX          0x11u

#define ATTR_RES_NAME              0x01010003u
#define ATTR_RES_VALUE             0x01010024u
#define ATTR_RES_VERSION_CODE      0x0101021bu
#define ATTR_RES_VERSION_NAME      0x0101021cu

static uint16_t rd16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

typedef struct {
    char    **strings;
    uint32_t  count;
    uint32_t *res_ids;
    uint32_t  res_count;
} axml_pool;

static void pool_free(axml_pool *pl) {
    uint32_t i;
    if (pl->strings) {
        for (i = 0; i < pl->count; i++) free(pl->strings[i]);
        free(pl->strings);
    }
    free(pl->res_ids);
    memset(pl, 0, sizeof *pl);
}

static const char *pool_str(const axml_pool *pl, int32_t idx) {
    if (idx < 0 || (uint32_t)idx >= pl->count) return NULL;
    return pl->strings[idx];
}

static uint32_t pool_res_id(const axml_pool *pl, int32_t idx) {
    if (idx < 0 || (uint32_t)idx >= pl->res_count) return 0;
    return pl->res_ids[idx];
}

/* Decode UTF-8 string pool entry (1-or-2 byte char len + 1-or-2 byte byte len). */
static char *decode_utf8_entry(const unsigned char *p, size_t avail) {
    size_t pos = 0, blen;
    char *s;
    if (avail < 2) return NULL;
    /* Skip UTF-16 character length */
    if (p[pos] & 0x80u) {
        if (avail < 4) return NULL;
        pos += 2;
    } else {
        pos += 1;
    }
    /* Read UTF-8 byte length */
    if (pos >= avail) return NULL;
    if (p[pos] & 0x80u) {
        if (pos + 2 > avail) return NULL;
        blen = (((size_t)(p[pos] & 0x7fu)) << 8) | (size_t)p[pos + 1];
        pos += 2;
    } else {
        blen = (size_t)p[pos];
        pos += 1;
    }
    if (blen > avail - pos) return NULL;
    s = (char *)malloc(blen + 1);
    if (!s) return NULL;
    if (blen) memcpy(s, p + pos, blen);
    s[blen] = '\0';
    return s;
}

/* Decode UTF-16LE string pool entry to UTF-8 (BMP). */
static char *decode_utf16_entry(const unsigned char *p, size_t avail) {
    size_t pos = 0, u16len, i, out_pos = 0;
    char *s;
    if (avail < 2) return NULL;
    u16len = rd16(p);
    pos = 2;
    if (u16len & 0x8000u) {
        if (avail < 4) return NULL;
        u16len = ((u16len & 0x7fffu) << 16) | rd16(p + 2);
        pos = 4;
    }
    if (u16len > (avail - pos) / 2u) return NULL;
    if (u16len > (SIZE_MAX - 1u) / 3u) return NULL;
    s = (char *)malloc(u16len * 3u + 1u);
    if (!s) return NULL;
    for (i = 0; i < u16len; i++) {
        uint16_t ch = rd16(p + pos + i * 2u);
        if (ch < 0x80u) {
            s[out_pos++] = (char)ch;
        } else if (ch < 0x800u) {
            s[out_pos++] = (char)(0xc0u | (ch >> 6));
            s[out_pos++] = (char)(0x80u | (ch & 0x3fu));
        } else {
            s[out_pos++] = (char)(0xe0u | (ch >> 12));
            s[out_pos++] = (char)(0x80u | ((ch >> 6) & 0x3fu));
            s[out_pos++] = (char)(0x80u | (ch & 0x3fu));
        }
    }
    s[out_pos] = '\0';
    return s;
}

static int parse_string_pool(const unsigned char *chunk, size_t csize, axml_pool *pl) {
    uint32_t scount, flags, sstart, i;
    if (csize < 28) return -1;
    scount = rd32(chunk + 8);
    flags  = rd32(chunk + 16);
    sstart = rd32(chunk + 20);
    if (scount > 100000u) return -1;
    if (sstart > csize) return -1;
    if ((size_t)scount > (csize - 28u) / 4u) return -1;
    if (scount == 0) return 0;

    pl->strings = (char **)calloc(scount, sizeof(char *));
    if (!pl->strings) return -1;
    pl->count = scount;
    for (i = 0; i < scount; i++) {
        uint32_t off = rd32(chunk + 28u + (size_t)i * 4u);
        size_t abs_off;
        if (off > csize - sstart) return -1;
        abs_off = (size_t)sstart + (size_t)off;
        pl->strings[i] = (flags & AXML_UTF8_FLAG)
            ? decode_utf8_entry(chunk + abs_off, csize - abs_off)
            : decode_utf16_entry(chunk + abs_off, csize - abs_off);
        if (!pl->strings[i]) return -1;
    }
    return 0;
}

static void copy_str(char *dst, size_t dstsz, const char *src) {
    size_t n;
    if (!dst || !dstsz || !src) return;
    n = strlen(src);
    if (n >= dstsz) n = dstsz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Resolve relative activity name (".MainActivity" -> "com.pkg.MainActivity"). */
static void qualify_activity(char *dst, size_t dstsz, const char *pkg, const char *act) {
    if (!act || !act[0]) return;
    if (act[0] == '.' && pkg && pkg[0]) {
        size_t lp = strlen(pkg), la = strlen(act);
        if (lp + la < dstsz) {
            memcpy(dst, pkg, lp);
            memcpy(dst + lp, act, la + 1);
            return;
        }
    } else if (!strchr(act, '.') && pkg && pkg[0]) {
        size_t lp = strlen(pkg), la = strlen(act);
        if (lp + 1 + la < dstsz) {
            memcpy(dst, pkg, lp);
            dst[lp] = '.';
            memcpy(dst + lp + 1, act, la + 1);
            return;
        }
    }
    copy_str(dst, dstsz, act);
}

int afw_axml_parse(const unsigned char *buf, size_t len, afw_apk_manifest *out) {
    axml_pool pool;
    size_t pos;
    uint32_t root_size;
    char cur_activity[256];
    char cur_activity_lib[128];
    int in_activity = 0, in_intent_filter = 0;
    int act_has_main = 0, act_has_launcher = 0;

    if (!buf || !out || len < 8) return -1;
    memset(out, 0, sizeof *out);
    memset(&pool, 0, sizeof pool);
    cur_activity[0] = '\0';
    cur_activity_lib[0] = '\0';

    if (rd16(buf) != RES_XML_TYPE) return -1;
    pos = rd16(buf + 2);
    root_size = rd32(buf + 4);
    if (pos < 8 || root_size > len || pos > root_size) return -1;

    while (pos + 8 <= root_size) {
        uint16_t ctype = rd16(buf + pos);
        uint16_t chdr  = rd16(buf + pos + 2);
        uint32_t csize = rd32(buf + pos + 4);
        const unsigned char *chunk = buf + pos;

        if (csize < 8 || chdr < 8 || chdr > csize || csize > root_size - pos) {
            pool_free(&pool);
            return -1;
        }

        if (ctype == RES_STRING_POOL_TYPE) {
            if (parse_string_pool(chunk, csize, &pool) != 0) {
                pool_free(&pool);
                return -1;
            }
        } else if (ctype == RES_XML_RESOURCE_MAP_TYPE) {
            uint32_t n = (csize - chdr) / 4u, i;
            free(pool.res_ids);
            pool.res_ids = n ? (uint32_t *)malloc((size_t)n * sizeof(uint32_t)) : NULL;
            pool.res_count = pool.res_ids ? n : 0;
            for (i = 0; i < pool.res_count; i++)
                pool.res_ids[i] = rd32(chunk + chdr + (size_t)i * 4u);
        } else if (ctype == RES_XML_START_ELEMENT_TYPE) {
            if (chdr + 20u <= csize) {
                int32_t elem_idx = (int32_t)rd32(chunk + chdr + 4u);
                uint16_t attr_start = rd16(chunk + chdr + 8u);
                uint16_t attr_size  = rd16(chunk + chdr + 10u);
                uint16_t attr_count = rd16(chunk + chdr + 12u);
                const char *elem = pool_str(&pool, elem_idx);
                const char *meta_name = NULL, *meta_val = NULL;
                uint16_t ai;

                if (elem && strcmp(elem, "activity") == 0) {
                    in_activity = 1;
                    cur_activity[0] = '\0';
                    cur_activity_lib[0] = '\0';
                    act_has_main = 0;
                    act_has_launcher = 0;
                } else if (elem && strcmp(elem, "intent-filter") == 0 && in_activity) {
                    in_intent_filter = 1;
                }

                if (elem && attr_size >= 20u && (size_t)chdr + (size_t)attr_start <= csize) {
                    size_t abase = (size_t)chdr + (size_t)attr_start;
                    for (ai = 0; ai < attr_count; ai++) {
                        size_t aoff = abase + (size_t)ai * (size_t)attr_size;
                        int32_t aname_idx, araw_idx;
                        uint8_t vtype;
                        uint32_t vdata, rid;
                        const char *aname, *sval = NULL;
                        if (aoff + 20u > csize) break;
                        aname_idx = (int32_t)rd32(chunk + aoff + 4u);
                        araw_idx  = (int32_t)rd32(chunk + aoff + 8u);
                        vtype     = chunk[aoff + 15u];
                        vdata     = rd32(chunk + aoff + 16u);
                        aname     = pool_str(&pool, aname_idx);
                        rid       = pool_res_id(&pool, aname_idx);
                        if (araw_idx >= 0) sval = pool_str(&pool, araw_idx);
                        else if (vtype == AXML_TYPE_STRING) sval = pool_str(&pool, (int32_t)vdata);

                        if (strcmp(elem, "manifest") == 0) {
                            if (aname && strcmp(aname, "package") == 0 && sval)
                                copy_str(out->package_name, sizeof out->package_name, sval);
                            else if (((aname && strcmp(aname, "versionName") == 0) || rid == ATTR_RES_VERSION_NAME) && sval)
                                copy_str(out->version_name, sizeof out->version_name, sval);
                            else if (((aname && strcmp(aname, "versionCode") == 0) || rid == ATTR_RES_VERSION_CODE) &&
                                     (vtype == AXML_TYPE_INT_DEC || vtype == AXML_TYPE_INT_HEX))
                                out->version_code = (int32_t)vdata;
                        } else if (strcmp(elem, "activity") == 0) {
                            if (((aname && strcmp(aname, "name") == 0) || rid == ATTR_RES_NAME) && sval)
                                qualify_activity(cur_activity, sizeof cur_activity, out->package_name, sval);
                        } else if (strcmp(elem, "meta-data") == 0) {
                            if (((aname && strcmp(aname, "name") == 0) || rid == ATTR_RES_NAME) && sval)
                                meta_name = sval;
                            else if (((aname && strcmp(aname, "value") == 0) || rid == ATTR_RES_VALUE) && sval)
                                meta_val = sval;
                        } else if (strcmp(elem, "action") == 0 && in_intent_filter) {
                            if (((aname && strcmp(aname, "name") == 0) || rid == ATTR_RES_NAME) && sval &&
                                strcmp(sval, "android.intent.action.MAIN") == 0)
                                act_has_main = 1;
                        } else if (strcmp(elem, "category") == 0 && in_intent_filter) {
                            if (((aname && strcmp(aname, "name") == 0) || rid == ATTR_RES_NAME) && sval &&
                                strcmp(sval, "android.intent.category.LAUNCHER") == 0)
                                act_has_launcher = 1;
                        }
                    }
                    if (strcmp(elem, "meta-data") == 0 && meta_name && meta_val &&
                        strcmp(meta_name, "android.app.lib_name") == 0) {
                        if (in_activity)
                            copy_str(cur_activity_lib, sizeof cur_activity_lib, meta_val);
                        if (!out->native_lib_name[0])
                            copy_str(out->native_lib_name, sizeof out->native_lib_name, meta_val);
                    }
                }
            }
        } else if (ctype == RES_XML_END_ELEMENT_TYPE) {
            if (chdr + 8u <= csize) {
                int32_t elem_idx = (int32_t)rd32(chunk + chdr + 4u);
                const char *elem = pool_str(&pool, elem_idx);
                if (elem && strcmp(elem, "intent-filter") == 0) {
                    in_intent_filter = 0;
                } else if (elem && strcmp(elem, "activity") == 0 && in_activity) {
                    int is_launcher = act_has_main && act_has_launcher;
                    if (is_launcher || (!out->has_launcher_activity && !out->main_activity[0] && cur_activity[0])) {
                        copy_str(out->main_activity, sizeof out->main_activity, cur_activity);
                        if (cur_activity_lib[0])
                            copy_str(out->native_lib_name, sizeof out->native_lib_name, cur_activity_lib);
                        if (is_launcher) out->has_launcher_activity = 1;
                    }
                    in_activity = 0;
                    in_intent_filter = 0;
                }
            }
        }
        pos += csize;
    }

    pool_free(&pool);
    return out->package_name[0] ? 0 : -1;
}
