/*
 * dex_vm.c - Real Android DEX (classes.dex) parser, Dalvik register VM,
 * built-in Java/Android framework classes, and JNI native method dispatcher.
 */
#include "dex_vm.h"
#include "jni_bridge.h"
#include "elf_loader.h"
#include "platform.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACC_STATIC 0x0008u
#define ACC_NATIVE 0x0100u

static uint16_t rd16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int rd_uleb(const unsigned char *buf, size_t size, size_t *pos, uint32_t *out) {
    uint32_t val = 0;
    unsigned shift = 0;
    while (*pos < size && shift < 35) {
        unsigned char b = buf[(*pos)++];
        val |= ((uint32_t)(b & 0x7fu)) << shift;
        if ((b & 0x80u) == 0) { *out = val; return 0; }
        shift += 7;
    }
    return -1;
}

typedef struct {
    uint32_t class_idx;
    uint32_t type_idx;
    uint32_t name_idx;
} dex_field_id;

typedef struct {
    uint32_t class_idx;
    uint32_t proto_idx;
    uint32_t name_idx;
} dex_method_id;

typedef struct {
    uint32_t shorty_idx;
    uint32_t ret_type_idx;
    uint32_t params_off;
} dex_proto_id;

typedef struct {
    uint32_t method_idx;
    uint32_t access_flags;
    uint32_t code_off;
} dex_encoded_method;

typedef struct {
    uint32_t            class_idx;
    uint32_t            super_idx;
    dex_encoded_method *methods;
    uint32_t            nmethods;
} dex_class_def;

typedef enum {
    OBJ_FREE = 0,
    OBJ_CLASS,
    OBJ_STRING,
    OBJ_STRINGBUILDER,
    OBJ_INSTANCE,
    OBJ_INT_ARRAY,
    OBJ_PRINTSTREAM,
    OBJ_CANVAS,
    OBJ_PAINT,
    OBJ_ASSET_MGR
} dex_obj_kind;

typedef struct {
    int      field_id;
    uint64_t val;
} obj_field_slot;

#define MAX_INST_FIELDS 32

typedef struct {
    dex_obj_kind   kind;
    char           class_desc[192];
    char          *str;
    size_t         str_cap;
    int32_t       *iarr;
    int32_t        arr_len;
    uint32_t       paint_rgba;
    float          paint_text_size;
    float          paint_stroke;
    obj_field_slot fields[MAX_INST_FIELDS];
    int            nfields;
} dex_obj;

typedef struct {
    char  class_desc[192];
    char  name[128];
    char  sig[192];
    void *fn_ptr;
} dex_native_entry;

#define MAX_DEX_OBJS    4096
#define MAX_DEX_NATIVES 128

struct afw_dex_vm_s {
    unsigned char      *data;
    size_t              size;
    char              **strings;
    uint32_t            nstrings;
    uint32_t           *types;
    uint32_t            ntypes;
    dex_proto_id       *protos;
    uint32_t            nprotos;
    dex_field_id       *fields;
    uint32_t            nfields;
    dex_method_id      *methods;
    uint32_t            nmethods;
    dex_class_def      *classes;
    uint32_t            nclasses;
    uint64_t           *static_vals;

    dex_obj            *objs;
    uint32_t            nobjs;
    uint32_t            sys_out_handle;
    uint32_t            asset_mgr_handle;
    uint32_t            content_view_handle;

    dex_native_entry    natives[MAX_DEX_NATIVES];
    int                 nnatives;

    afw_jni_state      *jni;
    const afw_apk      *apk;
    afw_gui_surface    *surface;
    afw_dex_load_lib_fn load_lib_cb;
    void               *load_lib_ud;
    int                 frames_drawn;
};

static const char *dex_str(const afw_dex_vm *vm, uint32_t idx) {
    return (vm && idx < vm->nstrings && vm->strings[idx]) ? vm->strings[idx] : "";
}

static const char *dex_type(const afw_dex_vm *vm, uint32_t tidx) {
    return (vm && tidx < vm->ntypes) ? dex_str(vm, vm->types[tidx]) : "";
}

/* Convert Android ARGB int (0xAARRGGBB) to afw_gui RGBA8888 (0xAABBGGRR). */
static uint32_t argb_to_rgba(int32_t argb) {
    uint32_t u = (uint32_t)argb;
    uint8_t a = (uint8_t)((u >> 24) & 0xffu);
    uint8_t r = (uint8_t)((u >> 16) & 0xffu);
    uint8_t g = (uint8_t)((u >> 8) & 0xffu);
    uint8_t b = (uint8_t)(u & 0xffu);
    return afw_rgba(r, g, b, a);
}

/* ---- Managed object helpers ------------------------------------------- */
static uint32_t alloc_obj(afw_dex_vm *vm, dex_obj_kind kind, const char *desc) {
    uint32_t idx;
    dex_obj *o;
    if (!vm || vm->nobjs >= MAX_DEX_OBJS) return 0;
    idx = vm->nobjs++;
    o = &vm->objs[idx];
    memset(o, 0, sizeof *o);
    o->kind = kind;
    if (desc) snprintf(o->class_desc, sizeof o->class_desc, "%s", desc);
    return idx + 1u; /* 1-based handle */
}

static dex_obj *get_obj(const afw_dex_vm *vm, uint32_t handle) {
    if (!vm || handle == 0 || handle > vm->nobjs) return NULL;
    return &vm->objs[handle - 1u];
}

uint32_t afw_dex_new_string(afw_dex_vm *vm, const char *utf8) {
    uint32_t h;
    dex_obj *o;
    size_t n;
    if (!utf8) utf8 = "";
    h = alloc_obj(vm, OBJ_STRING, "Ljava/lang/String;");
    o = get_obj(vm, h);
    if (!o) return 0;
    n = strlen(utf8);
    o->str = (char *)malloc(n + 1);
    if (!o->str) return 0;
    memcpy(o->str, utf8, n + 1);
    o->str_cap = n + 1;
    return h;
}

const char *afw_dex_get_string(const afw_dex_vm *vm, uint32_t handle) {
    dex_obj *o = get_obj(vm, handle);
    if (!o) return NULL;
    if (o->kind == OBJ_STRING || o->kind == OBJ_STRINGBUILDER) return o->str ? o->str : "";
    return NULL;
}

static void sb_append(dex_obj *sb, const char *s) {
    size_t cur, add, need;
    char *nb;
    if (!sb || sb->kind != OBJ_STRINGBUILDER) return;
    if (!s) s = "null";
    cur = sb->str ? strlen(sb->str) : 0;
    add = strlen(s);
    need = cur + add + 1;
    if (need > sb->str_cap) {
        size_t ncap = sb->str_cap ? sb->str_cap * 2 : 64;
        while (ncap < need) ncap *= 2;
        nb = (char *)realloc(sb->str, ncap);
        if (!nb) return;
        sb->str = nb;
        sb->str_cap = ncap;
    }
    memcpy(sb->str + cur, s, add + 1);
}

uint32_t afw_dex_new_int_array(afw_dex_vm *vm, int32_t len) {
    uint32_t h;
    dex_obj *o;
    if (len < 0 || len > 1000000) return 0;
    h = alloc_obj(vm, OBJ_INT_ARRAY, "[I");
    o = get_obj(vm, h);
    if (!o) return 0;
    o->iarr = len ? (int32_t *)calloc((size_t)len, sizeof(int32_t)) : NULL;
    if (len && !o->iarr) return 0;
    o->arr_len = len;
    return h;
}

int32_t *afw_dex_int_array_data(afw_dex_vm *vm, uint32_t handle, int32_t *len_out) {
    dex_obj *o = get_obj(vm, handle);
    if (!o || o->kind != OBJ_INT_ARRAY) {
        if (len_out) *len_out = 0;
        return NULL;
    }
    if (len_out) *len_out = o->arr_len;
    return o->iarr;
}

static void normalize_class_desc(const char *in, char *out, size_t outsz) {
    size_t i = 0, p = 0;
    if (!in || !in[0]) { out[0] = '\0'; return; }
    if (in[0] == 'L' && in[strlen(in) - 1] == ';') {
        snprintf(out, outsz, "%s", in);
        return;
    }
    if (p + 1 < outsz) out[p++] = 'L';
    for (i = 0; in[i] && p + 2 < outsz; i++)
        out[p++] = (in[i] == '.') ? '/' : in[i];
    if (p + 1 < outsz) out[p++] = ';';
    out[p] = '\0';
}

uint32_t afw_dex_find_class(afw_dex_vm *vm, const char *slash_or_desc) {
    char desc[192];
    uint32_t i;
    if (!vm || !slash_or_desc) return 0;
    normalize_class_desc(slash_or_desc, desc, sizeof desc);
    for (i = 0; i < vm->nobjs; i++) {
        if (vm->objs[i].kind == OBJ_CLASS && strcmp(vm->objs[i].class_desc, desc) == 0)
            return i + 1u;
    }
    return alloc_obj(vm, OBJ_CLASS, desc);
}

const char *afw_dex_obj_class_desc(const afw_dex_vm *vm, uint32_t handle) {
    dex_obj *o = get_obj(vm, handle);
    return o ? o->class_desc : "";
}

uint32_t afw_dex_new_instance(afw_dex_vm *vm, const char *class_desc) {
    if (!vm || !class_desc) return 0;
    if (strcmp(class_desc, "Ljava/lang/StringBuilder;") == 0)
        return alloc_obj(vm, OBJ_STRINGBUILDER, class_desc);
    if (strcmp(class_desc, "Landroid/graphics/Paint;") == 0) {
        uint32_t h = alloc_obj(vm, OBJ_PAINT, class_desc);
        dex_obj *o = get_obj(vm, h);
        if (o) { o->paint_rgba = afw_rgba(255, 255, 255, 255); o->paint_text_size = 16.0f; o->paint_stroke = 2.0f; }
        return h;
    }
    return alloc_obj(vm, OBJ_INSTANCE, class_desc);
}

/* Build full JNI method signature "(params)ret" from proto_id */
static void build_proto_sig(const afw_dex_vm *vm, uint32_t proto_idx, char *out, size_t outsz) {
    size_t pos = 0;
    const dex_proto_id *pr;
    if (!vm || proto_idx >= vm->nprotos || outsz < 4) { if (outsz) out[0] = '\0'; return; }
    pr = &vm->protos[proto_idx];
    out[pos++] = '(';
    if (pr->params_off && pr->params_off + 4 <= vm->size) {
        uint32_t n = rd32(vm->data + pr->params_off), i;
        for (i = 0; i < n && pr->params_off + 4 + (size_t)(i + 1) * 2 <= vm->size; i++) {
            uint16_t tid = rd16(vm->data + pr->params_off + 4 + (size_t)i * 2);
            const char *t = dex_type(vm, tid);
            size_t l = strlen(t);
            if (pos + l + 2 < outsz) { memcpy(out + pos, t, l); pos += l; }
        }
    }
    if (pos + 2 < outsz) out[pos++] = ')';
    {
        const char *rt = dex_type(vm, pr->ret_type_idx);
        size_t l = strlen(rt);
        if (pos + l + 1 < outsz) { memcpy(out + pos, rt, l); pos += l; }
    }
    out[pos] = '\0';
}

int afw_dex_find_method_id(const afw_dex_vm *vm, const char *class_desc,
                           const char *name, const char *sig) {
    char ndesc[192];
    uint32_t i;
    if (!vm || !class_desc || !name) return -1;
    normalize_class_desc(class_desc, ndesc, sizeof ndesc);
    for (i = 0; i < vm->nmethods; i++) {
        const char *cd = dex_type(vm, vm->methods[i].class_idx);
        const char *mn = dex_str(vm, vm->methods[i].name_idx);
        if (strcmp(cd, ndesc) != 0 || strcmp(mn, name) != 0) continue;
        if (sig && sig[0]) {
            char msig[256];
            build_proto_sig(vm, vm->methods[i].proto_idx, msig, sizeof msig);
            if (strcmp(msig, sig) != 0) continue;
        }
        return (int)i;
    }
    return -1;
}

const char *afw_dex_method_shorty(const afw_dex_vm *vm, int method_idx) {
    if (!vm || method_idx < 0 || (uint32_t)method_idx >= vm->nmethods) return "V";
    return dex_str(vm, vm->protos[vm->methods[method_idx].proto_idx].shorty_idx);
}

int afw_dex_find_field_id(const afw_dex_vm *vm, const char *class_desc, const char *name) {
    char ndesc[192];
    uint32_t i;
    if (!vm || !class_desc || !name) return -1;
    normalize_class_desc(class_desc, ndesc, sizeof ndesc);
    for (i = 0; i < vm->nfields; i++) {
        if (strcmp(dex_type(vm, vm->fields[i].class_idx), ndesc) == 0 &&
            strcmp(dex_str(vm, vm->fields[i].name_idx), name) == 0)
            return (int)i;
    }
    return -1;
}

uint64_t afw_dex_get_inst_field(const afw_dex_vm *vm, uint32_t obj_h, int field_id) {
    dex_obj *o = get_obj(vm, obj_h);
    int i;
    if (!o) return 0;
    for (i = 0; i < o->nfields; i++)
        if (o->fields[i].field_id == field_id) return o->fields[i].val;
    return 0;
}

void afw_dex_set_inst_field(afw_dex_vm *vm, uint32_t obj_h, int field_id, uint64_t val) {
    dex_obj *o = get_obj(vm, obj_h);
    int i;
    if (!o) return;
    for (i = 0; i < o->nfields; i++) {
        if (o->fields[i].field_id == field_id) { o->fields[i].val = val; return; }
    }
    if (o->nfields < MAX_INST_FIELDS) {
        o->fields[o->nfields].field_id = field_id;
        o->fields[o->nfields].val = val;
        o->nfields++;
    }
}

int afw_dex_register_native(afw_dex_vm *vm, const char *class_desc,
                            const char *name, const char *sig, void *fn_ptr) {
    char ndesc[192];
    int i;
    if (!vm || !class_desc || !name || !fn_ptr) return -1;
    normalize_class_desc(class_desc, ndesc, sizeof ndesc);
    for (i = 0; i < vm->nnatives; i++) {
        if (strcmp(vm->natives[i].class_desc, ndesc) == 0 &&
            strcmp(vm->natives[i].name, name) == 0 &&
            (!sig || strcmp(vm->natives[i].sig, sig) == 0)) {
            vm->natives[i].fn_ptr = fn_ptr;
            return 0;
        }
    }
    if (vm->nnatives >= MAX_DEX_NATIVES) return -1;
    snprintf(vm->natives[vm->nnatives].class_desc, sizeof vm->natives[0].class_desc, "%s", ndesc);
    snprintf(vm->natives[vm->nnatives].name, sizeof vm->natives[0].name, "%s", name);
    snprintf(vm->natives[vm->nnatives].sig, sizeof vm->natives[0].sig, "%s", sig ? sig : "");
    vm->natives[vm->nnatives].fn_ptr = fn_ptr;
    vm->nnatives++;
    return 0;
}

static void *resolve_native_fn(afw_dex_vm *vm, const char *class_desc, const char *name, const char *sig) {
    int i;
    char mangled[384];
    size_t p = 0;
    const char *s;
    for (i = 0; i < vm->nnatives; i++) {
        if (strcmp(vm->natives[i].class_desc, class_desc) == 0 &&
            strcmp(vm->natives[i].name, name) == 0 &&
            (!vm->natives[i].sig[0] || !sig || strcmp(vm->natives[i].sig, sig) == 0))
            return vm->natives[i].fn_ptr;
    }
    /* Standard JNI symbol mangling: Java_<pkg>_<Class>_<method> */
    p += (size_t)snprintf(mangled, sizeof mangled, "Java_");
    s = (class_desc[0] == 'L') ? class_desc + 1 : class_desc;
    for (; *s && *s != ';' && p + 3 < sizeof mangled; s++) {
        if (*s == '/') mangled[p++] = '_';
        else if (*s == '_') { mangled[p++] = '_'; mangled[p++] = '1'; }
        else mangled[p++] = *s;
    }
    if (p + 2 < sizeof mangled) mangled[p++] = '_';
    for (s = name; *s && p + 3 < sizeof mangled; s++) {
        if (*s == '_') { mangled[p++] = '_'; mangled[p++] = '1'; }
        else mangled[p++] = *s;
    }
    mangled[p] = '\0';
    return afw_global_sym(mangled);
}

/* ---- Built-in Java / Android framework method dispatch ---------------- */
static float u32_to_f(uint32_t u) { float f; memcpy(&f, &u, 4); return f; }
static uint32_t f_to_u32(float f) { uint32_t u; memcpy(&u, &f, 4); return u; }

static int try_builtin_method(afw_dex_vm *vm, const char *cd, const char *mn, const char *shorty,
                              const uint64_t *args, int nargs, uint64_t *ret_out) {
    uint64_t ret = 0;
    (void)nargs;
    if (strcmp(cd, "Ljava/lang/Object;") == 0) {
        if (strcmp(mn, "<init>") == 0) { if (ret_out) *ret_out = 0; return 1; }
        if (strcmp(mn, "hashCode") == 0) { if (ret_out) *ret_out = args[0]; return 1; }
        if (strcmp(mn, "equals") == 0) { if (ret_out) *ret_out = (args[0] == args[1]) ? 1 : 0; return 1; }
        return 0;
    }
    if (strcmp(cd, "Ljava/lang/String;") == 0) {
        if (strcmp(mn, "length") == 0) {
            const char *s = afw_dex_get_string(vm, (uint32_t)args[0]);
            ret = s ? (uint64_t)strlen(s) : 0;
            if (ret_out) *ret_out = ret;
            return 1;
        }
        if (strcmp(mn, "equals") == 0) {
            const char *a = afw_dex_get_string(vm, (uint32_t)args[0]);
            const char *b = afw_dex_get_string(vm, (uint32_t)args[1]);
            ret = (a && b && strcmp(a, b) == 0) ? 1 : 0;
            if (ret_out) *ret_out = ret;
            return 1;
        }
        if (strcmp(mn, "valueOf") == 0) {
            char tmp[64];
            if (shorty[1] == 'I') snprintf(tmp, sizeof tmp, "%d", (int32_t)args[0]);
            else if (shorty[1] == 'J') snprintf(tmp, sizeof tmp, "%lld", (long long)args[0]);
            else if (shorty[1] == 'L') {
                const char *s = afw_dex_get_string(vm, (uint32_t)args[0]);
                snprintf(tmp, sizeof tmp, "%s", s ? s : "null");
            } else snprintf(tmp, sizeof tmp, "%u", (uint32_t)args[0]);
            ret = afw_dex_new_string(vm, tmp);
            if (ret_out) *ret_out = ret;
            return 1;
        }
        if (strcmp(mn, "trim") == 0) {
            const char *s = afw_dex_get_string(vm, (uint32_t)args[0]);
            if (!s) s = "";
            while (*s && (unsigned char)*s <= ' ') s++;
            {
                size_t len = strlen(s);
                while (len > 0 && (unsigned char)s[len - 1] <= ' ') len--;
                char *cp = (char *)malloc(len + 1);
                if (cp) { memcpy(cp, s, len); cp[len] = '\0'; }
                ret = afw_dex_new_string(vm, cp ? cp : "");
                free(cp);
            }
            if (ret_out) *ret_out = ret;
            return 1;
        }
        if (strcmp(mn, "contains") == 0) {
            const char *a = afw_dex_get_string(vm, (uint32_t)args[0]);
            const char *b = afw_dex_get_string(vm, (uint32_t)args[1]);
            if (ret_out) *ret_out = (a && b && strstr(a, b) != NULL) ? 1 : 0;
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Ljava/lang/StringBuilder;") == 0) {
        dex_obj *sb = get_obj(vm, (uint32_t)args[0]);
        if (strcmp(mn, "<init>") == 0) {
            if (sb && nargs >= 2 && shorty[1] == 'L') sb_append(sb, afw_dex_get_string(vm, (uint32_t)args[1]));
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "append") == 0) {
            char tmp[64];
            if (shorty[1] == 'L') sb_append(sb, afw_dex_get_string(vm, (uint32_t)args[1]));
            else if (shorty[1] == 'I') { snprintf(tmp, sizeof tmp, "%d", (int32_t)args[1]); sb_append(sb, tmp); }
            else if (shorty[1] == 'J') { snprintf(tmp, sizeof tmp, "%lld", (long long)args[1]); sb_append(sb, tmp); }
            else if (shorty[1] == 'Z') sb_append(sb, args[1] ? "true" : "false");
            else if (shorty[1] == 'C') { tmp[0] = (char)args[1]; tmp[1] = '\0'; sb_append(sb, tmp); }
            else if (shorty[1] == 'F') { snprintf(tmp, sizeof tmp, "%.2f", u32_to_f((uint32_t)args[1])); sb_append(sb, tmp); }
            if (ret_out) *ret_out = args[0];
            return 1;
        }
        if (strcmp(mn, "toString") == 0) {
            ret = afw_dex_new_string(vm, (sb && sb->str) ? sb->str : "");
            if (ret_out) *ret_out = ret;
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Ljava/lang/System;") == 0) {
        if (strcmp(mn, "loadLibrary") == 0) {
            const char *lib = afw_dex_get_string(vm, (uint32_t)args[0]);
            if (lib && vm->load_lib_cb) {
                if (vm->load_lib_cb(lib, vm->load_lib_ud) != 0)
                    fprintf(stderr, "[dex] System.loadLibrary(\"%s\") failed\n", lib);
            }
            if (ret_out) *ret_out = 0;
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Ljava/io/PrintStream;") == 0) {
        if (strcmp(mn, "println") == 0 || strcmp(mn, "print") == 0) {
            const char *nl = (strcmp(mn, "println") == 0) ? "\n" : "";
            if (nargs < 2) printf("%s", nl);
            else if (shorty[1] == 'I') printf("%d%s", (int32_t)args[1], nl);
            else if (shorty[1] == 'J') printf("%lld%s", (long long)args[1], nl);
            else {
                const char *s = afw_dex_get_string(vm, (uint32_t)args[1]);
                printf("%s%s", s ? s : "(obj)", nl);
            }
            fflush(stdout);
            if (ret_out) *ret_out = 0;
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Landroid/util/Log;") == 0) {
        const char *tag = afw_dex_get_string(vm, (uint32_t)args[0]);
        const char *msg = afw_dex_get_string(vm, (uint32_t)args[1]);
        char lv = (mn[0] >= 'a' && mn[0] <= 'z') ? (char)(mn[0] - 'a' + 'A') : 'I';
        printf("[logcat %c/%s] %s\n", lv, tag ? tag : "", msg ? msg : "");
        fflush(stdout);
        if (ret_out) *ret_out = 1;
        return 1;
    }
    if (strcmp(cd, "Ljava/lang/Math;") == 0) {
        if (strcmp(mn, "abs") == 0 && shorty[1] == 'I') {
            int32_t v = (int32_t)args[0];
            if (ret_out) *ret_out = (uint64_t)(uint32_t)(v < 0 ? -v : v);
            return 1;
        }
        if (strcmp(mn, "max") == 0 && shorty[1] == 'I') {
            int32_t a = (int32_t)args[0], b = (int32_t)args[1];
            if (ret_out) *ret_out = (uint64_t)(uint32_t)(a > b ? a : b);
            return 1;
        }
        if (strcmp(mn, "min") == 0 && shorty[1] == 'I') {
            int32_t a = (int32_t)args[0], b = (int32_t)args[1];
            if (ret_out) *ret_out = (uint64_t)(uint32_t)(a < b ? a : b);
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Landroid/app/Activity;") == 0) {
        if (strcmp(mn, "<init>") == 0 || strcmp(mn, "onCreate") == 0 ||
            strcmp(mn, "onStart") == 0 || strcmp(mn, "onResume") == 0 ||
            strcmp(mn, "onPause") == 0 || strcmp(mn, "onStop") == 0 || strcmp(mn, "onDestroy") == 0) {
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "setContentView") == 0) {
            vm->content_view_handle = (uint32_t)args[1];
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "getAssets") == 0) {
            if (ret_out) *ret_out = vm->asset_mgr_handle;
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Landroid/view/View;") == 0) {
        if (strcmp(mn, "<init>") == 0 || strcmp(mn, "invalidate") == 0 || strcmp(mn, "onDraw") == 0) {
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "getWidth") == 0) {
            if (ret_out) *ret_out = vm->surface ? (uint64_t)vm->surface->width : 0;
            return 1;
        }
        if (strcmp(mn, "getHeight") == 0) {
            if (ret_out) *ret_out = vm->surface ? (uint64_t)vm->surface->height : 0;
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Landroid/graphics/Color;") == 0) {
        if (strcmp(mn, "rgb") == 0) {
            uint32_t c = 0xff000000u | (((uint32_t)args[0] & 0xffu) << 16) |
                         (((uint32_t)args[1] & 0xffu) << 8) | ((uint32_t)args[2] & 0xffu);
            if (ret_out) *ret_out = c;
            return 1;
        }
        if (strcmp(mn, "argb") == 0) {
            uint32_t c = (((uint32_t)args[0] & 0xffu) << 24) | (((uint32_t)args[1] & 0xffu) << 16) |
                         (((uint32_t)args[2] & 0xffu) << 8) | ((uint32_t)args[3] & 0xffu);
            if (ret_out) *ret_out = c;
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Landroid/graphics/Paint;") == 0) {
        dex_obj *p = get_obj(vm, (uint32_t)args[0]);
        if (strcmp(mn, "<init>") == 0) { if (ret_out) *ret_out = 0; return 1; }
        if (strcmp(mn, "setColor") == 0) {
            if (p) p->paint_rgba = argb_to_rgba((int32_t)args[1]);
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "setTextSize") == 0) {
            if (p) p->paint_text_size = u32_to_f((uint32_t)args[1]);
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "setStrokeWidth") == 0) {
            if (p) p->paint_stroke = u32_to_f((uint32_t)args[1]);
            if (ret_out) *ret_out = 0;
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Landroid/graphics/Canvas;") == 0) {
        if (strcmp(mn, "getWidth") == 0) {
            if (ret_out) *ret_out = vm->surface ? (uint64_t)vm->surface->width : 0;
            return 1;
        }
        if (strcmp(mn, "getHeight") == 0) {
            if (ret_out) *ret_out = vm->surface ? (uint64_t)vm->surface->height : 0;
            return 1;
        }
        if (strcmp(mn, "drawColor") == 0) {
            if (vm->surface) afw_gui_clear(vm->surface, argb_to_rgba((int32_t)args[1]));
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "drawRect") == 0) {
            dex_obj *p = get_obj(vm, (uint32_t)args[5]);
            float l = u32_to_f((uint32_t)args[1]), t = u32_to_f((uint32_t)args[2]);
            float r = u32_to_f((uint32_t)args[3]), b = u32_to_f((uint32_t)args[4]);
            if (vm->surface)
                afw_gui_fill_rect(vm->surface, (int)l, (int)t, (int)(r - l), (int)(b - t),
                                  p ? p->paint_rgba : afw_rgba(255, 255, 255, 255));
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "drawCircle") == 0) {
            dex_obj *p = get_obj(vm, (uint32_t)args[4]);
            float cx = u32_to_f((uint32_t)args[1]), cy = u32_to_f((uint32_t)args[2]);
            float rad = u32_to_f((uint32_t)args[3]);
            if (vm->surface)
                afw_gui_fill_circle(vm->surface, (int)cx, (int)cy, (int)rad,
                                    p ? p->paint_rgba : afw_rgba(255, 255, 255, 255));
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "drawLine") == 0) {
            dex_obj *p = get_obj(vm, (uint32_t)args[5]);
            if (vm->surface)
                afw_gui_draw_line(vm->surface,
                                  (int)u32_to_f((uint32_t)args[1]), (int)u32_to_f((uint32_t)args[2]),
                                  (int)u32_to_f((uint32_t)args[3]), (int)u32_to_f((uint32_t)args[4]),
                                  p ? p->paint_rgba : afw_rgba(255, 255, 255, 255));
            if (ret_out) *ret_out = 0;
            return 1;
        }
        if (strcmp(mn, "drawText") == 0) {
            const char *txt = afw_dex_get_string(vm, (uint32_t)args[1]);
            float x = u32_to_f((uint32_t)args[2]), y = u32_to_f((uint32_t)args[3]);
            dex_obj *p = get_obj(vm, (uint32_t)args[4]);
            int scale = (p && p->paint_text_size >= 24.0f) ? 3 : 2;
            if (vm->surface && txt)
                afw_gui_draw_text(vm->surface, (int)x, (int)y, scale,
                                  p ? p->paint_rgba : afw_rgba(255, 255, 255, 255), txt);
            if (ret_out) *ret_out = 0;
            return 1;
        }
        return 0;
    }
    if (strcmp(cd, "Landroid/content/res/AssetManager;") == 0) {
        if (strcmp(mn, "readText") == 0) {
            const char *rel = afw_dex_get_string(vm, (uint32_t)args[1]);
            char full[384];
            unsigned char *abuf = NULL;
            size_t asz = 0;
            if (vm->apk && rel) {
                snprintf(full, sizeof full, "assets/%s", rel);
                if (afw_apk_read_file(vm->apk, full, &abuf, &asz) == 0) {
                    while (asz > 0 && (abuf[asz - 1] == '\n' || abuf[asz - 1] == '\r'))
                        abuf[--asz] = '\0';
                    ret = afw_dex_new_string(vm, (const char *)abuf);
                    free(abuf);
                    if (ret_out) *ret_out = ret;
                    return 1;
                }
            }
            if (ret_out) *ret_out = afw_dex_new_string(vm, "");
            return 1;
        }
        return 0;
    }
    return 0;
}

/* ---- Find encoded_method in class hierarchy --------------------------- */
static const dex_encoded_method *find_encoded_method(const afw_dex_vm *vm, const char *class_desc,
                                                     const char *name, const char *sig,
                                                     const char **owner_out) {
    uint32_t ci, mi;
    char cur[192];
    int depth;
    snprintf(cur, sizeof cur, "%s", class_desc ? class_desc : "");
    for (depth = 0; depth < 16 && cur[0]; depth++) {
        const dex_class_def *found_cls = NULL;
        for (ci = 0; ci < vm->nclasses; ci++) {
            if (strcmp(dex_type(vm, vm->classes[ci].class_idx), cur) == 0) {
                found_cls = &vm->classes[ci];
                break;
            }
        }
        if (!found_cls) break;
        for (mi = 0; mi < found_cls->nmethods; mi++) {
            const dex_encoded_method *em = &found_cls->methods[mi];
            const dex_method_id *mid = &vm->methods[em->method_idx];
            if (strcmp(dex_str(vm, mid->name_idx), name) != 0) continue;
            if (sig && sig[0]) {
                char msig[256];
                build_proto_sig(vm, mid->proto_idx, msig, sizeof msig);
                if (strcmp(msig, sig) != 0) continue;
            }
            if (owner_out) *owner_out = dex_type(vm, found_cls->class_idx);
            return em;
        }
        if (found_cls->super_idx == 0xffffffffu) break;
        snprintf(cur, sizeof cur, "%s", dex_type(vm, found_cls->super_idx));
    }
    return NULL;
}

static int invoke_method_internal(afw_dex_vm *vm, int method_idx,
                                  const uint64_t *args, int nargs,
                                  int is_virtual, uint64_t *ret_out);

/* ---- Dalvik bytecode interpreter -------------------------------------- */
static int exec_code_item(afw_dex_vm *vm, uint32_t code_off,
                          const uint64_t *args, int nargs, uint64_t *ret_out) {
    uint16_t regs_sz, ins_sz;
    uint32_t insns_sz, pc = 0;
    const unsigned char *code_p;
    uint32_t regs[256];
    uint64_t last_ret = 0;
    int i, steps = 0;

    if (code_off + 16 > vm->size) return -1;
    regs_sz  = rd16(vm->data + code_off + 0);
    ins_sz   = rd16(vm->data + code_off + 2);
    insns_sz = rd32(vm->data + code_off + 12);
    if (regs_sz > 256 || ins_sz > regs_sz) return -1;
    if ((size_t)insns_sz * 2 > vm->size - (code_off + 16)) return -1;
    code_p = vm->data + code_off + 16;

    memset(regs, 0, sizeof regs);
    /* Incoming args sit at top registers [regs_sz - ins_sz .. regs_sz).
     * Each incoming arg slot is already packed as 32-bit register units. */
    for (i = 0; i < nargs && i < (int)ins_sz; i++)
        regs[regs_sz - ins_sz + i] = (uint32_t)args[i];

    while (pc < insns_sz) {
        uint16_t w0 = rd16(code_p + (size_t)pc * 2);
        uint8_t op = (uint8_t)(w0 & 0xffu);
        if (++steps > 5000000) {
            fprintf(stderr, "[dex] aborting runaway loop\n");
            return -1;
        }
        switch (op) {
        case 0x00: /* nop */ pc += 1; break;
        case 0x01: case 0x07: /* move / move-object vA, vB */
            regs[(w0 >> 8) & 0xf] = regs[(w0 >> 12) & 0xf];
            pc += 1; break;
        case 0x02: case 0x08: /* move/from16 */
            regs[(w0 >> 8) & 0xff] = regs[rd16(code_p + (size_t)(pc + 1) * 2)];
            pc += 2; break;
        case 0x04: /* move-wide vA, vB */ {
            unsigned a = (w0 >> 8) & 0xf, b = (w0 >> 12) & 0xf;
            regs[a] = regs[b]; regs[a + 1] = regs[b + 1];
            pc += 1; break;
        }
        case 0x05: /* move-wide/from16 */ {
            unsigned a = (w0 >> 8) & 0xff, b = rd16(code_p + (size_t)(pc + 1) * 2);
            regs[a] = regs[b]; regs[a + 1] = regs[b + 1];
            pc += 2; break;
        }
        case 0x0a: case 0x0c: /* move-result / move-result-object */
            regs[(w0 >> 8) & 0xff] = (uint32_t)last_ret;
            pc += 1; break;
        case 0x0b: /* move-result-wide */ {
            unsigned a = (w0 >> 8) & 0xff;
            regs[a] = (uint32_t)(last_ret & 0xffffffffULL);
            regs[a + 1] = (uint32_t)(last_ret >> 32);
            pc += 1; break;
        }
        case 0x0e: /* return-void */
            if (ret_out) *ret_out = 0;
            return 0;
        case 0x0f: case 0x11: /* return / return-object */
            if (ret_out) *ret_out = (uint64_t)regs[(w0 >> 8) & 0xff];
            return 0;
        case 0x10: /* return-wide */ {
            unsigned a = (w0 >> 8) & 0xff;
            if (ret_out) *ret_out = (uint64_t)regs[a] | ((uint64_t)regs[a + 1] << 32);
            return 0;
        }
        case 0x12: /* const/4 vA, #+B */ {
            int32_t v = (int32_t)(int8_t)((w0 >> 8) & 0xf0) >> 4;
            regs[(w0 >> 8) & 0xf] = (uint32_t)v;
            pc += 1; break;
        }
        case 0x13: /* const/16 vAA, #+BBBB */ {
            int16_t v = (int16_t)rd16(code_p + (size_t)(pc + 1) * 2);
            regs[(w0 >> 8) & 0xff] = (uint32_t)(int32_t)v;
            pc += 2; break;
        }
        case 0x14: /* const vAA, #+BBBBBBBB */ {
            uint32_t lo = rd16(code_p + (size_t)(pc + 1) * 2);
            uint32_t hi = rd16(code_p + (size_t)(pc + 2) * 2);
            regs[(w0 >> 8) & 0xff] = lo | (hi << 16);
            pc += 3; break;
        }
        case 0x15: /* const/high16 vAA, #+BBBB0000 */ {
            uint32_t hi = rd16(code_p + (size_t)(pc + 1) * 2);
            regs[(w0 >> 8) & 0xff] = hi << 16;
            pc += 2; break;
        }
        case 0x16: /* const-wide/16 */ {
            unsigned a = (w0 >> 8) & 0xff;
            int64_t v = (int16_t)rd16(code_p + (size_t)(pc + 1) * 2);
            regs[a] = (uint32_t)((uint64_t)v & 0xffffffffULL);
            regs[a + 1] = (uint32_t)((uint64_t)v >> 32);
            pc += 2; break;
        }
        case 0x17: /* const-wide/32 */ {
            unsigned a = (w0 >> 8) & 0xff;
            uint32_t lo = rd16(code_p + (size_t)(pc + 1) * 2);
            uint32_t hi = rd16(code_p + (size_t)(pc + 2) * 2);
            int64_t v = (int32_t)(lo | (hi << 16));
            regs[a] = (uint32_t)((uint64_t)v & 0xffffffffULL);
            regs[a + 1] = (uint32_t)((uint64_t)v >> 32);
            pc += 3; break;
        }
        case 0x18: /* const-wide */ {
            unsigned a = (w0 >> 8) & 0xff;
            regs[a]     = (uint32_t)rd16(code_p + (size_t)(pc + 1) * 2) |
                          ((uint32_t)rd16(code_p + (size_t)(pc + 2) * 2) << 16);
            regs[a + 1] = (uint32_t)rd16(code_p + (size_t)(pc + 3) * 2) |
                          ((uint32_t)rd16(code_p + (size_t)(pc + 4) * 2) << 16);
            pc += 5; break;
        }
        case 0x1a: /* const-string vAA, string@BBBB */ {
            uint16_t sid = rd16(code_p + (size_t)(pc + 1) * 2);
            regs[(w0 >> 8) & 0xff] = afw_dex_new_string(vm, dex_str(vm, sid));
            pc += 2; break;
        }
        case 0x1b: /* const-string/jumbo */ {
            uint32_t sid = (uint32_t)rd16(code_p + (size_t)(pc + 1) * 2) |
                           ((uint32_t)rd16(code_p + (size_t)(pc + 2) * 2) << 16);
            regs[(w0 >> 8) & 0xff] = afw_dex_new_string(vm, dex_str(vm, sid));
            pc += 3; break;
        }
        case 0x1c: /* const-class vAA, type@BBBB */ {
            uint16_t tid = rd16(code_p + (size_t)(pc + 1) * 2);
            regs[(w0 >> 8) & 0xff] = afw_dex_find_class(vm, dex_type(vm, tid));
            pc += 2; break;
        }
        case 0x1f: /* check-cast */ pc += 2; break;
        case 0x20: /* instance-of */ regs[(w0 >> 8) & 0xf] = regs[(w0 >> 12) & 0xf] ? 1u : 0u; pc += 2; break;
        case 0x21: /* array-length vA, vB */ {
            int32_t alen = 0;
            (void)afw_dex_int_array_data(vm, regs[(w0 >> 12) & 0xf], &alen);
            regs[(w0 >> 8) & 0xf] = (uint32_t)alen;
            pc += 1; break;
        }
        case 0x22: /* new-instance vAA, type@BBBB */ {
            uint16_t tid = rd16(code_p + (size_t)(pc + 1) * 2);
            regs[(w0 >> 8) & 0xff] = afw_dex_new_instance(vm, dex_type(vm, tid));
            pc += 2; break;
        }
        case 0x23: /* new-array vA, vB, type@CCCC */ {
            unsigned a = (w0 >> 8) & 0xf, b = (w0 >> 12) & 0xf;
            regs[a] = afw_dex_new_int_array(vm, (int32_t)regs[b]);
            pc += 2; break;
        }
        case 0x28: /* goto +AA */
            pc = (uint32_t)((int32_t)pc + (int8_t)(w0 >> 8));
            break;
        case 0x29: /* goto/16 +AAAA */
            pc = (uint32_t)((int32_t)pc + (int16_t)rd16(code_p + (size_t)(pc + 1) * 2));
            break;
        case 0x2d: case 0x2e: /* cmpl-float / cmpg-float */ {
            unsigned d = (w0 >> 8) & 0xff;
            uint16_t w1 = rd16(code_p + (size_t)(pc + 1) * 2);
            float a = u32_to_f(regs[w1 & 0xff]), b = u32_to_f(regs[(w1 >> 8) & 0xff]);
            int32_t r = (a < b) ? -1 : ((a > b) ? 1 : ((a == b) ? 0 : (op == 0x2d ? -1 : 1)));
            regs[d] = (uint32_t)r;
            pc += 2; break;
        }
        case 0x31: /* cmp-long */ {
            unsigned d = (w0 >> 8) & 0xff;
            uint16_t w1 = rd16(code_p + (size_t)(pc + 1) * 2);
            unsigned ra = w1 & 0xff, rb = (w1 >> 8) & 0xff;
            int64_t a = (int64_t)((uint64_t)regs[ra] | ((uint64_t)regs[ra + 1] << 32));
            int64_t b = (int64_t)((uint64_t)regs[rb] | ((uint64_t)regs[rb + 1] << 32));
            regs[d] = (uint32_t)((a < b) ? -1 : ((a > b) ? 1 : 0));
            pc += 2; break;
        }
        case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37: /* if-test vA, vB, +CCCC */ {
            int32_t a = (int32_t)regs[(w0 >> 8) & 0xf];
            int32_t b = (int32_t)regs[(w0 >> 12) & 0xf];
            int16_t off = (int16_t)rd16(code_p + (size_t)(pc + 1) * 2);
            int take = 0;
            if (op == 0x32) take = (a == b);
            else if (op == 0x33) take = (a != b);
            else if (op == 0x34) take = (a < b);
            else if (op == 0x35) take = (a >= b);
            else if (op == 0x36) take = (a > b);
            else take = (a <= b);
            pc = take ? (uint32_t)((int32_t)pc + off) : (pc + 2);
            break;
        }
        case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d: /* if-testz vAA, +BBBB */ {
            int32_t a = (int32_t)regs[(w0 >> 8) & 0xff];
            int16_t off = (int16_t)rd16(code_p + (size_t)(pc + 1) * 2);
            int take = 0;
            if (op == 0x38) take = (a == 0);
            else if (op == 0x39) take = (a != 0);
            else if (op == 0x3a) take = (a < 0);
            else if (op == 0x3b) take = (a >= 0);
            else if (op == 0x3c) take = (a > 0);
            else take = (a <= 0);
            pc = take ? (uint32_t)((int32_t)pc + off) : (pc + 2);
            break;
        }
        case 0x44: case 0x46: /* aget / aget-object */ {
            uint16_t w1 = rd16(code_p + (size_t)(pc + 1) * 2);
            int32_t len = 0, idx = (int32_t)regs[(w1 >> 8) & 0xff];
            int32_t *arr = afw_dex_int_array_data(vm, regs[w1 & 0xff], &len);
            regs[(w0 >> 8) & 0xff] = (arr && idx >= 0 && idx < len) ? (uint32_t)arr[idx] : 0;
            pc += 2; break;
        }
        case 0x4b: case 0x4d: /* aput / aput-object */ {
            uint16_t w1 = rd16(code_p + (size_t)(pc + 1) * 2);
            int32_t len = 0, idx = (int32_t)regs[(w1 >> 8) & 0xff];
            int32_t *arr = afw_dex_int_array_data(vm, regs[w1 & 0xff], &len);
            if (arr && idx >= 0 && idx < len) arr[idx] = (int32_t)regs[(w0 >> 8) & 0xff];
            pc += 2; break;
        }
        case 0x52: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: /* iget* */ {
            unsigned a = (w0 >> 8) & 0xf, b = (w0 >> 12) & 0xf;
            uint16_t fid = rd16(code_p + (size_t)(pc + 1) * 2);
            regs[a] = (uint32_t)afw_dex_get_inst_field(vm, regs[b], (int)fid);
            pc += 2; break;
        }
        case 0x59: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: /* iput* */ {
            unsigned a = (w0 >> 8) & 0xf, b = (w0 >> 12) & 0xf;
            uint16_t fid = rd16(code_p + (size_t)(pc + 1) * 2);
            afw_dex_set_inst_field(vm, regs[b], (int)fid, (uint64_t)regs[a]);
            pc += 2; break;
        }
        case 0x60: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: /* sget* */ {
            unsigned a = (w0 >> 8) & 0xff;
            uint16_t fid = rd16(code_p + (size_t)(pc + 1) * 2);
            if (fid < vm->nfields) {
                const char *fcd = dex_type(vm, vm->fields[fid].class_idx);
                const char *fnm = dex_str(vm, vm->fields[fid].name_idx);
                if (strcmp(fcd, "Ljava/lang/System;") == 0 && strcmp(fnm, "out") == 0)
                    regs[a] = vm->sys_out_handle;
                else
                    regs[a] = (uint32_t)vm->static_vals[fid];
            }
            pc += 2; break;
        }
        case 0x67: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: /* sput* */ {
            unsigned a = (w0 >> 8) & 0xff;
            uint16_t fid = rd16(code_p + (size_t)(pc + 1) * 2);
            if (fid < vm->nfields) vm->static_vals[fid] = (uint64_t)regs[a];
            pc += 2; break;
        }
        case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72: /* invoke */
        case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: /* invoke-range */ {
            uint16_t mid = rd16(code_p + (size_t)(pc + 1) * 2);
            uint16_t w2  = rd16(code_p + (size_t)(pc + 2) * 2);
            uint64_t cargs[16];
            int cnt, k;
            int is_virt = (op == 0x6e || op == 0x72 || op == 0x74 || op == 0x78);
            if (op >= 0x74) {
                cnt = (w0 >> 8) & 0xff;
                if (cnt > 16) cnt = 16;
                for (k = 0; k < cnt; k++) cargs[k] = regs[w2 + k];
            } else {
                cnt = (w0 >> 12) & 0xf;
                if (cnt > 5) cnt = 5;
                if (cnt >= 1) cargs[0] = regs[w2 & 0xf];
                if (cnt >= 2) cargs[1] = regs[(w2 >> 4) & 0xf];
                if (cnt >= 3) cargs[2] = regs[(w2 >> 8) & 0xf];
                if (cnt >= 4) cargs[3] = regs[(w2 >> 12) & 0xf];
                if (cnt >= 5) cargs[4] = regs[(w0 >> 8) & 0xf];
            }
            if (invoke_method_internal(vm, (int)mid, cargs, cnt, is_virt, &last_ret) != 0)
                return -1;
            pc += 3; break;
        }
        /* Conversions & unary ops */
        case 0x7b: regs[(w0 >> 8) & 0xf] = (uint32_t)(-(int32_t)regs[(w0 >> 12) & 0xf]); pc += 1; break;
        case 0x7c: regs[(w0 >> 8) & 0xf] = ~regs[(w0 >> 12) & 0xf]; pc += 1; break;
        case 0x7f: regs[(w0 >> 8) & 0xf] = f_to_u32(-u32_to_f(regs[(w0 >> 12) & 0xf])); pc += 1; break;
        case 0x82: /* int-to-float */
            regs[(w0 >> 8) & 0xf] = f_to_u32((float)(int32_t)regs[(w0 >> 12) & 0xf]);
            pc += 1; break;
        case 0x87: /* float-to-int */
            regs[(w0 >> 8) & 0xf] = (uint32_t)(int32_t)u32_to_f(regs[(w0 >> 12) & 0xf]);
            pc += 1; break;
        case 0x8d: regs[(w0 >> 8) & 0xf] = (uint32_t)(int32_t)(int8_t)regs[(w0 >> 12) & 0xf]; pc += 1; break;
        case 0x8e: regs[(w0 >> 8) & 0xf] = regs[(w0 >> 12) & 0xf] & 0xffffu; pc += 1; break;
        case 0x8f: regs[(w0 >> 8) & 0xf] = (uint32_t)(int32_t)(int16_t)regs[(w0 >> 12) & 0xf]; pc += 1; break;
        case 0x81: /* int-to-long */ {
            unsigned a = (w0 >> 8) & 0xf, b = (w0 >> 12) & 0xf;
            int64_t v = (int32_t)regs[b];
            regs[a] = (uint32_t)((uint64_t)v & 0xffffffffULL);
            regs[a + 1] = (uint32_t)((uint64_t)v >> 32);
            pc += 1; break;
        }
        case 0x84: /* long-to-int */
            regs[(w0 >> 8) & 0xf] = regs[(w0 >> 12) & 0xf];
            pc += 1; break;
        /* 3-register int/float ops */
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94:
        case 0x95: case 0x96: case 0x97: case 0x98: case 0x99: case 0x9a: {
            unsigned d = (w0 >> 8) & 0xff;
            uint16_t w1 = rd16(code_p + (size_t)(pc + 1) * 2);
            int32_t a = (int32_t)regs[w1 & 0xff], b = (int32_t)regs[(w1 >> 8) & 0xff], r = 0;
            if (op == 0x90) r = a + b;
            else if (op == 0x91) r = a - b;
            else if (op == 0x92) r = a * b;
            else if (op == 0x93) r = b ? a / b : 0;
            else if (op == 0x94) r = b ? a % b : 0;
            else if (op == 0x95) r = a & b;
            else if (op == 0x96) r = a | b;
            else if (op == 0x97) r = a ^ b;
            else if (op == 0x98) r = (int32_t)((uint32_t)a << (b & 31));
            else if (op == 0x99) r = a >> (b & 31);
            else r = (int32_t)((uint32_t)a >> (b & 31));
            regs[d] = (uint32_t)r;
            pc += 2; break;
        }
        case 0xa6: case 0xa7: case 0xa8: case 0xa9: /* add/sub/mul/div-float */ {
            unsigned d = (w0 >> 8) & 0xff;
            uint16_t w1 = rd16(code_p + (size_t)(pc + 1) * 2);
            float a = u32_to_f(regs[w1 & 0xff]), b = u32_to_f(regs[(w1 >> 8) & 0xff]), r = 0.0f;
            if (op == 0xa6) r = a + b;
            else if (op == 0xa7) r = a - b;
            else if (op == 0xa8) r = a * b;
            else r = (b != 0.0f) ? a / b : 0.0f;
            regs[d] = f_to_u32(r);
            pc += 2; break;
        }
        /* 2-addr int/float ops */
        case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4:
        case 0xb5: case 0xb6: case 0xb7: case 0xb8: case 0xb9: case 0xba: {
            unsigned d = (w0 >> 8) & 0xf, s = (w0 >> 12) & 0xf;
            int32_t a = (int32_t)regs[d], b = (int32_t)regs[s], r = 0;
            if (op == 0xb0) r = a + b;
            else if (op == 0xb1) r = a - b;
            else if (op == 0xb2) r = a * b;
            else if (op == 0xb3) r = b ? a / b : 0;
            else if (op == 0xb4) r = b ? a % b : 0;
            else if (op == 0xb5) r = a & b;
            else if (op == 0xb6) r = a | b;
            else if (op == 0xb7) r = a ^ b;
            else if (op == 0xb8) r = (int32_t)((uint32_t)a << (b & 31));
            else if (op == 0xb9) r = a >> (b & 31);
            else r = (int32_t)((uint32_t)a >> (b & 31));
            regs[d] = (uint32_t)r;
            pc += 1; break;
        }
        case 0xc6: case 0xc7: case 0xc8: case 0xc9: /* add/sub/mul/div-float/2addr */ {
            unsigned d = (w0 >> 8) & 0xf, s = (w0 >> 12) & 0xf;
            float a = u32_to_f(regs[d]), b = u32_to_f(regs[s]), r = 0.0f;
            if (op == 0xc6) r = a + b;
            else if (op == 0xc7) r = a - b;
            else if (op == 0xc8) r = a * b;
            else r = (b != 0.0f) ? a / b : 0.0f;
            regs[d] = f_to_u32(r);
            pc += 1; break;
        }
        /* lit16 & lit8 int ops */
        case 0xd0: case 0xd1: case 0xd2: case 0xd3: case 0xd4: case 0xd5: case 0xd6: case 0xd7: {
            unsigned a = (w0 >> 8) & 0xf, b = (w0 >> 12) & 0xf;
            int32_t bv = (int32_t)regs[b], lit = (int16_t)rd16(code_p + (size_t)(pc + 1) * 2), r = 0;
            if (op == 0xd0) r = bv + lit;
            else if (op == 0xd1) r = lit - bv;
            else if (op == 0xd2) r = bv * lit;
            else if (op == 0xd3) r = lit ? bv / lit : 0;
            else if (op == 0xd4) r = lit ? bv % lit : 0;
            else if (op == 0xd5) r = bv & lit;
            else if (op == 0xd6) r = bv | lit;
            else r = bv ^ lit;
            regs[a] = (uint32_t)r;
            pc += 2; break;
        }
        case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc:
        case 0xdd: case 0xde: case 0xdf: case 0xe0: case 0xe1: case 0xe2: {
            unsigned d = (w0 >> 8) & 0xff;
            uint16_t w1 = rd16(code_p + (size_t)(pc + 1) * 2);
            int32_t bv = (int32_t)regs[w1 & 0xff], lit = (int8_t)(w1 >> 8), r = 0;
            if (op == 0xd8) r = bv + lit;
            else if (op == 0xd9) r = lit - bv;
            else if (op == 0xda) r = bv * lit;
            else if (op == 0xdb) r = lit ? bv / lit : 0;
            else if (op == 0xdc) r = lit ? bv % lit : 0;
            else if (op == 0xdd) r = bv & lit;
            else if (op == 0xde) r = bv | lit;
            else if (op == 0xdf) r = bv ^ lit;
            else if (op == 0xe0) r = (int32_t)((uint32_t)bv << (lit & 31));
            else if (op == 0xe1) r = bv >> (lit & 31);
            else r = (int32_t)((uint32_t)bv >> (lit & 31));
            regs[d] = (uint32_t)r;
            pc += 2; break;
        }
        default:
            fprintf(stderr, "[dex] unsupported Dalvik opcode 0x%02x at pc=%u\n", op, pc);
            return -1;
        }
    }
    if (ret_out) *ret_out = 0;
    return 0;
}

static int invoke_method_internal(afw_dex_vm *vm, int method_idx,
                                  const uint64_t *args, int nargs,
                                  int is_virtual, uint64_t *ret_out) {
    const dex_method_id *mid;
    const char *cd, *mn, *shorty;
    char sig[256];
    const dex_encoded_method *em;
    const char *owner = NULL;

    if (!vm || method_idx < 0 || (uint32_t)method_idx >= vm->nmethods) return -1;
    mid    = &vm->methods[method_idx];
    cd     = dex_type(vm, mid->class_idx);
    mn     = dex_str(vm, mid->name_idx);
    shorty = dex_str(vm, vm->protos[mid->proto_idx].shorty_idx);
    build_proto_sig(vm, mid->proto_idx, sig, sizeof sig);

    /* Virtual dispatch ONLY for invoke-virtual / invoke-interface (NOT invoke-super/direct!) */
    if (is_virtual && nargs > 0 && args[0] != 0) {
        const char *dyn_cd = afw_dex_obj_class_desc(vm, (uint32_t)args[0]);
        if (dyn_cd && dyn_cd[0] && strcmp(dyn_cd, cd) != 0 && strcmp(mn, "<init>") != 0) {
            em = find_encoded_method(vm, dyn_cd, mn, sig, &owner);
            if (em) cd = owner;
        }
    }

    em = find_encoded_method(vm, cd, mn, sig, &owner);
    if (em) {
        if (em->access_flags & ACC_NATIVE) {
            void *fn = resolve_native_fn(vm, owner ? owner : cd, mn, sig);
            uint32_t target_obj;
            const uint64_t *nargs_ptr;
            int nn;
            if (!fn) {
                fprintf(stderr, "[dex] unresolved native method %s.%s%s\n", cd, mn, sig);
                return -1;
            }
            if (em->access_flags & ACC_STATIC) {
                target_obj = afw_dex_find_class(vm, owner ? owner : cd);
                nargs_ptr = args;
                nn = nargs;
            } else {
                target_obj = (nargs > 0) ? (uint32_t)args[0] : 0;
                nargs_ptr = (nargs > 1) ? args + 1 : NULL;
                nn = (nargs > 0) ? nargs - 1 : 0;
            }
            {
                uint64_t r = afw_jni_call_native(vm->jni, fn, target_obj, shorty, nargs_ptr, nn);
                if (ret_out) *ret_out = r;
            }
            return 0;
        }
        if (em->code_off)
            return exec_code_item(vm, em->code_off, args, nargs, ret_out);
    }

    /* Walk class hierarchy for built-in Android / Java framework methods
     * (e.g. MainActivity -> Activity.setContentView / getAssets, DemoView -> View -> Object). */
    {
        char walk[192];
        int depth;
        snprintf(walk, sizeof walk, "%s", cd);
        for (depth = 0; depth < 16 && walk[0]; depth++) {
            uint32_t ci;
            const dex_class_def *fcls = NULL;
            if (try_builtin_method(vm, walk, mn, shorty, args, nargs, ret_out))
                return 0;
            for (ci = 0; ci < vm->nclasses; ci++) {
                if (strcmp(dex_type(vm, vm->classes[ci].class_idx), walk) == 0) {
                    fcls = &vm->classes[ci];
                    break;
                }
            }
            if (!fcls || fcls->super_idx == 0xffffffffu) break;
            snprintf(walk, sizeof walk, "%s", dex_type(vm, fcls->super_idx));
        }
        if (try_builtin_method(vm, "Ljava/lang/Object;", mn, shorty, args, nargs, ret_out))
            return 0;
    }

    fprintf(stderr, "[dex] method not found: %s.%s%s\n", cd, mn, sig);
    return -1;
}

int afw_dex_invoke_method_id(afw_dex_vm *vm, int method_idx,
                             const uint64_t *args, int nargs, uint64_t *ret_out) {
    return invoke_method_internal(vm, method_idx, args, nargs, 1, ret_out);
}

int afw_dex_invoke_by_name(afw_dex_vm *vm, const char *class_desc,
                           const char *name, const char *sig,
                           const uint64_t *args, int nargs, uint64_t *ret_out) {
    int mid = afw_dex_find_method_id(vm, class_desc, name, sig);
    if (mid < 0) return -1;
    return afw_dex_invoke_method_id(vm, mid, args, nargs, ret_out);
}

/* ---- DEX binary parser ------------------------------------------------ */
static int parse_dex(afw_dex_vm *vm) {
    uint32_t str_off, type_off, proto_off, field_off, meth_off, cls_off, i;
    if (vm->size < 112) return -1;
    if (memcmp(vm->data, "dex\n03", 6) != 0 && memcmp(vm->data, "dex\n04", 6) != 0)
        return -1;

    vm->nstrings = rd32(vm->data + 56); str_off   = rd32(vm->data + 60);
    vm->ntypes   = rd32(vm->data + 64); type_off  = rd32(vm->data + 68);
    vm->nprotos  = rd32(vm->data + 72); proto_off = rd32(vm->data + 76);
    vm->nfields  = rd32(vm->data + 80); field_off = rd32(vm->data + 84);
    vm->nmethods = rd32(vm->data + 88); meth_off  = rd32(vm->data + 92);
    vm->nclasses = rd32(vm->data + 96); cls_off   = rd32(vm->data + 100);

    if (vm->nstrings > 100000 || vm->ntypes > 100000 || vm->nprotos > 100000 ||
        vm->nfields > 100000 || vm->nmethods > 100000 || vm->nclasses > 65536)
        return -1;

    /* Strings */
    if (vm->nstrings) {
        if (str_off > vm->size || (size_t)vm->nstrings * 4 > vm->size - str_off) return -1;
        vm->strings = (char **)calloc(vm->nstrings, sizeof(char *));
        if (!vm->strings) return -1;
        for (i = 0; i < vm->nstrings; i++) {
            uint32_t doff = rd32(vm->data + str_off + (size_t)i * 4);
            size_t p = doff, slen = 0;
            uint32_t u16len = 0;
            if (p >= vm->size || rd_uleb(vm->data, vm->size, &p, &u16len) != 0) return -1;
            while (p + slen < vm->size && vm->data[p + slen] != 0) slen++;
            vm->strings[i] = (char *)malloc(slen + 1);
            if (!vm->strings[i]) return -1;
            if (slen) memcpy(vm->strings[i], vm->data + p, slen);
            vm->strings[i][slen] = '\0';
        }
    }
    /* Types */
    if (vm->ntypes) {
        if (type_off > vm->size || (size_t)vm->ntypes * 4 > vm->size - type_off) return -1;
        vm->types = (uint32_t *)malloc((size_t)vm->ntypes * sizeof(uint32_t));
        if (!vm->types) return -1;
        for (i = 0; i < vm->ntypes; i++)
            vm->types[i] = rd32(vm->data + type_off + (size_t)i * 4);
    }
    /* Protos */
    if (vm->nprotos) {
        if (proto_off > vm->size || (size_t)vm->nprotos * 12 > vm->size - proto_off) return -1;
        vm->protos = (dex_proto_id *)calloc(vm->nprotos, sizeof(dex_proto_id));
        if (!vm->protos) return -1;
        for (i = 0; i < vm->nprotos; i++) {
            const unsigned char *p = vm->data + proto_off + (size_t)i * 12;
            vm->protos[i].shorty_idx   = rd32(p + 0);
            vm->protos[i].ret_type_idx = rd32(p + 4);
            vm->protos[i].params_off   = rd32(p + 8);
        }
    }
    /* Fields */
    if (vm->nfields) {
        if (field_off > vm->size || (size_t)vm->nfields * 8 > vm->size - field_off) return -1;
        vm->fields = (dex_field_id *)calloc(vm->nfields, sizeof(dex_field_id));
        vm->static_vals = (uint64_t *)calloc(vm->nfields, sizeof(uint64_t));
        if (!vm->fields || !vm->static_vals) return -1;
        for (i = 0; i < vm->nfields; i++) {
            const unsigned char *p = vm->data + field_off + (size_t)i * 8;
            vm->fields[i].class_idx = rd16(p + 0);
            vm->fields[i].type_idx  = rd16(p + 2);
            vm->fields[i].name_idx  = rd32(p + 4);
        }
    }
    /* Methods */
    if (vm->nmethods) {
        if (meth_off > vm->size || (size_t)vm->nmethods * 8 > vm->size - meth_off) return -1;
        vm->methods = (dex_method_id *)calloc(vm->nmethods, sizeof(dex_method_id));
        if (!vm->methods) return -1;
        for (i = 0; i < vm->nmethods; i++) {
            const unsigned char *p = vm->data + meth_off + (size_t)i * 8;
            vm->methods[i].class_idx = rd16(p + 0);
            vm->methods[i].proto_idx = rd16(p + 2);
            vm->methods[i].name_idx  = rd32(p + 4);
        }
    }
    /* Class defs & class_data_item */
    if (vm->nclasses) {
        if (cls_off > vm->size || (size_t)vm->nclasses * 32 > vm->size - cls_off) return -1;
        vm->classes = (dex_class_def *)calloc(vm->nclasses, sizeof(dex_class_def));
        if (!vm->classes) return -1;
        for (i = 0; i < vm->nclasses; i++) {
            const unsigned char *p = vm->data + cls_off + (size_t)i * 32;
            uint32_t cdata_off;
            vm->classes[i].class_idx = rd32(p + 0);
            vm->classes[i].super_idx = rd32(p + 8);
            cdata_off = rd32(p + 24);
            if (cdata_off && cdata_off < vm->size) {
                size_t cp = cdata_off;
                uint32_t sf = 0, inf = 0, dm = 0, vm_cnt = 0, k, acc = 0, mid = 0;
                if (rd_uleb(vm->data, vm->size, &cp, &sf) != 0 ||
                    rd_uleb(vm->data, vm->size, &cp, &inf) != 0 ||
                    rd_uleb(vm->data, vm->size, &cp, &dm) != 0 ||
                    rd_uleb(vm->data, vm->size, &cp, &vm_cnt) != 0)
                    return -1;
                for (k = 0; k < sf + inf; k++) {
                    uint32_t fdiff = 0, facc = 0;
                    if (rd_uleb(vm->data, vm->size, &cp, &fdiff) != 0 ||
                        rd_uleb(vm->data, vm->size, &cp, &facc) != 0) return -1;
                }
                vm->classes[i].nmethods = dm + vm_cnt;
                if (dm + vm_cnt) {
                    vm->classes[i].methods = (dex_encoded_method *)calloc(dm + vm_cnt, sizeof(dex_encoded_method));
                    if (!vm->classes[i].methods) return -1;
                }
                mid = 0;
                for (k = 0; k < dm; k++) {
                    uint32_t mdiff = 0, coff = 0;
                    if (rd_uleb(vm->data, vm->size, &cp, &mdiff) != 0 ||
                        rd_uleb(vm->data, vm->size, &cp, &acc) != 0 ||
                        rd_uleb(vm->data, vm->size, &cp, &coff) != 0) return -1;
                    mid += mdiff;
                    vm->classes[i].methods[k].method_idx   = mid;
                    vm->classes[i].methods[k].access_flags = acc;
                    vm->classes[i].methods[k].code_off     = coff;
                }
                mid = 0;
                for (k = 0; k < vm_cnt; k++) {
                    uint32_t mdiff = 0, coff = 0;
                    if (rd_uleb(vm->data, vm->size, &cp, &mdiff) != 0 ||
                        rd_uleb(vm->data, vm->size, &cp, &acc) != 0 ||
                        rd_uleb(vm->data, vm->size, &cp, &coff) != 0) return -1;
                    mid += mdiff;
                    vm->classes[i].methods[dm + k].method_idx   = mid;
                    vm->classes[i].methods[dm + k].access_flags = acc;
                    vm->classes[i].methods[dm + k].code_off     = coff;
                }
            }
        }
    }
    return 0;
}

afw_dex_vm *afw_dex_vm_create(const unsigned char *dex_bytes, size_t dex_size,
                              const afw_apk *apk, afw_gui_surface *surface,
                              afw_dex_load_lib_fn load_lib_cb, void *load_lib_ud) {
    afw_dex_vm *vm;
    if (!dex_bytes || dex_size < 112) return NULL;
    vm = (afw_dex_vm *)calloc(1, sizeof *vm);
    if (!vm) return NULL;
    vm->data = (unsigned char *)malloc(dex_size);
    vm->objs = (dex_obj *)calloc(MAX_DEX_OBJS, sizeof(dex_obj));
    if (!vm->data || !vm->objs) { afw_dex_vm_destroy(vm); return NULL; }
    memcpy(vm->data, dex_bytes, dex_size);
    vm->size        = dex_size;
    vm->apk         = apk;
    vm->surface     = surface;
    vm->load_lib_cb = load_lib_cb;
    vm->load_lib_ud = load_lib_ud;
    vm->jni         = afw_jni_create(vm);
    if (!vm->jni || parse_dex(vm) != 0) { afw_dex_vm_destroy(vm); return NULL; }
    vm->sys_out_handle   = alloc_obj(vm, OBJ_PRINTSTREAM, "Ljava/io/PrintStream;");
    vm->asset_mgr_handle = alloc_obj(vm, OBJ_ASSET_MGR, "Landroid/content/res/AssetManager;");
    return vm;
}

void afw_dex_vm_destroy(afw_dex_vm *vm) {
    uint32_t i;
    if (!vm) return;
    if (vm->strings) {
        for (i = 0; i < vm->nstrings; i++) free(vm->strings[i]);
        free(vm->strings);
    }
    if (vm->classes) {
        for (i = 0; i < vm->nclasses; i++) free(vm->classes[i].methods);
        free(vm->classes);
    }
    if (vm->objs) {
        for (i = 0; i < vm->nobjs; i++) {
            free(vm->objs[i].str);
            free(vm->objs[i].iarr);
        }
        free(vm->objs);
    }
    afw_jni_destroy(vm->jni);
    free(vm->types);
    free(vm->protos);
    free(vm->fields);
    free(vm->methods);
    free(vm->static_vals);
    free(vm->data);
    free(vm);
}

void *afw_dex_vm_get_javavm(afw_dex_vm *vm) { return vm ? afw_jni_get_javavm(vm->jni) : NULL; }
void *afw_dex_vm_get_jnienv(afw_dex_vm *vm) { return vm ? afw_jni_get_jnienv(vm->jni) : NULL; }
int   afw_dex_frames_drawn(const afw_dex_vm *vm) { return vm ? vm->frames_drawn : 0; }

/* ---- Run Android Activity lifecycle + View.onDraw(Canvas) loop -------- */
int afw_dex_run_activity(afw_dex_vm *vm, const char *activity_dotted, int max_frames) {
    char desc[192];
    uint32_t act_obj, canvas_obj;
    uint64_t args[2];
    int clinit_id, f;

    if (!vm || !activity_dotted) return -1;
    normalize_class_desc(activity_dotted, desc, sizeof desc);

    /* Run static initializer <clinit> if present (typically calls System.loadLibrary) */
    clinit_id = afw_dex_find_method_id(vm, desc, "<clinit>", "()V");
    if (clinit_id >= 0) {
        if (afw_dex_invoke_method_id(vm, clinit_id, NULL, 0, NULL) != 0)
            return -1;
    }

    act_obj = afw_dex_new_instance(vm, desc);
    if (!act_obj) return -1;

    /* Activity.<init>() */
    args[0] = act_obj;
    if (afw_dex_invoke_by_name(vm, desc, "<init>", "()V", args, 1, NULL) != 0)
        return -1;

    /* Activity.onCreate(Bundle null) */
    args[0] = act_obj;
    args[1] = 0;
    if (afw_dex_invoke_by_name(vm, desc, "onCreate", "(Landroid/os/Bundle;)V", args, 2, NULL) != 0)
        return -1;

    /* Optional onStart / onResume */
    if (afw_dex_find_method_id(vm, desc, "onStart", "()V") >= 0)
        (void)afw_dex_invoke_by_name(vm, desc, "onStart", "()V", args, 1, NULL);
    if (afw_dex_find_method_id(vm, desc, "onResume", "()V") >= 0)
        (void)afw_dex_invoke_by_name(vm, desc, "onResume", "()V", args, 1, NULL);

    /* Frame loop: invoke contentView.onDraw(Canvas) and present to Win32 window */
    canvas_obj = alloc_obj(vm, OBJ_CANVAS, "Landroid/graphics/Canvas;");
    if (vm->content_view_handle) {
        const char *vdesc = afw_dex_obj_class_desc(vm, vm->content_view_handle);
        int ondraw_id = afw_dex_find_method_id(vm, vdesc, "onDraw", "(Landroid/graphics/Canvas;)V");
        if (ondraw_id >= 0) {
            for (f = 0; max_frames <= 0 || f < max_frames; f++) {
                if (vm->surface) {
                    afw_gui_pump_events(vm->surface);
                    if (afw_os_atomic_load_i32(&vm->surface->should_close)) break;
                }
                args[0] = vm->content_view_handle;
                args[1] = canvas_obj;
                if (afw_dex_invoke_method_id(vm, ondraw_id, args, 2, NULL) != 0)
                    return -1;
                vm->frames_drawn++;
                if (vm->surface) afw_gui_present(vm->surface);
            }
        }
    }

    /* Optional onDestroy */
    args[0] = act_obj;
    if (afw_dex_find_method_id(vm, desc, "onDestroy", "()V") >= 0)
        (void)afw_dex_invoke_by_name(vm, desc, "onDestroy", "()V", args, 1, NULL);

    return 0;
}
