/*
 * elf_loader.c - The heart of Milestone M0.
 *
 * What a real Android linker (/system/bin/linker64) does, done by us:
 *   1. Read the .so file and check it is a 64-bit x86 Android library.
 *   2. Copy its segments into memory at the right offsets.
 *   3. Read the dynamic section: which libraries it needs, its symbols.
 *   4. Connect every imported function to bionic-win (our libc).
 *   5. Apply relocations: patch the addresses inside the code/data.
 *   6. Set memory protections (code = executable, data = writable).
 *   7. Run the library's constructors.
 */
#include "elf_loader.h"
#include "attest.h"
#include "bionic_shim.h"
#include "exec.h"
#include "funcs.h"
#include "platform.h"
#include "sha256.h"
#include "tls_static.h"
#include "vma.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALIGN_DOWN(x, a) ((x) & ~((uint64_t)(a) - 1))
#define ALIGN_UP(x, a) ALIGN_DOWN((x) + (a) - 1, (a))

typedef SYSV void (*init_fn)(void);

int afw_load_patch_only;
int afw_load_allow_unproven;
int afw_attest_dump;

int afw_gate_ok(const afw_lib *lib) {
    const afw_patch_report *r = &lib->patch;
    return !r->unproven && !r->attest_rejected && !r->lsda_failures && !r->sys_untouched && !r->sys_outside_functions &&
           !r->fs_unsupported &&
           !r->gs_unsupported && !r->gs_outside_functions &&   /* gs: is the TEB on Windows (issue #15) */
           !r->fs_outside_functions &&   /* fs: look-alikes outside .eh_frame (reviewer 4); measured 0 in bionic */
           /* every fs:[reg] must really be rewritten (Windows); measurement mode
            * reports what Windows would do */
           (afw_load_patch_only || r->fs_reg_trampolined == r->fs_reg_feasible);
}

#define MAX_LIBS AFW_MAX_LIBS
static afw_lib *g_libs[MAX_LIBS];
static int g_nlibs;
static unsigned long long g_libs_adds;   /* monotonic finished-library count (dlpi_adds) */
static afw_lib *g_quarantine_head;   /* intrusive list: unbounded, zero-alloc, fail-safe under OOM */
static int g_nquarantine;

/* Append-only, immutable crash-diagnostic table for VEH (src/crash.c).
 * Entries are written once in lib_finish() under afw_libs_wrlock() ONLY after
 * a library reaches pending == 0 (never discarded/freed/moved) and published
 * via seq_cst store to g_ncrash_libs. */
typedef struct {
    uintptr_t        base;
    size_t           size;
    intptr_t         bias;
    const Elf64_Sym *symtab;
    const char      *strtab;
    size_t           nsyms;
    const char      *name;
} afw_crash_entry;

static afw_crash_entry g_crash_libs[MAX_LIBS];
static int32_t         g_ncrash_libs;

#ifdef AFW_TEST
static int g_fail_adopt;
void afw_load_test_fail_adopt(int nth) { g_fail_adopt = nth; }
#endif

/* Crash-handler diagnostic (called from VEH in src/crash.c): MUST remain
 * lock-free and never acquire afw_libs_rdlock() or VMA g_lock. Reads only
 * immutable entries published before the acquire load of g_ncrash_libs. */
int afw_describe_address(uintptr_t addr, char *out, size_t outsz) {
    int32_t k, n = afw_os_atomic_load_i32(&g_ncrash_libs);
    if (n < 0) n = 0;
    if (n > MAX_LIBS) n = MAX_LIBS;
    for (k = 0; k < n; k++) {
        const afw_crash_entry *e = &g_crash_libs[k];
        const char *best = NULL;
        uint64_t best_v = 0, off;
        size_t i;
        if (!e->base || addr < e->base || addr - e->base >= e->size) continue;
        off = (uint64_t)(addr - (uintptr_t)e->bias);
        for (i = 1; i < e->nsyms; i++) {
            const Elf64_Sym *s = &e->symtab[i];
            if (s->st_shndx == SHN_UNDEF || ELF64_ST_TYPE(s->st_info) != STT_FUNC) continue;
            if (s->st_value <= off && s->st_value >= best_v) {
                best_v = s->st_value;
                best = e->strtab + s->st_name;
            }
        }
        if (best)
            snprintf(out, outsz, "%s+0x%llx (%s+0x%llx)",
                     e->name, (unsigned long long)off,
                     best, (unsigned long long)(off - best_v));
        else
            snprintf(out, outsz, "%s+0x%llx", e->name, (unsigned long long)off);
        return 1;
    }
    snprintf(out, outsz, "%p (outside Android libraries)", (void *)addr);
    return 0;
}

static unsigned char *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    buf = (unsigned char *)malloc((size_t)n);
    if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); buf = NULL; }
    fclose(f);
    *out_size = (size_t)n;
    return buf;
}

/* A defined, exported symbol of an already loaded library other than self
 * (load order = dependency order, as the global scope of a dynamic linker). */
void *afw_sym(const afw_lib *lib, const char *name);
static const Elf64_Sym *find_def(const afw_lib *lib, const char *name) {
    size_t i;
    for (i = 1; i < lib->nsyms; i++) {
        const Elf64_Sym *s = &lib->symtab[i];
        if (s->st_shndx != SHN_UNDEF && ELF64_ST_BIND(s->st_info) != STB_LOCAL &&
            strcmp(lib->strtab + s->st_name, name) == 0)
            return s;
    }
    return NULL;
}

#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif

/* An import defined by another loaded library. Never runs library code: for
 * an IFUNC it returns the RESOLVER and sets *is_ifunc; the importer runs the
 * resolver in its own step 6c, after the exporting library is finished
 * (libc's memcpy, strlen... are IFUNCs on x86_64). */
static void *global_lookup(const char *name, const afw_lib *self, int *is_ifunc) {
    int k;
    void *res = NULL;
    *is_ifunc = 0;
    afw_libs_rdlock();
    for (k = 0; k < g_nlibs; k++) {
        const Elf64_Sym *s;
        if (g_libs[k] == self) continue;
        s = find_def(g_libs[k], name);
        if (s) {
            *is_ifunc = ELF64_ST_TYPE(s->st_info) == STT_GNU_IFUNC;
            res = (void *)(g_libs[k]->bias + s->st_value);
            break;
        }
    }
    afw_libs_rdunlock();
    return res;
}

/* Symbols the loader itself must provide even when a loaded library exports
 * them too (G1-TLS: __tls_get_addr until bionic's DTV exists). */
static int loader_override(const char *name) {
    return strcmp(name, "__tls_get_addr") == 0;
}

static const char *machine_name(uint16_t m) {
    switch (m) {
    case EM_X86_64: return "x86_64";
    case EM_AARCH64: return "arm64-v8a";
    case EM_ARM: return "armeabi-v7a";
    case EM_386: return "x86";
    default: return "unknown";
    }
}

/* Number of symbols: from DT_HASH, or computed from DT_GNU_HASH. */
static size_t count_symbols(const uint32_t *hash, const uint32_t *gnu) {
    if (hash) return hash[1]; /* nchain */
    if (gnu) {
        uint32_t nbuckets = gnu[0], symoffset = gnu[1], bloom_size = gnu[2];
        const uint64_t *bloom = (const uint64_t *)(gnu + 4);
        const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
        const uint32_t *chain = buckets + nbuckets;
        uint32_t i, last = 0;
        for (i = 0; i < nbuckets; i++)
            if (buckets[i] > last) last = buckets[i];
        if (last < symoffset) return symoffset;
        while (!(chain[last - symoffset] & 1)) last++;
        return (size_t)last + 1;
    }
    return 0;
}

/* Record a resolver to run once the code is patched and executable (6c). */
static int defer_ifunc(afw_lib *lib, uint64_t *where, uint64_t resolver) {
    if (lib->nirel == lib->capirel) {
        size_t nc = lib->capirel ? lib->capirel * 2 : 64;
        void *nb;
        if (nc < lib->capirel || nc > SIZE_MAX / sizeof *lib->irel) { fprintf(stderr, "error: too many IFUNCs\n"); return -1; }
        nb = realloc(lib->irel, nc * sizeof *lib->irel);
        if (!nb) { fprintf(stderr, "error: out of memory\n"); return -1; }
        lib->irel = nb; lib->capirel = nc;
    }
    lib->irel[lib->nirel].where = where;
    lib->irel[lib->nirel].resolver = resolver;
    lib->nirel++;
    return 0;
}

#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif
#ifndef DT_TEXTREL
#define DT_TEXTREL 22
#endif
#define DT_ANDROID_RELR_    0x6fffe000
#define DT_ANDROID_RELRSZ_  0x6fffe001
#define DT_ANDROID_RELRENT_ 0x6fffe003

/* Apply one array of RELA relocations. */
static int apply_rela(afw_lib *lib, const Elf64_Rela *rel, size_t count,
                      const uint64_t *symaddr, const unsigned char *imp_ifunc) {
    size_t i;
    for (i = 0; i < count; i++) {
        uint32_t type = ELF64_R_TYPE(rel[i].r_info);
        uint32_t sym = ELF64_R_SYM(rel[i].r_info);
        uintptr_t waddr = (uintptr_t)lib->bias + (uintptr_t)rel[i].r_offset;
        uint64_t *where = (uint64_t *)waddr;
        uint64_t S;
        int64_t A = rel[i].r_addend;
        if (type != R_X86_64_NONE) {
            uintptr_t lb = (uintptr_t)lib->base;
            if (waddr < lb || lib->size < sizeof(uint64_t) || waddr - lb > lib->size - sizeof(uint64_t)) {
                fprintf(stderr, "error: relocation offset 0x%llx outside mapped image\n",
                        (unsigned long long)rel[i].r_offset);
                return -1;
            }
        }
        if (sym >= lib->nsyms && sym != 0) {
            fprintf(stderr, "error: relocation symbol index %u out of range (nsyms %zu)\n", sym, lib->nsyms);
            return -1;
        }
        S = sym ? symaddr[sym] : 0;

        /* an IFUNC of this library, or one imported from another loaded
         * library: S is the RESOLVER; the address comes from running it,
         * later (step 6c) */
        if (sym && ((lib->symtab[sym].st_shndx != SHN_UNDEF &&
                     ELF64_ST_TYPE(lib->symtab[sym].st_info) == STT_GNU_IFUNC) || imp_ifunc[sym]) &&
            (type == R_X86_64_64 || type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT)) {
            if (afw_load_patch_only) continue;
            if (A != 0) { fprintf(stderr, "error: IFUNC relocation with an addend\n"); return -1; }
            if (defer_ifunc(lib, where, S) != 0) return -1;
            continue;
        }

        switch (type) {
        case R_X86_64_NONE: break;
        case R_X86_64_64: *where = S + A; break;
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT: *where = S; break;
        case R_X86_64_RELATIVE: *where = (uint64_t)lib->bias + A; break;
        /* TLS: a symbol's value is its offset inside its module's TLS block.
         * sym 0 (static __thread) means this library, S = 0 (reviewer 3). */
        case R_X86_64_TPOFF64:
        case R_X86_64_DTPMOD64:
        case R_X86_64_DTPOFF64: {
            const Elf64_Sym *sy = sym ? &lib->symtab[sym] : NULL;
            uint64_t sv = sy ? sy->st_value : 0;
            if (afw_load_patch_only) break;
            if (sy && sy->st_shndx == SHN_UNDEF) {
                fprintf(stderr, "error: TLS symbol %s is defined in another library; not supported in G1\n",
                        lib->strtab + sy->st_name);
                return -1;
            }
            if (sy && ELF64_ST_TYPE(sy->st_info) != STT_TLS) {
                fprintf(stderr, "error: TLS relocation against non-TLS symbol %s\n", lib->strtab + sy->st_name);
                return -1;
            }
            if (!lib->tls_module) {
                fprintf(stderr, "error: TLS relocation in a library without PT_TLS\n");
                return -1;
            }
            if (type == R_X86_64_DTPMOD64) *where = (uint64_t)lib->tls_module;
            else if (type == R_X86_64_DTPOFF64) *where = sv + (uint64_t)A;
            else *where = sv + (uint64_t)A - afw_tls_static_off(lib->tls_module);  /* negative */
            break;
        }
        case R_X86_64_TLSDESC:
            if (afw_load_patch_only) break;
            fprintf(stderr, "error: TLSDESC relocation (TLS descriptors) not supported yet\n");
            return -1;
        case R_X86_64_IRELATIVE: {
            /* The resolver is library code: it may run only once the code is
             * patched and executable and TLS is set up (reviewer 4, #8). Record
             * it; afw_load runs it in step 6c, before RELRO is applied. */
            if (afw_load_patch_only) break;  /* never run library code when measuring */
            if (defer_ifunc(lib, where, (uint64_t)(lib->bias + A)) != 0) return -1;
            break;
        }
        default:
            if (afw_load_patch_only) {
                static int warned[64];
                if (type < 64 && !warned[type]++)
                    fprintf(stderr, "note: relocation type %u not supported yet (skipped in measurement mode)\n", type);
                break;
            }
            fprintf(stderr, "error: unsupported relocation type %u at 0x%llx\n",
                    type, (unsigned long long)rel[i].r_offset);
            return -1;
        }
        lib->nrelocs++;
    }
    return 0;
}

/* RELR: compact encoding of RELATIVE relocations (newer Android NDKs). */
static void apply_relr(afw_lib *lib, const uint64_t *relr, size_t count) {
    uint64_t *where = NULL;
    size_t i;
    for (i = 0; i < count; i++) {
        uint64_t e = relr[i];
        if ((e & 1) == 0) {
            where = (uint64_t *)(lib->bias + e);
            *where++ += (uint64_t)lib->bias;
            lib->nrelocs++;
        } else {
            long k;
            for (k = 0; (e >>= 1) != 0; k++)
                if (e & 1) { where[k] += (uint64_t)lib->bias; lib->nrelocs++; }
            where += 63;
        }
    }
}

/* Signed LEB128 reader for Android APS2 packed relocations (DT_ANDROID_RELA).
 * Rejects truncated or overlong (>10-byte) encodings without UB. */
static int sleb128_read(const unsigned char **cur, const unsigned char *end, int64_t *out) {
    const unsigned char *p = *cur;
    uint64_t val = 0;
    unsigned shift = 0;
    while (p < end) {
        unsigned char byte = *p++;
        if (shift == 63) {
            if ((byte & 0x80u) != 0 || (byte != 0x00u && byte != 0x7fu))
                return -1;
            val |= ((uint64_t)(byte & 1u)) << 63;
            *cur = p;
            *out = (int64_t)val;
            return 0;
        }
        val |= ((uint64_t)(byte & 0x7fu)) << shift;
        shift += 7;
        if ((byte & 0x80u) == 0) {
            if (shift < 64 && (byte & 0x40u))
                val |= (~0ULL) << shift;
            *cur = p;
            *out = (int64_t)val;
            return 0;
        }
    }
    return -1;
}

/* Android packed RELA relocations (APS2, used by real Android 14 libm.so and
 * NDK libc++_shared.so). Decodes each group and feeds single Elf64_Rela
 * entries into apply_rela() so all IFUNC/TLS/error checks stay identical. */
static int apply_android_rela(afw_lib *lib, const unsigned char *buf, size_t sz,
                              const uint64_t *symaddr, const unsigned char *imp_ifunc) {
    const unsigned char *cur, *end;
    int64_t reloc_count = 0, init_off = 0, emitted = 0;
    uint64_t r_offset, r_info = 0;
    int64_t r_addend = 0;
    if (!buf || sz < 4 || memcmp(buf, "APS2", 4) != 0) {
        fprintf(stderr, "error: invalid Android packed relocation header (expected APS2)\n");
        return -1;
    }
    cur = buf + 4;
    end = buf + sz;
    if (sleb128_read(&cur, end, &reloc_count) != 0 || reloc_count < 0 ||
        sleb128_read(&cur, end, &init_off) != 0) {
        fprintf(stderr, "error: truncated APS2 relocation header\n");
        return -1;
    }
    r_offset = (uint64_t)init_off;
    while (emitted < reloc_count) {
        int64_t group_size = 0, group_flags_s = 0, group_off_delta = 0, gi;
        uint64_t flags;
        if (sleb128_read(&cur, end, &group_size) != 0 ||
            sleb128_read(&cur, end, &group_flags_s) != 0) {
            fprintf(stderr, "error: truncated APS2 relocation group header\n");
            return -1;
        }
        if (group_size <= 0 || group_size > reloc_count - emitted) {
            fprintf(stderr, "error: invalid APS2 relocation group size %lld\n", (long long)group_size);
            return -1;
        }
        flags = (uint64_t)group_flags_s;
        if (flags & ~15ULL) {
            fprintf(stderr, "error: unknown APS2 relocation group flags 0x%llx\n", (unsigned long long)flags);
            return -1;
        }
        if (flags & 2u) { /* RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG */
            if (sleb128_read(&cur, end, &group_off_delta) != 0) {
                fprintf(stderr, "error: truncated APS2 group offset delta\n");
                return -1;
            }
        }
        if (flags & 1u) { /* RELOCATION_GROUPED_BY_INFO_FLAG */
            int64_t v = 0;
            if (sleb128_read(&cur, end, &v) != 0) {
                fprintf(stderr, "error: truncated APS2 group info\n");
                return -1;
            }
            r_info = (uint64_t)v;
        }
        if ((flags & 4u) && (flags & 8u)) { /* GROUPED_BY_ADDEND && HAS_ADDEND */
            int64_t d = 0;
            if (sleb128_read(&cur, end, &d) != 0) {
                fprintf(stderr, "error: truncated APS2 group addend\n");
                return -1;
            }
            r_addend = (int64_t)((uint64_t)r_addend + (uint64_t)d);
        } else if (!(flags & 8u)) { /* !RELOCATION_GROUP_HAS_ADDEND_FLAG */
            r_addend = 0;
        }
        for (gi = 0; gi < group_size; gi++) {
            Elf64_Rela one;
            if (flags & 2u) {
                r_offset += (uint64_t)group_off_delta;
            } else {
                int64_t d = 0;
                if (sleb128_read(&cur, end, &d) != 0) {
                    fprintf(stderr, "error: truncated APS2 relocation offset delta\n");
                    return -1;
                }
                r_offset += (uint64_t)d;
            }
            if (!(flags & 1u)) {
                int64_t v = 0;
                if (sleb128_read(&cur, end, &v) != 0) {
                    fprintf(stderr, "error: truncated APS2 relocation info\n");
                    return -1;
                }
                r_info = (uint64_t)v;
            }
            if ((flags & 8u) && !(flags & 4u)) {
                int64_t d = 0;
                if (sleb128_read(&cur, end, &d) != 0) {
                    fprintf(stderr, "error: truncated APS2 relocation addend delta\n");
                    return -1;
                }
                r_addend = (int64_t)((uint64_t)r_addend + (uint64_t)d);
            }
            one.r_offset = r_offset;
            one.r_info = r_info;
            one.r_addend = r_addend;
            if (apply_rela(lib, &one, 1, symaddr, imp_ifunc) != 0) return -1;
            emitted++;
        }
    }
    return 0;
}

static int patch_bounds(const void *ctx, uint64_t addr, uint64_t *s, uint64_t *e) {
    return afw_func_bounds((const afw_lib *)ctx, addr, s, e);
}
static int patch_entries(const void *ctx, uint64_t func, uint64_t *out, int max) {
    return afw_func_landing_pads((const afw_lib *)ctx, func, out, max);
}
/* Every page of [addr, addr+len) is mapped by the file readable and NOT
 * writable (no overflow, no crossing into a writable or unmapped page). */
static int patch_readonly(const void *ctx, uint64_t addr, uint64_t len) {
    const afw_lib *lib = (const afw_lib *)ctx;
    uint64_t b = (uint64_t)(uintptr_t)lib->base, off, last, pg;
    if (!lib->load_prot || len == 0 || !afw_lib_readable(lib, addr, len)) return 0;
    off = addr - b;
    last = off + len - 1;
    for (pg = off / AFW_PAGE_SIZE; pg <= last / AFW_PAGE_SIZE; pg++) {
        if (pg >= lib->load_npages) return 0;
        if (!(lib->load_prot[pg] & PF_R) || (lib->load_prot[pg] & PF_W)) return 0;
    }
    return 1;
}
static int patch_readable(const void *ctx, uint64_t addr, uint64_t len) {
    return afw_lib_readable((const afw_lib *)ctx, addr, len);
}

/* NT_GNU_BUILD_ID of a PT_NOTE, as lowercase hex, bounds-checked. */
static void read_build_id(const unsigned char *f, size_t n, const Elf64_Phdr *p, char out[AFW_BUILD_ID_HEX]) {
    uint64_t o = p->p_offset, end;
    if (o > n || p->p_filesz > n - o) return;
    end = o + p->p_filesz;
    while (end - o >= 12) {
        uint32_t nsz, dsz, type, k;
        uint64_t name, desc, next;
        memcpy(&nsz, f + o, 4); memcpy(&dsz, f + o + 4, 4); memcpy(&type, f + o + 8, 4);
        name = o + 12;
        desc = name + (((uint64_t)nsz + 3) & ~3ull);
        next = desc + (((uint64_t)dsz + 3) & ~3ull);
        if (desc > end || next > end) return;
        if (type == 3 && nsz == 4 && memcmp(f + name, "GNU", 4) == 0 &&
            dsz > 0 && (size_t)dsz * 2 < AFW_BUILD_ID_HEX) {
            for (k = 0; k < dsz; k++) snprintf(out + 2 * k, 3, "%02x", f[desc + k]);
            return;
        }
        o = next;
    }
}

static int g_defer_finish;
static int lib_finish(afw_lib *lib, int verbose);
static void discard(afw_lib *lib);
static void retire_failed(afw_lib *lib);

static int load_inner(const char *path, afw_lib *lib, int verbose) {
    size_t fsize = 0, i;
    unsigned char *file;
    Elf64_Ehdr *eh;
    Elf64_Phdr *ph;
    uint64_t lo = UINT64_MAX, hi = 0;
    Elf64_Phdr dyn_copy, relro_copy, tls_copy;  /* copies: the file buffer is freed early */
    uint64_t eh_hdr_vaddr = 0;
    int skip_relocs = 0;
    Elf64_Phdr *dyn_ph = NULL, *relro_ph = NULL, *tls_ph = NULL;
    const uint32_t *hash = NULL, *gnu_hash = NULL;
    const Elf64_Rela *rela = NULL, *jmprel = NULL;
    size_t relasz = 0, pltrelsz = 0, relrsz = 0, android_relasz = 0;
    const uint64_t *relr = NULL;
    const unsigned char *android_rela = NULL;
    int64_t pltrel = DT_RELA;
    uint64_t soname_off = 0, needed_off[AFW_MAX_NEEDED];
    uint64_t *symaddr;
    unsigned char *imp_ifunc;
    unsigned char *pageprot;
    size_t npages;

    memset(lib, 0, sizeof(*lib));
    lib->path = path;

    /* 1. Read and validate ------------------------------------------ */
    file = read_file(path, &fsize);
    if (file) {                         /* identity of exactly these bytes (attestations, reports) */
        uint8_t h[32];
        afw_sha256(file, fsize, h);
        afw_sha256_hex(h, lib->sha256);
    }
    if (!file) { fprintf(stderr, "error: cannot read '%s'\n", path); return -1; }
    eh = (Elf64_Ehdr *)file;

    if (fsize < sizeof(Elf64_Ehdr) || memcmp(eh->e_ident, "\x7f" "ELF", 4) != 0) {
        fprintf(stderr, "error: '%s' is not an ELF file\n", path);
        free(file); return -1;
    }
    if (eh->e_ident[4] != ELFCLASS64 || eh->e_ident[5] != ELFDATA2LSB ||
        eh->e_type != ET_DYN) {
        fprintf(stderr, "error: not a 64-bit little-endian shared library\n");
        free(file); return -1;
    }
    if (eh->e_machine != EM_X86_64) {
        fprintf(stderr,
                "error: this library is built for %s, not x86_64.\n"
                "       Running ARM code on an x86 PC needs binary translation\n"
                "       (planned for milestone M5). Look for the x86_64 version\n"
                "       of the library inside the APK: lib/x86_64/\n",
                machine_name(eh->e_machine));
        free(file); return -1;
    }
    if (eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr) > fsize) {
        fprintf(stderr, "error: corrupt program headers\n");
        free(file); return -1;
    }
    ph = (Elf64_Phdr *)(file + eh->e_phoff);
    /* a copy for dl_iterate_phdr (the file buffer is freed early) */
    lib->phdr = (Elf64_Phdr *)malloc((size_t)eh->e_phnum * sizeof(Elf64_Phdr) + 1);
    if (!lib->phdr) { fprintf(stderr, "error: out of memory\n"); free(file); return -1; }
    memcpy(lib->phdr, ph, (size_t)eh->e_phnum * sizeof(Elf64_Phdr));
    lib->phnum = eh->e_phnum;
    lib->phoff = eh->e_phoff;

    /* Executable sections (when section headers exist): the audit sweeps
     * only these, not whole PT_LOAD segments that also hold .dynstr/.rodata */
    if (eh->e_shoff && eh->e_shnum && eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) <= fsize) {
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(file + eh->e_shoff);
        for (i = 0; i < eh->e_shnum; i++)
            if ((sh[i].sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) == (SHF_ALLOC | SHF_EXECINSTR) && sh[i].sh_size) {
                if (lib->nxsec < 16) {
                    lib->xsec_vaddr[lib->nxsec] = sh[i].sh_addr;
                    lib->xsec_size[lib->nxsec] = sh[i].sh_size;
                    lib->nxsec++;
                } else {
                    lib->xsec_truncated = 1;
                }
            }
    }

    /* 2. Map segments ------------------------------------------------ */
    for (i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            if (ph[i].p_vaddr < lo) lo = ph[i].p_vaddr;
            if (ph[i].p_vaddr + ph[i].p_memsz > hi) hi = ph[i].p_vaddr + ph[i].p_memsz;
        } else if (ph[i].p_type == PT_DYNAMIC) {
            dyn_copy = ph[i];
            dyn_ph = &dyn_copy;
        } else if (ph[i].p_type == PT_GNU_EH_FRAME) {
            eh_hdr_vaddr = ph[i].p_vaddr;
        } else if (ph[i].p_type == PT_GNU_RELRO) {
            relro_copy = ph[i];
            relro_ph = &relro_copy;
        } else if (ph[i].p_type == PT_INTERP) {
            lib->is_exec = 1;       /* an executable: afw_exec starts it at e_entry */
        } else if (ph[i].p_type == PT_NOTE) {
            read_build_id(file, fsize, &ph[i], lib->build_id);
        } else if (ph[i].p_type == PT_TLS) {
            if (afw_load_patch_only) fprintf(stderr, "note: PT_TLS present (ignored in measurement mode)\n");
            else { tls_copy = ph[i]; tls_ph = &tls_copy; }
        }
    }
    if (lo == UINT64_MAX || !dyn_ph) {
        fprintf(stderr, "error: no loadable segments or no dynamic section\n");
        free(file); return -1;
    }
    if (lib->is_exec && !afw_load_patch_only) {
        int entry_ok = 0;
        for (i = 0; i < eh->e_phnum; i++) {
            uint64_t seg_sz = ph[i].p_filesz;
            if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X)) continue;
            if (seg_sz == 0 || seg_sz > ph[i].p_memsz || seg_sz > UINT64_MAX - ph[i].p_vaddr) continue;
            if (eh->e_entry >= ph[i].p_vaddr && eh->e_entry < ph[i].p_vaddr + seg_sz) {
                entry_ok = 1;
                break;
            }
        }
        if (!entry_ok) {
            fprintf(stderr, "error: executable %s has e_entry 0x%llx outside any executable PT_LOAD segment\n",
                    path, (unsigned long long)eh->e_entry);
            free(file);
            return -1;
        }
    }
    lo = ALIGN_DOWN(lo, AFW_PAGE_SIZE);
    hi = ALIGN_UP(hi, AFW_PAGE_SIZE);
    lib->size = (size_t)(hi - lo);
    /* The stub area for patched syscalls sits right after the library, so a
     * call rel32 from any code in it always reaches its stub. */
    lib->base = (unsigned char *)afw_mem_alloc(lib->size + AFW_STUB_RESERVE);
    lib->stub_area = lib->base ? lib->base + lib->size : NULL;
    if (!lib->base) { fprintf(stderr, "error: out of memory\n"); free(file); return -1; }
    lib->bias = (intptr_t)lib->base - (intptr_t)lo;
    if (lib->is_exec && !afw_load_patch_only)
        lib->entry = (uint64_t)lib->bias + eh->e_entry;

    npages = lib->size / AFW_PAGE_SIZE;
    pageprot = (unsigned char *)calloc(npages, 1);

    if (verbose) printf("Segments:\n");
    for (i = 0; i < eh->e_phnum; i++) {
        size_t p, first, last;
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_offset + ph[i].p_filesz > fsize) {
            fprintf(stderr, "error: segment outside file\n");
            free(file); free(pageprot); return -1;
        }
        memcpy((void *)(lib->bias + ph[i].p_vaddr), file + ph[i].p_offset, ph[i].p_filesz);
        /* the rest (.bss) is already zero */

        first = (size_t)((ALIGN_DOWN(ph[i].p_vaddr, AFW_PAGE_SIZE) - lo) / AFW_PAGE_SIZE);
        last = (size_t)((ALIGN_UP(ph[i].p_vaddr + ph[i].p_memsz, AFW_PAGE_SIZE) - lo) / AFW_PAGE_SIZE);
        for (p = first; p < last; p++) pageprot[p] |= (unsigned char)(ph[i].p_flags & 7);

        if (verbose)
            printf("  LOAD vaddr=0x%06llx size=0x%06llx  %c%c%c\n",
                   (unsigned long long)ph[i].p_vaddr, (unsigned long long)ph[i].p_memsz,
                   (ph[i].p_flags & PF_R) ? 'R' : '-', (ph[i].p_flags & PF_W) ? 'W' : '-',
                   (ph[i].p_flags & PF_X) ? 'X' : '-');
    }
    free(file); /* everything we need is now in memory */

    if (eh_hdr_vaddr) lib->eh_frame_hdr = (const unsigned char *)(lib->bias + eh_hdr_vaddr);

    /* 3. Dynamic section --------------------------------------------- */
    lib->dynamic = (Elf64_Dyn *)(lib->bias + dyn_ph->p_vaddr);
    {
        Elf64_Dyn *d;
        for (d = lib->dynamic; d->d_tag != DT_NULL; d++) {
            uint64_t ptr = (uint64_t)lib->bias + d->d_val;
            switch (d->d_tag) {
            case DT_NEEDED:
                if (lib->nneeded < AFW_MAX_NEEDED) needed_off[lib->nneeded++] = d->d_val;
                break;
            case DT_SONAME: soname_off = d->d_val; break;
            case DT_STRTAB: lib->strtab = (const char *)(uintptr_t)ptr; break;
            case DT_SYMTAB: lib->symtab = (Elf64_Sym *)(uintptr_t)ptr; break;
            case DT_HASH: hash = (const uint32_t *)(uintptr_t)ptr; break;
            case DT_GNU_HASH: gnu_hash = (const uint32_t *)(uintptr_t)ptr; break;
            case DT_RELA: rela = (const Elf64_Rela *)(uintptr_t)ptr; break;
            case DT_RELASZ: relasz = d->d_val; break;
            case DT_JMPREL: jmprel = (const Elf64_Rela *)(uintptr_t)ptr; break;
            case DT_PLTRELSZ: pltrelsz = d->d_val; break;
            case DT_PLTREL: pltrel = (int64_t)d->d_val; break;
            /* RELR; the NDK writes it under Android's own tags below API 30
             * (--use-android-relr-tags). Ignoring those tags skipped every
             * relative relocation silently (measured: libdeps_base.so, PR #11). */
            case DT_RELR: case DT_ANDROID_RELR_: relr = (const uint64_t *)(uintptr_t)ptr; break;
            case DT_RELRSZ: case DT_ANDROID_RELRSZ_: relrsz = d->d_val; break;
            case DT_RELRENT: case DT_ANDROID_RELRENT_:
                if (d->d_val != 8) { fprintf(stderr, "error: RELR entry size %llu\n", (unsigned long long)d->d_val);
                                     free(pageprot); return -1; }
                break;
            case DT_TEXTREL:
                fprintf(stderr, "error: text relocations (DT_TEXTREL) are not supported\n");
                free(pageprot); return -1;
            case DT_INIT: lib->init = ptr; break;
            case DT_FINI: lib->fini = ptr; break;
            case DT_INIT_ARRAY: lib->init_array = (uint64_t *)(uintptr_t)ptr; break;
            case DT_INIT_ARRAYSZ: lib->init_array_count = d->d_val / 8; break;
            case DT_FINI_ARRAY: lib->fini_array = (uint64_t *)(uintptr_t)ptr; break;
            case DT_FINI_ARRAYSZ: lib->fini_array_count = d->d_val / 8; break;
            case DT_REL:
                fprintf(stderr, "error: REL relocations are not used on x86_64\n");
                free(pageprot); return -1;
            case DT_ANDROID_REL:
                if (afw_load_patch_only) { skip_relocs = 1; break; }
                fprintf(stderr, "error: Android packed REL relocations are not used on x86_64\n");
                free(pageprot); return -1;
            case DT_ANDROID_RELA:
                android_rela = (const unsigned char *)(uintptr_t)ptr;
                break;
            case DT_ANDROID_RELASZ:
                android_relasz = d->d_val;
                break;
            default: break;
            }
        }
    }
    if (!lib->strtab || !lib->symtab) {
        fprintf(stderr, "error: missing symbol tables\n");
        free(pageprot); return -1;
    }
    if (soname_off) lib->soname = lib->strtab + soname_off;
    for (i = 0; i < (size_t)lib->nneeded; i++) lib->needed[i] = lib->strtab + needed_off[i];
    if (pltrel != DT_RELA) {
        fprintf(stderr, "error: unexpected PLT relocation format\n");
        free(pageprot); return -1;
    }

    lib->nsyms = count_symbols(hash, gnu_hash);
    if (verbose) {
        printf("Library:    %s\n", lib->soname ? lib->soname : "(no soname)");
        printf("Needs:     ");
        for (i = 0; i < (size_t)lib->nneeded; i++) printf(" %s", lib->needed[i]);
        printf("\nSymbols:    %zu\n", lib->nsyms);
    }

    /* Mark pending BEFORE publishing to g_libs[] so concurrent dl_iterate_phdr /
     * dlsym readers never observe a half-relocated/unpatched library as finished. */
    lib->pending = 1;
    afw_libs_wrlock();
    if (g_nlibs >= MAX_LIBS) {
        afw_libs_wrunlock();
        fprintf(stderr, "error: too many loaded libraries (limit %d)\n", MAX_LIBS);
        free(pageprot); return -1;
    }
    g_libs[g_nlibs++] = lib;
    afw_libs_wrunlock();

    /* 3b. Static TLS: register this library's PT_TLS (its .tdata image stays
     *     in the mapped library; each thread copies it after relocation). */
    if (tls_ph) {
        afw_tls_segment seg;
        seg.p_vaddr = tls_ph->p_vaddr; seg.p_align = tls_ph->p_align;
        seg.p_memsz = tls_ph->p_memsz; seg.p_filesz = tls_ph->p_filesz;
        lib->tls_module = afw_tls_static_register((const void *)(lib->bias + tls_ph->p_vaddr), &seg,
                                                  lib->soname ? lib->soname : path);
        if (!lib->tls_module) return -1;
        if (verbose) printf("TLS:        module %d, %llu bytes (%llu initialised), align %llu, at tp-%llu\n",
                            lib->tls_module, (unsigned long long)seg.p_memsz, (unsigned long long)seg.p_filesz,
                            (unsigned long long)seg.p_align,
                            (unsigned long long)afw_tls_static_off(lib->tls_module));
    }

    /* 4. Resolve symbols against bionic-win -------------------------- */
    symaddr = (uint64_t *)calloc(lib->nsyms ? lib->nsyms : 1, sizeof(uint64_t));
    imp_ifunc = (unsigned char *)calloc(lib->nsyms ? lib->nsyms : 1, 1);
    if (!symaddr || !imp_ifunc) {
        fprintf(stderr, "error: out of memory\n");
        free(symaddr); free(imp_ifunc); free(pageprot); return -1;
    }
    for (i = 1; i < lib->nsyms; i++) {
        const Elf64_Sym *s = &lib->symtab[i];
        const char *name = lib->strtab + s->st_name;
        int bind = ELF64_ST_BIND(s->st_info);

        if (s->st_shndx != SHN_UNDEF) {
            symaddr[i] = (uint64_t)lib->bias + s->st_value;
            if (bind != STB_LOCAL && name[0]) lib->nexports++;
            continue;
        }
        if (!name[0]) continue;
        {
            void *shim = afw_shim_lookup(name);
            /* libc_shared_globals' layout is measured for one libc build only
             * (docs/design/G1-LIBC-INIT.md): any other build would read and
             * write the wrong fields. */
            if (shim && strcmp(name, "__loader_shared_globals") == 0 && !afw_load_patch_only &&
                strcmp(lib->build_id, AFW_SHARED_GLOBALS_BUILD_ID) != 0) {
                fprintf(stderr, "error: %s needs libc_shared_globals, whose layout is known only for libc.so\n"
                                "       Build ID %s; this one is '%s'. Refusing to guess it.\n",
                        path, AFW_SHARED_GLOBALS_BUILD_ID, lib->build_id);
                free(symaddr); free(imp_ifunc); free(pageprot); return -1;
            }
            int gi = 0;
            void *glob = loader_override(name) ? NULL : global_lookup(name, lib, &gi);
            if (glob) {                                 /* another loaded library defines it */
                symaddr[i] = (uint64_t)(uintptr_t)glob;
                imp_ifunc[i] = (unsigned char)gi;
                lib->nimports_linked++;
                if (verbose > 1) printf("  library  %s\n", name);
            } else if (shim) {
                symaddr[i] = (uint64_t)(uintptr_t)shim;
                lib->nimports_shimmed++;
                if (verbose > 1) printf("  linked   %s\n", name);
            } else if (bind == STB_WEAK) {
                symaddr[i] = 0;
                lib->nimports_weak_null++;
                if (verbose > 1) printf("  weak     %s (left empty)\n", name);
            } else {
                symaddr[i] = (uint64_t)(uintptr_t)afw_shim_missing_stub(name);
                lib->nimports_missing++;
                if (verbose) printf("  MISSING  %s (stub installed)\n", name);
            }
        }
    }

    /* 5. Relocate ---------------------------------------------------- */
    if (skip_relocs) {
        fprintf(stderr, "note: packed relocations present: relocation skipped (measurement mode)\n");
        relr = NULL; rela = NULL; android_rela = NULL; jmprel = NULL;
    }
    if (relr) apply_relr(lib, relr, relrsz / 8);
    if (android_rela) {
        uintptr_t ab = (uintptr_t)android_rela, lb = (uintptr_t)lib->base;
        if (ab < lb || (size_t)(ab - lb) > lib->size || android_relasz > lib->size - (size_t)(ab - lb)) {
            fprintf(stderr, "error: DT_ANDROID_RELA range outside mapped image\n");
            free(symaddr); free(imp_ifunc); free(pageprot); return -1;
        }
        if (apply_android_rela(lib, android_rela, android_relasz, symaddr, imp_ifunc) != 0) {
            free(symaddr); free(imp_ifunc); free(pageprot); return -1;
        }
    }
    if (rela && apply_rela(lib, rela, relasz / sizeof(Elf64_Rela), symaddr, imp_ifunc) != 0) {
        free(symaddr); free(imp_ifunc); free(pageprot); return -1;
    }
    if (jmprel && apply_rela(lib, jmprel, pltrelsz / sizeof(Elf64_Rela), symaddr, imp_ifunc) != 0) {
        free(symaddr); free(imp_ifunc); free(pageprot); return -1;
    }
    free(symaddr); free(imp_ifunc);

    /* 5b. Load-time patching of syscall / fs: instructions ------------ */
    {
        /* Decode only real functions (from .eh_frame), never the data that
         * shares the executable segment: decoded data could look like an
         * fs: access or a syscall and be "patched" into garbage. Fallback,
         * when there is no .eh_frame_hdr: whole executable segments, where
         * patch.c still requires known function bounds before changing bytes. */
        afw_code_range *cr, segs[16];
        int nsegs = 0, segs_truncated = 0, have_funcs;
        unsigned char **fstart;
        size_t *fsize;
        int ncr = afw_func_list(lib, &fstart, &fsize), k;
        have_funcs = ncr > 0;
        if (ncr > 0) {
            cr = (afw_code_range *)malloc((size_t)ncr * sizeof *cr);
            for (k = 0; k < ncr; k++) { cr[k].addr = fstart[k]; cr[k].size = fsize[k]; }
        } else {
            cr = (afw_code_range *)malloc(16 * sizeof *cr);
            for (i = 0; i < npages && ncr < 16;) {
                size_t j = i;
                if (!(pageprot[i] & PF_X)) { i++; continue; }
                while (j < npages && (pageprot[j] & PF_X)) j++;
                cr[ncr].addr = lib->base + i * AFW_PAGE_SIZE;
                cr[ncr].size = (j - i) * AFW_PAGE_SIZE;
                ncr++;
                i = j;
            }
        }
        free(fstart); free(fsize);
        if (lib->nxsec) {
            for (k = 0; k < lib->nxsec && k < 16; k++) {
                segs[k].addr = (unsigned char *)(lib->bias + lib->xsec_vaddr[k]);
                segs[k].size = (size_t)lib->xsec_size[k];
            }
            nsegs = k;
            segs_truncated = lib->xsec_truncated || (lib->nxsec > 16);
        } else {
            int nseg = 0;
            for (i = 0; i < npages;) {
                size_t j = i;
                if (!(pageprot[i] & PF_X)) { i++; continue; }
                while (j < npages && (pageprot[j] & PF_X)) j++;
                if (nseg < 16) {
                    segs[nseg].addr = lib->base + i * AFW_PAGE_SIZE;
                    segs[nseg].size = (j - i) * AFW_PAGE_SIZE;
                    nseg++;
                } else {
                    segs_truncated = 1;
                }
                i = j;
            }
            nsegs = nseg;
        }
        if (verbose) printf("Code:       %d %s decoded\n", ncr, lib->eh_frame_hdr ? "functions (.eh_frame)" : "segments (no .eh_frame_hdr)");
        afw_patch_ctx pc;
        memset(&pc, 0, sizeof pc);
        pc.bounds = patch_bounds; pc.ctx = lib; pc.bias = lib->bias; pc.name = lib->soname ? lib->soname : path;
        pc.ranges_are_functions = have_funcs; pc.segs = segs; pc.nsegs = nsegs; pc.segs_truncated = segs_truncated;
        pc.entries = patch_entries;
        pc.attest = afw_attest_for(lib->sha256, lib->attest_buf, (int)(sizeof lib->attest_buf / sizeof lib->attest_buf[0]), &pc.nattest);
        pc.readonly = patch_readonly;
        pc.attest_dump = afw_attest_dump;
        lib->load_prot = pageprot; lib->load_npages = npages;
        if (pc.nattest < 0) {
            fprintf(stderr, "error: attestation table for %s cannot be read; refusing to run it\n", path);
            lib->load_prot = NULL; lib->load_npages = 0;
            free(cr); free(pageprot); return -1;
        }
        pc.readable = patch_readable;
        {
            int prc = afw_patch_code(cr, ncr, lib->stub_area, AFW_STUB_RESERVE, &pc, &lib->patch, verbose);
            lib->load_prot = NULL; lib->load_npages = 0;   /* pageprot is freed below */
            if (prc < 0) {
                fprintf(stderr, "error: could not patch %s safely; refusing to run it\n", path);
                free(cr); free(pageprot); return -1;
            }
        }
        free(cr);
        if (!afw_load_patch_only && !afw_load_allow_unproven && !afw_gate_ok(lib)) {
            fprintf(stderr,
                    "error: refusing to run %s: patching left %d unproven syscall/fs: look-alikes,\n"
                    "       %d undecodable exception tables, %d untouched syscall sites and %d syscall\n"
                    "       bytes outside known functions, %d unsupported fs: accesses,\n"
                    "       %d fs:[reg] accesses not rewritten (rewriting exists on Windows only),\n"
                    "       %d unsupported gs: accesses (+%d outside known functions).\n"
                    "       Code we cannot prove safe is not run.\n"
                    "       (--allow-unproven overrides this, for diagnosis only)\n",
                    path, lib->patch.unproven, lib->patch.lsda_failures, lib->patch.sys_untouched,
                    lib->patch.sys_outside_functions, lib->patch.fs_unsupported,
                    lib->patch.fs_reg_feasible - lib->patch.fs_reg_trampolined,
                    lib->patch.gs_unsupported, lib->patch.gs_outside_functions);
            free(pageprot); return -1;
        }
        if (afw_mem_protect(lib->stub_area, AFW_STUB_RESERVE, AFW_PROT_R | AFW_PROT_X) != 0) {
            fprintf(stderr, "error: cannot make the stub area executable\n");
            free(pageprot); return -1;
        }
        afw_flush_icache(lib->stub_area, AFW_STUB_RESERVE);
        if (verbose)
            printf("Patched:    syscalls %d + %d moved (%d stubs), refused %d; fs: %d; fs:[reg] %d real, %d data\n",
                   lib->patch.sys_patched, lib->patch.sys_patched_moved, lib->patch.stubs,
                   lib->patch.sys_refused_branch + lib->patch.sys_refused_redzone + lib->patch.sys_refused_unknown,
                   lib->patch.fs_patched, lib->patch.fs_reg_in_func, lib->patch.fs_reg_outside);
    }

    /* 6a. Memory protection: code becomes executable (already patched) - */
    for (i = 0; i < npages;) {
        size_t j = i;
        while (j < npages && pageprot[j] == pageprot[i]) j++;
        if (afw_mem_protect(lib->base + i * AFW_PAGE_SIZE, (j - i) * AFW_PAGE_SIZE, pageprot[i]) != 0) {
            fprintf(stderr, "error: cannot set memory protection\n");
            free(pageprot); return -1;
        }
        i = j;
    }
    afw_flush_icache(lib->base, lib->size);

    lib->pageprot = pageprot;
    lib->npages = npages;
    if (relro_ph) {
        lib->relro_first = (size_t)((ALIGN_DOWN(relro_ph->p_vaddr, AFW_PAGE_SIZE) - lo) / AFW_PAGE_SIZE);
        lib->relro_last = (size_t)((ALIGN_DOWN(relro_ph->p_vaddr + relro_ph->p_memsz, AFW_PAGE_SIZE) - lo) / AFW_PAGE_SIZE);
    }
    lib->pending = 1;
    if (g_defer_finish) return 0;      /* afw_load_with_deps finishes the whole set together */
    if (!afw_load_patch_only && lib->is_exec && lib->entry)
        afw_exec_prepare_auxv(lib, path);
    return lib_finish(lib, verbose);
}

/* Phase B: everything that runs library code or closes the TLS layout.
 * With dependencies, every library of the set is mapped, relocated and
 * patched (phase A) before the first one gets here - like Android's linker,
 * which relocates the whole set before any constructor. Otherwise a
 * dependency without TLS (libdl) would close the static TLS layout before
 * the library that has TLS (libc) is even mapped (measured, PR #11). */
static int lib_finish(afw_lib *lib, int verbose) {
    size_t i;
    unsigned char *pageprot = lib->pageprot;
    size_t npages = lib->npages;
    lib->pageprot = NULL;

    if (!afw_load_patch_only) {
        /* 6b. Static TLS layout is final now: every thread block, including this
         *     thread's, gets the relocated .tdata images. Before any library code. */
        if (afw_tls_static_finish() != 0) { free(pageprot); return -1; }

        /* 6c. IFUNC resolvers (this library's and imported ones): the first
         *     library code to run, on patched, executable code, writing into
         *     pages that are still writable */
        if (lib->nirel) lib->code_ran = 1;
        for (i = 0; i < lib->nirel; i++) {
            typedef SYSV uint64_t (*resolver_fn)(void);
            resolver_fn r = (resolver_fn)(uintptr_t)lib->irel[i].resolver;
            *lib->irel[i].where = r();
        }
        if (verbose && lib->nirel) printf("IFUNC:      %zu resolver(s) run after patching (%s)\n", lib->nirel,
                                          lib->soname ? lib->soname : lib->path);
    }
    free(lib->irel); lib->irel = NULL; lib->nirel = lib->capirel = 0;

    /* 6d. RELRO: read-only from now on --------------------------------- */
    for (i = lib->relro_first; i < lib->relro_last && i < npages; i++) {
        pageprot[i] &= (unsigned char)~PF_W;
        if (afw_mem_protect(lib->base + i * AFW_PAGE_SIZE, AFW_PAGE_SIZE, pageprot[i]) != 0) {
            fprintf(stderr, "error: cannot apply RELRO\n");
            free(pageprot); return -1;
        }
    }

    /* 6e. Hand the image to the VMA layer, so the library's own mprotect /
     *     madvise / munmap work as on Linux (libc's WriteProtected globals,
     *     issue #12). Once, with the final protections, before any
     *     constructor: re-adopting later could overwrite changes Linux code
     *     made. The stub area after the image stays outside. ELF PF_* and
     *     Linux PROT_* differ: R and X are swapped. */
    for (i = 0; i < npages; i++)
        pageprot[i] = (unsigned char)(((pageprot[i] & PF_R) ? LNX_PROT_READ : 0) |
                                      ((pageprot[i] & PF_W) ? LNX_PROT_WRITE : 0) |
                                      ((pageprot[i] & PF_X) ? LNX_PROT_EXEC : 0));
    {
        int rc;
#ifdef AFW_TEST
        if (g_fail_adopt > 0 && --g_fail_adopt == 0) rc = -12;   /* simulated -ENOMEM */
        else
#endif
        rc = afw_vma_adopt((uint64_t)(uintptr_t)lib->base, (uint64_t)lib->size, pageprot);
        if (rc != 0) {
            fprintf(stderr, "error: the VMA layer refused %s's image (%d)\n",
                    lib->soname ? lib->soname : lib->path, rc);
            free(pageprot); return -1;
        }
        lib->vma_adopted = 1;
    }
    free(pageprot);
    afw_libs_wrlock();
    lib->pending = 0;
    g_libs_adds++;
    if (!afw_load_patch_only) {
        int32_t ci = afw_os_atomic_load_i32(&g_ncrash_libs);
        if (ci >= 0 && ci < MAX_LIBS) {
            g_crash_libs[ci].base   = (uintptr_t)lib->base;
            g_crash_libs[ci].size   = lib->size;
            g_crash_libs[ci].bias   = lib->bias;
            g_crash_libs[ci].symtab = lib->symtab;
            g_crash_libs[ci].strtab = lib->strtab;
            g_crash_libs[ci].nsyms  = lib->nsyms;
            g_crash_libs[ci].name   = lib->soname ? lib->soname : lib->path;
            afw_os_atomic_store_i32(&g_ncrash_libs, ci + 1);
        }
    }
    afw_libs_wrunlock();

    if (afw_load_patch_only) return 0;

    /* 7. Constructors ------------------------------------------------ */
    if (verbose) printf("Running %zu constructor(s) of %s...\n",
                        lib->init_array_count + (lib->init ? 1 : 0), lib->soname ? lib->soname : lib->path);
    if (lib->init || lib->init_array_count) lib->code_ran = 1;
    if (lib->init) ((init_fn)(uintptr_t)lib->init)();
    for (i = 0; i < lib->init_array_count; i++) {
        uint64_t f = lib->init_array[i];
        if (f != 0 && f != UINT64_MAX) ((init_fn)(uintptr_t)f)();
    }
    return 0;
}

/* A failed load leaves nothing behind (reviewer 4, #8): no entry in the
 * library list (main's lib is on its stack), no mapping, no TLS module. */
int afw_loaded_count(void) {
    int n;
    afw_libs_rdlock();
    n = g_nlibs;
    afw_libs_rdunlock();
    return n;
}
int afw_quarantined_count(void) {
    int n;
    afw_libs_rdlock();
    n = g_nquarantine;
    afw_libs_rdunlock();
    return n;
}
const afw_lib *afw_quarantined_at(int k) {
    const afw_lib *q, *res = NULL;
    if (k < 0) return NULL;
    afw_libs_rdlock();
    for (q = g_quarantine_head; q; q = q->quarantine_next)
        if (k-- == 0) { res = q; break; }
    afw_libs_rdunlock();
    return res;
}

/* DT_NEEDED names of an ELF file on disk (without mapping it). Returns the
 * count (<= max), or -1. names point into *buf, which the caller frees. */
static int file_needed(const char *path, unsigned char **buf, const char **names, int max) {
    size_t n = 0;
    unsigned char *f = read_file(path, &n);
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)f;
    const Elf64_Phdr *ph;
    uint64_t dyn_off = 0, dyn_sz = 0, strtab_va = 0, strtab_off = 0;
    int i, c = 0;
    size_t k;
    *buf = f;
    if (!f || n < sizeof *eh || memcmp(f, "\x7f" "ELF", 4) != 0 || eh->e_phoff > n ||
        (size_t)eh->e_phnum * sizeof *ph > n - eh->e_phoff)
        return -1;
    ph = (const Elf64_Phdr *)(f + eh->e_phoff);
    for (i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_DYNAMIC) { dyn_off = ph[i].p_offset; dyn_sz = ph[i].p_filesz; }
    if (!dyn_off || dyn_off > n || dyn_sz > n - dyn_off) return 0;
    for (k = 0; k + sizeof(Elf64_Dyn) <= dyn_sz; k += sizeof(Elf64_Dyn)) {
        const Elf64_Dyn *d = (const Elf64_Dyn *)(f + dyn_off + k);
        if (d->d_tag == DT_STRTAB) strtab_va = d->d_val;
    }
    for (i = 0; i < eh->e_phnum; i++)                    /* vaddr -> file offset */
        if (ph[i].p_type == PT_LOAD && strtab_va >= ph[i].p_vaddr && strtab_va < ph[i].p_vaddr + ph[i].p_filesz)
            strtab_off = strtab_va - ph[i].p_vaddr + ph[i].p_offset;
    if (!strtab_off || strtab_off >= n) return 0;
    for (k = 0; k + sizeof(Elf64_Dyn) <= dyn_sz && c < max; k += sizeof(Elf64_Dyn)) {
        const Elf64_Dyn *d = (const Elf64_Dyn *)(f + dyn_off + k);
        if (d->d_tag == DT_NEEDED && strtab_off + d->d_val < n &&
            memchr(f + strtab_off + d->d_val, 0, n - strtab_off - d->d_val))
            names[c++] = (const char *)(f + strtab_off + d->d_val);
    }
    return c;
}

static int find_lib(const char *name, const char *dir, char *out, size_t outsz);

/* ---- the registry, for the linker API (loader_api.c) ------------------ */
static const char *base_name(const char *p) {
    const char *b = strrchr(p, '/'), *bs = strrchr(p, '\\');
    if (bs && (!b || bs > b)) b = bs;
    return b ? b + 1 : p;
}

afw_lib *afw_lib_at(int k) {
    afw_lib *res;
    afw_libs_rdlock();
    res = (k >= 0 && k < g_nlibs) ? g_libs[k] : NULL;
    afw_libs_rdunlock();
    return res;
}

int afw_libs_snapshot_finished(afw_lib **out, int max, unsigned long long *adds_out) {
    int k, n = 0;
    afw_libs_rdlock();
    for (k = 0; k < g_nlibs && n < max; k++) {
        if (g_libs[k] && !g_libs[k]->pending)
            out[n++] = g_libs[k];
    }
    if (adds_out) *adds_out = g_libs_adds;
    afw_libs_rdunlock();
    return n;
}

afw_lib *afw_lib_containing(const void *addr) {
    uintptr_t a = (uintptr_t)addr;
    int k;
    afw_lib *res = NULL;
    if (!addr) return NULL;
    afw_libs_rdlock();
    for (k = 0; k < g_nlibs; k++) {
        afw_lib *l = g_libs[k];
        if (!l || l->pending || !l->base) continue;
        if (a >= (uintptr_t)l->base && a - (uintptr_t)l->base < l->size) {
            res = l;
            break;
        }
    }
    afw_libs_rdunlock();
    return res;
}

int32_t afw_lib_tls_dtor_count(const afw_lib *lib) {
    if (!lib) return 0;
    return afw_os_atomic_load_i32(&lib->tls_dtor_refcount);
}

afw_lib *afw_find_loaded(const char *name) {
    int k;
    const char *want = base_name(name);
    afw_lib *res = NULL;
    afw_libs_rdlock();
    for (k = 0; k < g_nlibs; k++)
        if ((g_libs[k]->soname && strcmp(g_libs[k]->soname, want) == 0) ||
            strcmp(base_name(g_libs[k]->path), want) == 0) {
            res = g_libs[k];
            break;
        }
    afw_libs_rdunlock();
    return res;
}

int afw_is_loaded(const void *handle) {
    int k, found = 0;
    afw_libs_rdlock();
    for (k = 0; k < g_nlibs; k++)
        if ((const void *)g_libs[k] == handle) { found = 1; break; }
    afw_libs_rdunlock();
    return found;
}

int afw_is_retained(const void *handle) {
    int k, found = 0;
    const afw_lib *q;
    afw_libs_rdlock();
    for (k = 0; k < g_nlibs; k++)
        if ((const void *)g_libs[k] == handle) { found = 1; break; }
    if (!found) {
        for (q = g_quarantine_head; q; q = q->quarantine_next)
            if ((const void *)q == handle) { found = 1; break; }
    }
    afw_libs_rdunlock();
    return found;
}

/* RTLD_DEFAULT order: every finished library, in load order (an IFUNC is
 * resolved by afw_sym OUTSIDE afw_libs_rdlock, never for an unfinished library). */
void *afw_global_sym(const char *name) {
    afw_lib *snap[MAX_LIBS];
    int k, n = afw_libs_snapshot_finished(snap, MAX_LIBS, NULL);
    for (k = 0; k < n; k++) {
        void *p = afw_sym(snap[k], name);
        if (p) return p;
    }
    return NULL;
}

int afw_find_lib(const char *name, char *out, size_t outsz) {
    char dir[1024];
    if (strchr(name, '/') || strchr(name, '\\')) {
        FILE *t = fopen(name, "rb");
        if (!t) return 0;
        fclose(t);
        snprintf(out, outsz, "%s", name);
        return 1;
    }
    /* AFW_LIB_PATH, then the directory of the first library loaded */
    afw_libs_rdlock();
    if (g_nlibs) {
        const char *p = g_libs[0]->path, *b = base_name(p);
        snprintf(dir, sizeof dir, "%.*s", b > p ? (int)(b - p - 1) : 1, b > p ? p : ".");
    } else {
        snprintf(dir, sizeof dir, ".");
    }
    afw_libs_rdunlock();
    return find_lib(name, dir, out, outsz);
}

static int already_loaded(const char *name) {
    int k, found = 0;
    const char *base;
    afw_libs_rdlock();
    for (k = 0; k < g_nlibs; k++) {
        if (g_libs[k]->soname && strcmp(g_libs[k]->soname, name) == 0) { found = 1; break; }
        base = strrchr(g_libs[k]->path, '/');
        if (!base) base = strrchr(g_libs[k]->path, '\\');
        base = base ? base + 1 : g_libs[k]->path;
        if (strcmp(base, name) == 0) { found = 1; break; }
    }
    afw_libs_rdunlock();
    return found;
}

/* Find name in the search path: the directories in AFW_LIB_PATH (';' or ':'
 * separated), then dir. */
static int find_lib(const char *name, const char *dir, char *out, size_t outsz) {
    const char *env = getenv("AFW_LIB_PATH");
    char d[1024];
    FILE *t;
    while (env && *env) {
        size_t l = strcspn(env, ";:");
        if (l && l < sizeof d) {
            memcpy(d, env, l); d[l] = 0;
            snprintf(out, outsz, "%s/%s", d, name);
            if ((t = fopen(out, "rb")) != NULL) { fclose(t); return 1; }
        }
        env += l + (env[l] ? 1 : 0);
    }
    snprintf(out, outsz, "%s/%s", dir, name);
    if ((t = fopen(out, "rb")) != NULL) { fclose(t); return 1; }
    return 0;
}

static int prepare_with_deps(const char *path, afw_lib *lib, afw_lib *deps, int maxdeps, int *ndeps, int verbose) {
    const char *names[AFW_MAX_NEEDED];
    unsigned char *buf = NULL;
    char dir[1024], found[1200];
    const char *slash = strrchr(path, '/');
    const char *bslash = strrchr(path, '\\');
    int n, i;
    if (bslash && (!slash || bslash > slash)) slash = bslash;
    snprintf(dir, sizeof dir, "%.*s", slash ? (int)(slash - path) : 1, slash ? path : ".");
    n = file_needed(path, &buf, names, AFW_MAX_NEEDED);
    for (i = 0; i < n; i++) {                            /* dependencies first (post-order) */
        if (already_loaded(names[i])) continue;
        if (!find_lib(names[i], dir, found, sizeof found)) {
            if (verbose) printf("dependency %s: not found, its symbols come from bionic-win\n", names[i]);
            continue;
        }
        if (*ndeps >= maxdeps) { fprintf(stderr, "error: too many libraries\n"); free(buf); return -1; }
        if (verbose) printf("\n== dependency %s (of %s)\n", found, path);
        {   /* the library keeps its path: `found` is this frame's (ASan: use after return) */
            char *own = (char *)malloc(strlen(found) + 1);
            afw_lib *d = &deps[(*ndeps)++];
            int rc;
            if (!own) { fprintf(stderr, "error: out of memory\n"); free(buf); return -1; }
            strcpy(own, found);
            rc = prepare_with_deps(own, d, deps, maxdeps, ndeps, verbose);
            if (rc != 0) free(own);
            else d->path_owned = 1;
            if (rc == 0) continue;
        }
        {
            fprintf(stderr, "error: dependency %s failed to load\n", found);
            free(buf); return -1;
        }
    }
    free(buf);
    if (verbose && n > 0) printf("\n== %s\n", path);
    return afw_load(path, lib, verbose);
}

int afw_load_with_deps(const char *path, afw_lib *lib, afw_lib *deps, int maxdeps, int *ndeps, int verbose) {
    afw_lib *batch[MAX_LIBS];
    int k, first, nbatch = 0, rc, prev_defer;
    afw_dlopen_lock();
    afw_libs_rdlock();
    first = g_nlibs;
    afw_libs_rdunlock();
    prev_defer = g_defer_finish;
    g_defer_finish = 1;
    rc = prepare_with_deps(path, lib, deps, maxdeps, ndeps, verbose);
    g_defer_finish = prev_defer;
    afw_libs_rdlock();
    for (k = first; k < g_nlibs && nbatch < MAX_LIBS; k++)
        batch[nbatch++] = g_libs[k];
    afw_libs_rdunlock();
    if (rc != 0) {                       /* nothing of the set ran: undo it, newest first */
        for (k = nbatch - 1; k >= 0; k--) retire_failed(batch[k]);
        afw_dlopen_unlock();
        return -1;
    }
    /* Now that the executable and all dependencies are mapped (Phase A), install
     * the executable's complete auxv into libc_shared_globals BEFORE Phase B runs
     * libc.so's or the executable's constructors. */
    if (!afw_load_patch_only && lib->is_exec && lib->entry)
        afw_exec_prepare_auxv(lib, path);
    if (verbose) printf("\n== all %d libraries mapped and relocated; TLS layout closes now\n", nbatch);
    for (k = 0; k < nbatch; k++)         /* dependency order: a library after the ones it needs */
        if (batch[k]->pending && lib_finish(batch[k], verbose) != 0) {
            int j;
            const char *who = batch[k]->soname ? batch[k]->soname : batch[k]->path;
            int late = batch[k]->code_ran || afw_tls_static_is_finished();
            fprintf(stderr, "error: %s failed to finish (%s); retiring it and %d unfinished library(ies)\n",
                    who, late ? "after point of no return" : "before TLS close", nbatch - k - 1);
            /* Retire batch[k..nbatch) newest first:
             *  - Before the point of no return (no code ran and TLS module not
             *    locked in a closed layout): discard() rolls back completely.
             *  - After the point of no return (IFUNC ran or TLS module locked in
             *    the closed layout): quarantine() removes the library from active
             *    g_libs[] while keeping its mapping, TLS module, and struct alive.
             * Earlier libraries batch[0..k-1] whose constructors already ran stay
             * loaded in g_libs[] (callers check afw_is_retained()). */
            for (j = nbatch - 1; j >= k; j--) retire_failed(batch[j]);
            afw_dlopen_unlock();
            return -1;
        }
    afw_dlopen_unlock();
    return 0;
}

static void remove_from_registry_locked(afw_lib *lib) {
    int k;
    for (k = 0; k < g_nlibs; k++)
        if (g_libs[k] == lib) {
            memmove(&g_libs[k], &g_libs[k + 1], (size_t)(g_nlibs - k - 1) * sizeof *g_libs);
            g_nlibs--;
            break;
        }
}

static void remove_from_registry(afw_lib *lib) {
    afw_libs_wrlock();
    remove_from_registry_locked(lib);
    afw_libs_wrunlock();
}

static int can_discard(const afw_lib *lib) {
    if (lib->code_ran) return 0;
    if (lib->tls_module && afw_tls_static_is_finished()) return 0;
    return 1;
}

static void discard(afw_lib *lib) {
    remove_from_registry(lib);
    if (lib->tls_module) {
        if (afw_tls_static_unregister(lib->tls_module) != 0)
            fprintf(stderr, "warning: TLS module of the failed library stays registered\n");
        else
            lib->tls_module = 0;
    }
    free(lib->irel); lib->irel = NULL; lib->nirel = lib->capirel = 0;
    if (lib->vma_adopted) {
        if (afw_vma_forget((uint64_t)(uintptr_t)lib->base) != 0)
            fprintf(stderr, "warning: the VMA layer still lists the failed library\n");
        else
            lib->vma_adopted = 0;
    }
    if (lib->base) afw_mem_free(lib->base, lib->size + AFW_STUB_RESERVE);
    lib->base = NULL; lib->stub_area = NULL;
    free(lib->pageprot); lib->pageprot = NULL; lib->pending = 0;
    free(lib->phdr); lib->phdr = NULL; lib->phnum = 0;
    if (lib->path_owned) { free((void *)lib->path); lib->path = NULL; lib->path_owned = 0; }
}

/* Past the point of no return (IFUNC/constructors ran, or static TLS layout
 * closed with this library's module in it): atomically move from active g_libs[]
 * onto the unbounded intrusive quarantine list under afw_libs_wrlock so no
 * lookup returns a failed library and afw_is_retained() never sees a gap. */
static void quarantine(afw_lib *lib) {
    afw_libs_wrlock();
    remove_from_registry_locked(lib);
    if (!lib->quarantined) {
        lib->quarantined = 1;
        lib->quarantine_next = g_quarantine_head;
        g_quarantine_head = lib;
        g_nquarantine++;
    }
    afw_libs_wrunlock();
    free(lib->irel); lib->irel = NULL; lib->nirel = lib->capirel = 0;
    free(lib->pageprot); lib->pageprot = NULL;
    free(lib->phdr); lib->phdr = NULL; lib->phnum = 0;
}

static void retire_failed(afw_lib *lib) {
    if (can_discard(lib)) discard(lib);
    else quarantine(lib);
}

int afw_load(const char *path, afw_lib *lib, int verbose) {
    int rc;
    afw_dlopen_lock();
    rc = load_inner(path, lib, verbose);
    if (rc != 0) retire_failed(lib);
    afw_dlopen_unlock();
    return rc;
}

void *afw_sym(const afw_lib *lib, const char *name) {
    const Elf64_Sym *s = find_def(lib, name);
    if (!s) return NULL;
    if (ELF64_ST_TYPE(s->st_info) == STT_GNU_IFUNC) {   /* the value is the resolver */
        typedef SYSV void *(*resolver_fn)(void);
        if (afw_load_patch_only || lib->pending) return NULL;  /* never run unfinished library code */
        return ((resolver_fn)(uintptr_t)(lib->bias + s->st_value))();
    }
    return (void *)(lib->bias + s->st_value);
}

void afw_unload(afw_lib *lib) {
    size_t i;
    for (i = lib->fini_array_count; i > 0; i--) {
        uint64_t f = lib->fini_array[i - 1];
        if (f != 0 && f != UINT64_MAX) ((init_fn)(uintptr_t)f)();
    }
    if (lib->fini) ((init_fn)(uintptr_t)lib->fini)();
    afw_shim_run_atexit();
}
