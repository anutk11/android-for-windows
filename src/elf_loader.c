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
#include "bionic_shim.h"
#include "funcs.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALIGN_DOWN(x, a) ((x) & ~((uint64_t)(a) - 1))
#define ALIGN_UP(x, a) ALIGN_DOWN((x) + (a) - 1, (a))

typedef SYSV void (*init_fn)(void);

int afw_load_patch_only;

#define MAX_LIBS 64
static afw_lib *g_libs[MAX_LIBS];
static int g_nlibs;

int afw_describe_address(uintptr_t addr, char *out, size_t outsz) {
    int k;
    for (k = 0; k < g_nlibs; k++) {
        const afw_lib *lib = g_libs[k];
        uintptr_t b = (uintptr_t)lib->base;
        const char *best = NULL;
        uint64_t best_v = 0, off;
        size_t i;
        if (addr < b || addr >= b + lib->size) continue;
        off = (uint64_t)(addr - (uintptr_t)lib->bias);
        for (i = 1; i < lib->nsyms; i++) {
            const Elf64_Sym *s = &lib->symtab[i];
            if (s->st_shndx == SHN_UNDEF || ELF64_ST_TYPE(s->st_info) != STT_FUNC) continue;
            if (s->st_value <= off && s->st_value >= best_v) {
                best_v = s->st_value;
                best = lib->strtab + s->st_name;
            }
        }
        if (best)
            snprintf(out, outsz, "%s+0x%llx (%s+0x%llx)",
                     lib->soname ? lib->soname : lib->path, (unsigned long long)off,
                     best, (unsigned long long)(off - best_v));
        else
            snprintf(out, outsz, "%s+0x%llx", lib->soname ? lib->soname : lib->path,
                     (unsigned long long)off);
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

/* Apply one array of RELA relocations. */
static int apply_rela(afw_lib *lib, const Elf64_Rela *rel, size_t count,
                      const uint64_t *symaddr) {
    size_t i;
    for (i = 0; i < count; i++) {
        uint32_t type = ELF64_R_TYPE(rel[i].r_info);
        uint32_t sym = ELF64_R_SYM(rel[i].r_info);
        uint64_t *where = (uint64_t *)(lib->bias + rel[i].r_offset);
        uint64_t S = sym ? symaddr[sym] : 0;
        int64_t A = rel[i].r_addend;

        switch (type) {
        case R_X86_64_NONE: break;
        case R_X86_64_64: *where = S + A; break;
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT: *where = S; break;
        case R_X86_64_RELATIVE: *where = (uint64_t)lib->bias + A; break;
        case R_X86_64_IRELATIVE: {
            typedef SYSV uint64_t (*resolver_fn)(void);
            if (afw_load_patch_only) break;  /* never run library code when measuring */
            resolver_fn r = (resolver_fn)(uintptr_t)(lib->bias + A);
            *where = r();
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

static int patch_bounds(const void *ctx, uint64_t addr, uint64_t *s, uint64_t *e) {
    return afw_func_bounds((const afw_lib *)ctx, addr, s, e);
}
static int patch_entries(const void *ctx, uint64_t func, uint64_t *out, int max) {
    return afw_func_landing_pads((const afw_lib *)ctx, func, out, max);
}

int afw_load(const char *path, afw_lib *lib, int verbose) {
    size_t fsize = 0, i;
    unsigned char *file;
    Elf64_Ehdr *eh;
    Elf64_Phdr *ph;
    uint64_t lo = UINT64_MAX, hi = 0;
    Elf64_Phdr dyn_copy, relro_copy;     /* copies: the file buffer is freed early */
    uint64_t eh_hdr_vaddr = 0;
    int skip_relocs = 0;
    Elf64_Phdr *dyn_ph = NULL, *relro_ph = NULL;
    const uint32_t *hash = NULL, *gnu_hash = NULL;
    const Elf64_Rela *rela = NULL, *jmprel = NULL;
    size_t relasz = 0, pltrelsz = 0, relrsz = 0;
    const uint64_t *relr = NULL;
    int64_t pltrel = DT_RELA;
    uint64_t soname_off = 0, needed_off[AFW_MAX_NEEDED];
    uint64_t *symaddr;
    unsigned char *pageprot;
    size_t npages;

    memset(lib, 0, sizeof(*lib));
    lib->path = path;

    /* 1. Read and validate ------------------------------------------ */
    file = read_file(path, &fsize);
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

    /* Executable sections (when section headers exist): the audit sweeps
     * only these, not whole PT_LOAD segments that also hold .dynstr/.rodata */
    if (eh->e_shoff && eh->e_shnum && eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) <= fsize) {
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(file + eh->e_shoff);
        for (i = 0; i < eh->e_shnum && lib->nxsec < 16; i++)
            if ((sh[i].sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) == (SHF_ALLOC | SHF_EXECINSTR) && sh[i].sh_size) {
                lib->xsec_vaddr[lib->nxsec] = sh[i].sh_addr;
                lib->xsec_size[lib->nxsec] = sh[i].sh_size;
                lib->nxsec++;
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
        } else if (ph[i].p_type == PT_TLS) {
            if (!afw_load_patch_only) {
                fprintf(stderr, "error: thread-local storage (PT_TLS) not supported yet\n");
                free(file); return -1;
            }
            fprintf(stderr, "note: PT_TLS present (ignored in measurement mode)\n");
        }
    }
    if (lo == UINT64_MAX || !dyn_ph) {
        fprintf(stderr, "error: no loadable segments or no dynamic section\n");
        free(file); return -1;
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
            case DT_RELR: relr = (const uint64_t *)(uintptr_t)ptr; break;
            case DT_RELRSZ: relrsz = d->d_val; break;
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
            case DT_ANDROID_RELA:
                if (afw_load_patch_only) { skip_relocs = 1; break; }
                fprintf(stderr, "error: Android packed relocations (APS2) not supported yet.\n"
                                "       Rebuild with -Wl,--pack-dyn-relocs=none\n");
                free(pageprot); return -1;
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

    if (g_nlibs < MAX_LIBS) g_libs[g_nlibs++] = lib;

    /* 4. Resolve symbols against bionic-win -------------------------- */
    symaddr = (uint64_t *)calloc(lib->nsyms ? lib->nsyms : 1, sizeof(uint64_t));
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
            if (shim) {
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
        relr = NULL; rela = NULL; jmprel = NULL;
    }
    if (relr) apply_relr(lib, relr, relrsz / 8);
    if (rela && apply_rela(lib, rela, relasz / sizeof(Elf64_Rela), symaddr) != 0) {
        free(symaddr); free(pageprot); return -1;
    }
    if (jmprel && apply_rela(lib, jmprel, pltrelsz / sizeof(Elf64_Rela), symaddr) != 0) {
        free(symaddr); free(pageprot); return -1;
    }
    free(symaddr);

    /* 5b. Load-time patching of syscall / fs: instructions ------------ */
    {
        /* Decode only real functions (from .eh_frame), never the data that
         * shares the executable segment: decoded data could look like an
         * fs: access or a syscall and be "patched" into garbage. Fallback,
         * when there is no .eh_frame_hdr: whole executable segments, where
         * patch.c still requires known function bounds before changing bytes. */
        afw_code_range *cr, segs[8];
        int nsegs = 0, have_funcs;
        unsigned char **fstart;
        size_t *fsize;
        int ncr = afw_func_list(lib, &fstart, &fsize), k;
        have_funcs = ncr > 0;
        if (ncr > 0) {
            cr = (afw_code_range *)malloc((size_t)ncr * sizeof *cr);
            for (k = 0; k < ncr; k++) { cr[k].addr = fstart[k]; cr[k].size = fsize[k]; }
        } else {
            cr = (afw_code_range *)malloc(8 * sizeof *cr);
            for (i = 0; i < npages && ncr < 8;) {
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
            for (k = 0; k < lib->nxsec && k < 8; k++) {
                segs[k].addr = (unsigned char *)(lib->bias + lib->xsec_vaddr[k]);
                segs[k].size = (size_t)lib->xsec_size[k];
            }
            nsegs = k;
        } else {
            int nseg = 0;
            for (i = 0; i < npages && nseg < 8;) {
                size_t j = i;
                if (!(pageprot[i] & PF_X)) { i++; continue; }
                while (j < npages && (pageprot[j] & PF_X)) j++;
                segs[nseg].addr = lib->base + i * AFW_PAGE_SIZE;
                segs[nseg].size = (j - i) * AFW_PAGE_SIZE;
                nseg++;
                i = j;
            }
            nsegs = nseg;
        }
        if (verbose) printf("Code:       %d %s decoded\n", ncr, lib->eh_frame_hdr ? "functions (.eh_frame)" : "segments (no .eh_frame_hdr)");
        afw_patch_ctx pc;
        pc.bounds = patch_bounds; pc.ctx = lib; pc.bias = lib->bias; pc.name = lib->soname ? lib->soname : path;
        pc.ranges_are_functions = have_funcs; pc.segs = segs; pc.nsegs = nsegs;
        pc.entries = patch_entries;
        if (afw_patch_code(cr, ncr, lib->stub_area, AFW_STUB_RESERVE, &pc, &lib->patch, verbose) < 0) {
            fprintf(stderr, "error: could not patch %s safely; refusing to run it\n", path);
            free(cr); free(pageprot); return -1;
        }
        free(cr);
        afw_mem_protect(lib->stub_area, AFW_STUB_RESERVE, AFW_PROT_R | AFW_PROT_X);
        afw_flush_icache(lib->stub_area, AFW_STUB_RESERVE);
        if (verbose)
            printf("Patched:    syscalls %d + %d moved (%d stubs), refused %d; fs: %d; fs:[reg] %d real, %d data\n",
                   lib->patch.sys_patched, lib->patch.sys_patched_moved, lib->patch.stubs,
                   lib->patch.sys_refused_branch + lib->patch.sys_refused_redzone + lib->patch.sys_refused_unknown,
                   lib->patch.fs_patched, lib->patch.fs_reg_in_func, lib->patch.fs_reg_outside);
    }

    /* 6. Memory protection ------------------------------------------- */
    if (relro_ph) {
        size_t p;
        size_t first = (size_t)((ALIGN_DOWN(relro_ph->p_vaddr, AFW_PAGE_SIZE) - lo) / AFW_PAGE_SIZE);
        size_t last = (size_t)((ALIGN_DOWN(relro_ph->p_vaddr + relro_ph->p_memsz, AFW_PAGE_SIZE) - lo) / AFW_PAGE_SIZE);
        for (p = first; p < last && p < npages; p++) pageprot[p] &= (unsigned char)~PF_W;
    }
    for (i = 0; i < npages;) {
        size_t j = i;
        while (j < npages && pageprot[j] == pageprot[i]) j++;
        afw_mem_protect(lib->base + i * AFW_PAGE_SIZE, (j - i) * AFW_PAGE_SIZE, pageprot[i]);
        i = j;
    }
    free(pageprot);
    afw_flush_icache(lib->base, lib->size);

    if (afw_load_patch_only) return 0;

    /* 7. Constructors ------------------------------------------------ */
    if (verbose) printf("Running %zu constructor(s)...\n",
                        lib->init_array_count + (lib->init ? 1 : 0));
    if (lib->init) ((init_fn)(uintptr_t)lib->init)();
    for (i = 0; i < lib->init_array_count; i++) {
        uint64_t f = lib->init_array[i];
        if (f != 0 && f != UINT64_MAX) ((init_fn)(uintptr_t)f)();
    }
    return 0;
}

void *afw_sym(const afw_lib *lib, const char *name) {
    size_t i;
    for (i = 1; i < lib->nsyms; i++) {
        const Elf64_Sym *s = &lib->symtab[i];
        if (s->st_shndx != SHN_UNDEF && ELF64_ST_BIND(s->st_info) != STB_LOCAL &&
            strcmp(lib->strtab + s->st_name, name) == 0)
            return (void *)(lib->bias + s->st_value);
    }
    return NULL;
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
