/*
 * syscall_scan.c - Gate G1 experiment: static scan of a real bionic libc.so.
 *
 * Disassembles every executable segment with Zydis and reports:
 *   - every `syscall` instruction, with its Linux syscall number (from the
 *     `mov eax, imm` before it) and the function that contains it;
 *   - every fs:-segment memory access, split into the form our TLS patcher
 *     handles (fs:[disp32]) and register-based forms it does not;
 *   - rdfsbase/wrfsbase instructions;
 *   - the library's imports (e.g. __loader_* that linker64 must provide).
 *
 * usage: syscall_scan <lib.so> [symbols.elf]
 *   symbols.elf: optional ELF whose .symtab names hidden functions (bionic
 *   ships one compressed in its .gnu_debugdata section).
 */
#include <Zydis/Zydis.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/elf.h"
#include "syscall_names.h" /* generated: static const char *const g_nr_name[] */

#define SHT_SYMTAB 2
#define SHT_DYNSYM 11



typedef struct { uint64_t addr; uint64_t size; const char *name; } func_sym;

static func_sym *g_funcs;
static size_t g_nfuncs, g_capfuncs;

static unsigned char *read_all(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long sz;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    b = (unsigned char *)malloc((size_t)sz);
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) { free(b); b = NULL; }
    fclose(f);
    *n = (size_t)sz;
    return b;
}

static void add_func(uint64_t addr, uint64_t size, const char *name) {
    if (!name[0] || addr == 0) return;
    if (g_nfuncs == g_capfuncs) {
        g_capfuncs = g_capfuncs ? g_capfuncs * 2 : 4096;
        g_funcs = (func_sym *)realloc(g_funcs, g_capfuncs * sizeof(func_sym));
    }
    g_funcs[g_nfuncs].addr = addr;
    g_funcs[g_nfuncs].name = name;
    g_funcs[g_nfuncs].size = size;
    g_nfuncs++;
}

/* Collect STT_FUNC symbols from .symtab and .dynsym sections of a file. */
static void load_symbols(const unsigned char *f, size_t n) {
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)f;
    const Elf64_Shdr *sh;
    int i;
    if (n < sizeof *eh || memcmp(f, "\x7f" "ELF", 4) || !eh->e_shoff) return;
    sh = (const Elf64_Shdr *)(f + eh->e_shoff);
    for (i = 0; i < eh->e_shnum; i++) {
        size_t k, cnt;
        const Elf64_Sym *syms;
        const char *str;
        if (sh[i].sh_type != SHT_SYMTAB && sh[i].sh_type != SHT_DYNSYM) continue;
        syms = (const Elf64_Sym *)(f + sh[i].sh_offset);
        str = (const char *)(f + sh[sh[i].sh_link].sh_offset);
        cnt = sh[i].sh_size / sizeof(Elf64_Sym);
        for (k = 1; k < cnt; k++)
            if (ELF64_ST_TYPE(syms[k].st_info) == STT_FUNC && syms[k].st_shndx != SHN_UNDEF)
                add_func(syms[k].st_value, syms[k].st_size, str + syms[k].st_name);
    }
}

static int cmp_func(const void *a, const void *b) {
    uint64_t x = ((const func_sym *)a)->addr, y = ((const func_sym *)b)->addr;
    return x < y ? -1 : x > y;
}

static const char *func_at(uint64_t addr) {
    size_t lo = 0, hi = g_nfuncs;
    if (!g_nfuncs || addr < g_funcs[0].addr) return "?";
    while (hi - lo > 1) {
        size_t mid = (lo + hi) / 2;
        if (g_funcs[mid].addr <= addr) lo = mid; else hi = mid;
    }
    return g_funcs[lo].name;
}

/* Is addr inside a sized function symbol? */
static int in_func(uint64_t addr) {
    size_t lo = 0, hi = g_nfuncs, i;
    if (!g_nfuncs || addr < g_funcs[0].addr) return 0;
    while (hi - lo > 1) { size_t m = (lo + hi) / 2; if (g_funcs[m].addr <= addr) lo = m; else hi = m; }
    for (i = lo + 1; i-- > 0 && lo - i < 4;)   /* aliases share an address */
        if (g_funcs[i].addr <= addr && addr < g_funcs[i].addr + g_funcs[i].size) return 1;
    return 0;
}
static int g_fs_abs_in, g_sites_in, g_fs_reg_in;

static uint64_t func_end(uint64_t addr) {
    size_t i;
    for (i = 0; i < g_nfuncs; i++)
        if (g_funcs[i].addr > addr) return g_funcs[i].addr;
    return addr + 256;
}

/* ---- results ---- */
#define MAX_NR 1024
static int g_nr_count[MAX_NR];
static const char *g_nr_example[MAX_NR];
static int g_sites, g_unresolved, g_fail;
static int g_pattern7;        /* "mov eax, imm32 ; syscall" adjacent = 7 bytes */
static int g_redzone_sites;   /* syscall site in a function that uses [rsp-N] */
static uint64_t *g_targets; static size_t g_ntargets, g_captargets;
static uint64_t g_site_mov[4096]; static size_t g_nsite_mov;
static const unsigned char *g_code_base; static uint64_t g_code_vaddr; static size_t g_code_size;
static int g_fs_abs, g_fs_reg, g_fsbase_ins;
static int g_fs_disp_count[64];      /* fs:[8*i], i < 64 */
static int g_fs_disp_other;

static const char *nr_name(int nr) {
    if (nr >= 0 && nr < (int)(sizeof g_nr_name / sizeof g_nr_name[0]) && g_nr_name[nr])
        return g_nr_name[nr];
    return "?";
}

static int writes_eax(const ZydisDecodedInstruction *ins, const ZydisDecodedOperand *ops) {
    int i;
    for (i = 0; i < ins->operand_count; i++) {
        if (ops[i].type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
        if (!(ops[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) continue;
        switch (ops[i].reg.value) {
        case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_AL: return 1;
        default: break;
        }
    }
    return 0;
}

/* Does the function containing ip touch memory below rsp ([rsp - N])? */
static int uses_red_zone(uint64_t ip) {
    ZydisDecoder dec;
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    uint64_t a = 0, e = func_end(ip);
    size_t lo = 0, hi = g_nfuncs;
    while (hi - lo > 1) { size_t m = (lo + hi) / 2; if (g_funcs[m].addr <= ip) lo = m; else hi = m; }
    if (g_nfuncs) a = g_funcs[lo].addr;
    if (a < g_code_vaddr || e > g_code_vaddr + g_code_size || e - a > 65536) return -1;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    while (a < e) {
        int i;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, g_code_base + (a - g_code_vaddr), e - a, &ins, ops))) { a++; continue; }
        for (i = 0; i < ins.operand_count_visible; i++)
            if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base == ZYDIS_REGISTER_RSP &&
                ops[i].mem.disp.value < 0) return 1;
        a += ins.length;
    }
    return 0;
}

static void scan(const unsigned char *code, size_t size, uint64_t vaddr, int verbose) {
    ZydisDecoder dec;
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    size_t off = 0;
    int64_t eax = -1; /* last known immediate in eax, -1 = unknown */
    uint64_t prev_end = 0; int prev_mov_eax = 0;
    g_code_base = code; g_code_vaddr = vaddr; g_code_size = size;
    const char *eax_func = NULL;

    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    while (off < size) {
        uint64_t ip = vaddr + off;
        int i;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, size - off, &ins, ops))) {
            off++; eax = -1; prev_mov_eax = 0;
            continue;
        }
        /* direct branch targets, to check no branch lands inside a site */
        if (ins.meta.category == ZYDIS_CATEGORY_COND_BR || ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            ins.meta.category == ZYDIS_CATEGORY_CALL) {
            for (i = 0; i < ins.operand_count_visible; i++) {
                ZyanU64 t;
                if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative &&
                    ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[i], ip, &t))) {
                    if (g_ntargets == g_captargets) {
                        g_captargets = g_captargets ? g_captargets * 2 : 65536;
                        g_targets = (uint64_t *)realloc(g_targets, g_captargets * sizeof(uint64_t));
                    }
                    g_targets[g_ntargets++] = t;
                }
            }
        }
        /* fs: memory operands */
        for (i = 0; i < ins.operand_count_visible; i++) {
            if (ops[i].type != ZYDIS_OPERAND_TYPE_MEMORY || ops[i].mem.segment != ZYDIS_REGISTER_FS)
                continue;
            if (ops[i].mem.base == ZYDIS_REGISTER_NONE && ops[i].mem.index == ZYDIS_REGISTER_NONE) {
                int64_t d = ops[i].mem.disp.value;
                g_fs_abs++;
                if (in_func(ip)) g_fs_abs_in++;
                if (d >= 0 && d < 8 * 64 && (d & 7) == 0) g_fs_disp_count[d / 8]++;
                else g_fs_disp_other++;
            } else {
                g_fs_reg++;
                if (in_func(ip)) g_fs_reg_in++;
                if (verbose) printf("  fs: register form at 0x%llx in %s\n",
                                    (unsigned long long)ip, func_at(ip));
            }
        }
        if (ins.mnemonic == ZYDIS_MNEMONIC_RDFSBASE || ins.mnemonic == ZYDIS_MNEMONIC_WRFSBASE) {
            g_fsbase_ins++;
            printf("  %s at 0x%llx in %s\n", ins.mnemonic == ZYDIS_MNEMONIC_RDFSBASE ?
                   "rdfsbase" : "wrfsbase", (unsigned long long)ip, func_at(ip));
        }

        if (ins.mnemonic == ZYDIS_MNEMONIC_SYSCALL) {
            const char *fn = func_at(ip);
            int rz = uses_red_zone(ip);
            g_sites++;
            if (in_func(ip)) g_sites_in++;
            if (prev_mov_eax && prev_end == ip) {
                g_pattern7++;
                if (g_nsite_mov < 4096) g_site_mov[g_nsite_mov++] = ip - 5;
            }
            else printf("  not the 7-byte pattern: syscall at 0x%llx in %s\n", (unsigned long long)ip, fn);
            if (rz == 1) { g_redzone_sites++; printf("  RED ZONE: syscall at 0x%llx in %s uses [rsp-N]\n", (unsigned long long)ip, fn); }
            if (eax >= 0 && eax < MAX_NR && eax_func == fn) {
                g_nr_count[eax]++;
                if (!g_nr_example[eax]) g_nr_example[eax] = fn;
            } else {
                g_unresolved++;
                printf("  syscall with unknown number at 0x%llx in %s\n",
                       (unsigned long long)ip, fn);
            }
            eax = -1;
        } else if (ins.mnemonic == ZYDIS_MNEMONIC_MOV && ins.operand_count_visible == 2 &&
                   ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   (ops[0].reg.value == ZYDIS_REGISTER_EAX || ops[0].reg.value == ZYDIS_REGISTER_RAX) &&
                   ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            eax = (int64_t)ops[1].imm.value.u;
            eax_func = func_at(ip);
        } else if (ins.meta.category == ZYDIS_CATEGORY_RET ||
                   ins.meta.category == ZYDIS_CATEGORY_CALL ||
                   ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                   writes_eax(&ins, ops)) {
            eax = -1;
        }
        prev_mov_eax = (ins.mnemonic == ZYDIS_MNEMONIC_MOV && ins.length == 5 &&
                        ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_EAX &&
                        ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE);
        prev_end = ip + ins.length;
        off += ins.length;
    }
}

int main(int argc, char **argv) {
    size_t n, symn = 0, i;
    unsigned char *f, *symf = NULL;
    const Elf64_Ehdr *eh;
    const Elf64_Phdr *ph;
    int nr, distinct = 0;

    if (argc < 2) { fprintf(stderr, "usage: %s <lib.so> [symbols.elf]\n", argv[0]); return 2; }
    f = read_all(argv[1], &n);
    if (!f) { fprintf(stderr, "cannot read %s\n", argv[1]); return 1; }
    eh = (const Elf64_Ehdr *)f;
    if (memcmp(f, "\x7f" "ELF", 4) || eh->e_machine != EM_X86_64) {
        fprintf(stderr, "not an x86_64 ELF\n"); return 1;
    }
    load_symbols(f, n);
    if (argc > 2 && (symf = read_all(argv[2], &symn)) != NULL) load_symbols(symf, symn);
    qsort(g_funcs, g_nfuncs, sizeof(func_sym), cmp_func);

    printf("=== %s ===\n", argv[1]);
    printf("function symbols known: %zu%s\n", g_nfuncs,
           symf ? " (including .gnu_debugdata)" : "");

    /* Dynamic section: NEEDED and imports */
    ph = (const Elf64_Phdr *)(f + eh->e_phoff);
    for (i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            /* Needs section-based lookup for strtab offset; use section headers */
            break;
        }
    }
    {
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(f + eh->e_shoff);
        int s;
        for (s = 0; eh->e_shoff && s < eh->e_shnum; s++) {
            if (sh[s].sh_type == SHT_DYNSYM) {
                const Elf64_Sym *syms = (const Elf64_Sym *)(f + sh[s].sh_offset);
                const char *str = (const char *)(f + sh[sh[s].sh_link].sh_offset);
                size_t k, cnt = sh[s].sh_size / sizeof(Elf64_Sym), nimp = 0, nexp = 0;
                printf("imports:");
                for (k = 1; k < cnt; k++) {
                    if (syms[k].st_shndx == SHN_UNDEF) {
                        nimp++;
                        printf(" %s", str + syms[k].st_name);
                    } else nexp++;
                }
                printf("\nimported: %zu, exported: %zu\n", nimp, nexp);
            }
            if (sh[s].sh_type == 6 /* SHT_DYNAMIC */) {
                const Elf64_Dyn *d = (const Elf64_Dyn *)(f + sh[s].sh_offset);
                const char *str = (const char *)(f + sh[sh[s].sh_link].sh_offset);
                printf("needed:");
                for (; d->d_tag != DT_NULL; d++)
                    if (d->d_tag == DT_NEEDED) printf(" %s", str + d->d_val);
                printf("\n");
            }
        }
    }
    /* vDSO use: bionic looks up these names in the vDSO image */
    {
        static const char *vdso[] = {"__vdso_clock_gettime", "__vdso_gettimeofday",
                                     "__vdso_time", "__vdso_getcpu", "__vdso_clock_getres"};
        size_t v;
        printf("vDSO names referenced:");
        for (v = 0; v < sizeof vdso / sizeof vdso[0]; v++) {
            size_t L = strlen(vdso[v]), k;
            for (k = 0; k + L <= n; k++)
                if (memcmp(f + k, vdso[v], L) == 0) { printf(" %s", vdso[v] + 7); break; }
        }
        printf("\n\n");
    }

    /* Build ID (PT_NOTE, NT_GNU_BUILD_ID) */
    for (i = 0; i < eh->e_phnum; i++) {
        size_t o, end;
        if (ph[i].p_type != 4 /* PT_NOTE */) continue;
        o = ph[i].p_offset; end = o + ph[i].p_filesz;
        while (o + 12 <= end) {
            uint32_t nsz, dsz, type, k;
            memcpy(&nsz, f + o, 4); memcpy(&dsz, f + o + 4, 4); memcpy(&type, f + o + 8, 4);
            if (type == 3 && nsz == 4 && memcmp(f + o + 12, "GNU", 4) == 0) {
                printf("build id: ");
                for (k = 0; k < dsz; k++) printf("%02x", f[o + 12 + 4 + k]);
                printf("\n");
            }
            o += 12 + ((nsz + 3) & ~3u) + ((dsz + 3) & ~3u);
        }
    }
    /* GWP-ASan controls: environment variables / properties named in the binary */
    {
        size_t k;
        printf("GWP-ASan control strings:");
        for (k = 0; k + 8 < n; k++) {
            if ((memcmp(f + k, "GWP_ASAN", 8) == 0 || memcmp(f + k, "gwp_asan.", 9) == 0) &&
                (k == 0 || f[k - 1] == 0 || f[k - 1] == '.')) {
                size_t st = k;
                while (st > 0 && f[st - 1] >= 0x20 && f[st - 1] < 0x7f) st--;
                printf(" \"%s\"", (const char *)f + st);
                k += strlen((const char *)f + k);
            }
        }
        printf("\n");
    }

    for (i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X))
            scan(f + ph[i].p_offset, ph[i].p_filesz, ph[i].p_vaddr, 1);

    for (nr = 0; nr < MAX_NR; nr++) if (g_nr_count[nr]) distinct++;
    printf("\nsyscall instructions: %d  (number resolved: %d, unknown: %d)\n",
           g_sites, g_sites - g_unresolved, g_unresolved);
    printf("distinct Linux syscalls: %d\n", distinct);
    printf("sites with the 7-byte \"mov eax, imm32; syscall\" pattern: %d of %d\n", g_pattern7, g_sites);
    printf("sites inside functions that use the red zone: %d\n", g_redzone_sites);
    {
        size_t a, b;
        int bad = 0;
        for (a = 0; a < g_nsite_mov; a++)
            for (b = 0; b < g_ntargets; b++)
                if (g_targets[b] > g_site_mov[a] && g_targets[b] < g_site_mov[a] + 7) {
                    printf("  BRANCH INTO SITE: target 0x%llx inside site at 0x%llx (%s)\n",
                           (unsigned long long)g_targets[b], (unsigned long long)g_site_mov[a],
                           func_at(g_site_mov[a]));
                    bad++;
                }
        printf("branches landing inside a 7-byte site: %d (checked %zu branch targets)\n\n", bad, g_ntargets);
        if (bad || g_redzone_sites) g_fail = 1;
    }
    printf("  nr  name                     sites  example function\n");
    for (nr = 0; nr < MAX_NR; nr++)
        if (g_nr_count[nr])
            printf("%4d  %-24s %5d  %s\n", nr, nr_name(nr), g_nr_count[nr], g_nr_example[nr]);

    printf("\nfs: accesses: %d absolute fs:[disp32] (patchable), %d register-based\n",
           g_fs_abs, g_fs_reg);
    printf("inside sized function symbols: syscall %d of %d, fs:[disp32] %d of %d, fs:[reg] %d of %d\n",
           g_sites_in, g_sites, g_fs_abs_in, g_fs_abs, g_fs_reg_in, g_fs_reg);
    for (i = 0; i < 64; i++)
        if (g_fs_disp_count[i])
            printf("  fs:[0x%02zx] (slot %zu): %d\n", i * 8, i, g_fs_disp_count[i]);
    if (g_fs_disp_other) printf("  other displacements: %d\n", g_fs_disp_other);
    printf("rdfsbase/wrfsbase instructions: %d\n", g_fsbase_ins);
    if (g_fail) printf("\nSCAN FAILED: some syscall sites are unsafe to patch\n");
    return g_fail;
}
