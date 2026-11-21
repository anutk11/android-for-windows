/*
 * patch.c - Load-time rewriting of syscall and fs: instructions, with Zydis.
 */
#include "patch.h"
#include "syscall.h"
#include "tls_patch.h"

#include <Zydis.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *mov;   /* start of "mov eax, imm32" (5 bytes) */
    uint32_t nr;
} site;

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

/* Is any branch target strictly inside (lo, hi)? targets[] is sorted. */
static int target_inside(const uint64_t *t, size_t n, uint64_t lo, uint64_t hi) {
    size_t a = 0, b = n;
    while (a < b) { size_t m = (a + b) / 2; if (t[m] <= lo) a = m + 1; else b = m; }
    return a < n && t[a] < hi;
}

static int is_block_end(const ZydisDecodedInstruction *ins) {
    return ins->meta.category == ZYDIS_CATEGORY_RET ||
           ins->meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
           ins->mnemonic == ZYDIS_MNEMONIC_INT3 || ins->mnemonic == ZYDIS_MNEMONIC_UD2 ||
           ins->mnemonic == ZYDIS_MNEMONIC_HLT;
}

static int touches_red_zone(const ZydisDecodedInstruction *ins, const ZydisDecodedOperand *ops) {
    int i;
    for (i = 0; i < ins->operand_count_visible; i++)
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base == ZYDIS_REGISTER_RSP &&
            ops[i].mem.disp.value < 0)
            return 1;
    return 0;
}

/*
 * The red-zone check covers the straight-line region around the site: from
 * the previous block end (ret, jmp, int3, ud2) to the next one. Bionic's
 * syscall wrappers are a single such region. Documented as an assumption in
 * syscall.h.
 */
static int region_uses_red_zone(ZydisDecoder *dec, const afw_code_range *r, unsigned char *site_at,
                                const uint64_t *ends, size_t nends) {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    unsigned char *p = r->addr, *end = r->addr + r->size;
    size_t a = 0, b = nends;
    /* start = last block end before the site */
    while (a < b) { size_t m = (a + b) / 2; if (ends[m] <= (uint64_t)(uintptr_t)site_at) a = m + 1; else b = m; }
    if (a > 0) p = (unsigned char *)(uintptr_t)ends[a - 1];
    if (p < r->addr) p = r->addr;
    while (p < end) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, p, (ZyanUSize)(end - p), &ins, ops))) { p++; continue; }
        if (touches_red_zone(&ins, ops)) return 1;
        if (p > site_at && is_block_end(&ins)) break;
        p += ins.length;
    }
    return 0;
}

int afw_patch_code(const afw_code_range *ranges, int nranges,
                   unsigned char *stub_area, size_t stub_size,
                   afw_patch_report *rep, int verbose) {
    ZydisDecoder dec;
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    uint64_t *targets = NULL, *ends = NULL;
    size_t ntargets = 0, captargets = 0, nends = 0, capends = 0;
    site *sites = NULL;
    size_t nsites = 0, capsites = 0, i;
    unsigned char *stub_for[AFW_MAX_SYSCALL] = {0};
    size_t stub_used = 0;
    int r;

    memset(rep, 0, sizeof *rep);
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    /* Pass 1: decode everything; collect branch targets, block ends, sites;
     * rewrite fs: accesses directly (same length, no neighbours touched). */
    for (r = 0; r < nranges; r++) {
        unsigned char *p = ranges[r].addr, *end = p + ranges[r].size;
        unsigned char *prev = NULL;
        int prev_mov_eax = 0;
        uint32_t prev_imm = 0;
        while (p < end) {
            uint64_t ip = (uint64_t)(uintptr_t)p;
            int k;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, (ZyanUSize)(end - p), &ins, ops))) {
                p++; prev_mov_eax = 0;
                continue;
            }
            /* direct branch targets */
            if (ins.meta.category == ZYDIS_CATEGORY_COND_BR || ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                ins.meta.category == ZYDIS_CATEGORY_CALL) {
                for (k = 0; k < ins.operand_count_visible; k++) {
                    ZyanU64 t;
                    if (ops[k].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[k].imm.is_relative &&
                        ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[k], ip, &t))) {
                        if (ntargets == captargets) {
                            captargets = captargets ? captargets * 2 : 4096;
                            targets = (uint64_t *)realloc(targets, captargets * sizeof *targets);
                        }
                        targets[ntargets++] = t;
                    }
                }
            }
            if (is_block_end(&ins)) {
                if (nends == capends) {
                    capends = capends ? capends * 2 : 4096;
                    ends = (uint64_t *)realloc(ends, capends * sizeof *ends);
                }
                ends[nends++] = ip + ins.length;
            }
            /* fs: memory operands */
            for (k = 0; k < ins.operand_count_visible; k++) {
                if (ops[k].type != ZYDIS_OPERAND_TYPE_MEMORY || ops[k].mem.segment != ZYDIS_REGISTER_FS)
                    continue;
                if (ops[k].mem.base != ZYDIS_REGISTER_NONE || ops[k].mem.index != ZYDIS_REGISTER_NONE) {
                    rep->fs_register_form++;
                    continue;
                }
#if defined(_WIN32)
                {
                    int64_t d = ops[k].mem.disp.value;
                    int teb = (d >= 0 && (d & 7) == 0) ? afw_tls_teb_offset((int)(d / 8)) : -1;
                    int j;
                    if (teb < 0 || ins.raw.disp.size != 32) continue; /* left to the fault handler */
                    for (j = 0; j < ins.raw.prefix_count; j++)
                        if (p[j] == 0x64) { p[j] = 0x65; break; }   /* fs: -> gs: */
                    memcpy(p + ins.raw.disp.offset, &teb, 4);
                    rep->fs_patched++;
                }
#endif
            }
            if (ins.mnemonic == ZYDIS_MNEMONIC_SYSCALL) {
                if (prev_mov_eax && prev + 5 == p) {
                    if (nsites == capsites) {
                        capsites = capsites ? capsites * 2 : 256;
                        sites = (site *)realloc(sites, capsites * sizeof *sites);
                    }
                    sites[nsites].mov = prev;
                    sites[nsites].nr = prev_imm;
                    nsites++;
                } else {
                    rep->sys_unhandled++;
                    if (verbose) printf("  [patch] syscall without adjacent mov eax at %p (left as is)\n", (void *)p);
                }
            }
            prev_mov_eax = ins.mnemonic == ZYDIS_MNEMONIC_MOV && ins.length == 5 &&
                           ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_EAX &&
                           ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
            prev_imm = (uint32_t)ops[1].imm.value.u;
            prev = p;
            p += ins.length;
        }
    }
    if (targets) qsort(targets, ntargets, sizeof *targets, cmp_u64);
    if (ends) qsort(ends, nends, sizeof *ends, cmp_u64);

    /* Pass 2: rewrite syscall sites that are safe */
    for (i = 0; i < nsites; i++) {
        unsigned char *m = sites[i].mov, *stub;
        uint64_t lo = (uint64_t)(uintptr_t)m;
        const afw_code_range *rg = NULL;
        int64_t rel;
        uint32_t nr = sites[i].nr;
        for (r = 0; r < nranges; r++)
            if (m >= ranges[r].addr && m < ranges[r].addr + ranges[r].size) rg = &ranges[r];

        if (target_inside(targets, ntargets, lo, lo + 7)) {
            rep->sys_refused_branch++;
            fprintf(stderr, "  [patch] REFUSED syscall %u at %p: a branch lands inside the site\n", nr, (void *)m);
            continue;
        }
        if (rg && region_uses_red_zone(&dec, rg, m + 5, ends, nends)) {
            rep->sys_refused_redzone++;
            fprintf(stderr, "  [patch] REFUSED syscall %u at %p: code around it uses the red zone\n", nr, (void *)m);
            continue;
        }
        if (nr >= AFW_MAX_SYSCALL) { rep->sys_unhandled++; continue; }

        stub = stub_for[nr];
        if (!stub) {
            uint64_t entry = (uint64_t)(uintptr_t)afw_syscall_entry;
            if (stub_used + 24 > stub_size) { fprintf(stderr, "  [patch] stub area full\n"); break; }
            stub = stub_area + stub_used;
            stub[0] = 0xB8; memcpy(stub + 1, &nr, 4);               /* mov eax, nr */
            stub[5] = 0xFF; stub[6] = 0x25; memset(stub + 7, 0, 4); /* jmp [rip+0] */
            memcpy(stub + 11, &entry, 8);
            stub_used += 24;
            stub_for[nr] = stub;
            rep->stubs++;
        }
        rel = (int64_t)(stub - (m + 5));
        if (rel > INT32_MAX || rel < INT32_MIN) { fprintf(stderr, "  [patch] stub out of range\n"); continue; }
        {
            int32_t rel32 = (int32_t)rel;
            m[0] = 0xE8; memcpy(m + 1, &rel32, 4);   /* call stub_nr */
            m[5] = 0x66; m[6] = 0x90;                 /* 2-byte nop */
        }
        rep->sys_patched++;
    }

    free(targets); free(ends); free(sites);
    return (rep->sys_refused_branch || rep->sys_refused_redzone) ? 1 : 0;
}
