/*
 * patch.c - Load-time rewriting of syscall and fs: instructions, with Zydis.
 * See patch.h for the rules.
 */
#include "patch.h"
#include "syscall.h"
#include "tls_patch.h"

#include <Zydis.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *start;  /* first byte replaced */
    int len;               /* bytes replaced (>= 5), ends right after `syscall` */
    int form;              /* 'A' or 'B' */
    uint32_t nr;           /* form A */
} site;

typedef struct { unsigned char *p; int len; int movable; } hist;

#define VEC_PUSH(arr, n, cap, val) do { \
    if ((n) == (cap)) { (cap) = (cap) ? (cap) * 2 : 1024; (arr) = realloc((arr), (cap) * sizeof *(arr)); } \
    (arr)[(n)++] = (val); } while (0)

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

/* Is any branch target strictly inside (lo, hi)? t[] is sorted. */
static int target_inside(const uint64_t *t, size_t n, uint64_t lo, uint64_t hi) {
    size_t a = 0, b = n;
    while (a < b) { size_t m = (a + b) / 2; if (t[m] <= lo) a = m + 1; else b = m; }
    return a < n && t[a] < hi;
}

static int is_branch(const ZydisDecodedInstruction *ins) {
    return ins->meta.category == ZYDIS_CATEGORY_RET || ins->meta.category == ZYDIS_CATEGORY_CALL ||
           ins->meta.category == ZYDIS_CATEGORY_COND_BR || ins->meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
           ins->meta.category == ZYDIS_CATEGORY_SYSCALL;
}

static int uses_r11(const ZydisDecodedInstruction *ins, const ZydisDecodedOperand *ops) {
    int i;
    for (i = 0; i < ins->operand_count; i++) {
        ZydisRegister r = ZYDIS_REGISTER_NONE;
        if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER) r = ops[i].reg.value;
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            (ops[i].mem.base == ZYDIS_REGISTER_R11 || ops[i].mem.index == ZYDIS_REGISTER_R11))
            return 1;
        if (r == ZYDIS_REGISTER_R11 || r == ZYDIS_REGISTER_R11D || r == ZYDIS_REGISTER_R11W ||
            r == ZYDIS_REGISTER_R11B)
            return 1;
    }
    return 0;
}

static ZydisRegister reg64(ZydisRegister r) {
    return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r);
}

/*
 * Whole-function red zone check. Returns 1 if anything in [s, e) may touch
 * memory below rsp: [rsp - N], or [reg - N] where reg received a copy of rsp
 * (mov reg, rsp / lea reg, [rsp + ...]). Conservative on purpose.
 */
static int function_uses_red_zone(ZydisDecoder *dec, uint64_t s, uint64_t e) {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisRegister copies[16];
    int64_t max_sub = 0;
    int ncopies = 0, pass;
    for (pass = 0; pass < 2; pass++) {
        uint64_t a = s;
        while (a < e) {
            const unsigned char *p = (const unsigned char *)(uintptr_t)a;
            int i, k;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, p, (ZyanUSize)(e - a), &ins, ops))) { a++; continue; }
            if (pass == 0) {
                /* collect registers that receive a copy of rsp */
                if (ins.operand_count_visible >= 2 && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    reg64(ops[0].reg.value) != ZYDIS_REGISTER_RSP &&
                    ((ins.mnemonic == ZYDIS_MNEMONIC_MOV && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                      ops[1].reg.value == ZYDIS_REGISTER_RSP) ||
                     (ins.mnemonic == ZYDIS_MNEMONIC_LEA && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                      ops[1].mem.base == ZYDIS_REGISTER_RSP)) && ncopies < 16)
                    copies[ncopies++] = reg64(ops[0].reg.value);
                /* frame allocation: sub rsp, imm */
                if (ins.mnemonic == ZYDIS_MNEMONIC_SUB && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ops[0].reg.value == ZYDIS_REGISTER_RSP && ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    (int64_t)ops[1].imm.value.s > max_sub)
                    max_sub = (int64_t)ops[1].imm.value.s;
            } else {
                for (i = 0; i < ins.operand_count_visible; i++) {
                    if (ops[i].type != ZYDIS_OPERAND_TYPE_MEMORY || ops[i].mem.disp.value >= 0) continue;
                    if (ops[i].mem.base == ZYDIS_REGISTER_RSP) return 1;
                    for (k = 0; k < ncopies; k++)
                        if (ops[i].mem.base == copies[k] && -ops[i].mem.disp.value > max_sub) return 2;
                }
            }
            a += ins.length;
        }
    }
    return 0;
}

static void describe(const afw_patch_ctx *c, const unsigned char *p, char *buf, size_t n) {
    snprintf(buf, n, "%s+0x%llx", c->name ? c->name : "lib",
             (unsigned long long)((intptr_t)p - c->bias));
}

/* Print bytes + Zydis decoding of one instruction. */
static void dump_ins(const unsigned char *p, const ZydisDecodedInstruction *ins, const ZydisDecodedOperand *ops) {
    ZydisFormatter f;
    char text[128];
    int i;
    ZydisFormatterInit(&f, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterFormatInstruction(&f, ins, ops, ins->operand_count_visible, text, sizeof text,
                                    (ZyanU64)(uintptr_t)p, ZYAN_NULL);
    fprintf(stderr, "             bytes: [");
    for (i = 0; i < ins->length + 8; i++) fprintf(stderr, i == ins->length ? "] %02x" : (i ? " %02x" : "%02x"), p[i]);
    fprintf(stderr, "\n             decoded: %s\n", text);
}

/*
 * Control-flow reachability inside one function: 1 marks an instruction
 * start that some path from the entry reaches. Direct branches are followed.
 *
 * Switch tables are followed only when the whole chain is PROVEN along the
 * path (registers tracked per path):
 *     cmp  rI, N ; ja default        -> rI < N+1        (bound, also via mov copies)
 *     lea  rT, [rip + table]         -> rT = table
 *     movsxd rX, dword [rT + rI*4]   -> rX = table entry, rI bounded
 *     add  rX, rT                    -> rX = table + entry
 *     jmp  rX
 * and every one of the N+1 entries lands inside the function. Anything less
 * (unknown bound, unrelated registers, an entry outside) makes the function
 * UNDECIDED: bytes no proven path reaches are never decoded or changed.
 */
#define NREG (ZYDIS_REGISTER_MAX_VALUE + 1)
typedef struct {
    uint64_t lea[NREG];      /* rip-relative lea result held by the register */
    uint64_t bound[NREG];    /* register known to be < bound (0 = unknown) */
    uint64_t ent_tab[NREG];  /* register holds an entry of table ent_tab, read via ent_base */
    uint64_t ent_cnt[NREG];
    ZydisRegister ent_base[NREG];
    uint64_t sum_tab[NREG];  /* register = table + entry (proven) */
    uint64_t sum_cnt[NREG];
} flow_state;

static void reg_clear(flow_state *f, ZydisRegister r) {
    f->lea[r] = f->bound[r] = f->ent_tab[r] = f->sum_tab[r] = 0;
}

static unsigned char *reach_map(ZydisDecoder *dec, unsigned char *base, size_t size, int *undecided,
                                const unsigned char **why, const uint64_t *extra, int nextra) {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    unsigned char *map = (unsigned char *)calloc(size ? size : 1, 1);
    size_t *work = NULL, nwork = 0, capwork = 0, off;
    uint64_t lo = (uint64_t)(uintptr_t)base, hi = lo + size;
    flow_state *f = (flow_state *)malloc(sizeof *f);
    *undecided = 0;
    VEC_PUSH(work, nwork, capwork, (size_t)0);
    {
        int e;
        for (e = 0; e < nextra; e++)
            if (extra[e] >= lo && extra[e] < hi) VEC_PUSH(work, nwork, capwork, (size_t)(extra[e] - lo));
    }
    while (nwork) {
        ZydisRegister cmp_reg = ZYDIS_REGISTER_NONE;
        uint64_t cmp_imm = 0;
        off = work[--nwork];
        memset(f, 0, sizeof *f);                  /* register facts hold along one path only */
        while (off < size && map[off] != 1) {
            int k, stop = 0, w;
            uint64_t ip = lo + off;
            ZydisRegister pending_cmp = cmp_reg;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, base + off, (ZyanUSize)(size - off), &ins, ops))) break;
            map[off] = 1;
            cmp_reg = ZYDIS_REGISTER_NONE;

            /* --- facts produced by this instruction --- */
            if (ins.mnemonic == ZYDIS_MNEMONIC_CMP && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                cmp_reg = reg64(ops[0].reg.value);
                cmp_imm = ops[1].imm.value.u;
            } else if (pending_cmp != ZYDIS_REGISTER_NONE &&
                       (ins.mnemonic == ZYDIS_MNEMONIC_JNBE || ins.mnemonic == ZYDIS_MNEMONIC_JNB)) {
                /* fall-through of "ja/jae default": unsigned index < bound */
                f->bound[pending_cmp] = ins.mnemonic == ZYDIS_MNEMONIC_JNBE ? cmp_imm + 1 : cmp_imm;
            }
            {
                /* new values: clear facts of every register this instruction writes,
                 * then record what it proves */
                uint64_t keep_lea = 0, keep_bound = 0, keep_tab = 0, keep_cnt = 0, keep_sum = 0, keep_scnt = 0;
                ZydisRegister keep_base = ZYDIS_REGISTER_NONE, dst = ZYDIS_REGISTER_NONE;
                int recognised = 0;
                if (ins.operand_count_visible >= 2 && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    dst = reg64(ops[0].reg.value);
                    if (ins.mnemonic == ZYDIS_MNEMONIC_LEA && ops[1].mem.base == ZYDIS_REGISTER_RIP &&
                        ops[1].mem.index == ZYDIS_REGISTER_NONE) {
                        keep_lea = ip + ins.length + (uint64_t)ops[1].mem.disp.value; recognised = 1;
                    } else if (ins.mnemonic == ZYDIS_MNEMONIC_MOV && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        ZydisRegister src = reg64(ops[1].reg.value);   /* copies keep the bound */
                        keep_bound = f->bound[src]; keep_lea = f->lea[src]; recognised = 1;
                    } else if (ins.mnemonic == ZYDIS_MNEMONIC_MOVSXD && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                               ops[1].mem.scale == 4 && ops[1].mem.disp.value == 0 &&
                               ops[1].mem.base != ZYDIS_REGISTER_NONE && f->lea[ops[1].mem.base] &&
                               ops[1].mem.index != ZYDIS_REGISTER_NONE && f->bound[reg64(ops[1].mem.index)]) {
                        keep_tab = f->lea[ops[1].mem.base]; keep_cnt = f->bound[reg64(ops[1].mem.index)];
                        keep_base = ops[1].mem.base; recognised = 1;
                    } else if (ins.mnemonic == ZYDIS_MNEMONIC_ADD && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                               f->ent_tab[dst] && reg64(ops[1].reg.value) == f->ent_base[dst] &&
                               f->lea[f->ent_base[dst]] == f->ent_tab[dst]) {
                        keep_sum = f->ent_tab[dst]; keep_scnt = f->ent_cnt[dst]; recognised = 1;
                    }
                }
                for (w = 0; w < ins.operand_count; w++)
                    if (ops[w].type == ZYDIS_OPERAND_TYPE_REGISTER && (ops[w].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                        reg_clear(f, reg64(ops[w].reg.value));
                if (recognised && dst != ZYDIS_REGISTER_NONE) {
                    f->lea[dst] = keep_lea; f->bound[dst] = keep_bound;
                    f->ent_tab[dst] = keep_tab; f->ent_cnt[dst] = keep_cnt; f->ent_base[dst] = keep_base;
                    f->sum_tab[dst] = keep_sum; f->sum_cnt[dst] = keep_scnt;
                }
            }

            /* --- control flow --- */
            if (ins.meta.category == ZYDIS_CATEGORY_COND_BR || ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
                for (k = 0; k < ins.operand_count_visible; k++) {
                    ZyanU64 t;
                    if (ops[k].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[k].imm.is_relative &&
                        ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[k], ip, &t))) {
                        if (t >= lo && t < hi) VEC_PUSH(work, nwork, capwork, (size_t)(t - lo));
                    } else if (ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR &&
                               ops[k].visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
                        if (ops[k].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[k].mem.base == ZYDIS_REGISTER_RIP) {
                            /* jmp [rip+x]: tail call through the GOT, leaves the function */
                        } else if (ops[k].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                   f->sum_tab[reg64(ops[k].reg.value)] &&
                                   f->sum_cnt[reg64(ops[k].reg.value)] <= 4096) {
                            uint64_t tab = f->sum_tab[reg64(ops[k].reg.value)];
                            uint64_t n = f->sum_cnt[reg64(ops[k].reg.value)], e;
                            int bad = 0;
                            for (e = 0; e < n && !bad; e++) {
                                int32_t rel;
                                uint64_t t2;
                                memcpy(&rel, (const void *)(uintptr_t)(tab + 4 * e), 4);
                                t2 = tab + (uint64_t)(int64_t)rel;
                                if (t2 < lo || t2 >= hi) bad = 1;
                            }
                            if (bad) { *undecided = 1; *why = base + off; }
                            else for (e = 0; e < n; e++) {
                                int32_t rel;
                                memcpy(&rel, (const void *)(uintptr_t)(tab + 4 * e), 4);
                                VEC_PUSH(work, nwork, capwork, (size_t)(tab + (uint64_t)(int64_t)rel - lo));
                            }
                        } else {
                            *undecided = 1; *why = base + off;
                        }
                    }
                }
                if (ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR) stop = 1;
            }
            if (ins.meta.category == ZYDIS_CATEGORY_RET || ins.mnemonic == ZYDIS_MNEMONIC_INT3 ||
                ins.mnemonic == ZYDIS_MNEMONIC_UD2 || ins.mnemonic == ZYDIS_MNEMONIC_HLT)
                stop = 1;
            off += ins.length;
            if (stop) break;
        }
    }
    free(f);
    free(work);
    return map;
}

static int has_fs_operand(const ZydisDecodedInstruction *ins, const ZydisDecodedOperand *ops) {
    int k;
    for (k = 0; k < ins->operand_count_visible; k++)
        if (ops[k].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[k].mem.segment == ZYDIS_REGISTER_FS) return 1;
    return 0;
}

int afw_patch_code(const afw_code_range *ranges, int nranges,
                   unsigned char *stub_area, size_t stub_size,
                   const afw_patch_ctx *c, afw_patch_report *rep, int verbose) {
    ZydisDecoder dec;
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    uint64_t *targets = NULL;
    size_t ntargets = 0, captargets = 0;
    site *sites = NULL;
    size_t nsites = 0, capsites = 0, i;
    unsigned char *stub_for[AFW_MAX_SYSCALL] = {0};
    size_t stub_used = 0;
    uint64_t entry = (uint64_t)(uintptr_t)afw_syscall_entry;
    int r, fatal = 0;
    char where[160];
    unsigned char **maps = (unsigned char **)calloc(nranges ? (size_t)nranges : 1, sizeof *maps);
    int *undecided = (int *)calloc(nranges ? (size_t)nranges : 1, sizeof *undecided);

    memset(rep, 0, sizeof *rep);
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    /* Pass 1: decode everything; collect branch targets and syscall sites;
     * rewrite fs:[disp32] directly (same length, neighbours untouched). */
    for (r = 0; r < nranges; r++) {
        unsigned char *p = ranges[r].addr, *end = p + ranges[r].size;
        hist h[3] = {{0}};
        int prev_mov_eax = 0;
        uint32_t prev_imm = 0;
        unsigned char *map = NULL;
        if (c && c->ranges_are_functions) {
            const unsigned char *why = NULL;
            uint64_t pads[1024];
            int npads = c->entries ? c->entries(c->ctx, (uint64_t)(uintptr_t)p, pads, 1024) : 0;
            int lsda_failed = npads < 0;
            if (lsda_failed) {
                /* unsupported format, corrupt table, or more pads than we hold:
                 * we cannot claim to know every entry point */
                rep->lsda_failures++;
                describe(c, p, where, sizeof where);
                fprintf(stderr, "  [flow] function at %s: exception table %s - function UNDECIDED\n", where,
                        npads == -2 ? "has more landing pads than supported" : "could not be decoded");
                npads = 0;
            }
            rep->landing_pads += npads;
            map = maps[r] = reach_map(&dec, p, ranges[r].size, &undecided[r], &why, pads, npads);
            if (lsda_failed && !undecided[r]) { undecided[r] = 1; why = NULL; }
            if (undecided[r]) {
                rep->funcs_undecided++;
                if (verbose && why && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, why, 16, &ins, ops))) {
                    char w2[160];
                    describe(c, p, where, sizeof where);
                    describe(c, why, w2, sizeof w2);
                    fprintf(stderr, "  [flow] function at %s: indirect jump at %s is not a switch table "
                                    "(tail call through a pointer?) - unreached bytes stay untouched\n", where, w2);
                    dump_ins(why, &ins, ops);
                }
            }
        }
        while (p < end) {
            uint64_t ip = (uint64_t)(uintptr_t)p;
            int k, movable;
            if (map && map[p - ranges[r].addr] != 1) {   /* not reachable: never decode as code */
                p++; prev_mov_eax = 0; memset(h, 0, sizeof h);
                continue;
            }
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, (ZyanUSize)(end - p), &ins, ops))) {
                p++; prev_mov_eax = 0; memset(h, 0, sizeof h);
                continue;
            }
            if (ins.meta.category == ZYDIS_CATEGORY_COND_BR || ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                ins.meta.category == ZYDIS_CATEGORY_CALL) {
                for (k = 0; k < ins.operand_count_visible; k++) {
                    ZyanU64 t;
                    if (ops[k].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[k].imm.is_relative &&
                        ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[k], ip, &t)))
                        VEC_PUSH(targets, ntargets, captargets, (uint64_t)t);
                }
            }
            for (k = 0; k < ins.operand_count_visible; k++) {
                if (ops[k].type != ZYDIS_OPERAND_TYPE_MEMORY || ops[k].mem.segment != ZYDIS_REGISTER_FS)
                    continue;
                if (ops[k].mem.base != ZYDIS_REGISTER_NONE || ops[k].mem.index != ZYDIS_REGISTER_NONE) {
                    uint64_t fs_, fe_;
                    int inside = c && c->bounds && c->bounds(c->ctx, ip, &fs_, &fe_);
                    describe(c, p, where, sizeof where);
                    if (inside) rep->fs_reg_in_func++; else rep->fs_reg_outside++;
                    fprintf(stderr, "  [patch] fs:[reg] at %s: %s\n", where,
                            inside ? "INSIDE a known function - real ELF TLS access (needs G2)"
                                   : "outside every known function - data decoded as code, ignored");
                    dump_ins(p, &ins, ops);
                    continue;
                }
                rep->fs_disp_seen++;
#if defined(_WIN32)
                {
                    int64_t d = ops[k].mem.disp.value;
                    uint64_t fs0, fe0;
                    if (!c || !c->bounds || !c->bounds(c->ctx, ip, &fs0, &fe0)) {
                        rep->fs_skipped_outside++;   /* never change bytes outside a known function */
                        continue;
                    }
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
                site s;
                uint64_t sf0, se0;
                if (!c || !c->bounds || !c->bounds(c->ctx, ip, &sf0, &se0)) {
                    /* not inside a known function: decoded data, or unknown code - leave it */
                    rep->sys_refused_unknown++;
                    describe(c, p, where, sizeof where);
                    fprintf(stderr, "  [patch] syscall bytes at %s are outside every known function: not touched\n", where);
                    goto next_ins;
                }
                memset(&s, 0, sizeof s);
                if (prev_mov_eax && h[0].p + 5 == p) {
                    s.start = h[0].p; s.len = 7; s.form = 'A'; s.nr = prev_imm;
                } else {
                    /* form B: move >= 3 bytes of the preceding instructions */
                    int total = 0, n = 0;
                    unsigned char *next = p;
                    while (n < 3 && h[n].p && h[n].movable && h[n].p + h[n].len == next && total < 3) {
                        total += h[n].len; next = h[n].p; n++;
                    }
                    if (total >= 3) { s.start = next; s.len = total + 2; s.form = 'B'; }
                }
                if (s.form) VEC_PUSH(sites, nsites, capsites, s);
                else {
                    rep->sys_refused_unknown++;
                    describe(c, p, where, sizeof where);
                    fprintf(stderr, "  [patch] REFUSED syscall at %s: nothing safe to move before it\n", where);
                }
            }
        next_ins:
            movable = !is_branch(&ins) && !(ins.attributes & ZYDIS_ATTRIB_IS_RELATIVE) && !uses_r11(&ins, ops) &&
                      ins.mnemonic != ZYDIS_MNEMONIC_SYSCALL;
            h[2] = h[1]; h[1] = h[0];
            h[0].p = p; h[0].len = ins.length; h[0].movable = movable;
            prev_mov_eax = ins.mnemonic == ZYDIS_MNEMONIC_MOV && ins.length == 5 &&
                           ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_EAX &&
                           ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
            if (prev_mov_eax) prev_imm = (uint32_t)ops[1].imm.value.u;
            p += ins.length;
        }
    }
    if (targets) qsort(targets, ntargets, sizeof *targets, cmp_u64);

    /* Pass 2: rewrite the sites that are provably safe */
    for (i = 0; i < nsites && !fatal; i++) {
        site *s = &sites[i];
        uint64_t lo = (uint64_t)(uintptr_t)s->start, fs_, fe_;
        unsigned char *stub = NULL;
        int64_t rel;
        describe(c, s->start, where, sizeof where);

        if (target_inside(targets, ntargets, lo, lo + (uint64_t)s->len)) {
            rep->sys_refused_branch++;
            fprintf(stderr, "  [patch] REFUSED syscall at %s: a branch lands inside the site\n", where);
            continue;
        }
        if (!c || !c->bounds || !c->bounds(c->ctx, lo, &fs_, &fe_)) {
            rep->sys_refused_unknown++;
            fprintf(stderr, "  [patch] REFUSED syscall at %s: function boundaries unknown\n", where);
            continue;
        }
        if ((r = function_uses_red_zone(&dec, fs_, fe_)) != 0) {
            rep->sys_refused_redzone++;
            if (r == 1) rep->redzone_direct++; else rep->redzone_via_copy++;
            fprintf(stderr, "  [patch] REFUSED syscall at %s: its function may use the red zone\n", where);
            continue;
        }

        if (s->form == 'A' && s->nr < AFW_MAX_SYSCALL && stub_for[s->nr]) {
            stub = stub_for[s->nr];
        } else {
            size_t need = (size_t)(s->form == 'A' ? 24 : 2 + (s->len - 2) + 2 + 14 + 8);
            if (stub_used + need > stub_size) {
                fprintf(stderr, "  [patch] FATAL: stub area full (%zu bytes)\n", stub_size);
                fatal = 1; break;
            }
            stub = stub_area + stub_used;
            if (s->form == 'A') {
                stub[0] = 0xB8; memcpy(stub + 1, &s->nr, 4);               /* mov eax, nr */
                stub[5] = 0xFF; stub[6] = 0x25; memset(stub + 7, 0, 4);    /* jmp [rip+0] */
                memcpy(stub + 11, &entry, 8);
                if (s->nr < AFW_MAX_SYSCALL) stub_for[s->nr] = stub;
            } else {
                int m = s->len - 2, o = 0;
                stub[o++] = 0x41; stub[o++] = 0x5B;                        /* pop r11 */
                memcpy(stub + o, s->start, (size_t)m); o += m;             /* moved instructions */
                stub[o++] = 0x41; stub[o++] = 0x53;                        /* push r11 */
                stub[o++] = 0xFF; stub[o++] = 0x25; memset(stub + o, 0, 4); o += 4; /* jmp [rip+0] */
                memcpy(stub + o, &entry, 8);
            }
            stub_used += (need + 7) & ~(size_t)7;
            rep->stubs++;
        }
        rel = (int64_t)(stub - (s->start + 5));
        if (rel > INT32_MAX || rel < INT32_MIN) {
            fprintf(stderr, "  [patch] FATAL: stub out of rel32 range at %s\n", where);
            fatal = 1; break;
        }
        {
            int32_t rel32 = (int32_t)rel;
            int k;
            s->start[0] = 0xE8; memcpy(s->start + 1, &rel32, 4);            /* call stub */
            for (k = 5; k < s->len; k++) s->start[k] = 0x90;                /* nop */
            if (s->len - 5 == 2) { s->start[5] = 0x66; s->start[6] = 0x90; }
        }
        if (s->form == 'A') rep->sys_patched++; else rep->sys_patched_moved++;
        if (verbose > 1) printf("  [patch] syscall at %s: form %c\n", where, s->form);
    }

    /* Audit: a plain linear sweep of the executable segments finds every
     * byte pattern that LOOKS like a syscall or an fs: access. Each one must
     * be either handled above, unreachable (left alone), or reported. */
    if (c && c->ranges_are_functions) {
        int g;
        for (g = 0; g < c->nsegs; g++) {
            unsigned char *p = c->segs[g].addr, *end = p + c->segs[g].size;
            while (p < end) {
                int is_sys, is_fs;
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, (ZyanUSize)(end - p), &ins, ops))) { p++; continue; }
                is_sys = ins.mnemonic == ZYDIS_MNEMONIC_SYSCALL;
                is_fs = has_fs_operand(&ins, ops);
                if (is_sys || is_fs) {
                    int lo = 0, hi = nranges, found = -1;
                    while (lo < hi) {   /* ranges are sorted by address (.eh_frame_hdr order) */
                        int m = (lo + hi) / 2;
                        if (ranges[m].addr > p) hi = m;
                        else if (ranges[m].addr + ranges[m].size <= p) lo = m + 1;
                        else { found = m; break; }
                    }
                    if (found < 0) {
                        if (is_sys) {
                            rep->sys_outside_functions++;
                            describe(c, p, where, sizeof where);
                            fprintf(stderr, "  [audit] WARNING: syscall bytes at %s, outside every .eh_frame function "
                                            "(data, or code without unwind info): not touched\n", where);
                        } else rep->fs_outside_functions++;
                    } else if (maps[found] && maps[found][p - ranges[found].addr] != 1) {
                        describe(c, p, where, sizeof where);
                        if (undecided[found]) {
                            rep->unproven++;
                            fprintf(stderr, "  [audit] UNPROVEN: %s-looking bytes at %s, in a function with an unresolved "
                                            "indirect jump: not touched\n", is_sys ? "syscall" : "fs:", where);
                        } else {
                            rep->unreachable_ignored++;
                            if (verbose > 1)
                                fprintf(stderr, "  [audit] %s-looking bytes at %s: no path reaches them, left untouched\n",
                                        is_sys ? "syscall" : "fs:", where);
                        }
                    }
                }
                p += ins.length;
            }
        }
    }
    for (r = 0; r < nranges; r++) free(maps[r]);
    free(maps); free(undecided);

    free(targets); free(sites);
    if (fatal) return -1;
    return (rep->sys_refused_branch || rep->sys_refused_redzone || rep->sys_refused_unknown) ? 1 : 0;
}
