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
/* fs:[reg] site: the instruction plus the following instructions moved with it */
typedef struct { unsigned char *start; int pre_len, ins_len, total, ends_ret; } fsite;
/* two ways to collect the 5 bytes: successors first, or predecessors first */
typedef struct { fsite opt[2]; int nopt; } fsite2;

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

/* Any operand, visible or hidden (push/pop/call stack use), touching rsp. */
static int uses_rsp(const ZydisDecodedInstruction *ins, const ZydisDecodedOperand *ops) {
    int i;
    for (i = 0; i < ins->operand_count; i++) {
        ZydisRegister r = ZYDIS_REGISTER_NONE;
        if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER) r = ops[i].reg.value;
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            (ops[i].mem.base == ZYDIS_REGISTER_RSP || ops[i].mem.index == ZYDIS_REGISTER_RSP))
            return 1;
        if (r == ZYDIS_REGISTER_RSP || r == ZYDIS_REGISTER_ESP || r == ZYDIS_REGISTER_SP || r == ZYDIS_REGISTER_SPL)
            return 1;
    }
    return 0;
}

/* Control transfer or trap of any kind: never copied into a trampoline. */
static int transfers_control(const ZydisDecodedInstruction *n) {
    return is_branch(n) || n->meta.category == ZYDIS_CATEGORY_INTERRUPT || n->meta.category == ZYDIS_CATEGORY_SYSTEM ||
           n->mnemonic == ZYDIS_MNEMONIC_XBEGIN || n->mnemonic == ZYDIS_MNEMONIC_XABORT ||
           n->mnemonic == ZYDIS_MNEMONIC_XEND || n->mnemonic == ZYDIS_MNEMONIC_UD0 ||
           n->mnemonic == ZYDIS_MNEMONIC_UD1 || n->mnemonic == ZYDIS_MNEMONIC_UD2 ||
           n->mnemonic == ZYDIS_MNEMONIC_INT3 || n->mnemonic == ZYDIS_MNEMONIC_HLT;
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
    int64_t copy_off[16];     /* copy = rsp + copy_off at the time of the copy */
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
                {
                    copy_off[ncopies] = ins.mnemonic == ZYDIS_MNEMONIC_LEA ? ops[1].mem.disp.value : 0;
                    copies[ncopies++] = reg64(ops[0].reg.value);
                }
                /* frame allocation: sub rsp, imm */
                if (ins.mnemonic == ZYDIS_MNEMONIC_SUB && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ops[0].reg.value == ZYDIS_REGISTER_RSP && ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    (int64_t)ops[1].imm.value.s > max_sub)
                    max_sub = (int64_t)ops[1].imm.value.s;
            } else {
                for (i = 0; i < ins.operand_count_visible; i++) {
                    if (ops[i].type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
                    if (ops[i].mem.base == ZYDIS_REGISTER_RSP && ops[i].mem.disp.value < 0) return 1;
                    /* through a copy: rsp-relative offset = copy offset + displacement; below
                     * what "sub rsp, K" allocated means the red zone */
                    for (k = 0; k < ncopies; k++)
                        if (ops[i].mem.base == copies[k] && copy_off[k] + ops[i].mem.disp.value < -max_sub)
                            return 2;
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

/* Full record of one UNPROVEN site, for review (docs/unproven/). Every
 * line starts with "UNPROVEN-DETAIL" so CI can collect them. Decoding of
 * the function is linear from its start; "R" marks bytes the control-flow
 * analysis reached, "-" bytes it did not. */
static void unproven_detail(ZydisDecoder *dec, const afw_patch_ctx *c, unsigned char *fstart, size_t fsize,
                            const unsigned char *map, const unsigned char *why, const unsigned char *site,
                            int is_sys) {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisFormatter f;
    char text[160];
    unsigned char *q = fstart, *fend = fstart + fsize;
    size_t reached = 0, i;
    const unsigned char *lo = site - 160 < fstart ? fstart : site - 160;
    const unsigned char *hi = site + 48 > fend ? fend : site + 48;
    const unsigned char *b0 = site - 16 < fstart ? fstart : site - 16;
    const unsigned char *b1 = site + 16 > fend ? fend : site + 16;
    long long bias = (long long)c->bias;
    const char *nm = c->name ? c->name : "lib";

    ZydisFormatterInit(&f, ZYDIS_FORMATTER_STYLE_INTEL);
    for (i = 0; map && i < fsize; i++) reached += map[i] == 1;
    fprintf(stderr, "UNPROVEN-DETAIL ==== %s+0x%llx kind=%s\n", nm, (long long)((intptr_t)site - bias),
            is_sys ? "syscall" : "fs");
    fprintf(stderr, "UNPROVEN-DETAIL function=%s+0x%llx..0x%llx size=%llu reached_bytes=%llu\n", nm,
            (long long)((intptr_t)fstart - bias), (long long)((intptr_t)fend - bias),
            (unsigned long long)fsize, (unsigned long long)reached);
    if (why && ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, why, 16, &ins, ops))) {
        ZydisFormatterFormatInstruction(&f, &ins, ops, ins.operand_count_visible, text, sizeof text,
                                        (ZyanU64)((intptr_t)why - bias), ZYAN_NULL);
        fprintf(stderr, "UNPROVEN-DETAIL reason=indirect jump not proven to be a switch table at %s+0x%llx: %s\n",
                nm, (long long)((intptr_t)why - bias), text);
    } else {
        fprintf(stderr, "UNPROVEN-DETAIL reason=function undecided (exception table not decoded, or no jump recorded)\n");
    }
    /* Function-level facts, printed once per function (several sites can share one). */
    {
        static const unsigned char *last_func;
        if (last_func != fstart) {
            unsigned char *st = (unsigned char *)calloc(fsize ? fsize : 1, 1);   /* instruction starts */
            const unsigned char *hist[12];
            int nh = 0, h, norph = 0;
            last_func = fstart;
            for (q = fstart; st && q < fend;) {
                int ok = ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(fend - q), &ins, ops));
                size_t len = ok ? ins.length : 1;
                st[q - fstart] = 1;
                if (q == why) break;
                if (ok) { if (nh == 12) { memmove(hist, hist + 1, 11 * sizeof *hist); nh = 11; } hist[nh++] = q; }
                q += len;
            }
            if (why && why >= fstart && why < fend) {
                uint64_t table = 0;
                fprintf(stderr, "UNPROVEN-DETAIL pre-jump (up to 12 instructions before the undecided jump):\n");
                for (h = 0; h <= nh; h++) {
                    const unsigned char *a = h < nh ? hist[h] : why;
                    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, a, (ZyanUSize)(fend - a), &ins, ops))) continue;
                    ZydisFormatterFormatInstruction(&f, &ins, ops, ins.operand_count_visible, text, sizeof text,
                                                    (ZyanU64)((intptr_t)a - bias), ZYAN_NULL);
                    fprintf(stderr, "UNPROVEN-DETAIL   %c %s 0x%llx: %s\n", map && map[a - fstart] == 1 ? 'R' : '-',
                            a == why ? ">>" : "  ", (long long)((intptr_t)a - bias), text);
                    if (a != why && ins.mnemonic == ZYDIS_MNEMONIC_LEA && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                        ZyanU64 t;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[1], (ZyanU64)(uintptr_t)a, &t)))
                            table = (uint64_t)t;   /* the last rip-relative lea before the jump */
                    }
                }
                /* rest of the function's instruction starts, for boundary checks */
                for (; st && q < fend;) {
                    int ok = ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(fend - q), &ins, ops));
                    st[q - fstart] = 1; q += ok ? ins.length : 1;
                }
                if (table) {
                    int e;
                    fprintf(stderr, "UNPROVEN-DETAIL table at %s+0x%llx (from the last rip-relative lea; "
                                    "entries are int32 relative to the table):\n", nm, (long long)(table - bias));
                    for (e = 0; e < 64; e++) {
                        int32_t v;
                        uint64_t tgt;
                        const char *where2, *bound;
                        if (!c->readable || !c->readable(c->ctx, table + 4u * (unsigned)e, 4)) {
                            fprintf(stderr, "UNPROVEN-DETAIL   [%2d] not readable - stop\n", e); break;
                        }
                        memcpy(&v, (const void *)(uintptr_t)(table + 4u * (unsigned)e), 4);
                        tgt = table + (uint64_t)(int64_t)v;
                        if (tgt < (uint64_t)(uintptr_t)fstart || tgt >= (uint64_t)(uintptr_t)fend) {
                            where2 = "OUTSIDE function"; bound = "-";
                        } else {
                            where2 = "inside";
                            bound = st && st[tgt - (uint64_t)(uintptr_t)fstart] ? "on boundary" : "MID-INSTRUCTION";
                        }
                        fprintf(stderr, "UNPROVEN-DETAIL   [%2d] entry=%d -> 0x%llx  %s, %s, %s\n", e, v,
                                (long long)((intptr_t)tgt - bias), where2, bound,
                                (tgt >= (uint64_t)(uintptr_t)fstart && tgt < (uint64_t)(uintptr_t)fend && map &&
                                 map[tgt - (uint64_t)(uintptr_t)fstart] == 1) ? "reached" : "not reached");
                    }
                } else fprintf(stderr, "UNPROVEN-DETAIL table: no rip-relative lea in the 12 instructions before the jump\n");
            }
            /* orphan blocks: start right after an unconditional jmp / ret / ud2 / hlt, never reached */
            for (q = fstart; q < fend;) {
                int ok = ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(fend - q), &ins, ops));
                size_t len = ok ? ins.length : 1;
                if (ok && (ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR || ins.meta.category == ZYDIS_CATEGORY_RET ||
                           ins.mnemonic == ZYDIS_MNEMONIC_UD2 || ins.mnemonic == ZYDIS_MNEMONIC_HLT) &&
                    q + len < fend && map && map[q + len - fstart] != 1) {
                    if (norph < 64)
                        fprintf(stderr, "UNPROVEN-DETAIL orphan block at %s+0x%llx (after the instruction at 0x%llx)\n",
                                nm, (long long)((intptr_t)(q + len) - bias), (long long)((intptr_t)q - bias));
                    norph++;
                }
                q += len;
            }
            fprintf(stderr, "UNPROVEN-DETAIL orphan blocks in function: %d\n", norph);
            free(st);
        }
    }
    fprintf(stderr, "UNPROVEN-DETAIL bytes %s+0x%llx:", nm, (long long)((intptr_t)b0 - bias));
    for (; b0 < b1; b0++) fprintf(stderr, b0 == site ? " [%02x" : " %02x", *b0);
    fprintf(stderr, "   ('[' = site)\n");
    /* linear decoding from the function start; print the window around the site */
    q = fstart;
    while (q < fend) {
        int ok = ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(fend - q), &ins, ops));
        size_t len = ok ? ins.length : 1;
        if (q + len > lo && q < hi) {
            if (ok) ZydisFormatterFormatInstruction(&f, &ins, ops, ins.operand_count_visible, text, sizeof text,
                                                    (ZyanU64)((intptr_t)q - bias), ZYAN_NULL);
            else snprintf(text, sizeof text, "(bad) %02x", *q);
            fprintf(stderr, "UNPROVEN-DETAIL   %c %s 0x%llx: %s%s\n", map && map[q - fstart] == 1 ? 'R' : '-',
                    (site >= q && site < q + len) ? ">>" : "  ", (long long)((intptr_t)q - bias), text,
                    (site > q && site < q + len) ? "   (site is INSIDE this instruction)" : "");
        }
        q += len;
    }
}

/* Does this instruction write (any part of) register r64? */
static int writes_reg(const ZydisDecodedInstruction *ins, const ZydisDecodedOperand *ops, ZydisRegister r64) {
    int i;
    for (i = 0; i < ins->operand_count; i++)
        if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER && (ops[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
            reg64(ops[i].reg.value) == r64)
            return 1;
    return 0;
}

/* Data flow from the table to the jump (reviewer 2, PR #7): walking back
 * from "jmp rX" over straight-line, reached instructions with no branch:
 *   rX  <- add rX, rT   (or add rT, rX)
 *   rX' <- movsxd ..., dword [rT + rI*4]   (the other add operand)
 *   rT  <- lea rT, [rip + T]
 * with rT not written between the lea and the add. Returns 1 if proven. */
static int attest_chain(ZydisDecoder *dec, unsigned char *const *win, int n, const unsigned char *map,
                        unsigned char *fstart, uint64_t T, unsigned char **lea_at, const char **why) {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisRegister rx, ra, rb, rt = ZYDIS_REGISTER_NONE, rload = ZYDIS_REGISTER_NONE;
    int i, iadd = -1, iload = -1, ilea = -1;
    /* win[n-1] is the jump */
    if (n < 4) { *why = "too few instructions before the jump"; return 0; }
    for (i = 0; i < n; i++)
        if (map[win[i] - fstart] != 1) { *why = "an instruction of the dispatch is not reached"; return 0; }
    ZydisDecoderDecodeFull(dec, win[n - 1], 16, &ins, ops);
    rx = reg64(ops[0].reg.value);
    for (i = n - 2; i >= 0; i--) {                       /* the add that defines rX */
        ZydisDecoderDecodeFull(dec, win[i], 16, &ins, ops);
        if (is_branch(&ins)) { *why = "a branch between the dispatch and the jump"; return 0; }
        if (!writes_reg(&ins, ops, rx)) continue;
        if (ins.mnemonic != ZYDIS_MNEMONIC_ADD || ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            ops[1].type != ZYDIS_OPERAND_TYPE_REGISTER || ins.operand_width != 64) {
            *why = "the jump register is not set by add reg, reg"; return 0;
        }
        ra = reg64(ops[0].reg.value); rb = reg64(ops[1].reg.value);
        iadd = i;
        (void)ra;
        /* one add operand is the loaded entry, the other the table base: try both */
        {
            int pick;
            for (pick = 0; pick < 2 && ilea < 0; pick++) {
                ZydisRegister cand_load = pick ? rb : rx, cand_base = pick ? rx : rb;
                int j, jl = -1, jt = -1;
                for (j = iadd - 1; j >= 0 && jl < 0; j--) {          /* writer of the loaded register */
                    ZydisDecoderDecodeFull(dec, win[j], 16, &ins, ops);
                    if (is_branch(&ins)) break;
                    if (writes_reg(&ins, ops, cand_load)) {
                        if (ins.mnemonic == ZYDIS_MNEMONIC_MOVSXD && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                            ops[1].size == 32 && reg64(ops[1].mem.base) == cand_base && ops[1].mem.scale == 4 &&
                            ops[1].mem.disp.value == 0 && ops[1].mem.index != ZYDIS_REGISTER_NONE)
                            jl = j;
                        break;
                    }
                }
                if (jl < 0) continue;
                for (j = iadd - 1; j >= 0; j--) {                    /* writer of the base, before the add */
                    ZydisDecoderDecodeFull(dec, win[j], 16, &ins, ops);
                    if (is_branch(&ins)) break;
                    if (!writes_reg(&ins, ops, cand_base)) continue;
                    if (ins.mnemonic == ZYDIS_MNEMONIC_LEA && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                        ZyanU64 t;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[1], (ZyanU64)(uintptr_t)win[j], &t)) &&
                            (uint64_t)t == T && j < jl)
                            jt = j;
                    }
                    break;                                           /* the nearest writer decides */
                }
                if (jt >= 0) { ilea = jt; iload = jl; rt = cand_base; rload = cand_load; }
            }
        }
        break;
    }
    (void)rt; (void)rload; (void)iload;
    if (iadd < 0) { *why = "nothing sets the jump register"; return 0; }
    if (ilea < 0) { *why = "no lea T -> movsxd [base + idx*4] -> add -> jmp chain for the attested table"; return 0; }
    *lea_at = win[ilea];
    return 1;
}

/* Re-verify one attestation against the bytes in memory (reviewer 3, #2 and
 * PR #7): the jump is an indirect "jmp reg", decoded at its own address and
 * reached by the analysis, inside this function; a rip-relative lea of the
 * same table, itself REACHED by the analysis, precedes it; the table lies in
 * memory the file maps read-only; each of entries [0, k) lands inside the
 * function on the start of a validly decoded instruction that is not int3
 * padding. Fills out[] with the k targets and returns k, or -1 + reason. */
static int attest_verify(ZydisDecoder *dec, const afw_patch_ctx *c, unsigned char *fstart, size_t fsize,
                         const unsigned char *map, const afw_attest *a, uint64_t *out, int max,
                         const uint64_t *tt, size_t ntt, int und_count, const unsigned char *und_why,
                         const char **why) {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    unsigned char *fend = fstart + fsize, *J = (unsigned char *)(c->bias + (intptr_t)a->jmp_rva), *q;
    uint64_t T = (uint64_t)(c->bias + (intptr_t)a->table_rva);
    unsigned char *starts;
    int lea_ok = 0, e;
    if (a->k <= 0 || a->k > max) { *why = "entry count out of range"; return -1; }
    if (J < fstart || J >= fend) { *why = "jump not inside this function"; return -1; }
    if (!map || map[J - fstart] != 1) { *why = "jump not reached by the analysis"; return -1; }
    /* J must be the ONLY unresolved indirect jump the analysis reached in this
     * function: another one could land anywhere, inside the chain included
     * (reviewer 2, PR #7) */
    if (und_count != 1 || und_why != J) {
        *why = "the function has another unresolved indirect jump besides the attested one"; return -1;
    }
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, J, (ZyanUSize)(fend - J), &ins, ops)) ||
        ins.mnemonic != ZYDIS_MNEMONIC_JMP || ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        *why = "no indirect jmp reg at the attested address"; return -1;
    }
    if (!c->readonly || !c->readonly(c->ctx, T, 4u * (unsigned)a->k)) {
        *why = "table not in memory the file maps read-only"; return -1;
    }
    starts = (unsigned char *)calloc(fsize, 1);
    if (!starts) { *why = "out of memory"; return -1; }
    {
        unsigned char *win[16];
        int nw = 0, at_j = 0;
        for (q = fstart; q < fend;) {
            int ok = ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(fend - q), &ins, ops));
            if (ok) starts[q - fstart] = 1;              /* undecodable bytes are never a boundary */
            if (q <= J) {
                if (!ok) nw = 0;                         /* the window must decode cleanly up to J */
                else { if (nw == 16) { memmove(win, win + 1, 15 * sizeof *win); nw = 15; } win[nw++] = q; }
                if (q == J) at_j = ok;
            }
            q += ok ? ins.length : 1;
        }
        {
            unsigned char *lea_at = NULL;
            lea_ok = at_j && attest_chain(dec, win, nw, map, fstart, T, &lea_at, why);
            if (!at_j) *why = "the linear decoding of the function does not land on the jump";
            /* every way to the jump goes through the chain (reviewer 2, PR #7): no
             * branch target in (lea, J] - neither a direct branch of this function,
             * nor any target the analysis has recorded, nor an entry of the table */
            if (lea_ok) {
                uint64_t lo = (uint64_t)(uintptr_t)lea_at, hi = (uint64_t)(uintptr_t)J;
                size_t ti;
                int e2;
                for (ti = 0; ti < ntt && lea_ok; ti++)
                    if (tt[ti] > lo && tt[ti] <= hi) lea_ok = 0;
                /* direct branches and calls anywhere in the library's executable
                 * code, not only this function and not only those the analysis has
                 * seen so far (reviewer 2): a linear sweep of every executable
                 * segment. Data decoded as code can only add false targets, which
                 * only rejects more. */
                {
                    int g, nsweep = c->nsegs;
                    for (g = 0; g < (nsweep ? nsweep : 1) && lea_ok; g++) {
                        unsigned char *s0 = nsweep ? c->segs[g].addr : fstart;
                        unsigned char *s1 = nsweep ? s0 + c->segs[g].size : fend;
                        for (q = s0; q < s1 && lea_ok;) {
                            int ok = ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(s1 - q), &ins, ops));
                            if (ok && is_branch(&ins) && ins.operand_count_visible >= 1 &&
                                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                                ZyanU64 t;
                                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[0], (ZyanU64)(uintptr_t)q, &t)) &&
                                    (uint64_t)t > lo && (uint64_t)t <= hi)
                                    lea_ok = 0;
                            }
                            q += ok ? ins.length : 1;
                        }
                    }
                }
                for (e2 = 0; e2 < a->k && lea_ok; e2++) {
                    int32_t v;
                    uint64_t tgt;
                    if (!c->readable || !c->readable(c->ctx, T + 4u * (unsigned)e2, 4)) break;
                    memcpy(&v, (const void *)(uintptr_t)(T + 4u * (unsigned)e2), 4);
                    tgt = T + (uint64_t)(int64_t)v;
                    if (tgt > lo && tgt <= hi) lea_ok = 0;
                }
                if (!lea_ok) *why = "a branch lands inside the dispatch chain (lea .. jmp): the chain does not decide every way to the jump";
            }
        }
    }
    if (!lea_ok) { free(starts); return -1; }
    for (e = 0; e < a->k; e++) {
        int32_t v;
        uint64_t tgt;
        if (!c->readable || !c->readable(c->ctx, T + 4u * (unsigned)e, 4)) {
            free(starts); *why = "table entry not inside readable memory"; return -1;
        }
        memcpy(&v, (const void *)(uintptr_t)(T + 4u * (unsigned)e), 4);
        tgt = T + (uint64_t)(int64_t)v;
        if (tgt < (uint64_t)(uintptr_t)fstart || tgt >= (uint64_t)(uintptr_t)fend ||
            !starts[tgt - (uint64_t)(uintptr_t)fstart] || *(const unsigned char *)(uintptr_t)tgt == 0xCC) {
            free(starts); *why = "a table entry does not land on a decodable, non-padding instruction of this function";
            return -1;
        }
        out[e] = tgt;
    }
    free(starts);
    return a->k;
}

/* The evidence behind one attestation, for the people who sign it: the
 * instructions before the jump (R = reached) and entries [0, k + 2) of the
 * table with where they land. Lines start with "ATTEST-DETAIL". */
static void attest_dump(ZydisDecoder *dec, const afw_patch_ctx *c, unsigned char *fstart, size_t fsize,
                        const unsigned char *map, const afw_attest *a) {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisFormatter f;
    char text[160];
    unsigned char *fend = fstart + fsize, *J = (unsigned char *)(c->bias + (intptr_t)a->jmp_rva), *q;
    unsigned char *hist[20], *starts = (unsigned char *)calloc(fsize ? fsize : 1, 1);
    uint64_t T = (uint64_t)(c->bias + (intptr_t)a->table_rva);
    long long bias = (long long)c->bias;
    const char *nm = c->name ? c->name : "lib";
    int nh = 0, h, e;
    if (!starts) return;
    ZydisFormatterInit(&f, ZYDIS_FORMATTER_STYLE_INTEL);
    fprintf(stderr, "ATTEST-DETAIL ==== %s jump 0x%llx table 0x%llx k=%d  function 0x%llx..0x%llx (%s)\n", nm,
            (long long)a->jmp_rva, (long long)a->table_rva, a->k, (long long)((intptr_t)fstart - bias),
            (long long)((intptr_t)fend - bias), a->note ? a->note : "");
    for (q = fstart; q < fend;) {
        int ok = ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(fend - q), &ins, ops));
        if (ok) starts[q - fstart] = 1;
        if (q <= J && ok) { if (nh == 20) { memmove(hist, hist + 1, 19 * sizeof *hist); nh = 19; } hist[nh++] = q; }
        q += ok ? ins.length : 1;
    }
    fprintf(stderr, "ATTEST-DETAIL instructions before the jump (R = reached by the analysis before attestation):\n");
    for (h = 0; h < nh; h++) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, hist[h], (ZyanUSize)(fend - hist[h]), &ins, ops))) continue;
        ZydisFormatterFormatInstruction(&f, &ins, ops, ins.operand_count_visible, text, sizeof text,
                                        (ZyanU64)((intptr_t)hist[h] - bias), ZYAN_NULL);
        fprintf(stderr, "ATTEST-DETAIL   %c %s 0x%llx: %s\n", map && map[hist[h] - fstart] == 1 ? 'R' : '-',
                hist[h] == J ? ">>" : "  ", (long long)((intptr_t)hist[h] - bias), text);
    }
    {   /* where the index comes from: every branch in the function into the dispatch block */
        unsigned char *blk = NULL, *q2;
        char nmf[160];
        describe(c, fstart, nmf, sizeof nmf);
        fprintf(stderr, "ATTEST-DETAIL function: %s\n", nmf);
        for (h = nh - 1; h > 0; h--) {           /* the dispatch block starts after the last branch before J */
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, hist[h - 1], 16, &ins, ops))) break;
            if (is_branch(&ins)) { blk = hist[h]; break; }
        }
        if (!blk && nh) blk = hist[0];
        fprintf(stderr, "ATTEST-DETAIL dispatch block starts at 0x%llx; branches into it from this function:\n",
                (long long)((intptr_t)blk - bias));
        for (q2 = fstart; blk && q2 < fend;) {
            int ok = ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q2, (ZyanUSize)(fend - q2), &ins, ops));
            if (ok && is_branch(&ins) && ins.operand_count_visible >= 1 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                ZyanU64 t;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[0], (ZyanU64)(uintptr_t)q2, &t)) &&
                    (unsigned char *)(uintptr_t)t == blk) {
                    /* the 8 instructions before that branch, linearly */
                    unsigned char *w[9], *r2;
                    int nw2 = 0, x;
                    for (r2 = fstart; r2 <= q2;) {
                        ZydisDecodedInstruction i2;
                        ZydisDecodedOperand o2[ZYDIS_MAX_OPERAND_COUNT];
                        int ok2 = ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, r2, (ZyanUSize)(fend - r2), &i2, o2));
                        if (ok2) { if (nw2 == 9) { memmove(w, w + 1, 8 * sizeof *w); nw2 = 8; } w[nw2++] = r2; }
                        r2 += ok2 ? i2.length : 1;
                    }
                    fprintf(stderr, "ATTEST-DETAIL   -- from 0x%llx:\n", (long long)((intptr_t)q2 - bias));
                    for (x = 0; x < nw2; x++) {
                        ZydisDecodedInstruction i3;
                        ZydisDecodedOperand o3[ZYDIS_MAX_OPERAND_COUNT];
                        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, w[x], 16, &i3, o3))) continue;
                        ZydisFormatterFormatInstruction(&f, &i3, o3, i3.operand_count_visible, text, sizeof text,
                                                        (ZyanU64)((intptr_t)w[x] - bias), ZYAN_NULL);
                        fprintf(stderr, "ATTEST-DETAIL     %c 0x%llx: %s\n", map && map[w[x] - fstart] == 1 ? 'R' : '-',
                                (long long)((intptr_t)w[x] - bias), text);
                    }
                }
            }
            q2 += ok ? ins.length : 1;
        }
    }
    fprintf(stderr, "ATTEST-DETAIL table entries [0, k+2) (int32 relative to the table):\n");
    for (e = 0; e < a->k + 2; e++) {
        int32_t v;
        uint64_t tgt;
        int in;
        if (!c->readable || !c->readable(c->ctx, T + 4u * (unsigned)e, 4)) {
            fprintf(stderr, "ATTEST-DETAIL   [%2d] not readable\n", e); break;
        }
        memcpy(&v, (const void *)(uintptr_t)(T + 4u * (unsigned)e), 4);
        tgt = T + (uint64_t)(int64_t)v;
        in = tgt >= (uint64_t)(uintptr_t)fstart && tgt < (uint64_t)(uintptr_t)fend;
        text[0] = 0;
        if (in && ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, (const void *)(uintptr_t)tgt,
                                                      (ZyanUSize)((uint64_t)(uintptr_t)fend - tgt), &ins, ops)))
            ZydisFormatterFormatInstruction(&f, &ins, ops, ins.operand_count_visible, text, sizeof text,
                                            (ZyanU64)((intptr_t)tgt - bias), ZYAN_NULL);
        fprintf(stderr, "ATTEST-DETAIL   [%2d]%s entry=%d -> 0x%llx  %s%s  %s\n", e, e < a->k ? "*" : " ", v,
                (long long)((intptr_t)tgt - bias), in ? "inside" : "OUTSIDE the function",
                in ? (starts[tgt - (uint64_t)(uintptr_t)fstart] ? ", on boundary" : ", MID-INSTRUCTION") : "", text);
    }
    fprintf(stderr, "ATTEST-DETAIL (* = attested entries)\n");
    free(starts);
}

static unsigned char *reach_map(ZydisDecoder *dec, unsigned char *base, size_t size, int *undecided,
                                const unsigned char **why, const uint64_t *extra, int nextra,
                                const afw_patch_ctx *c, uint64_t **tt, size_t *ntt, size_t *captt) {
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
                            int32_t ent[4096];
                            int bad = 0;
                            /* the whole table must be inside the loaded image before any read */
                            if (!c || !c->readable || !c->readable(c->ctx, tab, 4 * n)) bad = 1;
                            if (!bad) memcpy(ent, (const void *)(uintptr_t)tab, (size_t)(4 * n));
                            for (e = 0; e < n && !bad; e++) {
                                uint64_t t2 = tab + (uint64_t)(int64_t)ent[e];
                                if (t2 < lo || t2 >= hi) bad = 1;
                            }
                            if (bad) { (*undecided)++; *why = base + off; }   /* counts unresolved jumps */
                            else for (e = 0; e < n; e++) {
                                uint64_t t2 = tab + (uint64_t)(int64_t)ent[e];
                                VEC_PUSH(work, nwork, capwork, (size_t)(t2 - lo));
                                VEC_PUSH(*tt, *ntt, *captt, t2);   /* also a branch target */
                            }
                        } else {
                            (*undecided)++; *why = base + off;
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

/* A refused site: its 2-byte syscall becomes ud2. Same length, nothing else
 * changes, no stack use. Running it stops with a clear crash report. */
static void trap_syscall(unsigned char *sys, afw_patch_report *rep) {
    if (sys[0] == 0x0F && sys[1] == 0x05) { sys[1] = 0x0B; rep->sys_trapped++; }
}

static int has_fs_operand(const ZydisDecodedInstruction *ins, const ZydisDecodedOperand *ops) {
    int k;
    for (k = 0; k < ins->operand_count_visible; k++)
        if (ops[k].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[k].mem.segment == ZYDIS_REGISTER_FS) return 1;
    return 0;
}

/* Which original instruction a trampoline stands for (crash reports). */
#define AFW_MAX_STUB_NOTES 4096
static struct { const unsigned char *lo, *hi, *site; } g_notes[AFW_MAX_STUB_NOTES];
static int g_nnotes;
static void afw_stub_note(const unsigned char *stub, size_t len, const unsigned char *site) {
    if (g_nnotes < AFW_MAX_STUB_NOTES) {
        g_notes[g_nnotes].lo = stub; g_notes[g_nnotes].hi = stub + len; g_notes[g_nnotes].site = site; g_nnotes++;
    }
}
const void *afw_stub_origin(const void *pc) {
    int i;
    for (i = 0; i < g_nnotes; i++)
        if ((const unsigned char *)pc >= g_notes[i].lo && (const unsigned char *)pc < g_notes[i].hi)
            return g_notes[i].site;
    return NULL;
}

/* An instruction that may be copied into a trampoline: no branch, no r11,
 * no fs:, no syscall. rip-relative memory operands are allowed (disp32 is
 * re-based by copy_insn). */
static int tramp_movable(ZydisDecoder *dec, const unsigned char *q, const unsigned char *end, int *len) {
    ZydisDecodedInstruction n;
    ZydisDecodedOperand nops[ZYDIS_MAX_OPERAND_COUNT];
    int k;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(end - q), &n, nops))) return 0;
    *len = n.length;
    if (transfers_control(&n) || uses_r11(&n, nops) || has_fs_operand(&n, nops) || n.mnemonic == ZYDIS_MNEMONIC_SYSCALL)
        return 0;
    if (n.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
        for (k = 0; k < n.operand_count; k++)
            if (nops[k].type == ZYDIS_OPERAND_TYPE_MEMORY && nops[k].mem.base == ZYDIS_REGISTER_RIP) break;
        if (k == n.operand_count || n.raw.disp.size != 32) return 0;
    }
    return 1;
}

/* Copy one instruction from src to dst, re-basing a rip-relative disp32.
 * Returns 0, or -1 if the target is out of rel32 range. */
static int copy_insn(ZydisDecoder *dec, unsigned char *dst, const unsigned char *src) {
    ZydisDecodedInstruction n;
    ZydisDecodedOperand nops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, src, ZYDIS_MAX_INSTRUCTION_LENGTH, &n, nops))) return -1;
    memcpy(dst, src, n.length);
    if ((n.attributes & ZYDIS_ATTRIB_IS_RELATIVE) && n.raw.disp.size == 32) {
        int32_t d;
        int64_t nd;
        memcpy(&d, src + n.raw.disp.offset, 4);
        nd = (int64_t)d + (int64_t)((intptr_t)src - (intptr_t)dst);   /* same target from the new place */
        if (nd > INT32_MAX || nd < INT32_MIN) return -1;
        d = (int32_t)nd;
        memcpy(dst + n.raw.disp.offset, &d, 4);
    }
    return 0;
}

/* Can the fs:[reg] instruction at p be moved into a trampoline (design
 * section 6)? Takes the following instructions (and a final ret), then if
 * needed the preceding ones, until there are >= 5 bytes for "jmp rel32".
 * prev[]: up to 3 preceding instruction starts, nearest first (NULL ends).
 * Returns 1 and fills *f, or 0 with a reason. */
static int fs_reg_site(ZydisDecoder *dec, unsigned char *p, unsigned char *fstart, unsigned char *end,
                       unsigned char *const prev[3], const ZydisDecodedInstruction *ins,
                       const ZydisDecodedOperand *ops, int pred_first, fsite *f, const char **why) {
    int k, total = ins->length, cnt = 0, len;
    unsigned char *q = p + ins->length, *start = p;
    for (k = 0; k < ins->operand_count_visible; k++)
        if (ops[k].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[k].mem.segment == ZYDIS_REGISTER_FS) break;
    if (k == ins->operand_count_visible) { *why = "no fs: memory operand"; return 0; }
    if (ops[k].mem.index != ZYDIS_REGISTER_NONE) { *why = "fs:[base+index]: no room for the tp register"; return 0; }
    if (ops[k].mem.base == ZYDIS_REGISTER_NONE || ops[k].mem.base == ZYDIS_REGISTER_RSP ||
        ops[k].mem.base == ZYDIS_REGISTER_RIP || ops[k].mem.base == ZYDIS_REGISTER_R11 ||
        ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, ops[k].mem.base) != 64) {
        *why = "fs: base register cannot be an index"; return 0;
    }
    if (uses_r11(ins, ops)) { *why = "instruction uses r11"; return 0; }
    if (ins->attributes & ZYDIS_ATTRIB_IS_RELATIVE) { *why = "instruction is rip-relative"; return 0; }
    /* rsp is 136 bytes lower inside the stub (reviewer 3) */
    if (uses_rsp(ins, ops)) { *why = "instruction uses rsp (visible or implicit)"; return 0; }
    if (ins->mnemonic == ZYDIS_MNEMONIC_LEA) { *why = "lea ignores fs:, the rewrite would add tp"; return 0; }
    if (ins->address_width != 64) { *why = "32-bit address size (0x67 prefix)"; return 0; }
    if (transfers_control(ins)) { *why = "control transfer"; return 0; }
    f->ends_ret = 0;
    {
        int pass;
        for (pass = 0; pass < 2; pass++) {
            if ((pass == 0) == !pred_first) {       /* successors (a final plain ret may end the stub) */
                while (total < 5 && cnt < 3 && q < end && !f->ends_ret) {
                    if (*q == 0xC3) { total += 1; f->ends_ret = 1; break; }
                    if (!tramp_movable(dec, q, end, &len)) break;
                    total += len; q += len; cnt++;
                }
            } else {                                  /* predecessors */
                for (k = 0; total < 5 && k < 3 && prev[k] && prev[k] >= fstart; k++) {
                    if (prev[k] >= start) continue;
                    if (!tramp_movable(dec, prev[k], start, &len) || prev[k] + len != start) break;
                    total += len; start = prev[k];
                }
            }
        }
    }
    if (total < 5) { *why = "fewer than 5 movable bytes around it"; return 0; }
    f->start = start; f->pre_len = (int)(p - start); f->ins_len = ins->length;
    f->total = total;
    return 1;
}

/* Build the trampoline for one fs:[reg] site at stub; returns its length or
 * -1. tp comes from gs:[teb] (TEB slot 0). Nothing here changes RFLAGS. */
static int fs_reg_stub(ZydisDecoder *dec, const fsite *f, int32_t teb, unsigned char *stub, size_t room) {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisEncoderRequest req;
    unsigned char enc[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize elen = sizeof enc;
    const unsigned char *core = f->start + f->pre_len, *q;
    int k, o = 0;
    int64_t rel;
    if (room < 128) return -1;   /* longest stub: 3 moved instrs (45) + 21 fixed + 15 access + 5 */
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, core, (ZyanUSize)f->ins_len, &ins, ops))) return -1;
    if (!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(&ins, ops, ins.operand_count_visible, &req)))
        return -1;
    for (k = 0; k < req.operand_count; k++)
        if (req.operands[k].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            req.operands[k].mem.index = req.operands[k].mem.base;   /* TPOFF register */
            req.operands[k].mem.scale = 1;
            req.operands[k].mem.base = ZYDIS_REGISTER_R11;          /* tp */
        }
    req.prefixes &= ~(ZydisInstructionAttributes)ZYDIS_ATTRIB_HAS_SEGMENT_FS;
    if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, enc, &elen))) return -1;
    {   /* the re-encoded access must decode back to: same mnemonic, no fs:, [r11 + reg*1 + disp] */
        ZydisDecodedInstruction e;
        ZydisDecodedOperand eops[ZYDIS_MAX_OPERAND_COUNT];
        int m1, m2;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, enc, elen, &e, eops)) || e.mnemonic != ins.mnemonic ||
            (e.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS) || e.operand_count_visible != ins.operand_count_visible)
            return -1;
        for (m1 = 0; m1 < ins.operand_count_visible; m1++)
            if (ops[m1].type == ZYDIS_OPERAND_TYPE_MEMORY) break;
        for (m2 = 0; m2 < e.operand_count_visible; m2++)
            if (eops[m2].type == ZYDIS_OPERAND_TYPE_MEMORY) break;
        if (m1 == ins.operand_count_visible || m2 != m1 || eops[m2].mem.base != ZYDIS_REGISTER_R11 ||
            eops[m2].mem.index != ops[m1].mem.base || eops[m2].mem.scale != 1 ||
            eops[m2].mem.disp.value != ops[m1].mem.disp.value || eops[m2].size != ops[m1].size ||
            eops[m2].mem.segment == ZYDIS_REGISTER_FS)
            return -1;
    }
    for (q = f->start; q < core;) {                                      /* moved predecessors */
        int len;
        ZydisDecodedInstruction n;
        ZydisDecodedOperand nops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(core - q), &n, nops))) return -1;
        len = n.length;
        if (copy_insn(dec, stub + o, q)) return -1;
        o += len; q += len;
    }
    memcpy(stub + o, "\x48\x8D\x64\x24\x80", 5); o += 5;                 /* lea rsp, [rsp-128] (skip red zone) */
    stub[o++] = 0x41; stub[o++] = 0x53;                                  /* push r11 */
    memcpy(stub + o, "\x65\x4C\x8B\x1C\x25", 5); o += 5;                 /* mov r11, gs:[teb] = tp */
    memcpy(stub + o, &teb, 4); o += 4;
    memcpy(stub + o, enc, elen); o += (int)elen;                         /* the access, [r11 + reg + disp] */
    stub[o++] = 0x41; stub[o++] = 0x5B;                                  /* pop r11 */
    memcpy(stub + o, "\x48\x8D\xA4\x24\x80\x00\x00\x00", 8); o += 8;     /* lea rsp, [rsp+128] */
    for (q = core + f->ins_len; q < f->start + f->total;) {              /* moved successors */
        ZydisDecodedInstruction n;
        ZydisDecodedOperand nops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, q, (ZyanUSize)(f->start + f->total - q), &n, nops)))
            return -1;
        if (copy_insn(dec, stub + o, q)) return -1;
        o += n.length; q += n.length;
    }
    if (!f->ends_ret) {
        rel = (int64_t)((f->start + f->total) - (stub + o + 5));
        if (rel > INT32_MAX || rel < INT32_MIN) return -1;
        stub[o++] = 0xE9; { int32_t r32 = (int32_t)rel; memcpy(stub + o, &r32, 4); o += 4; }  /* jmp back */
    }
    return o;
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
    fsite2 *fsites = NULL;
    size_t nfsites = 0, capfsites = 0;
    unsigned char *stub_for[AFW_MAX_SYSCALL] = {0};
    size_t stub_used = 0;
    uint64_t entry = (uint64_t)(uintptr_t)afw_syscall_entry;
    int r, fatal = 0;
    char where[160];
    unsigned char **maps = (unsigned char **)calloc(nranges ? (size_t)nranges : 1, sizeof *maps);
    int *undecided = (int *)calloc(nranges ? (size_t)nranges : 1, sizeof *undecided);
    const unsigned char **whys = (const unsigned char **)calloc(nranges ? (size_t)nranges : 1, sizeof *whys);
    unsigned char **maps0 = (unsigned char **)calloc(nranges ? (size_t)nranges : 1, sizeof *maps0);  /* before attestations */
    unsigned char attest_used[64] = {0};   /* which attestations were looked at (all must be) */

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
            map = maps[r] = reach_map(&dec, p, ranges[r].size, &undecided[r], &why, pads, npads,
                                      c, &targets, &ntargets, &captargets);
            {
                int q;
                for (q = 0; q < npads; q++)       /* landing pads and attested targets are targets too */
                    VEC_PUSH(targets, ntargets, captargets, pads[q]);
            }
            /* attestations for jumps inside this function: verify, then re-run the
             * analysis with the attested table targets as extra entry points */
            if (undecided[r] && c->nattest) {
                int a, added = 0, last_a = 0;
                for (a = 0; a < c->nattest; a++) {
                    const char *awhy = "";
                    unsigned char *J = (unsigned char *)(c->bias + (intptr_t)c->attest[a].jmp_rva);
                    int k;
                    if (J < p || J >= end) continue;
                    if (a < 64) attest_used[a] = 1;
                    if (c->attest_dump) attest_dump(&dec, c, p, ranges[r].size, map, &c->attest[a]);
                    k = attest_verify(&dec, c, p, ranges[r].size, map, &c->attest[a], pads + npads, 1024 - npads,
                                      targets, ntargets, undecided[r], why, &awhy);
                    describe(c, J, where, sizeof where);
                    if (k < 0) {
                        rep->attest_rejected++;
                        fprintf(stderr, "  [attest] REJECTED for the jump at %s: %s (%s) - not used\n", where, awhy,
                                c->attest[a].note ? c->attest[a].note : "");
                        continue;
                    }
                    rep->attest_applied++;
                    fprintf(stderr, "  [attest] applied for the jump at %s: %d table entries verified (%s)\n", where, k,
                            c->attest[a].note ? c->attest[a].note : "");
                    npads += k; added += k; last_a = a;
                }
                if (added) {
                    int und2 = 0;
                    const unsigned char *why2 = NULL;
                    unsigned char *m2 = reach_map(&dec, p, ranges[r].size, &und2, &why2, pads, npads,
                                                  c, &targets, &ntargets, &captargets);
                    int q2;
                    for (q2 = npads - added; q2 < npads; q2++)   /* the jump lands there: branch targets */
                        VEC_PUSH(targets, ntargets, captargets, pads[q2]);
                    if (!m2) { fprintf(stderr, "  [attest] FATAL: out of memory re-running the analysis\n"); fatal = 1; }
                    else if (und2 != 1 || why2 == NULL ||
                             (uint64_t)(uintptr_t)why2 != (uint64_t)(c->bias + (intptr_t)c->attest[last_a].jmp_rva)) {
                        /* code reached through the attested entries has ANOTHER unresolved
                         * indirect jump: it could land in the chain - the attestation fails */
                        free(m2);
                        rep->attest_applied--; rep->attest_rejected++;
                        describe(c, p, where, sizeof where);
                        fprintf(stderr, "  [attest] REJECTED in the function at %s: code reached through the attested "
                                        "entries has another unresolved indirect jump - not used\n", where);
                    } else { maps0[r] = map; map = maps[r] = m2; undecided[r] = und2; why = why2; }
                }
            }
            if (lsda_failed && !undecided[r]) { undecided[r] = 1; why = NULL; }
            if (whys) whys[r] = undecided[r] ? why : NULL;
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
                    if (inside) {
                        fsite fx;
                        const char *why = "";
                        rep->fs_reg_in_func++;
                        unsigned char *prev[3] = {h[0].p, h[1].p, h[2].p};
                        fsite2 f2;
                        f2.nopt = 0;
                        if (fs_reg_site(&dec, p, ranges[r].addr, end, prev, &ins, ops, 0, &f2.opt[0], &why))
                            f2.nopt++;
                        if (fs_reg_site(&dec, p, ranges[r].addr, end, prev, &ins, ops, 1, &f2.opt[f2.nopt], &why) &&
                            (f2.nopt == 0 || f2.opt[1].start != f2.opt[0].start || f2.opt[1].total != f2.opt[0].total))
                            f2.nopt++;
                        if (f2.nopt) fx = f2.opt[0];
                        if (f2.nopt) {
                            rep->fs_reg_feasible++;
                            VEC_PUSH(fsites, nfsites, capfsites, f2);
                            if (verbose) fprintf(stderr, "  [patch] fs:[reg] at %s: ELF TLS access, trampoline "
                                                         "(%d bytes moved%s)\n", where, fx.total,
                                                 fx.ends_ret ? ", ends with ret" : "");
                        } else {
                            rep->fs_unsupported++;
                            fprintf(stderr, "  [patch] fs:[reg] at %s: REFUSED (%s); library will not be run\n",
                                    where, why);
                            dump_ins(p, &ins, ops);
                        }
                    } else {
                        rep->fs_reg_outside++;
                        fprintf(stderr, "  [patch] fs:[reg] at %s: outside every known function - data decoded "
                                        "as code, ignored\n", where);
                        dump_ins(p, &ins, ops);
                    }
                    continue;
                }
                rep->fs_disp_seen++;
                {
                    int64_t d0 = ops[k].mem.disp.value;
                    /* only an exact plain READ counts as a read: CONDWRITE (cmpxchg), READWRITE
                     * and 0 (lea, nop [mem]) are all refused (reviewer 3) */
                    int w = ops[k].actions != ZYDIS_OPERAND_ACTION_READ, q;
                    for (q = 0; q < rep->nfs_kind; q++)
                        if (rep->fs_kind[q].disp == d0 && rep->fs_kind[q].mnemonic == (int)ins.mnemonic &&
                            rep->fs_kind[q].write == w) break;
                    if (q == rep->nfs_kind && q < (int)(sizeof rep->fs_kind / sizeof rep->fs_kind[0])) {
                        rep->fs_kind[q].disp = d0; rep->fs_kind[q].mnemonic = (int)ins.mnemonic;
                        rep->fs_kind[q].write = w; rep->fs_kind[q].count = 0; rep->nfs_kind++;
                    }
                    if (q < rep->nfs_kind) rep->fs_kind[q].count++;
                    /* measured: real code only READS tp (fs:[0]) and the stack guard
                     * (fs:[0x28]), both constant per thread, so a per-thread copy in
                     * the TEB is exact. Anything else is not proven: block loading. */
                    if (w || (d0 != 0 && d0 != 0x28)) {
                        rep->fs_unsupported++;
                        describe(c, p, where, sizeof where);
                        fprintf(stderr, "  [patch] fs: access at %s is %s fs:[0x%llx]: not supported, "
                                        "library will not be run\n", where, w ? "a WRITE to" : "a read of",
                                (long long)d0);
                        dump_ins(p, &ins, ops);
                    }
                }
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
                    /* not inside a known function: may be data, so its bytes are not
                     * changed - but the library will not be run (load gate) */
                    rep->sys_untouched++;
                    describe(c, p, where, sizeof where);
                    fprintf(stderr, "  [patch] syscall bytes at %s are outside every known function: "
                                    "not touched, library will not be run\n", where);
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
                    fprintf(stderr, "  [patch] REFUSED syscall at %s: nothing safe to move before it (now ud2)\n", where);
                    trap_syscall(p, rep);
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
    if (c && c->nattest) {                 /* an attestation nobody used is stale: it counts as rejected */
        int a;
        for (a = 0; a < c->nattest; a++)
            if (a >= 64 || !attest_used[a]) {
                rep->attest_rejected++;
                fprintf(stderr, "  [attest] REJECTED: the jump at %s+0x%llx is not in any function the analysis "
                                "left undecided - stale attestation (%s)\n", c->name ? c->name : "lib",
                        (long long)c->attest[a].jmp_rva, c->attest[a].note ? c->attest[a].note : "");
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
            fprintf(stderr, "  [patch] REFUSED syscall at %s: a branch lands inside the site (now ud2)\n", where);
            trap_syscall(s->start + s->len - 2, rep);
            continue;
        }
        if (!c || !c->bounds || !c->bounds(c->ctx, lo, &fs_, &fe_)) {
            rep->sys_refused_unknown++;
            fprintf(stderr, "  [patch] REFUSED syscall at %s: function boundaries unknown (now ud2)\n", where);
            trap_syscall(s->start + s->len - 2, rep);
            continue;
        }
        if ((r = function_uses_red_zone(&dec, fs_, fe_)) != 0) {
            rep->sys_refused_redzone++;
            if (r == 1) rep->redzone_direct++; else rep->redzone_via_copy++;
            fprintf(stderr, "  [patch] REFUSED syscall at %s: its function may use the red zone (now ud2)\n", where);
            trap_syscall(s->start + s->len - 2, rep);
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

    /* Pass 2b: fs:[reg] trampolines (design section 6).
     * Plan first, write after: a layout must have no branch target inside,
     * must not overlap any syscall site (its bytes were rewritten in pass 2)
     * nor another fs:[reg] site's chosen layout (reviewer 3). If a site has
     * no free layout, the previous site may switch to its other layout. */
    {
        int *pick = (int *)malloc((nfsites ? nfsites : 1) * sizeof *pick);
        int32_t teb = afw_tls_teb_offset(0);
        size_t j;
        if (!pick) fatal = 1;
        for (i = 0; i < nfsites && !fatal; i++) {
            int o, ok = -1;
            pick[i] = -1;
            for (o = 0; o < fsites[i].nopt && ok < 0; o++) {
                const fsite *f = &fsites[i].opt[o];
                uint64_t lo = (uint64_t)(uintptr_t)f->start, hi = lo + (uint64_t)f->total;
                int clash = target_inside(targets, ntargets, lo, hi);
                for (j = 0; j < nsites && !clash; j++)
                    clash = lo < (uint64_t)(uintptr_t)(sites[j].start + sites[j].len) &&
                            (uint64_t)(uintptr_t)sites[j].start < hi;
                if (!clash && i > 0 && pick[i - 1] >= 0) {
                    const fsite *g = &fsites[i - 1].opt[pick[i - 1]];
                    clash = lo < (uint64_t)(uintptr_t)(g->start + g->total) && (uint64_t)(uintptr_t)g->start < hi;
                    if (clash && fsites[i - 1].nopt == 2) {      /* one step back: can the previous move? */
                        const fsite *g2 = &fsites[i - 1].opt[1 - pick[i - 1]];
                        uint64_t l2 = (uint64_t)(uintptr_t)g2->start, h2 = l2 + (uint64_t)g2->total;
                        int c2 = target_inside(targets, ntargets, l2, h2) || (lo < h2 && l2 < hi);
                        for (j = 0; j < nsites && !c2; j++)
                            c2 = l2 < (uint64_t)(uintptr_t)(sites[j].start + sites[j].len) &&
                                 (uint64_t)(uintptr_t)sites[j].start < h2;
                        if (!c2 && i > 1 && pick[i - 2] >= 0) {
                            const fsite *g3 = &fsites[i - 2].opt[pick[i - 2]];
                            c2 = l2 < (uint64_t)(uintptr_t)(g3->start + g3->total) &&
                                 (uint64_t)(uintptr_t)g3->start < h2;
                        }
                        if (!c2) { pick[i - 1] = 1 - pick[i - 1]; clash = 0; }
                    }
                }
                if (!clash) ok = o;
            }
            pick[i] = ok;
            if (ok < 0) {
                describe(c, fsites[i].opt[0].start + fsites[i].opt[0].pre_len, where, sizeof where);
                rep->fs_reg_feasible--; rep->fs_unsupported++;
                fprintf(stderr, "  [patch] fs:[reg] at %s: REFUSED (every layout has a branch target inside or "
                                "overlaps another rewritten site); library will not be run\n", where);
            }
        }
        for (i = 0; i < nfsites && !fatal && teb >= 0; i++) {   /* not Windows: planned, never written */
            fsite *f;
            int len, k;
            int64_t rel;
            if (pick[i] < 0) continue;
            f = &fsites[i].opt[pick[i]];
            describe(c, f->start + f->pre_len, where, sizeof where);
            if (stub_used >= stub_size) { fprintf(stderr, "  [patch] FATAL: stub area full\n"); fatal = 1; break; }
            len = fs_reg_stub(&dec, f, teb, stub_area + stub_used, stub_size - stub_used);
            if (len < 0) {
                rep->fs_reg_feasible--; rep->fs_unsupported++;
                fprintf(stderr, "  [patch] fs:[reg] at %s: REFUSED (could not build or verify the trampoline)\n",
                        where);
                continue;
            }
            rel = (int64_t)((intptr_t)(stub_area + stub_used) - (intptr_t)(f->start + 5));
            if (rel > INT32_MAX || rel < INT32_MIN) { fatal = 1; break; }
            f->start[0] = 0xE9; { int32_t r32 = (int32_t)rel; memcpy(f->start + 1, &r32, 4); }  /* jmp stub */
            for (k = 5; k < f->total; k++) f->start[k] = 0xCC;                                 /* never run */
            afw_stub_note(stub_area + stub_used, (size_t)len, f->start + f->pre_len);
            stub_used += ((size_t)len + 15) & ~(size_t)15;
            rep->stubs++;
            rep->fs_reg_trampolined++;
        }
        free(pick);
    }
    free(fsites);

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
                    } else if (maps0[found] && maps[found] && maps[found][p - ranges[found].addr] == 1 &&
                               maps0[found][p - ranges[found].addr] != 1) {
                        /* reached only because of an attestation: handled, but say so every time (reviewer 2) */
                        rep->via_attestation++;
                        describe(c, p, where, sizeof where);
                        fprintf(stderr, "  [audit] ATTESTED: %s-looking bytes at %s are reached only through attested "
                                        "table entries (not proven; handled like any reached site)\n",
                                is_sys ? "syscall" : "fs:", where);
                    } else if (maps[found] && maps[found][p - ranges[found].addr] != 1) {
                        describe(c, p, where, sizeof where);
                        if (undecided[found]) {
                            rep->unproven++;
                            fprintf(stderr, "  [audit] UNPROVEN: %s-looking bytes at %s, in a function with an unresolved "
                                            "indirect jump: not touched\n", is_sys ? "syscall" : "fs:", where);
                            unproven_detail(&dec, c, ranges[found].addr, ranges[found].size, maps[found],
                                            whys ? whys[found] : NULL, p, is_sys);
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
    for (r = 0; r < nranges; r++) { free(maps[r]); free(maps0[r]); }
    free(maps0);
    free(maps); free(undecided); free((void *)whys);

    free(targets); free(sites);
    if (fatal) return -1;
    return (rep->sys_refused_branch || rep->sys_refused_redzone || rep->sys_refused_unknown) ? 1 : 0;
}

const char *afw_mnemonic_name(int mnemonic) {
    const char *n = ZydisMnemonicGetString((ZydisMnemonic)mnemonic);
    return n ? n : "?";
}
