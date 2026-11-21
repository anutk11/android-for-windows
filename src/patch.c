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
            } else {
                for (i = 0; i < ins.operand_count_visible; i++) {
                    if (ops[i].type != ZYDIS_OPERAND_TYPE_MEMORY || ops[i].mem.disp.value >= 0) continue;
                    if (ops[i].mem.base == ZYDIS_REGISTER_RSP) return 1;
                    for (k = 0; k < ncopies; k++)
                        if (ops[i].mem.base == copies[k]) return 1;
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

    memset(rep, 0, sizeof *rep);
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    /* Pass 1: decode everything; collect branch targets and syscall sites;
     * rewrite fs:[disp32] directly (same length, neighbours untouched). */
    for (r = 0; r < nranges; r++) {
        unsigned char *p = ranges[r].addr, *end = p + ranges[r].size;
        hist h[3] = {{0}};
        int prev_mov_eax = 0;
        uint32_t prev_imm = 0;
        while (p < end) {
            uint64_t ip = (uint64_t)(uintptr_t)p;
            int k, movable;
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
                site s;
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
        if (function_uses_red_zone(&dec, fs_, fe_)) {
            rep->sys_refused_redzone++;
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

    free(targets); free(sites);
    if (fatal) return -1;
    return (rep->sys_refused_branch || rep->sys_refused_redzone || rep->sys_refused_unknown) ? 1 : 0;
}
