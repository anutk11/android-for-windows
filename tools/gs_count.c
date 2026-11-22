/*
 * gs_count.c - count %gs: / %fs: accesses in the executable sections of an
 * ELF file, decoding them as code with Zydis (issue #15, G3 planning).
 *
 * Why not objdump: a boot .oat file keeps its code under one OBJECT symbol
 * (oatexec), so objdump prints it as data. This tool ignores symbols and
 * sweeps every SHF_EXECINSTR section linearly. A .oat text section has
 * method headers between methods, so for .oat files the counts are an
 * APPROXIMATION (a linear sweep may decode some data as instructions).
 *
 * usage: gs_count <file> [label]          prints counts only, no bytes
 */
#include <Zydis/Zydis.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/elf.h"

#define MAXD 4096
typedef struct { int64_t disp; long n; } dcount;

typedef struct {
    long total, read, write, call, jmp, lea, regbased;
    dcount d[MAXD];
    int nd;
    long d_overflow;
} seg_stats;

static void add_disp(seg_stats *s, int64_t disp) {
    int i;
    for (i = 0; i < s->nd; i++) if (s->d[i].disp == disp) { s->d[i].n++; return; }
    if (s->nd < MAXD) { s->d[s->nd].disp = disp; s->d[s->nd].n = 1; s->nd++; }
    else s->d_overflow++;
}

static int by_count(const void *a, const void *b) {
    long x = ((const dcount *)a)->n, y = ((const dcount *)b)->n;
    return (y > x) - (y < x);
}

static void print(const char *name, seg_stats *s) {
    int i;
    if (!s->total) return;
    printf("--- %%%s: %ld accesses: read %ld, write %ld, indirect call %ld, indirect jmp %ld, "
           "lea (no access) %ld; register-based %ld\n",
           name, s->total, s->read, s->write, s->call, s->jmp, s->lea, s->regbased);
    qsort(s->d, (size_t)s->nd, sizeof s->d[0], by_count);
    printf("--- %%%s: %d distinct fixed displacements%s; most used:\n", name, s->nd,
           s->d_overflow ? " (table full)" : "");
    for (i = 0; i < s->nd && i < 12; i++) printf("  %8ld  %s:0x%llx\n", s->d[i].n, name, (unsigned long long)s->d[i].disp);
}

int main(int argc, char **argv) {
    FILE *f;
    long size;
    unsigned char *buf;
    const Elf64_Ehdr *eh;
    const Elf64_Shdr *sh;
    ZydisDecoder dec;
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    seg_stats gs, fs;
    long insns = 0, bad = 0;
    int i, k;

    if (argc < 2) { fprintf(stderr, "usage: gs_count <file> [label]\n"); return 2; }
    f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, 0, SEEK_SET);
    buf = (unsigned char *)malloc((size_t)size);
    if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size) { fprintf(stderr, "read failed\n"); return 1; }
    fclose(f);
    eh = (const Elf64_Ehdr *)buf;
    if (size < (long)sizeof *eh || memcmp(eh->e_ident, "\x7f" "ELF", 4) != 0 || eh->e_shentsize != sizeof(Elf64_Shdr) ||
        eh->e_shoff > (uint64_t)size || (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > (uint64_t)size - eh->e_shoff) {
        fprintf(stderr, "%s: not an ELF64 file with section headers\n", argv[1]);
        return 1;
    }
    sh = (const Elf64_Shdr *)(buf + eh->e_shoff);
    memset(&gs, 0, sizeof gs); memset(&fs, 0, sizeof fs);
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    for (i = 0; i < eh->e_shnum; i++) {
        const unsigned char *p, *end;
        if (!(sh[i].sh_flags & 0x4) || sh[i].sh_type != 1) continue;        /* SHF_EXECINSTR, PROGBITS */
        if (sh[i].sh_offset > (uint64_t)size || sh[i].sh_size > (uint64_t)size - sh[i].sh_offset) continue;
        p = buf + sh[i].sh_offset;
        end = p + sh[i].sh_size;
        while (p < end) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, (ZyanUSize)(end - p), &ins, ops))) { p++; bad++; continue; }
            insns++;
            for (k = 0; k < ins.operand_count_visible; k++) {
                seg_stats *s;
                if (ops[k].type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
                if (ops[k].mem.segment == ZYDIS_REGISTER_GS) s = &gs;
                else if (ops[k].mem.segment == ZYDIS_REGISTER_FS) s = &fs;
                else continue;
                s->total++;
                if (ins.mnemonic == ZYDIS_MNEMONIC_LEA) s->lea++;
                else if (ins.mnemonic == ZYDIS_MNEMONIC_CALL) s->call++;
                else if (ins.mnemonic == ZYDIS_MNEMONIC_JMP) s->jmp++;
                else if (ops[k].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) s->write++;
                else s->read++;
                if (ops[k].mem.base != ZYDIS_REGISTER_NONE || ops[k].mem.index != ZYDIS_REGISTER_NONE) s->regbased++;
                else add_disp(s, ops[k].mem.disp.value);
            }
            p += ins.length;
        }
    }
    printf("=== %s: %ld instructions decoded (%ld undecodable bytes skipped), %ld %%gs:, %ld %%fs:\n",
           argc > 2 ? argv[2] : argv[1], insns, bad, gs.total, fs.total);
    print("gs", &gs);
    print("fs", &fs);
    free(buf);
    return 0;
}
