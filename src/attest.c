/*
 * attest.c - attestations (allowlist) for jump tables that the analysis
 * cannot bound, docs/unproven/ and issue #2.
 *
 * Each record is pinned to one exact binary by the sha256 of the file the
 * loader read (computed on that buffer, before anything is mapped or
 * patched). It claims only: "entries [0, k) of this table, used by this
 * jump, are code addresses". The loader re-verifies the jump, the lea of
 * the table and every entry at each load (patch.c, attest_verify) and uses
 * the entries only as extra entry points. Sites reached that way are
 * reported as ATTESTED, never as proven. A different binary gets nothing.
 *
 * Signers: listed per record. Adding or changing a record needs the
 * written approval of all three reviewers (docs/COLLABORATION.md, rule 6).
 */
#include "attest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *sha256;
    afw_attest a;
} record;

/* linker64, Android 14 UE1A.230829.036.A1 x86_64 (provenance-scan.txt) */
#define LINKER64 "c5f2d0e1e2c6104d3c30a6169bee9363f16ad1a658ab1bc375e93bbcc6842bd3"
/* libc++_shared.so from the pinned NDK (android-lib job) */
#define LIBCXX   "7918ebd0b8074c312d0c610205d49760b98c008026e6b817cd92103a3e12241b"

static const record g_records[] = {
    {LINKER64, {0x8088c, 0xd940, 6, "linker64 table 0xd940: entries 0-5 (sites 0x808da = entry 3, 0x80914 = entry 5)"}},
    {LINKER64, {0x96c15, 0x105a4, 8, "linker64 table 0x105a4: entries 0-7 (site 0x96c3d = entry 0)"}},
    {LIBCXX,   {0xd4635, 0x593d8, 6, "libc++ table 0x593d8: entries 0-5 (sites 0xd4acd..0xd4b30 via case blocks)"}},
    {LIBCXX,   {0xd54f2, 0x59450, 6, "libc++ table 0x59450: entries 0-5 (site 0xd5556 = entry 0)"}},
};

#ifdef AFW_TEST
static const char *g_tamper = "none";
void afw_attest_set_tamper(const char *what) { g_tamper = what; }
static afw_attest g_extra[4];
static int g_nextra;
int afw_attest_add_test(const char *spec) {      /* "jmp_rva,table_rva,k" for any binary */
    unsigned long long j, t;
    int k;
    if (g_nextra == 4 || sscanf(spec, "%llx,%llx,%d", &j, &t, &k) != 3) return -1;
    g_extra[g_nextra].jmp_rva = j; g_extra[g_nextra].table_rva = t; g_extra[g_nextra].k = k;
    g_extra[g_nextra].note = "test attestation from the command line";
    g_nextra++;
    return 0;
}
#define TAMPER(x) (!strcmp(g_tamper, x))
#else
#define TAMPER(x) 0
#endif

const afw_attest *afw_attest_for(const char *sha256_hex, afw_attest *buf, int max, int *n) {
    int i, m = 0;
    *n = 0;
    if (TAMPER("hash")) return NULL;   /* as if the binary differed by one byte */
    for (i = 0; i < (int)(sizeof g_records / sizeof g_records[0]); i++) {
        if (strcmp(g_records[i].sha256, sha256_hex) != 0) continue;
        if (m == max) {
            fprintf(stderr, "error: more attestations for this binary than the loader holds\n");
            *n = -1;
            return NULL;
        }
        buf[m] = g_records[i].a;
        if (TAMPER("jmp")) buf[m].jmp_rva += 1;
        else if (TAMPER("table")) buf[m].table_rva += 4;
        else if (TAMPER("k")) buf[m].k += 1;
        m++;
    }
#ifdef AFW_TEST
    for (i = 0; i < g_nextra && m < max; i++) buf[m++] = g_extra[i];
#endif
    *n = m;
    return m ? buf : NULL;
}
