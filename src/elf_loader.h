/*
 * elf_loader.h - Loads an Android shared library (.so) into a normal
 * Windows process, without any Android system underneath.
 */
#ifndef AFW_ELF_LOADER_H
#define AFW_ELF_LOADER_H

#include <stddef.h>
#include <stdint.h>
#include "elf.h"
#include "patch.h"

#define AFW_MAX_NEEDED 32

typedef struct afw_lib_s {
    const char *path;
    unsigned char *base;        /* where the library lives in memory */
    size_t size;
    intptr_t bias;              /* base - lowest virtual address */

    Elf64_Dyn *dynamic;
    const char *strtab;
    Elf64_Sym *symtab;
    size_t nsyms;

    const char *soname;
    const char *needed[AFW_MAX_NEEDED];
    int nneeded;

    /* constructors / destructors */
    uint64_t init, fini;
    uint64_t *init_array, *fini_array;
    size_t init_array_count, fini_array_count;

    /* load-time patching */
    unsigned char *stub_area;
    const unsigned char *eh_frame_hdr;   /* for function boundaries */
    uint64_t xsec_vaddr[16], xsec_size[16]; /* SHF_EXECINSTR sections */
    int nxsec;
    afw_patch_report patch;

    int tls_module;
    /* IRELATIVE relocations, run only after the code is patched and executable */
    struct { uint64_t *where; uint64_t resolver; } *irel;
    size_t nirel, capirel;             /* 1-based static TLS module id, 0 = no PT_TLS */

    /* report */
    int nrelocs;
    int nimports_shimmed;
    int nimports_missing;
    int nimports_weak_null;
    int nexports;
} afw_lib;

/* Measurement mode: map, link and patch a library but never run it
 * (no constructors; relocation formats we do not support yet are skipped
 * with a warning). Used to measure patching on real Android libraries. */
extern int afw_load_patch_only;

/* Normal loading refuses a library whose patching left anything unproven
 * (look-alikes in undecided functions, undecodable exception tables). This
 * flag overrides that, for diagnosis only. */
extern int afw_load_allow_unproven;

/* The load gate: 1 if patching left the library provably safe to run.
 * Blocks on: unproven look-alikes, undecodable exception tables, syscall
 * bytes that were neither patched nor turned into ud2, syscall bytes in
 * executable sections outside every known function. */
int afw_gate_ok(const afw_lib *lib);

/* Load, relocate, link against bionic-win and run constructors.
 * Returns 0 on success; prints the reason on failure. */
int afw_load(const char *path, afw_lib *lib, int verbose);

/* Find an exported symbol (like dlsym). */
void *afw_sym(const afw_lib *lib, const char *name);

/* Describe an address: "libfoo.so+0x1234 (near some_function)".
 * Returns 0 if the address is not inside any loaded library. */
int afw_describe_address(uintptr_t addr, char *out, size_t outsz);

/* Run destructors. */
void afw_unload(afw_lib *lib);

#endif
