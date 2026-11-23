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

#define AFW_BUILD_ID_HEX 65
/* the only libc.so whose libc_shared_globals layout is measured (tools/fetch_bionic.py pins it) */
#define AFW_SHARED_GLOBALS_BUILD_ID "fa337969c798946280caa45e2d71a2e7"

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

    char build_id[AFW_BUILD_ID_HEX];
    Elf64_Phdr *phdr;           /* a copy of the program headers (dl_iterate_phdr) */
    int path_owned;             /* path was allocated for this library (dependencies) */
    int phnum;   /* NT_GNU_BUILD_ID, hex; "" if none */

    /* phase A done, phase B (TLS close, IFUNC, RELRO, constructors) not yet */
    int pending;
    int code_ran;               /* IFUNC resolver or constructor started: past rollback point */
    int quarantined;            /* retained past point of no return (never freed/unmapped) */
    struct afw_lib_s *quarantine_next;   /* intrusive quarantine list (zero-alloc, unbounded) */
    int vma_adopted;            /* the image is registered with the VMA layer (6e) */
    unsigned char *pageprot;
    size_t npages, relro_first, relro_last;

    /* report */
    int nrelocs;
    int nimports_shimmed;
    int nimports_linked;        /* resolved against another loaded library */
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
/* How many libraries are registered (tests: a failed load must not count). */
int afw_loaded_count(void);
/* How many failed libraries are quarantined (past point of no return: TLS
 * already closed or code already ran, so mapping/TLS/struct stay live). */
int afw_quarantined_count(void);
const afw_lib *afw_quarantined_at(int k);

/* The load gate: 1 if patching left the library provably safe to run.
 * Blocks on: unproven look-alikes, undecodable exception tables, syscall
 * bytes that were neither patched nor turned into ud2, syscall bytes in
 * executable sections outside every known function. */
int afw_gate_ok(const afw_lib *lib);

/* Load, relocate, link against bionic-win and run constructors.
 * Returns 0 on success; prints the reason on failure. */
int afw_load(const char *path, afw_lib *lib, int verbose);
/* Load path after its DT_NEEDED libraries (found next to it or in
 * AFW_LIB_PATH), dependencies first; each one's imports resolve against the
 * libraries loaded before it, then bionic-win. deps[] receives the loaded
 * dependencies (*ndeps counts them). */
int afw_load_with_deps(const char *path, afw_lib *lib, afw_lib *deps, int maxdeps, int *ndeps, int verbose);

/* The registry of loaded libraries, for the linker API (loader_api.c). */
afw_lib *afw_lib_at(int k);                        /* k-th in load order, or NULL */
afw_lib *afw_find_loaded(const char *name);        /* by soname or file name */
int afw_is_loaded(const void *handle);
int afw_is_retained(const void *handle);           /* loaded OR quarantined: do not free */
void *afw_global_sym(const char *name);            /* RTLD_DEFAULT */
int afw_find_lib(const char *name, char *out, size_t outsz);

/* Find an exported symbol (like dlsym). */
void *afw_sym(const afw_lib *lib, const char *name);

/* Describe an address: "libfoo.so+0x1234 (near some_function)".
 * Returns 0 if the address is not inside any loaded library. */
int afw_describe_address(uintptr_t addr, char *out, size_t outsz);

/* Run destructors. */
void afw_unload(afw_lib *lib);

#ifdef AFW_TEST
/* Test hook: fail the nth next afw_vma_adopt() in lib_finish() with -ENOMEM (0 = off). */
void afw_load_test_fail_adopt(int nth);
#endif

#endif
