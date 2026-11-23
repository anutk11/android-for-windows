/*
 * exec.h - start a loaded Android executable at its entry point (exec.c).
 */
#ifndef AFW_EXEC_H
#define AFW_EXEC_H
#include "elf_loader.h"

/* Build the executable's full auxv and install it into libc_shared_globals.
 * Called by the loader after Phase A mapping and BEFORE Phase B constructors
 * so libc.so and executable constructors see the complete auxv. */
void afw_exec_prepare_auxv(const afw_lib *exe, const char *execfn);

/* Builds the kernel's initial stack (argc, argv, envp, auxv) and jumps to
 * the executable's entry. envp may be NULL (treated as empty). The program
 * ends the process through exit(); returns -1 only if it could not start. */
int afw_exec(const afw_lib *exe, int argc, char **argv, char **envp);
#endif
