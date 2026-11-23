/*
 * exec.h - start a loaded Android executable at its entry point (exec.c).
 */
#ifndef AFW_EXEC_H
#define AFW_EXEC_H
#include "elf_loader.h"

/* Builds the kernel's initial stack (argc, argv, envp, auxv) and jumps to
 * the executable's entry. The program ends the process through exit();
 * returns -1 only if it could not start. */
int afw_exec(const afw_lib *exe, int argc, char **argv);
#endif
