/*
 * funcs.h - Function boundaries of a loaded library.
 *
 * Source of truth: the .eh_frame unwind tables (via .eh_frame_hdr), which
 * every NDK library has, stripped or not. Each FDE gives the exact
 * [start, end) of one function. Fallback: exported symbols with st_size.
 */
#ifndef AFW_FUNCS_H
#define AFW_FUNCS_H

#include <stddef.h>
#include <stdint.h>

struct afw_lib_s;

/* Find the function containing addr. Returns 1 and sets [*start, *end) on
 * success, 0 if no function is known to contain it. */
int afw_func_bounds(const struct afw_lib_s *lib, uint64_t addr, uint64_t *start, uint64_t *end);

/* All functions listed in .eh_frame_hdr, as code ranges (malloc'ed array,
 * caller frees). Returns the count; 0 if the library has no such table. */
int afw_func_list(const struct afw_lib_s *lib, unsigned char ***starts, size_t **sizes);

#endif
