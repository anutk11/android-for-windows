/*
 * funcs.h - Function boundaries of a loaded library.
 *
 * Source of truth: the .eh_frame unwind tables (via .eh_frame_hdr), which
 * every NDK library has, stripped or not. Each FDE gives the exact
 * [start, end) of one function. Fallback: exported symbols with st_size.
 */
#ifndef AFW_FUNCS_H
#define AFW_FUNCS_H

#include <stdint.h>

struct afw_lib_s;

/* Find the function containing addr. Returns 1 and sets [*start, *end) on
 * success, 0 if no function is known to contain it. */
int afw_func_bounds(const struct afw_lib_s *lib, uint64_t addr, uint64_t *start, uint64_t *end);

#endif
