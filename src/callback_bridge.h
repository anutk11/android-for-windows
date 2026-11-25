/*
 * callback_bridge.h - Loader-to-guest callback trampoline with DWARF .eh_frame.
 *
 * When guest DSO A calls into loader-provided callback glue which invokes guest
 * DSO B, an exception thrown in DSO B must unwind cleanly through the loader
 * bridge frame back into DSO A's catch handler without crossing an opaque host
 * PE frame (which has no DWARF .eh_frame).
 *
 * This module lazily allocates a single 4KB W^X RX page holding:
 *   +0x000: 14-byte SysV x86-64 bridge trampoline:
 *           int __loader_afw_callback_bridge(int (*cb)(void *), void *arg)
 *   +0x100: DWARF .eh_frame (CIE + FDE + 0 terminator) describing the bridge frame
 *   +0x200: .eh_frame_hdr (version 1, 1 FDE entry) for O(1) lookup by libunwind
 *
 * Exposed to libunwind via a synthetic "[afw-callback-bridge]" entry in
 * afw_l_dl_iterate_phdr() (PT_LOAD RX + PT_GNU_EH_FRAME).
 */
#ifndef AFW_CALLBACK_BRIDGE_H
#define AFW_CALLBACK_BRIDGE_H

#include <stdint.h>
#include "elf.h"

#define AFW_CALLBACK_BRIDGE_CODE_OFF   0x000u
#define AFW_CALLBACK_BRIDGE_CODE_SIZE  14u
#define AFW_CALLBACK_BRIDGE_EH_OFF     0x100u
#define AFW_CALLBACK_BRIDGE_EH_HDR_OFF 0x200u
#define AFW_CALLBACK_BRIDGE_EH_HDR_SZ  20u

/* Lazily initialize (thread-safe under afw_dlopen_lock) and return the RX
 * entry address of the System V callback bridge trampoline, or NULL on OOM. */
void *afw_callback_bridge_entry(void);

/* If the callback bridge has been initialized, populate the synthetic
 * dl_iterate_phdr fields (dlpi_addr, dlpi_name, dlpi_phdr, dlpi_phnum) and
 * return 1. Otherwise return 0 without initializing it. Lock-free. */
int afw_callback_bridge_phdr(uint64_t *addr_out, const char **name_out,
                             const Elf64_Phdr **phdr_out, uint16_t *phnum_out);

#endif
