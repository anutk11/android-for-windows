/*
 * callback_bridge.c - DWARF-unwound SysV callback bridge trampoline (G2-5b).
 *
 * All memory allocation and W^X protection goes through platform.h (Rule 8).
 */
#include "callback_bridge.h"
#include "platform.h"

#include <string.h>

static uintptr_t g_bridge_page;

static const Elf64_Phdr g_bridge_phdrs[2] = {
    {
        /* PT_LOAD covering the full 4KB RX trampoline + unwind metadata page */
        PT_LOAD,
        PF_R | PF_X,
        0,
        0,
        0,
        AFW_PAGE_SIZE,
        AFW_PAGE_SIZE,
        AFW_PAGE_SIZE
    },
    {
        /* PT_GNU_EH_FRAME pointing to the .eh_frame_hdr at +0x200 */
        PT_GNU_EH_FRAME,
        PF_R,
        AFW_CALLBACK_BRIDGE_EH_HDR_OFF,
        AFW_CALLBACK_BRIDGE_EH_HDR_OFF,
        AFW_CALLBACK_BRIDGE_EH_HDR_OFF,
        AFW_CALLBACK_BRIDGE_EH_HDR_SZ,
        AFW_CALLBACK_BRIDGE_EH_HDR_SZ,
        4
    }
};

static void write_u32(unsigned char *p, uint32_t v) {
    memcpy(p, &v, 4);
}

static void write_i32(unsigned char *p, int32_t v) {
    memcpy(p, &v, 4);
}

/* Populate the 4KB page with the SysV trampoline, DWARF .eh_frame, and .eh_frame_hdr.
 *
 * Layout inside the 4KB page (base P):
 *   +0x000..+0x00d (14 bytes):
 *     0x00: 55             push rbp          ; RSP -= 8 (now 16B aligned), CFA = RSP+16
 *     0x01: 48 89 e5       mov rbp, rsp      ; CFA = RBP+16
 *     0x04: 48 89 f8       mov rax, rdi      ; cb
 *     0x07: 48 89 f7       mov rdi, rsi      ; arg -> first SysV arg
 *     0x0a: ff d0          call rax          ; return address pushed = P+0x0c
 *     0x0c: 5d             pop rbp           ; CFA = RSP+8, RBP restored
 *     0x0d: c3             ret
 *
 *   +0x100..+0x117 (24 bytes): CIE (length = 20)
 *     +0x100: u32 length = 20
 *     +0x104: u32 CIE_id = 0
 *     +0x108: u8  version = 1
 *     +0x109: "zR\0"
 *     +0x10c: uleb128 code_alignment = 1
 *     +0x10d: sleb128 data_alignment = -8 (0x78)
 *     +0x10e: u8  return_address_register = 16 (RIP)
 *     +0x10f: uleb128 aug_len = 1
 *     +0x110: u8  fde_encoding = 0x1b (DW_EH_PE_pcrel | DW_EH_PE_sdata4)
 *     +0x111: DW_CFA_def_cfa(7 [rsp], 8)     : 0x0c, 0x07, 0x08
 *     +0x114: DW_CFA_offset(16 [rip], 1)     : 0x90, 0x01
 *     +0x116: DW_CFA_nop, DW_CFA_nop         : 0x00, 0x00
 *
 *   +0x118..+0x137 (32 bytes): FDE (length = 28)
 *     +0x118: u32 length = 28
 *     +0x11c: u32 CIE_pointer = 0x1c (0x11c - 0x1c = 0x100)
 *     +0x120: i32 pc_begin = -0x120 (pcrel from +0x120 -> +0x000)
 *     +0x124: i32 pc_range = 14     (+0x000..+0x00e)
 *     +0x128: uleb128 aug_len = 0
 *     +0x129: DW_CFA_advance_loc(1)          : 0x41 (loc = 0x01)
 *     +0x12a: DW_CFA_def_cfa_offset(16)      : 0x0e, 0x10
 *     +0x12c: DW_CFA_offset(6 [rbp], 2)      : 0x86, 0x02 (rbp at CFA-16)
 *     +0x12e: DW_CFA_advance_loc(3)          : 0x43 (loc = 0x04)
 *     +0x12f: DW_CFA_def_cfa_register(6)     : 0x0d, 0x06 (CFA = rbp+16)
 *     +0x131: DW_CFA_advance_loc(9)          : 0x49 (loc = 0x0d, after pop rbp)
 *     +0x132: DW_CFA_def_cfa(7 [rsp], 8)     : 0x0c, 0x07, 0x08
 *     +0x135: DW_CFA_restore(6 [rbp])        : 0xc6
 *     +0x136: DW_CFA_nop, DW_CFA_nop         : 0x00, 0x00
 *   +0x138..+0x13b (4 bytes): terminator = 0
 *
 *   +0x200..+0x213 (20 bytes): .eh_frame_hdr
 *     +0x200: u8  version = 1
 *     +0x201: u8  eh_frame_ptr_enc = 0x1b (pcrel | sdata4)
 *     +0x202: u8  fde_count_enc    = 0x03 (udata4)
 *     +0x203: u8  table_enc        = 0x3b (datarel | sdata4)
 *     +0x204: i32 eh_frame_ptr     = -0x104 (pcrel from +0x204 -> +0x100)
 *     +0x208: u32 fde_count        = 1
 *     +0x20c: i32 table[0].loc     = -0x200 (datarel from +0x200 -> +0x000)
 *     +0x210: i32 table[0].fde     = -0x0e8 (datarel from +0x200 -> +0x118)
 */
static void build_bridge_page(unsigned char *page) {
    static const unsigned char code[AFW_CALLBACK_BRIDGE_CODE_SIZE] = {
        0x55,                   /* push rbp */
        0x48, 0x89, 0xe5,       /* mov rbp, rsp */
        0x48, 0x89, 0xf8,       /* mov rax, rdi */
        0x48, 0x89, 0xf7,       /* mov rdi, rsi */
        0xff, 0xd0,             /* call rax */
        0x5d,                   /* pop rbp */
        0xc3                    /* ret */
    };
    static const unsigned char cie_tail[16] = {
        0x01,                   /* version = 1 */
        'z', 'R', 0x00,         /* augmentation = "zR" */
        0x01,                   /* code_alignment_factor = 1 */
        0x78,                   /* data_alignment_factor = -8 (SLEB128) */
        0x10,                   /* return_address_register = 16 (RIP) */
        0x01,                   /* augmentation_data_length = 1 */
        0x1b,                   /* fde_encoding = pcrel | sdata4 */
        0x0c, 0x07, 0x08,       /* DW_CFA_def_cfa(rsp, 8) */
        0x90, 0x01,             /* DW_CFA_offset(rip, 1) -> CFA - 8 */
        0x00, 0x00              /* DW_CFA_nop x2 */
    };
    static const unsigned char fde_tail[16] = {
        0x00,                   /* augmentation_data_length = 0 */
        0x41,                   /* DW_CFA_advance_loc(1) -> +0x01 */
        0x0e, 0x10,             /* DW_CFA_def_cfa_offset(16) */
        0x86, 0x02,             /* DW_CFA_offset(rbp, 2) -> CFA - 16 */
        0x43,                   /* DW_CFA_advance_loc(3) -> +0x04 */
        0x0d, 0x06,             /* DW_CFA_def_cfa_register(rbp) */
        0x49,                   /* DW_CFA_advance_loc(9) -> +0x0d */
        0x0c, 0x07, 0x08,       /* DW_CFA_def_cfa(rsp, 8) */
        0xc6,                   /* DW_CFA_restore(rbp) */
        0x00, 0x00              /* DW_CFA_nop x2 */
    };
    unsigned char *cie = page + AFW_CALLBACK_BRIDGE_EH_OFF;
    unsigned char *fde = cie + 24;
    unsigned char *hdr = page + AFW_CALLBACK_BRIDGE_EH_HDR_OFF;

    memcpy(page + AFW_CALLBACK_BRIDGE_CODE_OFF, code, sizeof code);

    /* CIE at +0x100 (24 bytes) */
    write_u32(cie + 0, 20u);
    write_u32(cie + 4, 0u);
    memcpy(cie + 8, cie_tail, sizeof cie_tail);

    /* FDE at +0x118 (32 bytes) */
    write_u32(fde + 0, 28u);
    write_u32(fde + 4, 0x1cu);
    write_i32(fde + 8, -(int32_t)(AFW_CALLBACK_BRIDGE_EH_OFF + 24u + 8u));
    write_i32(fde + 12, (int32_t)AFW_CALLBACK_BRIDGE_CODE_SIZE);
    memcpy(fde + 16, fde_tail, sizeof fde_tail);
    write_u32(fde + 32, 0u); /* 4-byte zero terminator at +0x138 */

    /* .eh_frame_hdr at +0x200 (20 bytes) */
    hdr[0] = 0x01; /* version */
    hdr[1] = 0x1b; /* eh_frame_ptr_enc: pcrel | sdata4 */
    hdr[2] = 0x03; /* fde_count_enc: udata4 */
    hdr[3] = 0x3b; /* table_enc: datarel | sdata4 */
    write_i32(hdr + 4,  -(int32_t)((AFW_CALLBACK_BRIDGE_EH_HDR_OFF + 4u) - AFW_CALLBACK_BRIDGE_EH_OFF));
    write_u32(hdr + 8,  1u);
    write_i32(hdr + 12, -(int32_t)(AFW_CALLBACK_BRIDGE_EH_HDR_OFF - AFW_CALLBACK_BRIDGE_CODE_OFF));
    write_i32(hdr + 16, -(int32_t)(AFW_CALLBACK_BRIDGE_EH_HDR_OFF - (AFW_CALLBACK_BRIDGE_EH_OFF + 24u)));
}

void *afw_callback_bridge_entry(void) {
    uintptr_t p = afw_os_atomic_load_uptr(&g_bridge_page);
    if (p) return (void *)p;

    afw_dlopen_lock();
    p = afw_os_atomic_load_uptr(&g_bridge_page);
    if (!p) {
        unsigned char *page = (unsigned char *)afw_mem_alloc(AFW_PAGE_SIZE);
        if (page) {
            build_bridge_page(page);
            if (afw_mem_protect(page, AFW_PAGE_SIZE, AFW_PROT_R | AFW_PROT_X) != 0) {
                afw_mem_free(page, AFW_PAGE_SIZE);
            } else {
                afw_flush_icache(page, AFW_PAGE_SIZE);
                p = (uintptr_t)page;
                afw_os_atomic_store_uptr(&g_bridge_page, p);
            }
        }
    }
    afw_dlopen_unlock();
    return (void *)p;
}

int afw_callback_bridge_phdr(uint64_t *addr_out, const char **name_out,
                             const Elf64_Phdr **phdr_out, uint16_t *phnum_out) {
    uintptr_t p = afw_os_atomic_load_uptr(&g_bridge_page);
    if (!p) return 0;
    if (addr_out)  *addr_out  = (uint64_t)p;
    if (name_out)  *name_out  = "[afw-callback-bridge]";
    if (phdr_out)  *phdr_out  = g_bridge_phdrs;
    if (phnum_out) *phnum_out = 2;
    return 1;
}
