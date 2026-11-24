/*
 * pthread_tdata_lib.c - Startup DSO with non-zero .tdata (p_filesz > 0) and
 * .tbss for G2-4b pthread_mt_test (Reviewer 3 anchor #1).
 *
 * Verifies that SYS_clone child threads inherit initialized non-zero static
 * ELF TLS data even when Bionic's libc_shared_globals->tls_modules is empty.
 */
#include <stdint.h>

#define AFW_TDATA_MAGIC 0x1122334455667788ULL
#define AFW_TDATA_TAG   0xCAFEBABE12345678ULL

static __thread uint64_t t_tdata_magic = AFW_TDATA_MAGIC; /* General Dynamic (__tls_get_addr) */
__thread uint64_t t_tdata_tag __attribute__((tls_model("initial-exec"))) = AFW_TDATA_TAG; /* Initial Exec (TPOFF64 / fs:[reg]) */
static __thread uint64_t t_tbss_zero   = 0;

uint64_t afw_tdata_get_magic(void) { return t_tdata_magic; }
void     afw_tdata_set_magic(uint64_t v) { t_tdata_magic = v; }

uint64_t afw_tdata_get_tag(void) { return t_tdata_tag; }
void     afw_tdata_set_tag(uint64_t v) { t_tdata_tag = v; }

uint64_t afw_tbss_get(void) { return t_tbss_zero; }
void     afw_tbss_set(uint64_t v) { t_tbss_zero = v; }
