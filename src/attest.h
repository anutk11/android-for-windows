/* attest.h - attestations for jump tables the analysis cannot bound (see patch.h). */
#ifndef AFW_ATTEST_H
#define AFW_ATTEST_H
#include <stdint.h>
#include "patch.h"

/* Attestations for the binary with this sha256 (64 hex chars); *n = count. */
const afw_attest *afw_attest_for(const char *sha256_hex, int *n);

/* Test only: damage one field of every attestation before it is verified
 * ("hash", "jmp", "table", "k", "none"). Every variant must be rejected. */
void afw_attest_set_tamper(const char *what);

#endif
