/* attest.h - attestations for jump tables the analysis cannot bound (see patch.h). */
#ifndef AFW_ATTEST_H
#define AFW_ATTEST_H
#include <stdint.h>
#include "patch.h"

/* Copies the attestations for the binary with this sha256 (64 hex chars)
 * into buf (the caller's: no shared state). Returns buf, or NULL if none;
 * *n = count. More records than max is an error: -1 in *n, NULL. */
const afw_attest *afw_attest_for(const char *sha256_hex, afw_attest *buf, int max, int *n);

#ifdef AFW_TEST
/* Test builds only: damage one field of every attestation before it is
 * verified ("hash", "jmp", "table", "k", "none"). Every one must be rejected. */
void afw_attest_set_tamper(const char *what);
/* Test builds only: an attestation for whatever binary is loaded. */
int afw_attest_add_test(const char *spec);
#endif

#endif
