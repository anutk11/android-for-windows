/* sha256.h - SHA-256 (FIPS 180-4), for pinning attestations to exact binaries. */
#ifndef AFW_SHA256_H
#define AFW_SHA256_H
#include <stddef.h>
#include <stdint.h>
void afw_sha256(const void *data, size_t len, uint8_t out[32]);
void afw_sha256_hex(const uint8_t h[32], char out[65]);
void afw_hmac_sha256_zero_key_slices(const void *const *ptrs, const size_t *lens, int n, uint8_t out[32]);
#endif
