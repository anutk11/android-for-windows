/*
 * apk.h - Self-contained Android APK (ZIP + RFC 1951 Inflate + AXML) reader.
 *
 * Pure C11 with zero external dependencies (no zlib/libzip needed). Supports
 * STORED (0) and DEFLATED (8) entries with CRC-32 verification, manifest
 * parsing, asset queries, classes.dex extraction, and lib/x86_64/ .so unpacking.
 */
#ifndef AFW_APK_H
#define AFW_APK_H

#include <stddef.h>
#include <stdint.h>
#include "axml.h"

typedef struct {
    char     *name;
    uint16_t  method;        /* 0 = STORED, 8 = DEFLATED */
    uint32_t  crc32;
    uint32_t  comp_size;
    uint32_t  uncomp_size;
    uint32_t  local_hdr_off;
} afw_apk_entry;

typedef struct {
    unsigned char    *data;
    size_t            size;
    afw_apk_entry    *entries;
    size_t            nentries;
    afw_apk_manifest  manifest;
    int               has_manifest;
    int               has_dex;
    int               nx86_64_libs;
} afw_apk;

/* Open and parse an APK file on disk. Returns 0 on success, -1 on error. */
int afw_apk_open(const char *path, afw_apk *out);

/* Open and parse an APK already in memory (takes no ownership of buf; copies it). */
int afw_apk_open_mem(const unsigned char *buf, size_t size, afw_apk *out);

/* Release all memory held by an opened APK. */
void afw_apk_close(afw_apk *apk);

/* Find an entry by exact path inside the APK (e.g. "assets/hello.txt"). */
const afw_apk_entry *afw_apk_find(const afw_apk *apk, const char *name);

/* Read and decompress entry `e` into a freshly malloc'd buffer (+ trailing NUL).
 * Caller frees *out_buf. Verifies CRC-32. Returns 0 on success, -1 on error. */
int afw_apk_read_entry(const afw_apk *apk, const afw_apk_entry *e,
                       unsigned char **out_buf, size_t *out_size);

/* Convenience wrapper: find by name and read. */
int afw_apk_read_file(const afw_apk *apk, const char *name,
                      unsigned char **out_buf, size_t *out_size);

/* Extract all x86_64 shared libraries under lib/x86_64/ from the APK into `out_dir` (which
 * must already exist). Returns number of extracted libraries, or -1 on error. */
int afw_apk_extract_x86_64_libs(const afw_apk *apk, const char *out_dir);

/* Self-contained RFC 1951 raw DEFLATE decompressor (exposed for unit tests).
 * Returns 0 on success, -1 on corrupt stream or size mismatch. */
int afw_inflate_raw(const unsigned char *in, size_t in_len,
                    unsigned char *out, size_t out_len);

/* IEEE 802.3 CRC-32 (exposed for unit tests). */
uint32_t afw_crc32(const unsigned char *buf, size_t len);

#endif
