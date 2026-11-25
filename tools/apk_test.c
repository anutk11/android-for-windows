/*
 * apk_test.c - Host unit tests for src/apk.c (ZIP + RFC 1951 Inflate + CRC-32)
 * and src/axml.c (Android Binary XML manifest parser).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/apk.h"
#include "../src/axml.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL (%s:%d): %s\n", __FILE__, __LINE__, msg); } \
} while (0)

int main(int argc, char **argv) {
    afw_apk apk;
    unsigned char *buf = NULL;
    size_t sz = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: apk_test <sample.apk> [utf8_sample.apk]\n");
        return 2;
    }

    CHECK(afw_apk_open(argv[1], &apk) == 0, "open APK");
    CHECK(apk.has_manifest == 1, "parsed binary AndroidManifest.xml (UTF-16LE)");
    CHECK(strcmp(apk.manifest.package_name, "com.afw.testapp") == 0, "manifest package_name");
    CHECK(strcmp(apk.manifest.version_name, "2.5") == 0, "manifest version_name");
    CHECK(apk.manifest.version_code == 42, "manifest version_code");
    CHECK(strcmp(apk.manifest.main_activity, "android.app.NativeActivity") == 0, "manifest main_activity");
    CHECK(strcmp(apk.manifest.native_lib_name, "demo_native") == 0, "manifest native_lib_name");
    CHECK(apk.manifest.has_launcher_activity == 1, "manifest has MAIN+LAUNCHER");
    CHECK(apk.nx86_64_libs == 1, "detected 1 x86_64 native library");

    CHECK(afw_apk_read_file(&apk, "assets/hello.txt", &buf, &sz) == 0, "inflate DEFLATED asset");
    CHECK(buf != NULL && sz > 0 && strstr((const char *)buf, "Hello from compressed APK asset!") != NULL,
          "inflated asset payload matches");
    free(buf); buf = NULL;

    CHECK(afw_apk_read_file(&apk, "assets/large.txt", &buf, &sz) == 0, "inflate multi-block dynamic Huffman asset");
    CHECK(buf != NULL && sz == 40000 && memcmp(buf, "AFW-DEFLATE-BLOCK-0000\n", 23) == 0,
          "large dynamic Huffman inflated accurately");
    free(buf); buf = NULL;

    CHECK(afw_apk_read_file(&apk, "assets/does_not_exist.txt", &buf, &sz) == -1,
          "missing entry returns -1");

    /* Corrupt CRC test */
    {
        afw_apk_entry bad = *afw_apk_find(&apk, "assets/hello.txt");
        bad.crc32 ^= 0x12345678u;
        CHECK(afw_apk_read_entry(&apk, &bad, &buf, &sz) == -1, "corrupt CRC-32 rejected");
    }

    afw_apk_close(&apk);

    /* Optional second APK with UTF-8 string pool + relative activity name */
    if (argc >= 3) {
        CHECK(afw_apk_open(argv[2], &apk) == 0, "open UTF-8 manifest APK");
        CHECK(apk.has_manifest == 1, "parsed UTF-8 binary AndroidManifest.xml");
        CHECK(strcmp(apk.manifest.package_name, "com.afw.dexapp") == 0, "UTF-8 package_name");
        CHECK(strcmp(apk.manifest.main_activity, "com.afw.dexapp.MainActivity") == 0,
              "relative activity '.MainActivity' resolved to full class name");
        CHECK(apk.has_dex == 1, "detected classes.dex");
        afw_apk_close(&apk);
    }

    /* Truncated/corrupt buffer rejected safely */
    {
        unsigned char junk[16] = { 0x50, 0x4b, 0x03, 0x04, 1, 2, 3, 4 };
        afw_apk bad_apk;
        CHECK(afw_apk_open_mem(junk, sizeof junk, &bad_apk) == -1, "corrupt ZIP rejected");
    }

    printf("apk_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
