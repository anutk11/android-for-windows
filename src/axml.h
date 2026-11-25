/*
 * axml.h - Android Binary XML (AXML) parser for AndroidManifest.xml inside APKs.
 *
 * Parses aapt / aapt2 compiled binary XML (RES_XML_TYPE) to extract package
 * name, version info, launchable Activity class name, and NativeActivity
 * android.app.lib_name metadata. Bounds-checked on all inputs.
 */
#ifndef AFW_AXML_H
#define AFW_AXML_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char     package_name[256];
    char     version_name[64];
    int32_t  version_code;
    char     main_activity[256];
    char     native_lib_name[128];
    int      has_launcher_activity;
} afw_apk_manifest;

/* Parse binary AndroidManifest.xml in [buf, buf+len) into *out.
 * Returns 0 on success, -1 on corrupt/unsupported input. */
int afw_axml_parse(const unsigned char *buf, size_t len, afw_apk_manifest *out);

#endif
