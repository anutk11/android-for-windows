/*
 * apk_runner.h - End-to-end Android .apk runner (NativeActivity + DEX/JNI).
 */
#ifndef AFW_APK_RUNNER_H
#define AFW_APK_RUNNER_H

typedef struct {
    int         headless;
    int         width;
    int         height;
    int         max_frames;      /* 0 = interactive until window closes */
    const char *screenshot_path; /* optional .bmp path saved after run */
    int         verbose;
} afw_apk_run_opts;

/* Load and execute an Android .apk file. Returns 0 on success, non-zero on error. */
int afw_run_apk(const char *apk_path, const afw_apk_run_opts *opts);

#endif
