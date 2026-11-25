/*
 * apk_runner.c - End-to-end Android .apk runner (NativeActivity + DEX/JNI).
 */
#include "apk_runner.h"
#include "apk.h"
#include "android_native.h"
#include "dex_vm.h"
#include "elf_loader.h"
#include "gles_bridge.h"
#include "jni_bridge.h"
#include "platform.h"
#include "win_gui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#include <unistd.h>
#endif

static void runner_sleep_ms(int ms) {
    if (ms <= 0) return;
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

typedef struct {
    const char *lib_dir;
    afw_dex_vm *vm;
    int         verbose;
    afw_lib     libs[16];
    afw_lib     deps[16][32];
    char        paths[16][1024];
    int         nlibs;
} dex_lib_ctx;

/* Loaded Android DSOs remain registered in elf_loader's global g_libs[] until
 * process exit (same lifetime model as main.c), so keep their afw_lib structs
 * and path strings in static storage rather than on the stack or freed heap. */
static afw_lib     g_native_lib;
static afw_lib     g_native_deps[32];
static char        g_native_path[1024];
static dex_lib_ctx g_dex_lctx;

static int dex_load_library_cb(const char *libname, void *ud) {
    dex_lib_ctx *ctx = (dex_lib_ctx *)ud;
    int ndeps = 0, slot;
    void *onload;

    if (!ctx || !libname || ctx->nlibs >= 16) return -1;
    slot = ctx->nlibs;
    snprintf(ctx->paths[slot], sizeof ctx->paths[slot], "%s/lib%s.so", ctx->lib_dir, libname);
    printf("[apk] System.loadLibrary(\"%s\") -> %s\n", libname, ctx->paths[slot]);
    fflush(stdout);
    if (afw_load_with_deps(ctx->paths[slot], &ctx->libs[slot], ctx->deps[slot], 32, &ndeps, ctx->verbose) != 0) {
        fprintf(stderr, "[apk] error: failed to load native library %s\n", ctx->paths[slot]);
        return -1;
    }
    ctx->nlibs++;
    onload = afw_sym(&ctx->libs[slot], "JNI_OnLoad");
    if (onload && ctx->vm) {
        typedef SYSV int32_t (*onload_fn)(void *, void *);
        int32_t ver = ((onload_fn)onload)(afw_dex_vm_get_javavm(ctx->vm), NULL);
        printf("[apk] JNI_OnLoad(\"%s\") -> 0x%x\n", libname, (unsigned)ver);
        fflush(stdout);
    }
    return 0;
}

static int run_native_activity(const afw_apk *apk, const char *lib_dir,
                               afw_gui_surface *surface, const afw_apk_run_opts *opts) {
    int ndeps = 0;
    typedef SYSV void (*on_create_fn)(void *activity, void *saved_state, size_t saved_sz);
    on_create_fn on_create;
    afw_ANativeActivity *act;
    afw_ANativeActivityCallbacks *cb;
    void *win, *iq;
    int ticks = 0;

    snprintf(g_native_path, sizeof g_native_path, "%s/lib%s.so", lib_dir, apk->manifest.native_lib_name);
    printf("[apk] Mode: NativeActivity (lib=%s)\n", g_native_path);
    fflush(stdout);

    memset(&g_native_lib, 0, sizeof g_native_lib);
    memset(g_native_deps, 0, sizeof g_native_deps);
    if (afw_load_with_deps(g_native_path, &g_native_lib, g_native_deps, 32, &ndeps, opts->verbose) != 0) {
        fprintf(stderr, "[apk] error: failed to load NativeActivity library %s\n", g_native_path);
        return 1;
    }

    on_create = (on_create_fn)afw_sym(&g_native_lib, "ANativeActivity_onCreate");
    if (!on_create) {
        fprintf(stderr, "[apk] error: %s does not export ANativeActivity_onCreate\n", g_native_path);
        return 1;
    }

    afw_android_native_bind(apk, surface, lib_dir, NULL, NULL);
    act = afw_android_get_activity();
    cb  = act->callbacks;
    win = afw_android_get_window();
    iq  = afw_android_get_input_queue();

    on_create(act, NULL, 0);
    if (cb->onStart)  cb->onStart(act);
    if (cb->onResume) cb->onResume(act);
    if (cb->onInputQueueCreated)   cb->onInputQueueCreated(act, iq);
    if (cb->onNativeWindowCreated) cb->onNativeWindowCreated(act, win);
    if (cb->onWindowFocusChanged)  cb->onWindowFocusChanged(act, 1);

    /* Main presentation & message pump loop */
    for (;;) {
        afw_gui_pump_events(surface);
        if (cb->onNativeWindowRedrawNeeded)
            cb->onNativeWindowRedrawNeeded(act, win);
        if (afw_os_atomic_load_i32(&surface->should_close) || afw_android_finish_requested())
            break;
        if (opts->max_frames > 0 && surface->frames_presented >= (uint64_t)opts->max_frames)
            break;
        runner_sleep_ms(16);
        if (opts->max_frames > 0 && ++ticks > 600) {
            fprintf(stderr, "[apk] timeout waiting for %d frames (got %llu)\n",
                    opts->max_frames, (unsigned long long)surface->frames_presented);
            break;
        }
    }

    if (cb->onWindowFocusChanged)    cb->onWindowFocusChanged(act, 0);
    if (cb->onNativeWindowDestroyed) cb->onNativeWindowDestroyed(act, win);
    if (cb->onInputQueueDestroyed)   cb->onInputQueueDestroyed(act, iq);
    if (cb->onPause)                 cb->onPause(act);
    if (cb->onStop)                  cb->onStop(act);
    if (cb->onDestroy)               cb->onDestroy(act);

    afw_gles_shutdown();
    afw_android_native_unbind();
    return (opts->max_frames > 0 && surface->frames_presented < (uint64_t)opts->max_frames) ? 1 : 0;
}

static int run_dex_activity(const afw_apk *apk, const char *lib_dir,
                            afw_gui_surface *surface, const afw_apk_run_opts *opts) {
    unsigned char *dex_buf = NULL;
    size_t dex_sz = 0;
    afw_dex_vm *vm;
    int rc;

    printf("[apk] Mode: DEX/Java Activity (%s)\n", apk->manifest.main_activity);
    fflush(stdout);
    if (afw_apk_read_file(apk, "classes.dex", &dex_buf, &dex_sz) != 0) {
        fprintf(stderr, "[apk] error: failed to extract classes.dex\n");
        return 1;
    }

    memset(&g_dex_lctx, 0, sizeof g_dex_lctx);
    g_dex_lctx.lib_dir = lib_dir;
    g_dex_lctx.verbose = opts->verbose;

    vm = afw_dex_vm_create(dex_buf, dex_sz, apk, surface, dex_load_library_cb, &g_dex_lctx);
    free(dex_buf);
    if (!vm) {
        fprintf(stderr, "[apk] error: failed to parse classes.dex\n");
        return 1;
    }
    g_dex_lctx.vm = vm;

    afw_android_native_bind(apk, surface, lib_dir,
                            afw_dex_vm_get_javavm(vm), afw_dex_vm_get_jnienv(vm));

    rc = afw_dex_run_activity(vm, apk->manifest.main_activity, opts->max_frames);

    afw_android_native_unbind();
    afw_dex_vm_destroy(vm);
    return rc == 0 ? 0 : 1;
}

int afw_run_apk(const char *apk_path, const afw_apk_run_opts *opts) {
    afw_apk apk;
    afw_gui_surface surface;
    char tmp_dir[512];
    char title[320];
    int width, height, extracted, rc = 1;
    afw_apk_run_opts def_opts;

    if (!opts) {
        memset(&def_opts, 0, sizeof def_opts);
        opts = &def_opts;
    }
    width  = opts->width  > 0 ? opts->width  : 640;
    height = opts->height > 0 ? opts->height : 480;

    if (afw_apk_open(apk_path, &apk) != 0) {
        fprintf(stderr, "[apk] error: cannot open APK '%s'\n", apk_path);
        return 1;
    }
    if (!apk.has_manifest) {
        fprintf(stderr, "[apk] error: '%s' has no readable AndroidManifest.xml\n", apk_path);
        afw_apk_close(&apk);
        return 1;
    }

    printf("=== Android-for-Windows APK Runner ===\n");
    printf("  APK:       %s\n", apk_path);
    printf("  Package:   %s (v%s / %d)\n", apk.manifest.package_name,
           apk.manifest.version_name[0] ? apk.manifest.version_name : "1.0",
           apk.manifest.version_code);
    printf("  Activity:  %s\n", apk.manifest.main_activity);
    printf("  NativeLib: %s\n", apk.manifest.native_lib_name[0] ? apk.manifest.native_lib_name : "(none)");
    printf("  DEX:       %s | x86_64 libs: %d\n", apk.has_dex ? "classes.dex" : "none", apk.nx86_64_libs);
    fflush(stdout);

    snprintf(tmp_dir, sizeof tmp_dir, "afw_apk_libs_%u", (unsigned)afw_os_current_tid());
    (void)afw_os_mkdir(tmp_dir, 0755);
    extracted = afw_apk_extract_x86_64_libs(&apk, tmp_dir);
    if (extracted < 0) {
        fprintf(stderr, "[apk] error: failed to extract lib/x86_64 libraries into %s\n", tmp_dir);
        afw_apk_close(&apk);
        return 1;
    }
    printf("  Extracted: %d x86_64 native library(ies) -> %s\n", extracted, tmp_dir);
    fflush(stdout);

    snprintf(title, sizeof title, "%s - Android for Windows", apk.manifest.package_name);
    if (afw_gui_create(&surface, title, width, height, opts->headless) != 0) {
        fprintf(stderr, "[apk] error: failed to create GUI surface (%dx%d)\n", width, height);
        afw_apk_close(&apk);
        return 1;
    }

    if (apk.manifest.native_lib_name[0] &&
        (strcmp(apk.manifest.main_activity, "android.app.NativeActivity") == 0 || !apk.has_dex)) {
        rc = run_native_activity(&apk, tmp_dir, &surface, opts);
    } else if (apk.has_dex && apk.manifest.main_activity[0]) {
        rc = run_dex_activity(&apk, tmp_dir, &surface, opts);
    } else {
        fprintf(stderr, "[apk] error: APK has neither NativeActivity android.app.lib_name nor classes.dex\n");
        rc = 1;
    }

    if (rc == 0 && opts->screenshot_path && opts->screenshot_path[0]) {
        if (afw_gui_save_bmp(&surface, opts->screenshot_path) == 0)
            printf("[apk] Saved screenshot: %s (%dx%d, frames=%llu)\n",
                   opts->screenshot_path, surface.width, surface.height,
                   (unsigned long long)surface.frames_presented);
        else {
            fprintf(stderr, "[apk] error: failed to save screenshot %s\n", opts->screenshot_path);
            rc = 1;
        }
    }

    printf("[apk] Finished (rc=%d, frames=%llu)\n", rc, (unsigned long long)surface.frames_presented);
    fflush(stdout);
    afw_gui_destroy(&surface);
    afw_apk_close(&apk);
    return rc;
}
