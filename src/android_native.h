/*
 * android_native.h - Android NDK NativeActivity, ANativeWindow, AAssetManager,
 * ALooper, AInputQueue, AConfiguration, and liblog System V ABI runtime shims.
 */
#ifndef AFW_ANDROID_NATIVE_H
#define AFW_ANDROID_NATIVE_H

#include <stddef.h>
#include <stdint.h>
#include "platform.h"
#include "apk.h"
#include "win_gui.h"

/* Exact Android NDK LP64 ABI layout (<android/native_activity.h>) */
typedef struct {
    SYSV void  (*onStart)(void *activity);
    SYSV void  (*onResume)(void *activity);
    SYSV void *(*onSaveInstanceState)(void *activity, size_t *outSize);
    SYSV void  (*onPause)(void *activity);
    SYSV void  (*onStop)(void *activity);
    SYSV void  (*onDestroy)(void *activity);
    SYSV void  (*onWindowFocusChanged)(void *activity, int hasFocus);
    SYSV void  (*onNativeWindowCreated)(void *activity, void *window);
    SYSV void  (*onNativeWindowResized)(void *activity, void *window);
    SYSV void  (*onNativeWindowRedrawNeeded)(void *activity, void *window);
    SYSV void  (*onNativeWindowDestroyed)(void *activity, void *window);
    SYSV void  (*onInputQueueCreated)(void *activity, void *queue);
    SYSV void  (*onInputQueueDestroyed)(void *activity, void *queue);
    SYSV void  (*onContentRectChanged)(void *activity, const void *rect);
    SYSV void  (*onConfigurationChanged)(void *activity);
    SYSV void  (*onLowMemory)(void *activity);
} afw_ANativeActivityCallbacks;

typedef struct {
    afw_ANativeActivityCallbacks *callbacks;
    void       *vm;
    void       *env;
    void       *clazz;
    const char *internalDataPath;
    const char *externalDataPath;
    int32_t     sdkVersion;
    void       *instance;
    void       *assetManager;
    const char *obbPath;
} afw_ANativeActivity;

typedef struct {
    int32_t  width;
    int32_t  height;
    int32_t  stride;
    int32_t  format;
    void    *bits;
    uint32_t reserved[6];
} afw_ANativeWindow_Buffer;

/* Bind active APK + GUI surface to the Android Native runtime. */
void  afw_android_native_bind(const afw_apk *apk, afw_gui_surface *surface,
                              const char *data_dir, void *jvm, void *jenv);
void  afw_android_native_unbind(void);

/* Accessors for the active ANativeActivity / ANativeWindow / AInputQueue. */
afw_ANativeActivity *afw_android_get_activity(void);
void *afw_android_get_window(void);
void *afw_android_get_input_queue(void);
void *afw_android_get_asset_manager(void);
afw_gui_surface *afw_android_window_surface(void *native_window);
int   afw_android_finish_requested(void);

/* Lookup Android NDK libandroid.so / liblog.so symbols (called by bionic_shim.c). */
void *afw_android_native_lookup(const char *name);

#endif
