/*
 * native_demo.cpp - Real Android NDK C++17 NativeActivity APK demo.
 *
 * Exercises inside a real .apk on Windows:
 *   - ANativeActivity_onCreate + full lifecycle callbacks
 *   - AAssetManager reading DEFLATE-compressed assets/greeting.txt from APK
 *   - C++17 std::runtime_error throw/catch via bundled lib/x86_64/libc++_shared.so
 *   - Bionic pthread_create + ALooper_prepare + ALooper_pollOnce render loop
 *   - EGL 1.4 + OpenGL ES 2.0 triangle & background rendering -> Win32 HWND / BMP
 */
#include <android/asset_manager.h>
#include <android/log.h>
#include <android/looper.h>
#include <android/native_activity.h>
#include <android/native_window.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <pthread.h>

#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "NativeDemo", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "NativeDemo", __VA_ARGS__)

namespace {
struct DemoApp {
    ANativeActivity *activity = nullptr;
    ANativeWindow   *window   = nullptr;
    pthread_t        thread{};
    std::atomic<int> running{0};
    std::atomic<int> window_ready{0};
    std::atomic<int> thread_started{0};
    std::atomic<int> checks_ok{0};
    int              frames = 0;
};

static const char *kVertSrc =
    "attribute vec2 a_pos;\n"
    "attribute vec4 a_color;\n"
    "varying vec4 v_color;\n"
    "void main() { v_color = a_color; gl_Position = vec4(a_pos, 0.0, 1.0); }\n";

static const char *kFragSrc =
    "precision mediump float;\n"
    "varying vec4 v_color;\n"
    "void main() { gl_FragColor = v_color; }\n";

static void *render_thread_fn(void *vp) {
    DemoApp *app = static_cast<DemoApp *>(vp);
    ALooper *looper = ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
    (void)looper;

    /* Wait until window is created */
    while (app->running.load(std::memory_order_acquire) &&
           !app->window_ready.load(std::memory_order_acquire)) {
        ALooper_pollOnce(5, nullptr, nullptr, nullptr);
    }
    if (!app->running.load(std::memory_order_acquire) || !app->window)
        return nullptr;

    /* Initialize EGL 1.4 + OpenGL ES 2.0 */
    EGLDisplay dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major = 0, minor = 0;
    eglInitialize(dpy, &major, &minor);

    const EGLint cfg_attrs[] = {
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8,
        EGL_NONE
    };
    EGLConfig cfg = nullptr;
    EGLint ncfg = 0;
    eglChooseConfig(dpy, cfg_attrs, &cfg, 1, &ncfg);

    EGLSurface surf = eglCreateWindowSurface(dpy, cfg, app->window, nullptr);
    const EGLint ctx_attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    EGLContext ctx = eglCreateContext(dpy, cfg, EGL_NO_CONTEXT, ctx_attrs);
    eglMakeCurrent(dpy, surf, surf, ctx);

    EGLint w = 0, h = 0;
    eglQuerySurface(dpy, surf, EGL_WIDTH, &w);
    eglQuerySurface(dpy, surf, EGL_HEIGHT, &h);
    LOGI("EGL %d.%d initialized (%dx%d), GL=%s", major, minor, w, h,
         reinterpret_cast<const char *>(glGetString(GL_RENDERER)));

    GLuint vs = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vs, 1, &kVertSrc, nullptr);
    glCompileShader(vs);
    GLuint fs = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(fs, 1, &kFragSrc, nullptr);
    glCompileShader(fs);
    GLuint prog = glCreateProgram();
    glAttachShader(prog, vs);
    glAttachShader(prog, fs);
    glLinkProgram(prog);
    glUseProgram(prog);

    GLint pos_loc = glGetAttribLocation(prog, "a_pos");
    GLint col_loc = glGetAttribLocation(prog, "a_color");
    glEnableVertexAttribArray(static_cast<GLuint>(pos_loc));
    glEnableVertexAttribArray(static_cast<GLuint>(col_loc));

    /* Centered vibrant triangle in NDC */
    const float pos_data[6] = {
         0.0f,  0.65f,
        -0.65f, -0.55f,
         0.65f, -0.55f
    };
    const float col_data[12] = {
        1.0f, 0.2f, 0.2f, 1.0f,   /* bright red top */
        0.2f, 1.0f, 0.3f, 1.0f,   /* bright green bottom-left */
        0.2f, 0.6f, 1.0f, 1.0f    /* bright cyan-blue bottom-right */
    };

    while (app->running.load(std::memory_order_acquire)) {
        ALooper_pollOnce(1, nullptr, nullptr, nullptr);
        glViewport(0, 0, w, h);
        /* Deep navy background */
        glClearColor(0.08f, 0.16f, 0.35f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        glVertexAttribPointer(static_cast<GLuint>(pos_loc), 2, GL_FLOAT, GL_FALSE, 0, pos_data);
        glVertexAttribPointer(static_cast<GLuint>(col_loc), 4, GL_FLOAT, GL_FALSE, 0, col_data);
        glDrawArrays(GL_TRIANGLES, 0, 3);

        eglSwapBuffers(dpy, surf);
        app->frames++;
        if (app->frames == 1 && app->checks_ok.load(std::memory_order_acquire)) {
            std::printf("NATIVE_DEMO_APK_PASSED (EGL %d.%d, %dx%d)\n", major, minor, w, h);
            std::fflush(stdout);
        }
    }

    glDeleteProgram(prog);
    glDeleteShader(vs);
    glDeleteShader(fs);
    eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroyContext(dpy, ctx);
    eglDestroySurface(dpy, surf);
    eglTerminate(dpy);
    return nullptr;
}

static void on_window_created(ANativeActivity *act, ANativeWindow *win) {
    DemoApp *app = static_cast<DemoApp *>(act->instance);
    app->window = win;
    ANativeWindow_acquire(win);
    app->window_ready.store(1, std::memory_order_release);
}

static void on_window_destroyed(ANativeActivity *act, ANativeWindow *win) {
    DemoApp *app = static_cast<DemoApp *>(act->instance);
    (void)win;
    app->running.store(0, std::memory_order_release);
    if (app->thread_started.exchange(0, std::memory_order_acq_rel)) {
        pthread_join(app->thread, nullptr);
    }
    if (app->window) {
        ANativeWindow_release(app->window);
        app->window = nullptr;
    }
}

static void on_destroy(ANativeActivity *act) {
    DemoApp *app = static_cast<DemoApp *>(act->instance);
    if (!app) return;
    app->running.store(0, std::memory_order_release);
    if (app->thread_started.exchange(0, std::memory_order_acq_rel)) {
        pthread_join(app->thread, nullptr);
    }
    delete app;
    act->instance = nullptr;
}
} // namespace

extern "C" void ANativeActivity_onCreate(ANativeActivity *activity, void *savedState, size_t savedStateSize) {
    (void)savedState;
    (void)savedStateSize;
    DemoApp *app = new DemoApp();
    app->activity = activity;
    activity->instance = app;
    activity->callbacks->onNativeWindowCreated   = on_window_created;
    activity->callbacks->onNativeWindowDestroyed = on_window_destroyed;
    activity->callbacks->onDestroy               = on_destroy;

    /* 1. Verify compressed APK asset read via AAssetManager */
    int asset_ok = 0;
    if (activity->assetManager) {
        AAsset *a = AAssetManager_open(activity->assetManager, "greeting.txt", AASSET_MODE_BUFFER);
        if (a) {
            char buf[128] = {0};
            int n = AAsset_read(a, buf, sizeof(buf) - 1);
            AAsset_close(a);
            if (n > 0 && std::strstr(buf, "Hello from Android NativeActivity APK!") != nullptr) {
                LOGI("Asset verified (%d bytes): %s", n, buf);
                asset_ok = 1;
            }
        }
    }
    if (!asset_ok) LOGE("FAIL: could not read assets/greeting.txt from APK");

    /* 2. Verify C++17 exception handling via bundled libc++_shared.so */
    int cxx_ok = 0;
    try {
        throw std::runtime_error("apk-cxx-ok");
    } catch (const std::runtime_error &e) {
        cxx_ok = (std::strcmp(e.what(), "apk-cxx-ok") == 0) ? 1 : 0;
    }
    if (!cxx_ok) LOGE("FAIL: C++ exception check failed");

    app->checks_ok.store((asset_ok && cxx_ok) ? 1 : 0, std::memory_order_release);
    app->running.store(1, std::memory_order_release);
    if (pthread_create(&app->thread, nullptr, render_thread_fn, app) == 0) {
        app->thread_started.store(1, std::memory_order_release);
    }
}
