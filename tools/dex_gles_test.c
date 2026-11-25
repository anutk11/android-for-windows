/*
 * dex_gles_test.c - Host unit tests for win_gui, android_native, gles_bridge,
 * dex_vm, and jni_bridge (runs under Linux ASan+UBSan+LSan and Windows).
 *
 * Usage:
 *   dex_gles_test [path/to/dex_jni_demo.apk]
 */
#include "../src/android_native.h"
#include "../src/apk.h"
#include "../src/dex_vm.h"
#include "../src/gles_bridge.h"
#include "../src/jni_bridge.h"
#include "../src/platform.h"
#include "../src/win_gui.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Standalone host test stub (no ELF loader linked in). */
void *afw_global_sym(const char *name) { (void)name; return NULL; }

static int g_passed = 0;
static int g_failed = 0;

static void check(const char *name, int cond) {
    if (cond) {
        g_passed++;
    } else {
        g_failed++;
        fprintf(stderr, "  [FAIL] %s\n", name);
    }
}

static void get_rgb(const afw_gui_surface *s, int x, int y, uint8_t *r, uint8_t *g, uint8_t *b) {
    uint32_t px = s->pixels[(size_t)y * (size_t)s->width + (size_t)x];
    *r = (uint8_t)(px & 0xFFu);
    *g = (uint8_t)((px >> 8) & 0xFFu);
    *b = (uint8_t)((px >> 16) & 0xFFu);
}

/* ---- 1. Win32/Headless GUI surface, 2D primitives, BMP & SPSC events ---- */
static void test_win_gui(void) {
    afw_gui_surface s;
    afw_gui_event ev, out;
    uint8_t r, g, b;
    const char *bmp_path = "out_dex_gles_test.bmp";
    FILE *f;
    unsigned char hdr[54];
    int i;

    check("gui_create 160x120 headless", afw_gui_create(&s, "Test", 160, 120, 1) == 0);
    afw_gui_clear(&s, afw_rgba(10, 20, 30, 255));
    afw_gui_fill_rect(&s, 20, 15, 40, 30, afw_rgba(200, 100, 50, 255));
    afw_gui_fill_circle(&s, 110, 60, 15, afw_rgba(40, 220, 80, 255));
    afw_gui_draw_line(&s, 0, 0, 10, 10, afw_rgba(255, 255, 255, 255));
    afw_gui_draw_text(&s, 10, 90, 2, afw_rgba(250, 240, 10, 255), "AFW");
    afw_gui_present(&s);

    get_rgb(&s, 5, 100, &r, &g, &b);
    check("gui_clear background pixel", r == 10 && g == 20 && b == 30);
    get_rgb(&s, 30, 25, &r, &g, &b);
    check("gui_fill_rect interior pixel", r == 200 && g == 100 && b == 50);
    get_rgb(&s, 110, 60, &r, &g, &b);
    check("gui_fill_circle center pixel", r == 40 && g == 220 && b == 80);
    get_rgb(&s, 5, 5, &r, &g, &b);
    check("gui_draw_line diagonal pixel", r == 255 && g == 255 && b == 255);
    check("gui_present increments frame counter", s.frames_presented == 1);

    /* BMP export header check */
    check("gui_save_bmp succeeds", afw_gui_save_bmp(&s, bmp_path) == 0);
    f = fopen(bmp_path, "rb");
    check("bmp file readable", f != NULL);
    if (f) {
        size_t nr = fread(hdr, 1, sizeof hdr, f);
        int32_t w = (int32_t)(hdr[18] | (hdr[19] << 8) | (hdr[20] << 16) | (hdr[21] << 24));
        int32_t h = (int32_t)(hdr[22] | (hdr[23] << 8) | (hdr[24] << 16) | (hdr[25] << 24));
        fclose(f);
        check("bmp magic BM and dimensions 160x120", nr == 54 && hdr[0] == 'B' && hdr[1] == 'M' && w == 160 && h == 120);
        remove(bmp_path);
    }

    /* SPSC event ring wraparound check */
    for (i = 0; i < 80; i++) {
        memset(&ev, 0, sizeof ev);
        ev.type = (i & 1) ? AFW_EV_KEY_DOWN : AFW_EV_TOUCH_DOWN;
        ev.x = (float)i;
        ev.keycode = 100 + i;
        afw_gui_push_event(&s, &ev);
        check("gui_pop_event returns pushed event", afw_gui_pop_event(&s, &out) == 1 && out.keycode == 100 + i);
    }
    check("gui_pop_event empty returns 0", afw_gui_pop_event(&s, &out) == 0);

    afw_gui_destroy(&s);
}

/* ---- 2. EGL 1.4 + OpenGL ES 2.0 software rasterizer ---- */
static void test_gles_bridge(void) {
    typedef SYSV void *(*eglGetDisplay_fn)(void *);
    typedef SYSV int32_t (*eglInitialize_fn)(void *, int32_t *, int32_t *);
    typedef SYSV int32_t (*eglChooseConfig_fn)(void *, const int32_t *, void **, int32_t, int32_t *);
    typedef SYSV void *(*eglCreateWindowSurface_fn)(void *, void *, void *, const int32_t *);
    typedef SYSV void *(*eglCreateContext_fn)(void *, void *, void *, const int32_t *);
    typedef SYSV int32_t (*eglMakeCurrent_fn)(void *, void *, void *, void *);
    typedef SYSV int32_t (*eglSwapBuffers_fn)(void *, void *);
    typedef SYSV int32_t (*eglDestroyContext_fn)(void *, void *);
    typedef SYSV int32_t (*eglDestroySurface_fn)(void *, void *);
    typedef SYSV int32_t (*eglTerminate_fn)(void *);

    typedef SYSV void (*glViewport_fn)(int32_t, int32_t, int32_t, int32_t);
    typedef SYSV void (*glClearColor_fn)(float, float, float, float);
    typedef SYSV void (*glClear_fn)(uint32_t);
    typedef SYSV uint32_t (*glCreateProgram_fn)(void);
    typedef SYSV void (*glLinkProgram_fn)(uint32_t);
    typedef SYSV void (*glUseProgram_fn)(uint32_t);
    typedef SYSV int32_t (*glGetAttribLocation_fn)(uint32_t, const char *);
    typedef SYSV void (*glEnableVertexAttribArray_fn)(uint32_t);
    typedef SYSV void (*glVertexAttribPointer_fn)(uint32_t, int32_t, uint32_t, uint8_t, int32_t, const void *);
    typedef SYSV void (*glDrawArrays_fn)(uint32_t, int32_t, int32_t);
    typedef SYSV void (*glDeleteProgram_fn)(uint32_t);

    afw_gui_surface s;
    void *win, *dpy, *cfg = NULL, *surf, *ctx;
    int32_t maj = 0, min = 0, ncfg = 0;
    uint32_t prog;
    int32_t pos_loc, col_loc;
    uint8_t r, g, b;

    const float pos[6] = { 0.0f, 0.8f, -0.8f, -0.8f, 0.8f, -0.8f };
    const float col[12] = {
        1.0f, 0.0f, 0.0f, 1.0f,
        0.0f, 1.0f, 0.0f, 1.0f,
        0.0f, 0.0f, 1.0f, 1.0f
    };

    check("gles surface create", afw_gui_create(&s, "GLES", 200, 200, 1) == 0);
    afw_android_native_bind(NULL, &s, ".", NULL, NULL);
    win = afw_android_get_window();
    check("android native window bound", win != NULL);

    dpy = ((eglGetDisplay_fn)afw_gles_lookup("eglGetDisplay"))(NULL);
    check("eglInitialize returns 1.4",
          ((eglInitialize_fn)afw_gles_lookup("eglInitialize"))(dpy, &maj, &min) == 1 && maj == 1 && min == 4);
    check("eglChooseConfig succeeds",
          ((eglChooseConfig_fn)afw_gles_lookup("eglChooseConfig"))(dpy, NULL, &cfg, 1, &ncfg) == 1 && ncfg == 1);
    surf = ((eglCreateWindowSurface_fn)afw_gles_lookup("eglCreateWindowSurface"))(dpy, cfg, win, NULL);
    ctx  = ((eglCreateContext_fn)afw_gles_lookup("eglCreateContext"))(dpy, cfg, NULL, NULL);
    check("eglMakeCurrent succeeds",
          ((eglMakeCurrent_fn)afw_gles_lookup("eglMakeCurrent"))(dpy, surf, surf, ctx) == 1);

    prog = ((glCreateProgram_fn)afw_gles_lookup("glCreateProgram"))();
    ((glLinkProgram_fn)afw_gles_lookup("glLinkProgram"))(prog);
    ((glUseProgram_fn)afw_gles_lookup("glUseProgram"))(prog);
    pos_loc = ((glGetAttribLocation_fn)afw_gles_lookup("glGetAttribLocation"))(prog, "a_pos");
    col_loc = ((glGetAttribLocation_fn)afw_gles_lookup("glGetAttribLocation"))(prog, "a_color");
    ((glEnableVertexAttribArray_fn)afw_gles_lookup("glEnableVertexAttribArray"))((uint32_t)pos_loc);
    ((glEnableVertexAttribArray_fn)afw_gles_lookup("glEnableVertexAttribArray"))((uint32_t)col_loc);

    ((glViewport_fn)afw_gles_lookup("glViewport"))(0, 0, 200, 200);
    ((glClearColor_fn)afw_gles_lookup("glClearColor"))(0.1f, 0.2f, 0.4f, 1.0f);
    ((glClear_fn)afw_gles_lookup("glClear"))(0x00004000u);
    ((glVertexAttribPointer_fn)afw_gles_lookup("glVertexAttribPointer"))((uint32_t)pos_loc, 2, 0x1406u, 0, 0, pos);
    ((glVertexAttribPointer_fn)afw_gles_lookup("glVertexAttribPointer"))((uint32_t)col_loc, 4, 0x1406u, 0, 0, col);
    ((glDrawArrays_fn)afw_gles_lookup("glDrawArrays"))(0x0004u, 0, 3);
    check("eglSwapBuffers succeeds", ((eglSwapBuffers_fn)afw_gles_lookup("eglSwapBuffers"))(dpy, surf) == 1);

    get_rgb(&s, 5, 5, &r, &g, &b);
    check("gles background pixel matches glClearColor", r >= 24 && r <= 27 && g >= 50 && g <= 52 && b >= 100 && b <= 104);
    get_rgb(&s, 100, 100, &r, &g, &b);
    check("gles triangle interior pixel rasterized", r > 50 && g > 50 && b > 50);

    ((glDeleteProgram_fn)afw_gles_lookup("glDeleteProgram"))(prog);
    ((eglMakeCurrent_fn)afw_gles_lookup("eglMakeCurrent"))(dpy, NULL, NULL, NULL);
    ((eglDestroyContext_fn)afw_gles_lookup("eglDestroyContext"))(dpy, ctx);
    ((eglDestroySurface_fn)afw_gles_lookup("eglDestroySurface"))(dpy, surf);
    ((eglTerminate_fn)afw_gles_lookup("eglTerminate"))(dpy);
    afw_gles_shutdown();
    afw_android_native_unbind();
    afw_gui_destroy(&s);
}

/* ---- 3. Real DEX + Bidirectional JNI (incl. CallIntMethodV SysV va_list) ---- */
typedef struct {
    uint32_t gp_offset;
    uint32_t fp_offset;
    void    *overflow_arg_area;
    void    *reg_save_area;
} test_sysv_va_tag;

typedef struct {
    const char *name;
    const char *sig;
    void       *fn;
} test_jni_reg;

static SYSV void *host_native_run_check(void *env, void *thiz, int32_t a, int32_t b) {
    const void *const *vt = *(const void *const **)env;
    typedef SYSV void *(*GetObjectClass_fn)(void *, void *);
    typedef SYSV void *(*GetMethodID_fn)(void *, void *, const char *, const char *);
    typedef SYSV int32_t (*CallIntMethod_fn)(void *, void *, void *, int32_t);
    typedef SYSV int32_t (*CallIntMethodV_fn)(void *, void *, void *, const test_sysv_va_tag *);
    typedef SYSV void *(*NewIntArray_fn)(void *, int32_t);
    typedef SYSV void (*SetIntArrayRegion_fn)(void *, void *, int32_t, int32_t, const int32_t *);
    typedef SYSV void (*GetIntArrayRegion_fn)(void *, void *, int32_t, int32_t, int32_t *);
    typedef SYSV void *(*NewStringUTF_fn)(void *, const char *);

    void *cls = ((GetObjectClass_fn)vt[31])(env, thiz);
    void *mid = ((GetMethodID_fn)vt[33])(env, cls, "javaCallback", "(I)I");
    /* Verify BOTH direct CallIntMethod (slot 49) and SysV va_list CallIntMethodV (slot 50) */
    int32_t v_direct = ((CallIntMethod_fn)vt[49])(env, thiz, mid, 6);
    uint64_t reg_save[6] = { 0, 0, 0, 6, 0, 0 }; /* 4th GP arg (rcx) holds first variadic arg */
    test_sysv_va_tag va = { 24, 48, NULL, reg_save };
    int32_t v_valist = ((CallIntMethodV_fn)vt[50])(env, thiz, mid, &va);

    void *arr = ((NewIntArray_fn)vt[179])(env, 3);
    int32_t in_vals[3] = { a, b, (v_direct == 45 && v_valist == 45) ? v_valist : -1 };
    int32_t out_vals[3] = { 0, 0, 0 };
    char buf[64];

    ((SetIntArrayRegion_fn)vt[211])(env, arr, 0, 3, in_vals);
    ((GetIntArrayRegion_fn)vt[203])(env, arr, 0, 3, out_vals);
    snprintf(buf, sizeof buf, "JNI_OK:%d", out_vals[0] + out_vals[1] + out_vals[2]);
    return ((NewStringUTF_fn)vt[167])(env, buf);
}

static int host_load_lib_cb(const char *libname, void *ud) {
    afw_dex_vm *vm = *(afw_dex_vm **)ud;
    void *env = afw_dex_vm_get_jnienv(vm);
    const void *const *vt = *(const void *const **)env;
    typedef SYSV void *(*FindClass_fn)(void *, const char *);
    typedef SYSV int32_t (*RegisterNatives_fn)(void *, void *, const test_jni_reg *, int32_t);
    void *cls;
    test_jni_reg reg = { "nativeRunCheck", "(II)Ljava/lang/String;", (void *)host_native_run_check };

    if (strcmp(libname, "dex_jni_demo") != 0) return -1;
    cls = ((FindClass_fn)vt[6])(env, "com/afw/dexdemo/MainActivity");
    if (!cls) return -1;
    return ((RegisterNatives_fn)vt[215])(env, cls, &reg, 1);
}

static void test_dex_apk(const char *apk_path) {
    afw_apk apk;
    afw_gui_surface s;
    unsigned char *dex_buf = NULL;
    size_t dex_sz = 0;
    afw_dex_vm *vm = NULL;
    uint8_t r, g, b;

    check("open dex_jni_demo.apk", afw_apk_open(apk_path, &apk) == 0);
    check("extract classes.dex", afw_apk_read_file(&apk, "classes.dex", &dex_buf, &dex_sz) == 0 && dex_sz > 112);
    check("create gui surface for DEX Canvas", afw_gui_create(&s, "DEX", 640, 480, 1) == 0);

    vm = afw_dex_vm_create(dex_buf, dex_sz, &apk, &s, host_load_lib_cb, &vm);
    free(dex_buf);
    check("dex_vm_create parses javac+d8 classes.dex", vm != NULL);
    if (vm) {
        int rc = afw_dex_run_activity(vm, apk.manifest.main_activity, 2);
        check("dex_run_activity completes 2 frames", rc == 0 && afw_dex_frames_drawn(vm) == 2);
        get_rgb(&s, 10, 10, &r, &g, &b);
        check("Canvas background green (JNI_OK:75 verified!)", r == 24 && g == 120 && b == 64);
        get_rgb(&s, 100, 80, &r, &g, &b);
        check("Canvas golden header rect rendered", r == 240 && g == 200 && b == 40);
        get_rgb(&s, 320, 340, &r, &g, &b);
        check("Canvas red circle rendered", r == 220 && g == 48 && b == 48);
        afw_dex_vm_destroy(vm);
    }

    afw_gui_destroy(&s);
    afw_apk_close(&apk);
}

int main(int argc, char **argv) {
    test_win_gui();
    test_gles_bridge();
    if (argc >= 2)
        test_dex_apk(argv[1]);
    printf("dex_gles_test: %d passed, %d failed\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}
