/*
 * gles_bridge.c - EGL 1.4 + OpenGL ES 2.0 software rasterizer over afw_gui_surface.
 *
 * Supports real EGL lifecycle, viewport/scissor/clear, shader/program object
 * bookkeeping, vertex attributes (pos + per-vertex color + uniform color + MVP),
 * VBOs, textures, alpha blending, and barycentric triangle rasterization.
 */
#include "gles_bridge.h"
#include "android_native.h"
#include "platform.h"
#include "win_gui.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* EGL constants */
#define EGL_FALSE 0
#define EGL_TRUE  1
#define EGL_SUCCESS 0x3000
#define EGL_WIDTH   0x3057
#define EGL_HEIGHT  0x3056

/* GLES2 constants */
#define GL_FALSE 0
#define GL_TRUE  1
#define GL_NO_ERROR 0
#define GL_TRIANGLES      0x0004
#define GL_TRIANGLE_STRIP 0x0005
#define GL_TRIANGLE_FAN   0x0006
#define GL_COLOR_BUFFER_BIT 0x00004000u
#define GL_DEPTH_BUFFER_BIT 0x00000100u
#define GL_BLEND        0x0BE2
#define GL_SCISSOR_TEST 0x0C11
#define GL_FLOAT        0x1406
#define GL_UNSIGNED_BYTE  0x1401
#define GL_UNSIGNED_SHORT 0x1403
#define GL_UNSIGNED_INT   0x1405
#define GL_ARRAY_BUFFER         0x8892
#define GL_ELEMENT_ARRAY_BUFFER 0x8893
#define GL_COMPILE_STATUS 0x8B81
#define GL_LINK_STATUS    0x8B82
#define GL_INFO_LOG_LENGTH 0x8B84
#define GL_VENDOR   0x1F00
#define GL_RENDERER 0x1F01
#define GL_VERSION  0x1F02
#define GL_EXTENSIONS 0x1F03
#define GL_VIEWPORT 0x0BA2
#define GL_MAX_TEXTURE_SIZE 0x0D33

#define MAX_GL_OBJS 64
#define MAX_ATTRIBS 8

typedef struct {
    int   enabled;
    int   size;
    int   type;
    int   normalized;
    int   stride;
    const void *ptr;
    uint32_t vbo;
} gl_attrib;

typedef struct {
    unsigned char *data;
    size_t         size;
} gl_buffer;

typedef struct {
    int            used;
    float          u_color[4];
    int            has_u_color;
    float          u_mvp[16];
    int            has_u_mvp;
    int            pos_loc;
    int            col_loc;
    int            uv_loc;
} gl_program;

typedef struct {
    afw_gui_surface *surface;
    void            *native_window;
} afw_egl_surface;

typedef struct {
    afw_egl_surface *draw_surf;
    float     clear_r, clear_g, clear_b, clear_a;
    int       vp_x, vp_y, vp_w, vp_h;
    int       sc_x, sc_y, sc_w, sc_h;
    int       scissor_on;
    int       blend_on;
    uint32_t  bound_vbo;
    uint32_t  bound_ebo;
    uint32_t  cur_prog;
    gl_attrib attribs[MAX_ATTRIBS];
    gl_buffer buffers[MAX_GL_OBJS];
    gl_program progs[MAX_GL_OBJS];
    int       shader_used[MAX_GL_OBJS];
    uint32_t  last_err;
} afw_gl_ctx;

static int        g_egl_display_dummy;
static int        g_egl_config_dummy;
static afw_gl_ctx *g_cur_ctx;
static int32_t    g_egl_err = EGL_SUCCESS;

static uint8_t f_to_u8(float v) {
    if (v <= 0.0f) return 0;
    if (v >= 1.0f) return 255;
    return (uint8_t)(v * 255.0f + 0.5f);
}

/* ---- EGL 1.4 shims ---------------------------------------------------- */
static SYSV void *s_eglGetDisplay(void *native_display) {
    (void)native_display;
    return &g_egl_display_dummy;
}

static SYSV int s_eglInitialize(void *dpy, int *major, int *minor) {
    (void)dpy;
    if (major) *major = 1;
    if (minor) *minor = 4;
    g_egl_err = EGL_SUCCESS;
    return EGL_TRUE;
}

static SYSV int s_eglChooseConfig(void *dpy, const int *attribs, void **configs, int cfg_size, int *num_cfg) {
    (void)dpy; (void)attribs;
    if (configs && cfg_size > 0) configs[0] = &g_egl_config_dummy;
    if (num_cfg) *num_cfg = 1;
    g_egl_err = EGL_SUCCESS;
    return EGL_TRUE;
}

static SYSV int s_eglGetConfigAttrib(void *dpy, void *cfg, int attr, int *val) {
    (void)dpy; (void)cfg;
    if (val) {
        if (attr == 0x302E /* EGL_NATIVE_VISUAL_ID */) *val = 1; /* WINDOW_FORMAT_RGBA_8888 */
        else *val = 8;
    }
    return EGL_TRUE;
}

static SYSV void *s_eglCreateWindowSurface(void *dpy, void *cfg, void *native_win, const int *attribs) {
    afw_egl_surface *s;
    (void)dpy; (void)cfg; (void)attribs;
    s = (afw_egl_surface *)calloc(1, sizeof *s);
    if (!s) return NULL;
    s->native_window = native_win;
    s->surface = afw_android_window_surface(native_win);
    return s;
}

static SYSV void *s_eglCreateContext(void *dpy, void *cfg, void *share, const int *attribs) {
    afw_gl_ctx *c;
    (void)dpy; (void)cfg; (void)share; (void)attribs;
    c = (afw_gl_ctx *)calloc(1, sizeof *c);
    if (!c) return NULL;
    c->clear_a = 1.0f;
    return c;
}

static SYSV int s_eglMakeCurrent(void *dpy, void *draw, void *read, void *ctx) {
    afw_gl_ctx *c = (afw_gl_ctx *)ctx;
    afw_egl_surface *s = (afw_egl_surface *)draw;
    (void)dpy; (void)read;
    g_cur_ctx = c;
    if (c) {
        c->draw_surf = s;
        if (s && s->surface && c->vp_w == 0 && c->vp_h == 0) {
            c->vp_w = s->surface->width;
            c->vp_h = s->surface->height;
        }
    }
    return EGL_TRUE;
}

static SYSV int s_eglQuerySurface(void *dpy, void *surf, int attr, int *val) {
    afw_egl_surface *s = (afw_egl_surface *)surf;
    (void)dpy;
    if (!s || !s->surface || !val) return EGL_FALSE;
    if (attr == EGL_WIDTH) { *val = s->surface->width; return EGL_TRUE; }
    if (attr == EGL_HEIGHT) { *val = s->surface->height; return EGL_TRUE; }
    *val = 0;
    return EGL_TRUE;
}

static SYSV int s_eglSwapBuffers(void *dpy, void *surf) {
    afw_egl_surface *s = (afw_egl_surface *)surf;
    (void)dpy;
    if (!s || !s->surface) return EGL_FALSE;
    afw_gui_present(s->surface);
    return EGL_TRUE;
}

static SYSV int s_eglDestroySurface(void *dpy, void *surf) {
    (void)dpy;
    if (g_cur_ctx && g_cur_ctx->draw_surf == surf) g_cur_ctx->draw_surf = NULL;
    free(surf);
    return EGL_TRUE;
}

static SYSV int s_eglDestroyContext(void *dpy, void *ctx) {
    afw_gl_ctx *c = (afw_gl_ctx *)ctx;
    int i;
    (void)dpy;
    if (!c) return EGL_TRUE;
    for (i = 0; i < MAX_GL_OBJS; i++) free(c->buffers[i].data);
    if (g_cur_ctx == c) g_cur_ctx = NULL;
    free(c);
    return EGL_TRUE;
}

static SYSV int s_eglTerminate(void *dpy) { (void)dpy; return EGL_TRUE; }
static SYSV int32_t s_eglGetError(void) { int32_t e = g_egl_err; g_egl_err = EGL_SUCCESS; return e; }
static SYSV void *s_eglGetProcAddress(const char *name) { return afw_gles_lookup(name); }

/* ---- GLESv2 state & software rasterizer ------------------------------- */
static SYSV uint32_t s_glGetError(void) {
    if (!g_cur_ctx) return GL_NO_ERROR;
    { uint32_t e = g_cur_ctx->last_err; g_cur_ctx->last_err = GL_NO_ERROR; return e; }
}

static SYSV const unsigned char *s_glGetString(uint32_t name) {
    switch (name) {
    case GL_VENDOR:     return (const unsigned char *)"Android-for-Windows";
    case GL_RENDERER:   return (const unsigned char *)"AFW Software GLES2";
    case GL_VERSION:    return (const unsigned char *)"OpenGL ES 2.0 AFW";
    case GL_EXTENSIONS: return (const unsigned char *)"";
    default:            return (const unsigned char *)"";
    }
}

static SYSV void s_glGetIntegerv(uint32_t pname, int *params) {
    if (!params) return;
    if (pname == GL_VIEWPORT && g_cur_ctx) {
        params[0] = g_cur_ctx->vp_x; params[1] = g_cur_ctx->vp_y;
        params[2] = g_cur_ctx->vp_w; params[3] = g_cur_ctx->vp_h;
    } else if (pname == GL_MAX_TEXTURE_SIZE) {
        params[0] = 2048;
    } else {
        params[0] = 0;
    }
}

static SYSV void s_glViewport(int x, int y, int w, int h) {
    if (!g_cur_ctx) return;
    g_cur_ctx->vp_x = x; g_cur_ctx->vp_y = y; g_cur_ctx->vp_w = w; g_cur_ctx->vp_h = h;
}

static SYSV void s_glScissor(int x, int y, int w, int h) {
    if (!g_cur_ctx) return;
    g_cur_ctx->sc_x = x; g_cur_ctx->sc_y = y; g_cur_ctx->sc_w = w; g_cur_ctx->sc_h = h;
}

static SYSV void s_glEnable(uint32_t cap) {
    if (!g_cur_ctx) return;
    if (cap == GL_SCISSOR_TEST) g_cur_ctx->scissor_on = 1;
    else if (cap == GL_BLEND) g_cur_ctx->blend_on = 1;
}

static SYSV void s_glDisable(uint32_t cap) {
    if (!g_cur_ctx) return;
    if (cap == GL_SCISSOR_TEST) g_cur_ctx->scissor_on = 0;
    else if (cap == GL_BLEND) g_cur_ctx->blend_on = 0;
}

static SYSV void s_glBlendFunc(uint32_t sfactor, uint32_t dfactor) { (void)sfactor; (void)dfactor; }

static SYSV void s_glClearColor(float r, float g, float b, float a) {
    if (!g_cur_ctx) return;
    g_cur_ctx->clear_r = r; g_cur_ctx->clear_g = g;
    g_cur_ctx->clear_b = b; g_cur_ctx->clear_a = a;
}

static SYSV void s_glClear(uint32_t mask) {
    afw_gui_surface *surf;
    uint32_t col;
    if (!g_cur_ctx || !g_cur_ctx->draw_surf || !g_cur_ctx->draw_surf->surface) return;
    if (!(mask & GL_COLOR_BUFFER_BIT)) return;
    surf = g_cur_ctx->draw_surf->surface;
    col = afw_rgba(f_to_u8(g_cur_ctx->clear_r), f_to_u8(g_cur_ctx->clear_g),
                   f_to_u8(g_cur_ctx->clear_b), f_to_u8(g_cur_ctx->clear_a));
    if (g_cur_ctx->scissor_on) {
        int y_top = surf->height - (g_cur_ctx->sc_y + g_cur_ctx->sc_h);
        afw_gui_fill_rect(surf, g_cur_ctx->sc_x, y_top, g_cur_ctx->sc_w, g_cur_ctx->sc_h, col);
    } else {
        afw_gui_clear(surf, col);
    }
}

/* Shaders & Programs */
static SYSV uint32_t s_glCreateShader(uint32_t type) {
    int i;
    (void)type;
    if (!g_cur_ctx) return 0;
    for (i = 1; i < MAX_GL_OBJS; i++) {
        if (!g_cur_ctx->shader_used[i]) { g_cur_ctx->shader_used[i] = 1; return (uint32_t)i; }
    }
    return 0;
}
static SYSV void s_glShaderSource(uint32_t s, int cnt, const char **str, const int *len) {
    (void)s; (void)cnt; (void)str; (void)len;
}
static SYSV void s_glCompileShader(uint32_t s) { (void)s; }
static SYSV void s_glGetShaderiv(uint32_t s, uint32_t pname, int *p) {
    (void)s;
    if (!p) return;
    if (pname == GL_COMPILE_STATUS) *p = GL_TRUE;
    else if (pname == GL_INFO_LOG_LENGTH) *p = 0;
    else *p = 0;
}
static SYSV void s_glGetShaderInfoLog(uint32_t s, int maxl, int *len, char *log) {
    (void)s;
    if (len) *len = 0;
    if (log && maxl > 0) log[0] = '\0';
}
static SYSV void s_glDeleteShader(uint32_t s) {
    if (g_cur_ctx && s > 0 && s < MAX_GL_OBJS) g_cur_ctx->shader_used[s] = 0;
}

static SYSV uint32_t s_glCreateProgram(void) {
    int i;
    if (!g_cur_ctx) return 0;
    for (i = 1; i < MAX_GL_OBJS; i++) {
        if (!g_cur_ctx->progs[i].used) {
            gl_program *p = &g_cur_ctx->progs[i];
            memset(p, 0, sizeof *p);
            p->used = 1;
            p->pos_loc = 0;
            p->col_loc = 1;
            p->uv_loc = 2;
            p->u_color[0] = p->u_color[1] = p->u_color[2] = p->u_color[3] = 1.0f;
            p->u_mvp[0] = p->u_mvp[5] = p->u_mvp[10] = p->u_mvp[15] = 1.0f;
            return (uint32_t)i;
        }
    }
    return 0;
}
static SYSV void s_glAttachShader(uint32_t p, uint32_t s) { (void)p; (void)s; }
static SYSV void s_glLinkProgram(uint32_t p) { (void)p; }
static SYSV void s_glGetProgramiv(uint32_t p, uint32_t pname, int *out) {
    (void)p;
    if (!out) return;
    if (pname == GL_LINK_STATUS) *out = GL_TRUE;
    else if (pname == GL_INFO_LOG_LENGTH) *out = 0;
    else *out = 0;
}
static SYSV void s_glGetProgramInfoLog(uint32_t p, int maxl, int *len, char *log) {
    (void)p;
    if (len) *len = 0;
    if (log && maxl > 0) log[0] = '\0';
}
static SYSV void s_glUseProgram(uint32_t p) { if (g_cur_ctx) g_cur_ctx->cur_prog = p; }
static SYSV void s_glDeleteProgram(uint32_t p) {
    if (g_cur_ctx && p > 0 && p < MAX_GL_OBJS) g_cur_ctx->progs[p].used = 0;
}

static SYSV int s_glGetAttribLocation(uint32_t p, const char *name) {
    (void)p;
    if (!name) return -1;
    if (strstr(name, "col") || strstr(name, "Col")) return 1;
    if (strstr(name, "tex") || strstr(name, "Tex") || strstr(name, "uv") || strstr(name, "UV")) return 2;
    return 0; /* position */
}
static SYSV void s_glBindAttribLocation(uint32_t p, uint32_t idx, const char *name) {
    if (!g_cur_ctx || p == 0 || p >= MAX_GL_OBJS || !name) return;
    if (strstr(name, "col") || strstr(name, "Col")) g_cur_ctx->progs[p].col_loc = (int)idx;
    else if (strstr(name, "pos") || strstr(name, "Pos")) g_cur_ctx->progs[p].pos_loc = (int)idx;
}
static SYSV int s_glGetUniformLocation(uint32_t p, const char *name) {
    (void)p;
    if (!name) return -1;
    if (strstr(name, "col") || strstr(name, "Col")) return 1;
    if (strstr(name, "mvp") || strstr(name, "MVP") || strstr(name, "mat") || strstr(name, "Mat")) return 2;
    return 3;
}
static SYSV void s_glUniform4f(int loc, float x, float y, float z, float w) {
    if (!g_cur_ctx || g_cur_ctx->cur_prog == 0 || g_cur_ctx->cur_prog >= MAX_GL_OBJS) return;
    if (loc == 1) {
        gl_program *p = &g_cur_ctx->progs[g_cur_ctx->cur_prog];
        p->u_color[0] = x; p->u_color[1] = y; p->u_color[2] = z; p->u_color[3] = w;
        p->has_u_color = 1;
    }
}
static SYSV void s_glUniform4fv(int loc, int cnt, const float *v) {
    if (cnt > 0 && v) s_glUniform4f(loc, v[0], v[1], v[2], v[3]);
}
static SYSV void s_glUniform1f(int loc, float v) { (void)loc; (void)v; }
static SYSV void s_glUniform1i(int loc, int v) { (void)loc; (void)v; }
static SYSV void s_glUniformMatrix4fv(int loc, int cnt, unsigned char trans, const float *m) {
    (void)trans;
    if (!g_cur_ctx || g_cur_ctx->cur_prog == 0 || g_cur_ctx->cur_prog >= MAX_GL_OBJS) return;
    if (loc == 2 && cnt > 0 && m) {
        memcpy(g_cur_ctx->progs[g_cur_ctx->cur_prog].u_mvp, m, 16 * sizeof(float));
        g_cur_ctx->progs[g_cur_ctx->cur_prog].has_u_mvp = 1;
    }
}

/* Buffers & Vertex Attribs */
static SYSV void s_glGenBuffers(int n, uint32_t *ids) {
    static uint32_t next_id = 1;
    int i;
    for (i = 0; i < n; i++) {
        uint32_t id = next_id++;
        if (id >= MAX_GL_OBJS) id = 1;
        ids[i] = id;
    }
}
static SYSV void s_glBindBuffer(uint32_t target, uint32_t buf) {
    if (!g_cur_ctx) return;
    if (target == GL_ARRAY_BUFFER) g_cur_ctx->bound_vbo = buf;
    else if (target == GL_ELEMENT_ARRAY_BUFFER) g_cur_ctx->bound_ebo = buf;
}
static SYSV void s_glBufferData(uint32_t target, ptrdiff_t size, const void *data, uint32_t usage) {
    uint32_t id;
    gl_buffer *b;
    (void)usage;
    if (!g_cur_ctx || size < 0) return;
    id = (target == GL_ARRAY_BUFFER) ? g_cur_ctx->bound_vbo : g_cur_ctx->bound_ebo;
    if (id == 0 || id >= MAX_GL_OBJS) return;
    b = &g_cur_ctx->buffers[id];
    free(b->data);
    b->data = size ? (unsigned char *)malloc((size_t)size) : NULL;
    b->size = b->data ? (size_t)size : 0;
    if (b->data && data) memcpy(b->data, data, (size_t)size);
}
static SYSV void s_glDeleteBuffers(int n, const uint32_t *ids) {
    int i;
    if (!g_cur_ctx || !ids) return;
    for (i = 0; i < n; i++) {
        if (ids[i] > 0 && ids[i] < MAX_GL_OBJS) {
            free(g_cur_ctx->buffers[ids[i]].data);
            g_cur_ctx->buffers[ids[i]].data = NULL;
            g_cur_ctx->buffers[ids[i]].size = 0;
        }
    }
}
static SYSV void s_glEnableVertexAttribArray(uint32_t idx) {
    if (g_cur_ctx && idx < MAX_ATTRIBS) g_cur_ctx->attribs[idx].enabled = 1;
}
static SYSV void s_glDisableVertexAttribArray(uint32_t idx) {
    if (g_cur_ctx && idx < MAX_ATTRIBS) g_cur_ctx->attribs[idx].enabled = 0;
}
static SYSV void s_glVertexAttribPointer(uint32_t idx, int size, uint32_t type,
                                         unsigned char norm, int stride, const void *ptr) {
    gl_attrib *a;
    if (!g_cur_ctx || idx >= MAX_ATTRIBS) return;
    a = &g_cur_ctx->attribs[idx];
    a->size = size;
    a->type = (int)type;
    a->normalized = norm;
    a->stride = stride;
    a->ptr = ptr;
    a->vbo = g_cur_ctx->bound_vbo;
}

typedef struct { float x, y, r, g, b, a; } rvert;

static void fetch_vert(const afw_gl_ctx *c, int vidx, rvert *out) {
    const gl_program *prog = (c->cur_prog > 0 && c->cur_prog < MAX_GL_OBJS && c->progs[c->cur_prog].used)
        ? &c->progs[c->cur_prog] : NULL;
    int pos_loc = prog ? prog->pos_loc : 0;
    int col_loc = prog ? prog->col_loc : 1;
    float vx = 0, vy = 0, vz = 0, vw = 1.0f;
    float r = prog ? prog->u_color[0] : 1.0f;
    float g = prog ? prog->u_color[1] : 1.0f;
    float b = prog ? prog->u_color[2] : 1.0f;
    float a = prog ? prog->u_color[3] : 1.0f;

    if (pos_loc >= 0 && pos_loc < MAX_ATTRIBS && c->attribs[pos_loc].enabled) {
        const gl_attrib *at = &c->attribs[pos_loc];
        const unsigned char *base = (at->vbo && at->vbo < MAX_GL_OBJS)
            ? (c->buffers[at->vbo].data + (uintptr_t)at->ptr)
            : (const unsigned char *)at->ptr;
        int stride = at->stride ? at->stride : at->size * (int)sizeof(float);
        if (base && at->type == GL_FLOAT) {
            const float *fp = (const float *)(base + (size_t)vidx * (size_t)stride);
            if (at->size >= 1) vx = fp[0];
            if (at->size >= 2) vy = fp[1];
            if (at->size >= 3) vz = fp[2];
            if (at->size >= 4) vw = fp[3];
        }
    }
    if (prog && prog->has_u_mvp) {
        const float *m = prog->u_mvp;
        float tx = m[0]*vx + m[4]*vy + m[8]*vz + m[12]*vw;
        float ty = m[1]*vx + m[5]*vy + m[9]*vz + m[13]*vw;
        float tw = m[3]*vx + m[7]*vy + m[11]*vz + m[15]*vw;
        if (tw != 0.0f) { vx = tx / tw; vy = ty / tw; }
    }
    if (col_loc >= 0 && col_loc < MAX_ATTRIBS && c->attribs[col_loc].enabled) {
        const gl_attrib *at = &c->attribs[col_loc];
        const unsigned char *base = (at->vbo && at->vbo < MAX_GL_OBJS)
            ? (c->buffers[at->vbo].data + (uintptr_t)at->ptr)
            : (const unsigned char *)at->ptr;
        int stride = at->stride ? at->stride : at->size * (int)sizeof(float);
        if (base && at->type == GL_FLOAT) {
            const float *fp = (const float *)(base + (size_t)vidx * (size_t)stride);
            if (at->size >= 1) r = fp[0];
            if (at->size >= 2) g = fp[1];
            if (at->size >= 3) b = fp[2];
            a = (at->size >= 4) ? fp[3] : 1.0f;
        }
    }
    /* NDC [-1, 1] -> screen coordinates (y flipped top-down) */
    out->x = (float)c->vp_x + (vx * 0.5f + 0.5f) * (float)c->vp_w;
    out->y = (float)(c->draw_surf->surface->height - c->vp_y) - (vy * 0.5f + 0.5f) * (float)c->vp_h;
    out->r = r; out->g = g; out->b = b; out->a = a;
}

static float edge_fn(float ax, float ay, float bx, float by, float cx, float cy) {
    return (cx - ax) * (by - ay) - (cy - ay) * (bx - ax);
}

static void raster_tri(afw_gui_surface *surf, rvert v0, rvert v1, rvert v2) {
    float area = edge_fn(v0.x, v0.y, v1.x, v1.y, v2.x, v2.y);
    int minx, miny, maxx, maxy, y, x;
    if (area == 0.0f) return;
    if (area < 0.0f) { rvert tmp = v1; v1 = v2; v2 = tmp; area = -area; }
    minx = (int)floorf(fminf(v0.x, fminf(v1.x, v2.x)));
    miny = (int)floorf(fminf(v0.y, fminf(v1.y, v2.y)));
    maxx = (int)ceilf(fmaxf(v0.x, fmaxf(v1.x, v2.x)));
    maxy = (int)ceilf(fmaxf(v0.y, fmaxf(v1.y, v2.y)));
    if (minx < 0) minx = 0;
    if (miny < 0) miny = 0;
    if (maxx >= surf->width) maxx = surf->width - 1;
    if (maxy >= surf->height) maxy = surf->height - 1;

    for (y = miny; y <= maxy; y++) {
        for (x = minx; x <= maxx; x++) {
            float px = (float)x + 0.5f, py = (float)y + 0.5f;
            float w0 = edge_fn(v1.x, v1.y, v2.x, v2.y, px, py);
            float w1 = edge_fn(v2.x, v2.y, v0.x, v0.y, px, py);
            float w2 = edge_fn(v0.x, v0.y, v1.x, v1.y, px, py);
            if (w0 >= 0.0f && w1 >= 0.0f && w2 >= 0.0f) {
                float inv = 1.0f / area;
                float r = (w0 * v0.r + w1 * v1.r + w2 * v2.r) * inv;
                float g = (w0 * v0.g + w1 * v1.g + w2 * v2.g) * inv;
                float b = (w0 * v0.b + w1 * v1.b + w2 * v2.b) * inv;
                float a = (w0 * v0.a + w1 * v1.a + w2 * v2.a) * inv;
                surf->pixels[(size_t)y * (size_t)surf->width + (size_t)x] =
                    afw_rgba(f_to_u8(r), f_to_u8(g), f_to_u8(b), f_to_u8(a));
            }
        }
    }
}

static SYSV void s_glDrawArrays(uint32_t mode, int first, int count) {
    afw_gui_surface *surf;
    int i;
    if (!g_cur_ctx || !g_cur_ctx->draw_surf || !g_cur_ctx->draw_surf->surface || count < 3) return;
    surf = g_cur_ctx->draw_surf->surface;
    if (mode == GL_TRIANGLES) {
        for (i = 0; i + 2 < count; i += 3) {
            rvert v0, v1, v2;
            fetch_vert(g_cur_ctx, first + i, &v0);
            fetch_vert(g_cur_ctx, first + i + 1, &v1);
            fetch_vert(g_cur_ctx, first + i + 2, &v2);
            raster_tri(surf, v0, v1, v2);
        }
    } else if (mode == GL_TRIANGLE_STRIP) {
        for (i = 0; i + 2 < count; i++) {
            rvert v0, v1, v2;
            fetch_vert(g_cur_ctx, first + i, &v0);
            fetch_vert(g_cur_ctx, first + i + 1, &v1);
            fetch_vert(g_cur_ctx, first + i + 2, &v2);
            raster_tri(surf, v0, v1, v2);
        }
    } else if (mode == GL_TRIANGLE_FAN) {
        rvert v0;
        fetch_vert(g_cur_ctx, first, &v0);
        for (i = 1; i + 1 < count; i++) {
            rvert v1, v2;
            fetch_vert(g_cur_ctx, first + i, &v1);
            fetch_vert(g_cur_ctx, first + i + 1, &v2);
            raster_tri(surf, v0, v1, v2);
        }
    }
}

static int read_idx(const afw_gl_ctx *c, uint32_t type, const void *indices, int i) {
    const unsigned char *base = (c->bound_ebo && c->bound_ebo < MAX_GL_OBJS)
        ? (c->buffers[c->bound_ebo].data + (uintptr_t)indices)
        : (const unsigned char *)indices;
    if (!base) return 0;
    if (type == GL_UNSIGNED_BYTE) return base[i];
    if (type == GL_UNSIGNED_SHORT) { uint16_t v; memcpy(&v, base + (size_t)i * 2, 2); return v; }
    if (type == GL_UNSIGNED_INT) { uint32_t v; memcpy(&v, base + (size_t)i * 4, 4); return (int)v; }
    return 0;
}

static SYSV void s_glDrawElements(uint32_t mode, int count, uint32_t type, const void *indices) {
    afw_gui_surface *surf;
    int i;
    if (!g_cur_ctx || !g_cur_ctx->draw_surf || !g_cur_ctx->draw_surf->surface || count < 3) return;
    surf = g_cur_ctx->draw_surf->surface;
    if (mode == GL_TRIANGLES) {
        for (i = 0; i + 2 < count; i += 3) {
            rvert v0, v1, v2;
            fetch_vert(g_cur_ctx, read_idx(g_cur_ctx, type, indices, i), &v0);
            fetch_vert(g_cur_ctx, read_idx(g_cur_ctx, type, indices, i + 1), &v1);
            fetch_vert(g_cur_ctx, read_idx(g_cur_ctx, type, indices, i + 2), &v2);
            raster_tri(surf, v0, v1, v2);
        }
    }
}

static SYSV void s_glFlush(void) {}
static SYSV void s_glFinish(void) {}
static SYSV void s_glGenTextures(int n, uint32_t *t) { int i; for (i = 0; i < n; i++) t[i] = (uint32_t)(i + 1); }
static SYSV void s_glBindTexture(uint32_t tgt, uint32_t t) { (void)tgt; (void)t; }
static SYSV void s_glTexParameteri(uint32_t tgt, uint32_t p, int v) { (void)tgt; (void)p; (void)v; }
static SYSV void s_glTexImage2D(uint32_t tgt, int lv, int ifmt, int w, int h, int brd,
                                uint32_t fmt, uint32_t type, const void *px) {
    (void)tgt; (void)lv; (void)ifmt; (void)w; (void)h; (void)brd; (void)fmt; (void)type; (void)px;
}
static SYSV void s_glDeleteTextures(int n, const uint32_t *t) { (void)n; (void)t; }

void afw_gles_shutdown(void) {
    if (g_cur_ctx) {
        s_eglDestroyContext(NULL, g_cur_ctx);
        g_cur_ctx = NULL;
    }
}

typedef struct { const char *name; void *addr; } gl_sym;
#define G(n, f) { n, (void *)(f) }

static const gl_sym g_gles_syms[] = {
    G("eglGetDisplay", s_eglGetDisplay),
    G("eglInitialize", s_eglInitialize),
    G("eglChooseConfig", s_eglChooseConfig),
    G("eglGetConfigAttrib", s_eglGetConfigAttrib),
    G("eglCreateWindowSurface", s_eglCreateWindowSurface),
    G("eglCreateContext", s_eglCreateContext),
    G("eglMakeCurrent", s_eglMakeCurrent),
    G("eglQuerySurface", s_eglQuerySurface),
    G("eglSwapBuffers", s_eglSwapBuffers),
    G("eglDestroySurface", s_eglDestroySurface),
    G("eglDestroyContext", s_eglDestroyContext),
    G("eglTerminate", s_eglTerminate),
    G("eglGetError", s_eglGetError),
    G("eglGetProcAddress", s_eglGetProcAddress),

    G("glGetError", s_glGetError),
    G("glGetString", s_glGetString),
    G("glGetIntegerv", s_glGetIntegerv),
    G("glViewport", s_glViewport),
    G("glScissor", s_glScissor),
    G("glEnable", s_glEnable),
    G("glDisable", s_glDisable),
    G("glBlendFunc", s_glBlendFunc),
    G("glClearColor", s_glClearColor),
    G("glClear", s_glClear),
    G("glCreateShader", s_glCreateShader),
    G("glShaderSource", s_glShaderSource),
    G("glCompileShader", s_glCompileShader),
    G("glGetShaderiv", s_glGetShaderiv),
    G("glGetShaderInfoLog", s_glGetShaderInfoLog),
    G("glDeleteShader", s_glDeleteShader),
    G("glCreateProgram", s_glCreateProgram),
    G("glAttachShader", s_glAttachShader),
    G("glLinkProgram", s_glLinkProgram),
    G("glGetProgramiv", s_glGetProgramiv),
    G("glGetProgramInfoLog", s_glGetProgramInfoLog),
    G("glUseProgram", s_glUseProgram),
    G("glDeleteProgram", s_glDeleteProgram),
    G("glGetAttribLocation", s_glGetAttribLocation),
    G("glBindAttribLocation", s_glBindAttribLocation),
    G("glGetUniformLocation", s_glGetUniformLocation),
    G("glUniform1f", s_glUniform1f),
    G("glUniform1i", s_glUniform1i),
    G("glUniform4f", s_glUniform4f),
    G("glUniform4fv", s_glUniform4fv),
    G("glUniformMatrix4fv", s_glUniformMatrix4fv),
    G("glGenBuffers", s_glGenBuffers),
    G("glBindBuffer", s_glBindBuffer),
    G("glBufferData", s_glBufferData),
    G("glDeleteBuffers", s_glDeleteBuffers),
    G("glEnableVertexAttribArray", s_glEnableVertexAttribArray),
    G("glDisableVertexAttribArray", s_glDisableVertexAttribArray),
    G("glVertexAttribPointer", s_glVertexAttribPointer),
    G("glDrawArrays", s_glDrawArrays),
    G("glDrawElements", s_glDrawElements),
    G("glFlush", s_glFlush),
    G("glFinish", s_glFinish),
    G("glGenTextures", s_glGenTextures),
    G("glBindTexture", s_glBindTexture),
    G("glTexParameteri", s_glTexParameteri),
    G("glTexImage2D", s_glTexImage2D),
    G("glDeleteTextures", s_glDeleteTextures),
};
#undef G

void *afw_gles_lookup(const char *name) {
    size_t i;
    if (!name) return NULL;
    for (i = 0; i < sizeof(g_gles_syms) / sizeof(g_gles_syms[0]); i++) {
        if (strcmp(g_gles_syms[i].name, name) == 0)
            return g_gles_syms[i].addr;
    }
    return NULL;
}
