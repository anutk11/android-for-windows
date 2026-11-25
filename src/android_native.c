/*
 * android_native.c - Android NDK libandroid.so + liblog.so System V ABI shims.
 */
#include "android_native.h"
#include "fd.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#endif

/* ---- Active runtime state --------------------------------------------- */
typedef struct {
    const afw_apk *apk;
} afw_asset_mgr;

typedef struct {
    unsigned char *data;
    size_t         size;
    size_t         pos;
} afw_asset;

typedef struct {
    const afw_apk *apk;
    char           prefix[256];
    size_t         index;
} afw_asset_dir;

typedef struct {
    afw_gui_surface *surface;
    int32_t          format; /* 1 = WINDOW_FORMAT_RGBA_8888 */
    int32_t          refcount;
} afw_native_window;

typedef struct {
    int32_t type;      /* 1 = KEY, 2 = MOTION */
    int32_t action;    /* 0 = DOWN, 1 = UP, 2 = MOVE */
    int32_t keycode;
    float   x, y;
} afw_input_event;

typedef struct {
    afw_gui_surface *surface;
    void            *looper;
    int              ident;
} afw_input_queue;

typedef struct {
    int32_t density;
    int32_t orientation;
    int32_t sdk_version;
    char    lang[4];
    char    country[4];
} afw_configuration;

#define AFW_MAX_LOOPER_FDS 16
typedef SYSV int (*afw_looper_cb)(int fd, int events, void *data);

typedef struct {
    int           fd;
    int           ident;
    int           events;
    afw_looper_cb callback;
    void         *data;
} afw_looper_entry;

typedef struct {
    int32_t          refcount;
    int32_t          woken;
    int              nfds;
    afw_looper_entry fds[AFW_MAX_LOOPER_FDS];
    afw_input_queue *attached_iq;
} afw_looper;

static afw_ANativeActivityCallbacks g_callbacks;
static afw_ANativeActivity          g_activity;
static afw_asset_mgr                g_asset_mgr;
static afw_native_window            g_window;
static afw_input_queue              g_input_queue;
static char                         g_data_dir[512];
static int32_t                      g_finish_req;
static _Thread_local afw_looper    *t_looper;

static void sleep_ms_portable(int ms) {
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

void afw_android_native_bind(const afw_apk *apk, afw_gui_surface *surface,
                             const char *data_dir, void *jvm, void *jenv) {
    memset(&g_callbacks, 0, sizeof g_callbacks);
    memset(&g_activity, 0, sizeof g_activity);
    g_asset_mgr.apk = apk;
    g_window.surface = surface;
    g_window.format = 1; /* WINDOW_FORMAT_RGBA_8888 */
    g_window.refcount = 1;
    g_input_queue.surface = surface;
    g_input_queue.looper = NULL;
    g_input_queue.ident = 0;
    afw_os_atomic_store_i32(&g_finish_req, 0);

    snprintf(g_data_dir, sizeof g_data_dir, "%s", data_dir ? data_dir : ".");
    g_activity.callbacks        = &g_callbacks;
    g_activity.vm               = jvm;
    g_activity.env              = jenv;
    g_activity.clazz            = NULL;
    g_activity.internalDataPath = g_data_dir;
    g_activity.externalDataPath = g_data_dir;
    g_activity.sdkVersion       = 34;
    g_activity.instance         = NULL;
    g_activity.assetManager     = &g_asset_mgr;
    g_activity.obbPath          = g_data_dir;
}

void afw_android_native_unbind(void) {
    if (t_looper) {
        free(t_looper);
        t_looper = NULL;
    }
    g_asset_mgr.apk = NULL;
    g_window.surface = NULL;
    g_input_queue.surface = NULL;
}

afw_ANativeActivity *afw_android_get_activity(void) { return &g_activity; }
void *afw_android_get_window(void) { return &g_window; }
void *afw_android_get_input_queue(void) { return &g_input_queue; }
void *afw_android_get_asset_manager(void) { return &g_asset_mgr; }
afw_gui_surface *afw_android_window_surface(void *nw) {
    afw_native_window *w = (afw_native_window *)nw;
    return w ? w->surface : g_window.surface;
}
int afw_android_finish_requested(void) {
    return afw_os_atomic_load_i32(&g_finish_req) != 0;
}

/* ---- liblog: __android_log_print (portable SysV ABI formatter) --------
 * In System V x86-64 ABI, variadic int/ptr args 4..6 arrive in rcx, r8, r9
 * and args 7..9 on the caller's stack; float/double args arrive in xmm0..xmm3.
 * Taking them as explicit SYSV parameters works identically on Windows clang-cl
 * and Linux gcc/clang without non-portable sysv_va_list builtins. */
static void append_str(char *dst, size_t cap, size_t *pos, const char *s) {
    if (!s) s = "(null)";
    while (*s && *pos + 1 < cap) dst[(*pos)++] = *s++;
}

static void format_sysv_log(char *out, size_t cap, const char *fmt,
                            const uint64_t *iargs, int niargs,
                            const double *fargs, int nfargs) {
    size_t pos = 0;
    int ii = 0, fi = 0;
    char tmp[64];
    if (!cap) return;
    if (!fmt) { out[0] = '\0'; return; }
    while (*fmt && pos + 1 < cap) {
        int is_long = 0, is_ll = 0, is_z = 0;
        if (*fmt != '%') { out[pos++] = *fmt++; continue; }
        fmt++;
        while (*fmt == '-' || *fmt == '+' || *fmt == ' ' || *fmt == '0' || *fmt == '#' ||
               (*fmt >= '0' && *fmt <= '9') || *fmt == '.') fmt++;
        if (*fmt == 'l') { is_long = 1; fmt++; if (*fmt == 'l') { is_ll = 1; fmt++; } }
        else if (*fmt == 'z') { is_z = 1; fmt++; }
        switch (*fmt) {
        case '%': out[pos++] = '%'; break;
        case 's': {
            const char *s = (ii < niargs) ? (const char *)(uintptr_t)iargs[ii++] : "(arg)";
            append_str(out, cap, &pos, s);
            break;
        }
        case 'c': {
            uint64_t v = (ii < niargs) ? iargs[ii++] : '?';
            out[pos++] = (char)v;
            break;
        }
        case 'd': case 'i': {
            uint64_t v = (ii < niargs) ? iargs[ii++] : 0;
            if (is_ll || is_long || is_z)
                snprintf(tmp, sizeof tmp, "%lld", (long long)v);
            else
                snprintf(tmp, sizeof tmp, "%d", (int)v);
            append_str(out, cap, &pos, tmp);
            break;
        }
        case 'u': {
            uint64_t v = (ii < niargs) ? iargs[ii++] : 0;
            if (is_ll || is_long || is_z)
                snprintf(tmp, sizeof tmp, "%llu", (unsigned long long)v);
            else
                snprintf(tmp, sizeof tmp, "%u", (unsigned int)v);
            append_str(out, cap, &pos, tmp);
            break;
        }
        case 'x': case 'X': {
            uint64_t v = (ii < niargs) ? iargs[ii++] : 0;
            if (is_ll || is_long || is_z)
                snprintf(tmp, sizeof tmp, (*fmt == 'X') ? "%llX" : "%llx", (unsigned long long)v);
            else
                snprintf(tmp, sizeof tmp, (*fmt == 'X') ? "%X" : "%x", (unsigned int)v);
            append_str(out, cap, &pos, tmp);
            break;
        }
        case 'p': {
            uint64_t v = (ii < niargs) ? iargs[ii++] : 0;
            snprintf(tmp, sizeof tmp, "%p", (void *)(uintptr_t)v);
            append_str(out, cap, &pos, tmp);
            break;
        }
        case 'f': case 'g': {
            double d = (fi < nfargs) ? fargs[fi++] : 0.0;
            snprintf(tmp, sizeof tmp, "%.3f", d);
            append_str(out, cap, &pos, tmp);
            break;
        }
        default:
            if (*fmt) out[pos++] = *fmt;
            break;
        }
        if (*fmt) fmt++;
    }
    out[pos] = '\0';
}

static void emit_log_line(int prio, const char *tag, const char *text) {
    static const char levels[] = "??VDIWEF";
    char lv = (prio >= 0 && prio < 8) ? levels[prio] : '?';
    printf("[logcat %c/%s] %s\n", lv, tag ? tag : "", text ? text : "");
    fflush(stdout);
}

static SYSV int s_android_log_print(int prio, const char *tag, const char *fmt,
                                    uint64_t a0, uint64_t a1, uint64_t a2,
                                    double f0, double f1, double f2,
                                    uint64_t a3, uint64_t a4, uint64_t a5) {
    char buf[1024];
    uint64_t iargs[6] = { a0, a1, a2, a3, a4, a5 };
    double   fargs[3] = { f0, f1, f2 };
    format_sysv_log(buf, sizeof buf, fmt, iargs, 6, fargs, 3);
    emit_log_line(prio, tag, buf);
    return 1;
}

static SYSV int s_android_log_vprint(int prio, const char *tag, const char *fmt, void *ap_ptr) {
    (void)ap_ptr;
    emit_log_line(prio, tag, fmt ? fmt : "");
    return 1;
}

static SYSV void s_android_log_assert(const char *cond, const char *tag, const char *fmt,
                                      uint64_t a0, uint64_t a1, uint64_t a2,
                                      double f0, double f1) {
    char buf[1024];
    uint64_t iargs[3] = { a0, a1, a2 };
    double   fargs[2] = { f0, f1 };
    format_sysv_log(buf, sizeof buf, fmt ? fmt : (cond ? cond : "assertion failed"),
                    iargs, 3, fargs, 2);
    emit_log_line(7, tag ? tag : "assert", buf);
    abort();
}

/* ---- ANativeWindow shims ---------------------------------------------- */
static SYSV void s_ANativeWindow_acquire(void *w) {
    afw_native_window *nw = (afw_native_window *)w;
    if (nw) (void)afw_os_atomic_add_i32(&nw->refcount, 1);
}

static SYSV void s_ANativeWindow_release(void *w) {
    afw_native_window *nw = (afw_native_window *)w;
    if (nw) (void)afw_os_atomic_add_i32(&nw->refcount, -1);
}

static SYSV int32_t s_ANativeWindow_getWidth(void *w) {
    afw_native_window *nw = (afw_native_window *)w;
    return (nw && nw->surface) ? nw->surface->width : 0;
}

static SYSV int32_t s_ANativeWindow_getHeight(void *w) {
    afw_native_window *nw = (afw_native_window *)w;
    return (nw && nw->surface) ? nw->surface->height : 0;
}

static SYSV int32_t s_ANativeWindow_getFormat(void *w) {
    afw_native_window *nw = (afw_native_window *)w;
    return nw ? nw->format : 1;
}

static SYSV int32_t s_ANativeWindow_setBuffersGeometry(void *w, int32_t width, int32_t height, int32_t format) {
    afw_native_window *nw = (afw_native_window *)w;
    if (!nw || !nw->surface) return -22;
    if (width > 0 && height > 0) {
        if (afw_gui_resize(nw->surface, width, height) != 0) return -12;
    }
    if (format > 0) nw->format = format;
    return 0;
}

static SYSV int32_t s_ANativeWindow_lock(void *w, afw_ANativeWindow_Buffer *out_buf, void *dirty_bounds) {
    afw_native_window *nw = (afw_native_window *)w;
    (void)dirty_bounds;
    if (!nw || !nw->surface || !nw->surface->pixels || !out_buf) return -22;
    memset(out_buf, 0, sizeof *out_buf);
    out_buf->width  = nw->surface->width;
    out_buf->height = nw->surface->height;
    out_buf->stride = nw->surface->width;
    out_buf->format = nw->format;
    out_buf->bits   = nw->surface->pixels;
    return 0;
}

static SYSV int32_t s_ANativeWindow_unlockAndPost(void *w) {
    afw_native_window *nw = (afw_native_window *)w;
    if (!nw || !nw->surface) return -22;
    afw_gui_present(nw->surface);
    return 0;
}

/* ---- AAssetManager / AAsset / AAssetDir shims ------------------------- */
static SYSV void *s_AAssetManager_open(void *mgr, const char *filename, int mode) {
    afw_asset_mgr *am = (afw_asset_mgr *)mgr;
    char full[512];
    unsigned char *data = NULL;
    size_t sz = 0;
    afw_asset *a;
    (void)mode;
    if (!am || !am->apk || !filename) return NULL;
    while (*filename == '/') filename++;
    snprintf(full, sizeof full, "assets/%s", filename);
    if (afw_apk_read_file(am->apk, full, &data, &sz) != 0) return NULL;
    a = (afw_asset *)calloc(1, sizeof *a);
    if (!a) { free(data); return NULL; }
    a->data = data;
    a->size = sz;
    a->pos  = 0;
    return a;
}

static SYSV int s_AAsset_read(void *asset, void *buf, size_t count) {
    afw_asset *a = (afw_asset *)asset;
    size_t avail, n;
    if (!a || !buf) return -1;
    if (a->pos >= a->size) return 0;
    avail = a->size - a->pos;
    n = count < avail ? count : avail;
    if (n) memcpy(buf, a->data + a->pos, n);
    a->pos += n;
    return (int)n;
}

static SYSV int64_t s_AAsset_seek64(void *asset, int64_t offset, int whence) {
    afw_asset *a = (afw_asset *)asset;
    int64_t np;
    if (!a) return -1;
    if (whence == 0) np = offset;
    else if (whence == 1) np = (int64_t)a->pos + offset;
    else if (whence == 2) np = (int64_t)a->size + offset;
    else return -1;
    if (np < 0 || (uint64_t)np > (uint64_t)a->size) return -1;
    a->pos = (size_t)np;
    return np;
}

static SYSV int64_t s_AAsset_getLength64(void *asset) {
    afw_asset *a = (afw_asset *)asset;
    return a ? (int64_t)a->size : 0;
}

static SYSV int64_t s_AAsset_getRemainingLength64(void *asset) {
    afw_asset *a = (afw_asset *)asset;
    return (a && a->pos <= a->size) ? (int64_t)(a->size - a->pos) : 0;
}

static SYSV const void *s_AAsset_getBuffer(void *asset) {
    afw_asset *a = (afw_asset *)asset;
    return a ? a->data : NULL;
}

static SYSV int s_AAsset_isAllocated(void *asset) { return asset ? 1 : 0; }

static SYSV void s_AAsset_close(void *asset) {
    afw_asset *a = (afw_asset *)asset;
    if (!a) return;
    free(a->data);
    free(a);
}

static SYSV void *s_AAssetManager_openDir(void *mgr, const char *dir_name) {
    afw_asset_mgr *am = (afw_asset_mgr *)mgr;
    afw_asset_dir *d;
    if (!am || !am->apk) return NULL;
    d = (afw_asset_dir *)calloc(1, sizeof *d);
    if (!d) return NULL;
    d->apk = am->apk;
    if (dir_name && dir_name[0])
        snprintf(d->prefix, sizeof d->prefix, "assets/%s/", dir_name);
    else
        snprintf(d->prefix, sizeof d->prefix, "assets/");
    return d;
}

static SYSV const char *s_AAssetDir_getNextFileName(void *dir) {
    afw_asset_dir *d = (afw_asset_dir *)dir;
    size_t plen;
    if (!d || !d->apk) return NULL;
    plen = strlen(d->prefix);
    while (d->index < d->apk->nentries) {
        const char *name = d->apk->entries[d->index++].name;
        if (strncmp(name, d->prefix, plen) == 0 && name[plen] && !strchr(name + plen, '/'))
            return name + plen;
    }
    return NULL;
}

static SYSV void s_AAssetDir_rewind(void *dir) {
    afw_asset_dir *d = (afw_asset_dir *)dir;
    if (d) d->index = 0;
}

static SYSV void s_AAssetDir_close(void *dir) { free(dir); }

/* ---- ALooper & AInputQueue shims -------------------------------------- */
static SYSV void *s_ALooper_forThread(void) { return t_looper; }

static SYSV void *s_ALooper_prepare(int opts) {
    (void)opts;
    if (!t_looper) {
        t_looper = (afw_looper *)calloc(1, sizeof *t_looper);
        if (t_looper) t_looper->refcount = 1;
    }
    return t_looper;
}

static SYSV void s_ALooper_acquire(void *lp) {
    afw_looper *l = (afw_looper *)lp;
    if (l) (void)afw_os_atomic_add_i32(&l->refcount, 1);
}

static SYSV void s_ALooper_release(void *lp) {
    afw_looper *l = (afw_looper *)lp;
    if (!l) return;
    if (afw_os_atomic_add_i32(&l->refcount, -1) <= 0) {
        if (t_looper == l) t_looper = NULL;
        free(l);
    }
}

static SYSV int s_ALooper_addFd(void *lp, int fd, int ident, int events, afw_looper_cb cb, void *data) {
    afw_looper *l = (afw_looper *)lp;
    int i;
    if (!l || fd < 0) return -1;
    for (i = 0; i < l->nfds; i++) {
        if (l->fds[i].fd == fd) {
            l->fds[i].ident = ident;
            l->fds[i].events = events;
            l->fds[i].callback = cb;
            l->fds[i].data = data;
            return 1;
        }
    }
    if (l->nfds >= AFW_MAX_LOOPER_FDS) return -1;
    l->fds[l->nfds].fd = fd;
    l->fds[l->nfds].ident = ident;
    l->fds[l->nfds].events = events;
    l->fds[l->nfds].callback = cb;
    l->fds[l->nfds].data = data;
    l->nfds++;
    return 1;
}

static SYSV int s_ALooper_removeFd(void *lp, int fd) {
    afw_looper *l = (afw_looper *)lp;
    int i;
    if (!l) return -1;
    for (i = 0; i < l->nfds; i++) {
        if (l->fds[i].fd == fd) {
            memmove(&l->fds[i], &l->fds[i + 1], (size_t)(l->nfds - i - 1) * sizeof l->fds[0]);
            l->nfds--;
            return 1;
        }
    }
    return 0;
}

static SYSV void s_ALooper_wake(void *lp) {
    afw_looper *l = (afw_looper *)lp;
    if (l) afw_os_atomic_store_i32(&l->woken, 1);
}

static SYSV int s_ALooper_pollOnce(int timeout_ms, int *out_fd, int *out_events, void **out_data) {
    afw_looper *l = t_looper;
    if (!l) return -4; /* ALOOPER_POLL_ERROR */
    if (g_window.surface) afw_gui_pump_events(g_window.surface);

    if (afw_os_atomic_xchg_i32(&l->woken, 0))
        return -1; /* ALOOPER_POLL_WAKE */

    /* Check attached AInputQueue for pending Win32 events */
    if (l->attached_iq && l->attached_iq->surface &&
        afw_os_atomic_load_i32(&l->attached_iq->surface->ev_head) !=
        afw_os_atomic_load_i32(&l->attached_iq->surface->ev_tail)) {
        if (out_fd) *out_fd = -1;
        if (out_events) *out_events = 1;
        if (out_data) *out_data = l->attached_iq;
        return l->attached_iq->ident;
    }

    if (timeout_ms > 0) {
        int slice = timeout_ms > 16 ? 16 : timeout_ms;
        sleep_ms_portable(slice);
        if (g_window.surface) afw_gui_pump_events(g_window.surface);
        if (afw_os_atomic_xchg_i32(&l->woken, 0))
            return -1;
    }
    return -3; /* ALOOPER_POLL_TIMEOUT */
}

static SYSV int s_ALooper_pollAll(int timeout_ms, int *out_fd, int *out_events, void **out_data) {
    return s_ALooper_pollOnce(timeout_ms, out_fd, out_events, out_data);
}

static SYSV void s_AInputQueue_attachLooper(void *iq, void *lp, int ident, afw_looper_cb cb, void *data) {
    afw_input_queue *q = (afw_input_queue *)iq;
    afw_looper *l = (afw_looper *)lp;
    (void)cb; (void)data;
    if (!q || !l) return;
    q->looper = l;
    q->ident = ident;
    l->attached_iq = q;
}

static SYSV void s_AInputQueue_detachLooper(void *iq) {
    afw_input_queue *q = (afw_input_queue *)iq;
    if (!q) return;
    if (q->looper) ((afw_looper *)q->looper)->attached_iq = NULL;
    q->looper = NULL;
}

static SYSV int32_t s_AInputQueue_hasEvents(void *iq) {
    afw_input_queue *q = (afw_input_queue *)iq;
    if (!q || !q->surface) return 0;
    return afw_os_atomic_load_i32(&q->surface->ev_head) !=
           afw_os_atomic_load_i32(&q->surface->ev_tail) ? 1 : 0;
}

static SYSV int32_t s_AInputQueue_getEvent(void *iq, void **out_ev) {
    afw_input_queue *q = (afw_input_queue *)iq;
    afw_gui_event gev;
    afw_input_event *iev;
    if (!q || !q->surface || !out_ev) return -22;
    if (!afw_gui_pop_event(q->surface, &gev)) return -11; /* -EAGAIN */
    iev = (afw_input_event *)calloc(1, sizeof *iev);
    if (!iev) return -12;
    switch (gev.type) {
    case AFW_EV_TOUCH_DOWN: iev->type = 2; iev->action = 0; iev->x = gev.x; iev->y = gev.y; break;
    case AFW_EV_TOUCH_UP:   iev->type = 2; iev->action = 1; iev->x = gev.x; iev->y = gev.y; break;
    case AFW_EV_TOUCH_MOVE: iev->type = 2; iev->action = 2; iev->x = gev.x; iev->y = gev.y; break;
    case AFW_EV_KEY_DOWN:   iev->type = 1; iev->action = 0; iev->keycode = gev.keycode; break;
    case AFW_EV_KEY_UP:     iev->type = 1; iev->action = 1; iev->keycode = gev.keycode; break;
    default:                iev->type = 1; iev->action = 0; iev->keycode = 4; break;
    }
    *out_ev = iev;
    return 0;
}

static SYSV int32_t s_AInputQueue_preDispatchEvent(void *iq, void *ev) { (void)iq; (void)ev; return 0; }
static SYSV void s_AInputQueue_finishEvent(void *iq, void *ev, int handled) {
    (void)iq; (void)handled;
    free(ev);
}

static SYSV int32_t s_AInputEvent_getType(const void *ev) {
    return ev ? ((const afw_input_event *)ev)->type : 0;
}
static SYSV int32_t s_AInputEvent_getSource(const void *ev) {
    return (ev && ((const afw_input_event *)ev)->type == 2) ? 0x1002 : 0x101;
}
static SYSV int32_t s_AMotionEvent_getAction(const void *ev) {
    return ev ? ((const afw_input_event *)ev)->action : 0;
}
static SYSV size_t s_AMotionEvent_getPointerCount(const void *ev) { return ev ? 1 : 0; }
static SYSV float s_AMotionEvent_getX(const void *ev, size_t idx) {
    (void)idx;
    return ev ? ((const afw_input_event *)ev)->x : 0.0f;
}
static SYSV float s_AMotionEvent_getY(const void *ev, size_t idx) {
    (void)idx;
    return ev ? ((const afw_input_event *)ev)->y : 0.0f;
}
static SYSV int32_t s_AKeyEvent_getAction(const void *ev) {
    return ev ? ((const afw_input_event *)ev)->action : 0;
}
static SYSV int32_t s_AKeyEvent_getKeyCode(const void *ev) {
    return ev ? ((const afw_input_event *)ev)->keycode : 0;
}

/* ---- AConfiguration & ANativeActivity helpers ------------------------- */
static SYSV void *s_AConfiguration_new(void) {
    afw_configuration *c = (afw_configuration *)calloc(1, sizeof *c);
    if (c) {
        c->density = 160;
        c->orientation = 2; /* LANDSCAPE */
        c->sdk_version = 34;
        c->lang[0] = 'e'; c->lang[1] = 'n';
        c->country[0] = 'U'; c->country[1] = 'S';
    }
    return c;
}
static SYSV void s_AConfiguration_delete(void *c) { free(c); }
static SYSV void s_AConfiguration_fromAssetManager(void *out, void *am) { (void)out; (void)am; }
static SYSV void s_AConfiguration_copy(void *dst, void *src) {
    if (dst && src) memcpy(dst, src, sizeof(afw_configuration));
}
static SYSV int32_t s_AConfiguration_getDensity(void *c) { return c ? ((afw_configuration *)c)->density : 160; }
static SYSV int32_t s_AConfiguration_getOrientation(void *c) { return c ? ((afw_configuration *)c)->orientation : 2; }
static SYSV int32_t s_AConfiguration_getSdkVersion(void *c) { return c ? ((afw_configuration *)c)->sdk_version : 34; }
static SYSV void s_AConfiguration_getLanguage(void *c, char *out) {
    if (c && out) { out[0] = ((afw_configuration *)c)->lang[0]; out[1] = ((afw_configuration *)c)->lang[1]; }
}
static SYSV void s_AConfiguration_getCountry(void *c, char *out) {
    if (c && out) { out[0] = ((afw_configuration *)c)->country[0]; out[1] = ((afw_configuration *)c)->country[1]; }
}

static SYSV void s_ANativeActivity_finish(void *act) {
    (void)act;
    afw_os_atomic_store_i32(&g_finish_req, 1);
    if (g_window.surface) afw_os_atomic_store_i32(&g_window.surface->should_close, 1);
}
static SYSV void s_ANativeActivity_setWindowFlags(void *act, uint32_t add, uint32_t rem) {
    (void)act; (void)add; (void)rem;
}

/* ---- Lookup table ----------------------------------------------------- */
typedef struct { const char *name; void *addr; } sym_ent;
#define E(n, f) { n, (void *)(f) }

static const sym_ent g_android_syms[] = {
    E("__android_log_print", s_android_log_print),
    E("__android_log_vprint", s_android_log_vprint),
    E("__android_log_assert", s_android_log_assert),

    E("ANativeWindow_acquire", s_ANativeWindow_acquire),
    E("ANativeWindow_release", s_ANativeWindow_release),
    E("ANativeWindow_getWidth", s_ANativeWindow_getWidth),
    E("ANativeWindow_getHeight", s_ANativeWindow_getHeight),
    E("ANativeWindow_getFormat", s_ANativeWindow_getFormat),
    E("ANativeWindow_setBuffersGeometry", s_ANativeWindow_setBuffersGeometry),
    E("ANativeWindow_lock", s_ANativeWindow_lock),
    E("ANativeWindow_unlockAndPost", s_ANativeWindow_unlockAndPost),

    E("AAssetManager_open", s_AAssetManager_open),
    E("AAssetManager_openDir", s_AAssetManager_openDir),
    E("AAssetDir_getNextFileName", s_AAssetDir_getNextFileName),
    E("AAssetDir_rewind", s_AAssetDir_rewind),
    E("AAssetDir_close", s_AAssetDir_close),
    E("AAsset_read", s_AAsset_read),
    E("AAsset_seek", s_AAsset_seek64),
    E("AAsset_seek64", s_AAsset_seek64),
    E("AAsset_getLength", s_AAsset_getLength64),
    E("AAsset_getLength64", s_AAsset_getLength64),
    E("AAsset_getRemainingLength", s_AAsset_getRemainingLength64),
    E("AAsset_getRemainingLength64", s_AAsset_getRemainingLength64),
    E("AAsset_getBuffer", s_AAsset_getBuffer),
    E("AAsset_isAllocated", s_AAsset_isAllocated),
    E("AAsset_close", s_AAsset_close),

    E("ALooper_forThread", s_ALooper_forThread),
    E("ALooper_prepare", s_ALooper_prepare),
    E("ALooper_acquire", s_ALooper_acquire),
    E("ALooper_release", s_ALooper_release),
    E("ALooper_addFd", s_ALooper_addFd),
    E("ALooper_removeFd", s_ALooper_removeFd),
    E("ALooper_wake", s_ALooper_wake),
    E("ALooper_pollOnce", s_ALooper_pollOnce),
    E("ALooper_pollAll", s_ALooper_pollAll),

    E("AInputQueue_attachLooper", s_AInputQueue_attachLooper),
    E("AInputQueue_detachLooper", s_AInputQueue_detachLooper),
    E("AInputQueue_hasEvents", s_AInputQueue_hasEvents),
    E("AInputQueue_getEvent", s_AInputQueue_getEvent),
    E("AInputQueue_preDispatchEvent", s_AInputQueue_preDispatchEvent),
    E("AInputQueue_finishEvent", s_AInputQueue_finishEvent),
    E("AInputEvent_getType", s_AInputEvent_getType),
    E("AInputEvent_getSource", s_AInputEvent_getSource),
    E("AMotionEvent_getAction", s_AMotionEvent_getAction),
    E("AMotionEvent_getPointerCount", s_AMotionEvent_getPointerCount),
    E("AMotionEvent_getX", s_AMotionEvent_getX),
    E("AMotionEvent_getY", s_AMotionEvent_getY),
    E("AKeyEvent_getAction", s_AKeyEvent_getAction),
    E("AKeyEvent_getKeyCode", s_AKeyEvent_getKeyCode),

    E("AConfiguration_new", s_AConfiguration_new),
    E("AConfiguration_delete", s_AConfiguration_delete),
    E("AConfiguration_fromAssetManager", s_AConfiguration_fromAssetManager),
    E("AConfiguration_copy", s_AConfiguration_copy),
    E("AConfiguration_getDensity", s_AConfiguration_getDensity),
    E("AConfiguration_getOrientation", s_AConfiguration_getOrientation),
    E("AConfiguration_getSdkVersion", s_AConfiguration_getSdkVersion),
    E("AConfiguration_getLanguage", s_AConfiguration_getLanguage),
    E("AConfiguration_getCountry", s_AConfiguration_getCountry),

    E("ANativeActivity_finish", s_ANativeActivity_finish),
    E("ANativeActivity_setWindowFlags", s_ANativeActivity_setWindowFlags),
};
#undef E

void *afw_android_native_lookup(const char *name) {
    size_t i;
    if (!name) return NULL;
    for (i = 0; i < sizeof(g_android_syms) / sizeof(g_android_syms[0]); i++) {
        if (strcmp(g_android_syms[i].name, name) == 0)
            return g_android_syms[i].addr;
    }
    return NULL;
}
