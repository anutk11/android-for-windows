/*
 * win_gui.h - Cross-platform window & RGBA8888 framebuffer surface for APK UI.
 *
 * On Windows: opens a real Win32 HWND window (when !headless) and blits each
 * presented frame via StretchDIBits, translating mouse/keyboard input into
 * Android touch/key events. In --headless mode (CI), keeps the exact same
 * RGBA8888 framebuffer and supports BMP screenshot export.
 */
#ifndef AFW_WIN_GUI_H
#define AFW_WIN_GUI_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    AFW_EV_NONE = 0,
    AFW_EV_TOUCH_DOWN,
    AFW_EV_TOUCH_MOVE,
    AFW_EV_TOUCH_UP,
    AFW_EV_KEY_DOWN,
    AFW_EV_KEY_UP,
    AFW_EV_QUIT
} afw_gui_event_type;

typedef struct {
    afw_gui_event_type type;
    float              x;
    float              y;
    int32_t            keycode;
} afw_gui_event;

#define AFW_GUI_EV_CAP 64

typedef struct {
    int            width;
    int            height;
    uint32_t      *pixels;          /* RGBA8888: R=byte0, G=byte1, B=byte2, A=byte3 */
    int            headless;
    int32_t        should_close;
    uint64_t       frames_presented;
    void          *win_hwnd;        /* Win32 HWND (opaque outside win_gui.c) */
    uint32_t      *bgra_scratch;    /* Win32 StretchDIBits BGRA conversion buffer */
    afw_gui_event  ev_ring[AFW_GUI_EV_CAP];
    int32_t        ev_head;
    int32_t        ev_tail;
} afw_gui_surface;

int  afw_gui_create(afw_gui_surface *s, const char *title, int width, int height, int headless);
void afw_gui_destroy(afw_gui_surface *s);
int  afw_gui_resize(afw_gui_surface *s, int width, int height);
void afw_gui_present(afw_gui_surface *s);
void afw_gui_pump_events(afw_gui_surface *s);
int  afw_gui_pop_event(afw_gui_surface *s, afw_gui_event *out);
void afw_gui_push_event(afw_gui_surface *s, const afw_gui_event *ev);
int  afw_gui_save_bmp(const afw_gui_surface *s, const char *path);

/* 2D software drawing primitives (RGBA8888, used by Canvas & overlays). */
uint32_t afw_rgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void afw_gui_clear(afw_gui_surface *s, uint32_t rgba);
void afw_gui_fill_rect(afw_gui_surface *s, int x, int y, int w, int h, uint32_t rgba);
void afw_gui_fill_circle(afw_gui_surface *s, int cx, int cy, int r, uint32_t rgba);
void afw_gui_draw_line(afw_gui_surface *s, int x0, int y0, int x1, int y1, uint32_t rgba);
void afw_gui_draw_text(afw_gui_surface *s, int x, int y, int scale, uint32_t rgba, const char *text);

#endif
