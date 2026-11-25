/*
 * win_gui.c - Win32 HWND presentation + headless RGBA8888 framebuffer + BMP writer.
 */
#include "win_gui.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#endif

uint32_t afw_rgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
    return ((uint32_t)r) | ((uint32_t)g << 8) | ((uint32_t)b << 16) | ((uint32_t)a << 24);
}

static uint32_t blend_pixel(uint32_t dst, uint32_t src) {
    uint32_t sa = (src >> 24) & 0xffu;
    uint32_t inv, r, g, b;
    if (sa == 0) return dst;
    if (sa == 255) return src;
    inv = 255u - sa;
    r = (((src & 0xffu) * sa) + ((dst & 0xffu) * inv) + 127u) / 255u;
    g = ((((src >> 8) & 0xffu) * sa) + (((dst >> 8) & 0xffu) * inv) + 127u) / 255u;
    b = ((((src >> 16) & 0xffu) * sa) + (((dst >> 16) & 0xffu) * inv) + 127u) / 255u;
    return afw_rgba((uint8_t)r, (uint8_t)g, (uint8_t)b, 255u);
}

static void put_px(afw_gui_surface *s, int x, int y, uint32_t rgba) {
    if (!s || !s->pixels || x < 0 || y < 0 || x >= s->width || y >= s->height) return;
    s->pixels[(size_t)y * (size_t)s->width + (size_t)x] =
        blend_pixel(s->pixels[(size_t)y * (size_t)s->width + (size_t)x], rgba);
}

void afw_gui_push_event(afw_gui_surface *s, const afw_gui_event *ev) {
    int32_t head, tail, next;
    if (!s || !ev) return;
    head = afw_os_atomic_load_i32(&s->ev_head);
    tail = afw_os_atomic_load_i32(&s->ev_tail);
    next = (head + 1) % AFW_GUI_EV_CAP;
    if (next == tail) return; /* ring full */
    s->ev_ring[head] = *ev;
    afw_os_atomic_store_i32(&s->ev_head, next);
}

int afw_gui_pop_event(afw_gui_surface *s, afw_gui_event *out) {
    int32_t head, tail;
    if (!s || !out) return 0;
    head = afw_os_atomic_load_i32(&s->ev_head);
    tail = afw_os_atomic_load_i32(&s->ev_tail);
    if (tail == head) return 0;
    *out = s->ev_ring[tail];
    afw_os_atomic_store_i32(&s->ev_tail, (tail + 1) % AFW_GUI_EV_CAP);
    return 1;
}

#if defined(_WIN32)
static int g_wnd_class_reg = 0;

static int win_vk_to_android_key(WPARAM vk) {
    if (vk >= 'A' && vk <= 'Z') return 29 + (int)(vk - 'A'); /* AKEYCODE_A = 29 */
    if (vk >= '0' && vk <= '9') return 7 + (int)(vk - '0');  /* AKEYCODE_0 = 7 */
    switch (vk) {
    case VK_ESCAPE: return 4;  /* AKEYCODE_BACK */
    case VK_RETURN: return 66; /* AKEYCODE_ENTER */
    case VK_SPACE:  return 62; /* AKEYCODE_SPACE */
    case VK_LEFT:   return 21; /* AKEYCODE_DPAD_LEFT */
    case VK_RIGHT:  return 22; /* AKEYCODE_DPAD_RIGHT */
    case VK_UP:     return 19; /* AKEYCODE_DPAD_UP */
    case VK_DOWN:   return 20; /* AKEYCODE_DPAD_DOWN */
    default:        return 0;
    }
}

static LRESULT CALLBACK afw_wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    afw_gui_surface *s = (afw_gui_surface *)(uintptr_t)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
    afw_gui_event ev;
    memset(&ev, 0, sizeof ev);
    switch (msg) {
    case WM_CLOSE:
    case WM_DESTROY:
        if (s) {
            afw_os_atomic_store_i32(&s->should_close, 1);
            ev.type = AFW_EV_QUIT;
            afw_gui_push_event(s, &ev);
        }
        if (msg == WM_CLOSE) { DestroyWindow(hwnd); return 0; }
        return 0;
    case WM_LBUTTONDOWN:
        if (s) {
            SetCapture(hwnd);
            ev.type = AFW_EV_TOUCH_DOWN;
            ev.x = (float)(int16_t)LOWORD(lp);
            ev.y = (float)(int16_t)HIWORD(lp);
            afw_gui_push_event(s, &ev);
        }
        return 0;
    case WM_MOUSEMOVE:
        if (s && (wp & MK_LBUTTON)) {
            ev.type = AFW_EV_TOUCH_MOVE;
            ev.x = (float)(int16_t)LOWORD(lp);
            ev.y = (float)(int16_t)HIWORD(lp);
            afw_gui_push_event(s, &ev);
        }
        return 0;
    case WM_LBUTTONUP:
        if (s) {
            ReleaseCapture();
            ev.type = AFW_EV_TOUCH_UP;
            ev.x = (float)(int16_t)LOWORD(lp);
            ev.y = (float)(int16_t)HIWORD(lp);
            afw_gui_push_event(s, &ev);
        }
        return 0;
    case WM_KEYDOWN:
        if (s) {
            ev.type = AFW_EV_KEY_DOWN;
            ev.keycode = win_vk_to_android_key(wp);
            afw_gui_push_event(s, &ev);
        }
        return 0;
    case WM_KEYUP:
        if (s) {
            ev.type = AFW_EV_KEY_UP;
            ev.keycode = win_vk_to_android_key(wp);
            afw_gui_push_event(s, &ev);
        }
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        if (s) afw_gui_present(s);
        return 0;
    }
    default:
        return DefWindowProcA(hwnd, msg, wp, lp);
    }
}
#endif

int afw_gui_create(afw_gui_surface *s, const char *title, int width, int height, int headless) {
    size_t npix;
    if (!s || width <= 0 || height <= 0 || width > 8192 || height > 8192) return -1;
    memset(s, 0, sizeof *s);
    npix = (size_t)width * (size_t)height;
    s->pixels = (uint32_t *)calloc(npix, sizeof(uint32_t));
    if (!s->pixels) return -1;
    s->width = width;
    s->height = height;
    s->headless = headless ? 1 : 0;

#if defined(_WIN32)
    if (!s->headless) {
        HINSTANCE hi = GetModuleHandleA(NULL);
        RECT rc = { 0, 0, width, height };
        DWORD style = WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX);
        HWND hwnd;
        if (!g_wnd_class_reg) {
            WNDCLASSA wc;
            memset(&wc, 0, sizeof wc);
            wc.lpfnWndProc = afw_wnd_proc;
            wc.hInstance = hi;
            wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
            wc.lpszClassName = "AFWAndroidWindow";
            RegisterClassA(&wc);
            g_wnd_class_reg = 1;
        }
        AdjustWindowRect(&rc, style, FALSE);
        hwnd = CreateWindowExA(0, "AFWAndroidWindow", title ? title : "Android for Windows",
                               style, CW_USEDEFAULT, CW_USEDEFAULT,
                               rc.right - rc.left, rc.bottom - rc.top,
                               NULL, NULL, hi, NULL);
        if (hwnd) {
            SetWindowLongPtrA(hwnd, GWLP_USERDATA, (LONG_PTR)(uintptr_t)s);
            ShowWindow(hwnd, SW_SHOW);
            UpdateWindow(hwnd);
            s->win_hwnd = (void *)hwnd;
            s->bgra_scratch = (uint32_t *)calloc(npix, sizeof(uint32_t));
        }
    }
#else
    (void)title;
#endif
    return 0;
}

int afw_gui_resize(afw_gui_surface *s, int width, int height) {
    uint32_t *np;
    size_t npix;
    if (!s || width <= 0 || height <= 0 || width > 8192 || height > 8192) return -1;
    if (s->width == width && s->height == height) return 0;
    npix = (size_t)width * (size_t)height;
    np = (uint32_t *)calloc(npix, sizeof(uint32_t));
    if (!np) return -1;
    free(s->pixels);
    s->pixels = np;
    s->width = width;
    s->height = height;
#if defined(_WIN32)
    if (s->bgra_scratch) {
        uint32_t *nb = (uint32_t *)calloc(npix, sizeof(uint32_t));
        if (nb) { free(s->bgra_scratch); s->bgra_scratch = nb; }
    }
#endif
    return 0;
}

void afw_gui_present(afw_gui_surface *s) {
    if (!s || !s->pixels) return;
    s->frames_presented++;
#if defined(_WIN32)
    if (!s->headless && s->win_hwnd && s->bgra_scratch) {
        HWND hwnd = (HWND)s->win_hwnd;
        HDC hdc = GetDC(hwnd);
        if (hdc) {
            BITMAPINFO bmi;
            size_t i, n = (size_t)s->width * (size_t)s->height;
            for (i = 0; i < n; i++) {
                uint32_t px = s->pixels[i];
                uint32_t r = px & 0xffu;
                uint32_t g = (px >> 8) & 0xffu;
                uint32_t b = (px >> 16) & 0xffu;
                uint32_t a = (px >> 24) & 0xffu;
                s->bgra_scratch[i] = b | (g << 8) | (r << 16) | (a << 24);
            }
            memset(&bmi, 0, sizeof bmi);
            bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bmi.bmiHeader.biWidth = s->width;
            bmi.bmiHeader.biHeight = -s->height; /* top-down */
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = BI_RGB;
            StretchDIBits(hdc, 0, 0, s->width, s->height,
                          0, 0, s->width, s->height,
                          s->bgra_scratch, &bmi, DIB_RGB_COLORS, SRCCOPY);
            ReleaseDC(hwnd, hdc);
        }
    }
#endif
}

void afw_gui_pump_events(afw_gui_surface *s) {
#if defined(_WIN32)
    if (s && !s->headless && s->win_hwnd) {
        MSG msg;
        while (PeekMessageA(&msg, (HWND)s->win_hwnd, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
#else
    (void)s;
#endif
}

void afw_gui_destroy(afw_gui_surface *s) {
    if (!s) return;
#if defined(_WIN32)
    if (s->win_hwnd) {
        DestroyWindow((HWND)s->win_hwnd);
        s->win_hwnd = NULL;
    }
    free(s->bgra_scratch);
    s->bgra_scratch = NULL;
#endif
    free(s->pixels);
    s->pixels = NULL;
    s->width = s->height = 0;
}

int afw_gui_save_bmp(const afw_gui_surface *s, const char *path) {
    FILE *f;
    int row_stride, y, x;
    uint32_t img_size, file_size;
    unsigned char hdr[54];
    unsigned char *row;

    if (!s || !s->pixels || !path || s->width <= 0 || s->height <= 0) return -1;
    row_stride = (s->width * 3 + 3) & ~3;
    img_size = (uint32_t)row_stride * (uint32_t)s->height;
    file_size = 54u + img_size;

    memset(hdr, 0, sizeof hdr);
    hdr[0] = 'B'; hdr[1] = 'M';
    hdr[2] = (unsigned char)(file_size & 0xffu);
    hdr[3] = (unsigned char)((file_size >> 8) & 0xffu);
    hdr[4] = (unsigned char)((file_size >> 16) & 0xffu);
    hdr[5] = (unsigned char)((file_size >> 24) & 0xffu);
    hdr[10] = 54;
    hdr[14] = 40;
    hdr[18] = (unsigned char)(s->width & 0xff);
    hdr[19] = (unsigned char)((s->width >> 8) & 0xff);
    hdr[20] = (unsigned char)((s->width >> 16) & 0xff);
    hdr[21] = (unsigned char)((s->width >> 24) & 0xff);
    hdr[22] = (unsigned char)(s->height & 0xff);
    hdr[23] = (unsigned char)((s->height >> 8) & 0xff);
    hdr[24] = (unsigned char)((s->height >> 16) & 0xff);
    hdr[25] = (unsigned char)((s->height >> 24) & 0xff);
    hdr[26] = 1;
    hdr[28] = 24;
    hdr[34] = (unsigned char)(img_size & 0xffu);
    hdr[35] = (unsigned char)((img_size >> 8) & 0xffu);
    hdr[36] = (unsigned char)((img_size >> 16) & 0xffu);
    hdr[37] = (unsigned char)((img_size >> 24) & 0xffu);

    row = (unsigned char *)calloc(1, (size_t)row_stride);
    if (!row) return -1;
    f = fopen(path, "wb");
    if (!f) { free(row); return -1; }
    if (fwrite(hdr, 1, sizeof hdr, f) != sizeof hdr) { fclose(f); free(row); return -1; }
    /* Standard bottom-up BMP rows */
    for (y = s->height - 1; y >= 0; y--) {
        const uint32_t *src = s->pixels + (size_t)y * (size_t)s->width;
        memset(row, 0, (size_t)row_stride);
        for (x = 0; x < s->width; x++) {
            uint32_t px = src[x];
            row[x * 3 + 0] = (unsigned char)((px >> 16) & 0xffu); /* B */
            row[x * 3 + 1] = (unsigned char)((px >> 8) & 0xffu);  /* G */
            row[x * 3 + 2] = (unsigned char)(px & 0xffu);         /* R */
        }
        if (fwrite(row, 1, (size_t)row_stride, f) != (size_t)row_stride) {
            fclose(f); free(row); return -1;
        }
    }
    fclose(f);
    free(row);
    return 0;
}

/* ---- 2D drawing primitives -------------------------------------------- */
void afw_gui_clear(afw_gui_surface *s, uint32_t rgba) {
    size_t i, n;
    if (!s || !s->pixels) return;
    n = (size_t)s->width * (size_t)s->height;
    for (i = 0; i < n; i++) s->pixels[i] = rgba;
}

void afw_gui_fill_rect(afw_gui_surface *s, int x, int y, int w, int h, uint32_t rgba) {
    int x0, y0, x1, y1, py, px;
    if (!s || !s->pixels || w <= 0 || h <= 0) return;
    x0 = x < 0 ? 0 : x;
    y0 = y < 0 ? 0 : y;
    x1 = (x + w) > s->width ? s->width : (x + w);
    y1 = (y + h) > s->height ? s->height : (y + h);
    for (py = y0; py < y1; py++)
        for (px = x0; px < x1; px++)
            put_px(s, px, py, rgba);
}

void afw_gui_fill_circle(afw_gui_surface *s, int cx, int cy, int r, uint32_t rgba) {
    int dy, dx;
    if (!s || !s->pixels || r <= 0) return;
    for (dy = -r; dy <= r; dy++) {
        for (dx = -r; dx <= r; dx++) {
            if (dx * dx + dy * dy <= r * r)
                put_px(s, cx + dx, cy + dy, rgba);
        }
    }
}

void afw_gui_draw_line(afw_gui_surface *s, int x0, int y0, int x1, int y1, uint32_t rgba) {
    int dx = abs(x1 - x0), sx = x0 < x1 ? 1 : -1;
    int dy = -abs(y1 - y0), sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;
    for (;;) {
        put_px(s, x0, y0, rgba);
        if (x0 == x1 && y0 == y1) break;
        if (2 * err >= dy) { err += dy; x0 += sx; }
        if (2 * err <= dx) { err += dx; y0 += sy; }
    }
}

/* Minimal crisp 5x7 uppercase/digit bitmap font for Canvas.drawText(). */
static const uint8_t *glyph_5x7(char ch) {
    static const uint8_t blank[5] = {0, 0, 0, 0, 0};
    static const uint8_t digits[10][5] = {
        {0x3e,0x51,0x49,0x45,0x3e}, {0x00,0x42,0x7f,0x40,0x00},
        {0x42,0x61,0x51,0x49,0x46}, {0x21,0x41,0x45,0x4b,0x31},
        {0x18,0x14,0x12,0x7f,0x10}, {0x27,0x45,0x45,0x45,0x39},
        {0x3c,0x4a,0x49,0x49,0x30}, {0x01,0x71,0x09,0x05,0x03},
        {0x36,0x49,0x49,0x49,0x36}, {0x06,0x49,0x49,0x29,0x1e}
    };
    static const uint8_t alpha[26][5] = {
        {0x7e,0x11,0x11,0x11,0x7e}, {0x7f,0x49,0x49,0x49,0x36},
        {0x3e,0x41,0x41,0x41,0x22}, {0x7f,0x41,0x41,0x22,0x1c},
        {0x7f,0x49,0x49,0x49,0x41}, {0x7f,0x09,0x09,0x09,0x01},
        {0x3e,0x41,0x49,0x49,0x7a}, {0x7f,0x08,0x08,0x08,0x7f},
        {0x00,0x41,0x7f,0x41,0x00}, {0x20,0x40,0x41,0x3f,0x01},
        {0x7f,0x08,0x14,0x22,0x41}, {0x7f,0x40,0x40,0x40,0x40},
        {0x7f,0x02,0x0c,0x02,0x7f}, {0x7f,0x04,0x08,0x10,0x7f},
        {0x3e,0x41,0x41,0x41,0x3e}, {0x7f,0x09,0x09,0x09,0x06},
        {0x3e,0x41,0x51,0x21,0x5e}, {0x7f,0x09,0x19,0x29,0x46},
        {0x46,0x49,0x49,0x49,0x31}, {0x01,0x01,0x7f,0x01,0x01},
        {0x3f,0x40,0x40,0x40,0x3f}, {0x1f,0x20,0x40,0x20,0x1f},
        {0x3f,0x40,0x38,0x40,0x3f}, {0x63,0x14,0x08,0x14,0x63},
        {0x07,0x08,0x70,0x08,0x07}, {0x61,0x51,0x49,0x45,0x43}
    };
    static const uint8_t dash[5]  = {0x08,0x08,0x08,0x08,0x08};
    static const uint8_t colon[5] = {0x00,0x36,0x36,0x00,0x00};
    static const uint8_t bang[5]  = {0x00,0x00,0x5f,0x00,0x00};
    static const uint8_t dot[5]   = {0x00,0x60,0x60,0x00,0x00};
    if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 'a' + 'A');
    if (ch >= '0' && ch <= '9') return digits[ch - '0'];
    if (ch >= 'A' && ch <= 'Z') return alpha[ch - 'A'];
    if (ch == '-') return dash;
    if (ch == ':') return colon;
    if (ch == '!') return bang;
    if (ch == '.') return dot;
    return blank;
}

void afw_gui_draw_text(afw_gui_surface *s, int x, int y, int scale, uint32_t rgba, const char *text) {
    int cx = x;
    if (!s || !text) return;
    if (scale < 1) scale = 1;
    while (*text) {
        const uint8_t *g = glyph_5x7(*text++);
        int col, row;
        for (col = 0; col < 5; col++) {
            for (row = 0; row < 7; row++) {
                if ((g[col] >> row) & 1u)
                    afw_gui_fill_rect(s, cx + col * scale, y + row * scale, scale, scale, rgba);
            }
        }
        cx += 6 * scale;
    }
}
