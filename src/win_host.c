/*
 * win_host.c - Native Win32 window, DIB framebuffer presenter, mouse/keyboard
 * input event queue, BMP screenshot writer, and WinMM waveOut audio bridge.
 *
 * Interactive mode: opens a real resizable Win32 HWND window, blits ARGB_8888
 * Android Canvas frames via StretchDIBits, forwards mouse -> touch and keyboard
 * events, and streams PCM audio to the Windows default audio device.
 *
 * Headless mode (--headless): runs without creating a desktop HWND or opening
 * hardware audio, supports scripted --inject-click=X,Y, --screenshot=FILE.bmp,
 * and --auto-exit=MS for deterministic automated CI verification.
 */
#include "win_host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winmm.lib")
#else
#include <time.h>
#include <unistd.h>
#endif

#define EV_QUEUE_CAP 256
#define MAX_INJECT_CLICKS 16

static int   g_headless = 0;
static int   g_cfg_w = 420;
static int   g_cfg_h = 760;
static char  g_screenshot_path[512];
static int   g_inject_x[MAX_INJECT_CLICKS];
static int   g_inject_y[MAX_INJECT_CLICKS];
static int   g_ninject = 0;
static int   g_inject_idx = 0;
static int   g_inject_stage = 0; /* 0=idle, 1=sent down waiting to send up */
static int   g_auto_exit_ms = 0;
static int   g_auto_exit_sent = 0;

static afw_host_event g_evq[EV_QUEUE_CAP];
static int   g_ev_head = 0, g_ev_tail = 0;

static uint32_t *g_fb = NULL;
static int32_t   g_fb_w = 0, g_fb_h = 0;
static int32_t   g_frames = 0;
static int64_t   g_audio_bytes = 0;
static uint64_t  g_start_ms = 0;

static uint64_t now_ms(void) {
#if defined(_WIN32)
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
#endif
}

static void ev_push(int32_t type, int32_t x, int32_t y, int32_t mods) {
    int next = (g_ev_tail + 1) % EV_QUEUE_CAP;
    if (next == g_ev_head) return;
    g_evq[g_ev_tail].type = type;
    g_evq[g_ev_tail].x    = x;
    g_evq[g_ev_tail].y    = y;
    g_evq[g_ev_tail].mods = mods;
    g_ev_tail = next;
}

static int ev_pop(afw_host_event *out) {
    if (g_ev_head == g_ev_tail) return 0;
    *out = g_evq[g_ev_head];
    g_ev_head = (g_ev_head + 1) % EV_QUEUE_CAP;
    return 1;
}

static int g_cfg_size_locked = 0;
void afw_host_set_headless(int on) { g_headless = on ? 1 : 0; }
void afw_host_set_size(int w, int h) {
    if (w >= 64 && w <= 4096) { g_cfg_w = w; g_cfg_size_locked = 1; }
    if (h >= 64 && h <= 4096) { g_cfg_h = h; g_cfg_size_locked = 1; }
}
void afw_host_set_screenshot(const char *bmp_path) {
    if (!bmp_path) { g_screenshot_path[0] = '\0'; return; }
    snprintf(g_screenshot_path, sizeof g_screenshot_path, "%s", bmp_path);
}
void afw_host_add_inject_click(int x, int y) {
    if (g_ninject < MAX_INJECT_CLICKS) {
        g_inject_x[g_ninject] = x;
        g_inject_y[g_ninject] = y;
        g_ninject++;
    }
}
void afw_host_set_auto_exit_ms(int ms) {
    g_auto_exit_ms = ms > 0 ? ms : 0;
}

/* Write top-down 32-bit BGRA Windows BMP file (zero external dependencies). */
static void write_bmp(const char *path, const uint32_t *argb, int32_t w, int32_t h) {
    FILE *f;
    uint8_t hdr[54];
    uint32_t pixel_bytes, file_size;
    int32_t neg_h;
    if (!path || !path[0] || !argb || w <= 0 || h <= 0) return;
    if ((uint64_t)w * (uint64_t)h > 16777216ULL) return;
    pixel_bytes = (uint32_t)w * (uint32_t)h * 4u;
    file_size = 54u + pixel_bytes;
    neg_h = -h; /* top-down DIB */
    memset(hdr, 0, sizeof hdr);
    hdr[0] = 'B'; hdr[1] = 'M';
    memcpy(hdr + 2, &file_size, 4);
    hdr[10] = 54;
    hdr[14] = 40; /* BITMAPINFOHEADER */
    memcpy(hdr + 18, &w, 4);
    memcpy(hdr + 22, &neg_h, 4);
    hdr[26] = 1;  /* planes */
    hdr[28] = 32; /* bpp */
    memcpy(hdr + 34, &pixel_bytes, 4);
    f = fopen(path, "wb");
    if (!f) return;
    (void)fwrite(hdr, 1, sizeof hdr, f);
    /* Android ARGB_8888 (0xAARRGGBB on little-endian) is literally BGRA in memory! */
    (void)fwrite(argb, 4, (size_t)w * (size_t)h, f);
    fclose(f);
}

#if defined(_WIN32)
static HWND g_hwnd = NULL;
static int  g_mouse_down = 0;

static int map_vk_to_android_key(WPARAM vk) {
    if (vk >= 'A' && vk <= 'Z') return 29 + (int)(vk - 'A'); /* KEYCODE_A = 29 */
    if (vk >= '0' && vk <= '9') return 7 + (int)(vk - '0');  /* KEYCODE_0 = 7 */
    switch (vk) {
    case VK_ESCAPE: return 4;  /* KEYCODE_BACK */
    case VK_RETURN: return 66; /* KEYCODE_ENTER */
    case VK_BACK:   return 67; /* KEYCODE_DEL */
    case VK_SPACE:  return 62; /* KEYCODE_SPACE */
    case VK_UP:     return 19; /* KEYCODE_DPAD_UP */
    case VK_DOWN:   return 20; /* KEYCODE_DPAD_DOWN */
    case VK_LEFT:   return 21; /* KEYCODE_DPAD_LEFT */
    case VK_RIGHT:  return 22; /* KEYCODE_DPAD_RIGHT */
    default:        return (int)vk;
    }
}

static void blit_to_hdc(HDC hdc, HWND hwnd) {
    RECT rc;
    BITMAPINFO bi;
    if (!g_fb || g_fb_w <= 0 || g_fb_h <= 0) return;
    GetClientRect(hwnd, &rc);
    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = g_fb_w;
    bi.bmiHeader.biHeight      = -g_fb_h; /* top-down */
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    SetStretchBltMode(hdc, HALFTONE);
    StretchDIBits(hdc, 0, 0, rc.right - rc.left, rc.bottom - rc.top,
                  0, 0, g_fb_w, g_fb_h, g_fb, &bi, DIB_RGB_COLORS, SRCCOPY);
}

static LRESULT CALLBACK afw_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        blit_to_hdc(hdc, hwnd);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_LBUTTONDOWN: {
        int x = (int)(short)LOWORD(lp);
        int y = (int)(short)HIWORD(lp);
        g_mouse_down = 1;
        SetCapture(hwnd);
        ev_push(AFW_EV_TOUCH_DOWN, x, y, 0);
        return 0;
    }
    case WM_MOUSEMOVE:
        if (g_mouse_down) {
            int x = (int)(short)LOWORD(lp);
            int y = (int)(short)HIWORD(lp);
            ev_push(AFW_EV_TOUCH_MOVE, x, y, 0);
        }
        return 0;
    case WM_LBUTTONUP:
        if (g_mouse_down) {
            int x = (int)(short)LOWORD(lp);
            int y = (int)(short)HIWORD(lp);
            g_mouse_down = 0;
            ReleaseCapture();
            ev_push(AFW_EV_TOUCH_UP, x, y, 0);
        }
        return 0;
    case WM_KEYDOWN:
        ev_push(AFW_EV_KEY_DOWN, map_vk_to_android_key(wp), 0, 0);
        return 0;
    case WM_KEYUP:
        ev_push(AFW_EV_KEY_UP, map_vk_to_android_key(wp), 0, 0);
        return 0;
    case WM_CHAR:
        if (wp >= 32 && wp < 0x10000)
            ev_push(AFW_EV_CHAR, 0, (int32_t)wp, 0);
        return 0;
    case WM_SIZE: {
        int nw = (int)LOWORD(lp), nh = (int)HIWORD(lp);
        if (nw >= 64 && nh >= 64 && (nw != g_cfg_w || nh != g_cfg_h)) {
            g_cfg_w = nw; g_cfg_h = nh;
            ev_push(AFW_EV_RESIZE, nw, nh, 0);
        }
        return 0;
    }
    case WM_CLOSE:
    case WM_DESTROY:
        ev_push(AFW_EV_QUIT, 0, 0, 0);
        if (msg == WM_CLOSE) {
            DestroyWindow(hwnd);
            g_hwnd = NULL;
            return 0;
        }
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcA(hwnd, msg, wp, lp);
    }
}

static void pump_win32_messages(void) {
    MSG msg;
    if (g_headless || !g_hwnd) return;
    while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) {
            ev_push(AFW_EV_QUIT, 0, 0, 0);
        } else {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
}

/* ---- WinMM waveOut ring-buffer audio ----------------------------------- */
#define AFW_AUDIO_BUFS 8
typedef struct {
    int       active;
    int       headless_sink;
    HWAVEOUT  hwo;
    WAVEHDR   hdr[AFW_AUDIO_BUFS];
    void     *buf[AFW_AUDIO_BUFS];
    int       cap[AFW_AUDIO_BUFS];
    int       next;
} afw_audio_stream;

static afw_audio_stream g_audio;
#else
static int g_audio_active = 0;
#endif

SYSV int32_t afw_host_window_create(const char *title, int32_t width, int32_t height) {
    if (!g_cfg_size_locked) {
        if (width >= 64 && width <= 4096) g_cfg_w = width;
        if (height >= 64 && height <= 4096) g_cfg_h = height;
    }
    g_start_ms = now_ms();
    g_frames = 0;
    g_auto_exit_sent = 0;
    g_inject_idx = 0;
    g_inject_stage = 0;
#if defined(_WIN32)
    if (g_headless) return 0;
    if (!g_hwnd) {
        WNDCLASSA wc;
        RECT r = { 0, 0, g_cfg_w, g_cfg_h };
        DWORD style = WS_OVERLAPPEDWINDOW;
        memset(&wc, 0, sizeof wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = afw_wndproc;
        wc.hInstance     = GetModuleHandleA(NULL);
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.lpszClassName = "AfwAndroidWindowClass";
        RegisterClassA(&wc);
        AdjustWindowRect(&r, style, FALSE);
        g_hwnd = CreateWindowExA(0, wc.lpszClassName,
                                 (title && title[0]) ? title : "Android for Windows",
                                 style, CW_USEDEFAULT, CW_USEDEFAULT,
                                 r.right - r.left, r.bottom - r.top,
                                 NULL, NULL, wc.hInstance, NULL);
        if (!g_hwnd) return -1;
        ShowWindow(g_hwnd, SW_SHOW);
        UpdateWindow(g_hwnd);
    } else if (title && title[0]) {
        SetWindowTextA(g_hwnd, title);
    }
#else
    (void)title;
#endif
    return 0;
}

SYSV int32_t afw_host_present(const uint32_t *argb_pixels, int32_t width, int32_t height) {
    size_t n;
    if (!argb_pixels || width <= 0 || height <= 0 || (uint64_t)width * (uint64_t)height > 16777216ULL)
        return -1;
    n = (size_t)width * (size_t)height;
    if (width != g_fb_w || height != g_fb_h || !g_fb) {
        uint32_t *nb = (uint32_t *)realloc(g_fb, n * 4u);
        if (!nb) return -1;
        g_fb = nb;
        g_fb_w = width;
        g_fb_h = height;
    }
    memcpy(g_fb, argb_pixels, n * 4u);
    g_frames++;
    if (g_screenshot_path[0])
        write_bmp(g_screenshot_path, g_fb, g_fb_w, g_fb_h);
#if defined(_WIN32)
    if (!g_headless && g_hwnd) {
        HDC hdc = GetDC(g_hwnd);
        if (hdc) {
            blit_to_hdc(hdc, g_hwnd);
            ReleaseDC(g_hwnd, hdc);
        }
        pump_win32_messages();
    }
#endif
    return 0;
}

SYSV int32_t afw_host_poll_event(afw_host_event *ev_out) {
    if (!ev_out) return 0;
#if defined(_WIN32)
    pump_win32_messages();
#endif
    /* Scripted click injection (after at least 1 frame has rendered) */
    if (g_frames >= 1 && g_inject_idx < g_ninject && g_ev_head == g_ev_tail) {
        int x = g_inject_x[g_inject_idx], y = g_inject_y[g_inject_idx];
        if (g_inject_stage == 0) {
            ev_push(AFW_EV_TOUCH_DOWN, x, y, 0);
            g_inject_stage = 1;
        } else {
            ev_push(AFW_EV_TOUCH_UP, x, y, 0);
            g_inject_stage = 0;
            g_inject_idx++;
        }
    }
    /* Optional auto-exit timer for CI / automated tests */
    if (g_auto_exit_ms > 0 && !g_auto_exit_sent && g_start_ms > 0 &&
        g_inject_idx >= g_ninject && g_frames >= 2 &&
        (now_ms() - g_start_ms) >= (uint64_t)g_auto_exit_ms) {
        ev_push(AFW_EV_QUIT, 0, 0, 0);
        g_auto_exit_sent = 1;
    }
    if (ev_pop(ev_out)) return 1;
    memset(ev_out, 0, sizeof *ev_out);
    return 0;
}

SYSV void afw_host_get_size(int32_t *width_out, int32_t *height_out) {
    if (width_out)  *width_out  = g_cfg_w;
    if (height_out) *height_out = g_cfg_h;
}

SYSV int32_t afw_host_audio_open(int32_t sample_rate, int32_t channels, int32_t bits) {
    if (sample_rate < 8000 || sample_rate > 192000) return -1;
    if (channels < 1 || channels > 2) return -1;
    if (bits != 8 && bits != 16) return -1;
#if defined(_WIN32)
    if (g_audio.active) (void)afw_host_audio_close(1);
    memset(&g_audio, 0, sizeof g_audio);
    if (g_headless) {
        g_audio.active = 1;
        g_audio.headless_sink = 1;
        return 1;
    }
    {
        WAVEFORMATEX wf;
        memset(&wf, 0, sizeof wf);
        wf.wFormatTag      = WAVE_FORMAT_PCM;
        wf.nChannels       = (WORD)channels;
        wf.nSamplesPerSec  = (DWORD)sample_rate;
        wf.wBitsPerSample  = (WORD)bits;
        wf.nBlockAlign     = (WORD)(channels * (bits / 8));
        wf.nAvgBytesPerSec = wf.nSamplesPerSec * wf.nBlockAlign;
        if (waveOutOpen(&g_audio.hwo, WAVE_MAPPER, &wf, 0, 0, CALLBACK_NULL) != MMSYSERR_NOERROR) {
            /* Graceful fallback if machine has no sound card (e.g. server/VM) */
            g_audio.active = 1;
            g_audio.headless_sink = 1;
            return 1;
        }
        g_audio.active = 1;
        g_audio.headless_sink = 0;
        return 1;
    }
#else
    g_audio_active = 1;
    return 1;
#endif
}

SYSV int32_t afw_host_audio_write(int32_t handle, const void *pcm, int32_t bytes) {
    if (handle != 1 || !pcm || bytes <= 0) return -1;
#if defined(_WIN32)
    if (!g_audio.active) return -1;
    g_audio_bytes += bytes;
    if (g_audio.headless_sink) return bytes;
    {
        int idx = g_audio.next;
        WAVEHDR *h = &g_audio.hdr[idx];
        int tries = 0;
        while ((h->dwFlags & WHDR_PREPARED) && !(h->dwFlags & WHDR_DONE) && tries < 200) {
            Sleep(5);
            tries++;
        }
        if (h->dwFlags & WHDR_PREPARED)
            waveOutUnprepareHeader(g_audio.hwo, h, sizeof *h);
        if (g_audio.cap[idx] < bytes) {
            void *nb = realloc(g_audio.buf[idx], (size_t)bytes);
            if (!nb) return -1;
            g_audio.buf[idx] = nb;
            g_audio.cap[idx] = bytes;
        }
        memcpy(g_audio.buf[idx], pcm, (size_t)bytes);
        memset(h, 0, sizeof *h);
        h->lpData         = (LPSTR)g_audio.buf[idx];
        h->dwBufferLength = (DWORD)bytes;
        if (waveOutPrepareHeader(g_audio.hwo, h, sizeof *h) != MMSYSERR_NOERROR) return -1;
        if (waveOutWrite(g_audio.hwo, h, sizeof *h) != MMSYSERR_NOERROR) return -1;
        g_audio.next = (idx + 1) % AFW_AUDIO_BUFS;
        return bytes;
    }
#else
    if (!g_audio_active) return -1;
    g_audio_bytes += bytes;
    return bytes;
#endif
}

SYSV int32_t afw_host_audio_close(int32_t handle) {
    if (handle != 1) return -1;
#if defined(_WIN32)
    if (!g_audio.active) return 0;
    if (!g_audio.headless_sink && g_audio.hwo) {
        int i;
        waveOutReset(g_audio.hwo);
        for (i = 0; i < AFW_AUDIO_BUFS; i++) {
            if (g_audio.hdr[i].dwFlags & WHDR_PREPARED)
                waveOutUnprepareHeader(g_audio.hwo, &g_audio.hdr[i], sizeof g_audio.hdr[i]);
            free(g_audio.buf[i]);
        }
        waveOutClose(g_audio.hwo);
    }
    memset(&g_audio, 0, sizeof g_audio);
    return 0;
#else
    g_audio_active = 0;
    return 0;
#endif
}

SYSV void afw_host_sleep_ms(int32_t ms) {
    if (ms <= 0) return;
#if defined(_WIN32)
    if (!g_headless && g_hwnd) {
        int rem = ms;
        while (rem > 0) {
            int step = rem > 8 ? 8 : rem;
            pump_win32_messages();
            Sleep((DWORD)step);
            rem -= step;
        }
        return;
    }
    Sleep((DWORD)ms);
#else
    usleep((useconds_t)ms * 1000u);
#endif
}

SYSV void afw_host_get_stats(int32_t *frames_out, int64_t *audio_bytes_out) {
    if (frames_out)      *frames_out      = g_frames;
    if (audio_bytes_out) *audio_bytes_out = g_audio_bytes;
}
