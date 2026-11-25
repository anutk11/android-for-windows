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
#ifndef COBJMACROS
#define COBJMACROS
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <objbase.h>
#include <wincodec.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "mfuuid.lib")
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

SYSV void afw_host_free_buf(void *ptr) {
    free(ptr);
}

#if defined(_WIN32)
static void ensure_com_init(void) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    (void)hr; /* S_OK, S_FALSE, or RPC_E_CHANGED_MODE are all usable */
}

static int utf8_path_to_wide_win(const char *path, wchar_t *out, int cap) {
    char tmp[1024];
    int n, i;
    if (!path || !out || cap <= 0) return 0;
    if (strncmp(path, "/__afw_drv__/", 13) == 0 &&
        ((path[13] >= 'A' && path[13] <= 'Z') || (path[13] >= 'a' && path[13] <= 'z')) &&
        (path[14] == '/' || path[14] == '\0')) {
        snprintf(tmp, sizeof tmp, "%c:%s", path[13], path[14] ? path + 14 : "/");
        path = tmp;
    }
    n = MultiByteToWideChar(CP_UTF8, 0, path, -1, out, cap);
    if (n <= 0) return 0;
    for (i = 0; out[i]; i++) if (out[i] == L'/') out[i] = L'\\';
    return n;
}
#endif

SYSV uint32_t *afw_host_decode_image_alloc(const uint8_t *data, int32_t len,
                                           int32_t *out_w, int32_t *out_h) {
    if (out_w) *out_w = 0;
    if (out_h) *out_h = 0;
    if (!data || len <= 0) return NULL;
#if defined(_WIN32)
    ensure_com_init();
    {
        IWICImagingFactory *factory = NULL;
        IWICStream *stream = NULL;
        IWICBitmapDecoder *decoder = NULL;
        IWICBitmapFrameDecode *frame = NULL;
        IWICFormatConverter *conv = NULL;
        UINT w = 0, h = 0;
        uint32_t *pixels = NULL;
        HRESULT hr;

        hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
                              &IID_IWICImagingFactory, (void **)&factory);
        if (FAILED(hr) || !factory) goto wic_done;
        hr = IWICImagingFactory_CreateStream(factory, &stream);
        if (FAILED(hr) || !stream) goto wic_done;
        hr = IWICStream_InitializeFromMemory(stream, (BYTE *)(uintptr_t)data, (DWORD)len);
        if (FAILED(hr)) goto wic_done;
        hr = IWICImagingFactory_CreateDecoderFromStream(factory, (IStream *)stream, NULL,
                                                        WICDecodeMetadataCacheOnDemand, &decoder);
        if (FAILED(hr) || !decoder) goto wic_done;
        hr = IWICBitmapDecoder_GetFrame(decoder, 0, &frame);
        if (FAILED(hr) || !frame) goto wic_done;
        hr = IWICImagingFactory_CreateFormatConverter(factory, &conv);
        if (FAILED(hr) || !conv) goto wic_done;
        hr = IWICFormatConverter_Initialize(conv, (IWICBitmapSource *)frame,
                                            &GUID_WICPixelFormat32bppBGRA,
                                            WICBitmapDitherTypeNone, NULL, 0.0,
                                            WICBitmapPaletteTypeCustom);
        if (FAILED(hr)) goto wic_done;
        hr = IWICFormatConverter_GetSize(conv, &w, &h);
        if (FAILED(hr) || w == 0 || h == 0 || (uint64_t)w * (uint64_t)h > 16777216ULL)
            goto wic_done;
        pixels = (uint32_t *)malloc((size_t)w * (size_t)h * 4u);
        if (!pixels) goto wic_done;
        hr = IWICFormatConverter_CopyPixels(conv, NULL, w * 4u, w * h * 4u, (BYTE *)pixels);
        if (FAILED(hr)) {
            free(pixels);
            pixels = NULL;
        } else {
            if (out_w) *out_w = (int32_t)w;
            if (out_h) *out_h = (int32_t)h;
        }
    wic_done:
        if (conv)    IWICFormatConverter_Release(conv);
        if (frame)   IWICBitmapFrameDecode_Release(frame);
        if (decoder) IWICBitmapDecoder_Release(decoder);
        if (stream)  IWICStream_Release(stream);
        if (factory) IWICImagingFactory_Release(factory);
        return pixels;
    }
#else
    return NULL;
#endif
}

SYSV int16_t *afw_host_media_decode_alloc(const char *path, int32_t *out_samples,
                                          int32_t *out_rate, int32_t *out_channels) {
    if (out_samples)  *out_samples  = 0;
    if (out_rate)     *out_rate     = 44100;
    if (out_channels) *out_channels = 2;
    if (!path || !path[0]) return NULL;
#if defined(_WIN32)
    ensure_com_init();
    {
        static int mf_started = 0;
        wchar_t wpath[1024];
        IMFSourceReader *reader = NULL;
        IMFMediaType *req = NULL, *actual = NULL;
        UINT32 rate = 44100, ch = 2;
        uint8_t *buf = NULL;
        size_t used = 0, cap = 0;
        const size_t max_bytes = 32u * 1024u * 1024u;
        HRESULT hr;

        if (!mf_started) {
            if (SUCCEEDED(MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET)))
                mf_started = 1;
            else
                return NULL;
        }
        if (!utf8_path_to_wide_win(path, wpath, (int)(sizeof wpath / sizeof wpath[0])))
            return NULL;

        hr = MFCreateSourceReaderFromURL(wpath, NULL, &reader);
        if (FAILED(hr) || !reader) goto mf_done;
        hr = MFCreateMediaType(&req);
        if (FAILED(hr) || !req) goto mf_done;
        IMFMediaType_SetGUID(req, &MF_MT_MAJOR_TYPE, &MFMediaType_Audio);
        IMFMediaType_SetGUID(req, &MF_MT_SUBTYPE, &MFAudioFormat_PCM);
        IMFMediaType_SetUINT32(req, &MF_MT_AUDIO_BITS_PER_SAMPLE, 16);
        hr = IMFSourceReader_SetCurrentMediaType(reader, (DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, NULL, req);
        if (FAILED(hr)) goto mf_done;
        hr = IMFSourceReader_GetCurrentMediaType(reader, (DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, &actual);
        if (SUCCEEDED(hr) && actual) {
            (void)IMFMediaType_GetUINT32(actual, &MF_MT_AUDIO_SAMPLES_PER_SECOND, &rate);
            (void)IMFMediaType_GetUINT32(actual, &MF_MT_AUDIO_NUM_CHANNELS, &ch);
        }

        for (;;) {
            DWORD flags = 0;
            IMFSample *sample = NULL;
            IMFMediaBuffer *mb = NULL;
            BYTE *ptr = NULL;
            DWORD cur = 0;
            hr = IMFSourceReader_ReadSample(reader, (DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM,
                                            0, NULL, &flags, NULL, &sample);
            if (FAILED(hr) || (flags & MF_SOURCE_READERF_ENDOFSTREAM)) {
                if (sample) IMFSample_Release(sample);
                break;
            }
            if (!sample) continue;
            if (SUCCEEDED(IMFSample_ConvertToContiguousBuffer(sample, &mb)) && mb) {
                if (SUCCEEDED(IMFMediaBuffer_Lock(mb, &ptr, NULL, &cur)) && ptr && cur > 0) {
                    if (used + cur > max_bytes) cur = (DWORD)(max_bytes - used);
                    if (used + cur > cap) {
                        size_t ncap = cap ? cap * 2u : 65536u;
                        while (ncap < used + cur) ncap *= 2u;
                        uint8_t *nb = (uint8_t *)realloc(buf, ncap);
                        if (nb) { buf = nb; cap = ncap; }
                        else cur = 0;
                    }
                    if (cur > 0) {
                        memcpy(buf + used, ptr, cur);
                        used += cur;
                    }
                    IMFMediaBuffer_Unlock(mb);
                }
                IMFMediaBuffer_Release(mb);
            }
            IMFSample_Release(sample);
            if (used >= max_bytes) break;
        }
    mf_done:
        if (actual) IMFMediaType_Release(actual);
        if (req)    IMFMediaType_Release(req);
        if (reader) IMFSourceReader_Release(reader);
        if (!buf || used < 2) { free(buf); return NULL; }
        if (out_samples)  *out_samples  = (int32_t)(used / 2u);
        if (out_rate)     *out_rate     = (int32_t)rate;
        if (out_channels) *out_channels = (int32_t)ch;
        return (int16_t *)buf;
    }
#else
    return NULL;
#endif
}

SYSV float afw_host_measure_text_ttf(const char *utf8_text, float px_size, int32_t bold) {
    if (!utf8_text || !utf8_text[0]) return 0.0f;
#if defined(_WIN32)
    {
        wchar_t wbuf[512];
        int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8_text, -1, wbuf, 512);
        HDC hdc;
        HFONT font, oldf;
        SIZE sz = { 0, 0 };
        int h = (int)(px_size + 0.5f);
        if (wlen <= 1) return 0.0f;
        if (h < 8) h = 8;
        hdc = CreateCompatibleDC(NULL);
        if (!hdc) return -1.0f;
        font = CreateFontW(-h, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        oldf = (HFONT)SelectObject(hdc, font);
        GetTextExtentPoint32W(hdc, wbuf, wlen - 1, &sz);
        SelectObject(hdc, oldf);
        DeleteObject(font);
        DeleteDC(hdc);
        return (float)sz.cx;
    }
#else
    (void)px_size; (void)bold;
    return -1.0f;
#endif
}

SYSV int32_t afw_host_draw_text_ttf(uint32_t *fb, int32_t fb_w, int32_t fb_h,
                                    const int32_t clip[4], const char *utf8_text,
                                    float x, float baseline_y, float px_size,
                                    uint32_t argb, int32_t bold) {
    if (!fb || !utf8_text || !utf8_text[0] || fb_w <= 0 || fb_h <= 0) return -1;
#if defined(_WIN32)
    {
        wchar_t wbuf[512];
        int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8_text, -1, wbuf, 512);
        HDC hdc;
        HFONT font, oldf;
        TEXTMETRICW tm;
        SIZE sz = { 0, 0 };
        BITMAPINFO bmi;
        HBITMAP dib, oldb;
        uint32_t *bits = NULL;
        int tw, th, dst_x, dst_y, cl, ct, cr, cb, yy, xx;
        int h = (int)(px_size + 0.5f);
        uint32_t src_a = (argb >> 24) & 0xFFu;
        uint32_t src_r = (argb >> 16) & 0xFFu;
        uint32_t src_g = (argb >> 8)  & 0xFFu;
        uint32_t src_b = argb & 0xFFu;
        if (wlen <= 1 || src_a == 0) return 0;
        if (h < 8) h = 8;

        hdc = CreateCompatibleDC(NULL);
        if (!hdc) return -1;
        font = CreateFontW(-h, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        oldf = (HFONT)SelectObject(hdc, font);
        GetTextMetricsW(hdc, &tm);
        GetTextExtentPoint32W(hdc, wbuf, wlen - 1, &sz);
        tw = sz.cx + 4;
        th = sz.cy + 4;
        if (tw <= 0 || th <= 0 || tw > 4096 || th > 512) {
            SelectObject(hdc, oldf); DeleteObject(font); DeleteDC(hdc);
            return -1;
        }

        memset(&bmi, 0, sizeof bmi);
        bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth       = tw;
        bmi.bmiHeader.biHeight      = -th;
        bmi.bmiHeader.biPlanes      = 1;
        bmi.bmiHeader.biBitCount    = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        dib = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, (void **)&bits, NULL, 0);
        if (!dib || !bits) {
            SelectObject(hdc, oldf); DeleteObject(font); DeleteDC(hdc);
            return -1;
        }
        oldb = (HBITMAP)SelectObject(hdc, dib);
        memset(bits, 0, (size_t)tw * (size_t)th * 4u);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));
        ExtTextOutW(hdc, 0, 0, 0, NULL, wbuf, (UINT)(wlen - 1), NULL);
        GdiFlush();

        dst_x = (int)(x + 0.5f);
        dst_y = (int)(baseline_y + 0.5f) - tm.tmAscent;
        cl = clip ? clip[0] : 0;
        ct = clip ? clip[1] : 0;
        cr = clip ? clip[2] : fb_w;
        cb = clip ? clip[3] : fb_h;
        if (cl < 0) cl = 0;
        if (ct < 0) ct = 0;
        if (cr > fb_w) cr = fb_w;
        if (cb > fb_h) cb = fb_h;

        for (yy = 0; yy < th; yy++) {
            int py = dst_y + yy;
            if (py < ct || py >= cb) continue;
            for (xx = 0; xx < tw; xx++) {
                int px = dst_x + xx;
                uint32_t cov;
                if (px < cl || px >= cr) continue;
                cov = (bits[yy * tw + xx] >> 8) & 0xFFu; /* green channel = white coverage */
                if (cov == 0) continue;
                {
                    uint32_t a = (cov * src_a) / 255u;
                    uint32_t ia = 255u - a;
                    uint32_t dst = fb[py * fb_w + px];
                    uint32_t r = (src_r * a + ((dst >> 16) & 0xFFu) * ia) / 255u;
                    uint32_t g = (src_g * a + ((dst >> 8)  & 0xFFu) * ia) / 255u;
                    uint32_t b = (src_b * a + (dst & 0xFFu) * ia) / 255u;
                    fb[py * fb_w + px] = 0xFF000000u | (r << 16) | (g << 8) | b;
                }
            }
        }
        SelectObject(hdc, oldb);
        SelectObject(hdc, oldf);
        DeleteObject(dib);
        DeleteObject(font);
        DeleteDC(hdc);
        return 0;
    }
#else
    (void)clip; (void)x; (void)baseline_y; (void)px_size; (void)argb; (void)bold;
    return -1;
#endif
}

SYSV int32_t afw_host_get_user_dir(const char *kind, char *buf, int32_t bufsz) {
    if (!buf || bufsz <= 1) return -1;
    buf[0] = '\0';
#if defined(_WIN32)
    {
        const char *home = getenv("USERPROFILE");
        int i;
        if (!home || !home[0]) return -1;
        if (kind && kind[0]) snprintf(buf, (size_t)bufsz, "%s/%s", home, kind);
        else snprintf(buf, (size_t)bufsz, "%s", home);
        for (i = 0; buf[i]; i++) if (buf[i] == '\\') buf[i] = '/';
        return (int32_t)strlen(buf);
    }
#else
    {
        const char *home = getenv("HOME");
        if (!home || !home[0]) return -1;
        if (kind && kind[0]) snprintf(buf, (size_t)bufsz, "%s/%s", home, kind);
        else snprintf(buf, (size_t)bufsz, "%s", home);
        return (int32_t)strlen(buf);
    }
#endif
}
