/*
 * win_host.h - Native Windows GUI window, DIB framebuffer, input events,
 * BMP screenshot export, and WinMM (waveOut) PCM audio bridge for Android
 * apps running on real Android 14 libart.so (Gates G4/G5).
 *
 * All Win32 calls live inside src/win_host.c (Rule 8).
 */
#ifndef AFW_WIN_HOST_H
#define AFW_WIN_HOST_H

#include <stdint.h>
#include "platform.h"

#define AFW_EV_NONE       0
#define AFW_EV_TOUCH_DOWN 1
#define AFW_EV_TOUCH_MOVE 2
#define AFW_EV_TOUCH_UP   3
#define AFW_EV_KEY_DOWN   4
#define AFW_EV_KEY_UP     5
#define AFW_EV_CHAR       6
#define AFW_EV_RESIZE     7
#define AFW_EV_QUIT       8

typedef struct {
    int32_t type;
    int32_t x;
    int32_t y;
    int32_t mods;
} afw_host_event;

/* Host-side CLI configuration (called from main.c before executing launcher). */
void afw_host_set_headless(int on);
void afw_host_set_size(int width, int height);
void afw_host_set_screenshot(const char *bmp_path);
void afw_host_add_inject_click(int x, int y);
void afw_host_set_auto_exit_ms(int ms);

/* SYSV-ABI host bridge functions exposed to Android native code via bionic_shim.c. */
SYSV int32_t afw_host_window_create(const char *title, int32_t width, int32_t height);
SYSV int32_t afw_host_present(const uint32_t *argb_pixels, int32_t width, int32_t height);
SYSV int32_t afw_host_poll_event(afw_host_event *ev_out);
SYSV void    afw_host_get_size(int32_t *width_out, int32_t *height_out);
SYSV int32_t afw_host_audio_open(int32_t sample_rate, int32_t channels, int32_t bits);
SYSV int32_t afw_host_audio_write(int32_t handle, const void *pcm, int32_t bytes);
SYSV int32_t afw_host_audio_close(int32_t handle);
SYSV void    afw_host_sleep_ms(int32_t ms);
SYSV void    afw_host_get_stats(int32_t *frames_out, int64_t *audio_bytes_out);

#endif
