/*
 * win_host_test.c - Host unit tests for src/win_host.c (headless framebuffer,
 * 32-bit BMP screenshot export, injected clicks, auto-exit quit event, and
 * PCM audio bridge accounting).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/win_host.h"

static int g_pass = 0, g_fail = 0;

static void check(const char *name, int cond) {
    if (cond) {
        g_pass++;
    } else {
        g_fail++;
        fprintf(stderr, "FAIL: %s\n", name);
    }
}

static uint32_t read_le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t read_le16(const unsigned char *p) {
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

int main(void) {
    const char *bmp = "afw_win_host_test.bmp";
    int32_t w = 0, h = 0, frames = 0;
    int64_t audio_bytes = 0;
    uint32_t pixels[128 * 96];
    int x, y;
    afw_host_event ev;
    int got_down = 0, got_up = 0, got_quit = 0;
    int32_t ah;
    int16_t pcm[256];

    remove(bmp);

    afw_host_set_headless(1);
    afw_host_set_size(128, 96);
    afw_host_set_screenshot(bmp);
    afw_host_add_inject_click(25, 30);
    afw_host_set_auto_exit_ms(10);

    check("window_create succeeds in headless mode",
          afw_host_window_create("Test App", 400, 600) == 0);
    afw_host_get_size(&w, &h);
    check("window size respects CLI override (128x96)", w == 128 && h == 96);

    for (y = 0; y < 96; y++) {
        for (x = 0; x < 128; x++) {
            uint8_t r = (uint8_t)(x * 2);
            uint8_t g = (uint8_t)(y * 2);
            uint8_t b = 0x80;
            pixels[y * 128 + x] = 0xFF000000u | ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
        }
    }
    check("present succeeds", afw_host_present(pixels, 128, 96) == 0);
    check("present rejects invalid dimensions", afw_host_present(pixels, 0, 96) < 0);
    check("present rejects NULL pixels", afw_host_present(NULL, 128, 96) < 0);

    /* Present a second frame and poll injected click + auto-exit */
    check("second present succeeds", afw_host_present(pixels, 128, 96) == 0);
    afw_host_sleep_ms(15);
    while (afw_host_poll_event(&ev)) {
        if (ev.type == AFW_EV_TOUCH_DOWN && ev.x == 25 && ev.y == 30) got_down = 1;
        else if (ev.type == AFW_EV_TOUCH_UP && ev.x == 25 && ev.y == 30) got_up = 1;
        else if (ev.type == AFW_EV_QUIT) got_quit = 1;
    }
    check("injected click DOWN received at (25,30)", got_down);
    check("injected click UP received at (25,30)", got_up);
    check("auto-exit QUIT event received", got_quit);

    /* Audio bridge test */
    ah = afw_host_audio_open(44100, 1, 16);
    check("audio_open returns positive handle", ah > 0);
    memset(pcm, 0x22, sizeof pcm);
    check("audio_write writes full buffer",
          afw_host_audio_write(ah, pcm, (int32_t)sizeof pcm) == (int32_t)sizeof pcm);
    check("audio_write rejects invalid handle", afw_host_audio_write(999, pcm, 32) < 0);
    check("audio_close succeeds", afw_host_audio_close(ah) == 0);

    afw_host_get_stats(&frames, &audio_bytes);
    check("frame count == 2", frames == 2);
    check("audio bytes == sizeof(pcm)", audio_bytes == (int64_t)sizeof pcm);

    /* Verify written 32-bit BMP screenshot */
    {
        FILE *f = fopen(bmp, "rb");
        unsigned char hdr[54];
        size_t nread = f ? fread(hdr, 1, sizeof hdr, f) : 0;
        uint32_t px0 = 0;
        size_t pxread = (f && nread == 54) ? fread(&px0, 4, 1, f) : 0;
        if (f) fclose(f);
        check("BMP screenshot created", f != NULL && nread == 54);
        check("BMP signature 'BM'", hdr[0] == 'B' && hdr[1] == 'M');
        check("BMP width == 128", read_le32(hdr + 18) == 128u);
        check("BMP height == -96 (top-down)", (int32_t)read_le32(hdr + 22) == -96);
        check("BMP bpp == 32", read_le16(hdr + 28) == 32u);
        check("BMP pixel[0] matches ARGB_8888", pxread == 1 && px0 == pixels[0]);
        remove(bmp);
    }

    printf("win_host_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
