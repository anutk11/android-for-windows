/*
 * hello.c - A tiny Android library used to test the loader.
 * Built with the Android NDK as libhello.so (x86_64, Android API 24).
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>

static int g_value = 0;

/* Runs automatically when the library is loaded (via .init_array). */
__attribute__((constructor)) static void on_load(void) {
    g_value = 42;
}

const char *afw_greeting(void) {
    return "Hello from Android code!";
}

int afw_add(int a, int b) {
    return a + b;
}

int afw_init_value(void) {
    return g_value;
}

/* Android code calling a function that lives on the Windows side. */
int afw_apply(int (*fn)(int), int x) {
    return fn(x);
}

/* Has a local array, so the NDK's -fstack-protector-strong inserts a stack
 * guard check: reads fs:[0x28] on entry and exit. */
int afw_stack_test(int n) {
    volatile char buf[64];
    int i, sum = 0;
    for (i = 0; i < 64; i++) buf[i] = (char)(i % n);
    for (i = 0; i < 64; i++) sum += buf[i];
    return sum;
}

void afw_say(const char *name) {
    size_t n = strlen(name) + 32;
    char *buf = (char *)malloc(n);
    if (!buf) return;
    strcpy(buf, "Shalom, ");
    strcat(buf, name);
    strcat(buf, "!");
    puts(buf);
    __android_log_write(ANDROID_LOG_INFO, "hello.so", buf);
    free(buf);
}
