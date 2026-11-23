/*
 * g2_detach_probe.c - Minimal Windows test DLL for G2-1 Item 5.
 *
 * Verifies that DllMain(DLL_THREAD_DETACH) invoked during ExitThread() runs
 * on the restored original Windows host stack (after VirtualFree of the Bionic
 * stack) rather than on freed memory.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

static volatile DWORD    g_target_tid;
static volatile LONG     g_detach_count;
static volatile uint64_t g_detach_rsp;

__declspec(dllexport) void g2_detach_arm(DWORD tid) {
    InterlockedExchange(&g_detach_count, 0);
    g_detach_rsp = 0;
    g_target_tid = tid;
}

__declspec(dllexport) LONG g2_detach_result(uint64_t *rsp_out) {
    if (rsp_out) *rsp_out = g_detach_rsp;
    return InterlockedCompareExchange(&g_detach_count, 0, 0);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst;
    (void)reserved;
    if (reason == DLL_THREAD_DETACH && g_target_tid != 0 &&
        GetCurrentThreadId() == g_target_tid) {
        volatile uint64_t local_var = 0;
        g_detach_rsp = (uint64_t)(uintptr_t)&local_var;
        InterlockedIncrement(&g_detach_count);
    }
    return TRUE;
}
