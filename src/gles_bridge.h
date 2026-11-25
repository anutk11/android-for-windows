/*
 * gles_bridge.h - Self-contained EGL 1.4 + OpenGL ES 2.0 System V ABI bridge.
 *
 * Renders deterministically into the ANativeWindow's RGBA8888 afw_gui_surface
 * (blitted live to Win32 HWND on eglSwapBuffers, and works identically on
 * headless CI runners without requiring GPU OpenGL 2.0 drivers).
 */
#ifndef AFW_GLES_BRIDGE_H
#define AFW_GLES_BRIDGE_H

/* Lookup EGL / GLESv2 symbols (called by bionic_shim.c). */
void *afw_gles_lookup(const char *name);

/* Release any residual GLES resources after an APK run finishes. */
void  afw_gles_shutdown(void);

#endif
