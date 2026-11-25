package com.afw;

/**
 * Native bridge to Android-for-Windows Win32 host (src/win_host.c via afw_apk_launcher).
 * All native methods are bound via JNI RegisterNatives before AfwLauncher.launch() runs.
 */
public final class AfwHost {
    public static final int EV_NONE       = 0;
    public static final int EV_TOUCH_DOWN = 1;
    public static final int EV_TOUCH_MOVE = 2;
    public static final int EV_TOUCH_UP   = 3;
    public static final int EV_KEY_DOWN   = 4;
    public static final int EV_KEY_UP     = 5;
    public static final int EV_CHAR       = 6;
    public static final int EV_RESIZE     = 7;
    public static final int EV_QUIT       = 8;

    private AfwHost() {}

    public static native int windowCreate(String title, int width, int height);
    public static native int present(int[] argbPixels, int width, int height);
    public static native int pollEvent(int[] out4);
    public static native int getWidth();
    public static native int getHeight();
    public static native int audioOpen(int sampleRate, int channels, int bits);
    public static native int audioWrite(int handle, byte[] pcm, int offset, int length);
    public static native int audioClose(int handle);
    public static native void sleepMs(int ms);
    public static native int getFrames();
    public static native long getAudioBytes();
}
