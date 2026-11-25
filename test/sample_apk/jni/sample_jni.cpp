/*
 * sample_jni.cpp - Native Android x86_64 DSP library packaged inside
 * sample_music_app.apk (lib/x86_64/libsample_jni.so) and loaded via
 * System.loadLibrary("sample_jni") inside real Android 14 libart.so on Windows.
 */
#include <jni.h>
#include <cmath>
#include <cstdint>

extern "C" JNIEXPORT jstring JNICALL
Java_com_afw_sample_PlayerActivity_nativeDspVersion(JNIEnv *env, jclass) {
    return env->NewStringUTF("AFW-Native-DSP-1.0");
}

extern "C" JNIEXPORT jdouble JNICALL
Java_com_afw_sample_PlayerActivity_nativeSynthWave(
    JNIEnv *env, jclass, jshortArray outBuf, jdouble freqHz, jdouble phase, jint sampleRate) {
    if (!outBuf || sampleRate <= 0) return phase;
    jsize n = env->GetArrayLength(outBuf);
    if (n <= 0) return phase;
    jshort *dst = env->GetShortArrayElements(outBuf, nullptr);
    if (!dst) return phase;

    const double twoPi = 6.28318530717958647692;
    const double step = twoPi * freqHz / static_cast<double>(sampleRate);
    double p = phase;
    for (jsize i = 0; i < n; i++) {
        /* Fundamental sine + gentle 2nd & 3rd harmonics for a warm synth tone */
        double s = 0.72 * std::sin(p) + 0.20 * std::sin(2.0 * p) + 0.08 * std::sin(3.0 * p);
        int32_t v = static_cast<int32_t>(s * 18000.0);
        if (v > 32767) v = 32767;
        else if (v < -32768) v = -32768;
        dst[i] = static_cast<jshort>(v);
        p += step;
        if (p >= twoPi) p -= twoPi;
    }

    env->ReleaseShortArrayElements(outBuf, dst, 0);
    return p;
}
