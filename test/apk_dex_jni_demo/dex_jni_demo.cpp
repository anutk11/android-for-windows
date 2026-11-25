/*
 * dex_jni_demo.cpp - Real Android NDK C++17 JNI shared library for dex_jni_demo.apk.
 *
 * Exercises:
 *   - JNI_OnLoad(JavaVM*, void*) + vm->GetEnv + RegisterNatives
 *   - Bidirectional JNI: Java classes.dex -> C++ nativeRunCheck -> C++ calls back
 *     into Java MainActivity.javaCallback(6) via env->CallIntMethod -> returns 45
 *   - Real C++17 std::runtime_error throw/catch via bundled libc++_shared.so
 *   - JNI string creation (env->NewStringUTF) returned to Dalvik VM
 */
#include <jni.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>

static jstring JNICALL native_run_check(JNIEnv *env, jobject thiz, jint a, jint b) {
    /* 1. Verify C++17 exception works inside JNI call */
    int exc_ok = 0;
    try {
        throw std::runtime_error("jni-cxx-ok");
    } catch (const std::runtime_error &e) {
        exc_ok = (std::strcmp(e.what(), "jni-cxx-ok") == 0) ? 1 : 0;
    }
    if (!exc_ok) return env->NewStringUTF("ERR_CXX");

    /* 2. Call BACK into Java MainActivity.javaCallback(6) -> expects 6*7+3 = 45 */
    jclass cls = env->GetObjectClass(thiz);
    if (!cls) return env->NewStringUTF("ERR_CLS");
    jmethodID cb_mid = env->GetMethodID(cls, "javaCallback", "(I)I");
    if (!cb_mid) return env->NewStringUTF("ERR_MID");
    jint cb_val = env->CallIntMethod(thiz, cb_mid, static_cast<jint>(6));

    /* 3. Verify JNI int array roundtrip */
    jintArray arr = env->NewIntArray(3);
    jint vals[3] = { a, b, cb_val };
    env->SetIntArrayRegion(arr, 0, 3, vals);
    jint out_vals[3] = {0, 0, 0};
    env->GetIntArrayRegion(arr, 0, 3, out_vals);
    int sum = out_vals[0] + out_vals[1] + out_vals[2]; /* 10 + 20 + 45 = 75 */

    char buf[64];
    std::snprintf(buf, sizeof buf, "JNI_OK:%d", sum);
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || !env)
        return JNI_ERR;
    jclass cls = env->FindClass("com/afw/dexdemo/MainActivity");
    if (!cls) return JNI_ERR;
    static const JNINativeMethod methods[] = {
        { const_cast<char *>("nativeRunCheck"),
          const_cast<char *>("(II)Ljava/lang/String;"),
          reinterpret_cast<void *>(native_run_check) }
    };
    if (env->RegisterNatives(cls, methods, 1) != 0)
        return JNI_ERR;
    return JNI_VERSION_1_6;
}
