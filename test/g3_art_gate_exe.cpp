/*
 * g3_art_gate_exe.cpp - Real Android 14 libart.so boot & Java execution gate (G3).
 *
 * Usage:
 *   g3_art_gate_exe <art_root_dir> <g3_java_test.jar>
 *
 * Dynamically loads real Android 14 libart.so via dlopen(), boots the ART JVM
 * via JNI_CreateJavaVM() using the extracted bootclasspath JARs, executes
 * G3ArtTest.runAll() (ArrayList, HashMap, StringBuilder, ArithmeticException,
 * bidirectional JNI C++ <-> Java), and shuts down cleanly.
 */
#include <dlfcn.h>
#include <jni.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static jint JNICALL native_compute(JNIEnv *env, jclass cls, jint a, jint b) {
    jmethodID mid = env->GetStaticMethodID(cls, "javaHelper", "(I)I");
    if (!mid) return -1;
    jint cb = env->CallStaticIntMethod(cls, mid, static_cast<jint>(6));
    return a + b + cb; /* 10 + 20 + 45 = 75 */
}

int main(int argc, char **argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <art_dir> <test_jar>\n", argv[0]);
        return 2;
    }
    std::string art_dir = argv[1];
    std::string test_jar = argv[2];
    std::string javalib = art_dir + "/javalib";
    std::string lib64   = art_dir + "/lib64";

    setenv("ANDROID_ART_ROOT", art_dir.c_str(), 1);
    setenv("ANDROID_I18N_ROOT", art_dir.c_str(), 1);
    setenv("ANDROID_TZDATA_ROOT", art_dir.c_str(), 1);
    setenv("ANDROID_ROOT", art_dir.c_str(), 1);
    setenv("ANDROID_DATA", art_dir.c_str(), 1);

    std::printf("=== G3 ART Gate: booting real Android 14 libart.so ===\n");
    std::printf("  art_dir:  %s\n  test_jar: %s\n", art_dir.c_str(), test_jar.c_str());

    /* Redirect Android liblog output to stderr so all ART LOG()/CHECK() messages are visible. */
    void *h_log = dlopen("liblog.so", RTLD_NOW);
    if (h_log) {
        typedef void (*logger_fn)(const void *);
        typedef void (*set_logger_fn)(logger_fn);
        set_logger_fn set_logger = reinterpret_cast<set_logger_fn>(dlsym(h_log, "__android_log_set_logger"));
        logger_fn stderr_logger = reinterpret_cast<logger_fn>(dlsym(h_log, "__android_log_stderr_logger"));
        if (set_logger && stderr_logger) {
            set_logger(stderr_logger);
            std::printf("[G3] step 0 OK: liblog redirected to stderr\n");
        }
    }

    std::printf("[G3] step 1: dlopen(\"libart.so\", RTLD_NOW)...\n");
    void *h_art = dlopen("libart.so", RTLD_NOW);
    if (!h_art) {
        std::fprintf(stderr, "[G3] FAIL: dlopen(libart.so) failed: %s\n", dlerror());
        return 1;
    }
    std::printf("[G3] step 1 OK: libart.so loaded at %p\n", h_art);

    typedef jint (*create_vm_fn)(JavaVM **, JNIEnv **, void *);
    create_vm_fn create_vm = reinterpret_cast<create_vm_fn>(dlsym(h_art, "JNI_CreateJavaVM"));
    if (!create_vm) {
        std::fprintf(stderr, "[G3] FAIL: dlsym(JNI_CreateJavaVM) failed: %s\n", dlerror());
        return 1;
    }
    std::printf("[G3] step 2 OK: JNI_CreateJavaVM at %p\n", reinterpret_cast<void *>(create_vm));

    std::string bcp = "-Xbootclasspath:" +
        javalib + "/core-oj.jar:" +
        javalib + "/core-libart.jar:" +
        javalib + "/core-icu4j.jar:" +
        javalib + "/bouncycastle.jar:" +
        javalib + "/apache-xml.jar:" +
        javalib + "/okhttp.jar:" +
        javalib + "/conscrypt.jar";
    std::string cp = "-Djava.class.path=" + test_jar;
    std::string lp = "-Djava.library.path=" + lib64;

    std::vector<std::string> opt_strs = {
        bcp,
        cp,
        lp,
        "-Xnoimage-dex2oat",
        "-Xusejit:false",
        "-Xint",
        "-Xms8m",
        "-Xmx32m",
        "-Xnorelocate",
        "-Xverify:none"
    };
    std::vector<JavaVMOption> opts(opt_strs.size());
    for (size_t i = 0; i < opt_strs.size(); i++) {
        opts[i].optionString = const_cast<char *>(opt_strs[i].c_str());
        opts[i].extraInfo = nullptr;
    }

    JavaVMInitArgs args;
    args.version = JNI_VERSION_1_6;
    args.nOptions = static_cast<jint>(opts.size());
    args.options = opts.data();
    args.ignoreUnrecognized = JNI_TRUE;

    JavaVM *vm = nullptr;
    JNIEnv *env = nullptr;
    std::printf("[G3] step 3: calling JNI_CreateJavaVM()...\n");
    jint rc = create_vm(&vm, &env, &args);
    if (rc != JNI_OK || !vm || !env) {
        std::fprintf(stderr, "[G3] FAIL: JNI_CreateJavaVM returned %d\n", rc);
        return 1;
    }
    std::printf("[G3] step 3 OK: real Android 14 ART JVM created! (vm=%p, env=%p)\n",
                static_cast<void *>(vm), static_cast<void *>(env));

    std::printf("[G3] step 4: FindClass(\"G3ArtTest\") + RegisterNatives + runAll()...\n");
    jclass cls = env->FindClass("G3ArtTest");
    if (!cls) {
        if (env->ExceptionCheck()) env->ExceptionDescribe();
        std::fprintf(stderr, "[G3] FAIL: FindClass(G3ArtTest) returned NULL\n");
        return 1;
    }
    static const JNINativeMethod methods[] = {
        { const_cast<char *>("nativeCompute"), const_cast<char *>("(II)I"),
          reinterpret_cast<void *>(native_compute) }
    };
    if (env->RegisterNatives(cls, methods, 1) != 0) {
        std::fprintf(stderr, "[G3] FAIL: RegisterNatives failed\n");
        return 1;
    }
    jmethodID run_mid = env->GetStaticMethodID(cls, "runAll", "()Ljava/lang/String;");
    if (!run_mid) {
        std::fprintf(stderr, "[G3] FAIL: GetStaticMethodID(runAll) returned NULL\n");
        return 1;
    }
    jstring jres = static_cast<jstring>(env->CallStaticObjectMethod(cls, run_mid));
    if (env->ExceptionCheck() || !jres) {
        if (env->ExceptionCheck()) env->ExceptionDescribe();
        std::fprintf(stderr, "[G3] FAIL: G3ArtTest.runAll() threw or returned NULL\n");
        return 1;
    }
    const char *utf = env->GetStringUTFChars(jres, nullptr);
    std::printf("[G3] step 4 result: \"%s\"\n", utf ? utf : "(null)");
    int ok = (utf && std::strcmp(utf, "G3_ART_OK:75") == 0);
    if (utf) env->ReleaseStringUTFChars(jres, utf);

    vm->DestroyJavaVM();
    if (!ok) {
        std::fprintf(stderr, "[G3] FAIL: unexpected result from G3ArtTest.runAll()\n");
        return 1;
    }
    std::printf("G3 ART GATE PASSED\n");
    return 0;
}
