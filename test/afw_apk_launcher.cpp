/*
 * afw_apk_launcher.cpp - Android x86_64 PIE executable that boots real
 * Android 14 libart.so, binds com.afw.AfwHost JNI methods to the Windows
 * GUI/input/audio host shims (__afw_host_*), and launches any Android APK
 * via com.afw.AfwLauncher.launch(apkPath, dataDir).
 *
 * Usage:
 *   afw_apk_launcher <art_dir> <framework_jar> <apk_path> [data_dir]
 */
#include <dlfcn.h>
#include <jni.h>
#include <sys/stat.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

struct AfwHostEvent {
    int32_t type;
    int32_t x;
    int32_t y;
    int32_t mods;
};

typedef int32_t (*fn_window_create)(const char *, int32_t, int32_t);
typedef int32_t (*fn_present)(const uint32_t *, int32_t, int32_t);
typedef int32_t (*fn_poll_event)(AfwHostEvent *);
typedef void    (*fn_get_size)(int32_t *, int32_t *);
typedef int32_t (*fn_audio_open)(int32_t, int32_t, int32_t);
typedef int32_t (*fn_audio_write)(int32_t, const void *, int32_t);
typedef int32_t (*fn_audio_close)(int32_t);
typedef void    (*fn_sleep_ms)(int32_t);
typedef void    (*fn_get_stats)(int32_t *, int64_t *);

static fn_window_create g_win_create = nullptr;
static fn_present       g_present    = nullptr;
static fn_poll_event    g_poll_event = nullptr;
static fn_get_size      g_get_size   = nullptr;
static fn_audio_open    g_audio_open = nullptr;
static fn_audio_write   g_audio_write = nullptr;
static fn_audio_close   g_audio_close = nullptr;
static fn_sleep_ms      g_sleep_ms   = nullptr;
static fn_get_stats     g_get_stats  = nullptr;

static bool resolve_host_shims() {
    g_win_create  = reinterpret_cast<fn_window_create>(dlsym(RTLD_DEFAULT, "__afw_host_window_create"));
    g_present     = reinterpret_cast<fn_present>(dlsym(RTLD_DEFAULT, "__afw_host_present"));
    g_poll_event  = reinterpret_cast<fn_poll_event>(dlsym(RTLD_DEFAULT, "__afw_host_poll_event"));
    g_get_size    = reinterpret_cast<fn_get_size>(dlsym(RTLD_DEFAULT, "__afw_host_get_size"));
    g_audio_open  = reinterpret_cast<fn_audio_open>(dlsym(RTLD_DEFAULT, "__afw_host_audio_open"));
    g_audio_write = reinterpret_cast<fn_audio_write>(dlsym(RTLD_DEFAULT, "__afw_host_audio_write"));
    g_audio_close = reinterpret_cast<fn_audio_close>(dlsym(RTLD_DEFAULT, "__afw_host_audio_close"));
    g_sleep_ms    = reinterpret_cast<fn_sleep_ms>(dlsym(RTLD_DEFAULT, "__afw_host_sleep_ms"));
    g_get_stats   = reinterpret_cast<fn_get_stats>(dlsym(RTLD_DEFAULT, "__afw_host_get_stats"));
    return g_win_create && g_present && g_poll_event && g_get_size &&
           g_audio_open && g_audio_write && g_audio_close && g_sleep_ms && g_get_stats;
}

static jint JNICALL jni_window_create(JNIEnv *env, jclass, jstring jtitle, jint w, jint h) {
    const char *title = jtitle ? env->GetStringUTFChars(jtitle, nullptr) : "Android for Windows";
    int32_t rc = g_win_create(title ? title : "Android for Windows", w, h);
    if (jtitle && title) env->ReleaseStringUTFChars(jtitle, title);
    return rc;
}

static jint JNICALL jni_present(JNIEnv *env, jclass, jintArray jpixels, jint w, jint h) {
    if (!jpixels || w <= 0 || h <= 0) return -1;
    jsize len = env->GetArrayLength(jpixels);
    if (static_cast<int64_t>(len) < static_cast<int64_t>(w) * static_cast<int64_t>(h)) return -1;
    jint *ptr = env->GetIntArrayElements(jpixels, nullptr);
    if (!ptr) return -1;
    int32_t rc = g_present(reinterpret_cast<const uint32_t *>(ptr), w, h);
    env->ReleaseIntArrayElements(jpixels, ptr, JNI_ABORT);
    return rc;
}

static jint JNICALL jni_poll_event(JNIEnv *env, jclass, jintArray jout) {
    if (!jout || env->GetArrayLength(jout) < 4) return 0;
    AfwHostEvent ev{};
    int32_t got = g_poll_event(&ev);
    if (got) {
        jint vals[4] = { ev.type, ev.x, ev.y, ev.mods };
        env->SetIntArrayRegion(jout, 0, 4, vals);
    }
    return got;
}

static jint JNICALL jni_get_width(JNIEnv *, jclass) {
    int32_t w = 420, h = 740;
    g_get_size(&w, &h);
    return w;
}

static jint JNICALL jni_get_height(JNIEnv *, jclass) {
    int32_t w = 420, h = 740;
    g_get_size(&w, &h);
    return h;
}

static jint JNICALL jni_audio_open(JNIEnv *, jclass, jint rate, jint ch, jint bits) {
    return g_audio_open(rate, ch, bits);
}

static jint JNICALL jni_audio_write(JNIEnv *env, jclass, jint handle, jbyteArray jbuf, jint off, jint len) {
    if (!jbuf || off < 0 || len <= 0) return 0;
    jsize alen = env->GetArrayLength(jbuf);
    if (off + len > alen) len = alen - off;
    if (len <= 0) return 0;
    jbyte *ptr = env->GetByteArrayElements(jbuf, nullptr);
    if (!ptr) return -1;
    int32_t written = g_audio_write(handle, ptr + off, len);
    env->ReleaseByteArrayElements(jbuf, ptr, JNI_ABORT);
    return written;
}

static jint JNICALL jni_audio_close(JNIEnv *, jclass, jint handle) {
    return g_audio_close(handle);
}

static void JNICALL jni_sleep_ms(JNIEnv *, jclass, jint ms) {
    g_sleep_ms(ms);
}

static jint JNICALL jni_get_frames(JNIEnv *, jclass) {
    int32_t f = 0; int64_t ab = 0;
    g_get_stats(&f, &ab);
    return f;
}

static jlong JNICALL jni_get_audio_bytes(JNIEnv *, jclass) {
    int32_t f = 0; int64_t ab = 0;
    g_get_stats(&f, &ab);
    return ab;
}

/* Convert backslashes and escape Windows drive letters ("C:/..." -> "/__afw_drv__/C/...")
 * so ART's colon-separated -Xbootclasspath / -Djava.class.path never splits a drive letter. */
static std::string to_art_path(std::string p) {
    for (char &c : p) if (c == '\\') c = '/';
    if (p.size() >= 2 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':') {
        std::string out = "/__afw_drv__/";
        out.push_back(p[0]);
        if (p.size() > 2 && p[2] == '/') out += p.substr(2);
        else if (p.size() > 2) { out.push_back('/'); out += p.substr(2); }
        else out.push_back('/');
        return out;
    }
    return p;
}

static void mkdir_p(const std::string &dir) {
    std::string cur;
    for (size_t i = 0; i < dir.size(); i++) {
        cur.push_back(dir[i]);
        if (dir[i] == '/' && cur.size() > 1)
            mkdir(cur.c_str(), 0755);
    }
    if (!cur.empty()) mkdir(cur.c_str(), 0755);
}

int main(int argc, char **argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s <art_dir> <framework_jar> <apk_path> [data_dir]\n", argv[0]);
        return 2;
    }

    if (!resolve_host_shims()) {
        std::fprintf(stderr, "[afw] FAIL: host GUI/audio shims (__afw_host_*) not available\n");
        return 1;
    }

    std::string art_dir  = to_art_path(argv[1]);
    std::string fw_jar   = to_art_path(argv[2]);
    std::string apk_path = to_art_path(argv[3]);
    std::string data_dir;
    if (argc >= 5 && argv[4][0]) {
        data_dir = to_art_path(argv[4]);
    } else {
        size_t sl = apk_path.find_last_of('/');
        std::string base = (sl == std::string::npos) ? "." : apk_path.substr(0, sl);
        data_dir = base + "/.afw_data";
    }
    std::string app_lib_dir = data_dir + "/lib64";
    mkdir_p(app_lib_dir);

    std::string javalib = art_dir + "/javalib";
    std::string lib64   = art_dir + "/lib64";

    setenv("ANDROID_ART_ROOT", art_dir.c_str(), 1);
    setenv("ANDROID_I18N_ROOT", art_dir.c_str(), 1);
    setenv("ANDROID_TZDATA_ROOT", art_dir.c_str(), 1);
    setenv("ANDROID_ROOT", art_dir.c_str(), 1);
    setenv("ANDROID_DATA", data_dir.c_str(), 1);
    setenv("ANDROID_LOG_TAGS", "*:w", 1);

    /* Redirect Android liblog to stderr for warnings/errors. */
    void *h_log = dlopen("liblog.so", RTLD_NOW);
    if (h_log) {
        typedef void (*logger_fn)(const void *);
        typedef void (*set_logger_fn)(logger_fn);
        typedef int (*set_min_prio_fn)(int);
        auto set_logger = reinterpret_cast<set_logger_fn>(dlsym(h_log, "__android_log_set_logger"));
        auto stderr_logger = reinterpret_cast<logger_fn>(dlsym(h_log, "__android_log_stderr_logger"));
        auto set_min = reinterpret_cast<set_min_prio_fn>(dlsym(h_log, "__android_log_set_minimum_priority"));
        if (set_logger && stderr_logger) {
            set_logger(stderr_logger);
            if (set_min) set_min(5 /* ANDROID_LOG_WARN */);
        }
    }

    void *h_art = dlopen("libart.so", RTLD_NOW);
    if (!h_art) {
        std::fprintf(stderr, "[afw] FAIL: dlopen(libart.so): %s\n", dlerror());
        return 1;
    }
    typedef jint (*create_vm_fn)(JavaVM **, JNIEnv **, void *);
    auto create_vm = reinterpret_cast<create_vm_fn>(dlsym(h_art, "JNI_CreateJavaVM"));
    if (!create_vm) {
        std::fprintf(stderr, "[afw] FAIL: dlsym(JNI_CreateJavaVM): %s\n", dlerror());
        return 1;
    }

    std::string bcp = "-Xbootclasspath:" +
        javalib + "/core-oj.jar:" +
        javalib + "/core-libart.jar:" +
        javalib + "/core-icu4j.jar:" +
        javalib + "/bouncycastle.jar:" +
        javalib + "/apache-xml.jar:" +
        javalib + "/okhttp.jar:" +
        javalib + "/conscrypt.jar:" +
        fw_jar;
    std::string cp = "-Djava.class.path=" + apk_path;
    std::string lp = "-Djava.library.path=" + app_lib_dir + ":" + lib64;

    std::vector<std::string> opt_strs = {
        bcp,
        cp,
        lp,
        "-Xnoimage-dex2oat",
        "-Xusejit:false",
        "-Xint",
        "-Xms16m",
        "-Xmx128m",
        "-Xnorelocate",
        "-Xverify:none"
    };
    std::vector<JavaVMOption> opts(opt_strs.size() + 1);
    for (size_t i = 0; i < opt_strs.size(); i++) {
        opts[i].optionString = const_cast<char *>(opt_strs[i].c_str());
        opts[i].extraInfo = nullptr;
    }
    opts[opt_strs.size()].optionString = const_cast<char *>("vfprintf");
    opts[opt_strs.size()].extraInfo = reinterpret_cast<void *>(+[](FILE *, const char *fmt, va_list ap) -> int {
        int r = std::vfprintf(stderr, fmt, ap);
        std::fflush(stderr);
        return r;
    });

    JavaVMInitArgs args;
    args.version = JNI_VERSION_1_6;
    args.nOptions = static_cast<jint>(opts.size());
    args.options = opts.data();
    args.ignoreUnrecognized = JNI_TRUE;

    JavaVM *vm = nullptr;
    JNIEnv *env = nullptr;
    if (create_vm(&vm, &env, &args) != JNI_OK || !vm || !env) {
        std::fprintf(stderr, "[afw] FAIL: JNI_CreateJavaVM failed\n");
        return 1;
    }

    /* Register native host bridge methods on com.afw.AfwHost */
    jclass host_cls = env->FindClass("com/afw/AfwHost");
    if (!host_cls) {
        if (env->ExceptionCheck()) env->ExceptionDescribe();
        std::fprintf(stderr, "[afw] FAIL: FindClass(com/afw/AfwHost) failed\n");
        vm->DestroyJavaVM();
        return 1;
    }
    static const JNINativeMethod host_methods[] = {
        { const_cast<char *>("windowCreate"),  const_cast<char *>("(Ljava/lang/String;II)I"), reinterpret_cast<void *>(jni_window_create) },
        { const_cast<char *>("present"),       const_cast<char *>("([III)I"),                 reinterpret_cast<void *>(jni_present) },
        { const_cast<char *>("pollEvent"),     const_cast<char *>("([I)I"),                   reinterpret_cast<void *>(jni_poll_event) },
        { const_cast<char *>("getWidth"),      const_cast<char *>("()I"),                     reinterpret_cast<void *>(jni_get_width) },
        { const_cast<char *>("getHeight"),     const_cast<char *>("()I"),                     reinterpret_cast<void *>(jni_get_height) },
        { const_cast<char *>("audioOpen"),     const_cast<char *>("(III)I"),                  reinterpret_cast<void *>(jni_audio_open) },
        { const_cast<char *>("audioWrite"),    const_cast<char *>("(I[BII)I"),                reinterpret_cast<void *>(jni_audio_write) },
        { const_cast<char *>("audioClose"),    const_cast<char *>("(I)I"),                    reinterpret_cast<void *>(jni_audio_close) },
        { const_cast<char *>("sleepMs"),       const_cast<char *>("(I)V"),                    reinterpret_cast<void *>(jni_sleep_ms) },
        { const_cast<char *>("getFrames"),     const_cast<char *>("()I"),                     reinterpret_cast<void *>(jni_get_frames) },
        { const_cast<char *>("getAudioBytes"), const_cast<char *>("()J"),                     reinterpret_cast<void *>(jni_get_audio_bytes) },
    };
    if (env->RegisterNatives(host_cls, host_methods,
                             static_cast<jint>(sizeof(host_methods) / sizeof(host_methods[0]))) != 0) {
        if (env->ExceptionCheck()) env->ExceptionDescribe();
        std::fprintf(stderr, "[afw] FAIL: RegisterNatives(com/afw/AfwHost) failed\n");
        vm->DestroyJavaVM();
        return 1;
    }

    jclass launcher_cls = env->FindClass("com/afw/AfwLauncher");
    if (!launcher_cls) {
        if (env->ExceptionCheck()) env->ExceptionDescribe();
        std::fprintf(stderr, "[afw] FAIL: FindClass(com/afw/AfwLauncher) failed\n");
        vm->DestroyJavaVM();
        return 1;
    }
    jmethodID launch_mid = env->GetStaticMethodID(launcher_cls, "launch", "(Ljava/lang/String;Ljava/lang/String;)I");
    if (!launch_mid) {
        if (env->ExceptionCheck()) env->ExceptionDescribe();
        std::fprintf(stderr, "[afw] FAIL: GetStaticMethodID(AfwLauncher.launch) failed\n");
        vm->DestroyJavaVM();
        return 1;
    }

    jstring japk  = env->NewStringUTF(apk_path.c_str());
    jstring jdata = env->NewStringUTF(data_dir.c_str());
    jint exit_rc = env->CallStaticIntMethod(launcher_cls, launch_mid, japk, jdata);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        exit_rc = 1;
    }

    vm->DestroyJavaVM();
    return static_cast<int>(exit_rc);
}
