/*
 * jni_bridge.c - JNI 1.6 JavaVM & JNIEnv System V ABI vtable bridge.
 *
 * All vtable slot indices match the official JNI 1.6 / Android NDK <jni.h> ABI.
 */
#include "jni_bridge.h"
#include "platform.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
typedef __builtin_sysv_va_list afw_jni_va;
#define JNI_VA_START(ap, last) __builtin_sysv_va_start(ap, last)
#define JNI_VA_ARG(ap, type)   __builtin_sysv_va_arg(ap, type)
#define JNI_VA_END(ap)         __builtin_sysv_va_end(ap)
#else
typedef va_list afw_jni_va;
#define JNI_VA_START(ap, last) va_start(ap, last)
#define JNI_VA_ARG(ap, type)   va_arg(ap, type)
#define JNI_VA_END(ap)         va_end(ap)
#endif

struct afw_jni_state_s {
    const void **env_vtable_ptr; /* JNIEnv* points here */
    const void **vm_vtable_ptr;  /* JavaVM* points here */
    afw_dex_vm  *vm;
    int          has_exception;
};

static afw_jni_state *from_env(void *env) {
    return (afw_jni_state *)env;
}

static afw_jni_state *from_vm(void *jvm) {
    return (afw_jni_state *)((unsigned char *)jvm - offsetof(afw_jni_state, vm_vtable_ptr));
}

typedef struct {
    const char *name;
    const char *signature;
    void       *fnPtr;
} afw_jni_native_method;

typedef union {
    uint8_t  z;
    int8_t   b;
    uint16_t c;
    int16_t  s;
    int32_t  i;
    int64_t  j;
    float    f;
    double   d;
    void    *l;
} afw_jvalue;

/* ---- JavaVM (JNIInvokeInterface) methods ------------------------------ */
static SYSV int32_t vm_DestroyJavaVM(void *jvm) { (void)jvm; return 0; }

static SYSV int32_t vm_AttachCurrentThread(void *jvm, void **penv, void *args) {
    afw_jni_state *st = from_vm(jvm);
    (void)args;
    if (penv) *penv = &st->env_vtable_ptr;
    return 0;
}

static SYSV int32_t vm_DetachCurrentThread(void *jvm) { (void)jvm; return 0; }

static SYSV int32_t vm_GetEnv(void *jvm, void **penv, int32_t ver) {
    afw_jni_state *st = from_vm(jvm);
    (void)ver;
    if (penv) *penv = &st->env_vtable_ptr;
    return 0; /* JNI_OK */
}

static SYSV int32_t vm_AttachCurrentThreadAsDaemon(void *jvm, void **penv, void *args) {
    return vm_AttachCurrentThread(jvm, penv, args);
}

static const void *g_vm_vtable[8] = {
    NULL, NULL, NULL,
    (const void *)vm_DestroyJavaVM,
    (const void *)vm_AttachCurrentThread,
    (const void *)vm_DetachCurrentThread,
    (const void *)vm_GetEnv,
    (const void *)vm_AttachCurrentThreadAsDaemon
};

/* ---- JNIEnv (JNINativeInterface) methods ------------------------------ */
static SYSV int32_t jni_unimpl(void *env) {
    (void)env;
    fprintf(stderr, "[jni] warning: unimplemented JNIEnv slot called\n");
    return 0;
}

static SYSV int32_t jni_GetVersion(void *env) {
    (void)env;
    return 0x00010006; /* JNI_VERSION_1_6 */
}

static SYSV void *jni_FindClass(void *env, const char *name) {
    afw_jni_state *st = from_env(env);
    uint32_t h = afw_dex_find_class(st->vm, name);
    return (void *)(uintptr_t)h;
}

static SYSV void jni_ExceptionClear(void *env) {
    from_env(env)->has_exception = 0;
}

static SYSV uint8_t jni_ExceptionCheck(void *env) {
    return from_env(env)->has_exception ? 1 : 0;
}

static SYSV void *jni_NewGlobalRef(void *env, void *obj) { (void)env; return obj; }
static SYSV void  jni_DeleteGlobalRef(void *env, void *obj) { (void)env; (void)obj; }
static SYSV void  jni_DeleteLocalRef(void *env, void *obj) { (void)env; (void)obj; }

static SYSV void *jni_AllocObject(void *env, void *cls) {
    afw_jni_state *st = from_env(env);
    const char *desc = afw_dex_obj_class_desc(st->vm, (uint32_t)(uintptr_t)cls);
    return (void *)(uintptr_t)afw_dex_new_instance(st->vm, desc);
}

static SYSV void *jni_GetObjectClass(void *env, void *obj) {
    afw_jni_state *st = from_env(env);
    const char *desc = afw_dex_obj_class_desc(st->vm, (uint32_t)(uintptr_t)obj);
    return (void *)(uintptr_t)afw_dex_find_class(st->vm, desc);
}

static SYSV void *jni_GetMethodID(void *env, void *cls, const char *name, const char *sig) {
    afw_jni_state *st = from_env(env);
    const char *desc = afw_dex_obj_class_desc(st->vm, (uint32_t)(uintptr_t)cls);
    int mid = afw_dex_find_method_id(st->vm, desc, name, sig);
    return (mid >= 0) ? (void *)(uintptr_t)(mid + 1) : NULL;
}

static SYSV void *jni_GetStaticMethodID(void *env, void *cls, const char *name, const char *sig) {
    return jni_GetMethodID(env, cls, name, sig);
}

static int unpack_va_args(const char *shorty, afw_jni_va *ap, uint64_t *out, int max_args) {
    int n = 0;
    const char *p;
    if (!shorty || !shorty[0]) return 0;
    for (p = shorty + 1; *p && n < max_args; p++) {
        switch (*p) {
        case 'L': case '[':
            out[n++] = (uint64_t)(uintptr_t)JNI_VA_ARG(*ap, void *);
            break;
        case 'J':
            out[n++] = (uint64_t)JNI_VA_ARG(*ap, int64_t);
            break;
        case 'F': {
            float f = (float)JNI_VA_ARG(*ap, double);
            uint32_t bits = 0;
            memcpy(&bits, &f, 4);
            out[n++] = (uint64_t)bits;
            break;
        }
        case 'D': {
            double d = JNI_VA_ARG(*ap, double);
            uint64_t bits = 0;
            memcpy(&bits, &d, 8);
            out[n++] = bits;
            break;
        }
        default: /* I, Z, B, C, S */
            out[n++] = (uint64_t)(uint32_t)JNI_VA_ARG(*ap, int32_t);
            break;
        }
    }
    return n;
}

static int unpack_jval_args(const char *shorty, const afw_jvalue *jv, uint64_t *out, int max_args) {
    int n = 0;
    const char *p;
    if (!shorty || !shorty[0] || !jv) return 0;
    for (p = shorty + 1; *p && n < max_args; p++, jv++) {
        switch (*p) {
        case 'L': case '[': out[n++] = (uint64_t)(uintptr_t)jv->l; break;
        case 'J': out[n++] = (uint64_t)jv->j; break;
        case 'F': { uint32_t b = 0; memcpy(&b, &jv->f, 4); out[n++] = b; break; }
        case 'D': { uint64_t b = 0; memcpy(&b, &jv->d, 8); out[n++] = b; break; }
        default:  out[n++] = (uint64_t)(uint32_t)jv->i; break;
        }
    }
    return n;
}

static SYSV int32_t jni_CallIntMethod(void *env, void *obj, void *mid_p, ...) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    uint64_t ret = 0;
    afw_jni_va ap;
    args[n++] = (uint64_t)(uintptr_t)obj;
    JNI_VA_START(ap, mid_p);
    n += unpack_va_args(shorty, &ap, args + 1, 15);
    JNI_VA_END(ap);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return (int32_t)ret;
}

static SYSV int32_t jni_CallIntMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    uint64_t ret = 0;
    args[n++] = (uint64_t)(uintptr_t)obj;
    n += unpack_jval_args(shorty, jv, args + 1, 15);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return (int32_t)ret;
}

static SYSV void *jni_CallObjectMethod(void *env, void *obj, void *mid_p, ...) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    uint64_t ret = 0;
    afw_jni_va ap;
    args[n++] = (uint64_t)(uintptr_t)obj;
    JNI_VA_START(ap, mid_p);
    n += unpack_va_args(shorty, &ap, args + 1, 15);
    JNI_VA_END(ap);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return (void *)(uintptr_t)ret;
}

static SYSV void *jni_CallObjectMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    uint64_t ret = 0;
    args[n++] = (uint64_t)(uintptr_t)obj;
    n += unpack_jval_args(shorty, jv, args + 1, 15);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return (void *)(uintptr_t)ret;
}

static SYSV void jni_CallVoidMethod(void *env, void *obj, void *mid_p, ...) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    afw_jni_va ap;
    args[n++] = (uint64_t)(uintptr_t)obj;
    JNI_VA_START(ap, mid_p);
    n += unpack_va_args(shorty, &ap, args + 1, 15);
    JNI_VA_END(ap);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, NULL);
}

static SYSV void jni_CallVoidMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    args[n++] = (uint64_t)(uintptr_t)obj;
    n += unpack_jval_args(shorty, jv, args + 1, 15);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, NULL);
}

static SYSV int32_t jni_CallStaticIntMethod(void *env, void *cls, void *mid_p, ...) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    uint64_t ret = 0;
    afw_jni_va ap;
    (void)cls;
    JNI_VA_START(ap, mid_p);
    n = unpack_va_args(shorty, &ap, args, 16);
    JNI_VA_END(ap);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return (int32_t)ret;
}

static SYSV void *jni_CallStaticObjectMethod(void *env, void *cls, void *mid_p, ...) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    uint64_t ret = 0;
    afw_jni_va ap;
    (void)cls;
    JNI_VA_START(ap, mid_p);
    n = unpack_va_args(shorty, &ap, args, 16);
    JNI_VA_END(ap);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return (void *)(uintptr_t)ret;
}

static SYSV void *jni_GetFieldID(void *env, void *cls, const char *name, const char *sig) {
    afw_jni_state *st = from_env(env);
    const char *desc = afw_dex_obj_class_desc(st->vm, (uint32_t)(uintptr_t)cls);
    int fid = afw_dex_find_field_id(st->vm, desc, name);
    (void)sig;
    return (fid >= 0) ? (void *)(uintptr_t)(fid + 1) : NULL;
}

static SYSV void *jni_GetObjectField(void *env, void *obj, void *fid_p) {
    afw_jni_state *st = from_env(env);
    return (void *)(uintptr_t)afw_dex_get_inst_field(st->vm, (uint32_t)(uintptr_t)obj, (int)(uintptr_t)fid_p - 1);
}

static SYSV int32_t jni_GetIntField(void *env, void *obj, void *fid_p) {
    afw_jni_state *st = from_env(env);
    return (int32_t)afw_dex_get_inst_field(st->vm, (uint32_t)(uintptr_t)obj, (int)(uintptr_t)fid_p - 1);
}

static SYSV void jni_SetObjectField(void *env, void *obj, void *fid_p, void *val) {
    afw_jni_state *st = from_env(env);
    afw_dex_set_inst_field(st->vm, (uint32_t)(uintptr_t)obj, (int)(uintptr_t)fid_p - 1, (uint64_t)(uintptr_t)val);
}

static SYSV void jni_SetIntField(void *env, void *obj, void *fid_p, int32_t val) {
    afw_jni_state *st = from_env(env);
    afw_dex_set_inst_field(st->vm, (uint32_t)(uintptr_t)obj, (int)(uintptr_t)fid_p - 1, (uint64_t)(uint32_t)val);
}

static SYSV void *jni_NewStringUTF(void *env, const char *utf) {
    afw_jni_state *st = from_env(env);
    return (void *)(uintptr_t)afw_dex_new_string(st->vm, utf ? utf : "");
}

static SYSV int32_t jni_GetStringUTFLength(void *env, void *jstr) {
    afw_jni_state *st = from_env(env);
    const char *s = afw_dex_get_string(st->vm, (uint32_t)(uintptr_t)jstr);
    return s ? (int32_t)strlen(s) : 0;
}

static SYSV const char *jni_GetStringUTFChars(void *env, void *jstr, uint8_t *is_copy) {
    afw_jni_state *st = from_env(env);
    const char *s = afw_dex_get_string(st->vm, (uint32_t)(uintptr_t)jstr);
    if (is_copy) *is_copy = 0;
    return s ? s : "";
}

static SYSV void jni_ReleaseStringUTFChars(void *env, void *jstr, const char *chars) {
    (void)env; (void)jstr; (void)chars;
}

static SYSV int32_t jni_GetArrayLength(void *env, void *arr) {
    afw_jni_state *st = from_env(env);
    int32_t len = 0;
    (void)afw_dex_int_array_data(st->vm, (uint32_t)(uintptr_t)arr, &len);
    return len;
}

static SYSV void *jni_NewIntArray(void *env, int32_t len) {
    afw_jni_state *st = from_env(env);
    return (void *)(uintptr_t)afw_dex_new_int_array(st->vm, len);
}

static SYSV int32_t *jni_GetIntArrayElements(void *env, void *arr, uint8_t *is_copy) {
    afw_jni_state *st = from_env(env);
    if (is_copy) *is_copy = 0;
    return afw_dex_int_array_data(st->vm, (uint32_t)(uintptr_t)arr, NULL);
}

static SYSV void jni_ReleaseIntArrayElements(void *env, void *arr, int32_t *elems, int32_t mode) {
    (void)env; (void)arr; (void)elems; (void)mode;
}

static SYSV void jni_GetIntArrayRegion(void *env, void *arr, int32_t start, int32_t len, int32_t *buf) {
    afw_jni_state *st = from_env(env);
    int32_t alen = 0;
    int32_t *p = afw_dex_int_array_data(st->vm, (uint32_t)(uintptr_t)arr, &alen);
    if (p && buf && start >= 0 && len >= 0 && start + len <= alen)
        memcpy(buf, p + start, (size_t)len * sizeof(int32_t));
}

static SYSV void jni_SetIntArrayRegion(void *env, void *arr, int32_t start, int32_t len, const int32_t *buf) {
    afw_jni_state *st = from_env(env);
    int32_t alen = 0;
    int32_t *p = afw_dex_int_array_data(st->vm, (uint32_t)(uintptr_t)arr, &alen);
    if (p && buf && start >= 0 && len >= 0 && start + len <= alen)
        memcpy(p + start, buf, (size_t)len * sizeof(int32_t));
}

static SYSV int32_t jni_RegisterNatives(void *env, void *cls, const afw_jni_native_method *methods, int32_t n) {
    afw_jni_state *st = from_env(env);
    const char *desc = afw_dex_obj_class_desc(st->vm, (uint32_t)(uintptr_t)cls);
    int32_t i;
    if (!desc || !methods || n < 0) return -1;
    for (i = 0; i < n; i++) {
        if (afw_dex_register_native(st->vm, desc, methods[i].name, methods[i].signature, methods[i].fnPtr) != 0)
            return -1;
    }
    return 0;
}

static SYSV int32_t jni_UnregisterNatives(void *env, void *cls) { (void)env; (void)cls; return 0; }

static SYSV int32_t jni_GetJavaVM(void *env, void **vm_out) {
    afw_jni_state *st = from_env(env);
    if (vm_out) *vm_out = &st->vm_vtable_ptr;
    return 0;
}

static const void *g_jni_vtable[236];
static int g_jni_vtable_ready = 0;

static void init_jni_vtable(void) {
    size_t i;
    if (g_jni_vtable_ready) return;
    for (i = 0; i < 236; i++) g_jni_vtable[i] = (const void *)jni_unimpl;
    g_jni_vtable[0]   = NULL;
    g_jni_vtable[1]   = NULL;
    g_jni_vtable[2]   = NULL;
    g_jni_vtable[3]   = NULL;
    g_jni_vtable[4]   = (const void *)jni_GetVersion;
    g_jni_vtable[6]   = (const void *)jni_FindClass;
    g_jni_vtable[17]  = (const void *)jni_ExceptionClear;
    g_jni_vtable[21]  = (const void *)jni_NewGlobalRef;
    g_jni_vtable[22]  = (const void *)jni_DeleteGlobalRef;
    g_jni_vtable[23]  = (const void *)jni_DeleteLocalRef;
    g_jni_vtable[27]  = (const void *)jni_AllocObject;
    g_jni_vtable[31]  = (const void *)jni_GetObjectClass;
    g_jni_vtable[33]  = (const void *)jni_GetMethodID;
    g_jni_vtable[34]  = (const void *)jni_CallObjectMethod;
    g_jni_vtable[36]  = (const void *)jni_CallObjectMethodA;
    g_jni_vtable[49]  = (const void *)jni_CallIntMethod;
    g_jni_vtable[51]  = (const void *)jni_CallIntMethodA;
    g_jni_vtable[61]  = (const void *)jni_CallVoidMethod;
    g_jni_vtable[63]  = (const void *)jni_CallVoidMethodA;
    g_jni_vtable[94]  = (const void *)jni_GetFieldID;
    g_jni_vtable[95]  = (const void *)jni_GetObjectField;
    g_jni_vtable[100] = (const void *)jni_GetIntField;
    g_jni_vtable[104] = (const void *)jni_SetObjectField;
    g_jni_vtable[109] = (const void *)jni_SetIntField;
    g_jni_vtable[113] = (const void *)jni_GetStaticMethodID;
    g_jni_vtable[114] = (const void *)jni_CallStaticObjectMethod;
    g_jni_vtable[129] = (const void *)jni_CallStaticIntMethod;
    g_jni_vtable[167] = (const void *)jni_NewStringUTF;
    g_jni_vtable[168] = (const void *)jni_GetStringUTFLength;
    g_jni_vtable[169] = (const void *)jni_GetStringUTFChars;
    g_jni_vtable[170] = (const void *)jni_ReleaseStringUTFChars;
    g_jni_vtable[171] = (const void *)jni_GetArrayLength;
    g_jni_vtable[179] = (const void *)jni_NewIntArray;
    g_jni_vtable[187] = (const void *)jni_GetIntArrayElements;
    g_jni_vtable[195] = (const void *)jni_ReleaseIntArrayElements;
    g_jni_vtable[203] = (const void *)jni_GetIntArrayRegion;
    g_jni_vtable[211] = (const void *)jni_SetIntArrayRegion;
    g_jni_vtable[215] = (const void *)jni_RegisterNatives;
    g_jni_vtable[216] = (const void *)jni_UnregisterNatives;
    g_jni_vtable[219] = (const void *)jni_GetJavaVM;
    g_jni_vtable[228] = (const void *)jni_ExceptionCheck;
    g_jni_vtable_ready = 1;
}

afw_jni_state *afw_jni_create(afw_dex_vm *vm) {
    afw_jni_state *st;
    init_jni_vtable();
    st = (afw_jni_state *)calloc(1, sizeof *st);
    if (!st) return NULL;
    st->env_vtable_ptr = g_jni_vtable;
    st->vm_vtable_ptr  = g_vm_vtable;
    st->vm             = vm;
    return st;
}

void afw_jni_destroy(afw_jni_state *st) { free(st); }
void *afw_jni_get_javavm(afw_jni_state *st) { return st ? (void *)&st->vm_vtable_ptr : NULL; }
void *afw_jni_get_jnienv(afw_jni_state *st) { return st ? (void *)&st->env_vtable_ptr : NULL; }

int afw_jni_invoke_onload(afw_jni_state *st, void *onload_sym) {
    typedef SYSV int32_t (*onload_fn)(void *jvm, void *reserved);
    if (!st || !onload_sym) return 0;
    return ((onload_fn)onload_sym)(afw_jni_get_javavm(st), NULL);
}

uint64_t afw_jni_call_native(afw_jni_state *st, void *fn_ptr,
                             uint32_t this_or_cls, const char *shorty,
                             const uint64_t *args, int nargs) {
    typedef SYSV uint64_t (*fn0)(void *, void *);
    typedef SYSV uint64_t (*fn1)(void *, void *, uint64_t);
    typedef SYSV uint64_t (*fn2)(void *, void *, uint64_t, uint64_t);
    typedef SYSV uint64_t (*fn3)(void *, void *, uint64_t, uint64_t, uint64_t);
    typedef SYSV uint64_t (*fn4)(void *, void *, uint64_t, uint64_t, uint64_t, uint64_t);
    typedef SYSV uint64_t (*fn5)(void *, void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    typedef SYSV uint64_t (*fn6)(void *, void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    void *env = afw_jni_get_jnienv(st);
    void *obj = (void *)(uintptr_t)this_or_cls;
    uint64_t r = 0;
    (void)shorty;
    if (!st || !fn_ptr) return 0;
    switch (nargs) {
    case 0: r = ((fn0)fn_ptr)(env, obj); break;
    case 1: r = ((fn1)fn_ptr)(env, obj, args[0]); break;
    case 2: r = ((fn2)fn_ptr)(env, obj, args[0], args[1]); break;
    case 3: r = ((fn3)fn_ptr)(env, obj, args[0], args[1], args[2]); break;
    case 4: r = ((fn4)fn_ptr)(env, obj, args[0], args[1], args[2], args[3]); break;
    case 5: r = ((fn5)fn_ptr)(env, obj, args[0], args[1], args[2], args[3], args[4]); break;
    default: r = ((fn6)fn_ptr)(env, obj, args[0], args[1], args[2], args[3], args[4], args[5]); break;
    }
    return r;
}
