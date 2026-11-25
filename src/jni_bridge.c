/*
 * jni_bridge.c - JNI 1.6 JavaVM & JNIEnv System V ABI vtable bridge.
 *
 * All vtable slot indices match the official JNI 1.6 / Android NDK <jni.h> ABI.
 */
#include "jni_bridge.h"
#include "platform.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

typedef struct {
    uint32_t gp_offset;
    uint32_t fp_offset;
    void    *overflow_arg_area;
    void    *reg_save_area;
} afw_sysv_va_list_tag;

/* Unpack x86-64 System V ABI va_list (struct __va_list_tag *) into Dalvik args */
static int unpack_sysv_valist(const char *shorty, const afw_sysv_va_list_tag *va_in,
                              uint64_t *out, int max_args) {
    afw_sysv_va_list_tag ap;
    int n = 0;
    const char *p;
    if (!shorty || !shorty[0] || !va_in) return 0;
    ap = *va_in;
    for (p = shorty + 1; *p && n < max_args; p++) {
        if (*p == 'F' || *p == 'D') {
            double d = 0.0;
            if (ap.fp_offset <= 160 && ap.reg_save_area) {
                memcpy(&d, (const unsigned char *)ap.reg_save_area + ap.fp_offset, 8);
                ap.fp_offset += 16;
            } else if (ap.overflow_arg_area) {
                memcpy(&d, ap.overflow_arg_area, 8);
                ap.overflow_arg_area = (unsigned char *)ap.overflow_arg_area + 8;
            }
            if (*p == 'F') {
                float f = (float)d;
                uint32_t b = 0;
                memcpy(&b, &f, 4);
                out[n++] = (uint64_t)b;
            } else {
                uint64_t b = 0;
                memcpy(&b, &d, 8);
                out[n++] = b;
            }
        } else {
            uint64_t v = 0;
            if (ap.gp_offset <= 40 && ap.reg_save_area) {
                memcpy(&v, (const unsigned char *)ap.reg_save_area + ap.gp_offset, 8);
                ap.gp_offset += 8;
            } else if (ap.overflow_arg_area) {
                memcpy(&v, ap.overflow_arg_area, 8);
                ap.overflow_arg_area = (unsigned char *)ap.overflow_arg_area + 8;
            }
            if (*p == 'L' || *p == '[' || *p == 'J')
                out[n++] = v;
            else
                out[n++] = (uint64_t)(uint32_t)v;
        }
    }
    return n;
}

/* Unpack SysV variadic args arriving in (rcx, r8, r9, stack...) + (xmm0..xmm2) */
static int unpack_sysv_args(const char *shorty, const uint64_t *iargs, int niargs,
                            const double *fargs, int nfargs, uint64_t *out, int max_args) {
    int n = 0, ii = 0, fi = 0;
    const char *p;
    if (!shorty || !shorty[0]) return 0;
    for (p = shorty + 1; *p && n < max_args; p++) {
        switch (*p) {
        case 'L': case '[': case 'J':
            out[n++] = (ii < niargs) ? iargs[ii++] : 0;
            break;
        case 'F': {
            float f = (fi < nfargs) ? (float)fargs[fi++] : 0.0f;
            uint32_t bits = 0;
            memcpy(&bits, &f, 4);
            out[n++] = (uint64_t)bits;
            break;
        }
        case 'D': {
            double d = (fi < nfargs) ? fargs[fi++] : 0.0;
            uint64_t bits = 0;
            memcpy(&bits, &d, 8);
            out[n++] = bits;
            break;
        }
        default:
            out[n++] = (ii < niargs) ? (uint64_t)(uint32_t)iargs[ii++] : 0;
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

static uint64_t call_inst_sysv(void *env, void *obj, void *mid_p,
                               uint64_t a0, uint64_t a1, uint64_t a2,
                               double f0, double f1, double f2,
                               uint64_t a3, uint64_t a4) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t iargs[5] = { a0, a1, a2, a3, a4 };
    double   fargs[3] = { f0, f1, f2 };
    uint64_t args[16];
    int n = 0;
    uint64_t ret = 0;
    args[n++] = (uint64_t)(uintptr_t)obj;
    n += unpack_sysv_args(shorty, iargs, 5, fargs, 3, args + 1, 15);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return ret;
}

static uint64_t call_inst_v(void *env, void *obj, void *mid_p, const afw_sysv_va_list_tag *va) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    uint64_t ret = 0;
    args[n++] = (uint64_t)(uintptr_t)obj;
    n += unpack_sysv_valist(shorty, va, args + 1, 15);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return ret;
}

static uint64_t call_inst_a(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n = 0;
    uint64_t ret = 0;
    args[n++] = (uint64_t)(uintptr_t)obj;
    n += unpack_jval_args(shorty, jv, args + 1, 15);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return ret;
}

static uint64_t call_static_sysv(void *env, void *mid_p,
                                 uint64_t a0, uint64_t a1, uint64_t a2,
                                 double f0, double f1, double f2,
                                 uint64_t a3, uint64_t a4) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t iargs[5] = { a0, a1, a2, a3, a4 };
    double   fargs[3] = { f0, f1, f2 };
    uint64_t args[16];
    int n;
    uint64_t ret = 0;
    n = unpack_sysv_args(shorty, iargs, 5, fargs, 3, args, 16);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return ret;
}

static uint64_t call_static_v(void *env, void *mid_p, const afw_sysv_va_list_tag *va) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n;
    uint64_t ret = 0;
    n = unpack_sysv_valist(shorty, va, args, 16);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return ret;
}

static uint64_t call_static_a(void *env, void *mid_p, const afw_jvalue *jv) {
    afw_jni_state *st = from_env(env);
    int mid = (int)(uintptr_t)mid_p - 1;
    const char *shorty = afw_dex_method_shorty(st->vm, mid);
    uint64_t args[16];
    int n;
    uint64_t ret = 0;
    n = unpack_jval_args(shorty, jv, args, 16);
    (void)afw_dex_invoke_method_id(st->vm, mid, args, n, &ret);
    return ret;
}

static SYSV void *jni_NewObject(void *env, void *cls, void *mid_p,
                                uint64_t a0, uint64_t a1, uint64_t a2,
                                double f0, double f1, double f2,
                                uint64_t a3, uint64_t a4) {
    void *obj = jni_AllocObject(env, cls);
    if (obj) (void)call_inst_sysv(env, obj, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
    return obj;
}
static SYSV void *jni_NewObjectV(void *env, void *cls, void *mid_p, const afw_sysv_va_list_tag *va) {
    void *obj = jni_AllocObject(env, cls);
    if (obj) (void)call_inst_v(env, obj, mid_p, va);
    return obj;
}
static SYSV void *jni_NewObjectA(void *env, void *cls, void *mid_p, const afw_jvalue *jv) {
    void *obj = jni_AllocObject(env, cls);
    if (obj) (void)call_inst_a(env, obj, mid_p, jv);
    return obj;
}

static SYSV void *jni_CallObjectMethod(void *env, void *obj, void *mid_p,
                                       uint64_t a0, uint64_t a1, uint64_t a2,
                                       double f0, double f1, double f2,
                                       uint64_t a3, uint64_t a4) {
    return (void *)(uintptr_t)call_inst_sysv(env, obj, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
}
static SYSV void *jni_CallObjectMethodV(void *env, void *obj, void *mid_p, const afw_sysv_va_list_tag *va) {
    return (void *)(uintptr_t)call_inst_v(env, obj, mid_p, va);
}
static SYSV void *jni_CallObjectMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    return (void *)(uintptr_t)call_inst_a(env, obj, mid_p, jv);
}

static SYSV uint8_t jni_CallBooleanMethod(void *env, void *obj, void *mid_p,
                                          uint64_t a0, uint64_t a1, uint64_t a2,
                                          double f0, double f1, double f2,
                                          uint64_t a3, uint64_t a4) {
    return call_inst_sysv(env, obj, mid_p, a0, a1, a2, f0, f1, f2, a3, a4) ? 1 : 0;
}
static SYSV uint8_t jni_CallBooleanMethodV(void *env, void *obj, void *mid_p, const afw_sysv_va_list_tag *va) {
    return call_inst_v(env, obj, mid_p, va) ? 1 : 0;
}
static SYSV uint8_t jni_CallBooleanMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    return call_inst_a(env, obj, mid_p, jv) ? 1 : 0;
}

static SYSV int32_t jni_CallIntMethod(void *env, void *obj, void *mid_p,
                                      uint64_t a0, uint64_t a1, uint64_t a2,
                                      double f0, double f1, double f2,
                                      uint64_t a3, uint64_t a4) {
    return (int32_t)call_inst_sysv(env, obj, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
}
static SYSV int32_t jni_CallIntMethodV(void *env, void *obj, void *mid_p, const afw_sysv_va_list_tag *va) {
    return (int32_t)call_inst_v(env, obj, mid_p, va);
}
static SYSV int32_t jni_CallIntMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    return (int32_t)call_inst_a(env, obj, mid_p, jv);
}

static SYSV int64_t jni_CallLongMethod(void *env, void *obj, void *mid_p,
                                       uint64_t a0, uint64_t a1, uint64_t a2,
                                       double f0, double f1, double f2,
                                       uint64_t a3, uint64_t a4) {
    return (int64_t)call_inst_sysv(env, obj, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
}
static SYSV int64_t jni_CallLongMethodV(void *env, void *obj, void *mid_p, const afw_sysv_va_list_tag *va) {
    return (int64_t)call_inst_v(env, obj, mid_p, va);
}
static SYSV int64_t jni_CallLongMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    return (int64_t)call_inst_a(env, obj, mid_p, jv);
}

static SYSV float jni_CallFloatMethod(void *env, void *obj, void *mid_p,
                                      uint64_t a0, uint64_t a1, uint64_t a2,
                                      double f0, double f1, double f2,
                                      uint64_t a3, uint64_t a4) {
    uint32_t b = (uint32_t)call_inst_sysv(env, obj, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
    float f = 0.0f; memcpy(&f, &b, 4); return f;
}
static SYSV float jni_CallFloatMethodV(void *env, void *obj, void *mid_p, const afw_sysv_va_list_tag *va) {
    uint32_t b = (uint32_t)call_inst_v(env, obj, mid_p, va);
    float f = 0.0f; memcpy(&f, &b, 4); return f;
}
static SYSV float jni_CallFloatMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    uint32_t b = (uint32_t)call_inst_a(env, obj, mid_p, jv);
    float f = 0.0f; memcpy(&f, &b, 4); return f;
}

static SYSV double jni_CallDoubleMethod(void *env, void *obj, void *mid_p,
                                        uint64_t a0, uint64_t a1, uint64_t a2,
                                        double f0, double f1, double f2,
                                        uint64_t a3, uint64_t a4) {
    uint64_t b = call_inst_sysv(env, obj, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
    double d = 0.0; memcpy(&d, &b, 8); return d;
}
static SYSV double jni_CallDoubleMethodV(void *env, void *obj, void *mid_p, const afw_sysv_va_list_tag *va) {
    uint64_t b = call_inst_v(env, obj, mid_p, va);
    double d = 0.0; memcpy(&d, &b, 8); return d;
}
static SYSV double jni_CallDoubleMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    uint64_t b = call_inst_a(env, obj, mid_p, jv);
    double d = 0.0; memcpy(&d, &b, 8); return d;
}

static SYSV void jni_CallVoidMethod(void *env, void *obj, void *mid_p,
                                    uint64_t a0, uint64_t a1, uint64_t a2,
                                    double f0, double f1, double f2,
                                    uint64_t a3, uint64_t a4) {
    (void)call_inst_sysv(env, obj, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
}
static SYSV void jni_CallVoidMethodV(void *env, void *obj, void *mid_p, const afw_sysv_va_list_tag *va) {
    (void)call_inst_v(env, obj, mid_p, va);
}
static SYSV void jni_CallVoidMethodA(void *env, void *obj, void *mid_p, const afw_jvalue *jv) {
    (void)call_inst_a(env, obj, mid_p, jv);
}

static SYSV void *jni_CallStaticObjectMethod(void *env, void *cls, void *mid_p,
                                             uint64_t a0, uint64_t a1, uint64_t a2,
                                             double f0, double f1, double f2,
                                             uint64_t a3, uint64_t a4) {
    (void)cls;
    return (void *)(uintptr_t)call_static_sysv(env, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
}
static SYSV void *jni_CallStaticObjectMethodV(void *env, void *cls, void *mid_p, const afw_sysv_va_list_tag *va) {
    (void)cls;
    return (void *)(uintptr_t)call_static_v(env, mid_p, va);
}
static SYSV void *jni_CallStaticObjectMethodA(void *env, void *cls, void *mid_p, const afw_jvalue *jv) {
    (void)cls;
    return (void *)(uintptr_t)call_static_a(env, mid_p, jv);
}

static SYSV int32_t jni_CallStaticIntMethod(void *env, void *cls, void *mid_p,
                                            uint64_t a0, uint64_t a1, uint64_t a2,
                                            double f0, double f1, double f2,
                                            uint64_t a3, uint64_t a4) {
    (void)cls;
    return (int32_t)call_static_sysv(env, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
}
static SYSV int32_t jni_CallStaticIntMethodV(void *env, void *cls, void *mid_p, const afw_sysv_va_list_tag *va) {
    (void)cls;
    return (int32_t)call_static_v(env, mid_p, va);
}
static SYSV int32_t jni_CallStaticIntMethodA(void *env, void *cls, void *mid_p, const afw_jvalue *jv) {
    (void)cls;
    return (int32_t)call_static_a(env, mid_p, jv);
}

static SYSV int64_t jni_CallStaticLongMethod(void *env, void *cls, void *mid_p,
                                             uint64_t a0, uint64_t a1, uint64_t a2,
                                             double f0, double f1, double f2,
                                             uint64_t a3, uint64_t a4) {
    (void)cls;
    return (int64_t)call_static_sysv(env, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
}
static SYSV int64_t jni_CallStaticLongMethodV(void *env, void *cls, void *mid_p, const afw_sysv_va_list_tag *va) {
    (void)cls;
    return (int64_t)call_static_v(env, mid_p, va);
}
static SYSV int64_t jni_CallStaticLongMethodA(void *env, void *cls, void *mid_p, const afw_jvalue *jv) {
    (void)cls;
    return (int64_t)call_static_a(env, mid_p, jv);
}

static SYSV void jni_CallStaticVoidMethod(void *env, void *cls, void *mid_p,
                                          uint64_t a0, uint64_t a1, uint64_t a2,
                                          double f0, double f1, double f2,
                                          uint64_t a3, uint64_t a4) {
    (void)cls;
    (void)call_static_sysv(env, mid_p, a0, a1, a2, f0, f1, f2, a3, a4);
}
static SYSV void jni_CallStaticVoidMethodV(void *env, void *cls, void *mid_p, const afw_sysv_va_list_tag *va) {
    (void)cls;
    (void)call_static_v(env, mid_p, va);
}
static SYSV void jni_CallStaticVoidMethodA(void *env, void *cls, void *mid_p, const afw_jvalue *jv) {
    (void)cls;
    (void)call_static_a(env, mid_p, jv);
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
    g_jni_vtable[28]  = (const void *)jni_NewObject;
    g_jni_vtable[29]  = (const void *)jni_NewObjectV;
    g_jni_vtable[30]  = (const void *)jni_NewObjectA;
    g_jni_vtable[31]  = (const void *)jni_GetObjectClass;
    g_jni_vtable[33]  = (const void *)jni_GetMethodID;
    g_jni_vtable[34]  = (const void *)jni_CallObjectMethod;
    g_jni_vtable[35]  = (const void *)jni_CallObjectMethodV;
    g_jni_vtable[36]  = (const void *)jni_CallObjectMethodA;
    g_jni_vtable[37]  = (const void *)jni_CallBooleanMethod;
    g_jni_vtable[38]  = (const void *)jni_CallBooleanMethodV;
    g_jni_vtable[39]  = (const void *)jni_CallBooleanMethodA;
    g_jni_vtable[49]  = (const void *)jni_CallIntMethod;
    g_jni_vtable[50]  = (const void *)jni_CallIntMethodV;
    g_jni_vtable[51]  = (const void *)jni_CallIntMethodA;
    g_jni_vtable[52]  = (const void *)jni_CallLongMethod;
    g_jni_vtable[53]  = (const void *)jni_CallLongMethodV;
    g_jni_vtable[54]  = (const void *)jni_CallLongMethodA;
    g_jni_vtable[55]  = (const void *)jni_CallFloatMethod;
    g_jni_vtable[56]  = (const void *)jni_CallFloatMethodV;
    g_jni_vtable[57]  = (const void *)jni_CallFloatMethodA;
    g_jni_vtable[58]  = (const void *)jni_CallDoubleMethod;
    g_jni_vtable[59]  = (const void *)jni_CallDoubleMethodV;
    g_jni_vtable[60]  = (const void *)jni_CallDoubleMethodA;
    g_jni_vtable[61]  = (const void *)jni_CallVoidMethod;
    g_jni_vtable[62]  = (const void *)jni_CallVoidMethodV;
    g_jni_vtable[63]  = (const void *)jni_CallVoidMethodA;
    g_jni_vtable[94]  = (const void *)jni_GetFieldID;
    g_jni_vtable[95]  = (const void *)jni_GetObjectField;
    g_jni_vtable[100] = (const void *)jni_GetIntField;
    g_jni_vtable[104] = (const void *)jni_SetObjectField;
    g_jni_vtable[109] = (const void *)jni_SetIntField;
    g_jni_vtable[113] = (const void *)jni_GetStaticMethodID;
    g_jni_vtable[114] = (const void *)jni_CallStaticObjectMethod;
    g_jni_vtable[115] = (const void *)jni_CallStaticObjectMethodV;
    g_jni_vtable[116] = (const void *)jni_CallStaticObjectMethodA;
    g_jni_vtable[129] = (const void *)jni_CallStaticIntMethod;
    g_jni_vtable[130] = (const void *)jni_CallStaticIntMethodV;
    g_jni_vtable[131] = (const void *)jni_CallStaticIntMethodA;
    g_jni_vtable[132] = (const void *)jni_CallStaticLongMethod;
    g_jni_vtable[133] = (const void *)jni_CallStaticLongMethodV;
    g_jni_vtable[134] = (const void *)jni_CallStaticLongMethodA;
    g_jni_vtable[141] = (const void *)jni_CallStaticVoidMethod;
    g_jni_vtable[142] = (const void *)jni_CallStaticVoidMethodV;
    g_jni_vtable[143] = (const void *)jni_CallStaticVoidMethodA;
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
