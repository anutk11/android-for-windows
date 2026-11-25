/*
 * jni_bridge.h - JNI 1.6 JavaVM + JNIEnv System V ABI vtable bridge for dex_vm.
 */
#ifndef AFW_JNI_BRIDGE_H
#define AFW_JNI_BRIDGE_H

#include "dex_vm.h"

typedef struct afw_jni_state_s afw_jni_state;

afw_jni_state *afw_jni_create(afw_dex_vm *vm);
void           afw_jni_destroy(afw_jni_state *st);
void          *afw_jni_get_javavm(afw_jni_state *st);
void          *afw_jni_get_jnienv(afw_jni_state *st);

/* Invoke a SysV ABI native JNI function pointer with (JNIEnv*, this_or_cls, args...). */
uint64_t afw_jni_call_native(afw_jni_state *st, void *fn_ptr,
                             uint32_t this_or_cls, const char *shorty,
                             const uint64_t *args, int nargs);

/* Invoke JNI_OnLoad(JavaVM*, NULL) if exported by a newly loaded library. */
int afw_jni_invoke_onload(afw_jni_state *st, void *onload_sym);

#endif
